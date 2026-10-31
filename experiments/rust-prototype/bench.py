#!/usr/bin/env python3
"""Bounded ABBA real-TURN experiment runner (no SSH or credential issuance).

Required CLI paths: --source-root, --dependency-root, --rust-bin. stdin is one
JSON line: {"version":1,"repetitions":2,"request":<v1 client request>,
"lifecycle":true}. The same ephemeral credentials, pinned TURN IP/SNI, gateway
key and peer are passed to both workers exclusively through anonymous stdin.
Default short-run order is Python/Rust/Rust/Python; lifecycle adds one separate
Python/Rust pair (150-second renewal soak, owned TLS abort/recovery, explicit Stop).
Only redacted JSONL is emitted. Each comparison run is <=16 MiB and aggregate
comparison throughput targets are <=64 MiB; lifecycle sends two tiny workloads.

Worker request workload fields: payload_bytes, latency_packets, throughput_bytes,
window, packet_timeout_s, idle_s, renewal_soak_s, renewals (integer), recovery,
run_timeout_s. All time/byte/window limits are validated before launch.
An already deployed authenticated UDP echo must be supplied by the operator.
"""
import asyncio
import copy
import json
import math
import os
from pathlib import Path
import statistics
import sys
import time

from python_peer import LINE_LIMIT, Parser, emit, integer, validate_client

DEFAULT_WORKLOAD = dict(payload_bytes=1200, latency_packets=100, throughput_bytes=16 * 1024 * 1024,
                        window=512, packet_timeout_s=2, idle_s=5, renewal_soak_s=0,
                        renewals=0, recovery=False, run_timeout_s=180)

PHASES = frozenset(('startup', 'idle', 'latency', 'throughput', 'renewal', 'recovery', 'stop'))
STATES = frozenset(('phase', 'explicit_stop', 'input_closed'))
METRICS = frozenset(('sent_packets', 'sent_bytes', 'acked_packets', 'acked_bytes', 'timeouts',
                     'loss_packets', 'integrity_errors', 'late_packets', 'queue_drops',
                     'duration_s', 'p50_ms', 'p95_ms', 'target_bytes', 'throughput_bps',
                     'successful_renewals', 'required_renewals', 'success', 'detection_ms',
                     'recovery_ms'))
LIMITATIONS = [
    'Same authenticated UDP echo and pinned TURN IPv4/TLS SNI; not native QUIC/Tern end-to-end throughput.',
    'Throughput is verified echoed application payload bits per second, excluding framing/TLS/network overhead.',
    'A full-size-packet floor leaves less than one payload below the configured throughput target.',
    'Latency is sequential nearest-rank RTT p50/p95 including local scheduling; no warmup is discarded.',
    'Loss means no verified application echo before the deadline, not proof of network-layer loss.',
    'Production ClientCodec discards bad HMAC/direction/replay before application integrity counters.',
    'RSS is sampled process resident memory, not allocator live bytes/PSS; short peaks may be missed.',
    'CPU is sampled user+system time for the worker only, excluding echo, runner and kernel/network peers.',
    'Worker CPU includes payload generation, integrity validation and benchmark scheduling; it is not isolated relay CPU.',
    'Phase CPU boundaries are sampled; transition intervals are reported separately, not fabricated.',
    'macOS ps sampling overhead belongs to the runner; Linux reads procfs. Final CPU can miss the last interval.',
    'Stop latency includes pipe/scheduler delay until observed process exit; forced termination is not successful Stop.',
    'Two interleaved samples per implementation expose variation but do not establish statistical significance.',
    'Recovery injects only an owned TLS abort; it does not model WAN outages or provider-wide failures.',
]


def clean_event(value):
    if not isinstance(value, dict):
        raise ValueError('worker_protocol')
    event = value.get('event')
    if event in ('ready', 'done', 'stopped'):
        return {'event': event}
    if event == 'error':
        return {'event': 'error', 'code': 'worker_reported_error'}
    if event == 'state':
        state = value.get('state')
        if state not in STATES:
            raise ValueError('worker_protocol')
        result = {'event': 'state', 'state': state}
        if state == 'phase':
            if value.get('phase') not in PHASES:
                raise ValueError('worker_protocol')
            result['phase'] = value['phase']
        return result
    if event == 'sample' and value.get('phase') in PHASES:
        result = {'event': 'sample', 'phase': value['phase']}
        for name in METRICS:
            if name not in value:
                continue
            item = value[name]
            if item is None and name in ('p50_ms', 'p95_ms'):
                result[name] = None
            elif type(item) in (int, float) and math.isfinite(item) and 0 <= item <= 1e20:
                result[name] = item
            else:
                raise ValueError('worker_protocol')
        return result
    raise ValueError('worker_protocol')


def cpu_seconds(value):
    days, separator, clock = value.partition('-')
    if not separator:
        clock, days = days, '0'
    parts = clock.split(':')
    if len(parts) == 2:
        minutes, seconds = parts
        hours = '0'
    elif len(parts) == 3:
        hours, minutes, seconds = parts
    else:
        raise ValueError('accounting_format')
    return int(days) * 86400 + int(hours) * 3600 + int(minutes) * 60 + float(seconds)


async def process_usage(pid):
    if sys.platform.startswith('linux'):
        # Field 3 starts after the final ')' because comm can contain spaces.
        stat = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        ticks = os.sysconf('SC_CLK_TCK')
        return int(stat[21]) * os.sysconf('SC_PAGE_SIZE'), (int(stat[11]) + int(stat[12])) / ticks
    if sys.platform == 'darwin':
        process = await asyncio.create_subprocess_exec(
            '/bin/ps', '-o', 'rss=', '-o', 'time=', '-p', str(pid),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), 2)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        fields = stdout.decode('ascii').split()
        if process.returncode or len(fields) != 2:
            raise ValueError('accounting_unavailable')
        return int(fields[0]) * 1024, cpu_seconds(fields[1])
    raise ValueError('unsupported_accounting_platform')


class Accounting:
    def __init__(self, pid):
        self.pid = pid
        self.phase = 'startup'
        self.finished = asyncio.Event()
        self.phases = {}
        self.previous = None
        self.first_cpu = None
        self.last_cpu = None
        self.errors = 0
        self.peak = 0

    async def run(self):
        while not self.finished.is_set():
            try:
                rss, cpu = await process_usage(self.pid)
                now, phase = time.monotonic(), self.phase
                if self.first_cpu is None:
                    self.first_cpu = cpu
                self.last_cpu = cpu
                self.peak = max(self.peak, rss)
                row = self.phases.setdefault(phase, dict(samples=0, rss_sum=0, peak_rss_bytes=0,
                                                         cpu_seconds=0.0, measured_seconds=0.0))
                row['samples'] += 1
                row['rss_sum'] += rss
                row['peak_rss_bytes'] = max(row['peak_rss_bytes'], rss)
                if self.previous is not None:
                    before, previous_cpu, previous_phase = self.previous
                    target = row if previous_phase == phase else self.phases.setdefault(
                        'transition', dict(samples=0, rss_sum=0, peak_rss_bytes=0,
                                           cpu_seconds=0.0, measured_seconds=0.0))
                    target['cpu_seconds'] += max(0, cpu - previous_cpu)
                    target['measured_seconds'] += now - before
                self.previous = now, cpu, phase
            except (OSError, ValueError, IndexError, asyncio.TimeoutError):
                self.errors += 1
            try:
                await asyncio.wait_for(self.finished.wait(), .2)
            except asyncio.TimeoutError:
                pass

    def result(self):
        phases = {}
        for name, row in self.phases.items():
            elapsed = row['measured_seconds']
            phases[name] = {key: value for key, value in row.items() if key != 'rss_sum'}
            phases[name]['mean_rss_bytes'] = row['rss_sum'] / row['samples'] if row['samples'] else None
            phases[name]['cpu_percent_one_core'] = row['cpu_seconds'] / elapsed * 100 if elapsed else None
        return dict(peak_rss_bytes=self.peak or None, sampled_cpu_seconds=self.last_cpu,
                    observed_cpu_delta_seconds=(self.last_cpu - self.first_cpu)
                    if self.first_cpu is not None else None,
                    sampling_errors=self.errors, phases=phases)


async def discard_stderr(reader, terminal, flags):
    count = 0
    while True:
        data = await reader.read(8192)
        if not data:
            return
        count += len(data)
        if count > 1024 * 1024:
            flags['stderr_limit'] = True
            terminal.set()
            return


async def consume_events(reader, terminal, flags, accounting, identity, samples):
    lines = 0
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                return
            lines += 1
            if len(raw) > LINE_LIMIT or lines > 128:
                raise ValueError('worker_protocol')
            value = clean_event(json.loads(raw))
            event = value['event']
            if event == 'state' and value['state'] == 'phase':
                accounting.phase = value['phase']
            elif event == 'sample':
                if value['phase'] in samples:
                    raise ValueError('duplicate_sample')
                samples[value['phase']] = value
            elif event in ('done', 'stopped', 'error'):
                flags[event] = True
                if event in ('done', 'error'):
                    terminal.set()
            emit('worker', **identity, data=value)
    except (Exception, asyncio.CancelledError):
        flags['protocol_error'] = True
        terminal.set()


async def run_one(command, request, implementation, index, suite):
    identity = dict(implementation=implementation, sample_index=index, suite=suite)
    process = await asyncio.create_subprocess_exec(
        *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, limit=LINE_LIMIT, start_new_session=True)
    accounting = Accounting(process.pid)
    terminal = asyncio.Event()
    flags, samples = {}, {}
    sampler = asyncio.create_task(accounting.run())
    events = asyncio.create_task(consume_events(process.stdout, terminal, flags, accounting, identity, samples))
    stderr = asyncio.create_task(discard_stderr(process.stderr, terminal, flags))
    exited = asyncio.create_task(process.wait())
    signalled = asyncio.create_task(terminal.wait())
    stop_started = None
    stop_latency = None
    started = time.monotonic()
    try:
        encoded = json.dumps(request, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(encoded) > LINE_LIMIT:
            raise ValueError('request_limit')
        process.stdin.write(encoded)
        await asyncio.wait_for(process.stdin.drain(), 3)
        complete, _ = await asyncio.wait((signalled, exited),
                                         timeout=request['workload']['run_timeout_s'] + 20,
                                         return_when=asyncio.FIRST_COMPLETED)
        if not complete:
            flags['run_deadline'] = True
        if process.returncode is None:
            accounting.phase = 'stop'
            stop_started = time.monotonic()
            process.stdin.write(b'{"command":"stop"}\n')
            await asyncio.wait_for(process.stdin.drain(), 3)
            await asyncio.wait_for(asyncio.shield(exited), 10)
            stop_latency = (time.monotonic() - stop_started) * 1000
        await asyncio.wait_for(asyncio.shield(events), 2)
    except Exception:
        flags['runner_failure'] = True
    finally:
        if process.returncode is None:
            flags['forced_termination'] = True
            process.kill()
        await process.wait()
        if process.stdin:
            process.stdin.close()
        accounting.finished.set()
        await sampler
        for task in (events, stderr, signalled, exited):
            if not task.done():
                task.cancel()
        await asyncio.gather(events, stderr, signalled, exited, return_exceptions=True)
    work = request['workload']
    criteria = (all(phase in samples for phase in ('idle', 'latency', 'throughput'))
                and samples.get('latency', {}).get('acked_packets', 0) > 0
                and (work['throughput_bytes'] == 0 or samples.get('throughput', {}).get('acked_packets', 0) > 0)
                and all(sample.get('integrity_errors', 0) == 0 for sample in samples.values())
                and (work['renewals'] == 0 or samples.get('renewal', {}).get('success') == 1)
                and (not work['recovery'] or samples.get('recovery', {}).get('success') == 1))
    successful = (process.returncode == 0 and flags.get('done', False) and flags.get('stopped', False)
                  and stop_latency is not None and criteria and accounting.first_cpu is not None
                  and not any(flags.get(name) for name in ('error', 'protocol_error', 'stderr_limit',
                                                           'run_deadline', 'runner_failure', 'forced_termination')))
    result = dict(identity, successful=successful, exit_code=process.returncode,
                  explicit_stop_exit_ms=stop_latency, duration_s=time.monotonic() - started,
                  flags=flags, accounting=accounting.result(), samples=samples)
    emit('run_result', **result)
    return result


def summary(results):
    implementations = {}
    for name in ('python', 'rust'):
        rows = [row for row in results if row['implementation'] == name and row['suite'] == 'comparison']
        values = {}
        for field, getter in (
                ('throughput_bps', lambda r: r['samples'].get('throughput', {}).get('throughput_bps')),
                ('latency_p50_ms', lambda r: r['samples'].get('latency', {}).get('p50_ms')),
                ('latency_p95_ms', lambda r: r['samples'].get('latency', {}).get('p95_ms')),
                ('peak_rss_bytes', lambda r: r['accounting']['peak_rss_bytes']),
                ('cpu_seconds', lambda r: r['accounting']['sampled_cpu_seconds']),
                ('stop_exit_ms', lambda r: r['explicit_stop_exit_ms'])):
            observed = [getter(row) for row in rows if row['successful']]
            observed = [value for value in observed if value is not None]
            values[field] = dict(n=len(observed), median=statistics.median(observed) if observed else None,
                                 min=min(observed) if observed else None, max=max(observed) if observed else None)
        implementations[name] = values
    emit('summary', runs=len(results), successful_runs=sum(row['successful'] for row in results),
         implementations=implementations)


async def run(args):
    if sys.platform != 'darwin' and not sys.platform.startswith('linux'):
        raise ValueError('unsupported_accounting_platform')
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda loop, context: None)
    reader = asyncio.StreamReader(limit=LINE_LIMIT)
    pipe, _ = await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    try:
        raw = await asyncio.wait_for(reader.readline(), 15)
        if not raw or len(raw) > LINE_LIMIT:
            raise ValueError('invalid_input')
        config = json.loads(raw)
    finally:
        pipe.close()
    if not isinstance(config, dict) or config.get('version') != 1:
        raise ValueError('invalid_request')
    repetitions = integer(config.get('repetitions', 2), 2, 8)
    request = dict(config['request'])
    request['workload'] = dict(DEFAULT_WORKLOAD, **request.get('workload', {}))
    validate_client(request)
    lifecycle = config.get('lifecycle', True)
    if type(lifecycle) is not bool:
        raise ValueError('invalid_request')
    if request['workload']['renewals'] or request['workload']['renewal_soak_s'] or request['workload']['recovery']:
        raise ValueError('comparison_requires_short_workload')
    if request['workload']['throughput_bytes'] < request['workload']['payload_bytes']:
        raise ValueError('comparison_requires_payload')
    target = repetitions * 2 * request['workload']['throughput_bytes']
    if target > 64 * 1024 * 1024:
        raise ValueError('aggregate_byte_cap')
    if repetitions * 2 * request['workload']['run_timeout_s'] + (600 if lifecycle else 0) > 3600:
        raise ValueError('aggregate_time_cap')
    peer = str(Path(__file__).with_name('python_peer.py').resolve(strict=True))
    source = str(Path(args.source_root).resolve(strict=True))
    dependency = str(Path(args.dependency_root).resolve(strict=True))
    rust = str(Path(args.rust_bin).resolve(strict=True))
    commands = {'python': [sys.executable, peer, '--source-root', source, '--dependency-root', dependency],
                'rust': [rust]}
    emit('experiment', version=1, order='alternating_AB_BA', repetitions=repetitions,
         comparison_target_bytes=target, lifecycle=lifecycle,
         payload_bytes=request['workload']['payload_bytes'], window=request['workload']['window'],
         limitations=LIMITATIONS)
    results = []
    for index in range(repetitions):
        order = ('python', 'rust') if index % 2 == 0 else ('rust', 'python')
        for name in order:
            validate_client(request)
            results.append(await run_one(commands[name], request, name, index + 1, 'comparison'))
    if lifecycle:
        lifecycle_request = copy.deepcopy(request)
        work = lifecycle_request['workload']
        work.update(latency_packets=1, throughput_bytes=0, renewal_soak_s=150,
                    renewals=1, recovery=True, run_timeout_s=300)
        for name in ('python', 'rust'):
            validate_client(lifecycle_request)
            results.append(await run_one(commands[name], lifecycle_request, name, 1, 'lifecycle'))
    summary(results)
    return 0 if all(row['successful'] for row in results) else 1


def main():
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('--source-root', required=True)
        parser.add_argument('--dependency-root', required=True)
        parser.add_argument('--rust-bin', required=True)
        return asyncio.run(run(parser.parse_args()))
    except (Exception, KeyboardInterrupt):
        emit('error', code='benchmark_failed')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
