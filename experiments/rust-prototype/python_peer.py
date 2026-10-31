#!/usr/bin/env python3
"""Isolated real-TURN baseline / authenticated UDP echo; secrets arrive on stdin.

Client JSONL v1 is shared with the Rust worker. No credential issuance or SSH is
performed here. --source-root supplies the unchanged production Endpoint and
ClientCodec; --dependency-root supplies its existing pinned aioice installation.
The dedicated event loop pins TURN DNS to connect_ip, retaining host for TLS SNI
and normal certificate verification. stdout contains only allowlisted events.
"""
import argparse
import asyncio
import ipaddress
import json
import logging
import math
from pathlib import Path
import socket
import struct
import sys
import time

LINE_LIMIT = 65536
MAX_THROUGHPUT = 16 * 1024 * 1024
HEADER = struct.Struct('!4sQQ')


def emit(event, **fields):
    print(json.dumps({'event': event, **fields}, separators=(',', ':'), allow_nan=False), flush=True)


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('invalid_request')
    return value


def number(value, minimum, maximum):
    if type(value) not in (int, float) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError('invalid_request')
    return value


def text(value, maximum=4096):
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError('invalid_request')
    return value


def key_bytes(value):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError('invalid_request')
    result = bytes.fromhex(value)
    if len(result) != 32:
        raise ValueError('invalid_request')
    return result


def ipv4(value):
    return str(ipaddress.IPv4Address(text(value, 15)))


def validate_client(request):
    if request.get('version') != 1 or request.get('role') != 'client':
        raise ValueError('invalid_request')
    turn, peer, work = request['turn'], request['peer'], request['workload']
    host = text(turn['host'], 253)
    if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for c in host):
        raise ValueError('invalid_request')
    ipv4(turn['connect_ip'])
    try:
        literal_host = str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        literal_host = None
    if literal_host is not None and literal_host != turn['connect_ip']:
        raise ValueError('turn_ip_mismatch')
    integer(turn['port'], 1, 65535)
    text(turn['username'])
    text(turn['password'])
    number(turn['expires_unix'], time.time() + 30, time.time() + 172800)
    ipv4(peer['host'])
    integer(peer['port'], 1, 65535)
    key_bytes(peer['key_hex'])
    integer(work['payload_bytes'], HEADER.size, 65000)
    integer(work['latency_packets'], 1, 5000)
    if work['latency_packets'] * work['payload_bytes'] > 1024 * 1024:
        raise ValueError('latency_byte_cap')
    integer(work['throughput_bytes'], 0, MAX_THROUGHPUT)
    integer(work['window'], 1, 1024)
    number(work['packet_timeout_s'], 0.05, 10)
    number(work['idle_s'], 0, 30)
    number(work['renewal_soak_s'], 0, 600)
    integer(work['renewals'], 0, 3)
    if type(work['recovery']) is not bool:
        raise ValueError('invalid_request')
    number(work['run_timeout_s'], 1, 900)
    return request


async def read_json(reader):
    raw = await reader.readline()
    if not raw or len(raw) > LINE_LIMIT:
        raise ValueError('invalid_input')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('invalid_input')
    return value


async def receive_stop(reader):
    while True:
        raw = await reader.readline()
        if not raw:
            return 'input_closed'
        if len(raw) > LINE_LIMIT:
            raise ValueError('invalid_input')
        if json.loads(raw) != {'command': 'stop'}:
            raise ValueError('invalid_input')
        return 'explicit_stop'


def percentile(values, quantile):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * quantile) - 1)]


class Client:
    def __init__(self, request, dependency_root):
        from gateway_protocol import ClientCodec
        from relay_transport import Endpoint, load_aioice
        self.Endpoint = Endpoint
        self.turn = load_aioice(dependency_root)
        self.request, self.work = request, request['workload']
        self.codec = ClientCodec(key_bytes(request['peer']['key_hex']))
        self.endpoint = None
        self.next_id = 1
        self.queue = asyncio.Queue(maxsize=self.work['window'] * 2 + 8)
        self.queue_drops = 0
        self.padding = bytes(i % 251 for i in range(self.work['payload_bytes'] - HEADER.size))
        self.original_getaddrinfo = asyncio.get_running_loop().getaddrinfo

    def receive(self, payload):
        try:
            self.queue.put_nowait((time.monotonic_ns(), payload))
        except asyncio.QueueFull:
            self.queue_drops += 1

    async def open(self):
        config, peer = self.request['turn'], self.request['peer']
        loop = asyncio.get_running_loop()
        original = self.original_getaddrinfo

        async def pinned(host, port, *, family=0, type=0, proto=0, flags=0):
            if host.lower() == config['host'].lower():
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                         (config['connect_ip'], port))]
            return await original(host, port, family=family, type=type, proto=proto, flags=flags)

        loop.getaddrinfo = pinned
        self.endpoint = self.Endpoint(self.turn, 'tls', (peer['host'], peer['port']), self.receive, self.codec)
        entries = [{'urls': [f"turns:{config['host']}:{config['port']}?transport=tcp"],
                    'username': config['username'], 'credential': config['password']}]
        await self.endpoint.open(entries, config['expires_unix'])

    async def close(self):
        if self.endpoint is not None:
            await self.endpoint.close()
        asyncio.get_running_loop().getaddrinfo = self.original_getaddrinfo

    def phase(self, phase):
        emit('state', state='phase', phase=phase)

    async def exchange(self, phase, packets, window, report=True):
        self.phase(phase)
        pending = {}
        counters = dict(sent_packets=0, acked_packets=0, acked_bytes=0,
                        timeouts=0, integrity_errors=0, late_packets=0)
        rtts = []
        started = time.monotonic()
        drops_before = self.queue_drops
        timeout_ns = int(self.work['packet_timeout_s'] * 1e9)
        size = self.work['payload_bytes']
        while counters['sent_packets'] < packets or pending:
            self.endpoint._check_usable()
            while counters['sent_packets'] < packets and len(pending) < window:
                packet_id = self.next_id
                self.next_id += 1
                stamp = time.monotonic_ns()
                pending[packet_id] = stamp
                payload = HEADER.pack(b'TTRB', packet_id, stamp) + self.padding
                await self.endpoint.send(payload)
                counters['sent_packets'] += 1
            if not self.queue.empty():
                arrived, payload = self.queue.get_nowait()
            else:
                now = time.monotonic_ns()
                expired = [packet_id for packet_id, stamp in pending.items() if now - stamp >= timeout_ns]
                for packet_id in expired:
                    del pending[packet_id]
                    counters['timeouts'] += 1
                if not pending:
                    continue
                remaining = max(0, (min(pending.values()) + timeout_ns - time.monotonic_ns()) / 1e9)
                try:
                    arrived, payload = await asyncio.wait_for(self.queue.get(), remaining)
                except asyncio.TimeoutError:
                    continue
            if len(payload) != size:
                counters['integrity_errors'] += 1
                continue
            magic, packet_id, stamp = HEADER.unpack_from(payload)
            if magic != b'TTRB' or payload[HEADER.size:] != self.padding:
                counters['integrity_errors'] += 1
                continue
            expected = pending.get(packet_id)
            if expected is None:
                counters['late_packets'] += 1
                continue
            if arrived - expected >= timeout_ns:
                del pending[packet_id]
                counters['timeouts'] += 1
                counters['late_packets'] += 1
                continue
            if stamp != expected:
                counters['integrity_errors'] += 1
                continue
            del pending[packet_id]
            counters['acked_packets'] += 1
            counters['acked_bytes'] += len(payload)
            if phase == 'latency':
                rtts.append((arrived - stamp) / 1e6)
        duration = time.monotonic() - started
        sample = dict(counters, duration_s=duration, sent_bytes=counters['sent_packets'] * size,
                      queue_drops=self.queue_drops - drops_before,
                      loss_packets=counters['sent_packets'] - counters['acked_packets'])
        if phase == 'latency':
            sample.update(p50_ms=percentile(rtts, .5), p95_ms=percentile(rtts, .95))
        elif phase == 'throughput':
            sample.update(throughput_bps=counters['acked_bytes'] * 8 / max(duration, 1e-9),
                          target_bytes=self.work['throughput_bytes'])
        if report:
            emit('sample', phase=phase, **sample)
        return sample

    async def run(self):
        await self.open()
        emit('ready')
        self.phase('idle')
        started = time.monotonic()
        await asyncio.sleep(self.work['idle_s'])
        self.endpoint._check_usable()
        emit('sample', phase='idle', duration_s=time.monotonic() - started)
        await self.exchange('latency', self.work['latency_packets'], 1)
        packets = self.work['throughput_bytes'] // self.work['payload_bytes']
        await self.exchange('throughput', packets, self.work['window'])
        if self.work['renewal_soak_s'] or self.work['renewals']:
            self.phase('renewal')
            before = self.endpoint.refresh_count
            started = time.monotonic()
            while True:
                self.endpoint._check_usable()
                remaining = self.work['renewal_soak_s'] - (time.monotonic() - started)
                if remaining <= 0:
                    break
                await asyncio.sleep(min(.2, remaining))
            count = self.endpoint.refresh_count - before
            emit('sample', phase='renewal', duration_s=time.monotonic() - started,
                 successful_renewals=count, required_renewals=self.work['renewals'],
                 success=int(count >= self.work['renewals']))
        if self.work['recovery']:
            self.phase('recovery')
            started = time.monotonic()
            self.endpoint.native.abort()
            await asyncio.wait_for(asyncio.shield(self.endpoint.failure), 3)
            detection_ms = (time.monotonic() - started) * 1000
            await self.endpoint.close()
            while not self.queue.empty():
                self.queue.get_nowait()
            await self.open()
            sample = await self.exchange('recovery', 1, 1, report=False)
            emit('sample', phase='recovery', **sample,
                 detection_ms=detection_ms, recovery_ms=(time.monotonic() - started) * 1000,
                 success=int(sample['acked_packets'] == 1))
        emit('done')


class Echo(asyncio.DatagramProtocol):
    def __init__(self, request, exhausted):
        from gateway_protocol import CLIENT_TO_SERVER, SERVER_TO_CLIENT, ReplayWindow, decode_frame, encode_frame
        self.decode, self.encode, self.ReplayWindow = decode_frame, encode_frame, ReplayWindow
        self.incoming, self.outgoing = CLIENT_TO_SERVER, SERVER_TO_CLIENT
        self.key = key_bytes(request['key_hex'])
        self.max_bytes = integer(request['max_bytes'], 1, 128 * 1024 * 1024)
        self.exhausted = exhausted
        self.flows = {}
        self.transport = None
        self.counts = dict(echoed_packets=0, echoed_bytes=0, rejected_packets=0, replay_rejections=0,
                           flow_limit_rejections=0, socket_errors=0)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if self.exhausted.is_set():
            return
        decoded = self.decode(self.key, self.incoming, data)
        if decoded is None:
            self.counts['rejected_packets'] += 1
            return
        flow, sequence, payload = decoded
        if flow not in self.flows:
            if len(self.flows) >= 64:
                self.counts['flow_limit_rejections'] += 1
                return
            self.flows[flow] = [self.ReplayWindow(), 0]
        state = self.flows[flow]
        if not state[0].accept(sequence):
            self.counts['replay_rejections'] += 1
            return
        if self.counts['echoed_bytes'] + len(payload) > self.max_bytes:
            self.exhausted.set()
            return
        state[1] += 1
        self.transport.sendto(self.encode(self.key, self.outgoing, flow, state[1], payload), address)
        self.counts['echoed_packets'] += 1
        self.counts['echoed_bytes'] += len(payload)
        if self.counts['echoed_bytes'] >= self.max_bytes:
            self.exhausted.set()

    def error_received(self, exc):
        self.counts['socket_errors'] += 1


async def serve_echo(request, reader):
    if request.get('version') != 1 or request.get('role') != 'echo':
        raise ValueError('invalid_request')
    host = ipv4(request['bind_host'])
    advertised = ipv4(request['advertise_host'])
    duration = number(request['max_duration_s'], 1, 3600)
    exhausted = asyncio.Event()
    echo = Echo(request, exhausted)
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: echo, local_addr=(host, 0), family=socket.AF_INET)
    stop = asyncio.create_task(receive_stop(reader))
    budget = asyncio.create_task(exhausted.wait())
    timer = asyncio.create_task(asyncio.sleep(duration))
    try:
        emit('ready', host=advertised, port=transport.get_extra_info('sockname')[1])
        finished, _ = await asyncio.wait((stop, budget, timer), return_when=asyncio.FIRST_COMPLETED)
        reason = stop.result() if stop in finished else 'byte_cap' if budget in finished else 'time_cap'
        emit('sample', phase='echo', **echo.counts)
        emit('state', state=reason)
    finally:
        transport.close()
        for task in (stop, budget, timer):
            task.cancel()
        await asyncio.gather(stop, budget, timer, return_exceptions=True)
    emit('stopped')


async def serve_client(request, reader, dependency_root):
    validate_client(request)
    client = Client(request, dependency_root)
    stop = asyncio.create_task(receive_stop(reader))
    work = asyncio.create_task(asyncio.wait_for(client.run(), request['workload']['run_timeout_s']))
    failed = False
    try:
        finished, _ = await asyncio.wait((stop, work), return_when=asyncio.FIRST_COMPLETED)
        if work in finished:
            try:
                work.result()
            except Exception:
                failed = True
                emit('error', code='workload_failed')
            reason = await asyncio.wait_for(stop, 30)
        else:
            reason = stop.result()
        emit('state', state=reason)
    finally:
        for task in (work, stop):
            if not task.done():
                task.cancel()
        await asyncio.gather(work, stop, return_exceptions=True)
        await client.close()
    emit('stopped')
    return 1 if failed else 0


async def run(args):
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda loop, context: None)
    reader = asyncio.StreamReader(limit=LINE_LIMIT)
    transport, _ = await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    try:
        request = await asyncio.wait_for(read_json(reader), 15)
        if request.get('role') == 'echo':
            await serve_echo(request, reader)
            return 0
        if not args.dependency_root:
            raise ValueError('dependency_root_required')
        return await serve_client(request, reader, args.dependency_root)
    finally:
        transport.close()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid_arguments')


def main():
    logging.disable(logging.CRITICAL)
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('--source-root', required=True)
        parser.add_argument('--dependency-root')
        args = parser.parse_args()
        sys.path.insert(0, str(Path(args.source_root).resolve(strict=True)))
        return asyncio.run(run(args))
    except (Exception, KeyboardInterrupt):
        emit('error', code='peer_failed')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
