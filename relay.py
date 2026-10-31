#!/usr/bin/env python3
"""Loopback-only Tern TURN relay. Public CLI: start, resume, status, stop."""
import argparse
import asyncio
import fcntl
import json
import logging
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

from relay_config import RelayError, atomic_json, load_config, lock_file, private_file, public_status, state_directory
from relay_intent import clear_intent, load_resume_mode, save_intent
from relay_transport import CredentialCache, Endpoint, TransientTurnError, load_aioice
from relay_ssh import SshForwarder, resolve_ssh_destination
from gateway_client import GatewayControl, GatewayControlError, FAILURE_REASONS, RECOVERABLE_REASONS
from gateway_protocol import ClientCodec

MAX_FLOWS = 16
MAX_PENDING_PACKETS = 64
MAX_PENDING_BYTES = 256 * 1024
MAX_PAYLOAD = 65000
FLOW_IDLE_SECONDS = 180
NO_CLIENT_SECONDS = 120
START_TIMEOUT = 90
STOP_TIMEOUT = 12
ALLOCATION_RETRY_DELAYS = (2, 5)
ALLOCATION_RECOVERY_COOLDOWN = 30
GATEWAY_RETRY_DELAYS = (2, 5, 15, 30, 30)


def safe_error(exc, fallback='Relay operation failed; check configuration and local permissions.'):
    return str(exc) if isinstance(exc, RelayError) else fallback


def service_locked(directory):
    fd = lock_file(directory / 'service.lock')
    try:
        try:
            # Status readers must coexist; only the daemon holds an exclusive lock.
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(fd)


def ipc(directory, command='status', service_id=None):
    path = directory / 'control.sock'
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise RelayError('Control socket is not an owned private UNIX socket.')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(path))
        client.sendall(json.dumps({'command': command, 'service_id': service_id}).encode() + b'\n')
        data = bytearray()
        while b'\n' not in data:
            block = client.recv(4096)
            if not block or len(data) + len(block) > 16384:
                raise RelayError('Invalid response from local relay control socket.')
            data.extend(block)
    result = json.loads(data.partition(b'\n')[0])
    if not isinstance(result, dict) or not isinstance(result.get('service_id'), str):
        raise RelayError('Invalid local relay service identity.')
    return result


def saved_status(directory, service_id):
    try:
        fd = os.open(str(directory / 'status.json'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            result = json.loads(stream.read(16385))
        if isinstance(result, dict) and result.get('service_id') == service_id:
            return result
    except (OSError, ValueError, UnicodeError):
        pass
    return None


def remove_owned_runtime(path, socket_only=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    expected = stat.S_ISSOCK(info.st_mode) if socket_only else stat.S_ISREG(info.st_mode)
    if not expected or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise RelayError('Unsafe stale runtime artifact; refusing to replace it.')
    path.unlink()


class Flow:
    def __init__(self, service, address, endpoint=None):
        self.service, self.address, self.endpoint = service, address, endpoint
        self.queue = asyncio.Queue(maxsize=MAX_PENDING_PACKETS)
        self.pending_bytes = 0
        self.last_activity = time.monotonic()
        self.closing = False
        self.failure = None
        self.codec = getattr(endpoint, 'codec', None)
        self.recovering = endpoint is None
        self.recovery_error = None
        self.demand = asyncio.Event()
        if endpoint:
            endpoint.receive = self.receive
        self.task = asyncio.create_task(self.run())

    def enqueue(self, data):
        if self.closing:
            return
        self.last_activity = time.monotonic()
        self.demand.set()
        if self.queue.full() or self.pending_bytes + len(data) > MAX_PENDING_BYTES:
            # UDP overload is recoverable packet loss, not a dead allocation.
            self.service.record_queue_drop(len(data))
            return
        self.queue.put_nowait(data)
        self.pending_bytes += len(data)

    def receive(self, data):
        if not self.closing and self.service.local and self.service.gateway_available():
            try:
                self.service.local.sendto(data, self.address)
                self.service.status['bytes_down'] += len(data)
                self.last_activity = time.monotonic()
            except Exception:
                self.fail('Loopback delivery failed; reconnect to recover.')

    def fail(self, message):
        if self.closing or self.failure:
            return
        self.failure = message
        self.service.fail(message)
        self.task.cancel()

    def require_active(self):
        if self.closing or self.service.stopping.is_set():
            raise asyncio.CancelledError()
        self.service.require_gateway()
        if self.service.status['state'] == 'error':
            raise RelayError(self.service.status['error'])

    async def retire_endpoint(self):
        endpoint, self.endpoint = self.endpoint, None
        if endpoint is not None:
            await self.service.close_endpoint(endpoint)

    async def allocate(self):
        self.recovering = True
        while True:
            self.require_active()
            await self.service.wait_for_allocation()
            self.require_active()
            entries, expires = await self.service.credentials.get()
            self.require_active()
            try:
                self.endpoint = await self.service.open_endpoint(
                    self.receive, entries, expires, codec=self.codec)
                self.codec = getattr(self.endpoint, 'codec', self.codec)
                self.require_active()
                self.recovering = False
                self.recovery_error = None
                self.service.recovery_error = None
                return
            except TransientTurnError as exc:
                self.recovery_error = safe_error(exc)
                # open_endpoint owns the only bounded attempt loop. Once it
                # exhausts, only new client demand may start another batch.
                self.service.defer_allocations()
                self.demand.clear()
                await self.wait_for_demand()

    async def wait_for_demand(self):
        demand = asyncio.create_task(self.demand.wait())
        stopped = asyncio.create_task(self.service.stopping.wait())
        try:
            await asyncio.wait((demand, stopped, self.service.gateway.failure),
                               return_when=asyncio.FIRST_COMPLETED)
            self.require_active()
        finally:
            demand.cancel()
            stopped.cancel()
            await asyncio.gather(demand, stopped, return_exceptions=True)

    async def next_packet(self):
        failure = getattr(self.endpoint, 'failure', None)
        if failure is not None and failure.done():
            kind = TransientTurnError if getattr(self.endpoint, 'failure_recoverable', False) else RelayError
            raise kind(failure.result())
        if not self.queue.empty():
            return self.queue.get_nowait()
        if failure is None:
            return await self.queue.get()
        packet = asyncio.create_task(self.queue.get())
        try:
            await asyncio.wait((packet, failure), return_when=asyncio.FIRST_COMPLETED)
            if packet.done():
                return packet.result()
            kind = TransientTurnError if getattr(self.endpoint, 'failure_recoverable', False) else RelayError
            raise kind(failure.result())
        finally:
            if not packet.done():
                packet.cancel()
                await asyncio.gather(packet, return_exceptions=True)

    async def run(self):
        try:
            batch = 0
            while True:
                self.require_active()
                if self.endpoint is None:
                    await self.allocate()
                try:
                    data = await self.next_packet()
                    self.pending_bytes -= len(data)
                    self.require_active()
                    await self.endpoint.send(data)
                except TransientTurnError as exc:
                    self.recovery_error = safe_error(exc)
                    self.recovering = True
                    self.service.defer_allocations()
                    await self.retire_endpoint()
                    continue
                # Counts payload accepted by the actual TURN send operation,
                # not a promise that the remote application received it.
                self.service.status['bytes_up'] += len(data)
                batch += 1
                if batch == 32:
                    # Warm-channel sends need not suspend; share the loop with RX,
                    # other flows, control IPC and allocation refreshes.
                    batch = 0
                    await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass
        except GatewayControlError as exc:
            if not exc.recoverable:
                self.service.fail(safe_error(exc))
        except Exception as exc:
            self.service.fail(safe_error(exc, 'TURN flow failed; disconnect and reconnect to recover.'))
        finally:
            await self.finish()

    async def finish(self):
        if self.closing:
            return
        self.closing = True
        await self.retire_endpoint()
        if self.service.flows.get(self.address) is self:
            del self.service.flows[self.address]
            if not self.service.flows and not self.service.ssh.connections:
                self.service.no_clients_since = time.monotonic()


class LocalProtocol(asyncio.DatagramProtocol):
    def __init__(self, service):
        self.service = service

    def datagram_received(self, data, address):
        service = self.service
        if address[0] != '127.0.0.1' or service.stopping.is_set():
            return
        # Native UDP demand keeps an unavailable route alive without retaining
        # any payload or forwarding through the previous gateway generation.
        service.no_clients_since = time.monotonic()
        service.gateway_demand.set()
        if not service.gateway_available():
            return
        if len(data) > MAX_PAYLOAD:
            service.fail('Oversized UDP payload rejected; no TURN packet was sent.')
            return
        # Demand remains activity even when allocation admission is cooling down.
        service.no_clients_since = time.monotonic()
        flow = service.flows.get(address)
        if flow is None:
            if service.status['state'] != 'ready':
                return
            if len(service.flows) >= MAX_FLOWS:
                # Admission pressure is packet loss, not a permanent service fault.
                # Existing flows keep working; new ones can enter after idle cleanup.
                service.record_queue_drop(len(data))
                return
            warm, service.warm = service.warm, None
            flow = Flow(service, address, warm)
            service.flows[address] = flow
        flow.enqueue(data)

    def error_received(self, exc):
        self.service.fail('Loopback UDP socket reported an asynchronous error.')


class Service:
    def __init__(self, config, directory, mode, identity):
        self.config, self.directory, self.mode = config, directory, mode
        self.status = public_status(config, 'starting', mode, identity)
        self.credentials = CredentialCache(config['credential_file'])
        self.turn = None
        self.gateway = GatewayControl(config, directory)
        self.gateway_ready = False
        self.gateway_watch = None
        self.gateway_recovering = False
        self.gateway_reconnects = 0
        self.gateway_failure_reason = None
        self.gateway_descriptor = None
        self.gateway_demand = asyncio.Event()
        self.ssh_destination = None
        self.local = None
        self.control = None
        self.control_tasks = set()
        self.flows = {}
        self.ssh = SshForwarder(self.fail, self.ssh_connections_changed,
                                lambda: not self.stopping.is_set())
        self.warm = None
        self.stopping = asyncio.Event()
        self.startup = None
        self.renewal = None
        self.no_clients_since = time.monotonic()
        self.last_queue_drop = None
        self.allocation_retry_at = 0.0
        self.allocation_refreshes = 0
        self.recovery_error = None

    def snapshot(self):
        result = dict(self.status)
        result['flows'] = len(self.flows)
        result['gateway_recovering'] = self.gateway_recovering
        result['gateway_reconnects'] = self.gateway_reconnects
        result['gateway_failure_reason'] = self.gateway_failure_reason
        result['ssh_connections'] = self.ssh.connections
        result['queued_packets'] = sum(flow.queue.qsize() for flow in self.flows.values())
        result['queued_bytes'] = sum(flow.pending_bytes for flow in self.flows.values())
        result['congested'] = self.last_queue_drop is not None and time.monotonic() - self.last_queue_drop < 5
        endpoints = [flow.endpoint for flow in self.flows.values() if flow.endpoint]
        if self.warm:
            endpoints.append(self.warm)
        result['allocation_refreshes'] = getattr(self, 'allocation_refreshes', 0) + sum(
            getattr(endpoint, 'refresh_count', 0) for endpoint in endpoints)
        result['recovering_flows'] = sum(
            bool(getattr(flow, 'recovering', False) or
                 (getattr(flow.endpoint, 'failure_recoverable', False) and
                  flow.endpoint.failure.done())) for flow in self.flows.values())
        usable = any(not getattr(endpoint, 'closing', False) and
                     not (getattr(endpoint, 'failure', None) is not None and endpoint.failure.done()) and
                     (getattr(endpoint, 'allocation_deadline', None) is None or
                      endpoint.allocation_deadline > time.monotonic()) for endpoint in endpoints)
        usable = usable and self.gateway_available() and not self.stopping.is_set()
        result['recovery_error'] = next(
            (getattr(flow, 'recovery_error', None) for flow in self.flows.values()
             if getattr(flow, 'recovering', False) and getattr(flow, 'recovery_error', None)),
            getattr(self, 'recovery_error', None) if not usable else None)
        if result['state'] in ('error', 'stopped'):
            result['recovery_error'] = None
        if result['state'] == 'ready' and not usable:
            result.update(ok=False, state='starting', error=None)
        expiries = [flow.endpoint.expires for flow in self.flows.values() if flow.endpoint and flow.endpoint.expires]
        if self.warm and self.warm.expires:
            expiries.append(self.warm.expires)
        if self.credentials.expires:
            expiries.append(self.credentials.expires)
        result['credentials_expires_at'] = min(expiries) if expiries else None
        return result

    def record_queue_drop(self, size):
        self.status['queue_dropped_packets'] += 1
        self.status['queue_dropped_bytes'] += size
        self.last_queue_drop = time.monotonic()

    def ssh_connections_changed(self):
        if not self.ssh.connections and not self.flows:
            self.no_clients_since = time.monotonic()

    def fail(self, message):
        # Only fatal failures latch. Typed transient TURN failures are handled
        # by the affected flow, without disabling healthy sibling allocations.
        self.status.update(ok=False, state='error', error=message)

    def defer_allocations(self):
        self.allocation_retry_at = max(self.allocation_retry_at,
                                       time.monotonic() + ALLOCATION_RECOVERY_COOLDOWN)

    async def wait_for_allocation(self):
        stopped = asyncio.create_task(self.stopping.wait())
        try:
            while not self.stopping.is_set():
                self.require_gateway()
                delay = self.allocation_retry_at - time.monotonic()
                if delay <= 0:
                    return
                await asyncio.wait((stopped, self.gateway.failure), timeout=delay,
                                   return_when=asyncio.FIRST_COMPLETED)
            raise asyncio.CancelledError()
        finally:
            stopped.cancel()
            await asyncio.gather(stopped, return_exceptions=True)

    async def close_endpoint(self, endpoint):
        self.allocation_refreshes += getattr(endpoint, 'refresh_count', 0)
        await endpoint.close()

    def gateway_available(self):
        failure = getattr(self.gateway, 'failure', None)
        return self.gateway_ready and failure is not None and not failure.done()

    def require_gateway(self):
        if not self.gateway_available():
            if self.gateway_failure(self.gateway)[1]:
                raise GatewayControlError(self.gateway_failure(self.gateway)[0])
            raise RelayError('Exclusive gateway is unavailable; no direct fallback was attempted.')

    def endpoint(self, receive, codec=None):
        self.require_gateway()
        return Endpoint(self.turn, self.mode, self.gateway.peer, receive,
                        codec if codec is not None else ClientCodec(self.gateway.key))

    async def open_endpoint(self, receive, entries, expires, codec=None):
        for attempt in range(len(ALLOCATION_RETRY_DELAYS) + 1):
            if self.stopping.is_set():
                raise asyncio.CancelledError()
            status = getattr(self, 'status', {})
            if status.get('state') == 'error':
                raise RelayError(status['error'])
            endpoint = self.endpoint(receive) if codec is None else self.endpoint(receive, codec)
            codec = getattr(endpoint, 'codec', codec)
            try:
                await endpoint.open(entries, expires)
                if self.stopping.is_set():
                    raise asyncio.CancelledError()
                return endpoint
            except TransientTurnError:
                await endpoint.close()
                if attempt == len(ALLOCATION_RETRY_DELAYS):
                    raise
                # Fresh allocation, same verified gateway; packets stay bounded.
                # Authorization, certificate and gateway failures never enter here.
                try:
                    await asyncio.wait_for(self.stopping.wait(), ALLOCATION_RETRY_DELAYS[attempt])
                except asyncio.TimeoutError:
                    continue
                raise asyncio.CancelledError()
            except BaseException:
                await endpoint.close()
                raise

    @staticmethod
    def gateway_failure(gateway):
        reason = getattr(gateway, 'failure_reason', 'unknown')
        if not isinstance(reason, str) or reason not in FAILURE_REASONS:
            reason = 'unknown'
        recoverable = (getattr(gateway, 'failure_recoverable', False) is True
                       and reason in RECOVERABLE_REASONS)
        return reason, recoverable

    async def retire_gateway(self):
        # Disable the route before the first await. All old codecs/queues die
        # with their flows; only TURN reallocation within a generation reuses one.
        self.gateway_ready = False
        flows = list(self.flows.values())
        for flow in flows:
            flow.task.cancel()
        await asyncio.gather(*(flow.task for flow in flows), return_exceptions=True)
        await asyncio.gather(*(flow.finish() for flow in flows), return_exceptions=True)
        if self.warm:
            warm, self.warm = self.warm, None
            await self.close_endpoint(warm)
        await self.gateway.close()

    def verify_gateway_generation(self):
        previous = self.gateway_descriptor
        current = getattr(self.gateway, 'descriptor', None)
        if (not isinstance(previous, dict) or not isinstance(current, dict)
                or type(previous.get('daemon_pid')) is not int
                or previous['daemon_pid'] <= 0
                or type(current.get('daemon_pid')) is not int
                or current['daemon_pid'] != previous['daemon_pid']
                or current.get('fingerprint') != previous.get('fingerprint')
                or current.get('fingerprint') != self.config['gateway']['fingerprint']
                or current.get('daemon_socket') != previous.get('daemon_socket')
                or current.get('daemon_socket') != self.config['gateway']['daemon_socket']):
            raise GatewayControlError('identity_mismatch')

    async def warm_recovered_gateway(self):
        while True:
            await self.wait_for_allocation()
            entries, expires = await self.credentials.get()
            self.require_gateway()
            try:
                self.warm = await self.open_endpoint(lambda data: None, entries, expires)
                self.require_gateway()
                return
            except TransientTurnError as exc:
                # The control identity remains valid. Do not respawn SSH or nest
                # retry batches: another allocation batch requires new demand.
                self.recovery_error = safe_error(exc)
                self.defer_allocations()
                self.gateway_demand.clear()
                self.gateway_recovering = False
                await self.gateway_demand.wait()
                self.gateway_recovering = True

    async def finish_gateway_recovery(self):
        # Interrupted first startup may not have bound UDP yet. Bind it in
        # demand-only mode before warmup can wait for a new native packet.
        if self.stopping.is_set():
            raise asyncio.CancelledError()
        self.require_gateway()
        if self.local is None:
            self.local, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: LocalProtocol(self), local_addr=('127.0.0.1', self.config['listen_port']),
                family=socket.AF_INET)
        # Race the entire warmup against control loss, including credential and
        # demand waits. Cancellation owns and closes the in-flight allocation.
        warmup = asyncio.create_task(self.warm_recovered_gateway())
        try:
            await asyncio.wait((warmup, self.gateway.failure),
                               return_when=asyncio.FIRST_COMPLETED)
            if self.gateway.failure.done():
                reason, recoverable = self.gateway_failure(self.gateway)
                raise GatewayControlError(
                    reason if recoverable or reason not in RECOVERABLE_REASONS else 'unknown')
            await warmup
        finally:
            if not warmup.done():
                warmup.cancel()
            await asyncio.gather(warmup, return_exceptions=True)
        if self.stopping.is_set():
            raise asyncio.CancelledError()
        self.require_gateway()
        # Existing TCP listeners and streams are never reopened or closed.
        if self.ssh.server is None:
            await self.ssh.open(self.config['listen_port'], self.ssh_destination)
        if self.stopping.is_set():
            raise asyncio.CancelledError()
        self.require_gateway()
        if self.status['state'] == 'error':
            raise RelayError(self.status['error'])
        self.recovery_error = None
        self.gateway_recovering = False
        self.status.update(ok=True, state='ready', error=None)
        atomic_json(self.directory / 'status.json', self.snapshot())

    async def recover_gateway(self):
        for delay in GATEWAY_RETRY_DELAYS:
            await asyncio.sleep(delay)
            if self.stopping.is_set():
                raise asyncio.CancelledError()
            self.gateway_recovering = True
            self.gateway_reconnects += 1
            self.gateway = GatewayControl(self.config, self.directory)
            try:
                await self.gateway.open()
                if self.stopping.is_set():
                    raise asyncio.CancelledError()
                self.verify_gateway_generation()
                self.gateway_ready = True
                self.require_gateway()
                await self.finish_gateway_recovery()
                return
            except GatewayControlError as exc:
                self.gateway_failure_reason = exc.reason
                self.recovery_error = safe_error(exc)
                self.gateway_recovering = True
                await self.retire_gateway()
                if exc.recoverable is not True or exc.reason not in RECOVERABLE_REASONS:
                    raise
            except BaseException as exc:
                if isinstance(exc, Exception):
                    self.gateway_failure_reason = 'unknown'
                await self.retire_gateway()
                raise
        raise RelayError('Exclusive gateway recovery exhausted its bounded attempts; no direct fallback was attempted.')

    async def monitor_gateway(self):
        if self.gateway_descriptor is None:
            descriptor = getattr(self.gateway, 'descriptor', None)
            if isinstance(descriptor, dict):
                self.gateway_descriptor = dict(descriptor)
        while not self.stopping.is_set():
            await asyncio.shield(self.gateway.failure)
            reason, recoverable = self.gateway_failure(self.gateway)
            recoverable = recoverable and self.status['state'] != 'error'
            self.gateway_failure_reason = reason
            self.gateway_ready = False
            self.gateway_recovering = recoverable
            if recoverable:
                self.status.update(ok=False, state='starting', error=None)
                self.recovery_error = 'Exclusive gateway control lost; reconnecting the verified route.'
            else:
                self.fail('Exclusive gateway control failed; UDP forwarding is disabled. No direct fallback was attempted.')
            if self.startup and not self.startup.done():
                self.startup.cancel()
                await asyncio.gather(self.startup, return_exceptions=True)
            await self.retire_gateway()
            if not recoverable:
                break
            try:
                await self.recover_gateway()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if isinstance(exc, GatewayControlError):
                    self.gateway_failure_reason = exc.reason
                elif not isinstance(exc, RelayError):
                    self.gateway_failure_reason = 'unknown'
                self.fail(safe_error(exc, 'Exclusive gateway recovery failed; no direct fallback was attempted.'))
                break
        self.gateway_recovering = False
        # Fatal failures preserve the independent TCP path, but need no UDP
        # demand tracking because only explicit stop/start can recover them.
        if self.status['state'] == 'error' and self.local:
            self.local.close()
            self.local = None
        atomic_json(self.directory / 'status.json', self.snapshot())

    async def watch_gateway(self):
        monitor = asyncio.create_task(self.monitor_gateway())
        stopped = asyncio.create_task(self.stopping.wait())
        try:
            await asyncio.wait((monitor, stopped), return_when=asyncio.FIRST_COMPLETED)
            if monitor.done():
                await monitor
        finally:
            monitor.cancel()
            stopped.cancel()
            await asyncio.gather(monitor, stopped, return_exceptions=True)
            self.gateway_recovering = False

    def idle_expired(self, now):
        return ((self.startup is None or self.startup.done())
                and not self.flows and not self.ssh.connections
                and not self.gateway_recovering
                and now - self.no_clients_since >= NO_CLIENT_SECONDS)

    async def handle_control(self, reader, writer):
        task = asyncio.current_task()
        if len(self.control_tasks) >= 8:
            writer.close()
            return
        self.control_tasks.add(task)
        try:
            raw = await asyncio.wait_for(reader.readline(), 2)
            request = json.loads(raw)
            command = request.get('command') if isinstance(request, dict) else None
            if command not in ('status', 'stop', 'identity'):
                return
            if command == 'stop':
                if request.get('service_id') != self.status['service_id']:
                    return
                self.stopping.set()
            result = ({'service_id': self.status['service_id'], 'ssh_endpoint': self.ssh.endpoint,
                       'gateway': dict(self.config['gateway'])}
                      if command == 'identity' else self.snapshot())
            writer.write(json.dumps(result, separators=(',', ':')).encode() + b'\n')
            await asyncio.wait_for(writer.drain(), 2)
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (Exception, asyncio.CancelledError):
                pass
            self.control_tasks.discard(task)

    async def initialize(self):
        try:
            ssh_endpoint = await resolve_ssh_destination(self.config)
            self.ssh_destination = ssh_endpoint
            self.turn = load_aioice(self.config['dependency_dir'])
            await self.gateway.open()
            descriptor = getattr(self.gateway, 'descriptor', None)
            if isinstance(descriptor, dict):
                self.gateway_descriptor = dict(descriptor)
            self.gateway_ready = True
            self.require_gateway()
            self.gateway_watch = asyncio.create_task(self.watch_gateway())
            entries, expires = await self.credentials.get()
            self.warm = self.endpoint(lambda data: None)
            await self.warm.open(entries, expires)
            self.require_gateway()
            self.local, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: LocalProtocol(self), local_addr=('127.0.0.1', self.config['listen_port']), family=socket.AF_INET)
            await self.ssh.open(self.config['listen_port'], ssh_endpoint)
            self.require_gateway()
            self.status.update(ok=True, state='ready', error=None)
            self.no_clients_since = time.monotonic()
            # The UI may read this file immediately after start returns ready.
            atomic_json(self.directory / 'status.json', self.snapshot())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.fail(safe_error(exc, 'Relay startup failed; check dependency directory and loopback port availability.'))
            if not (self.gateway_watch and self.gateway.failure.done()):
                self.stopping.set()

    async def renew_credentials(self):
        try:
            await self.credentials.get(renew=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.fail(safe_error(exc, 'TURN credential renewal failed; disconnect and reconnect to recover.'))

    async def run(self):
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, self.stopping.set)
        try:
            remove_owned_runtime(self.directory / 'control.sock', socket_only=True)
            remove_owned_runtime(self.directory / 'pid.json')
            atomic_json(self.directory / 'pid.json', {'pid': os.getpid(), 'service_id': self.status['service_id']})
            atomic_json(self.directory / 'status.json', self.snapshot())
            self.control = await asyncio.start_unix_server(self.handle_control, path=str(self.directory / 'control.sock'), limit=1024)
            os.chmod(self.directory / 'control.sock', 0o600)
            self.startup = asyncio.create_task(self.initialize())
            while not self.stopping.is_set():
                try:
                    await asyncio.wait_for(self.stopping.wait(), 1)
                except asyncio.TimeoutError:
                    pass
                now = time.monotonic()
                for flow in list(self.flows.values()):
                    if flow.closing:
                        continue
                    if flow.task.done():
                        # Cancellation before the coroutine's first instruction
                        # does not execute its finally block.
                        await flow.finish()
                        continue
                    endpoint = flow.endpoint
                    if (endpoint and endpoint.failure.done() and
                            not getattr(endpoint, 'failure_recoverable', False)):
                        flow.fail(endpoint.failure.result())
                    elif endpoint and endpoint.expires and time.time() >= endpoint.expires - 15:
                        flow.fail('Active TURN credentials are expiring; disconnect and reconnect to recover.')
                    elif now - flow.last_activity >= FLOW_IDLE_SECONDS:
                        flow.task.cancel()
                if self.warm and self.warm.failure.done():
                    if getattr(self.warm, 'failure_recoverable', False):
                        self.recovery_error = self.warm.failure.result()
                        self.defer_allocations()
                    else:
                        self.fail(self.warm.failure.result())
                    warm, self.warm = self.warm, None
                    await self.close_endpoint(warm)
                if self.idle_expired(now):
                    self.stopping.set()
                if (self.status['state'] == 'ready' and self.credentials.expires
                        and time.time() >= self.credentials.expires - 300
                        and now >= self.credentials.retry_at
                        and (self.renewal is None or self.renewal.done())):
                    self.renewal = asyncio.create_task(self.renew_credentials())
                atomic_json(self.directory / 'status.json', self.snapshot())
        except Exception as exc:
            self.fail(safe_error(exc, 'Relay runtime failed; check private runtime directory permissions.'))
        finally:
            self.stopping.set()
            if self.local:
                self.local.close()
                self.local = None
            self.gateway_ready = False
            lifecycle = (self.startup, self.renewal, self.gateway_watch)
            for task in lifecycle:
                if task and not task.done():
                    task.cancel()
            await asyncio.gather(*(task for task in lifecycle if task), return_exceptions=True)
            await self.ssh.close()
            tasks = []
            closing_flows = list(self.flows.values())
            for flow in closing_flows:
                if not flow.closing:
                    flow.task.cancel()
                tasks.append(flow.task)
            if self.warm:
                warm, self.warm = self.warm, None
                tasks.append(asyncio.create_task(self.close_endpoint(warm)))
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.gather(*(flow.finish() for flow in closing_flows), return_exceptions=True)
            await self.gateway.close()
            if self.control:
                self.control.close()
                await self.control.wait_closed()
            for task in list(self.control_tasks):
                task.cancel()
            await asyncio.gather(*list(self.control_tasks), return_exceptions=True)
            self.flows.clear()
            self.warm = None
            self.credentials.entries = None
            self.credentials.expires = None
            if self.status['state'] != 'error':
                self.status.update(ok=True, state='stopped', mode=None, error=None)
            atomic_json(self.directory / 'status.json', self.snapshot())
            remove_owned_runtime(self.directory / 'control.sock', socket_only=True)
            remove_owned_runtime(self.directory / 'pid.json')


def current_status(config, directory):
    if not service_locked(directory):
        return public_status(config)
    try:
        return ipc(directory)
    except Exception:
        return public_status(config, 'error', error='Relay process holds its lock but control IPC is unavailable; do not kill a PID from a stale file.')


def start(config, directory, args):
    lock = lock_file(directory / 'service.lock')
    child = None
    identity = uuid.uuid4().hex
    try:
        ssh_endpoint = asyncio.run(resolve_ssh_destination(config))
        try:
            # Brief readers are not another daemon. Lifecycle writers are already
            # serialized by command.lock; allow in-flight status probes to leave.
            probe_deadline = time.monotonic() + 0.1
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= probe_deadline:
                        raise
                    time.sleep(0.005)
        except BlockingIOError:
            result = current_status(config, directory)
            running_identity = ipc(directory, 'identity')
            if (result['target'] != config['target'] or result['mode'] != args.mode
                    or result['address'] != public_status(config)['address']
                    or result.get('ssh_destination') != config['ssh_destination']
                    or result.get('relay_fingerprint') != config['gateway']['fingerprint']
                    or result.get('daemon_socket') != config['gateway']['daemon_socket']
                    or result.get('route_policy') != 'exclusive'
                    or running_identity.get('gateway') != config['gateway']
                    or running_identity['service_id'] != result['service_id']
                    or running_identity.get('ssh_endpoint') != ssh_endpoint):
                result = dict(result, ok=False, state='error', error='Another target, gateway, port, mode or resolved SSH destination is already running. Disconnect all TURN windows before changing it.')
            elif result['state'] != 'ready':
                result = dict(result, ok=False, state='error', error=result.get('error') or 'Existing relay is not ready. Disconnect before reconnecting.')
            return result
        child = subprocess.Popen(
            [sys.executable, '-E', '-s', '-B', str(Path(__file__).resolve()), '_serve', '--config', str(Path(args.config).absolute()),
             '--state-dir', str(directory), '--mode', args.mode, '--lock-fd', str(lock), '--service-id', identity],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True, pass_fds=(lock,))
        # The child inherits this same flock open-file description. Closing the
        # parent's fd does not unlock the daemon's lifetime lock.
        os.close(lock)
        lock = None
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            result = None
            try:
                result = ipc(directory)
            except Exception:
                pass
            if result and result['service_id'] == identity:
                if result['state'] == 'ready':
                    running_identity = ipc(directory, 'identity')
                    if (result['target'] != config['target']
                            or result['address'] != public_status(config)['address']
                            or result.get('ssh_destination') != config['ssh_destination']
                            or result.get('relay_fingerprint') != config['gateway']['fingerprint']
                            or result.get('daemon_socket') != config['gateway']['daemon_socket']
                            or result.get('route_policy') != 'exclusive'
                            or running_identity.get('gateway') != config['gateway']
                            or running_identity['service_id'] != identity
                            or running_identity.get('ssh_endpoint') != ssh_endpoint):
                        raise RelayError('Relay or SSH config changed during startup; no relay was retained.')
                    return result
                if result['state'] == 'error':
                    raise RelayError(result['error'])
            if child.poll() is not None:
                result = saved_status(directory, identity)
                raise RelayError(result['error'] if result and result.get('error') else 'Relay daemon exited before the exclusive gateway and TURN allocation became ready.')
            time.sleep(0.15)
        raise RelayError('Exclusive gateway or TURN startup timed out; no direct fallback was attempted.')
    except Exception as exc:
        if child is not None:
            # Only the unreaped child created by this invocation is signalled.
            # PID/status files are never used as authority to kill a process.
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
            if not service_locked(directory):
                remove_owned_runtime(directory / 'control.sock', socket_only=True)
                remove_owned_runtime(directory / 'pid.json')
        return public_status(config, 'error', args.mode, identity, safe_error(exc, 'Unable to start the relay daemon.'))
    finally:
        if lock is not None:
            os.close(lock)


def resume(config, directory, args):
    # The caller holds command.lock from reading selection through startup.
    # Absence is an explicit no-op: do not check credentials or resolve SSH.
    mode = load_resume_mode(config, directory)
    if mode is None:
        return current_status(config, directory)
    try:
        private_file(config['credential_file'])
    except OSError:
        raise RelayError('Cannot securely open the management key file.') from None
    args.mode = mode
    # Only explicit start persists intent; recovery cannot undo a later stop.
    return start(config, directory, args)


def stop(config, directory):
    clear_intent(directory)
    if not service_locked(directory):
        remove_owned_runtime(directory / 'control.sock', socket_only=True)
        remove_owned_runtime(directory / 'pid.json')
        return public_status(config)
    try:
        before = ipc(directory)
        ipc(directory, 'stop', before['service_id'])
    except Exception:
        raise RelayError('Cannot reach the live relay control socket; no process was killed using a saved PID.') from None
    deadline = time.monotonic() + STOP_TIMEOUT
    while time.monotonic() < deadline:
        if not service_locked(directory):
            final = saved_status(directory, before['service_id']) or before
            result = dict(final, ok=True, state='stopped', mode=None, flows=0, ssh_connections=0,
                          error=None, service_id=None, credentials_expires_at=None)
            return result
        time.sleep(0.1)
    raise RelayError('Relay shutdown did not finish within 12 seconds; no unrelated process was killed.')


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise RelayError('Invalid command arguments. Use start|resume|status|stop --config PATH --state-dir PATH; start also requires --mode tls|udp.')


def main():
    os.umask(0o077)
    config = None
    directory = None
    try:
        parser = JsonArgumentParser(description=__doc__)
        parser.add_argument('command', choices=('start', 'resume', 'status', 'stop', '_serve'))
        parser.add_argument('--config', required=True)
        parser.add_argument('--state-dir', required=True)
        parser.add_argument('--mode', choices=('tls', 'udp'))
        parser.add_argument('--lock-fd', type=int, help=argparse.SUPPRESS)
        parser.add_argument('--service-id', help=argparse.SUPPRESS)
        args = parser.parse_args()
        if args.command in ('start', '_serve') and args.mode is None:
            raise RelayError('start requires --mode tls or --mode udp.')
        if args.command == 'resume' and args.mode is not None:
            raise RelayError('resume uses only the saved backend mode; --mode is not accepted.')
        if args.command != '_serve' and (args.lock_fd is not None or args.service_id is not None):
            raise RelayError('Private daemon arguments are not valid for public commands.')
        try:
            config = load_config(args.config, check_key=args.command in ('start', '_serve'))
        except RelayError:
            if args.command not in ('stop', 'status'):
                raise
        directory = state_directory(args.state_dir)
        if args.command == '_serve':
            if args.lock_fd is None or not args.service_id or not config:
                raise RelayError('Private daemon invocation requires an inherited service lock.')
            expected = (directory / 'service.lock').stat()
            inherited = os.fstat(args.lock_fd)
            if (expected.st_dev, expected.st_ino) != (inherited.st_dev, inherited.st_ino):
                raise RelayError('Inherited service lock identity mismatch.')
            # A raw private invocation must also acquire exclusive ownership.
            fcntl.flock(args.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            logging.disable(logging.CRITICAL)
            try:
                async def run_service():
                    # Python 3.9 binds Event/Lock at construction time.
                    await Service(config, directory, args.mode, args.service_id).run()
                asyncio.run(run_service())
            finally:
                os.close(args.lock_fd)
            return 0
        if args.command == 'status':
            result = current_status(config, directory)
        else:
            command_lock = lock_file(directory / 'command.lock')
            try:
                try:
                    fcntl.flock(command_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RelayError('Another relay lifecycle command is in progress; wait and retry.') from None
                if args.command == 'start':
                    result = start(config, directory, args)
                    if result['ok'] and result['state'] == 'ready':
                        try:
                            save_intent(config, directory, args.mode)
                        except RelayError as exc:
                            # A reused backend may serve other windows. Do not
                            # stop it merely because persistence failed.
                            result = dict(result, ok=False, state='error', error=str(exc))
                elif args.command == 'resume':
                    result = resume(config, directory, args)
                else:
                    result = stop(config, directory)
            finally:
                os.close(command_lock)
    except Exception as exc:
        result = public_status(config, 'error', error=safe_error(exc))
    resume_mode = None
    if config is not None and directory is not None:
        try:
            resume_mode = load_resume_mode(config, directory)
        except RelayError:
            # Invalid selection disables recovery, not an already-live backend.
            pass
    result = dict(result, resume_mode=resume_mode)
    print(json.dumps(result, separators=(',', ':'), ensure_ascii=True, allow_nan=False))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
