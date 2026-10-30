"""Deterministic execution of Endpoint's owned renewal and cancellation paths."""
import asyncio
from collections import deque
from types import SimpleNamespace
import ssl
import time
import unittest
from unittest.mock import patch

import relay_transport
from gateway_protocol import ClientCodec, SERVER_TO_CLIENT, encode_frame
from relay_config import RelayError
from relay_transport import Endpoint, TransientTurnError


class TransactionTimeout(Exception):
    pass


class TransactionFailed(Exception):
    def __init__(self, code):
        self.response = SimpleNamespace(attributes={'ERROR-CODE': (code, 'private provider detail')})


class Message:
    sequence = 0

    def __init__(self, **kwargs):
        Message.sequence += 1
        self.transaction_id = Message.sequence
        self.attributes = {}


class Native:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.closed = False
        self.writes = []

    def set_write_buffer_limits(self, **kwargs):
        pass

    def is_closing(self):
        return self.closed

    def close(self):
        self.closed = True
        self.endpoint.connection_lost(None)

    abort = close

    def write(self, data):
        self.writes.append(data)


class Protocol:
    def __init__(self, server, **kwargs):
        self.lifetime = kwargs['lifetime']
        self.refresh_task = None
        self.requests = []
        self.actions = deque()
        self.nonce = b'original'

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        pass

    async def connect(self):
        return ('192.0.2.1', 1234)

    async def request_with_retry(self, request):
        self.requests.append((request.transaction_id, self.clock.now, dict(request.attributes)))
        delay, outcome = self.actions.popleft()
        if delay > self.clock.timeout:
            self.clock.now += self.clock.timeout
            raise asyncio.TimeoutError()
        self.clock.now += delay
        if isinstance(outcome, BaseException):
            raise outcome
        return SimpleNamespace(attributes={'LIFETIME': outcome}), None

    async def delete(self):
        # Mirror aioice's second cancellation: close must detach first.
        if self.refresh_task:
            self.refresh_task.cancel()
        self.transport.close()

    async def send_data(self, data, peer):
        self._send(b'\x40\x00\x00\x00' + data)

    def _send(self, data):
        self.transport.write(data)


class Transport:
    def __init__(self, inner):
        self.inner = inner

    async def _connect(self, endpoint):
        await self.inner.connect()
        endpoint.connection_made(self)


class Clock:
    def __init__(self):
        self.now = 0.0
        self.timeout = None
        self.sleeps = []
        self.timeouts = []
        self.on_sleep = None

    async def sleep(self, delay):
        self.sleeps.append(delay)
        if self.on_sleep:
            self.on_sleep(len(self.sleeps))
        self.now += delay

    async def wait_for(self, awaitable, timeout):
        self.timeout = timeout
        self.timeouts.append(timeout)
        return await awaitable

    def patches(self):
        aio = SimpleNamespace(**{name: getattr(asyncio, name) for name in dir(asyncio)})
        aio.sleep, aio.wait_for = self.sleep, self.wait_for
        return (patch.object(relay_transport, 'asyncio', aio),
                patch.object(relay_transport, 'time', SimpleNamespace(monotonic=lambda: self.now, time=time.time)))


class Renewal(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.received = []
        self.clock = Clock()
        turn = SimpleNamespace(TurnClientTcpProtocol=Protocol, TurnClientUdpProtocol=Protocol,
                               TurnTransport=Transport,
                               stun=SimpleNamespace(Message=Message, Method=SimpleNamespace(REFRESH=4),
                                                    Class=SimpleNamespace(REQUEST=0),
                                                    TransactionTimeout=TransactionTimeout,
                                                    TransactionFailed=TransactionFailed))
        self.endpoint = Endpoint(turn, 'tls', ('192.0.2.2', 1234), self.received.append,
                                 ClientCodec(b'k' * 32, flow_id=7))
        native = Native(self.endpoint)

        async def connect(factory, **kwargs):
            protocol = factory()
            protocol.connection_made(native)
            return native, protocol

        loop = asyncio.get_running_loop()
        with patch.object(loop, 'create_connection', connect), patch.object(
                relay_transport, 'time', SimpleNamespace(monotonic=lambda: 0, time=time.time)):
            await self.endpoint.open([{'urls': ['turns:example.invalid:443?transport=tcp'],
                                       'username': 'test', 'credential': 'test'}], time.time() + 3600)
        self.endpoint.inner.clock = self.clock
        self.native = native

    async def asyncTearDown(self):
        await self.endpoint.close()

    async def renew(self, actions, lifetime=120, stop_after=None):
        self.endpoint.inner.actions.extend(actions)
        if stop_after is not None:
            def stop(count):
                if self.endpoint.refresh_count >= stop_after:
                    raise asyncio.CancelledError()
            self.clock.on_sleep = stop
        aio_patch, time_patch = self.clock.patches()
        with aio_patch, time_patch:
            if stop_after is None:
                await self.endpoint.inner.refresh(lifetime)
            else:
                with self.assertRaises(asyncio.CancelledError):
                    await self.endpoint.inner.refresh(lifetime)

    async def test_timeout_retries_fresh_transaction_without_poisoning_allocation(self):
        await self.renew([(11, 120), (2, 120)], stop_after=1)
        requests = self.endpoint.inner.requests
        self.assertEqual([request[1] for request in requests], [60, 71])
        self.assertNotEqual(requests[0][0], requests[1][0])
        self.assertEqual(self.clock.timeouts, [10, 10])
        self.assertEqual(self.endpoint.refresh_count, 1)
        self.assertFalse(self.endpoint.failure.done())
        self.assertEqual(self.endpoint.allocation_deadline, 191)
        _, time_patch = self.clock.patches()
        with time_patch:
            await self.endpoint.send(b'still usable')
        self.assertEqual(len(self.native.writes), 1)

    async def test_returned_lifetime_and_round_trip_bound_next_deadline(self):
        await self.renew([(4, 30), (1, 120)], stop_after=2)
        self.assertEqual([r[1] for r in self.endpoint.inner.requests], [60, 75])
        self.assertEqual(self.clock.timeouts, [10, 2.5])
        self.assertEqual(self.endpoint.allocation_deadline, 195)
        self.assertEqual(self.endpoint.refresh_count, 2)

    async def test_repeated_timeouts_are_bounded_and_recoverable(self):
        await self.renew([(11, 120)] * 3)
        self.assertEqual(len(self.endpoint.inner.requests), 3)
        self.assertTrue(self.endpoint.failure_recoverable)
        with self.assertRaises(TransientTurnError):
            await self.endpoint.send(b'blocked')
        self.assertEqual(self.native.writes, [])

    async def test_delayed_scheduler_cannot_refresh_or_forward_expired_allocation(self):
        self.clock.on_sleep = lambda count: setattr(self.clock, 'now', 120)
        await self.renew([])
        self.assertEqual(self.endpoint.inner.requests, [])
        self.assertTrue(self.endpoint.failure_recoverable)
        with self.assertRaises(TransientTurnError):
            await self.endpoint.send(b'blocked')
        self.endpoint.datagram_received(encode_frame(b'k' * 32, SERVER_TO_CLIENT, 7, 1, b'late'), self.endpoint.peer)
        self.assertEqual(self.received, [])
        self.assertEqual(self.native.writes, [])

    async def test_request_timeout_never_exceeds_remaining_allocation_budget(self):
        self.clock.on_sleep = lambda count: setattr(self.clock, 'now', 59.5)
        await self.renew([(11, 120)])
        self.assertEqual(self.clock.timeouts, [0.5])
        self.assertEqual(len(self.endpoint.inner.requests), 1)
        self.assertEqual(self.clock.now, 120)
        self.assertTrue(self.endpoint.failure_recoverable)

    async def test_server_zero_lifetime_is_recoverable_expiry(self):
        await self.renew([(0, 0)])
        self.assertTrue(self.endpoint.failure_recoverable)
        self.assertEqual(self.endpoint.refresh_count, 0)

    async def test_denied_authentication_never_retries_or_leaks_provider_details(self):
        await self.renew([(0, TransactionFailed(403))])
        self.assertEqual(len(self.endpoint.inner.requests), 1)
        self.assertFalse(self.endpoint.failure_recoverable)
        self.assertNotIn('private', self.endpoint.failure.result())
        with self.assertRaises(RelayError) as raised:
            await self.endpoint.send(b'blocked')
        self.assertNotIsInstance(raised.exception, TransientTurnError)

    async def test_tls_failure_is_not_a_retryable_oserror(self):
        await self.renew([(0, ssl.SSLError('private TLS detail'))])
        self.assertFalse(self.endpoint.failure_recoverable)
        self.assertEqual(len(self.endpoint.inner.requests), 1)

    async def test_allocation_mismatch_requests_reallocation_not_auth_retry(self):
        await self.renew([(0, TransactionFailed(437))])
        self.assertTrue(self.endpoint.failure_recoverable)
        self.assertEqual(len(self.endpoint.inner.requests), 1)

    async def test_nonce_updated_by_protocol_survives_transient_retry(self):
        nonces = []
        protocol = self.endpoint.inner

        async def challenged(request):
            nonces.append(protocol.nonce)
            if len(nonces) == 1:
                # aioice request_with_retry owns 401/438 authentication. Its
                # updated nonce must survive a timeout of that transaction.
                protocol.nonce = b'fresh-nonce'
                raise TransactionTimeout()
            return SimpleNamespace(attributes={'LIFETIME': 120}), None

        protocol.request_with_retry = challenged
        await self.renew([], stop_after=1)
        self.assertEqual(nonces, [b'original', b'fresh-nonce'])
        self.assertEqual(self.endpoint.refresh_count, 1)
        self.assertFalse(self.endpoint.failure.done())

    async def test_response_after_deadline_cannot_resurrect_allocation(self):
        async def late(request):
            self.clock.now = 121
            return SimpleNamespace(attributes={'LIFETIME': 120}), None

        self.endpoint.inner.request_with_retry = late
        await self.renew([])
        self.assertTrue(self.endpoint.failure_recoverable)
        self.assertEqual(self.endpoint.allocation_deadline, 120)
        self.assertEqual(self.endpoint.refresh_count, 0)

    async def test_actual_write_is_blocked_if_channel_binding_outlives_allocation(self):
        self.endpoint.allocation_deadline = 120

        async def delayed_bind(data, peer):
            self.clock.now = 121
            self.endpoint.inner._send(b'\x40\x00\x00\x00' + data)

        self.endpoint.inner.send_data = delayed_bind
        _, time_patch = self.clock.patches()
        with time_patch:
            with self.assertRaises(TransientTurnError):
                await self.endpoint.send(b'late')
        self.assertEqual(self.native.writes, [])

    async def test_transport_close_is_recoverable_but_unspecified_failure_is_fatal(self):
        self.endpoint.connection_lost(None)
        self.assertTrue(self.endpoint.failure_recoverable)
        with self.assertRaises(TransientTurnError):
            await self.endpoint.send(b'closed')
        other = Endpoint(self.endpoint.turn, 'tls', self.endpoint.peer, self.received.append,
                         ClientCodec(b'k' * 32))
        other.fail('Gateway identity failed.')
        self.assertFalse(other.failure_recoverable)
        with self.assertRaises(RelayError) as raised:
            await other.send(b'blocked')
        self.assertNotIsInstance(raised.exception, TransientTurnError)
        await other.close()

    async def test_network_send_failure_latches_recoverable_state(self):
        async def failed(data, peer):
            raise OSError('private transport detail')

        self.endpoint.inner.send_data = failed
        with self.assertRaises(TransientTurnError):
            await self.endpoint.send(b'blocked')
        self.assertTrue(self.endpoint.failure_recoverable)
        self.assertNotIn('private', self.endpoint.failure.result())

    async def test_cancelling_refresh_does_not_latch_failure(self):
        self.clock.on_sleep = lambda count: (_ for _ in ()).throw(asyncio.CancelledError())
        aio_patch, time_patch = self.clock.patches()
        with aio_patch, time_patch:
            with self.assertRaises(asyncio.CancelledError):
                await self.endpoint.inner.refresh(120)
        self.assertFalse(self.endpoint.failure.done())

    async def test_close_cancels_pending_request_once_before_delete(self):
        entered, cancelled, cleanup = asyncio.Event(), asyncio.Event(), asyncio.Event()
        cancellations = []

        async def pending(request):
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancellations.append(1)
                cancelled.set()
                try:
                    await cleanup.wait()
                except asyncio.CancelledError:
                    cancellations.append(2)
                    raise
                raise

        self.endpoint.inner.request_with_retry = pending
        original_sleep = asyncio.sleep
        async def immediate(delay):
            await original_sleep(0)
        aio = SimpleNamespace(**{name: getattr(asyncio, name) for name in dir(asyncio)})
        aio.sleep = immediate
        with patch.object(relay_transport, 'asyncio', aio):
            self.endpoint.inner.refresh_task = asyncio.create_task(self.endpoint.inner.refresh(120))
            # The fixture's initial allocation timestamp is synthetic.
            self.endpoint.allocation_deadline = time.monotonic() + 120
            await asyncio.wait_for(entered.wait(), 1)
            closing = asyncio.create_task(self.endpoint.close())
            try:
                await asyncio.wait_for(cancelled.wait(), 1)
                await original_sleep(0)
            finally:
                cleanup.set()
            await asyncio.wait_for(closing, 1)
        self.assertEqual(cancellations, [1])
        self.assertTrue(self.native.closed)
        self.assertFalse(self.endpoint.failure.done())


if __name__ == '__main__':
    unittest.main()
