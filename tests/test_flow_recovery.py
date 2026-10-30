"""Flow-local TURN recovery keeps authenticated gateway identity and bounded demand."""
import asyncio
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from gateway_protocol import SERVER_TO_CLIENT, encode_frame
from relay import LocalProtocol, Service, MAX_PENDING_PACKETS
from relay_config import RelayError
from relay_transport import TransientTurnError


class FlowRecovery(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        config = {
            'credential_file': '/unused', 'listen_port': 18377,
            'ssh_destination': 'test',
            'target': {'name': 'test', 'host': '1.1.1.1', 'port': 8376,
                       'user': 'test', 'fingerprint': 'original'},
            'gateway': {'fingerprint': 'dedicated', 'daemon_socket': '/run/test.sock'},
        }
        self.service = Service(config, Path('/unused'), 'tls', 'test')
        self.key = b'k' * 32
        self.peer = ('192.0.2.4', 49000)
        self.service.gateway = SimpleNamespace(
            peer=self.peer, key=self.key, failure=asyncio.get_running_loop().create_future())
        self.service.gateway_ready = True
        self.service.status.update(ok=True, state='ready', error=None)
        self.service.local = SimpleNamespace(sendto=lambda data, address: None)
        async def credentials():
            return [], None
        self.service.credentials.get = credentials
        self.endpoints = []
        self.open_error = None
        self.open_gate = None
        owner = self

        class Provider:
            def __init__(self, turn, mode, peer, receive, codec):
                self.peer, self.receive, self.codec = peer, receive, codec
                self.failure = asyncio.get_running_loop().create_future()
                self.failure_recoverable = False
                self.refresh_count = 0
                self.expires = None
                self.closed = False
                self.sent = []
                self.send_error = None
                owner.endpoints.append(self)
            async def open(self, entries, expires):
                if owner.open_gate is not None:
                    await owner.open_gate.wait()
                if owner.open_error is not None:
                    raise owner.open_error
            async def send(self, data):
                if self.failure.done():
                    kind = TransientTurnError if self.failure_recoverable else RelayError
                    raise kind(self.failure.result())
                if self.send_error is not None:
                    raise self.send_error
                self.sent.append(self.codec.encode(data))
            async def close(self):
                self.closed = True
            def fail(self, message, recoverable=False):
                self.failure_recoverable = recoverable
                if not self.failure.done():
                    self.failure.set_result(message)
        self.patch = patch('relay.Endpoint', Provider)
        self.patch.start()
        self.delays = patch('relay.ALLOCATION_RETRY_DELAYS', (0, 0))
        self.delays.start()
        self.cooldown = patch('relay.ALLOCATION_RECOVERY_COOLDOWN', .02)
        self.cooldown.start()
        self.protocol = LocalProtocol(self.service)

    async def asyncTearDown(self):
        self.service.stopping.set()
        tasks = [flow.task for flow in self.service.flows.values()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.cooldown.stop()
        self.delays.stop()
        self.patch.stop()

    async def until(self, predicate):
        deadline = time.monotonic() + 1
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail('Flow recovery did not settle')
            await asyncio.sleep(.001)

    async def start_flow(self, port=40001):
        address = ('127.0.0.1', port)
        self.protocol.datagram_received(b'first', address)
        await self.until(lambda: address in self.service.flows
                         and self.service.flows[address].endpoint is not None
                         and self.service.flows[address].endpoint.sent)
        return self.service.flows[address]

    async def test_refresh_failure_preserves_codec_sequence_and_replay(self):
        flow = await self.start_flow()
        old = flow.endpoint
        old.refresh_count = 3
        codec = old.codec
        response = encode_frame(self.key, SERVER_TO_CLIENT, codec.flow_id, 7, b'reply')
        self.assertEqual(codec.decode(response), b'reply')
        old.fail('TURN allocation refresh timed out.', recoverable=True)
        await self.until(lambda: flow.recovering)
        snapshot = self.service.snapshot()
        self.assertEqual(snapshot['state'], 'starting')
        self.assertFalse(snapshot['ok'])
        self.assertEqual(snapshot['recovering_flows'], 1)
        self.assertEqual(snapshot['recovery_error'], 'TURN allocation refresh timed out.')
        await self.until(lambda: flow.endpoint is not None and flow.endpoint is not old)
        self.assertIs(flow.endpoint.codec, codec)
        self.assertIsNone(flow.endpoint.codec.decode(response))
        flow.enqueue(b'after')
        await self.until(lambda: flow.endpoint.sent)
        self.assertEqual(codec._sequence, 2)
        self.assertTrue(old.closed)
        self.assertEqual(self.service.snapshot()['allocation_refreshes'], 3)
        self.assertEqual(self.service.snapshot()['recovering_flows'], 0)
        self.assertEqual(self.service.snapshot()['state'], 'ready')
        self.assertIsNone(self.service.snapshot()['recovery_error'])
        self.assertTrue(all(endpoint.peer == self.peer for endpoint in self.endpoints))
        self.assertNotIn(('1.1.1.1', 8376), [endpoint.peer for endpoint in self.endpoints])

    async def test_healthy_sibling_survives_recovery(self):
        failed = await self.start_flow()
        sibling = await self.start_flow(40002)
        sibling_endpoint = sibling.endpoint
        failed.endpoint.fail('TURN connection lost.', recoverable=True)
        await self.until(lambda: failed.recovering)
        sibling.enqueue(b'healthy')
        await self.until(lambda: len(sibling_endpoint.sent) == 2)
        self.assertIs(sibling.endpoint, sibling_endpoint)
        self.assertFalse(sibling_endpoint.closed)
        self.assertEqual(self.service.snapshot()['state'], 'ready')
        self.assertIsNone(self.service.snapshot()['error'])

    async def test_transient_send_failure_rebuilds_only_affected_flow(self):
        flow = await self.start_flow()
        old = flow.endpoint
        old.send_error = TransientTurnError('TURN send timed out.')
        flow.enqueue(b'lost-udp-packet')
        await self.until(lambda: flow.endpoint is not None and flow.endpoint is not old)
        flow.enqueue(b'recovered')
        await self.until(lambda: flow.endpoint.sent)
        self.assertIs(flow.endpoint.codec, old.codec)
        self.assertTrue(old.closed)
        self.assertEqual(self.service.snapshot()['state'], 'ready')

    async def test_initial_exhaustion_is_demand_driven_and_stop_cancels_wait(self):
        self.open_error = TransientTurnError('TURN allocation timed out.')
        address = ('127.0.0.1', 40001)
        self.protocol.datagram_received(b'initial-demand', address)
        flow = self.service.flows[address]
        await self.until(lambda: len(self.endpoints) == 3 and self.endpoints[-1].closed)
        self.assertEqual(self.service.snapshot()['recovering_flows'], 1)
        self.assertEqual(self.service.snapshot()['state'], 'starting')
        await asyncio.sleep(.04)
        self.assertEqual(len(self.endpoints), 3)
        self.service.stopping.set()
        await asyncio.wait_for(flow.task, 1)
        self.assertEqual(len(self.endpoints), 3)
        self.assertFalse(self.service.flows)

    async def test_expired_allocation_is_not_published_as_ready(self):
        flow = await self.start_flow()
        flow.endpoint.allocation_deadline = time.monotonic() - 1
        self.assertFalse(self.service.snapshot()['ok'])
        self.assertEqual(self.service.snapshot()['state'], 'starting')

    async def test_exhaustion_waits_for_new_demand_and_shared_cooldown(self):
        flow = await self.start_flow()
        old = flow.endpoint
        self.open_error = TransientTurnError('TURN allocation timed out.')
        old.fail('TURN connection lost.', recoverable=True)
        await self.until(lambda: len(self.endpoints) == 4 and self.endpoints[-1].closed)
        await asyncio.sleep(.04)
        self.assertEqual(len(self.endpoints), 4, 'No autonomous nested retry loop')
        self.assertIs(self.service.flows[flow.address], flow)
        self.assertEqual(self.service.status['state'], 'ready')
        self.service.allocation_retry_at = time.monotonic() + .04
        self.service.no_clients_since = 0
        for _ in range(MAX_PENDING_PACKETS * 2):
            self.protocol.datagram_received(b'demand', flow.address)
        self.protocol.datagram_received(b'new-client', ('127.0.0.1', 40003))
        self.assertGreater(self.service.no_clients_since, 0)
        self.assertLessEqual(flow.queue.qsize(), MAX_PENDING_PACKETS)
        newcomer = self.service.flows[('127.0.0.1', 40003)]
        self.assertEqual(self.service.snapshot()['recovering_flows'], 2)
        await asyncio.sleep(.01)
        self.assertEqual(len(self.endpoints), 4)
        self.open_error = None
        await self.until(lambda: flow.endpoint is not None and newcomer.endpoint is not None)
        self.assertIs(flow.endpoint.codec, old.codec)
        self.assertEqual(len(self.endpoints), 6)

    async def test_warm_failure_admits_queued_new_client_during_cooldown(self):
        warm = self.service.endpoint(lambda data: None)
        self.service.warm = warm
        warm.fail('Warm TURN allocation refresh timed out.', recoverable=True)
        self.service.allocation_retry_at = time.monotonic() + .04
        self.service.no_clients_since = 0
        address = ('127.0.0.1', 40001)
        self.protocol.datagram_received(b'new-client', address)
        self.assertIn(address, self.service.flows)
        flow = self.service.flows[address]
        self.assertGreater(self.service.no_clients_since, 0)
        self.assertEqual(self.service.snapshot()['recovering_flows'], 1)
        self.assertEqual(self.service.snapshot()['state'], 'starting')
        self.assertFalse(self.service.snapshot()['ok'])
        await self.until(lambda: warm.closed)
        self.assertEqual(self.service.snapshot()['recovery_error'],
                         'Warm TURN allocation refresh timed out.')
        await asyncio.sleep(.01)
        self.assertEqual(len(self.endpoints), 1, 'Cooldown must prevent allocation requests')
        self.assertEqual(flow.queue.qsize(), 1)
        await self.until(lambda: flow.endpoint is not None and flow.endpoint.sent)
        self.assertIs(flow.endpoint.codec, warm.codec)
        self.assertEqual(self.service.snapshot()['recovering_flows'], 0)
        self.assertEqual(self.service.snapshot()['state'], 'ready')

    async def test_stop_during_cooldown_never_reopens(self):
        flow = await self.start_flow()
        self.service.allocation_retry_at = time.monotonic() + 30
        flow.endpoint.fail('TURN connection lost.', recoverable=True)
        await self.until(lambda: flow.recovering)
        self.service.stopping.set()
        await asyncio.wait_for(flow.task, 1)
        self.assertEqual(len(self.endpoints), 1)
        self.assertNotIn(flow.address, self.service.flows)

    async def test_cancel_during_allocation_closes_candidate(self):
        flow = await self.start_flow()
        self.open_gate = asyncio.Event()
        flow.endpoint.fail('TURN connection lost.', recoverable=True)
        await self.until(lambda: len(self.endpoints) == 2)
        flow.task.cancel()
        await flow.task
        self.assertTrue(all(endpoint.closed for endpoint in self.endpoints))
        self.open_gate.set()
        await asyncio.sleep(.03)
        self.assertEqual(len(self.endpoints), 2)

    async def test_gateway_eof_prevents_recovery(self):
        flow = await self.start_flow()
        self.service.allocation_retry_at = time.monotonic() + 30
        flow.endpoint.fail('TURN connection lost.', recoverable=True)
        await self.until(lambda: flow.recovering)
        self.service.gateway.failure.set_result('Gateway EOF')
        await asyncio.wait_for(flow.task, 1)
        self.assertEqual(len(self.endpoints), 1)
        self.assertEqual(self.service.snapshot()['state'], 'error')
        self.assertIn('no direct fallback', self.service.snapshot()['error'])

    async def test_fatal_endpoint_failure_latches_without_reallocation(self):
        flow = await self.start_flow()
        flow.endpoint.fail('TURN authorization rejected.')
        await asyncio.wait_for(flow.task, 1)
        self.assertEqual(len(self.endpoints), 1)
        self.assertEqual(self.service.snapshot()['state'], 'error')
        self.assertEqual(self.service.snapshot()['error'], 'TURN authorization rejected.')
        self.protocol.datagram_received(b'blocked', ('127.0.0.1', 40002))
        self.assertFalse(self.service.flows)

    async def test_fatal_reallocation_failure_is_not_retried(self):
        flow = await self.start_flow()
        self.open_error = RelayError('TURN TLS verification failed.')
        flow.endpoint.fail('TURN connection lost.', recoverable=True)
        await asyncio.wait_for(flow.task, 1)
        self.assertEqual(len(self.endpoints), 2)
        self.assertTrue(self.endpoints[-1].closed)
        self.assertEqual(self.service.snapshot()['state'], 'error')
        self.assertEqual(self.service.snapshot()['error'], 'TURN TLS verification failed.')
