"""Exclusive gateway readiness and fail-closed lifecycle at provider seams."""
import asyncio
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from relay import Service, LocalProtocol, START_TIMEOUT
from relay_config import RelayError, atomic_json


class ReadyPublication(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='ttr-ready-')
        self.state = Path(self.scratch.name).resolve()
        self.config = {
            'schema': 3, 'ssh_destination': 'test-ssh',
            'target': {'name': 'test', 'host': '1.1.1.1', 'port': 8376, 'user': 'tester',
                       'fingerprint': 'SHA256:' + 'A' * 43},
            'gateway': {'state_dir': '/home/tester/.tern-gateway',
                        'daemon_socket': '/run/user/1000/tern/daemon.sock',
                        'fingerprint': 'SHA256:' + 'A' * 42 + 'E'},
            'listen_port': 18379, 'credential_file': '/unused', 'dependency_dir': '/unused',
        }
        self.gateway = SimpleNamespace(
            peer=('1.1.1.1', 42817), key=b'g' * 32,
            fingerprint=self.config['gateway']['fingerprint'],
            failure=asyncio.get_running_loop().create_future(),
            open=AsyncMock(), close=AsyncMock())
        with patch('relay.GatewayControl', return_value=self.gateway):
            self.service = Service(self.config, self.state, 'tls', 'current-service')
        self.allocation = SimpleNamespace(
            expires=2000000000, failure=asyncio.get_running_loop().create_future(),
            open=AsyncMock(), send=AsyncMock(), close=AsyncMock(), fail=Mock())
        self.local = Mock()
        self.ssh_endpoint = {'host': '1.1.1.1', 'port': 22, 'user': 'tester'}
        self.open_ssh = AsyncMock()
        self.close_ssh = AsyncMock()
        self.credentials = AsyncMock(return_value=([], 2000000000))
        self.endpoint = Mock(return_value=self.allocation)
        self.patches = [
            patch('relay.resolve_ssh_destination', new=AsyncMock(return_value=self.ssh_endpoint)),
            patch('relay.load_aioice', return_value=object()),
            patch.object(self.service.ssh, 'open', self.open_ssh),
            patch.object(self.service.ssh, 'close', self.close_ssh),
            patch.object(self.service.credentials, 'get', self.credentials),
            patch.object(self.service, 'endpoint', self.endpoint),
            patch.object(asyncio.get_running_loop(), 'create_datagram_endpoint',
                         new=AsyncMock(return_value=(self.local, None))),
        ]
        for patcher in self.patches:
            patcher.start()
        atomic_json(self.state / 'status.json', self.service.snapshot())

    async def asyncTearDown(self):
        tasks = [task for task in (self.service.startup, self.service.gateway_watch) if task]
        tasks.extend(flow.task for flow in self.service.flows.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for patcher in reversed(self.patches):
            patcher.stop()
        self.scratch.cleanup()

    def published(self):
        return json.loads((self.state / 'status.json').read_text())

    async def test_ready_is_published_after_gateway_turn_and_both_listeners(self):
        order = []
        self.gateway.open.side_effect = lambda: order.append('gateway')
        self.allocation.open.side_effect = lambda *_: order.append('turn')
        self.open_ssh.side_effect = lambda *_: order.append('ssh')
        await self.service.initialize()
        self.assertEqual(order, ['gateway', 'turn', 'ssh'])
        self.open_ssh.assert_awaited_once_with(self.config['listen_port'], self.ssh_endpoint)
        published = self.published()
        self.assertEqual(published['state'], 'ready')
        self.assertTrue(published['ok'])
        self.assertEqual(published['service_id'], 'current-service')
        self.assertEqual(published['target'], self.config['target'])
        self.assertEqual(published['relay_fingerprint'], self.gateway.fingerprint)
        self.assertEqual(published['daemon_socket'], self.config['gateway']['daemon_socket'])
        self.assertEqual(published['route_policy'], 'exclusive')
        self.assertNotIn('key', published)
        self.assertEqual(START_TIMEOUT, 90)

    async def test_gateway_verification_blocks_turn_and_ready_publication(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def open_gateway():
            entered.set()
            await release.wait()
        self.gateway.open.side_effect = open_gateway
        self.service.startup = asyncio.create_task(self.service.initialize())
        await entered.wait()
        self.credentials.assert_not_awaited()
        self.endpoint.assert_not_called()
        self.assertEqual(self.published()['state'], 'starting')
        release.set()
        await self.service.startup
        self.assertEqual(self.published()['state'], 'ready')

    async def test_unverified_gateway_never_allocates_turn_or_becomes_ready(self):
        self.gateway.open.side_effect = RelayError('Dedicated gateway fingerprint mismatch.')
        await self.service.initialize()
        self.endpoint.assert_not_called()
        self.credentials.assert_not_awaited()
        self.open_ssh.assert_not_awaited()
        self.assertEqual(self.service.snapshot()['state'], 'error')
        self.assertFalse(self.service.gateway_available())
        self.assertTrue(self.service.stopping.is_set())

    async def test_gateway_failure_cancels_udp_and_preserves_independent_ssh(self):
        await self.service.initialize()
        blocked = asyncio.Event()
        entered = asyncio.Event()
        async def send(_):
            entered.set()
            await blocked.wait()
        self.allocation.send.side_effect = send
        protocol = LocalProtocol(self.service)
        protocol.datagram_received(b'inner-payload', ('127.0.0.1', 42001))
        await entered.wait()
        flow = self.service.flows[('127.0.0.1', 42001)]
        self.gateway.failure.set_result('control ended')
        # Reject traffic immediately, even before the monitor gets scheduled.
        protocol.datagram_received(b'never-forward', ('127.0.0.1', 42001))
        protocol.datagram_received(b'never-new-flow', ('127.0.0.1', 42002))
        await self.service.gateway_watch
        self.assertTrue(flow.task.done())
        self.assertEqual(self.service.flows, {})
        self.local.close.assert_called_once()
        self.close_ssh.assert_not_awaited()
        self.assertFalse(self.service.stopping.is_set())
        self.gateway.close.assert_awaited_once()
        self.assertEqual(self.published()['state'], 'error')
        self.assertIn('No direct fallback', self.published()['error'])
        self.assertEqual(self.service.snapshot()['bytes_up'], 0)
        self.allocation.send.assert_awaited_once_with(b'inner-payload')

    async def test_counters_measure_inner_payloads_not_gateway_frames(self):
        await self.service.initialize()
        protocol = LocalProtocol(self.service)
        address = ('127.0.0.1', 42001)
        protocol.datagram_received(b'inner-payload', address)
        await asyncio.sleep(0)
        self.allocation.send.assert_awaited_once_with(b'inner-payload')
        self.allocation.receive(b'inner-reply')
        self.local.sendto.assert_called_once_with(b'inner-reply', address)
        snapshot = self.service.snapshot()
        self.assertEqual(snapshot['bytes_up'], len(b'inner-payload'))
        self.assertEqual(snapshot['bytes_down'], len(b'inner-reply'))

    async def test_normal_shutdown_closes_owned_gateway_and_both_listeners(self):
        original_initialize = self.service.initialize
        async def initialize_and_stop():
            await original_initialize()
            self.service.stopping.set()
        loop = asyncio.get_running_loop()
        with patch.object(self.service, 'initialize', side_effect=initialize_and_stop), \
                patch.object(loop, 'add_signal_handler'):
            await self.service.run()
        self.gateway.open.assert_awaited_once()
        self.gateway.close.assert_awaited_once()
        self.allocation.close.assert_awaited_once()
        self.close_ssh.assert_awaited_once()
        self.local.close.assert_called_once()
        self.assertEqual(self.published()['state'], 'stopped')
        self.assertFalse(self.service.gateway_available())

    async def test_gateway_failure_cancels_incomplete_startup_without_ready(self):
        entered = asyncio.Event()
        async def credentials():
            entered.set()
            await asyncio.Event().wait()
        self.credentials.side_effect = credentials
        self.service.startup = asyncio.create_task(self.service.initialize())
        await entered.wait()
        self.gateway.failure.set_result('control ended during startup')
        await self.service.gateway_watch
        self.assertTrue(self.service.startup.cancelled())
        self.endpoint.assert_not_called()
        self.open_ssh.assert_not_awaited()
        self.assertEqual(self.published()['state'], 'error')
        self.assertFalse(self.service.gateway_available())

    async def test_each_endpoint_is_bound_only_to_dedicated_gateway(self):
        self.service.gateway_ready = True
        # Invoke the real factory while the TURN provider seam remains mocked.
        first = Service.endpoint(self.service, lambda _: None)
        second = Service.endpoint(self.service, lambda _: None)
        self.assertEqual(first.peer, self.gateway.peer)
        self.assertNotEqual(first.peer, (self.config['target']['host'], self.config['target']['port']))
        self.assertIsNot(first.codec, second.codec)
        self.gateway.failure.set_result('control ended')
        with self.assertRaises(RelayError):
            Service.endpoint(self.service, lambda _: None)


if __name__ == '__main__':
    unittest.main()
