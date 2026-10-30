"""Gateway generation recovery never carries old keys, codecs or UDP flows forward."""
import asyncio
from copy import deepcopy
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

from gateway_client import GatewayControlError
from gateway_protocol import SERVER_TO_CLIENT, encode_frame
from relay import LocalProtocol, Service
from relay_config import RelayError
from relay_transport import TransientTurnError


class GatewayRecovery(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='gateway-recovery-')
        self.config = {
            'credential_file': '/unused', 'listen_port': 18377,
            'ssh_destination': 'test',
            'target': {'name': 'test', 'host': '1.1.1.1', 'port': 8376,
                       'user': 'test', 'fingerprint': 'original'},
            'gateway': {'fingerprint': 'dedicated', 'daemon_socket': '/run/test.sock'},
        }
        self.controls = []
        self.endpoints = []
        self.open_errors = []
        self.open_gate = None
        self.turn_gate = None
        self.turn_error = None
        self.descriptor_change = None
        owner = self

        class Control:
            def __init__(self, config, directory):
                self.config = deepcopy(config)
                self.key = bytes([len(owner.controls) + 1]) * 32
                self.peer = ('192.0.2.4', 49000 + len(owner.controls))
                self.descriptor = {'daemon_pid': 34596, 'fingerprint': 'dedicated',
                                   'daemon_socket': '/run/test.sock'}
                if owner.descriptor_change and owner.controls:
                    self.descriptor.update(owner.descriptor_change)
                self.failure = asyncio.get_running_loop().create_future()
                self.failure_reason = 'unknown'
                self.failure_recoverable = False
                self.closed = False
                self.opened = False
                owner.controls.append(self)

            async def open(self):
                self.opened = True
                if owner.open_gate:
                    await owner.open_gate.wait()
                if owner.open_errors:
                    error = owner.open_errors.pop(0)
                    if error:
                        raise error
                return self.descriptor

            async def close(self):
                self.closed = True
                self.key = None

            def fail(self, reason='control_eof', recoverable=True):
                self.failure_reason = reason
                self.failure_recoverable = recoverable
                self.failure.set_result('Control failed safely.')

        class Provider:
            def __init__(self, turn, mode, peer, receive, codec):
                self.peer, self.receive, self.codec = peer, receive, codec
                self.failure = asyncio.get_running_loop().create_future()
                self.failure_recoverable = False
                self.expires = None
                self.closed = False
                self.sent = []
                owner.endpoints.append(self)

            async def open(self, entries, expires):
                if owner.turn_gate:
                    await owner.turn_gate.wait()
                if owner.turn_error:
                    raise owner.turn_error

            async def send(self, data):
                self.sent.append(self.codec.encode(data))

            async def close(self):
                self.closed = True

        self.patches = [patch('relay.GatewayControl', Control), patch('relay.Endpoint', Provider),
                        patch('relay.GATEWAY_RETRY_DELAYS', (0, 0, 0, 0, 0)),
                        patch('relay.ALLOCATION_RETRY_DELAYS', (0, 0)),
                        patch('relay.ALLOCATION_RECOVERY_COOLDOWN', .01)]
        for patcher in self.patches:
            patcher.start()
        self.service = Service(self.config, Path(self.scratch.name), 'tls', 'test')
        self.old = self.service.gateway
        self.service.gateway_ready = True
        self.service.status.update(ok=True, state='ready', error=None)
        self.service.local = Mock()
        self.service.credentials.get = AsyncMock(return_value=([], None))
        self.service.ssh.open = AsyncMock()
        self.service.ssh.close = AsyncMock()
        self.service.ssh.server = object()
        self.service.ssh.tasks[object()] = Mock()
        self.protocol = LocalProtocol(self.service)
        self.service.gateway_watch = asyncio.create_task(self.service.watch_gateway())
        await asyncio.sleep(0)

    async def asyncTearDown(self):
        self.service.stopping.set()
        self.service.gateway_watch.cancel()
        await asyncio.gather(self.service.gateway_watch, return_exceptions=True)
        flows = list(self.service.flows.values())
        for flow in flows:
            flow.task.cancel()
        await asyncio.gather(*(flow.task for flow in flows), return_exceptions=True)
        await asyncio.gather(*(flow.finish() for flow in flows), return_exceptions=True)
        if self.service.warm:
            await self.service.warm.close()
        await self.service.gateway.close()
        for patcher in reversed(self.patches):
            patcher.stop()
        self.scratch.cleanup()

    async def until(self, predicate):
        deadline = time.monotonic() + 1
        while not predicate():
            if time.monotonic() > deadline:
                self.fail('Gateway recovery did not settle')
            await asyncio.sleep(.001)

    async def flow(self, port=40001):
        address = ('127.0.0.1', port)
        self.protocol.datagram_received(b'first', address)
        await self.until(lambda: address in self.service.flows and
                         self.service.flows[address].endpoint is not None and
                         self.service.flows[address].endpoint.sent)
        return self.service.flows[address]

    async def recovered(self):
        await self.until(lambda: self.service.gateway is not self.old and
                         self.service.snapshot()['state'] == 'ready')

    async def test_forced_eof_rotates_key_and_discards_every_old_codec(self):
        first, second = await self.flow(), await self.flow(40002)
        old_codecs = [first.codec, second.codec]
        old_key = self.old.key
        old_endpoints = [first.endpoint, second.endpoint]
        self.old.fail()
        self.protocol.datagram_received(b'dropped', first.address)
        await self.recovered()
        self.assertTrue(self.old.closed)
        self.assertTrue(all(endpoint.closed for endpoint in old_endpoints))
        self.assertFalse(self.service.flows)
        self.assertNotEqual(self.service.gateway.key, old_key)
        self.assertTrue(all(self.service.warm.codec is not codec for codec in old_codecs))
        new = await self.flow()
        replay = encode_frame(old_key, SERVER_TO_CLIENT, new.codec.flow_id, 1, b'old-key')
        self.assertIsNone(new.codec.decode(replay))
        self.assertEqual(new.codec._sequence, 1)
        self.assertEqual(self.service.snapshot()['gateway_reconnects'], 1)
        self.assertEqual(self.service.snapshot()['gateway_failure_reason'], 'control_eof')
        self.assertFalse(self.service.snapshot()['gateway_recovering'])
        self.assertEqual(self.controls[1].config, self.config)

    async def test_tcp_listener_streams_and_udp_listener_survive_recovery(self):
        streams = dict(self.service.ssh.tasks)
        listener = self.service.ssh.server
        self.old.fail()
        await self.recovered()
        self.assertEqual(self.service.ssh.tasks, streams)
        self.assertIs(self.service.ssh.server, listener)
        self.service.ssh.close.assert_not_awaited()
        self.service.ssh.open.assert_not_awaited()
        self.service.local.close.assert_not_called()

    async def test_no_ready_or_forwarding_before_new_warm_allocation(self):
        self.turn_gate = asyncio.Event()
        self.old.fail()
        await self.until(lambda: len(self.endpoints) == 1)
        self.assertEqual(self.service.snapshot()['state'], 'starting')
        self.assertFalse(self.service.snapshot()['ok'])
        self.service.no_clients_since = 0
        self.protocol.datagram_received(b'drop-during-warmup', ('127.0.0.1', 40001))
        self.assertGreater(self.service.no_clients_since, 0)
        self.assertFalse(self.service.flows)
        self.turn_gate.set()
        await self.recovered()

    async def test_changed_daemon_is_fatal_before_turn_allocation(self):
        self.descriptor_change = {'daemon_pid': 34597}
        self.old.fail()
        await self.service.gateway_watch
        self.assertEqual(len(self.controls), 2)
        self.assertFalse(self.endpoints)
        self.assertTrue(self.controls[-1].closed)
        self.assertEqual(self.service.snapshot()['gateway_failure_reason'], 'identity_mismatch')
        self.assertEqual(self.service.snapshot()['state'], 'error')

    async def test_changed_pin_is_fatal_before_turn_allocation(self):
        self.descriptor_change = {'fingerprint': 'different'}
        self.old.fail()
        await self.service.gateway_watch
        self.assertEqual(len(self.controls), 2)
        self.assertFalse(self.endpoints)
        self.assertEqual(self.service.snapshot()['gateway_failure_reason'], 'identity_mismatch')

    async def test_unknown_open_error_does_not_retry(self):
        self.open_errors = [RelayError('Unknown control failure')]
        self.old.fail()
        await self.service.gateway_watch
        self.assertEqual(len(self.controls), 2)
        self.assertEqual(self.service.snapshot()['state'], 'error')
        self.assertEqual(self.service.snapshot()['gateway_failure_reason'], 'unknown')

    async def test_typed_fatal_open_error_does_not_retry(self):
        self.open_errors = [GatewayControlError('authorization_denied')]
        self.old.fail()
        await self.service.gateway_watch
        self.assertEqual(len(self.controls), 2)
        self.assertEqual(self.service.snapshot()['gateway_failure_reason'], 'authorization_denied')

    async def test_missing_or_unknown_failure_metadata_is_fatal(self):
        self.old.fail(reason='not-allowlisted')
        await self.service.gateway_watch
        self.assertEqual(len(self.controls), 1)
        self.assertEqual(self.service.snapshot()['state'], 'error')
        self.assertEqual(self.service.snapshot()['gateway_failure_reason'], 'unknown')

    async def test_legacy_synthetic_failure_without_flags_is_fatal(self):
        del self.old.failure_recoverable
        del self.old.failure_reason
        self.old.failure.set_result('Synthetic EOF')
        await self.service.gateway_watch
        self.assertEqual(len(self.controls), 1)
        self.assertEqual(self.service.snapshot()['state'], 'error')

    async def test_stop_during_backoff_prevents_spawn(self):
        with patch('relay.GATEWAY_RETRY_DELAYS', (30,) * 5):
            self.old.fail()
            await self.until(lambda: self.old.closed)
            self.service.stopping.set()
            await asyncio.wait_for(self.service.gateway_watch, 1)
        self.assertEqual(len(self.controls), 1)
        self.assertFalse(self.service.gateway_available())
        self.assertNotEqual(self.service.snapshot()['state'], 'ready')

    async def test_stop_during_open_closes_candidate_and_never_publishes_ready(self):
        self.open_gate = asyncio.Event()
        self.old.fail()
        await self.until(lambda: len(self.controls) == 2 and self.controls[1].opened)
        self.service.stopping.set()
        await asyncio.wait_for(self.service.gateway_watch, 1)
        self.open_gate.set()
        await asyncio.sleep(0)
        self.assertEqual(len(self.controls), 2)
        self.assertTrue(self.controls[1].closed)
        self.assertFalse(self.endpoints)
        self.assertNotEqual(self.service.snapshot()['state'], 'ready')

    async def test_repeated_transient_control_failures_exhaust_five_attempts(self):
        self.open_errors = [GatewayControlError('control_eof') for _ in range(5)]
        self.old.fail()
        await self.service.gateway_watch
        self.assertEqual(len(self.controls), 6)
        self.assertTrue(all(control.closed for control in self.controls))
        self.assertEqual(self.service.snapshot()['gateway_reconnects'], 5)
        self.assertEqual(self.service.snapshot()['state'], 'error')
        self.assertFalse(self.service.snapshot()['gateway_recovering'])

    async def test_transient_turn_exhaustion_keeps_control_and_waits_for_demand(self):
        self.turn_error = TransientTurnError('TURN allocation timed out.')
        self.old.fail()
        await self.until(lambda: len(self.endpoints) == 3 and self.endpoints[-1].closed)
        await self.until(lambda: not self.service.gateway_recovering)
        self.assertEqual(self.service.snapshot()['state'], 'starting')
        self.assertEqual(self.service.snapshot()['recovery_error'], 'TURN allocation timed out.')
        await asyncio.sleep(.02)
        self.assertEqual(len(self.controls), 2)
        self.assertEqual(len(self.endpoints), 3)
        self.turn_error = None
        self.protocol.datagram_received(b'new-demand', ('127.0.0.1', 40001))
        await self.recovered()
        self.assertEqual(len(self.controls), 2)
        self.assertEqual(len(self.endpoints), 4)
        self.assertIsNone(self.service.snapshot()['recovery_error'])

    async def test_control_loss_during_warmup_retries_without_late_ready(self):
        self.turn_gate = asyncio.Event()
        self.old.fail()
        await self.until(lambda: len(self.endpoints) == 1)
        self.controls[1].fail()
        await self.until(lambda: len(self.controls) == 3)
        self.assertTrue(self.endpoints[0].closed)
        self.assertTrue(self.controls[1].closed)
        self.assertEqual(self.service.snapshot()['state'], 'starting')
        self.turn_gate.set()
        await self.recovered()
        self.assertEqual(self.service.snapshot()['gateway_reconnects'], 2)

    async def test_active_udp_demand_and_recovery_prevent_idle_exit(self):
        self.service.ssh.tasks.clear()
        self.service.no_clients_since = time.monotonic() - 1000
        self.assertTrue(self.service.idle_expired(time.monotonic()))
        self.service.gateway_recovering = True
        self.assertFalse(self.service.idle_expired(time.monotonic()))
        self.service.gateway_recovering = False
        self.service.gateway_ready = False
        self.protocol.datagram_received(b'native-demand', ('127.0.0.1', 40001))
        self.assertFalse(self.service.idle_expired(time.monotonic()))
        self.assertFalse(self.service.flows)
        self.assertFalse(self.endpoints)
        self.assertTrue(self.service.idle_expired(time.monotonic() + 121))

    async def test_cancel_during_open_closes_candidate_without_more_attempts(self):
        self.open_gate = asyncio.Event()
        self.old.fail()
        await self.until(lambda: len(self.controls) == 2 and self.controls[1].opened)
        self.service.gateway_watch.cancel()
        await asyncio.gather(self.service.gateway_watch, return_exceptions=True)
        self.open_gate.set()
        await asyncio.sleep(0)
        self.assertTrue(self.controls[1].closed)
        self.assertEqual(len(self.controls), 2)
        self.assertFalse(self.service.gateway_available())
        self.assertNotEqual(self.service.snapshot()['state'], 'ready')

    async def test_stop_during_warmup_closes_pending_allocation(self):
        self.turn_gate = asyncio.Event()
        self.old.fail()
        await self.until(lambda: len(self.endpoints) == 1)
        self.service.stopping.set()
        await asyncio.wait_for(self.service.gateway_watch, 1)
        self.turn_gate.set()
        await asyncio.sleep(0)
        self.assertTrue(self.endpoints[0].closed)
        self.assertTrue(self.controls[1].closed)
        self.assertEqual(len(self.controls), 2)
        self.assertNotEqual(self.service.snapshot()['state'], 'ready')

    async def test_known_fatal_failure_during_warmup_preserves_reason(self):
        self.turn_gate = asyncio.Event()
        self.old.fail()
        await self.until(lambda: len(self.endpoints) == 1)
        self.controls[1].fail('security_error', recoverable=False)
        await self.service.gateway_watch
        self.assertEqual(len(self.controls), 2)
        self.assertEqual(self.service.snapshot()['gateway_failure_reason'], 'security_error')
        self.assertEqual(self.service.snapshot()['state'], 'error')

    async def test_recoverable_code_without_explicit_true_flag_is_fatal(self):
        self.old.fail('control_eof', recoverable='true')
        await self.service.gateway_watch
        self.assertEqual(len(self.controls), 1)
        self.assertEqual(self.service.snapshot()['state'], 'error')

    async def test_startup_loss_and_turn_exhaustion_wait_for_demand_and_both_listeners(self):
        self.service.gateway_watch.cancel()
        await asyncio.gather(self.service.gateway_watch, return_exceptions=True)
        self.service.gateway_ready = False
        self.service.status.update(ok=False, state='starting', error=None)
        self.service.local = None
        self.service.ssh.server = None
        self.service.ssh.tasks.clear()
        self.service.config['dependency_dir'] = '/unused'
        self.turn_gate = asyncio.Event()
        local = Mock()
        ssh_entered, ssh_release = asyncio.Event(), asyncio.Event()
        ssh_destination = {'host': '1.1.1.1', 'port': 22, 'user': 'test'}

        async def open_ssh(*_):
            ssh_entered.set()
            await ssh_release.wait()
            self.service.ssh.server = object()

        self.service.ssh.open.side_effect = open_ssh
        loop = asyncio.get_running_loop()
        with patch('relay.resolve_ssh_destination', AsyncMock(return_value=ssh_destination)), \
                patch('relay.load_aioice', return_value=object()), \
                patch.object(loop, 'create_datagram_endpoint',
                             AsyncMock(return_value=(local, None))) as bind_udp:
            self.service.startup = asyncio.create_task(self.service.initialize())
            await self.until(lambda: len(self.endpoints) == 1)
            self.old.fail()
            await self.until(lambda: len(self.controls) == 2 and len(self.endpoints) == 2)
            self.assertTrue(self.service.startup.cancelled())
            self.assertIs(self.service.local, local)
            self.assertIsNone(self.service.ssh.server)
            self.assertEqual(self.service.snapshot()['state'], 'starting')
            self.turn_error = TransientTurnError('TURN allocation timed out.')
            self.turn_gate.set()
            await self.until(lambda: len(self.endpoints) == 4 and self.endpoints[-1].closed)
            await self.until(lambda: not self.service.gateway_recovering)
            self.assertIs(self.service.local, local)
            self.assertEqual(self.service.snapshot()['state'], 'starting')
            self.service.ssh.open.assert_not_awaited()
            self.turn_error = None
            self.protocol.datagram_received(b'new-native-demand', ('127.0.0.1', 40001))
            await asyncio.wait_for(ssh_entered.wait(), 1)
            self.assertFalse(self.service.flows)
            self.assertEqual(self.service.snapshot()['state'], 'starting')
            self.assertFalse(self.service.snapshot()['ok'])
            ssh_release.set()
            await self.recovered()
            bind_udp.assert_awaited_once()
            self.service.ssh.open.assert_awaited_once_with(
                self.config['listen_port'], ssh_destination)
            self.assertEqual(len(self.controls), 2)


if __name__ == '__main__':
    unittest.main()
