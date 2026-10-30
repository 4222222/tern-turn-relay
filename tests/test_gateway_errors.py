"""Typed control failures stay sanitized, bounded and fail closed; no real SSH."""
import asyncio
import base64
from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import gateway_client as client
import remote_gateway as remote
from relay_config import RelayError


def response_process(raw):
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    return SimpleNamespace(stdout=reader)


class FailureCodes(unittest.TestCase):
    def test_code_sets_match_remote_and_unknown_is_always_fatal(self):
        self.assertEqual(client.FAILURE_REASONS, remote.FAILURE_REASONS)
        for reason in (None, '', 'provider-secret', [], {}, 1, True):
            with self.subTest(reason=reason):
                error = client.GatewayControlError(reason)
                self.assertEqual(error.reason, 'unknown')
                self.assertFalse(error.recoverable)
                self.assertNotIn('provider-secret', str(error))
        for reason in client.FAILURE_REASONS:
            error = client.GatewayControlError(reason)
            self.assertEqual(error.reason, reason)
            self.assertEqual(error.recoverable, reason in client.RECOVERABLE_REASONS)
            self.assertIsInstance(error, RelayError)

    def test_remote_error_envelope_never_uses_exception_text(self):
        for error in (ValueError('private-provider-data'),
                      remote.GatewayError('private-provider-data'),
                      remote.GatewayError('private-provider-data', 'state_lock_busy'),
                      remote.GatewayError('private-provider-data', 'private-provider-data')):
            value = remote.error_response(error)
            self.assertFalse(value['ok'])
            self.assertIn(value['reason'], client.FAILURE_REASONS)
            self.assertNotIn('private-provider-data', json.dumps(value))
        self.assertEqual(remote.error_response(
            remote.GatewayError('ignored', 'state_lock_busy'))['reason'], 'state_lock_busy')


class ReceiveFailures(unittest.IsolatedAsyncioTestCase):
    async def test_eof_is_distinct_from_invalid_or_partial_protocol(self):
        cases = [(b'', 'control_eof', True),
                 (b'{', 'protocol_error', False),
                 (b'not-json\n', 'protocol_error', False),
                 (b'\xff\n', 'protocol_error', False),
                 (b'[]\n', 'protocol_error', False),
                 (b'{"ok":1}\n', 'protocol_error', False),
                 (b'{"reason":"frontend_exit"}\n', 'protocol_error', False),
                 (b'x' * (client.MAX_LINE + 1) + b'\n', 'protocol_error', False)]
        for raw, reason, recoverable in cases:
            with self.subTest(reason=reason, prefix=raw[:20]):
                with self.assertRaises(client.GatewayControlError) as caught:
                    await client._receive(response_process(raw))
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(caught.exception.recoverable, recoverable)

    async def test_remote_reason_allowlist_ignores_untrusted_messages_and_flags(self):
        cases = [(reason, reason in client.RECOVERABLE_REASONS)
                 for reason in client.FAILURE_REASONS]
        cases += [(None, False), ('private-provider-data', False), ({}, False), ([], False)]
        for reason, recoverable in cases:
            value = {'ok': False, 'error': 'private-provider-data',
                     'recoverable': True, 'reason': reason}
            with self.subTest(reason=reason):
                with self.assertRaises(client.GatewayControlError) as caught:
                    await client._receive(response_process(json.dumps(value).encode() + b'\n'))
                self.assertEqual(caught.exception.recoverable, recoverable)
                self.assertNotIn('private-provider-data', str(caught.exception))
        with self.assertRaises(client.GatewayControlError) as caught:
            await client._receive(response_process(b'{"ok":false,"recoverable":true}\n'))
        self.assertEqual(caught.exception.reason, 'unknown')
        self.assertFalse(caught.exception.recoverable)

    async def test_send_timeout_and_closed_pipe_are_typed(self):
        for failure, reason in ((asyncio.TimeoutError(), 'send_timeout'),
                                (BrokenPipeError('secret'), 'control_eof'),
                                (ConnectionResetError('secret'), 'control_eof')):
            process = SimpleNamespace(stdin=SimpleNamespace(
                write=mock.Mock(), drain=mock.AsyncMock(side_effect=failure)))
            with self.subTest(reason=reason):
                with self.assertRaises(client.GatewayControlError) as caught:
                    await client._send(process, {'op': 'ping'})
                self.assertEqual(caught.exception.reason, reason)
                self.assertTrue(caught.exception.recoverable)
                self.assertNotIn('secret', str(caught.exception))

    async def test_heartbeat_receive_timeout_is_typed(self):
        gateway = client.GatewayControl({}, Path('/unused'))
        gateway._process = SimpleNamespace(stdout=asyncio.StreamReader())
        with mock.patch.object(client, 'HEARTBEAT_TIMEOUT', 0):
            with self.assertRaises(client.GatewayControlError) as caught:
                await gateway._observe()
        self.assertEqual(caught.exception.reason, 'heartbeat_timeout')
        self.assertTrue(caught.exception.recoverable)

    async def test_invalid_pong_is_fatal(self):
        gateway = client.GatewayControl({}, Path('/unused'))
        gateway._process = response_process(b'{"ok":true,"op":"private-provider-data"}\n')
        with self.assertRaises(client.GatewayControlError) as caught:
            await gateway._observe()
        self.assertEqual(caught.exception.reason, 'protocol_error')
        self.assertFalse(caught.exception.recoverable)
        self.assertNotIn('private-provider-data', str(caught.exception))

    async def test_fresh_open_eof_and_timeout_are_bounded_uncertainty_not_identity(self):
        cases = [(client.GatewayControlError('control_eof'), 'connectivity_uncertain', True),
                 (asyncio.TimeoutError(), 'connectivity_uncertain', True),
                 (client.GatewayControlError('identity_mismatch'), 'identity_mismatch', False),
                 (client.GatewayControlError('authorization_denied'), 'authorization_denied', False),
                 (client.GatewayControlError('state_lock_busy'), 'state_lock_busy', True),
                 (client.GatewayControlError('protocol_error'), 'protocol_error', False),
                 (RelayError('untrusted SSH denial'), 'security_error', False),
                 (ValueError('untrusted detail'), 'unknown', False)]
        for failure, reason, recoverable in cases:
            gateway = client.GatewayControl({}, Path('/unused'))
            with self.subTest(reason=reason), mock.patch.object(
                    gateway, '_open', mock.AsyncMock(side_effect=failure)):
                with self.assertRaises(client.GatewayControlError) as caught:
                    await gateway.open()
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(caught.exception.recoverable, recoverable)
                self.assertNotIn('untrusted', str(caught.exception))
                self.assertIsNone(gateway.peer)
                self.assertIsNone(gateway.key)

    async def test_deploy_eof_reaps_before_open_reports_connectivity_uncertainty(self):
        gateway = client.GatewayControl({
            'ssh_destination': 'test-server',
            'target': {'host': '1.1.1.1', 'fingerprint': 'SHA256:' + 'B' * 42 + 'A'},
            'gateway': {'state_dir': '/private/gateway', 'daemon_socket': '/private/daemon.sock',
                        'fingerprint': 'SHA256:' + 'A' * 43}}, Path('/unused'))
        process = response_process(b'')
        process.stdin = SimpleNamespace(write=mock.Mock(), drain=mock.AsyncMock(), close=mock.Mock())
        with mock.patch.object(client, '_package', return_value={}), \
                mock.patch.object(client, 'resolve_ssh_destination', mock.AsyncMock()), \
                mock.patch.object(client, '_spawn', mock.AsyncMock(return_value=process)), \
                mock.patch.object(client, '_reap', mock.AsyncMock()) as reap:
            with self.assertRaises(client.GatewayControlError) as caught:
                await gateway.open()
        self.assertEqual(caught.exception.reason, 'connectivity_uncertain')
        reap.assert_awaited_once_with(process)
        self.assertIsNone(gateway.key)

    async def test_supervisor_records_real_terminal_cause_and_fatal_wins(self):
        for causes, expected in (
                (('send_timeout', None), 'send_timeout'),
                ((None, 'heartbeat_timeout'), 'heartbeat_timeout'),
                (('send_timeout', 'identity_mismatch'), 'identity_mismatch'),
                ((None, 'unknown'), 'unknown')):
            gateway = client.GatewayControl({}, Path('/unused'))
            gateway.failure = asyncio.get_running_loop().create_future()

            async def failing(reason):
                if reason is None:
                    await asyncio.Future()
                if reason == 'unknown':
                    raise ValueError('private-provider-data')
                raise client.GatewayControlError(reason)

            with mock.patch.object(gateway, '_heartbeat', new=lambda: failing(causes[0])), \
                    mock.patch.object(gateway, '_observe', new=lambda: failing(causes[1])), \
                    mock.patch.object(client, '_reap', mock.AsyncMock()):
                await gateway._supervise()
            self.assertEqual(gateway.failure_reason, expected)
            self.assertEqual(gateway.failure_recoverable, expected in client.RECOVERABLE_REASONS)
            self.assertIsInstance(gateway.failure.result(), str)
            self.assertNotIn('private-provider-data', gateway.failure.result())

    async def test_concurrent_close_does_not_cancel_child_cleanup_twice(self):
        gateway = client.GatewayControl({}, Path('/unused'))
        gateway.failure = asyncio.get_running_loop().create_future()
        process = object()
        gateway._process = process
        started = asyncio.Event()
        cancelling = asyncio.Event()
        release = asyncio.Event()
        cancellation_count = 0

        async def heartbeat():
            nonlocal cancellation_count
            started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancellation_count += 1
                cancelling.set()
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    cancellation_count += 1
                    raise
                raise

        async def observe():
            await started.wait()
            raise client.GatewayControlError('control_eof')

        with mock.patch.object(gateway, '_heartbeat', heartbeat), \
                mock.patch.object(gateway, '_observe', observe), \
                mock.patch.object(client, '_reap', mock.AsyncMock()) as reap:
            gateway._supervisor = asyncio.create_task(gateway._supervise())
            await asyncio.wait_for(cancelling.wait(), 1)
            first = asyncio.create_task(gateway.close())
            second = asyncio.create_task(gateway.close())
            await asyncio.sleep(0)
            release.set()
            await asyncio.wait_for(asyncio.gather(first, second), 1)
        self.assertEqual(cancellation_count, 1)
        reap.assert_awaited_once_with(process)
        self.assertEqual(gateway.failure_reason, 'control_eof')
        self.assertIsNone(gateway._process)


class RemoteFailures(unittest.TestCase):
    def test_state_lock_busy_never_removes_lock_or_touches_other_processes(self):
        request = {'daemon_socket': '/private/daemon.sock', 'bind_host': '1.1.1.1',
                   'session_key': base64.b64encode(b'k' * 32).decode()}
        control = mock.Mock()
        control.initial.return_value = request
        pin = mock.Mock()
        arguments = ['remote_gateway.py', '--state-dir', '/private/gateway', '--serve']
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, 'argv', arguments))
            stack.enter_context(mock.patch.object(remote.os, 'umask'))
            stack.enter_context(mock.patch.object(remote.signal, 'signal'))
            stack.enter_context(mock.patch.object(remote, 'ControlInput', return_value=control))
            stack.enter_context(mock.patch.object(remote, 'DaemonPin', return_value=pin))
            stack.enter_context(mock.patch.object(remote, 'discover_tern', return_value='/private/tern'))
            stack.enter_context(mock.patch.object(remote, 'daemon_environment', return_value={}))
            stack.enter_context(mock.patch.object(remote, 'private_directory', side_effect=lambda path: path))
            stack.enter_context(mock.patch.object(remote, 'private_file', return_value=97))
            stack.enter_context(mock.patch.object(remote.fcntl, 'flock', side_effect=BlockingIOError()))
            close = stack.enter_context(mock.patch.object(remote.os, 'close'))
            unlink = stack.enter_context(mock.patch.object(remote.os, 'unlink'))
            spawn = stack.enter_context(mock.patch.object(remote.subprocess, 'Popen'))
            serve = stack.enter_context(mock.patch.object(remote, 'serve'))
            with self.assertRaises(remote.GatewayError) as caught:
                remote.main()
        self.assertEqual(caught.exception.reason, 'state_lock_busy')
        self.assertTrue(client.GatewayControlError(caught.exception.reason).recoverable)
        close.assert_called_once_with(97)
        unlink.assert_not_called()
        spawn.assert_not_called()
        serve.assert_not_called()
        pin.persist.assert_not_called()

    def test_daemon_identity_change_is_fatal(self):
        pin = object.__new__(remote.DaemonPin)
        pin.path = mock.Mock()
        pin.path.lstat.return_value = SimpleNamespace(
            st_dev=1, st_ino=3, st_mode=stat.S_IFSOCK | 0o600, st_uid=os.getuid())
        pin.socket_identity = (1, 2)
        with self.assertRaises(remote.GatewayError) as caught:
            pin.check()
        self.assertEqual(caught.exception.reason, 'identity_mismatch')
        self.assertFalse(client.GatewayControlError(caught.exception.reason).recoverable)

    def test_unsafe_private_file_remains_fatal(self):
        with mock.patch.object(remote.os, 'open', return_value=97), \
                mock.patch.object(remote.os, 'fstat', return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o644, st_uid=os.getuid(), st_nlink=1)), \
                mock.patch.object(remote.os, 'close') as close:
            with self.assertRaises(remote.GatewayError) as caught:
                remote.private_file(Path('/private/lock'))
        close.assert_called_once_with(97)
        self.assertEqual(caught.exception.reason, 'security_error')
        self.assertFalse(client.GatewayControlError(caught.exception.reason).recoverable)

    def test_remote_frontend_exit_and_heartbeat_expiry_emit_explicit_codes(self):
        for polls, times, reason in (
                ([1], [0], 'frontend_exit'),
                ([None, 1], [0, 0, 1], 'frontend_exit'),
                ([None, None], [0, 0, remote.HEARTBEAT_TIMEOUT + 1], 'heartbeat_timeout')):
            child = mock.Mock(pid=456)
            child.poll.side_effect = polls
            public = mock.MagicMock()
            public.getsockname.return_value = ('1.1.1.1', 45000)
            context = mock.MagicMock()
            context.__enter__.return_value = public
            with self.subTest(reason=reason), ExitStack() as stack:
                stack.enter_context(mock.patch.object(remote.selectors, 'DefaultSelector'))
                stack.enter_context(mock.patch.object(remote.socket, 'socket', return_value=context))
                stack.enter_context(mock.patch.object(remote, 'check_startup_control'))
                stack.enter_context(mock.patch.object(remote, 'owned_loopback_listener', return_value=True))
                stack.enter_context(mock.patch.object(remote.subprocess, 'Popen', return_value=child))
                stack.enter_context(mock.patch.object(remote.time, 'monotonic', side_effect=times))
                stack.enter_context(mock.patch.object(remote, 'emit'))
                reap = stack.enter_context(mock.patch.object(remote, 'reap_owned'))
                with self.assertRaises(remote.GatewayError) as caught:
                    remote.serve('/private/tern', Path('/private/native'), Path('/private/keys'),
                                 {}, mock.Mock(), mock.Mock(), b'k' * 32, '1.1.1.1', {})
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(remote.error_response(caught.exception)['reason'], reason)
                self.assertTrue(client.GatewayControlError(reason).recoverable)
                reap.assert_called_once_with(child)


class StableDaemonIdentity(unittest.TestCase):
    def setUp(self):
        self.state = {
            'start': '1000', 'boot': 'original-boot', 'path': '/trusted/tern',
            'exe_inode': 10, 'exe_device': 2, 'exe_owner': os.getuid(),
            'exe_mode': stat.S_IFREG | 0o755, 'socket_inode': 4,
            'socket_owner': os.getuid(), 'socket_mode': stat.S_IFSOCK | 0o600,
            'peer_pid': 123, 'peer_uid': os.getuid(), 'argv': None,
            'readlink': None, 'mapped': {},
        }

    def kernel(self):
        """Synthetic /proc and peer credentials; no native daemon or sockets."""
        state = self.state

        def text(path, *args, **kwargs):
            if str(path).endswith('/boot_id'):
                return state['boot']
            fields = ['S'] + ['0'] * 18 + [state['start']]
            return '123 (tern daemon) ' + ' '.join(fields)

        def command(path, *args, **kwargs):
            args = state['argv'] or [state['path'], 'daemon', '--socket', '/private/daemon.sock']
            return b'\0'.join(item.encode() for item in args) + b'\0'

        def metadata(path, *args, **kwargs):
            if str(path) == '/private/daemon.sock':
                return SimpleNamespace(st_dev=3, st_ino=state['socket_inode'],
                                       st_uid=state['socket_owner'], st_mode=state['socket_mode'])
            values = dict(st_dev=state['exe_device'], st_ino=state['exe_inode'],
                          st_uid=state['exe_owner'], st_mode=state['exe_mode'], st_nlink=1)
            if str(path) == '/proc/123/exe':
                values.update(state['mapped'])
            return SimpleNamespace(**values)

        opened = {}

        def open_executable(path, flags):
            self.assertEqual(str(path), '/proc/123/exe')
            opened['metadata'] = metadata(path)
            opened['path'] = state['readlink'] or state['path']
            return 97

        def readlink(path):
            self.assertEqual(str(path), '/proc/self/fd/97')
            value = opened['path']
            transition = state.get('after_readlink')
            if transition is not None:
                transition()
            return value

        def fstat(fd):
            self.assertEqual(fd, 97)
            return opened['metadata']

        stack = ExitStack()
        stack.enter_context(mock.patch.object(remote.Path, 'read_text', autospec=True, side_effect=text))
        stack.enter_context(mock.patch.object(remote.Path, 'read_bytes', autospec=True, side_effect=command))
        stack.enter_context(mock.patch.object(remote.Path, 'stat', autospec=True, side_effect=metadata))
        stack.enter_context(mock.patch.object(remote.Path, 'lstat', autospec=True, side_effect=metadata))
        stack.enter_context(mock.patch.object(remote.os, 'open', side_effect=open_executable))
        stack.enter_context(mock.patch.object(remote.os, 'readlink', side_effect=readlink))
        stack.enter_context(mock.patch.object(remote.os, 'fstat', side_effect=fstat))
        stack.enter_context(mock.patch.object(remote.os, 'close'))
        stack.enter_context(mock.patch.object(remote.os, 'access', return_value=True))
        stack.enter_context(mock.patch.object(remote, 'check_ancestors'))
        stack.enter_context(mock.patch.object(remote.socket, 'SO_PEERCRED', 17, create=True))
        connection = stack.enter_context(mock.patch.object(remote.socket, 'socket'))
        connection.return_value.__enter__.return_value.getsockopt.side_effect = (
            lambda *args: struct.pack('3i', state['peer_pid'], state['peer_uid'], 0))
        return stack

    def pin(self):
        pin = object.__new__(remote.DaemonPin)
        pin.path = Path('/private/daemon.sock')
        pin.pid = 123
        pin.socket_identity = (3, 4)
        with self.kernel():
            pin.identity = remote.process_identity(pin.pid, pin.path)
        return pin

    def test_in_place_executable_inode_upgrade_preserves_workspace_binding(self):
        pin = self.pin()
        original = dict(pin.identity)
        self.state['exe_inode'] = 99
        with self.kernel():
            pin.check(responsive=True)
            self.assertEqual(remote.process_identity(pin.pid, pin.path), original)
            self.assertEqual(remote.discover_tern(pin), '/trusted/tern')
        self.assertNotIn('exe_inode', original)
        self.assertNotIn('exe_device', original)

    def test_replacement_before_exec_preserves_binding_with_or_without_deleted_suffix(self):
        for deleted in (False, True):
            with self.subTest(deleted=deleted):
                self.setUp()
                pin = self.pin()
                original = dict(pin.identity)
                self.state['exe_inode'] = 99
                self.state['mapped'] = {'st_ino': 10, 'st_nlink': 0 if deleted else 1}
                if deleted:
                    self.state['readlink'] = '/trusted/tern (deleted)'
                with self.kernel():
                    pin.check(responsive=True)
                    self.assertEqual(remote.process_identity(pin.pid, pin.path), original)
                    self.assertEqual(remote.discover_tern(pin), '/trusted/tern')
                # The same pin also survives the subsequent in-place exec.
                self.state['mapped'] = {}
                self.state['readlink'] = None
                with self.kernel():
                    pin.check(responsive=True)

    def test_exec_between_path_and_metadata_reads_uses_one_executable_handle(self):
        pin = self.pin()
        original = dict(pin.identity)
        self.state['exe_inode'] = 99
        self.state['mapped'] = {'st_ino': 10, 'st_nlink': 0}
        self.state['readlink'] = '/trusted/tern (deleted)'

        def exec_upgrade():
            self.state['mapped'] = {}
            self.state['readlink'] = None
            self.state['after_readlink'] = None

        transition = mock.Mock(side_effect=exec_upgrade)
        self.state['after_readlink'] = transition
        with self.kernel(), mock.patch.object(remote.os, 'close') as close:
            pin.check(responsive=True)
            close.assert_called_once_with(97)
        transition.assert_called_once_with()
        self.assertEqual(pin.identity, original)
        with self.kernel():
            pin.check(responsive=True)

    def test_upgrade_transition_rejects_unsafe_mapped_or_installed_executable(self):
        changes = [
            ('mapped', {'st_ino': 10, 'st_nlink': 0, 'st_uid': os.getuid() + 10000}),
            ('mapped', {'st_ino': 10, 'st_nlink': 0, 'st_mode': stat.S_IFREG | 0o777}),
            ('mapped', {'st_ino': 10, 'st_nlink': 0, 'st_mode': stat.S_IFREG | 0o644}),
            ('mapped', {'st_ino': 10, 'st_nlink': 0, 'st_mode': stat.S_IFLNK | 0o755}),
            ('mapped', {'st_ino': 10, 'st_nlink': 1}),
            ('exe_owner', os.getuid() + 10000),
            ('exe_mode', stat.S_IFREG | 0o777),
            ('exe_mode', stat.S_IFLNK | 0o755),
            ('readlink', '/different/tern (deleted)'),
            ('readlink', '/trusted/tern (deleted) (deleted)'),
            ('peer_pid', 124), ('start', '1001'), ('socket_inode', 5),
        ]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                self.setUp()
                pin = self.pin()
                self.state['exe_inode'] = 99
                self.state['mapped'] = {'st_ino': 10, 'st_nlink': 0}
                self.state['readlink'] = '/trusted/tern (deleted)'
                self.state[field] = value
                with self.kernel(), self.assertRaises(remote.GatewayError) as caught:
                    pin.check(responsive=True)
                self.assertFalse(client.GatewayControlError(caught.exception.reason).recoverable)

    def test_changed_process_socket_executable_or_arguments_remain_fatal(self):
        changes = [
            ('peer_pid', 124), ('peer_uid', os.getuid() + 1),
            ('start', '1001'), ('boot', 'different-boot'),
            ('socket_inode', 5), ('socket_owner', os.getuid() + 1),
            ('socket_mode', stat.S_IFSOCK | 0o622),
            ('path', '/other/tern'), ('path', '/trusted/not-tern'),
            ('exe_owner', os.getuid() + 10000),
            ('exe_mode', stat.S_IFREG | 0o777),
            ('exe_mode', stat.S_IFREG | 0o644),
            ('exe_mode', stat.S_IFLNK | 0o755),
            ('argv', ['/trusted/tern', 'daemon', '--socket', '/other/socket']),
            ('argv', ['/trusted/tern', 'remote', '--socket', '/private/daemon.sock']),
            ('argv', ['/trusted/tern', 'daemon', '--socket', '/private/daemon.sock', '--changed']),
        ]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                self.setUp()
                pin = self.pin()
                self.state[field] = value
                with self.kernel(), self.assertRaises(remote.GatewayError) as caught:
                    pin.check(responsive=True)
                self.assertFalse(client.GatewayControlError(caught.exception.reason).recoverable)

    def legacy(self, pin):
        return {
            'pid': pin.pid, 'start_time': pin.identity['start_time'],
            'boot_id': pin.identity['boot_id'], 'daemon_socket': str(pin.path),
            'socket_device': 3, 'socket_inode': 4,
            'exe_device': 2, 'exe_inode': 10,
        }

    def save(self, directory, value):
        path = directory / 'daemon-identity.json'
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def test_legacy_migration_is_one_way_private_and_preserves_unrelated_files(self):
        pin = self.pin()
        legacy = self.legacy(pin)
        self.state['exe_inode'] = 99
        live_check = pin.check

        def validate_live(responsive=False):
            with self.kernel():
                live_check(responsive=responsive)

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = self.save(directory, legacy)
            unrelated = directory / 'keep'
            unrelated.write_bytes(b'original workspace data')
            with mock.patch.object(pin, 'check', side_effect=validate_live) as check:
                pin.persist(directory)
            self.assertEqual(check.call_args_list, [
                mock.call(responsive=True), mock.call(responsive=True)])
            saved = json.loads(path.read_text())
            self.assertEqual(saved, dict(
                pin.identity, version=2, daemon_socket=str(pin.path),
                socket_device=3, socket_inode=4))
            self.assertNotIn('exe_inode', saved)
            self.assertNotIn('exe_device', saved)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(unrelated.read_bytes(), b'original workspace data')
            self.assertEqual({item.name for item in directory.iterdir()},
                             {'daemon-identity.json', 'keep'})
            before = path.read_bytes()
            with mock.patch.object(pin, 'check'), mock.patch.object(remote.os, 'replace') as replace:
                pin.persist(directory)
            replace.assert_not_called()
            self.assertEqual(path.read_bytes(), before)

    def test_new_binding_uses_only_versioned_stable_identity(self):
        pin = self.pin()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with mock.patch.object(pin, 'check'):
                pin.persist(directory)
            path = directory / 'daemon-identity.json'
            self.assertEqual(json.loads(path.read_text()), dict(
                pin.identity, version=2, daemon_socket=str(pin.path),
                socket_device=3, socket_inode=4))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_migration_refuses_changed_stable_fields_and_malformed_records(self):
        pin = self.pin()
        legacy = self.legacy(pin)
        records = [None, [], {}, dict(legacy, unexpected=True),
                   dict(legacy, exe_inode=True), dict(legacy, exe_device=-1),
                   dict(legacy, pid=True), dict(legacy, version=1)]
        for field, value in (('pid', 124), ('start_time', '1001'),
                             ('boot_id', 'different'), ('daemon_socket', '/other/socket'),
                             ('socket_device', 9), ('socket_inode', 9)):
            records.append(dict(legacy, **{field: value}))
        for record in records:
            with self.subTest(record=record), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                path = self.save(directory, record)
                before = path.read_bytes()
                with mock.patch.object(pin, 'check'), self.assertRaises(remote.GatewayError):
                    pin.persist(directory)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual([item.name for item in directory.iterdir()], ['daemon-identity.json'])

    def test_migration_refuses_invalid_json_duplicate_fields_and_failed_live_checks(self):
        pin = self.pin()
        legacy = self.legacy(pin)
        duplicate = json.dumps(legacy)[:-1] + ',"pid":123}'
        for raw in ('{', duplicate, 'x' * 8193):
            with self.subTest(raw=raw[:30]), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                path = self.save(directory, legacy)
                path.write_text(raw)
                with mock.patch.object(pin, 'check'), self.assertRaises(remote.GatewayError):
                    pin.persist(directory)
                self.assertEqual(path.read_text(), raw)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = self.save(directory, legacy)
            before = path.read_bytes()
            with mock.patch.object(pin, 'check', side_effect=remote.GatewayError(
                    'unsafe executable', 'security_error')), self.assertRaises(remote.GatewayError):
                pin.persist(directory)
            self.assertEqual(path.read_bytes(), before)

    def test_versioned_binding_rejects_changed_path_argv_and_unknown_version(self):
        pin = self.pin()
        current = dict(pin.identity, version=2, daemon_socket=str(pin.path),
                       socket_device=3, socket_inode=4)
        for field, value in (('executable_path', '/other/tern'),
                             ('daemon_argv', ['tern', 'daemon']),
                             ('version', 3), ('version', 2.0)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                path = self.save(directory, dict(current, **{field: value}))
                before = path.read_bytes()
                with mock.patch.object(pin, 'check'), self.assertRaises(remote.GatewayError):
                    pin.persist(directory)
                self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
