"""Offline package-boundary and SSH-owned lifecycle coverage; no real SSH."""
import asyncio
import base64
import copy
import json
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import gateway_client as client
from relay_config import RelayError


def config():
    return {'ssh_destination': 'example-server',
            'target': {'host': '1.1.1.1', 'user': 'tester',
                       'fingerprint': 'SHA256:' + 'B' * 42 + 'A'},
            'gateway': {'state_dir': '/home/tester/private-gateway',
                        'daemon_socket': '/run/user/1000/tern/daemon.sock',
                        'fingerprint': 'SHA256:' + 'A' * 43}}


def descriptor(serving=True):
    value = {'ok': True, 'fingerprint': config()['gateway']['fingerprint'],
             'daemon_socket': config()['gateway']['daemon_socket'], 'daemon_pid': 123,
             'session_ids': ['session'], 'tab_ids': ['tab'], 'pane_ids': ['pane']}
    if serving:
        value.update(host='1.1.1.1', port=45000)
    return value


class ClientBoundaries(unittest.TestCase):
    def test_only_explicit_ssh_alias_and_pinned_runtime_are_accepted(self):
        candidate = config()
        del candidate['gateway']['fingerprint']
        client._settings(candidate, pinned=False)
        with self.assertRaises(RelayError):
            client._settings(candidate, pinned=True)
        candidate['ssh_destination'] = 'other-host'
        client._settings(candidate, pinned=False)
        for alias in ('-oProxyCommand=unsafe', 'user@host', 'host name', ''):
            candidate['ssh_destination'] = alias
            with self.subTest(alias=alias), self.assertRaises(RelayError):
                client._settings(candidate, pinned=False)

    def test_descriptor_rejects_identity_endpoint_and_secret_fields(self):
        for field, value in (
                ('fingerprint', 'SHA256:' + 'B' * 42 + 'A'),
                ('daemon_socket', '/different.sock'), ('daemon_pid', True),
                ('host', '8.8.8.8'), ('port', 22), ('port', True),
                ('session_key', 'secret-not-for-status'), ('pane_ids', ['\x00'])):
            response = descriptor()
            response[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RelayError) as caught:
                client._descriptor(config(), response, serving=True)
            self.assertNotIn('secret-not-for-status', str(caught.exception))
        self.assertEqual(client._descriptor(config(), descriptor(), True), descriptor())
        candidate = config()
        del candidate['gateway']['fingerprint']
        self.assertEqual(client._descriptor(candidate, descriptor(False), False), descriptor(False))

    def test_optional_owned_frontend_pid_is_validated_and_retained(self):
        response = descriptor()
        response['native_frontend_pid'] = 456
        self.assertEqual(client._descriptor(config(), response, True), response)
        for pid in (True, 0, -1, '456', response['daemon_pid']):
            response['native_frontend_pid'] = pid
            with self.subTest(pid=pid), self.assertRaises(RelayError):
                client._descriptor(config(), response, True)

    def test_original_native_identity_is_never_accepted(self):
        for serving in (False, True):
            candidate = config()
            response = descriptor(serving)
            response['fingerprint'] = candidate['target']['fingerprint']
            if serving:
                candidate['gateway']['fingerprint'] = response['fingerprint']
            else:
                del candidate['gateway']['fingerprint']
            with self.subTest(serving=serving), self.assertRaises(RelayError):
                client._descriptor(candidate, response, serving)

    def test_ssh_uses_config_with_strict_no_password_no_forwarding(self):
        command = ['python3', '-B', '/private/a b/helper.py', '--state-dir', "/private/it's safe"]
        argv = client._ssh_argv(config(), command)
        self.assertEqual(argv[-2], 'example-server')
        self.assertEqual(shlex.split(argv[-1]), command)
        for option in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'ForwardAgent=no',
                       'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
                       'ClearAllForwardings=yes', 'ControlPath=none'):
            self.assertIn(option, argv)


class PackageInstallation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='gateway-client-test-')
        self.directory = Path(self.temporary.name).resolve()
        self.module = self.directory / 'source'
        self.module.mkdir(mode=0o700)
        for name in client.MODULES:
            (self.module / name).write_bytes(('source ' + name).encode())
        (self.module / 'unrelated.py').write_text('never upload')
        self.config = config()
        self.config['gateway']['state_dir'] = str(self.directory / 'state')
        with mock.patch.object(client, '__file__', str(self.module / 'gateway_client.py')):
            self.package = client._package(self.config)

    def tearDown(self):
        self.temporary.cleanup()

    def install(self, package=None):
        # Executes only the self-contained installer against a private local fixture.
        result = subprocess.run([sys.executable, '-B', '-c', client._INSTALLER],
                                input=json.dumps(package or self.package).encode(),
                                capture_output=True, timeout=5)
        self.assertEqual(result.stderr, b'')
        return result.returncode, json.loads(result.stdout)

    def test_exact_private_atomic_release_and_idempotence_preserve_other_files(self):
        state = Path(self.config['gateway']['state_dir'])
        state.mkdir(mode=0o700)
        original = state / 'original-service'
        original.write_text('untouched')
        self.assertEqual(set(self.package['files']), set(client.MODULES))
        for _ in range(2):
            status, value = self.install()
            self.assertEqual(status, 0)
            self.assertEqual(value, {'ok': True, 'digest': self.package['digest']})
        release = state / 'releases' / self.package['digest']
        self.assertEqual({entry.name for entry in release.iterdir()}, set(client.MODULES))
        for directory in (state, release.parent, release):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for name in client.MODULES:
            self.assertEqual(stat.S_IMODE((release / name).stat().st_mode), 0o600)
            self.assertEqual((release / name).stat().st_nlink, 1)
            self.assertEqual((release / name).read_bytes(), (self.module / name).read_bytes())
        self.assertEqual(original.read_text(), 'untouched')

    def test_symlink_state_is_rejected_without_modifying_target(self):
        target = self.directory / 'unrelated'
        target.mkdir(mode=0o700)
        Path(self.config['gateway']['state_dir']).symlink_to(target, target_is_directory=True)
        code, result = self.install()
        self.assertNotEqual(code, 0)
        self.assertFalse(result['ok'])
        self.assertEqual(list(target.iterdir()), [])

    def test_release_symlink_and_unsafe_permissions_fail_closed(self):
        self.assertEqual(self.install()[0], 0)
        release = Path(self.config['gateway']['state_dir']) / 'releases' / self.package['digest']
        source = release / client.MODULES[0]
        source.chmod(0o644)
        self.assertNotEqual(self.install()[0], 0)
        source.unlink()
        original = self.directory / 'keep'
        original.write_text('keep')
        source.symlink_to(original)
        self.assertNotEqual(self.install()[0], 0)
        self.assertEqual(original.read_text(), 'keep')

    def test_mismatched_content_hash_rejected_before_state_creation(self):
        package = copy.deepcopy(self.package)
        package['files'][client.MODULES[0]] = base64.b64encode(b'changed').decode()
        self.assertNotEqual(self.install(package)[0], 0)
        self.assertFalse(Path(self.config['gateway']['state_dir']).exists())

    def test_local_module_symlink_is_rejected(self):
        source = self.module / client.MODULES[0]
        source.unlink()
        source.symlink_to(self.module / 'unrelated.py')
        with mock.patch.object(client, '__file__', str(self.module / 'gateway_client.py')):
            with self.assertRaises(OSError):
                client._package(self.config)


class Process:
    def __init__(self, ready=None):
        self.stdout = asyncio.StreamReader()
        self.stdin = self
        self.returncode = None
        self.messages = []
        self.closed = False
        self.reaped = False
        self.done = asyncio.Event()
        self.ping = asyncio.Event()
        if ready is not None:
            self.stdout.feed_data(json.dumps(ready).encode() + b'\n')

    def write(self, raw):
        value = json.loads(raw)
        self.messages.append(value)
        if value == {'op': 'ping'}:
            self.ping.set()
            self.stdout.feed_data(b'{"ok":true,"op":"pong"}\n')

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        self.closed = True
        self.returncode = 0
        self.stdout.feed_eof()
        self.done.set()

    async def wait(self):
        await self.done.wait()
        self.reaped = True
        return self.returncode

    def terminate(self):
        self.close()

    def kill(self):
        self.close()


class ControlLifecycle(unittest.IsolatedAsyncioTestCase):
    async def test_ready_heartbeat_key_stdin_and_clean_close(self):
        process = Process(descriptor())
        gateway = client.GatewayControl(config(), Path('/unused'))
        with mock.patch.object(client, '_deploy', mock.AsyncMock(return_value='/private/helper.py')), \
                mock.patch.object(client, '_spawn', mock.AsyncMock(return_value=process)) as spawn, \
                mock.patch.object(client, 'HEARTBEAT_INTERVAL', 0.001):
            result = await gateway.open()
            self.assertEqual(result, descriptor())
            self.assertEqual(gateway.peer, ('1.1.1.1', 45000))
            self.assertEqual(len(gateway.key), 32)
            encoded = base64.b64encode(gateway.key).decode()
            self.assertEqual(process.messages[0]['session_key'], encoded)
            self.assertNotIn(encoded, repr(spawn.call_args))
            self.assertNotIn('session_key', gateway.descriptor)
            await asyncio.wait_for(process.ping.wait(), 1)
            await asyncio.wait_for(gateway.close(), 1)
        self.assertTrue(process.closed)
        self.assertTrue(process.reaped)
        self.assertIsNone(gateway.key)
        self.assertTrue(gateway.failure.cancelled())

    async def test_eof_fails_closed_and_reaps_owned_child(self):
        process = Process(descriptor())
        gateway = client.GatewayControl(config(), Path('/unused'))
        with mock.patch.object(client, '_deploy', mock.AsyncMock(return_value='/private/helper.py')), \
                mock.patch.object(client, '_spawn', mock.AsyncMock(return_value=process)):
            await gateway.open()
            process.stdout.feed_eof()
            failure = await asyncio.wait_for(asyncio.shield(gateway.failure), 1)
            self.assertIn('exclusive route is closed', failure)
            await gateway.close()
        self.assertTrue(process.closed)
        self.assertTrue(process.reaped)

    async def test_pin_mismatch_closes_before_exposing_peer(self):
        response = descriptor()
        response['daemon_socket'] = '/different.sock'
        process = Process(response)
        gateway = client.GatewayControl(config(), Path('/unused'))
        with mock.patch.object(client, '_deploy', mock.AsyncMock(return_value='/private/helper.py')), \
                mock.patch.object(client, '_spawn', mock.AsyncMock(return_value=process)):
            with self.assertRaises(RelayError):
                await gateway.open()
        self.assertIsNone(gateway.peer)
        self.assertIsNone(gateway.key)
        self.assertTrue(process.reaped)

    async def test_startup_cancellation_reaps_child(self):
        process = Process()
        gateway = client.GatewayControl(config(), Path('/unused'))
        spawned = asyncio.Event()

        async def spawn(*args):
            spawned.set()
            return process

        with mock.patch.object(client, '_deploy', mock.AsyncMock(return_value='/private/helper.py')), \
                mock.patch.object(client, '_spawn', spawn):
            opening = asyncio.create_task(gateway.open())
            await spawned.wait()
            opening.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(opening, 1)
        self.assertTrue(process.closed)
        self.assertTrue(process.reaped)

    async def test_remote_error_content_is_never_exposed(self):
        process = Process({'ok': False, 'error': 'private-key-must-not-leak'})
        gateway = client.GatewayControl(config(), Path('/unused'))
        with mock.patch.object(client, '_deploy', mock.AsyncMock(return_value='/private/helper.py')), \
                mock.patch.object(client, '_spawn', mock.AsyncMock(return_value=process)):
            with self.assertRaises(RelayError) as caught:
                await gateway.open()
        self.assertNotIn('private-key-must-not-leak', str(caught.exception))
        self.assertTrue(process.reaped)


if __name__ == '__main__':
    unittest.main()
