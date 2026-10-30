"""Offline regressions for saved backend selection and the public relay CLI."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import relay
from relay_config import atomic_json, lock_file, public_status


class ResumeIntent(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='ttr-intent-')
        self.root = Path(self.scratch.name).resolve()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.config = self.root / 'config.json'
        self.configuration = {
            'schema': 3,
            'ssh_destination': 'test-ssh',
            'target': {'name': 'test', 'host': '1.1.1.1', 'port': 8376, 'user': 'tester',
                       'fingerprint': 'SHA256:' + 'A' * 43},
            'gateway': {'state_dir': '/home/tester/.tern-gateway',
                        'daemon_socket': '/run/user/1000/tern/daemon.sock',
                        'fingerprint': 'SHA256:' + 'A' * 42 + 'E'},
            'listen_port': 18379,
            'credential_file': str(self.root / 'missing-key.json'),
            'dependency_dir': str(self.root / 'missing-dependencies'),
        }
        self.config.write_text(json.dumps(self.configuration))
        self.config.chmod(0o600)
        self.intent = self.state / 'intent.json'
        self.secret = 'intent-tests-must-not-expose-this-key'

    def tearDown(self):
        self.scratch.cleanup()

    def command(self, verb, *options):
        argv = ['relay.py', verb, '--config', str(self.config), '--state-dir', str(self.state), *options]
        output = io.StringIO()
        previous_umask = os.umask(0o077)
        try:
            with patch('sys.argv', argv), contextlib.redirect_stdout(output):
                result = relay.main()
        finally:
            os.umask(previous_umask)
        self.assertNotIn(self.secret, output.getvalue())
        return result, json.loads(output.getvalue())

    def selection(self, mode='tls'):
        return {'target': dict(self.configuration['target']),
                'gateway': dict(self.configuration['gateway']), 'listen_port': 18379,
                'ssh_destination': 'test-ssh', 'mode': mode}

    def write_selection(self, value=None):
        atomic_json(self.intent, self.selection() if value is None else value)

    def create_key(self):
        key = Path(self.configuration['credential_file'])
        key.write_text(json.dumps({'provider': 'cloudflare', 'turn_key_id': 'local-test',
                                   'api_token': self.secret}))
        key.chmod(0o600)

    @contextlib.contextmanager
    def running_backend(self, mode='tls', state='ready'):
        # Preserve real lifecycle locks; fake only the SSH and control-socket
        # boundaries so ready reuse exercises the real public start path.
        descriptor = lock_file(self.state / 'service.lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        status = public_status(self.configuration, state, mode, 'running-service')
        endpoint = {'host': '1.1.1.1', 'port': 22, 'user': 'tester'}

        def reply(directory, command='status', service_id=None):
            if command == 'status':
                return dict(status)
            if command == 'identity':
                return {'service_id': 'running-service', 'ssh_endpoint': endpoint,
                        'gateway': dict(self.configuration['gateway'])}
            raise AssertionError('Unexpected control command: ' + command)

        try:
            with patch('relay.ipc', side_effect=reply), \
                    patch('relay.resolve_ssh_destination', new=AsyncMock(return_value=endpoint)) as resolve, \
                    patch('relay.subprocess.Popen', side_effect=AssertionError('Ready reuse must not spawn')):
                yield status, resolve
        finally:
            os.close(descriptor)

    def assert_recovery_rejected(self, error_fragment):
        with patch('relay.start', side_effect=AssertionError('Invalid intent may not start')) as start, \
                patch('relay.resolve_ssh_destination', side_effect=AssertionError('Invalid intent may not resolve SSH')) as resolve:
            result, status = self.command('resume')
        self.assertEqual(result, 1)
        self.assertFalse(status['ok'])
        self.assertEqual(status['state'], 'error')
        self.assertIsNone(status['resume_mode'])
        self.assertIn(error_fragment, status['error'])
        start.assert_not_called()
        resolve.assert_not_called()
        result, status = self.command('status')
        self.assertEqual(result, 0)
        self.assertEqual(status['state'], 'stopped')
        self.assertIsNone(status['resume_mode'])

    def test_concurrent_status_reader_is_not_a_running_daemon(self):
        descriptor = lock_file(self.state / 'service.lock')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            result, status = self.command('status')
            self.assertEqual(result, 0)
            self.assertEqual(status['state'], 'stopped')
            self.assertIsNone(status['error'])
        finally:
            os.close(descriptor)

    def test_resume_without_intent_does_not_start_or_require_credentials(self):
        with patch('relay.start', side_effect=AssertionError('No intent may start a backend')) as start, \
                patch('relay.resolve_ssh_destination', side_effect=AssertionError('No intent may resolve SSH')) as resolve:
            result, status = self.command('resume')
        self.assertEqual(result, 0)
        self.assertTrue(status['ok'])
        self.assertEqual(status['state'], 'stopped')
        self.assertIsNone(status['resume_mode'])
        self.assertFalse(self.intent.exists())
        self.assertFalse((self.state / 'status.json').exists())
        start.assert_not_called()
        resolve.assert_not_called()

    def test_no_intent_ignores_stale_ready_status(self):
        atomic_json(self.state / 'status.json', public_status(self.configuration, 'ready', 'udp', 'stale'))
        with patch('relay.start', side_effect=AssertionError('Stale status must not enable recovery')) as start:
            result, status = self.command('resume')
        self.assertEqual(result, 0)
        self.assertEqual(status['state'], 'stopped')
        self.assertIsNone(status['mode'])
        self.assertIsNone(status['resume_mode'])
        start.assert_not_called()

    def test_no_intent_reports_live_backend_without_starting_or_resolving(self):
        with self.running_backend() as (_, resolve), \
                patch('relay.start', side_effect=AssertionError('No intent may start')) as start:
            result, status = self.command('resume')
            resolve.assert_not_awaited()
        self.assertEqual(result, 0)
        self.assertEqual(status['state'], 'ready')
        self.assertEqual(status['mode'], 'tls')
        self.assertIsNone(status['resume_mode'])
        start.assert_not_called()

    def test_stopped_status_reports_saved_mode_without_requiring_credentials(self):
        for mode in ('tls', 'udp'):
            with self.subTest(mode=mode):
                self.write_selection(self.selection(mode))
                result, status = self.command('status')
                self.assertEqual(result, 0)
                self.assertEqual(status['state'], 'stopped')
                self.assertIsNone(status['mode'])
                self.assertEqual(status['resume_mode'], mode)

    def test_mismatched_selection_never_starts(self):
        changed_targets = {'name': 'other', 'host': '8.8.8.8', 'port': 8377,
                           'user': 'other', 'fingerprint': 'SHA256:' + 'B' * 43}
        variants = []
        for field, value in changed_targets.items():
            selection = self.selection()
            selection['target'][field] = value
            variants.append((field, selection))
        for field, value in (('state_dir', '/another/private-gateway'),
                             ('daemon_socket', '/run/user/1000/another.sock'),
                             ('fingerprint', 'SHA256:' + 'A' * 42 + 'I')):
            selection = self.selection()
            selection['gateway'][field] = value
            variants.append(('gateway.' + field, selection))
        for field, value in (('listen_port', 18380), ('ssh_destination', 'another-ssh')):
            selection = self.selection()
            selection[field] = value
            variants.append((field, selection))
        for field, selection in variants:
            with self.subTest(field=field):
                self.write_selection(selection)
                self.assert_recovery_rejected('does not match')

    def test_malformed_selection_never_starts(self):
        invalid = [None, [], {}, dict(self.selection(), mode='tcp'),
                   dict(self.selection(), listen_port=18379.0),
                   dict(self.selection(), extra=True)]
        old_selection = self.selection()
        del old_selection['gateway']
        invalid.extend([old_selection, dict(self.selection(), gateway=None)])
        target_float_port = self.selection()
        target_float_port['target']['port'] = 8376.0
        invalid.append(target_float_port)
        for value in invalid:
            with self.subTest(value=value):
                atomic_json(self.intent, value)
                self.assert_recovery_rejected('invalid or unsafe')
        self.intent.write_text('{not json')
        self.assert_recovery_rejected('invalid or unsafe')

    def test_symlink_selection_is_not_followed(self):
        other = self.root / 'other.json'
        atomic_json(other, self.selection())
        original = other.read_bytes()
        self.intent.symlink_to(other)
        self.assert_recovery_rejected('invalid or unsafe')
        self.assertTrue(self.intent.is_symlink())
        self.assertEqual(other.read_bytes(), original)

    def test_nonprivate_and_hardlinked_selection_are_rejected(self):
        self.write_selection()
        self.intent.chmod(0o644)
        self.assert_recovery_rejected('invalid or unsafe')
        self.intent.chmod(0o600)
        other = self.root / 'same-inode.json'
        os.link(self.intent, other)
        self.assert_recovery_rejected('invalid or unsafe')
        self.assertTrue(other.is_file())

    def test_nonregular_and_oversized_selection_are_rejected_without_blocking(self):
        self.intent.mkdir()
        self.assert_recovery_rejected('invalid or unsafe')
        self.intent.rmdir()
        os.mkfifo(self.intent, 0o600)
        self.assert_recovery_rejected('invalid or unsafe')
        self.intent.unlink()
        self.intent.write_text(' ' * 65537)
        self.intent.chmod(0o600)
        self.assert_recovery_rejected('invalid or unsafe')

    def test_stopped_stop_revokes_saved_selection_before_future_resume(self):
        self.write_selection()
        result, status = self.command('stop')
        self.assertEqual(result, 0)
        self.assertEqual(status['state'], 'stopped')
        self.assertIsNone(status['resume_mode'])
        self.assertFalse(self.intent.exists())
        with patch('relay.start', side_effect=AssertionError('Stop must disable recovery')) as start:
            result, status = self.command('resume')
        self.assertEqual(result, 0)
        self.assertEqual(status['state'], 'stopped')
        self.assertIsNone(status['resume_mode'])
        start.assert_not_called()

    def test_stop_unlinks_unsafe_selection_without_touching_link_targets(self):
        other = self.root / 'unrelated.json'
        other.write_text('unrelated data')
        other.chmod(0o644)
        for link in ('symbolic', 'hard'):
            with self.subTest(link=link):
                if link == 'symbolic':
                    self.intent.symlink_to(other)
                else:
                    os.link(other, self.intent)
                result, status = self.command('stop')
                self.assertEqual(result, 0)
                self.assertIsNone(status['resume_mode'])
                self.assertFalse(self.intent.is_symlink())
                self.assertFalse(self.intent.exists())
                self.assertEqual(other.read_text(), 'unrelated data')
                self.assertEqual(other.stat().st_mode & 0o777, 0o644)
        self.intent.write_text('malformed selection')
        self.intent.chmod(0o666)
        result, status = self.command('stop')
        self.assertEqual(result, 0)
        self.assertIsNone(status['resume_mode'])
        self.assertFalse(self.intent.exists())

    def test_stop_preserves_unexpected_intent_directory_and_returns_error(self):
        self.intent.mkdir()
        child = self.intent / 'keep'
        child.write_text('unrelated data')
        result, status = self.command('stop')
        self.assertEqual(result, 1)
        self.assertIn('Cannot clear saved relay selection', status['error'])
        self.assertIsNone(status['resume_mode'])
        self.assertEqual(child.read_text(), 'unrelated data')

    def test_stop_revokes_selection_even_when_stale_socket_cleanup_is_rejected(self):
        self.write_selection()
        other = self.root / 'unrelated'
        other.write_text('unrelated data')
        link = self.state / 'control.sock'
        link.symlink_to(other)
        result, status = self.command('stop')
        self.assertEqual(result, 1)
        self.assertIsNone(status['resume_mode'])
        self.assertFalse(self.intent.exists())
        self.assertTrue(link.is_symlink())
        self.assertEqual(other.read_text(), 'unrelated data')

    def test_stop_revokes_selection_without_a_valid_config(self):
        self.write_selection()
        self.config.write_text('invalid JSON')
        result, status = self.command('stop')
        self.assertEqual(result, 0)
        self.assertEqual(status['state'], 'stopped')
        self.assertIsNone(status['resume_mode'])
        self.assertFalse(self.intent.exists())

    def test_stop_revokes_selection_before_reporting_unreachable_backend(self):
        self.write_selection()
        with self.running_backend(), patch('relay.ipc', side_effect=OSError('control unavailable')):
            result, status = self.command('stop')
        self.assertEqual(result, 1)
        self.assertIn('Cannot reach the live relay control socket', status['error'])
        self.assertIsNone(status['resume_mode'])
        self.assertFalse(self.intent.exists())

    def test_ready_start_reuse_saves_only_the_explicitly_selected_mode(self):
        self.create_key()
        for mode in ('tls', 'udp'):
            with self.subTest(mode=mode), self.running_backend(mode):
                result, status = self.command('start', '--mode', mode)
                self.assertEqual(result, 0)
                self.assertEqual(status['state'], 'ready')
                self.assertEqual(status['mode'], mode)
                self.assertEqual(status['resume_mode'], mode)
                self.assertEqual(json.loads(self.intent.read_text()), self.selection(mode))
                self.assertEqual(self.intent.stat().st_mode & 0o777, 0o600)
                self.assertEqual(self.intent.stat().st_nlink, 1)

    def test_ready_reuse_rejects_different_dedicated_gateway(self):
        self.create_key()
        for field, value in (('relay_fingerprint', self.configuration['target']['fingerprint']),
                             ('daemon_socket', '/different/daemon.sock'),
                             ('route_policy', 'direct')):
            with self.subTest(field=field), self.running_backend() as (status, _):
                status[field] = value
                result, document = self.command('start', '--mode', 'tls')
                self.assertEqual(result, 1)
                self.assertIn('Another target, gateway', document['error'])
                self.assertFalse(self.intent.exists())

    def test_successful_explicit_start_replaces_symlink_without_touching_target(self):
        self.create_key()
        other = self.root / 'unrelated.json'
        other.write_text('unrelated data')
        self.intent.symlink_to(other)
        with self.running_backend('udp'):
            result, status = self.command('start', '--mode', 'udp')
        self.assertEqual(result, 0)
        self.assertEqual(status['resume_mode'], 'udp')
        self.assertFalse(self.intent.is_symlink())
        self.assertEqual(other.read_text(), 'unrelated data')

    def test_unsuccessful_explicit_start_does_not_enable_or_replace_selection(self):
        self.create_key()
        with self.running_backend('tls'):
            result, status = self.command('start', '--mode', 'udp')
        self.assertEqual(result, 1)
        self.assertIsNone(status['resume_mode'])
        self.assertFalse(self.intent.exists())
        self.write_selection(self.selection('udp'))
        before = self.intent.read_bytes()
        with self.running_backend('tls', 'starting'):
            result, status = self.command('start', '--mode', 'tls')
        self.assertEqual(result, 1)
        self.assertEqual(status['resume_mode'], 'udp')
        self.assertEqual(self.intent.read_bytes(), before)

    def test_persistence_failure_is_an_error_without_stopping_live_backend(self):
        self.create_key()
        self.intent.mkdir()
        child = self.intent / 'keep'
        child.write_text('unrelated data')
        with self.running_backend():
            result, status = self.command('start', '--mode', 'tls')
            self.assertEqual(result, 1)
            self.assertFalse(status['ok'])
            self.assertEqual(status['state'], 'error')
            self.assertEqual(status['mode'], 'tls')
            self.assertEqual(status['service_id'], 'running-service')
            self.assertIn('saving its backend selection failed', status['error'])
            self.assertIsNone(status['resume_mode'])
            result, status = self.command('status')
            self.assertEqual(result, 0)
            self.assertEqual(status['state'], 'ready')
            self.assertIsNone(status['resume_mode'])
        self.assertEqual(child.read_text(), 'unrelated data')

    def test_failed_replacement_does_not_claim_previous_selection_changed(self):
        self.create_key()
        self.write_selection(self.selection('udp'))
        before = self.intent.read_bytes()
        with self.running_backend(), patch('relay_config.os.replace', side_effect=PermissionError('private detail')):
            result, status = self.command('start', '--mode', 'tls')
        self.assertEqual(result, 1)
        self.assertEqual(status['mode'], 'tls')
        self.assertEqual(status['resume_mode'], 'udp')
        self.assertNotIn('private detail', status['error'])
        self.assertEqual(self.intent.read_bytes(), before)
        self.assertEqual(list(self.state.glob('.intent.json.*')), [])

    def test_resume_uses_saved_mode_without_rewriting_selection(self):
        self.create_key()
        for mode in ('tls', 'udp'):
            with self.subTest(mode=mode):
                self.write_selection(self.selection(mode))
                before = self.intent.stat()
                content = self.intent.read_bytes()
                with self.running_backend(mode) as (_, resolve):
                    result, status = self.command('resume')
                    resolve.assert_awaited_once()
                self.assertEqual(result, 0)
                self.assertEqual(status['state'], 'ready')
                self.assertEqual(status['mode'], mode)
                self.assertEqual(status['resume_mode'], mode)
                after = self.intent.stat()
                self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))
                self.assertEqual(self.intent.read_bytes(), content)

    def test_valid_selection_still_requires_private_credentials_before_ssh(self):
        self.write_selection()
        with patch('relay.start', side_effect=AssertionError('Missing key may not start')) as start, \
                patch('relay.resolve_ssh_destination', side_effect=AssertionError('Missing key may not resolve SSH')) as resolve:
            result, status = self.command('resume')
        self.assertEqual(result, 1)
        self.assertIn('Cannot securely open the management key file', status['error'])
        self.assertEqual(status['resume_mode'], 'tls')
        start.assert_not_called()
        resolve.assert_not_called()

    def test_resume_rejects_explicit_mode(self):
        self.write_selection()
        with patch('relay.start', side_effect=AssertionError('Resume cannot select a mode')) as start:
            result, status = self.command('resume', '--mode', 'udp')
        self.assertEqual(result, 1)
        self.assertIn('--mode is not accepted', status['error'])
        self.assertIsNone(status['resume_mode'])
        self.assertEqual(json.loads(self.intent.read_text())['mode'], 'tls')
        start.assert_not_called()

    def test_lifecycle_lock_blocks_resume_and_stop_without_rewriting_intent(self):
        self.write_selection()
        before = self.intent.read_bytes()
        descriptor = lock_file(self.state / 'command.lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with patch('relay.start', side_effect=AssertionError('Busy lifecycle must not start')) as start:
                for verb in ('resume', 'stop'):
                    with self.subTest(verb=verb):
                        result, status = self.command(verb)
                        self.assertEqual(result, 1)
                        self.assertIn('lifecycle command is in progress', status['error'])
                        self.assertEqual(status['resume_mode'], 'tls')
                        self.assertEqual(self.intent.read_bytes(), before)
                start.assert_not_called()
        finally:
            os.close(descriptor)
        result, status = self.command('stop')
        self.assertEqual(result, 0)
        self.assertIsNone(status['resume_mode'])
        with patch('relay.start', side_effect=AssertionError('Completed stop must defeat later resume')) as start:
            result, status = self.command('resume')
        self.assertEqual(result, 0)
        self.assertEqual(status['state'], 'stopped')
        self.assertIsNone(status['resume_mode'])
        start.assert_not_called()

    def test_deeply_nested_json_is_invalid_selection_not_an_unhandled_exception(self):
        self.intent.write_text('[' * 2000 + ']' * 2000)
        self.intent.chmod(0o600)
        self.assert_recovery_rejected('invalid or unsafe')



if __name__ == '__main__':
    unittest.main()
