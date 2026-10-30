"""Offline tests for strict, redacted setup; no SSH command is executed."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import setup as onboarding
from relay_config import load_config

PIN = 'SHA256:' + base64.b64encode(bytes(range(32))).decode().rstrip('=')


def remote():
    return {'ok': True, 'home': '/home/developer', 'uid': 1001, 'user': 'developer',
            'original_state_dir': '/home/developer/.state/original',
            'daemon_socket': '/run/user/1001/tern/daemon.sock',
            'target_port': 8376, 'fingerprint': PIN, 'host': '8.8.8.8'}


def arguments(*extra):
    return onboarding.parser().parse_args(['--ssh-destination', 'dev-host', *extra])


class SetupTests(unittest.TestCase):
    def test_strict_alias_resolution_and_remote_stdin(self):
        resolved = 'hostname 8.8.8.8\nuser developer\nport 22\n'
        runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, resolved, ''),
                                       subprocess.CompletedProcess([], 0, json.dumps(remote()), '')])
        result = onboarding.discover(arguments('--discover'), runner)
        self.assertEqual(result['fingerprint'], PIN)
        first, second = runner.call_args_list
        self.assertIn('StrictHostKeyChecking=yes', first.args[0])
        self.assertIn('UpdateHostKeys=no', second.args[0])
        self.assertIn('ControlPath=none', second.args[0])
        self.assertNotIn('accept-new', ' '.join(second.args[0]))
        self.assertEqual(json.loads(second.kwargs['input'])['daemon_socket'], None)
        self.assertNotIn(PIN, ' '.join(second.args[0]))

    def test_proxy_is_rejected_before_connecting(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0,
            'hostname 8.8.8.8\nuser developer\nport 22\nproxycommand dangerous command\n', ''))
        with self.assertRaisesRegex(onboarding.SetupError, 'ProxyJump/ProxyCommand'):
            onboarding.discover(arguments('--discover'), runner)
        self.assertEqual(runner.call_count, 1)

    def test_nonpublic_or_ambiguous_host_is_rejected(self):
        for text in ('hostname 127.0.0.1\n', 'hostname 8.8.8.8\nhostname 1.1.1.1\n'):
            runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0,
                text + 'user developer\nport 22\n', ''))
            with self.assertRaises(onboarding.SetupError):
                onboarding.resolve_destination('dev-host', runner)

    def test_remote_errors_cannot_disclose_suffixes(self):
        secret = 'private-token-value'
        runner = mock.Mock(side_effect=[subprocess.CompletedProcess([], 0,
            'hostname 8.8.8.8\nuser developer\nport 22\n', ''),
            subprocess.CompletedProcess([], 1, json.dumps({'ok': False, 'error':
                'Original Tern service is absent or ambiguous ' + secret}), secret)])
        with self.assertRaises(onboarding.SetupError) as failure:
            onboarding.discover(arguments('--discover'), runner)
        self.assertNotIn(secret, str(failure.exception))

    def test_dry_run_is_redacted_and_does_not_write(self):
        output = io.StringIO()
        with mock.patch.object(onboarding, 'discover', return_value=remote()), \
                mock.patch.object(onboarding, 'write_configuration') as write, contextlib.redirect_stdout(output):
            self.assertEqual(onboarding.main(['--ssh-destination', 'dev-host', '--dry-run']), 0)
        write.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertTrue(result['redacted'])
        for value in (PIN, remote()['home'], remote()['user'], remote()['host'], remote()['daemon_socket']):
            self.assertNotIn(value, output.getvalue())

    def test_help_contains_no_machine_identity_or_pin(self):
        help_text = onboarding.parser().format_help()
        self.assertIn('--original-state-dir', help_text)
        self.assertIn('--daemon-socket', help_text)
        self.assertNotIn(str(Path.home()), help_text)
        self.assertNotIn('SHA256:', help_text)

    def test_configuration_uses_discovered_identity_and_separate_gateway(self):
        config = onboarding.configuration(arguments('--credential-file', '/private/key.json'), remote())
        self.assertEqual(config['target']['fingerprint'], PIN)
        self.assertEqual(config['target']['name'], 'dev-host')
        self.assertEqual(config['gateway']['daemon_socket'], remote()['daemon_socket'])
        self.assertNotIn('fingerprint', config['gateway'])
        with self.assertRaises(onboarding.SetupError):
            onboarding.configuration(arguments('--gateway-state-dir', remote()['original_state_dir']), remote())

    def test_invalid_pin_or_listener_fails_even_in_dry_run(self):
        with self.assertRaises(onboarding.SetupError):
            onboarding.configuration(arguments('--listen-port', '22'), remote())
        with self.assertRaises(onboarding.SetupError):
            onboarding.configuration(arguments(), dict(remote(), fingerprint='not-a-verified-pin'))

    def test_private_creation_refuses_overwrite_and_preserves_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            parent.chmod(0o700)
            credential = parent / 'key.json'
            credential.write_text('{"opaque":"never read by setup"}')
            credential.chmod(0o600)
            config = onboarding.configuration(arguments('--credential-file', str(credential)), remote())
            destination = parent / 'config.json'
            onboarding.write_configuration(destination, config)
            self.assertEqual(load_config(destination, allow_unprovisioned=True), config)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(onboarding.SetupError, 'already exists'):
                onboarding.write_configuration(destination, config)
            self.assertEqual(credential.read_text(), '{"opaque":"never read by setup"}')

    def test_symlink_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            victim = root / 'victim'
            victim.write_text('preserve')
            destination = root / 'config.json'
            destination.symlink_to(victim)
            with self.assertRaises(onboarding.SetupError):
                onboarding.write_configuration(destination, {}, replace=True)
            self.assertEqual(victim.read_text(), 'preserve')


class RemoteSelectionTests(unittest.TestCase):
    def setUp(self):
        self.namespace = {}
        # Compile the exact remote helper definitions without running discovery.
        definitions = onboarding.REMOTE_DISCOVERY.split('\ntry:\n', 1)[0]
        exec(definitions, self.namespace)

    def test_multiple_original_services_require_explicit_state(self):
        services = [{'state': '/home/dev/service-a'}, {'state': '/home/dev/service-b'}]
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.namespace['select_service'](services, None)
        self.assertIs(self.namespace['select_service'](services, '/home/dev/service-b'), services[1])

    def test_unknown_service_state_is_not_guessed_among_multiple_processes(self):
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.namespace['select_service']([{'state': None}, {'state': None}], '/home/dev/original')

    def test_existing_daemon_override_requires_exact_match(self):
        daemons = [{'socket': '/run/a.sock'}, {'socket': '/run/b.sock'}]
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.namespace['select_daemon'](daemons, None)
        self.assertIs(self.namespace['select_daemon'](daemons, '/run/b.sock'), daemons[1])
        with self.assertRaises(ValueError):
            self.namespace['select_daemon'](daemons, '/run/missing.sock')

    def test_missing_or_symlink_identity_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileNotFoundError):
                self.namespace['regular'](root / 'host_key')
            real = root / 'real'
            real.write_text('synthetic')
            (root / 'host_key').symlink_to(real)
            with self.assertRaises(ValueError):
                self.namespace['regular'](root / 'host_key')


if __name__ == '__main__':
    unittest.main()
