"""Offline consumer-visible safety checks for the public relay CLI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from relay_config import RelayError, load_config

ROOT = Path(__file__).resolve().parents[1]


class RuntimeSafety(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='ttr-check-')
        self.root = Path(self.scratch.name).resolve()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.dependencies = self.root / 'empty-dependencies'
        self.dependencies.mkdir()
        self.key = self.root / 'key.json'
        self.secret = 'test-secret-must-not-appear-in-output'
        self.key.write_text(json.dumps({'provider': 'cloudflare', 'turn_key_id': 'local-test', 'api_token': self.secret}))
        self.key.chmod(0o600)
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps({
            'schema': 3,
            'ssh_destination': 'test-ssh',
            'target': {'name': 'test', 'host': '1.1.1.1', 'port': 8376, 'user': 'tester',
                       'fingerprint': 'SHA256:' + 'A' * 43},
            'gateway': {'state_dir': '/home/tester/.tern-gateway',
                        'daemon_socket': '/run/user/1000/tern/daemon.sock',
                        'fingerprint': 'SHA256:' + 'A' * 42 + 'E'},
            'listen_port': 18379,
            'credential_file': str(self.key),
            'dependency_dir': str(self.dependencies),
        }))
        self.config.chmod(0o600)

    def tearDown(self):
        self.scratch.cleanup()

    def command(self, verb):
        argv = [sys.executable, str(ROOT / 'relay.py'), verb,
                '--config', str(self.config), '--state-dir', str(self.state)]
        if verb == 'start':
            argv += ['--mode', 'tls']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertNotIn(self.secret, result.stdout + result.stderr)
        self.assertIn('resume_mode', json.loads(result.stdout))
        return result, json.loads(result.stdout)

    def assert_rejected_before_daemon(self):
        result, document = self.command('start')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(document['ok'])
        self.assertEqual(document['state'], 'error')
        self.assertFalse((self.state / 'status.json').exists())
        self.assertFalse((self.state / 'control.sock').exists())

    def test_readable_management_secret_is_rejected_before_start(self):
        self.key.chmod(0o644)
        self.assert_rejected_before_daemon()

    def test_writable_target_pin_configuration_is_rejected_before_start(self):
        self.config.chmod(0o666)
        self.assert_rejected_before_daemon()

    def test_schema_two_is_rejected_without_compatibility_fallback(self):
        config = json.loads(self.config.read_text())
        config['schema'] = 2
        del config['gateway']
        self.config.write_text(json.dumps(config))
        self.assert_rejected_before_daemon()

    def test_only_installer_can_omit_unprovisioned_gateway_fingerprint(self):
        config = json.loads(self.config.read_text())
        del config['gateway']['fingerprint']
        self.config.write_text(json.dumps(config))
        prepared = load_config(self.config, allow_unprovisioned=True)
        self.assertNotIn('fingerprint', prepared['gateway'])
        with self.assertRaises(RelayError):
            load_config(self.config)
        self.assert_rejected_before_daemon()
        for fingerprint in (None, '', 'not-a-pin', config['target']['fingerprint']):
            with self.subTest(fingerprint=fingerprint):
                config['gateway']['fingerprint'] = fingerprint
                self.config.write_text(json.dumps(config))
                with self.assertRaises(RelayError):
                    load_config(self.config, allow_unprovisioned=True)
        del config['gateway']['fingerprint']
        config['gateway']['daemon_socket'] = 'relative/path'
        self.config.write_text(json.dumps(config))
        with self.assertRaises(RelayError):
            load_config(self.config, allow_unprovisioned=True)

    def test_gateway_requires_distinct_canonical_pin_and_absolute_paths(self):
        original = json.loads(self.config.read_text())
        for field, value in (
                ('fingerprint', original['target']['fingerprint']),
                ('fingerprint', 'SHA256:' + 'B' * 43),
                ('fingerprint', None), ('state_dir', 'relative/path'),
                ('state_dir', '/remote/../original'), ('daemon_socket', '/run/bad\npath')):
            with self.subTest(field=field, value=value):
                config = dict(original, gateway=dict(original['gateway']))
                config['gateway'][field] = value
                self.config.write_text(json.dumps(config))
                self.assert_rejected_before_daemon()

    def test_public_status_keeps_original_target_and_dedicated_identity_separate(self):
        config = json.loads(self.config.read_text())
        result, document = self.command('status')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(document['target'], config['target'])
        self.assertEqual(document['relay_fingerprint'], config['gateway']['fingerprint'])
        self.assertEqual(document['daemon_socket'], config['gateway']['daemon_socket'])
        self.assertEqual(document['route_policy'], 'exclusive')

    def test_management_secret_symlink_is_not_followed(self):
        actual = self.root / 'actual-key.json'
        self.key.rename(actual)
        self.key.symlink_to(actual)
        self.assert_rejected_before_daemon()
        self.assertTrue(actual.is_file())

    def test_stop_never_signals_a_stale_unrelated_pid(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            saved = self.state / 'pid.json'
            saved.write_text(json.dumps({'pid': child.pid, 'service_id': 'stale'}))
            saved.chmod(0o600)
            result, document = self.command('stop')
            self.assertEqual(result.returncode, 0)
            self.assertEqual(document['state'], 'stopped')
            self.assertIsNone(child.poll(), 'stop killed a process merely named by a stale PID file')
        finally:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=3)

    def test_stop_preserves_unsafe_socket_symlink_and_its_target(self):
        unrelated = self.root / 'unrelated'
        unrelated.write_text('keep this data')
        link = self.state / 'control.sock'
        link.symlink_to(unrelated)
        result, document = self.command('stop')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(document['ok'])
        self.assertTrue(link.is_symlink())
        self.assertEqual(unrelated.read_text(), 'keep this data')

    def test_no_intent_resume_is_stopped_without_loading_credentials_or_daemon(self):
        self.key.unlink()
        result, document = self.command('resume')
        self.assertEqual(result.returncode, 0)
        self.assertTrue(document['ok'])
        self.assertEqual(document['state'], 'stopped')
        self.assertIsNone(document['resume_mode'])
        self.assertFalse((self.state / 'intent.json').exists())
        self.assertFalse((self.state / 'status.json').exists())
        self.assertFalse((self.state / 'control.sock').exists())

    def test_public_stop_revokes_intent_while_already_stopped(self):
        config = json.loads(self.config.read_text())
        intent = self.state / 'intent.json'
        intent.write_text(json.dumps({'target': config['target'], 'gateway': config['gateway'],
                                      'listen_port': config['listen_port'],
                                      'ssh_destination': config['ssh_destination'], 'mode': 'udp'}))
        intent.chmod(0o600)
        result, document = self.command('status')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(document['state'], 'stopped')
        self.assertEqual(document['resume_mode'], 'udp')
        result, document = self.command('stop')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(document['state'], 'stopped')
        self.assertIsNone(document['resume_mode'])
        self.assertFalse(intent.exists())
        self.key.unlink()
        result, document = self.command('resume')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(document['state'], 'stopped')
        self.assertIsNone(document['resume_mode'])
        self.assertFalse((self.state / 'status.json').exists())
        self.assertFalse((self.state / 'control.sock').exists())


if __name__ == '__main__':
    unittest.main()
