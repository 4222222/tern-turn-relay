"""Deterministic onboarding boundary tests; no SSH, cloud or native UI is contacted."""
import base64
import contextlib
import fcntl
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import credentials
import onboarding
import setup

KEY = {'provider': 'cloudflare', 'turn_key_id': 'synthetic-key-id', 'api_token': 'synthetic-hidden-token'}
PIN = 'SHA256:' + base64.b64encode(bytes(range(32))).decode().rstrip('=')
CANDIDATE = 'a' * 24


class OnboardingBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / 'home'
        self.home.mkdir()
        home = mock.patch.object(Path, 'home', return_value=self.home)
        home.start()
        self.addCleanup(home.stop)
        self.profile = self.root / 'profile'
        self.package = self.profile / 'plugins' / 'tern-turn-relay'
        self.package.mkdir(parents=True)
        self.ssh = self.root / 'ssh-config'
        self.args = onboarding.parser().parse_args(['inspect', '--package-dir', str(self.package),
            '--config-dir', str(self.profile), '--ssh-config', str(self.ssh)])
        self.paths = onboarding.context(self.args)

    def tearDown(self):
        self.temporary.cleanup()

    def remote(self):
        return {'ok': True, 'home': '/home/dev', 'uid': 1001, 'user': 'dev', 'host': '8.8.8.8',
                'original_state_dir': '/home/dev/original', 'daemon_socket': '/run/user/1001/tern.sock',
                'target_port': 8376, 'fingerprint': PIN, 'candidate_id': CANDIDATE}

    def review(self):
        with mock.patch.object(setup, 'discover', return_value=self.remote()):
            return onboarding.discover(self.paths, {'ssh_destination': 'dev'})['review']

    def cli(self, raw, action='inspect'):
        output, error = io.StringIO(), io.StringIO()
        argv = [action, '--package-dir', str(self.package), '--config-dir', str(self.profile),
                '--ssh-config', str(self.ssh)]
        with mock.patch('sys.stdin', io.StringIO(raw)), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = onboarding.main(argv)
        self.assertEqual(error.getvalue(), '')
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertNotIn(KEY['api_token'], output.getvalue())
        return code, json.loads(output.getvalue())

    def test_read_only_inspect_has_no_network_or_new_paths(self):
        ambient = self.home / '.ssh' / 'config'
        ambient.parent.mkdir()
        ambient.write_text('Host dev other *.wild !excluded\n HostName 8.8.8.8\nMatch exec ignored\n')
        self.ssh.write_text('Host scoped-rule-only\n')
        with mock.patch.object(setup, 'discover') as remote, mock.patch.object(credentials, 'probe_credentials') as cloud:
            code, result = self.cli('{}')
        self.assertEqual(code, 0)
        self.assertFalse(result['credential_configured'])
        self.assertFalse(result['configured'])
        self.assertFalse(result['running'])
        self.assertEqual(result['ssh_aliases'], [{'label': 'dev', 'value': 'dev'}, {'label': 'other', 'value': 'other'}])
        self.assertEqual(result['registration'], 'native')
        self.assertFalse(Path(self.paths['data_dir']).exists())
        remote.assert_not_called()
        cloud.assert_not_called()

    def test_invalid_json_boundaries_redact_secret(self):
        for raw in ('[]', '{"replace":false,"replace":true}', '{"x":NaN}', '{', ' ' * 65537,
                    json.dumps({'api_token': KEY['api_token']})):
            with self.subTest(raw_length=len(raw)):
                code, result = self.cli(raw)
                self.assertNotEqual(code, 0)
                self.assertEqual(result['code'], 'invalid-request')

    def test_data_cannot_escape_selected_profile(self):
        self.args.data_dir = self.root / 'other-data'
        with self.assertRaisesRegex(onboarding.OnboardingError, 'selected Tern profile'):
            onboarding.context(self.args)

    def test_native_custom_profile_defaults_to_private_scoped_rule_file(self):
        args = onboarding.parser().parse_args(['inspect', '--package-dir', str(self.package)])
        paths = onboarding.context(args)
        self.assertEqual(paths['ssh_config'], str(Path(paths['data_dir']) / 'ssh-config'))
        self.assertEqual(paths['ssh_alias_config'], str(self.home / '.ssh' / 'config'))
        self.assertFalse(Path(paths['data_dir']).exists())

    def test_default_profile_keeps_ambient_ssh_destination(self):
        package = self.home / 'Library' / 'Application Support' / 'Tern' / 'plugins' / 'tern-turn-relay'
        package.mkdir(parents=True)
        args = onboarding.parser().parse_args(['inspect', '--package-dir', str(package)])
        paths = onboarding.context(args)
        self.assertEqual(paths['ssh_config'], str(self.home / '.ssh' / 'config'))

    def test_existing_manifest_preserves_ssh_rule_ownership(self):
        data = Path(self.paths['data_dir'])
        data.mkdir(parents=True, mode=0o700)
        recorded = self.root / 'prior-owned-ssh-config'
        manifest = data / 'installation.json'
        manifest.write_text(json.dumps({'schema': 1, 'plugin': 'tern-turn-relay',
            'plugins': str(self.profile / 'plugins'), 'package': str(self.package),
            'ssh_config': str(recorded)}))
        manifest.chmod(0o600)
        self.args.ssh_config = None
        self.assertEqual(onboarding.context(self.args)['ssh_config'], str(recorded))
        self.args.ssh_config = self.ssh
        with self.assertRaisesRegex(onboarding.OnboardingError, 'cannot move'):
            onboarding.context(self.args)
        document = json.loads(manifest.read_text())
        document['plugins'] = str(self.root / 'different-profile' / 'plugins')
        manifest.write_text(json.dumps(document))
        self.args.ssh_config = None
        with self.assertRaisesRegex(onboarding.OnboardingError, 'does not match'):
            onboarding.context(self.args)

    def test_linked_custom_profile_is_derived_only_from_owned_data_record(self):
        data = Path(self.paths['data_dir'])
        source = data / 'packages' / 'release'
        source.mkdir(parents=True)
        self.package.rmdir()
        marker = self.profile / 'plugins' / 'tern-turn-relay.path'
        marker.write_text(str(source) + '\n')
        args = onboarding.parser().parse_args(['inspect', '--package-dir', str(source), '--data-dir', str(data)])
        with self.assertRaises(onboarding.OnboardingError) as missing:
            onboarding.context(args)
        self.assertEqual(missing.exception.code, 'ownership-required')
        manifest = data / 'installation.json'
        record = {'schema': 1, 'plugin': 'tern-turn-relay', 'plugins': str(self.profile / 'plugins'),
                  'package': str(source), 'ssh_config': str(self.ssh)}
        manifest.write_text(json.dumps(record))
        manifest.chmod(0o600)
        paths = onboarding.context(args)
        self.assertEqual(paths['config_dir'], str(self.profile))
        self.assertEqual(paths['ssh_config'], str(self.ssh))
        self.assertEqual(onboarding.registration(paths), 'linked')
        record['package'] = str(self.root / 'unrelated-package')
        manifest.write_text(json.dumps(record))
        with self.assertRaises(onboarding.OnboardingError):
            onboarding.context(args)

    def test_owned_path_rejects_symlink(self):
        link = self.root / 'link'
        link.symlink_to(self.profile, target_is_directory=True)
        with self.assertRaises(onboarding.OnboardingError):
            onboarding.owned_path(link / 'config.json')

    def test_inspect_reports_running_without_modifying_lock(self):
        runtime = Path(self.paths['data_dir']) / 'runtime'
        runtime.mkdir(parents=True)
        lock = runtime / 'service.lock'
        with lock.open('w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(onboarding.running(self.paths))
            with self.assertRaisesRegex(onboarding.OnboardingError, 'Disconnect TURN'):
                onboarding.require_stopped(self.paths)

    def test_discovery_returns_only_sanitized_candidates(self):
        remote = {'candidates': [{'id': CANDIDATE, 'pid': 44, 'port': 8376,
                  'state': '/home/dev/original', 'daemon_socket': '/run/user/1001/tern.sock',
                  'environment': KEY['api_token']}]}
        with mock.patch.object(setup, 'discover', return_value=remote):
            result = onboarding.discover(self.paths, {'ssh_destination': 'dev'})
        self.assertEqual(result['code'], 'choose')
        self.assertEqual(set(result['candidates'][0]), {'id', 'label', 'detail'})
        self.assertNotIn(KEY['api_token'], json.dumps(result))

    def test_review_exposes_exact_nonsecret_paths_and_verified_pin(self):
        review = self.review()
        self.assertEqual(review['configuration']['target']['port'], 8376)
        self.assertEqual(review['configuration']['target']['fingerprint'], PIN)
        self.assertEqual(review['paths']['data_dir'], self.paths['data_dir'])
        self.assertEqual(review['original_state_dir'], '/home/dev/original')
        self.assertFalse(review['migrate_native'])
        self.assertIsNone(review['previous_config_sha256'])
        self.assertEqual(review['listen_port'], 18377)
        self.assertEqual(review['configuration']['listen_port'], 18377)
        self.assertEqual(review['paths']['ssh_config'], str(self.ssh))

    def test_explicit_local_port_is_validated_before_remote_discovery(self):
        for port in (None, True, '19001', 1023, 65536):
            with mock.patch.object(setup, 'discover') as remote:
                with self.assertRaises(onboarding.OnboardingError):
                    onboarding.discover(self.paths, {'ssh_destination': 'dev', 'listen_port': port})
            remote.assert_not_called()

    def test_installed_local_port_is_preserved_without_override(self):
        previous = self.review()['configuration']
        previous['listen_port'] = 19002
        previous['gateway']['state_dir'] = '/home/dev/.local/state/tern-turn-relay'
        previous['gateway']['fingerprint'] = 'SHA256:' + base64.b64encode(bytes(range(1, 33))).decode().rstrip('=')
        with mock.patch.object(onboarding, 'current_configuration', return_value=previous), mock.patch.object(setup, 'discover', return_value=self.remote()):
            review = onboarding.discover(self.paths, {'ssh_destination': 'dev'})['review']
        self.assertEqual(review['listen_port'], 19002)
        self.assertEqual(review['configuration']['listen_port'], 19002)
        self.assertEqual(review['configuration']['gateway'], previous['gateway'])

    def test_new_daemon_uses_separate_reviewed_gateway_without_repinning_old_state(self):
        previous = self.review()['configuration']
        previous['gateway']['fingerprint'] = 'SHA256:' + base64.b64encode(bytes(range(1, 33))).decode().rstrip('=')
        before = json.dumps(previous, sort_keys=True)
        remote = dict(self.remote(), daemon_socket='/run/user/1001/other.sock', original_state_dir='/home/dev/other')
        with mock.patch.object(onboarding, 'current_configuration', return_value=previous), mock.patch.object(setup, 'discover', return_value=remote) as discovery:
            review = onboarding.discover(self.paths, {'ssh_destination': 'dev'})['review']
        self.assertNotEqual(review['configuration']['gateway']['state_dir'], previous['gateway']['state_dir'])
        self.assertEqual(review['configuration']['gateway']['daemon_socket'], '/run/user/1001/other.sock')
        self.assertNotIn('fingerprint', review['configuration']['gateway'])
        self.assertIn(previous['gateway']['state_dir'], ' '.join(review['changes']))
        self.assertEqual(discovery.call_args.args[0].excluded_state_dirs, [previous['gateway']['state_dir'] + '/native'])
        self.assertEqual(json.dumps(previous, sort_keys=True), before)

    def test_fresh_gateway_namespaces_are_stable_and_independent_per_installation(self):
        second_profile = self.root / 'second-profile'
        second_package = second_profile / 'plugins' / 'tern-turn-relay'
        second_package.mkdir(parents=True)
        second_args = onboarding.parser().parse_args(['inspect', '--package-dir', str(second_package)])
        second_paths = onboarding.context(second_args)
        with mock.patch.object(setup, 'discover', return_value=self.remote()), mock.patch.object(onboarding.socket, 'gethostname', return_value='machine-a'):
            first = onboarding.discover(self.paths, {'ssh_destination': 'dev'})['review']
            repeated = onboarding.discover(self.paths, {'ssh_destination': 'dev'})['review']
            second = onboarding.discover(second_paths, {'ssh_destination': 'dev'})['review']
        self.assertEqual(first['configuration']['gateway']['state_dir'], repeated['configuration']['gateway']['state_dir'])
        self.assertNotEqual(first['configuration']['gateway']['state_dir'], second['configuration']['gateway']['state_dir'])
        self.assertNotEqual(first['configuration']['gateway']['state_dir'], '/home/dev/.local/state/tern-turn-relay')
        with mock.patch.object(setup, 'discover', return_value=self.remote()), mock.patch.object(onboarding.socket, 'gethostname', return_value='machine-b'):
            other_machine = onboarding.discover(self.paths, {'ssh_destination': 'dev'})['review']
        self.assertNotEqual(first['configuration']['gateway']['state_dir'], other_machine['configuration']['gateway']['state_dir'])

    def test_changed_original_identity_on_same_daemon_does_not_reuse_old_gateway_pin(self):
        previous = self.review()['configuration']
        previous['gateway']['fingerprint'] = 'SHA256:' + base64.b64encode(bytes(range(1, 33))).decode().rstrip('=')
        new_pin = 'SHA256:' + base64.b64encode(bytes(range(2, 34))).decode().rstrip('=')
        remote = dict(self.remote(), original_state_dir='/home/dev/another-service', fingerprint=new_pin)
        with mock.patch.object(onboarding, 'current_configuration', return_value=previous), mock.patch.object(setup, 'discover', return_value=remote):
            review = onboarding.discover(self.paths, {'ssh_destination': 'dev'})['review']
        self.assertNotEqual(review['configuration']['gateway']['state_dir'], previous['gateway']['state_dir'])
        self.assertNotIn('fingerprint', review['configuration']['gateway'])

    def test_port_only_workspace_change_uses_different_gateway_namespace(self):
        previous = self.review()['configuration']
        previous['gateway']['fingerprint'] = 'SHA256:' + base64.b64encode(bytes(range(1, 33))).decode().rstrip('=')
        before = json.dumps(previous, sort_keys=True)
        remote = dict(self.remote(), target_port=9000)
        with mock.patch.object(onboarding, 'current_configuration', return_value=previous), mock.patch.object(setup, 'discover', return_value=remote):
            review = onboarding.discover(self.paths, {'ssh_destination': 'dev'})['review']
        self.assertNotEqual(review['configuration']['gateway']['state_dir'], previous['gateway']['state_dir'])
        self.assertNotIn('fingerprint', review['configuration']['gateway'])
        self.assertEqual(json.dumps(previous, sort_keys=True), before)

    def test_same_workspace_through_another_alias_preserves_existing_gateway(self):
        previous = self.review()['configuration']
        previous['gateway']['state_dir'] = '/home/dev/.local/state/tern-turn-relay'
        previous['gateway']['fingerprint'] = 'SHA256:' + base64.b64encode(bytes(range(1, 33))).decode().rstrip('=')
        with mock.patch.object(onboarding, 'current_configuration', return_value=previous), mock.patch.object(setup, 'discover', return_value=self.remote()):
            review = onboarding.discover(self.paths, {'ssh_destination': 'other-alias'})['review']
        self.assertEqual(review['configuration']['gateway'], previous['gateway'])

    def test_apply_rejects_modified_review_before_installer_or_write(self):
        review = self.review()
        review['configuration']['target']['port'] = 9999
        with mock.patch.object(setup, 'discover', return_value=self.remote()), mock.patch('install.install') as install:
            with self.assertRaisesRegex(onboarding.OnboardingError, 'review again'):
                onboarding.apply(self.paths, {'review': review}, self.args)
        install.assert_not_called()
        self.assertFalse(Path(self.paths['data_dir']).exists())

    def test_apply_rejects_changed_process_selection(self):
        review = self.review()
        remote = dict(self.remote(), candidate_id='b' * 24)
        with mock.patch.object(setup, 'discover', return_value=remote), mock.patch('install.install') as install:
            with self.assertRaises(onboarding.OnboardingError):
                onboarding.apply(self.paths, {'review': review}, self.args)
        install.assert_not_called()

    def test_selection_rejects_typed_remote_path_instead_of_candidate_id(self):
        with mock.patch.object(setup, 'discover') as remote:
            with self.assertRaises(onboarding.OnboardingError):
                onboarding.discover(self.paths, {'ssh_destination': 'dev', 'candidate_id': '/run/daemon.sock'})
        remote.assert_not_called()

    def test_credential_cancel_returns_redacted_json(self):
        with mock.patch.object(credentials, 'configure_native', side_effect=credentials.CredentialError('Local credential change cancelled.', 6)):
            code, result = self.cli('{}', 'configure-credentials')
        self.assertEqual(code, 6)
        self.assertEqual(result['code'], 'cancelled')

    def test_credential_change_does_not_apply_control_socket_length_limit(self):
        profile = self.root / ('long-profile-' + 'x' * 100)
        package = profile / 'plugins' / 'tern-turn-relay'
        package.mkdir(parents=True)
        args = onboarding.parser().parse_args(['configure-credentials', '--package-dir', str(package)])
        with mock.patch.object(credentials, 'configure_native', side_effect=credentials.CredentialError('Local credential change cancelled.', 6)):
            with self.assertRaises(credentials.CredentialError) as failure:
                onboarding.execute(args, {})
        self.assertEqual(failure.exception.exit_code, 6)
        locks = profile / 'plugin-data' / 'tern-turn-relay' / 'runtime'
        self.assertTrue((locks / 'command.lock').is_file())
        self.assertTrue((locks / 'service.lock').is_file())
        self.assertFalse((locks / 'control.sock').exists())

    def test_apply_hands_only_reviewed_configuration_to_installer(self):
        credential = Path(self.paths['credential_file'])
        credential.parent.mkdir(parents=True, mode=0o700)
        credential.write_text(json.dumps(KEY))
        credential.chmod(0o600)
        with mock.patch.object(setup, 'discover', return_value=self.remote()):
            review = onboarding.discover(self.paths, {'ssh_destination': 'dev', 'listen_port': 19001})['review']
        self.assertEqual(review['configuration']['listen_port'], 19001)
        seen = {}
        def install(args):
            seen.update(vars(args))
            self.assertEqual(json.loads(args.config.read_text()), review['configuration'])
            return {'ok': True, 'connection_started': False}
        with mock.patch.object(setup, 'discover', return_value=self.remote()), mock.patch('install.install', side_effect=install):
            result = onboarding.apply(self.paths, {'review': review}, self.args)
        self.assertTrue(result['configured'])
        self.assertFalse(result['connection_started'])
        self.assertIsNone(seen['expected_config_sha256'])
        self.assertFalse(seen['migrate_native'])
        self.assertFalse(seen['config'].exists())

    def test_installer_failure_preserves_prior_configuration_and_removes_staging(self):
        credential = Path(self.paths['credential_file'])
        credential.parent.mkdir(parents=True, mode=0o700)
        credential.write_text(json.dumps(KEY))
        credential.chmod(0o600)
        config = self.review()['configuration']
        config['gateway']['fingerprint'] = 'SHA256:' + base64.b64encode(bytes(range(1, 33))).decode().rstrip('=')
        destination = Path(self.paths['config_file'])
        destination.write_text(json.dumps(config))
        destination.chmod(0o600)
        before = destination.read_bytes()
        review = self.review()
        with mock.patch.object(setup, 'discover', return_value=self.remote()), mock.patch('install.install', side_effect=ValueError('synthetic install failure')):
            with self.assertRaises(ValueError):
                onboarding.apply(self.paths, {'review': review, 'authorize_replace': True}, self.args)
        self.assertEqual(destination.read_bytes(), before)
        self.assertEqual(list(destination.parent.glob('.onboarding-*')), [])

    def test_unexpected_failures_are_redacted(self):
        with mock.patch.object(onboarding, 'execute', side_effect=RuntimeError(KEY['api_token'])):
            code, result = self.cli('{}')
        self.assertEqual(code, 7)
        self.assertEqual(result['code'], 'operation-failed')

    def test_management_requires_exact_confirmation_and_rejects_extra_scope(self):
        for action in ('update', 'uninstall'):
            for request in ({}, {'confirm': False}, {'confirm': 1}, {'confirm': 'true'},
                            {'confirm': True, 'repository': 'untrusted'}):
                with mock.patch('install.run') as run, mock.patch('uninstall.uninstall') as uninstall:
                    code, result = self.cli(json.dumps(request), action)
                self.assertNotEqual(code, 0)
                self.assertFalse(result['ok'])
                run.assert_not_called()
                uninstall.assert_not_called()

    def test_management_refuses_running_relay_without_invoking_stop(self):
        runtime = Path(self.paths['data_dir']) / 'runtime'
        runtime.mkdir(parents=True)
        with (runtime / 'service.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for action in ('update', 'uninstall'):
                with mock.patch('install.run') as run, mock.patch('uninstall.uninstall') as uninstall:
                    code, result = self.cli('{"confirm":true}', action)
                self.assertEqual(code, 6)
                self.assertEqual(result['code'], 'stopped-required')
                run.assert_not_called()
                uninstall.assert_not_called()

    def test_update_requires_native_registration_and_rejects_stale_context(self):
        legacy = self.root / 'legacy-package'
        legacy.mkdir()
        paths = dict(self.paths, package_dir=str(legacy))
        self.args.action = 'update'
        with mock.patch('install.plugin_link', return_value=(self.profile / 'plugins' / 'tern-turn-relay.path', legacy)), mock.patch('install.run') as run:
            with self.assertRaises(onboarding.OnboardingError) as failure:
                onboarding.manage(paths, {'confirm': True}, self.args)
        self.assertEqual(failure.exception.code, 'migration-required')
        run.assert_not_called()
        with mock.patch('install.plugin_link', return_value=(None, None)), mock.patch('install.run') as run:
            with self.assertRaises(onboarding.OnboardingError) as failure:
                onboarding.manage(self.paths, {'confirm': True}, self.args)
        self.assertEqual(failure.exception.code, 'registration-changed')
        run.assert_not_called()

    def test_configured_uninstall_without_ownership_record_is_refused(self):
        config = Path(self.paths['config_file'])
        config.parent.mkdir(parents=True)
        config.write_bytes(b'{"existing":"preserve"}')
        with mock.patch('install.run') as run, mock.patch('uninstall.uninstall') as uninstall:
            code, result = self.cli('{"confirm":true}', 'uninstall')
        self.assertEqual(code, 6)
        self.assertEqual(result['code'], 'ownership-required')
        self.assertEqual(config.read_bytes(), b'{"existing":"preserve"}')
        run.assert_not_called()
        uninstall.assert_not_called()

    def test_update_preserves_configuration_credentials_and_managed_runtime(self):
        data = Path(self.paths['data_dir'])
        credential = Path(self.paths['credential_file'])
        credential.parent.mkdir(parents=True)
        credential.write_text(json.dumps(KEY))
        credential.chmod(0o600)
        config = Path(self.paths['config_file'])
        config.write_bytes(b'{"existing":"preserve"}')
        managed = data / 'managed-python' / 'keep'
        managed.parent.mkdir()
        managed.write_bytes(b'preserved-runtime')
        before = {path: path.read_bytes() for path in (credential, config, managed)}
        environment = (Path('/verified/tern'), {}, self.profile / 'plugins', data)
        (self.package / 'old-version').write_text('old')
        def replace_package(*_args, **_kwargs):
            self.package.rename(self.root / 'replaced-native-package')
            self.package.mkdir()
            (self.package / 'new-version').write_text('new')
            return ''
        with mock.patch('install.tern_environment', return_value=environment), mock.patch('install.run', side_effect=replace_package) as run:
            code, result = self.cli('{"confirm":true}', 'update')
        self.assertEqual(code, 0)
        self.assertTrue(result['updated'])
        self.assertTrue(result['reload_expected'])
        self.assertEqual(run.call_count, 1)
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        self.assertFalse((self.package / 'old-version').exists())
        self.assertEqual((self.package / 'new-version').read_text(), 'new')
        self.assertEqual(onboarding.registration(self.paths), 'native')

    def test_fresh_native_removal_preserves_existing_credential(self):
        data = Path(self.paths['data_dir'])
        credential = Path(self.paths['credential_file'])
        credential.parent.mkdir(parents=True)
        credential.write_text(json.dumps(KEY))
        credential.chmod(0o600)
        before = credential.read_bytes()
        environment = (Path('/verified/tern'), {}, self.profile / 'plugins', data)
        def remove_package(*_args, **_kwargs):
            self.package.rmdir()
            return ''
        with mock.patch('install.tern_environment', return_value=environment), mock.patch('install.run', side_effect=remove_package) as run, mock.patch('uninstall.uninstall') as uninstall:
            code, result = self.cli('{"confirm":true}', 'uninstall')
        self.assertEqual(code, 0)
        self.assertTrue(result['plugin_removed'])
        self.assertTrue(result['credentials_preserved'])
        self.assertEqual(credential.read_bytes(), before)
        self.assertEqual(run.call_count, 1)
        uninstall.assert_not_called()
        self.assertFalse(self.package.exists())
        self.assertEqual(onboarding.registration(self.paths), 'unregistered')

    def test_fresh_removal_does_not_report_success_for_unchanged_registration(self):
        data = Path(self.paths['data_dir'])
        environment = (Path('/verified/tern'), {}, self.profile / 'plugins', data)
        with mock.patch('install.tern_environment', return_value=environment), mock.patch('install.run', return_value=''):
            code, result = self.cli('{"confirm":true}', 'uninstall')
        self.assertEqual(code, 7)
        self.assertEqual(result['code'], 'removal-unconfirmed')
        self.assertTrue(self.package.is_dir())

    def test_management_rejects_wrong_resolved_profile_before_mutation(self):
        data = Path(self.paths['data_dir'])
        environment = (Path('/verified/tern'), {}, self.root / 'other-plugins', data)
        with mock.patch('install.tern_environment', return_value=environment), mock.patch('install.run') as run:
            code, result = self.cli('{"confirm":true}', 'update')
        self.assertEqual(code, 6)
        self.assertEqual(result['code'], 'context-mismatch')
        run.assert_not_called()


class NativeCredentialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name).resolve() / 'credentials' / 'cloudflare.json'

    def tearDown(self):
        self.temporary.cleanup()

    def store(self):
        self.path.parent.mkdir(mode=0o700)
        self.path.write_text(json.dumps(KEY))
        self.path.chmod(0o600)
        return self.path.read_bytes()

    def test_native_dialog_never_places_secrets_in_argv_or_environment(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0,
                           (KEY['turn_key_id'] + '\n' + KEY['api_token'] + '\n').encode()))
        with mock.patch.object(credentials, 'probe_credentials') as probe:
            result = credentials.configure_native(self.path, runner=runner)
        argv = runner.call_args.args[0]
        self.assertEqual(argv[0], '/usr/bin/osascript')
        self.assertIn('with hidden answer', argv[2])
        self.assertNotIn('System Events', argv[2])
        self.assertNotIn('tell application', argv[2])
        self.assertNotIn(KEY['api_token'], repr(runner.call_args))
        self.assertNotIn('env', runner.call_args.kwargs)
        self.assertNotIn(KEY['api_token'], json.dumps(result))
        probe.assert_called_once_with(KEY)
        self.assertEqual(credentials.load_management_key(self.path), KEY)

    def test_existing_key_requires_consent_before_dialog_or_probe(self):
        before = self.store()
        runner = mock.Mock()
        with mock.patch.object(credentials, 'probe_credentials') as probe:
            with self.assertRaises(credentials.CredentialError):
                credentials.configure_native(self.path, runner=runner)
        self.assertEqual(self.path.read_bytes(), before)
        runner.assert_not_called()
        probe.assert_not_called()

    def test_cancellation_preserves_existing_key_and_does_not_probe(self):
        before = self.store()
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b'__CANCELLED__\n'))
        with mock.patch.object(credentials, 'probe_credentials') as probe:
            with self.assertRaisesRegex(credentials.CredentialError, 'cancelled'):
                credentials.configure_native(self.path, replace=True, runner=runner)
        self.assertEqual(self.path.read_bytes(), before)
        probe.assert_not_called()

    def test_failed_probe_preserves_existing_key(self):
        before = self.store()
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b'new-id\nnew-token\n'))
        with mock.patch.object(credentials, 'probe_credentials', side_effect=credentials.CredentialError('Validation failed.', 5)):
            with self.assertRaises(credentials.CredentialError):
                credentials.configure_native(self.path, replace=True, runner=runner)
        self.assertEqual(self.path.read_bytes(), before)

    def test_dialog_failure_never_echoes_captured_secret(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 1, KEY['api_token'].encode()))
        with self.assertRaises(credentials.CredentialError) as raised:
            credentials.native_management_key(runner)
        self.assertNotIn(KEY['api_token'], str(raised.exception))


class KernelSelectionTests(unittest.TestCase):
    def setUp(self):
        self.remote = {}
        exec(setup.REMOTE_DISCOVERY.split('\ntry:\n', 1)[0], self.remote)

    def test_daemon_parent_child_relationship_is_required_without_explicit_binding(self):
        service = {'pid': 100, 'start': '1000', 'daemon': None}
        child = {'pid': 101, 'ppid': 100, 'start': '1001', 'socket': '/run/owned.sock'}
        unrelated = dict(child, pid=102, ppid=1)
        reused = dict(child, pid=103, start='999')
        self.assertEqual(self.remote['related_daemons'](service, [child, unrelated, reused]), [child])
        self.assertEqual(self.remote['related_daemons'](service, [unrelated]), [])
        self.assertEqual(self.remote['related_daemons'](dict(service, daemon='/run/other.sock'), [child]), [])

    def test_candidate_id_changes_when_pid_is_reused_or_listener_rebound(self):
        service = {'pid': 100, 'start': '1000', 'state': '/home/dev/state'}
        daemon = {'pid': 101, 'start': '1001', 'socket': '/run/owned.sock'}
        listener = {'port': 8376, 'inode': '555'}
        candidate = self.remote['candidate_id'](service, daemon, listener)
        self.assertNotEqual(candidate, self.remote['candidate_id'](dict(service, start='2000'), daemon, listener))
        self.assertNotEqual(candidate, self.remote['candidate_id'](service, daemon, dict(listener, inode='556')))

    def test_udp_listener_requires_matching_process_inode_uid_and_bound_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            entry = Path(temporary)
            (entry / 'fd').mkdir()
            (entry / 'net').mkdir()
            (entry / 'fd' / '5').symlink_to('socket:[555]')
            rows = ['header',
                    '0: 0100007F:20B8 00000000:0000 07 0:0 00:0 0 1001 0 555',
                    '1: 0100007F:20B9 00000000:0000 07 0:0 00:0 0 1001 0 556',
                    '2: 0100007F:20BA 00000000:0000 07 0:0 00:0 0 1002 0 555',
                    '3: 0100007F:20BB 0100007F:0016 01 0:0 00:0 0 1001 0 555']
            (entry / 'net' / 'udp').write_text('\n'.join(rows) + '\n')
            self.assertEqual(self.remote['udp_listeners'](entry, 1001),
                             [{'port': 8376, 'address': '127.0.0.1', 'inode': '555'}])
            (entry / 'fd' / '5').unlink()
            self.assertEqual(self.remote['udp_listeners'](entry, 1001), [])

    def test_observed_native_udp6_is_selected_instead_of_iroh_ephemeral_sockets(self):
        with tempfile.TemporaryDirectory() as temporary:
            entry = Path(temporary)
            (entry / 'fd').mkdir()
            (entry / 'net').mkdir()
            for descriptor, inode in ((10, 1010), (11, 1011), (12, 1012)):
                (entry / 'fd' / str(descriptor)).symlink_to('socket:[%d]' % inode)
            (entry / 'net' / 'udp').write_text('header\n0: 00000000:909D 00000000:0000 07 0:0 00:0 0 1001 0 1011\n')
            (entry / 'net' / 'udp6').write_text('header\n'
                '0: 00000000000000000000000000000000:20B8 00000000000000000000000000000000:0000 07 0:0 00:0 0 1001 0 1010\n'
                '1: 00000000000000000000000000000000:E808 00000000000000000000000000000000:0000 07 0:0 00:0 0 1001 0 1012\n')
            listeners = self.remote['udp_listeners'](entry, 1001)
            self.assertEqual(len(listeners), 3)
            self.assertEqual(self.remote['native_listeners']({'listen': None, 'listeners': listeners}, '8.8.8.8'),
                             [{'port': 8376, 'address': '::', 'inode': '1010'}])
            (entry / 'fd' / '10').unlink()
            listeners = self.remote['udp_listeners'](entry, 1001)
            self.assertEqual(self.remote['native_listeners']({'listen': None, 'listeners': listeners}, '8.8.8.8'), [])

    def test_explicit_listener_requires_exact_observed_bind_and_accepts_target_ipv4(self):
        public = {'port': 9000, 'address': '8.8.8.8', 'inode': '10'}
        wildcard = {'port': 9000, 'address': '0.0.0.0', 'inode': '11'}
        unrelated = {'port': 9000, 'address': '1.1.1.1', 'inode': '12'}
        listeners = [public, wildcard, unrelated]
        select = self.remote['native_listeners']
        self.assertEqual(select({'listen': '8.8.8.8:9000', 'listeners': listeners}, '8.8.8.8'), [public])
        self.assertEqual(select({'listen': '0.0.0.0:9000', 'listeners': listeners}, '8.8.8.8'), [wildcard])
        self.assertEqual(select({'listen': '1.1.1.1:9000', 'listeners': listeners}, '8.8.8.8'), [])
        self.assertEqual(select({'listen': '8.8.8.8:9001', 'listeners': listeners}, '8.8.8.8'), [])
        self.assertEqual(select({'listen': None, 'listeners': listeners}, '8.8.8.8'), [])

    def test_owned_gateway_frontends_cannot_be_selected_as_original_services(self):
        classify = self.remote['gateway_frontend']
        self.assertTrue(classify({'state': '/home/dev/.local/state/tern-turn-relay/native'}, '/home/dev', []))
        self.assertTrue(classify({'state': '/custom/gateway/native'}, '/home/dev', ['/custom/gateway/native']))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            native = root / 'native'
            native.mkdir()
            self.assertFalse(classify({'state': str(native)}, '/home/dev', []))
            (root / 'daemon-identity.json').write_text('{"version":2}')
            self.assertTrue(classify({'state': str(native)}, '/home/dev', []))


if __name__ == '__main__':
    unittest.main()
