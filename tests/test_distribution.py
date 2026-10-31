"""Offline installer/uninstaller/release tests: external commands are mocked."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import install
import package_release
import uninstall
from relay_config import atomic_json, lock_file
from ssh_compat import BEGIN, END

PIN = 'SHA256:' + base64.b64encode(bytes(range(32))).decode().rstrip('=')
GATEWAY_PIN = 'SHA256:' + base64.b64encode(bytes(reversed(range(32)))).decode().rstrip('=')
MINIMAL = ('plugin.toml', 'config.example.json', 'relay.py', 'credentials.py', 'README.md')


def release_source(root):
    root.mkdir(mode=0o700)
    (root / 'plugin.toml').write_text('id = "tern-turn-relay"\nversion = "0.2.0"\n')
    (root / 'config.example.json').write_text('{"documentation_only":true}')
    (root / 'relay.py').write_text('"""synthetic runtime"""\n')
    (root / 'credentials.py').write_text('"""synthetic credentials module"""\n')
    (root / 'README.md').write_text('Synthetic release documentation\n')
    (root / 'private-key.json').write_text('NEVER PACKAGE THIS')
    (root / '.artifacts').mkdir()
    (root / '.artifacts' / 'secret').write_text('NEVER PACKAGE THIS')


def config(root):
    return {'schema': 3, 'ssh_destination': 'dev-host', 'target': {
        'name': 'dev-host', 'host': '8.8.8.8', 'port': 8376, 'user': 'developer', 'fingerprint': PIN},
        'listen_port': 18377, 'gateway': {'state_dir': '/home/developer/.local/state/tern-turn-relay',
        'daemon_socket': '/run/user/1001/tern/daemon.sock', 'fingerprint': GATEWAY_PIN},
        'credential_file': str(root / 'credentials.json'), 'dependency_dir': str(root / 'deps')}


class DistributionTests(unittest.TestCase):
    def test_allowlist_is_explicit_and_contains_real_entrypoints(self):
        for name in ('relay.py', 'credentials.py', 'setup.py', 'install.py', 'uninstall.py',
                     'remote_gateway.py', 'README.md'):
            self.assertIn(name, package_release.FILES)
        for name in package_release.FILES + package_release.TESTS:
            self.assertNotIn('..', Path(name).parts)
            self.assertNotIn('.artifacts', Path(name).parts)
            self.assertNotIn('.sdk', Path(name).parts)
            self.assertNotIn('runtime', Path(name).parts)
            self.assertNotEqual(name, 'credentials.json')

    def test_reproducible_archive_checksum_excludes_unlisted_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            release_source(source)
            with mock.patch.object(package_release, 'FILES', MINIMAL), mock.patch.object(package_release, 'TESTS', ()):
                first = package_release.create_release(source, root / 'a')
                second = package_release.create_release(source, root / 'b')
            archive = Path(first['archive'])
            self.assertEqual(archive.read_bytes(), Path(second['archive']).read_bytes())
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), first['sha256'])
            self.assertIn(first['sha256'], Path(first['checksum']).read_text())
            with tarfile.open(archive, 'r:gz') as opened:
                self.assertEqual({member.name for member in opened},
                                 {'tern-turn-relay-0.2.0/' + name for name in MINIMAL})
                self.assertTrue(all(member.uid == 0 and member.gid == 0 and not member.uname for member in opened))
            with mock.patch.object(package_release, 'FILES', MINIMAL), mock.patch.object(package_release, 'TESTS', ()):
                with self.assertRaisesRegex(ValueError, 'already exists'):
                    package_release.create_release(source, root / 'a')

    def test_packager_rejects_symlink_input_and_runnable_example(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            release_source(source)
            with mock.patch.object(package_release, 'FILES', MINIMAL):
                (source / 'config.example.json').write_text('{"schema":3,"documentation_only":true}')
                with self.assertRaisesRegex(ValueError, 'non-runnable'):
                    package_release.release_files(source, include_tests=False)
                (source / 'config.example.json').write_text('{"documentation_only":true}')
                (source / 'relay.py').unlink()
                (source / 'relay.py').symlink_to(source / 'credentials.py')
                with self.assertRaisesRegex(ValueError, 'non-symlink'):
                    package_release.release_files(source, include_tests=False)

    def test_durable_source_survives_unpack_removal_and_upgrade_keeps_previous(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, data = root / 'unpacked', root / 'data'
            release_source(source)
            data.mkdir(mode=0o700)
            with mock.patch.object(package_release, 'FILES', MINIMAL):
                first = install.durable_package(data, source)
                self.assertEqual(first, install.durable_package(data, source))
                (source / 'relay.py').write_text('"""new synthetic runtime"""\n')
                second = install.durable_package(data, source)
            self.assertNotEqual(first, second)
            shutil.rmtree(source)
            self.assertIn('synthetic runtime', (first / 'relay.py').read_text())
            self.assertIn('new synthetic runtime', (second / 'relay.py').read_text())
            self.assertFalse((second / 'private-key.json').exists())
            self.assertFalse((second / '.artifacts').exists())
            first.chmod(0o700)
            second.chmod(0o700)

    def test_durable_package_renames_writable_staging_then_seals_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, data = root / 'source', root / 'data'
            release_source(source)
            data.mkdir(mode=0o700)
            rename = os.rename
            def require_writable_staging(staging, destination):
                self.assertEqual(Path(staging).stat().st_mode & 0o777, 0o700)
                rename(staging, destination)
            with mock.patch.object(package_release, 'FILES', MINIMAL), \
                    mock.patch.object(install.os, 'rename', side_effect=require_writable_staging):
                package = install.durable_package(data, source)
            self.assertEqual(package.stat().st_mode & 0o777, 0o500)
            self.assertEqual(list((data / 'packages').iterdir()), [package])
            package.chmod(0o700)

    def test_durable_package_failed_sealing_preserves_copy_for_verified_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, data = root / 'source', root / 'data'
            release_source(source)
            data.mkdir(mode=0o700)
            chmod = Path.chmod
            def fail_sealing(path, mode, *args, **kwargs):
                if mode == 0o500:
                    raise PermissionError('synthetic final chmod failure')
                return chmod(path, mode, *args, **kwargs)
            with mock.patch.object(package_release, 'FILES', MINIMAL):
                with mock.patch.object(Path, 'chmod', new=fail_sealing):
                    with self.assertRaisesRegex(PermissionError, 'final chmod failure'):
                        install.durable_package(data, source)
                packages = list((data / 'packages').iterdir())
                self.assertEqual(len(packages), 1)
                self.assertFalse(packages[0].name.startswith('.package-'))
                self.assertEqual(packages[0].stat().st_mode & 0o777, 0o700)
                self.assertEqual((packages[0] / 'relay.py').read_bytes(), (source / 'relay.py').read_bytes())
                package = install.durable_package(data, source)
            self.assertEqual(package, packages[0])
            self.assertEqual(package.stat().st_mode & 0o777, 0o500)
            package.chmod(0o700)

    def test_durable_package_failed_rename_cleans_only_private_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, data = root / 'source', root / 'data'
            release_source(source)
            data.mkdir(mode=0o700)
            with mock.patch.object(package_release, 'FILES', MINIMAL), \
                    mock.patch.object(install.os, 'rename', side_effect=PermissionError('synthetic rename failure')):
                with self.assertRaisesRegex(PermissionError, 'rename failure'):
                    install.durable_package(data, source)
            self.assertEqual(list((data / 'packages').iterdir()), [])
            self.assertTrue((source / 'relay.py').is_file())


    def test_modified_immutable_package_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, data = root / 'unpacked', root / 'data'
            release_source(source)
            data.mkdir(mode=0o700)
            with mock.patch.object(package_release, 'FILES', MINIMAL):
                package = install.durable_package(data, source)
                (package / 'relay.py').write_text('user-modified')
                with self.assertRaisesRegex(ValueError, 'modified'):
                    install.durable_package(data, source)
                self.assertEqual((package / 'relay.py').read_text(), 'user-modified')
                package.chmod(0o700)

    def test_valid_dependencies_are_reused_without_pip(self):
        with mock.patch.object(install, 'dependencies_valid', return_value=True), \
                mock.patch.object(install, 'run') as run:
            install.ensure_dependencies(Path('/unused/deps'), {})
        run.assert_not_called()

    def test_missing_dependencies_use_bounded_exact_pins_in_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve() / 'deps'
            with mock.patch.object(install, 'dependencies_valid', side_effect=[False, True]), \
                    mock.patch.object(install, 'run') as run:
                install.ensure_dependencies(target, {})
            argv = run.call_args.args[0]
            for name, version in install.VERSIONS.items():
                self.assertIn(name + '==' + version, argv)
            self.assertIn('--no-deps', argv)
            self.assertIn('--only-binary=:all:', argv)
            self.assertEqual(run.call_args.kwargs['timeout'], 180)
            self.assertTrue(target.is_dir())

    def test_incompatible_existing_dependencies_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve()
            (target / 'unrelated').write_text('keep')
            with mock.patch.object(install, 'dependencies_valid', return_value=False), \
                    mock.patch.object(install, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'preserved'):
                    install.ensure_dependencies(target, {})
            run.assert_not_called()
            self.assertEqual((target / 'unrelated').read_text(), 'keep')

    def test_default_upgrade_keeps_config_and_explicit_replacement_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            current = root / 'config.json'
            proposed = root / 'new.json'
            old = config(root)
            atomic_json(current, old)
            new = dict(old, listen_port=18378)
            atomic_json(proposed, new)
            self.assertEqual(install.selected_config(current, None, False), old)
            with self.assertRaisesRegex(ValueError, 'preserved'):
                install.selected_config(current, proposed, False)
            self.assertEqual(install.selected_config(current, proposed, True), new)
            self.assertEqual(json.loads(current.read_text()), old)

    def test_live_service_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = lock_file(root / 'service.lock')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(ValueError, 'Disconnect TURN'):
                    install.require_stopped(root)
            finally:
                os.close(descriptor)


class LegacyUpgradeTests(unittest.TestCase):
    def exercise_upgrade(self, fail_manifest=False, fail_links=False, path_marker=False):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary).resolve()
            data, plugins = root / 'data', root / 'plugins'
            data.mkdir(mode=0o700)
            plugins.mkdir()
            old_source, new_package = root / 'old-unpacked', data / 'packages' / 'new'
            old_source.mkdir()
            new_package.mkdir(parents=True)
            link = plugins / (install.PLUGIN_ID + '.path' if path_marker else install.PLUGIN_ID)
            def register(source):
                if path_marker:
                    link.write_text(str(source) + '\n')
                    link.chmod(0o600)
                else:
                    link.symlink_to(source)
            register(old_source)
            original = config(data)
            atomic_json(data / 'config.json', original)
            credential = data / 'credentials.json'
            credential.write_text('opaque private bytes')
            credential.chmod(0o600)
            ssh = root / 'ssh-config'
            ssh.write_text('Host unrelated\n')
            ssh.chmod(0o600)
            args = SimpleNamespace(tern=None, config_dir=None, ssh_config=ssh, config=None, replace_config=False)
            if fail_links:
                proposed = root / 'replacement.json'
                atomic_json(proposed, dict(original, listen_port=18378))
                args.config, args.replace_config = proposed, True
            descriptor = {'fingerprint': GATEWAY_PIN, 'daemon_socket': original['gateway']['daemon_socket']}
            def link_command(argv, env):
                self.assertEqual(argv[1:3], ['plugin', 'link'])
                if fail_links and Path(argv[-1]) == old_source:
                    raise ValueError('synthetic rollback link failure')
                link.unlink()
                register(Path(argv[-1]))
                if fail_links:
                    raise ValueError('synthetic activation link failure')
                return '{}'
            def compat(_config, path):
                path.write_text(BEGIN + 'Match all\n' + END + 'Host unrelated\n')
            def save(path, value):
                if fail_manifest and path.name == 'installation.json':
                    raise OSError('synthetic manifest failure')
                atomic_json(path, value)
            with mock.patch.object(install, 'tern_environment', return_value=(Path('/tern'), {}, plugins, data)), \
                    mock.patch.object(install, 'ensure_dependencies'), \
                    mock.patch.object(install, 'durable_package', return_value=new_package), \
                    mock.patch('gateway_client.provision', new=mock.AsyncMock(return_value=descriptor)), \
                    mock.patch.object(install, 'install_compat', side_effect=compat), \
                    mock.patch.object(install, 'run', side_effect=link_command), \
                    mock.patch.object(install, 'atomic_json', side_effect=save):
                if fail_links:
                    with self.assertRaises(install.InstallRecoveryError) as failure:
                        install.install(args)
                    self.assertEqual([name for name, _ in failure.exception.recovery_failures], ['plugin link'])
                    self.assertIn('all independent rollback actions', str(failure.exception))
                    self.assertEqual(str(failure.exception.__cause__), 'synthetic activation link failure')
                    self.assertEqual(str(failure.exception.recovery_failures[0][1]), 'synthetic rollback link failure')
                elif fail_manifest:
                    with self.assertRaises(OSError):
                        install.install(args)
                else:
                    result = install.install(args)
                    self.assertTrue(result['ok'])
            self.assertEqual(json.loads((data / 'config.json').read_text()), original)
            self.assertEqual(credential.read_text(), 'opaque private bytes')
            self.assertTrue(old_source.exists())
            self.assertEqual(install.plugin_link(plugins)[1], old_source if fail_manifest else new_package)
            if fail_manifest or fail_links:
                self.assertEqual(ssh.read_text(), 'Host unrelated\n')
            else:
                self.assertTrue((data / 'installation.json').is_file())

    def test_legacy_link_upgrade_preserves_existing_config_and_credentials(self):
        self.exercise_upgrade()

    def test_failed_activation_restores_legacy_link_config_and_ssh(self):
        self.exercise_upgrade(fail_manifest=True)

    def test_activation_and_rollback_link_failure_still_restore_config_and_ssh(self):
        self.exercise_upgrade(fail_links=True)

    def test_path_marker_legacy_upgrade_preserves_config_and_credentials(self):
        self.exercise_upgrade(path_marker=True)

    def test_path_marker_activation_failure_restores_previous_registration(self):
        self.exercise_upgrade(fail_manifest=True, path_marker=True)

    def test_path_marker_dual_link_failure_restores_config_and_ssh(self):
        self.exercise_upgrade(fail_links=True, path_marker=True)


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.data = self.root / 'data'
        self.plugins = self.root / 'plugins'
        self.package = self.data / 'packages' / '0.2.0-synthetic'
        self.package.mkdir(parents=True, mode=0o700)
        self.plugins.mkdir()
        helper = self.package / 'relay.py'
        helper.write_text('synthetic runtime')
        helper.chmod(0o600)
        self.link = self.plugins / install.PLUGIN_ID
        self.link.symlink_to(self.package)
        self.ssh = self.root / 'ssh-config'
        self.unrelated = 'Host unrelated\n    HostName example.invalid\n'
        self.block = BEGIN + 'Match all\n' + END
        self.ssh.write_text(self.block + self.unrelated)
        self.ssh.chmod(0o600)
        self.credential = self.data / 'credentials.json'
        self.credential.write_text('private material retained')
        self.config = self.data / 'config.json'
        self.config.write_text('configuration retained')
        atomic_json(self.data / 'installation.json', {'schema': 1, 'plugin': install.PLUGIN_ID,
            'plugins': str(self.plugins), 'package': str(self.package), 'ssh_config': str(self.ssh),
            'ssh_block_sha256': install.ssh_block_digest(self.block + self.unrelated)})
        self.args = SimpleNamespace(tern=None, config_dir=None, ssh_config=None)

    def invoke(self, leave_registration=False, fail_remove=False, edit_ssh=False):
        def run(argv, env):
            if 'stop' in argv:
                return '{"ok":true,"state":"stopped"}'
            native = self.link.is_dir() and not self.link.is_symlink()
            verb = 'remove' if native or self.link.is_symlink() else 'unlink'
            self.assertEqual(argv[-3:], ['plugin', verb, install.PLUGIN_ID])
            self.assertEqual(self.ssh.read_text(), self.unrelated)
            if not leave_registration:
                if native:
                    shutil.rmtree(self.link)
                else:
                    self.link.unlink()
            if edit_ssh:
                self.ssh.write_text(self.unrelated + 'Host independently-added\n')
            if fail_remove:
                raise ValueError('synthetic plugin CLI failure')
            return '{}'
        with mock.patch.object(uninstall, 'tern_environment', return_value=(Path('/tern'), {}, self.plugins, self.data)), \
                mock.patch.object(uninstall, 'run', side_effect=run) as command:
            result = uninstall.uninstall(self.args)
            return result, command.call_args_list

    def test_unlink_and_exact_marked_rule_removal_preserve_all_data(self):
        result, calls = self.invoke()
        self.assertTrue(result['credentials_preserved'])
        self.assertEqual(self.ssh.read_text(), self.unrelated)
        self.assertFalse(self.link.is_symlink())
        self.assertEqual(self.credential.read_text(), 'private material retained')
        self.assertEqual(self.config.read_text(), 'configuration retained')
        self.assertTrue(self.package.is_dir())
        self.assertEqual(len(calls), 2)
        self.assertNotIn('ssh', calls[0].args[0])

    def test_changed_marked_rule_is_not_removed(self):
        changed = BEGIN + 'Match host changed\n' + END + self.unrelated
        self.ssh.write_text(changed)
        with self.assertRaisesRegex(ValueError, 'belongs to another'):
            self.invoke()
        self.assertEqual(self.ssh.read_text(), changed)
        self.assertTrue(self.link.is_symlink())

    def test_different_plugin_link_is_not_unlinked(self):
        self.link.unlink()
        self.link.symlink_to(self.root)
        with self.assertRaisesRegex(ValueError, 'points elsewhere'):
            uninstall.owned_installation(self.data, self.plugins)
        self.assertTrue(self.link.is_symlink())

    def test_digest_covers_only_marked_block_not_other_user_rules(self):
        self.assertEqual(install.ssh_block_digest(self.block + self.unrelated),
                         install.ssh_block_digest(self.block + 'Host another\n'))
        with self.assertRaises(ValueError):
            install.ssh_block_digest(self.unrelated + self.block)

    def use_path_marker(self, source=None):
        self.link.unlink()
        self.link = self.plugins / (install.PLUGIN_ID + '.path')
        self.link.write_text(str(source or self.package) + '\n')
        self.link.chmod(0o600)

    def test_path_marker_uninstall_calls_native_unlink_and_preserves_secrets(self):
        self.use_path_marker()
        result, calls = self.invoke()
        self.assertTrue(result['plugin_unlinked'])
        self.assertFalse(self.link.exists())
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.ssh.read_text(), self.unrelated)
        self.assertEqual(self.credential.read_text(), 'private material retained')

    def test_path_marker_pointing_elsewhere_is_not_removed(self):
        self.use_path_marker(self.root)
        with self.assertRaisesRegex(ValueError, 'points elsewhere'):
            uninstall.owned_installation(self.data, self.plugins)
        self.assertTrue(self.link.is_file())

    def test_retained_path_marker_cannot_report_success_or_remove_ssh_rule(self):
        self.use_path_marker()
        with self.assertRaisesRegex(ValueError, 'did not remove'):
            self.invoke(leave_registration=True)
        self.assertTrue(self.link.is_file())
        self.assertEqual(self.ssh.read_text(), self.block + self.unrelated)

    def test_both_registration_representations_fail_closed(self):
        marker = self.plugins / (install.PLUGIN_ID + '.path')
        marker.write_text(str(self.package))
        marker.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'both symlink and path-marker'):
            install.plugin_link(self.plugins)

    def test_path_marker_rejects_relative_multiline_and_public_write(self):
        self.use_path_marker()
        for value in ('relative/source', str(self.package) + '\n/another/source\n'):
            self.link.write_text(value)
            with self.assertRaisesRegex(ValueError, 'one absolute path'):
                install.plugin_link(self.plugins)
        self.link.write_text(str(self.package))
        self.link.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            install.plugin_link(self.plugins)

    def test_symlink_path_marker_is_never_followed(self):
        self.use_path_marker()
        self.link.unlink()
        self.link.symlink_to(self.config)
        with self.assertRaises(OSError):
            install.plugin_link(self.plugins)
        self.assertEqual(self.config.read_text(), 'configuration retained')

    def use_native_copy(self):
        self.link.unlink()
        shutil.copytree(self.package, self.link)
        self.package = self.link
        (self.package / 'relay.py').chmod(0o644)  # Native git installs need not be 0600.
        manifest = self.data / 'installation.json'
        record = json.loads(manifest.read_text())
        record.update(package=str(self.package), registration='native')
        atomic_json(manifest, record)

    def test_native_uninstall_uses_remove_preserving_all_private_data(self):
        self.use_native_copy()
        runtime = self.data / 'managed-python'
        runtime.mkdir()
        (runtime / 'keep').write_text('managed runtime retained')
        result, calls = self.invoke()
        self.assertTrue(result['plugin_removed'])
        self.assertFalse(result['installed_package_preserved'])
        self.assertFalse(self.package.exists())
        self.assertEqual(self.ssh.read_text(), self.unrelated)
        self.assertEqual(self.config.read_text(), 'configuration retained')
        self.assertEqual(self.credential.read_text(), 'private material retained')
        self.assertTrue((runtime / 'keep').exists())
        self.assertEqual(len(calls), 2)

    def test_failed_native_removal_preserves_owned_ssh_rule(self):
        self.use_native_copy()
        with self.assertRaisesRegex(ValueError, 'did not remove'):
            self.invoke(leave_registration=True)
        self.assertEqual(self.ssh.read_text(), self.block + self.unrelated)
        self.assertTrue(self.package.is_dir())

    def test_native_ssh_cleanup_failure_keeps_package_available_for_retry(self):
        self.use_native_copy()
        self.args.require_stopped_only = True
        with mock.patch.object(uninstall, 'update', side_effect=PermissionError('synthetic SSH write failure')):
            with self.assertRaisesRegex(PermissionError, 'SSH write failure'):
                self.invoke()
        self.assertTrue((self.package / 'relay.py').is_file())
        self.assertEqual(self.ssh.read_text(), self.block + self.unrelated)
        self.assertEqual(self.config.read_text(), 'configuration retained')

    def test_native_cli_error_after_removal_reports_observed_success(self):
        self.use_native_copy()
        result, _ = self.invoke(fail_remove=True)
        self.assertTrue(result['ok'])
        self.assertTrue(result['plugin_removed'])
        self.assertTrue(result['cli_reported_error'])
        self.assertFalse(self.package.exists())
        self.assertEqual(self.ssh.read_text(), self.unrelated)

    def test_native_cli_failure_before_removal_restores_exact_ssh_bytes(self):
        self.use_native_copy()
        original = self.ssh.read_bytes()
        with self.assertRaisesRegex(ValueError, 'synthetic plugin CLI failure'):
            self.invoke(leave_registration=True, fail_remove=True)
        self.assertTrue((self.package / 'relay.py').is_file())
        self.assertEqual(self.ssh.read_bytes(), original)

    def test_failed_native_removal_never_overwrites_independent_ssh_changes(self):
        self.use_native_copy()
        with self.assertRaises(uninstall.UninstallRecoveryError):
            self.invoke(leave_registration=True, fail_remove=True, edit_ssh=True)
        self.assertTrue((self.package / 'relay.py').is_file())
        self.assertEqual(self.ssh.read_text(), self.unrelated + 'Host independently-added\n')

    def test_failed_native_removal_reports_ssh_restoration_failure(self):
        self.use_native_copy()
        update = uninstall.update
        attempts = []
        def fail_restore(path, transform):
            attempts.append(path)
            if len(attempts) == 2:
                raise PermissionError('synthetic SSH restoration failure')
            return update(path, transform)
        with mock.patch.object(uninstall, 'update', side_effect=fail_restore):
            with self.assertRaises(uninstall.UninstallRecoveryError) as failure:
                self.invoke(leave_registration=True, fail_remove=True)
        self.assertIsInstance(failure.exception.recovery_error, PermissionError)
        self.assertTrue((self.package / 'relay.py').is_file())
        self.assertEqual(self.ssh.read_text(), self.unrelated)

    def test_native_registration_cannot_borrow_legacy_ownership_record(self):
        self.link.unlink()
        self.link.mkdir()
        with self.assertRaisesRegex(ValueError, 'points elsewhere'):
            uninstall.owned_installation(self.data, self.plugins)

    def test_native_ui_uninstall_never_requests_stop(self):
        self.use_native_copy()
        self.args.require_stopped_only = True
        self.args.data_dir = self.data
        self.args.package_dir = self.package
        result, calls = self.invoke()
        self.assertFalse(result['stop_requested'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args[0][-3:], ['plugin', 'remove', install.PLUGIN_ID])

    def test_native_ui_uninstall_refuses_running_service_without_stop(self):
        self.args.require_stopped_only = True
        runtime = install.state_directory(self.data / 'runtime')
        descriptor = lock_file(runtime / 'service.lock')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with mock.patch.object(uninstall, 'tern_environment',
                    return_value=(Path('/tern'), {}, self.plugins, self.data)), \
                    mock.patch.object(uninstall, 'run') as command:
                with self.assertRaisesRegex(ValueError, 'Disconnect TURN'):
                    uninstall.uninstall(self.args)
                command.assert_not_called()
        finally:
            os.close(descriptor)
        self.assertTrue(self.link.is_symlink())
        self.assertEqual(self.ssh.read_text(), self.block + self.unrelated)

    def test_native_ui_uninstall_rejects_missing_registration(self):
        self.args.require_stopped_only = True
        self.use_path_marker()
        self.link.unlink()
        with self.assertRaisesRegex(ValueError, 'registration is missing'):
            self.invoke()
        self.assertEqual(self.ssh.read_text(), self.block + self.unrelated)

    def test_native_ui_uninstall_asserts_reviewed_profile_and_package(self):
        self.args.require_stopped_only = True
        self.args.data_dir = self.root / 'another-profile'
        with self.assertRaisesRegex(ValueError, 'selected Tern profile'):
            self.invoke()
        self.args.data_dir = self.data
        self.args.package_dir = self.root
        with self.assertRaisesRegex(ValueError, 'reviewed installation'):
            self.invoke()
        self.assertTrue(self.link.is_symlink())


if __name__ == '__main__':
    unittest.main()
