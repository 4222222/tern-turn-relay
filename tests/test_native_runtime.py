"""Offline native installation/migration and managed-runtime boundary tests."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import install
import managed_runtime
import package_release
from relay_config import atomic_json, lock_file
from test_distribution import config, GATEWAY_PIN, MINIMAL, release_source
from ssh_compat import BEGIN, END


class NativeInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.data = self.root / 'data'
        self.data.mkdir(mode=0o700)
        self.plugins = self.root / 'plugins'
        self.plugins.mkdir()
        self.native = self.plugins / install.PLUGIN_ID
        release_source(self.native)
        self.credential = self.data / 'credentials.json'
        self.credential.write_text('opaque credential; never read')
        self.credential.chmod(0o600)
        self.ssh = self.root / 'ssh-config'
        self.ssh.write_text('Host unrelated\n')
        self.ssh.chmod(0o600)
        self.proposal = self.root / 'reviewed.json'
        self.config = config(self.data)
        atomic_json(self.proposal, self.config)
        self.args = SimpleNamespace(tern=None, config_dir=None, ssh_config=self.ssh,
            config=self.proposal, replace_config=False, data_dir=self.data,
            package_dir=self.native, expected_config_sha256=None)

    def invoke(self, fail_manifest=False, run=None):
        async def provision(_config):
            # The installer retains service.lock, rather than just checking it.
            descriptor = lock_file(self.data / 'runtime' / 'service.lock')
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)
            return {'fingerprint': GATEWAY_PIN, 'daemon_socket': self.config['gateway']['daemon_socket']}
        def save(path, value):
            if fail_manifest and path.name == 'installation.json':
                raise OSError('synthetic manifest failure')
            atomic_json(path, value)
        def compat(_config, path):
            path.write_text(BEGIN + 'Match all\n' + END + 'Host unrelated\n')
        with mock.patch.object(install, 'ROOT', self.args.package_dir), \
                mock.patch.object(package_release, 'FILES', MINIMAL), \
                mock.patch.object(install, 'tern_environment', return_value=(Path('/tern'), {}, self.plugins, self.data)), \
                mock.patch.object(install, 'ensure_dependencies') as deps, \
                mock.patch.object(install, 'durable_package') as durable, \
                mock.patch('gateway_client.provision', new=mock.AsyncMock(side_effect=provision)), \
                mock.patch.object(install, 'install_compat', side_effect=compat), \
                mock.patch.object(install, 'atomic_json', side_effect=save), \
                mock.patch.object(install, 'run', side_effect=run) as command:
            if fail_manifest:
                with self.assertRaises(OSError):
                    install.install(self.args)
                result = None
            else:
                result = install.install(self.args)
            return result, command, durable, deps

    def test_native_plugin_configures_without_copy_or_conflicting_link(self):
        result, command, durable, deps = self.invoke()
        self.assertEqual(result['registration'], 'native')
        self.assertEqual(result['package'], str(self.native))
        self.assertFalse(result['connection_started'])
        self.assertTrue(result['original_daemon_preserved'])
        command.assert_not_called()
        durable.assert_not_called()
        deps.assert_called_once()
        self.assertEqual(self.credential.read_text(), 'opaque credential; never read')
        self.assertEqual(json.loads((self.data / 'installation.json').read_text())['registration'], 'native')

    def test_native_activation_failure_restores_config_and_ssh_not_plugin(self):
        _, command, durable, _ = self.invoke(fail_manifest=True)
        command.assert_not_called()
        durable.assert_not_called()
        self.assertTrue((self.native / 'relay.py').is_file())
        self.assertFalse((self.data / 'config.json').exists())
        self.assertEqual(self.ssh.read_text(), 'Host unrelated\n')

    def test_review_snapshot_is_checked_under_install_locks(self):
        atomic_json(self.data / 'config.json', self.config)
        with self.assertRaisesRegex(ValueError, 'changed after review'):
            self.invoke()
        self.args.expected_config_sha256 = hashlib.sha256((self.data / 'config.json').read_bytes()).hexdigest()
        result, *_ = self.invoke()
        self.assertTrue(result['ok'])

    def test_mismatched_profile_cannot_mutate_another_profile(self):
        self.args.data_dir = self.root / 'wrong-profile'
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.invoke()
        self.assertFalse((self.data / 'config.json').exists())

    def test_checkout_cannot_replace_native_plugin(self):
        source = self.root / 'checkout'
        release_source(source)
        self.args.package_dir = source
        with self.assertRaisesRegex(ValueError, 'existing native plugin'):
            self.invoke()
        self.assertFalse((self.data / 'config.json').exists())

    def legacy(self):
        source = self.root / 'new-source'
        release_source(source)
        self.args.package_dir = source
        shutil.rmtree(self.native)
        old = self.data / 'packages' / 'old'
        old.mkdir(parents=True, mode=0o700)
        (old / 'relay.py').write_text('old helper retained')
        (old / 'relay.py').chmod(0o600)
        marker = self.plugins / (install.PLUGIN_ID + '.path')
        marker.write_text(str(old) + '\n')
        marker.chmod(0o600)
        atomic_json(self.data / 'installation.json', {'schema': 1, 'plugin': install.PLUGIN_ID,
            'plugins': str(self.plugins), 'package': str(old), 'ssh_config': str(self.ssh),
            'ssh_block_sha256': install.ssh_block_digest(self.ssh.read_text())})
        self.args.migrate_native = True
        def command(argv, _env):
            if argv[1:3] == ['plugin', 'unlink']:
                marker.unlink()
            elif argv[1:3] == ['plugin', 'link']:
                marker.write_text(argv[-1] + '\n')
                marker.chmod(0o600)
            elif argv[1:3] == ['plugin', 'install']:
                shutil.copytree(Path(argv[-1]), self.native)
            elif argv[1:3] == ['plugin', 'remove']:
                shutil.rmtree(self.native)
            else:
                self.fail('Unexpected external command')
            return '{}'
        return old, marker, command

    def test_explicit_migration_copies_only_allowlist_and_preserves_old_package(self):
        old, marker, run = self.legacy()
        result, command, durable, _ = self.invoke(run=run)
        self.assertEqual(result['registration'], 'native')
        self.assertFalse(marker.exists())
        self.assertTrue(self.native.is_dir())
        self.assertEqual({p.name for p in self.native.iterdir()}, set(MINIMAL))
        self.assertEqual((old / 'relay.py').read_text(), 'old helper retained')
        self.assertEqual(command.call_count, 2)
        durable.assert_not_called()
        self.assertEqual(command.call_args_list[1].args[0][1:3], ['plugin', 'install'])

    def test_failed_cli_after_native_copy_rolls_back_without_explicit_reload(self):
        old, marker, run = self.legacy()
        def partial_failure(argv, env):
            result = run(argv, env)
            if argv[1:3] == ['plugin', 'install']:
                raise ValueError('synthetic CLI timeout after committed copy')
            return result
        with self.assertRaisesRegex(ValueError, 'synthetic CLI timeout'):
            self.invoke(run=partial_failure)
        self.assertFalse(self.native.exists())
        self.assertEqual(marker.read_text(), str(old) + '\n')
        self.assertEqual(self.ssh.read_text(), 'Host unrelated\n')
        self.assertFalse((self.data / 'config.json').exists())

    def test_changed_native_copy_is_preserved_when_cli_fails(self):
        old, marker, run = self.legacy()
        def changed_copy(argv, env):
            result = run(argv, env)
            if argv[1:3] == ['plugin', 'install']:
                (self.native / 'user-note').write_text('preserve independent change')
                raise ValueError('synthetic CLI failure')
            return result
        with self.assertRaises(install.InstallRecoveryError):
            self.invoke(run=changed_copy)
        self.assertEqual((self.native / 'user-note').read_text(), 'preserve independent change')
        self.assertTrue(old.is_dir())
        self.assertFalse(marker.exists())
        self.assertEqual(self.ssh.read_text(), 'Host unrelated\n')

    def test_migration_failure_restores_owned_marker_and_ssh(self):
        old, marker, run = self.legacy()
        self.invoke(fail_manifest=True, run=run)
        self.assertFalse(self.native.exists())
        self.assertEqual(marker.read_text(), str(old) + '\n')
        self.assertTrue(old.is_dir())
        self.assertEqual(self.ssh.read_text(), 'Host unrelated\n')
        self.assertFalse((self.data / 'config.json').exists())

    def test_migration_without_ownership_record_preserves_link(self):
        old, marker, run = self.legacy()
        (self.data / 'installation.json').unlink()
        with self.assertRaisesRegex(ValueError, 'owned legacy package'):
            self.invoke(run=run)
        self.assertEqual(marker.read_text(), str(old) + '\n')

    def test_owned_symlink_migration_removes_only_link_not_old_package(self):
        old, marker, _ = self.legacy()
        marker.unlink()
        self.native.symlink_to(old)
        def command(argv, _env):
            if argv[1:3] == ['plugin', 'remove']:
                self.assertTrue(self.native.is_symlink())
                self.native.unlink()
            elif argv[1:3] == ['plugin', 'install']:
                shutil.copytree(Path(argv[-1]), self.native)
            else:
                self.fail('Unexpected migration command')
            return '{}'
        result, *_ = self.invoke(run=command)
        self.assertEqual(result['registration'], 'native')
        self.assertFalse(self.native.is_symlink())
        self.assertTrue(self.native.is_dir())
        self.assertEqual((old / 'relay.py').read_text(), 'old helper retained')


class ManagedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.data = Path(self.temporary.name).resolve()
        self.data.chmod(0o700)
        self.container = self.data / '.managed-python-test'
        self.container.mkdir(mode=0o700)
        self.stage = self.container / 'runtime'
        executable = self.stage / 'python' / 'bin' / 'python3'
        executable.parent.mkdir(parents=True, mode=0o700)
        self.stage.chmod(0o700)
        executable.write_text('synthetic executable')
        executable.chmod(0o700)

    def test_finalize_promotes_only_runtime_and_writes_private_receipt(self):
        python = managed_runtime.finalize(self.stage, self.data, '20251014', 'aarch64', 'a' * 64)
        self.assertEqual(python, managed_runtime.runtime_python(self.data))
        self.assertTrue(python.is_file())
        self.assertFalse(self.stage.exists())
        receipt = self.data / 'managed-python' / 'bootstrap.receipt'
        self.assertEqual(receipt.read_text(), '20251014\naarch64\n' + 'a' * 64 + '\n')
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.data / 'runtime').exists())

    def test_existing_managed_runtime_is_never_overwritten(self):
        existing = self.data / 'managed-python'
        existing.mkdir()
        (existing / 'keep').write_text('keep')
        with self.assertRaisesRegex(ValueError, 'preserved'):
            managed_runtime.finalize(self.stage, self.data, '20251014', 'x86_64', 'a' * 64)
        self.assertEqual((existing / 'keep').read_text(), 'keep')

    def test_archive_escaping_symlink_and_special_file_are_rejected(self):
        link = self.stage / 'escape'
        link.symlink_to(self.data)
        with self.assertRaisesRegex(ValueError, 'escaping'):
            managed_runtime.audit_runtime(self.stage)
        link.unlink()
        os.mkfifo(link)
        with self.assertRaisesRegex(ValueError, 'special file'):
            managed_runtime.audit_runtime(self.stage)

    def test_archive_file_count_and_unpacked_size_are_bounded(self):
        with mock.patch.object(managed_runtime, 'MAX_ENTRIES', 1):
            with self.assertRaisesRegex(ValueError, 'file-count'):
                managed_runtime.audit_runtime(self.stage)
        with mock.patch.object(managed_runtime, 'MAX_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'unpacked size'):
                managed_runtime.audit_runtime(self.stage)

    def test_internal_python_symlinks_are_supported(self):
        executable = self.stage / 'python' / 'bin' / 'python3'
        executable.rename(executable.with_name('python3.13'))
        executable.symlink_to('python3.13')
        managed_runtime.audit_runtime(self.stage)
        self.assertTrue(executable.is_file())


@unittest.skipUnless(sys.platform == 'darwin', 'bootstrap uses macOS platform tools')
class BootstrapBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.data = self.root / 'data'
        self.launcher = Path(__file__).resolve().parents[1] / 'bootstrap-runtime.sh'

    def invoke(self, *arguments):
        result = subprocess.run(['/bin/sh', str(self.launcher), str(self.data), *arguments],
                                capture_output=True, text=True, timeout=10)
        return result.returncode, json.loads(result.stdout)

    def test_normal_launch_never_prepares_or_creates_data(self):
        code, result = self.invoke('--exec', '/not/a/script')
        self.assertEqual(code, 1)
        self.assertFalse(result['ok'])
        self.assertFalse(self.data.exists())

    def test_explicit_prepare_rejects_symlink_without_touching_target(self):
        target = self.root / 'target'
        target.mkdir(mode=0o700)
        self.data.symlink_to(target)
        code, result = self.invoke('--prepare')
        self.assertEqual(code, 1)
        self.assertIn('symbolic links', result['error'])
        self.assertEqual(list(target.iterdir()), [])

    def test_existing_unowned_runtime_is_preserved_without_network(self):
        runtime = self.data / 'managed-python'
        runtime.mkdir(parents=True)
        self.data.chmod(0o700)
        keep = runtime / 'keep'
        keep.write_text('not a managed Python installation')
        code, result = self.invoke('--prepare')
        self.assertEqual(code, 1)
        self.assertIn('preserved', result['error'])
        self.assertEqual(keep.read_text(), 'not a managed Python installation')
        self.assertFalse((self.data / '.managed-python.lock').exists())

    def test_competing_prepare_lock_is_never_removed(self):
        self.data.mkdir(mode=0o700)
        lock = self.data / '.managed-python.lock'
        lock.mkdir(mode=0o700)
        code, result = self.invoke('--prepare')
        self.assertEqual(code, 1)
        self.assertIn('already active', result['error'])
        self.assertTrue(lock.is_dir())

    def test_explicit_prepare_tightens_only_owned_data_directory(self):
        self.root.chmod(0o755)
        self.data.mkdir(mode=0o755)
        (self.data / '.managed-python.lock').mkdir(mode=0o700)
        self.invoke()
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o755)
        code, result = self.invoke('--prepare')
        self.assertEqual(code, 1)  # Existing setup lock prevents any network work.
        self.assertIn('already active', result['error'])
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)


    def test_matching_private_runtime_is_reused_without_bootstrap_work(self):
        runtime = self.data / 'managed-python'
        binary = runtime / 'python' / 'bin' / 'python3.13'
        binary.parent.mkdir(parents=True)
        for path in (self.data, runtime, runtime / 'python', binary.parent):
            path.chmod(0o700)
        # Mock only the executable. All shell ownership/receipt checks are real;
        # this fixture cannot enter the absent-runtime download branch.
        binary.write_text('#!/bin/sh\nprintf \'{"ok":true,"reused":true}\\n\'\n')
        binary.chmod(0o700)
        binary.with_name('python3').symlink_to('python3.13')
        architecture = 'aarch64' if os.uname().machine == 'arm64' else 'x86_64'
        digest = ('931db8f735e18700d4eab9ee39dbbd0b4c114d7d039dd2707b2d932ded039698'
                  if architecture == 'aarch64' else
                  '9f6bc3c15e2f9e2c9c90db2c8b3ee94598e777789f8aea6e36b69ae55d007d01')
        receipt = runtime / 'bootstrap.receipt'
        receipt.write_text('20251014\n' + architecture + '\n' + digest + '\n')
        receipt.chmod(0o600)
        for arguments in (('--prepare',), ('--exec', '/mock/script')):
            code, result = self.invoke(*arguments)
            self.assertEqual(code, 0)
            self.assertTrue(result['reused'])
            self.assertEqual({path.name for path in self.data.iterdir()}, {'managed-python'})


if __name__ == '__main__':
    unittest.main()
