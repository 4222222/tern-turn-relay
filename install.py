#!/usr/bin/env python3
"""Configure a native plugin or install a durable legacy link without touching Tern's daemon."""
import argparse
import asyncio
import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

from package_release import content_digest, release_files, release_version
from relay_config import atomic_json, load_config, lock_file, private_file, state_directory
from ssh_compat import install_compat, without_block

ROOT = Path(__file__).resolve().parent
PLUGIN_ID = 'tern-turn-relay'
VERSIONS = {'aioice': '0.10.2', 'dnspython': '2.7.0', 'ifaddr': '0.2.0'}


class InstallRecoveryError(ValueError):
    """Safe public summary retaining private exceptions for local callers."""

    def __init__(self, failures):
        self.recovery_failures = tuple(failures)
        super().__init__('Installation failed; all independent rollback actions were attempted. '
                         'Manual recovery is required for: ' + ', '.join(name for name, _ in failures))


def private_directory(path):
    path = Path(path).absolute()
    for parent in reversed([path] + list(path.parents)):
        if parent.is_symlink():
            raise ValueError('Refusing a directory containing a symlink')
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('Private directory must be owned by the current user')
    os.chmod(path, 0o700)


def run(argv, env=None, timeout=90):
    try:
        result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('External command unavailable or timed out; no diagnostic output was disclosed') from None
    if result.returncode:
        raise ValueError('External command failed; diagnostic output was withheld to protect local data')
    if len(result.stdout) > 1024 * 1024:
        raise ValueError('External command output exceeded its limit')
    return result.stdout.strip()


def tern_environment(tern=None, config_dir=None):
    candidate = Path('/Applications/Tern.app/Contents/MacOS/tern')
    found = shutil.which('tern')
    binary = tern or (candidate if candidate.is_file() else Path(found) if found else None)
    if binary is None or not binary.expanduser().is_file():
        raise ValueError('Tern executable not found; pass --tern')
    env = os.environ.copy()
    if config_dir:
        profile = config_dir.expanduser().absolute()
        private_directory(profile)
        env['TERN_CONFIG_DIR'] = str(profile)
        env['TERN_DAEMON_SOCKET'] = str(profile / 'daemon.sock')
    binary = binary.expanduser().absolute()
    plugins = Path(run([str(binary), 'plugin', 'dir'], env))
    if not plugins.is_absolute():
        raise ValueError('Tern returned a non-absolute plugin directory')
    return binary, env, plugins, plugins.parent / 'plugin-data' / PLUGIN_ID


def dependency_versions(path):
    if not path.is_dir() or path.is_symlink():
        return {}
    return {entry.metadata['Name'].lower(): entry.version
            for entry in importlib.metadata.distributions(path=[str(path)])}


def dependencies_valid(path):
    installed = dependency_versions(path)
    modules = ('aioice/__init__.py', 'dns/__init__.py', 'ifaddr/__init__.py')
    return (all(installed.get(name) == version for name, version in VERSIONS.items())
            and all((path / name).is_file() and not (path / name).is_symlink() for name in modules))


def ensure_dependencies(path, env):
    if dependencies_valid(path):
        return
    if path.exists() or path.is_symlink():
        raise ValueError('Existing dependency directory is incompatible; it was preserved. Select a new dependency directory in setup.')
    private_directory(path.parent)
    # pip touches only this freshly created staging directory. Never overlay a
    # user installation or accept unbounded dependency resolution.
    with tempfile.TemporaryDirectory(prefix='.deps-', dir=str(path.parent)) as temporary:
        run([sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check',
             '--no-cache-dir', '--no-input', '--only-binary=:all:', '--no-deps',
             '--retries', '1', '--timeout', '20', '--target', temporary,
             *[name + '==' + version for name, version in VERSIONS.items()]], env, timeout=180)
        if not dependencies_valid(Path(temporary)):
            raise ValueError('Installed dependencies do not match the exact pinned versions')
        if path.exists() or path.is_symlink():
            raise ValueError('Dependency destination appeared during installation')
        os.rename(temporary, path)


def durable_package(data, source=ROOT):
    files = release_files(source, include_tests=False)
    digest = content_digest(files)
    packages = data / 'packages'
    private_directory(packages)
    destination = packages / (release_version(source) + '-' + digest)
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_dir():
            raise ValueError('Installed package path is unsafe')
        names = {str(path.relative_to(destination)) for path in destination.rglob('*') if not path.is_dir()}
        if names != set(files):
            raise ValueError('Existing immutable package has unexpected files; it was preserved')
        for name, expected in files.items():
            path = destination / name
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or path.read_bytes() != expected):
                raise ValueError('Existing immutable package was modified; it was preserved')
        return destination
    with tempfile.TemporaryDirectory(prefix='.package-', dir=str(packages)) as temporary:
        staging = Path(temporary)
        for name, content in files.items():
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with path.open('xb') as stream:
                stream.write(content)
            path.chmod(0o600)
        # Prevent runtime imports from adding bytecode to immutable source.
        staging.chmod(0o500)
        os.rename(staging, destination)
    return destination


def require_stopped(runtime, hold=False):
    descriptor = lock_file(runtime / 'service.lock')
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Disconnect TURN before installing or replacing its configuration') from None
        if hold:
            retained, descriptor = descriptor, None
            return retained
    finally:
        if descriptor is not None:
            os.close(descriptor)


def selected_config(destination, supplied, replace):
    if destination.exists() or destination.is_symlink():
        current = load_config(destination, check_key=False)
        if not replace:
            if supplied and load_config(supplied, check_key=False, allow_unprovisioned=True) != current:
                raise ValueError('Existing configuration was preserved; omit --config for upgrade or explicitly pass --replace-config')
            return current
    if supplied is None:
        raise ValueError('First installation requires --config generated by setup.py')
    return load_config(supplied, check_key=False, allow_unprovisioned=True)


def ssh_block_digest(text):
    remainder = without_block(text)
    block = text[:len(text) - len(remainder)]
    return hashlib.sha256(block.encode('utf-8')).hexdigest() if block else None


def plugin_link(plugins):
    """Read native, symlink, or path-marker registration; reject ambiguity."""
    legacy = plugins / PLUGIN_ID
    marker = plugins / (PLUGIN_ID + '.path')
    found = []
    if legacy.exists() or legacy.is_symlink():
        info = legacy.lstat()
        if info.st_uid != os.getuid() or not (stat.S_ISLNK(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('Existing plugin is not an owned directory or managed link; it was preserved')
        if stat.S_ISDIR(info.st_mode) and info.st_mode & 0o022:
            raise ValueError('Native plugin directory is writable by other users; it was preserved')
        found.append((legacy, legacy.resolve()))
    if marker.exists() or marker.is_symlink():
        descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or info.st_nlink != 1 or not 0 < info.st_size <= 8192):
                raise ValueError('Plugin path marker is unsafe; it was preserved')
            text = stream.read(8193).decode('utf-8')
        value = text[:-1] if text.endswith('\n') else text
        if (len(text.encode('utf-8')) > 8192 or not Path(value).is_absolute()
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError('Plugin path marker must contain one absolute path')
        found.append((marker, Path(value).resolve()))
    if len(found) > 1:
        raise ValueError('Plugin has both symlink and path-marker or native registrations; resolve ambiguity before changing it')
    return found[0] if found else (None, None)


def owned_legacy_package(data, source, record):
    if (record is None or source is None or record.get('package') != str(source)
            or source.parent != data / 'packages' or source.is_symlink() or not source.is_dir()):
        raise ValueError('Native migration requires an owned legacy package and installation record')
    info = source.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError('Legacy package ownership is unsafe; it was preserved')
    private_file(source / 'relay.py')


class NativeMigration:
    """Allowlisted copy and reversible registration swap; never delete a source package."""

    def __init__(self, plugins, source, tern, env):
        self.plugins, self.source, self.tern, self.env = plugins, source, tern, env
        self.destination = plugins / PLUGIN_ID
        self.files = release_files(ROOT, include_tests=False)
        self.stage = Path(tempfile.mkdtemp(prefix='.tern-turn-relay-migrate-', dir=plugins))
        self.identity = None
        self.unlink_attempted = False
        try:
            for name, content in self.files.items():
                path = self.stage / name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with path.open('xb') as stream:
                    stream.write(content)
                path.chmod(0o600)
        except BaseException:
            shutil.rmtree(self.stage)
            raise

    def unchanged(self, directory):
        if directory.is_symlink() or not directory.is_dir():
            return False
        info = directory.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            return False
        paths = list(directory.rglob('*'))
        if any(path.is_symlink() for path in paths):
            return False
        directories = {str(path.relative_to(directory)) for path in paths if path.is_dir()}
        expected_directories = {str(parent) for name in self.files for parent in Path(name).parents
                                if parent != Path('.')}
        names = {str(path.relative_to(directory)) for path in paths if not path.is_dir()}
        if names != set(self.files) or directories != expected_directories:
            return False
        for name, content in self.files.items():
            path = directory / name
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or info.st_nlink != 1
                    or info.st_size != len(content) or path.read_bytes() != content):
                return False
        return True

    def activate(self):
        registration, source = plugin_link(self.plugins)
        if source != self.source:
            raise ValueError('Legacy registration changed during migration; it was preserved')
        self.unlink_attempted = True
        verb = 'remove' if registration.is_symlink() else 'unlink'
        run([str(self.tern), 'plugin', verb, PLUGIN_ID], self.env)
        if plugin_link(self.plugins)[0] is not None:
            raise ValueError('Tern did not remove the owned legacy registration')
        if self.destination.exists() or self.destination.is_symlink():
            raise ValueError('Native destination appeared during migration')
        try:
            # Tern owns its atomic copy and best-effort daemon reload. Only our
            # allowlisted staging tree is supplied, never the working checkout.
            run([str(self.tern), 'plugin', 'install', str(self.stage)], self.env)
        finally:
            # A timed-out CLI may already have committed its copy. Recognize
            # only the exact owned content so rollback can recover that case.
            if self.unchanged(self.destination):
                info = self.destination.stat()
                self.identity = (info.st_dev, info.st_ino)
        if self.identity is None:
            raise ValueError('Tern did not install the exact owned native package')

    def rollback(self):
        if self.identity is not None and self.destination.exists():
            info = self.destination.lstat()
            if ((info.st_dev, info.st_ino) != self.identity or not self.unchanged(self.destination)):
                raise ValueError('Migrated plugin changed independently; it was preserved')
            run([str(self.tern), 'plugin', 'remove', PLUGIN_ID], self.env)
            if plugin_link(self.plugins)[0] is not None:
                raise ValueError('Tern did not remove the owned failed migration copy')
        if self.unlink_attempted:
            current = plugin_link(self.plugins)[1]
            if current not in (None, self.source):
                raise ValueError('Plugin registration changed independently; it was preserved')
            if current is None:
                run([str(self.tern), 'plugin', 'link', str(self.source)], self.env)
            if plugin_link(self.plugins)[1] != self.source:
                raise ValueError('Tern did not restore the legacy plugin registration')

    def close(self):
        # Only the exact staging copy we created is eligible for cleanup.
        if self.stage.exists() and self.unchanged(self.stage):
            shutil.rmtree(self.stage)


def install(args):
    if args.config_dir and not args.ssh_config:
        raise ValueError('Isolated installation requires an explicit --ssh-config')
    tern, env, plugins, data = tern_environment(args.tern, args.config_dir)
    if getattr(args, 'data_dir', None) is not None and Path(args.data_dir).absolute() != data:
        raise ValueError('Plugin data directory does not match the selected Tern profile')
    if getattr(args, 'package_dir', None) is not None and Path(args.package_dir).resolve() != ROOT:
        raise ValueError('Installer package does not match the selected plugin directory')
    private_directory(data)
    runtime = state_directory(data / 'runtime')
    command_lock = lock_file(runtime / 'command.lock')
    service_lock = None
    migration = None
    try:
        try:
            fcntl.flock(command_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another relay lifecycle operation is in progress') from None
        service_lock = require_stopped(runtime, hold=True)
        registration, previous_source = plugin_link(plugins)
        native = registration == plugins / PLUGIN_ID and registration is not None and not registration.is_symlink()
        if native and previous_source != ROOT:
            raise ValueError('Configure the existing native plugin using its installed installer; it was preserved')
        ssh_config = (args.ssh_config or Path.home() / '.ssh' / 'config').expanduser().absolute()
        manifest = data / 'installation.json'
        previous_manifest = None
        if manifest.exists() or manifest.is_symlink():
            private_file(manifest)
            previous_manifest = json.loads(manifest.read_text(encoding='utf-8'))
            if (not isinstance(previous_manifest, dict) or previous_manifest.get('schema') != 1
                    or previous_manifest.get('plugin') != PLUGIN_ID
                    or previous_manifest.get('plugins') != str(plugins)):
                raise ValueError('Installation ownership record is invalid for this Tern profile')
            if not args.ssh_config:
                ssh_config = Path(previous_manifest['ssh_config'])
            elif str(ssh_config) != previous_manifest['ssh_config']:
                raise ValueError('SSH config ownership cannot move during upgrade; uninstall the old link first')
        if previous_manifest and previous_source is not None and str(previous_source) != previous_manifest.get('package'):
            raise ValueError('Current plugin registration does not match its installation ownership record')
        migrate_native = bool(getattr(args, 'migrate_native', False)) and not native
        if migrate_native:
            owned_legacy_package(data, previous_source, previous_manifest)
        destination = data / 'config.json'
        if hasattr(args, 'expected_config_sha256'):
            actual_digest = None
            if destination.exists() or destination.is_symlink():
                private_file(destination)
                actual_digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            if actual_digest != args.expected_config_sha256:
                raise ValueError('Configuration changed after review; review it again before applying')
        config = selected_config(destination, args.config.expanduser().absolute() if args.config else None,
                                 args.replace_config)
        private_file(config['credential_file'])  # Metadata only; never read management credentials.
        dependencies = Path(config['dependency_dir'])
        ensure_dependencies(dependencies, env)
        package = ROOT if native or migrate_native else durable_package(data)
        from gateway_client import provision
        descriptor = asyncio.run(provision(config))
        if descriptor['fingerprint'] == config['target']['fingerprint']:
            raise ValueError('Dedicated gateway identity must differ from the original service')
        if descriptor['daemon_socket'] != config['gateway']['daemon_socket']:
            raise ValueError('Gateway did not confirm the configured existing daemon')
        if config['gateway'].get('fingerprint', descriptor['fingerprint']) != descriptor['fingerprint']:
            raise ValueError('Existing gateway identity changed; stored configuration was preserved')
        config['gateway']['fingerprint'] = descriptor['fingerprint']
        old_config = destination.read_bytes() if destination.exists() else None
        old_ssh = ssh_config.read_bytes() if ssh_config.exists() and not ssh_config.is_symlink() else None
        installed_ssh = None
        if migrate_native:
            migration = NativeMigration(plugins, previous_source, tern, env)
            package = migration.destination
        try:
            atomic_json(destination, config)
            load_config(destination)
            install_compat(config, ssh_config)
            installed_ssh = ssh_config.read_bytes()
            if migration is not None:
                migration.activate()
            elif not native:
                run([str(tern), 'plugin', 'link', str(package)], env)
            if plugin_link(plugins)[1] != package:
                raise ValueError('Tern did not retain the selected plugin registration')
            atomic_json(manifest, {'schema': 1, 'plugin': PLUGIN_ID, 'package': str(package),
                                  'ssh_config': str(ssh_config), 'plugins': str(plugins),
                                  'registration': 'native' if native or migrate_native else 'linked',
                                  'ssh_block_sha256': ssh_block_digest(installed_ssh.decode('utf-8'))})
        except Exception as activation_error:
            # A failed Tern invocation must not prevent independent config/SSH
            # recovery. Keep source packages and every recovery exception.
            failures = []
            try:
                if migration is not None:
                    migration.rollback()
                elif not native and plugin_link(plugins)[1] == package:
                    if previous_source is not None:
                        run([str(tern), 'plugin', 'link', str(previous_source)], env)
                    else:
                        run([str(tern), 'plugin', 'unlink', PLUGIN_ID], env)
                    if plugin_link(plugins)[1] != previous_source:
                        raise ValueError('Tern did not restore the previous plugin registration')
            except Exception as recovery_error:
                failures.append(('plugin link', recovery_error))
            try:
                if old_config is None:
                    destination.unlink(missing_ok=True)
                else:
                    atomic_json(destination, json.loads(old_config))
            except Exception as recovery_error:
                failures.append(('plugin configuration', recovery_error))
            try:
                if installed_ssh is not None:
                    if ssh_config.is_symlink() or ssh_config.read_bytes() != installed_ssh:
                        raise ValueError('SSH configuration changed independently; it was preserved')
                    from ssh_compat import update
                    update(ssh_config, lambda _text: old_ssh.decode('utf-8') if old_ssh is not None else '')
            except Exception as recovery_error:
                failures.append(('SSH configuration', recovery_error))
            if failures:
                raise InstallRecoveryError(failures) from activation_error
            raise
        return {'ok': True, 'plugin': PLUGIN_ID, 'package': str(package), 'config': str(destination),
                'runtime': str(runtime), 'dependencies': str(dependencies),
                'registration': 'native' if native or migrate_native else 'linked',
                'connection_started': False, 'original_daemon_preserved': True}
    finally:
        try:
            if migration is not None:
                migration.close()
        finally:
            if service_lock is not None:
                os.close(service_lock)
            os.close(command_lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, help='setup.py output; omit on upgrade to preserve installed configuration')
    parser.add_argument('--tern', type=Path)
    parser.add_argument('--config-dir', type=Path, help='isolated Tern profile')
    parser.add_argument('--replace-config', action='store_true', help='explicitly replace plugin configuration, never credentials')
    parser.add_argument('--ssh-config', type=Path, help='OpenSSH configuration receiving only the marked scoped rule')
    parser.add_argument('--migrate-native', action='store_true',
                        help='explicitly migrate an ownership-recorded legacy link to an allowlisted native copy')
    args = parser.parse_args(argv)
    try:
        os.umask(0o077)
        print(json.dumps(install(args), indent=2))
        return 0
    except Exception as error:
        message = str(error) if isinstance(error, ValueError) else 'Installation failed; private diagnostic output was withheld'
        print(json.dumps({'ok': False, 'error': message}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
