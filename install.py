#!/usr/bin/env python3
"""Install a durable private plugin package without replacing the original Tern service."""
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


def require_stopped(runtime):
    descriptor = lock_file(runtime / 'service.lock')
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Disconnect TURN before installing or replacing its configuration') from None
    finally:
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
    """Read either supported Tern registration, refusing ambiguous ownership."""
    legacy = plugins / PLUGIN_ID
    marker = plugins / (PLUGIN_ID + '.path')
    found = []
    if legacy.exists() or legacy.is_symlink():
        info = legacy.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('Existing plugin is not an owned managed link; it was preserved')
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
        raise ValueError('Plugin has both symlink and path-marker registrations; resolve ambiguity before changing it')
    return found[0] if found else (None, None)


def install(args):
    if args.config_dir and not args.ssh_config:
        raise ValueError('Isolated installation requires an explicit --ssh-config')
    tern, env, plugins, data = tern_environment(args.tern, args.config_dir)
    private_directory(data)
    runtime = state_directory(data / 'runtime')
    command_lock = lock_file(runtime / 'command.lock')
    try:
        try:
            fcntl.flock(command_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another relay lifecycle operation is in progress') from None
        require_stopped(runtime)
        destination = data / 'config.json'
        config = selected_config(destination, args.config.expanduser().absolute() if args.config else None,
                                 args.replace_config)
        private_file(config['credential_file'])  # Metadata only; never read management credentials.
        dependencies = Path(config['dependency_dir'])
        ensure_dependencies(dependencies, env)
        package = durable_package(data)
        from gateway_client import provision
        descriptor = asyncio.run(provision(config))
        if descriptor['fingerprint'] == config['target']['fingerprint']:
            raise ValueError('Dedicated gateway identity must differ from the original service')
        if descriptor['daemon_socket'] != config['gateway']['daemon_socket']:
            raise ValueError('Gateway did not confirm the configured existing daemon')
        if config['gateway'].get('fingerprint', descriptor['fingerprint']) != descriptor['fingerprint']:
            raise ValueError('Existing gateway identity changed; stored configuration was preserved')
        config['gateway']['fingerprint'] = descriptor['fingerprint']
        ssh_config = (args.ssh_config or Path.home() / '.ssh' / 'config').expanduser().absolute()
        manifest = data / 'installation.json'
        previous_manifest = None
        if manifest.exists() or manifest.is_symlink():
            private_file(manifest)
            previous_manifest = json.loads(manifest.read_text(encoding='utf-8'))
            if previous_manifest.get('plugin') != PLUGIN_ID:
                raise ValueError('Installation ownership record is invalid')
            if not args.ssh_config:
                ssh_config = Path(previous_manifest['ssh_config'])
            elif str(ssh_config) != previous_manifest['ssh_config']:
                raise ValueError('SSH config ownership cannot move during upgrade; uninstall the old link first')
        _registration, previous_source = plugin_link(plugins)
        if previous_manifest and previous_source is not None and str(previous_source) != previous_manifest.get('package'):
            raise ValueError('Current plugin link does not match its installation ownership record')
        old_config = destination.read_bytes() if destination.exists() else None
        old_ssh = ssh_config.read_bytes() if ssh_config.exists() and not ssh_config.is_symlink() else None
        installed_ssh = None
        try:
            atomic_json(destination, config)
            load_config(destination)
            install_compat(config, ssh_config)
            installed_ssh = ssh_config.read_bytes()
            run([str(tern), 'plugin', 'link', str(package)], env)
            if plugin_link(plugins)[1] != package:
                raise ValueError('Tern did not register the installed durable package')
            atomic_json(manifest, {'schema': 1, 'plugin': PLUGIN_ID, 'package': str(package),
                                  'ssh_config': str(ssh_config), 'plugins': str(plugins),
                                  'ssh_block_sha256': ssh_block_digest(installed_ssh.decode('utf-8'))})
        except Exception as activation_error:
            # A failed Tern invocation must not prevent independent config/SSH
            # recovery. Keep source packages and every recovery exception.
            failures = []
            try:
                if plugin_link(plugins)[1] == package:
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
                'connection_started': False, 'original_daemon_preserved': True}
    finally:
        os.close(command_lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, help='setup.py output; omit on upgrade to preserve installed configuration')
    parser.add_argument('--tern', type=Path)
    parser.add_argument('--config-dir', type=Path, help='isolated Tern profile')
    parser.add_argument('--replace-config', action='store_true', help='explicitly replace plugin configuration, never credentials')
    parser.add_argument('--ssh-config', type=Path, help='OpenSSH configuration receiving only the marked scoped rule')
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
