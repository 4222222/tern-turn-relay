#!/usr/bin/env python3
"""Bounded, redacted native onboarding API. Inspection never contacts SSH or Cloudflare."""
import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import sys
import tempfile
from types import SimpleNamespace

# Keep read-only inspect from creating bytecode files in the native package.
sys.dont_write_bytecode = True

import credentials
import setup
from relay_config import load_config, private_file, validate_ssh_destination

MAX_JSON = 65536
PLUGIN_ID = 'tern-turn-relay'


class OnboardingError(ValueError):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise OnboardingError('invalid-request', 'Invalid onboarding arguments; no argument values were disclosed.')


def parser():
    result = Parser(description=__doc__)
    result.add_argument('action', choices=('inspect', 'discover', 'configure-credentials', 'apply', 'update', 'uninstall'))
    for name in ('data-dir', 'package-dir', 'config-dir', 'ssh-config', 'tern'):
        result.add_argument('--' + name, type=Path)
    return result


def owned_path(value, directory=False):
    path = Path(value).expanduser().absolute()
    if '..' in path.parts or any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise OnboardingError('unsafe-path', 'Onboarding paths must be canonical absolute local paths.')
    for item in reversed([path] + list(path.parents)):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.getuid())
                or (info.st_mode & 0o022 and not sticky)):
            raise OnboardingError('unsafe-path', 'Onboarding paths must have trusted non-symlink ownership.')
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise OnboardingError('unsafe-path', 'Onboarding path ancestry must consist of directories.')
        if item == path and directory and not stat.S_ISDIR(info.st_mode):
            raise OnboardingError('unsafe-path', 'Expected an owned local directory.')
        if item == path and info.st_uid != os.getuid():
            raise OnboardingError('unsafe-path', 'Onboarding paths must be owned by this user.')
    return path


def context(args):
    package = owned_path(args.package_dir or Path(__file__).resolve().parent, directory=True)
    default_profile = Path.home() / 'Library' / 'Application Support' / 'Tern'
    native = package.name == PLUGIN_ID and package.parent.name == 'plugins'
    supplied_data = owned_path(args.data_dir, directory=True) if args.data_dir is not None else None
    inferred_linked = args.config_dir is None and not native and supplied_data is not None
    if inferred_linked and (supplied_data.name != PLUGIN_ID or supplied_data.parent.name != 'plugin-data'):
        raise OnboardingError('context-mismatch', 'Plugin data must have the selected Tern profile ownership layout.')
    inferred_profile = package.parent.parent if native else supplied_data.parent.parent if inferred_linked else default_profile
    profile = owned_path(args.config_dir or inferred_profile, directory=True)
    data = supplied_data or owned_path(profile / 'plugin-data' / PLUGIN_ID, directory=True)
    if data != profile / 'plugin-data' / PLUGIN_ID:
        raise OnboardingError('context-mismatch', 'Plugin data must belong to the selected Tern profile.')
    ambient_ssh = owned_path(Path.home() / '.ssh' / 'config')
    default_ssh = ambient_ssh if profile == default_profile else data / 'ssh-config'
    ssh = owned_path(args.ssh_config or default_ssh)
    manifest = owned_path(data / 'installation.json')
    if inferred_linked and not manifest.exists():
        raise OnboardingError('ownership-required', 'A linked custom profile requires its installation ownership record.')
    if manifest.exists():
        private_file(manifest)
        descriptor = os.open(manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > MAX_JSON):
                raise OnboardingError('invalid-installation', 'Installation ownership record is not a private bounded file.')
            record = read_request(stream)
        plugins = profile / 'plugins'
        from install import plugin_link
        _marker, registered_package = plugin_link(plugins)
        if (type(record.get('schema')) is not int or record['schema'] != 1
                or record.get('plugin') != PLUGIN_ID or record.get('plugins') != str(plugins)
                or not isinstance(record.get('ssh_config'), str)
                or not Path(record['ssh_config']).is_absolute()
                or not isinstance(record.get('package'), str)
                or not Path(record['package']).is_absolute()
                or (registered_package is not None and record['package'] != str(registered_package))):
            raise OnboardingError('invalid-installation', 'Installation ownership record does not match this profile and registration.')
        if inferred_linked and (registered_package != package or record['package'] != str(package)):
            raise OnboardingError('invalid-installation', 'Supplied data does not own this linked plugin package.')
        recorded_ssh = owned_path(record['ssh_config'])
        if args.ssh_config is not None and ssh != recorded_ssh:
            raise OnboardingError('context-mismatch', 'The existing installation owns a different SSH config path; it cannot move during setup.')
        ssh = recorded_ssh
    return {'data_dir': str(data), 'package_dir': str(package), 'config_dir': str(profile),
            'config_file': str(data / 'config.json'),
            'credential_file': str(data / 'credentials' / 'cloudflare.json'),
            'dependency_dir': str(data / 'deps'), 'ssh_config': str(ssh),
            'ssh_alias_config': str(ambient_ssh)}


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key')
        value[key] = item
    return value


def read_request(stream):
    raw = stream.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise OnboardingError('invalid-request', 'Onboarding input exceeds 64 KiB.')
    try:
        value = json.loads(raw, object_pairs_hook=strict_object,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise OnboardingError('invalid-request', 'Onboarding input must be one bounded JSON object.') from None
    if not isinstance(value, dict):
        raise OnboardingError('invalid-request', 'Onboarding input must be a JSON object.')
    return value


def fields(request, allowed, required=()):
    if set(request) - set(allowed) or set(required) - set(request):
        raise OnboardingError('invalid-request', 'Onboarding input contains missing or unsupported fields.')


def boolean(request, name):
    value = request.get(name, False)
    if type(value) is not bool:
        raise OnboardingError('invalid-request', 'Consent fields must be JSON booleans.')
    return value


def current_configuration(paths):
    path = owned_path(paths['config_file'])
    if not path.exists():
        return None
    return load_config(path, check_key=False)


def config_digest(paths):
    path = owned_path(paths['config_file'])
    if not path.exists():
        return None
    private_file(path)
    with path.open('rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise OnboardingError('invalid-configuration', 'Installed configuration exceeds its limit.')
    return hashlib.sha256(raw).hexdigest()


def running(paths):
    """Observe an existing lock only: inspect creates no paths or lock files."""
    path = owned_path(Path(paths['data_dir']) / 'runtime' / 'service.lock')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise OnboardingError('unsafe-path', 'Relay service lock has unsafe ownership.')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(fd)


def ssh_aliases(path):
    """Read literal Host aliases only; never execute SSH, Include commands or Match exec."""
    path = owned_path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return []
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON:
            raise OnboardingError('ssh-config-limit', 'SSH alias inventory requires a regular config no larger than 64 KiB.')
        text = stream.read(MAX_JSON + 1).decode('utf-8')
    aliases = set()
    for line in text.splitlines():
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            continue
        if words and words[0].lower() == 'host':
            for alias in words[1:]:
                if re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}', alias):
                    aliases.add(alias)
                    if len(aliases) >= 64:
                        return [{'label': item, 'value': item} for item in sorted(aliases)]
    return [{'label': item, 'value': item} for item in sorted(aliases)]


def registration(paths):
    from install import plugin_link
    plugins = owned_path(Path(paths['config_dir']) / 'plugins', directory=True)
    marker, _source = plugin_link(plugins)
    if marker is None:
        return 'unregistered'
    return 'linked' if marker.suffix == '.path' or marker.is_symlink() else 'native'


def inspect(paths):
    config = current_configuration(paths)
    key_path = config['credential_file'] if config else paths['credential_file']
    owned_path(key_path)
    try:
        credentials.load_management_key(key_path)
        credential_ready = True
    except credentials.CredentialError as exc:
        if exc.exit_code != 3:
            raise
        credential_ready = False
    from install import dependencies_valid
    dependencies = Path(config['dependency_dir'] if config else paths['dependency_dir'])
    runtime_ready = dependencies_valid(owned_path(dependencies, directory=True))
    return {'credential_configured': credential_ready, 'configured': config is not None,
            'running': running(paths), 'ssh_aliases': ssh_aliases(paths['ssh_alias_config']),
            'current_target': config['target'] if config else None, 'paths': paths,
            'registration': registration(paths),
            'readiness': {'credentials': credential_ready, 'configuration': config is not None,
                          'runtime': runtime_ready, 'ready': credential_ready and config is not None and runtime_ready}}


def discover(paths, request):
    fields(request, ('ssh_destination', 'candidate_id', 'listen_port'), ('ssh_destination',))
    if 'listen_port' in request and (type(request['listen_port']) is not int or not 1024 <= request['listen_port'] <= 65535):
        raise OnboardingError('invalid-request', 'The reviewed local listener port must be an integer in 1024..65535.')
    alias = validate_ssh_destination(request['ssh_destination'])
    selected = request.get('candidate_id')
    if selected is not None and (not isinstance(selected, str) or not re.fullmatch(r'[a-f0-9]{24}', selected)):
        raise OnboardingError('invalid-request', 'Candidate selection must be an ID returned by discovery.')
    previous = current_configuration(paths)
    args = SimpleNamespace(ssh_destination=alias, original_state_dir=None, daemon_socket=None,
                           target_port=None, inventory=True, candidate_id=selected,
                           excluded_state_dirs=[previous['gateway']['state_dir'] + '/native'] if previous else [])
    remote = setup.discover(args)
    if 'candidates' in remote:
        candidates = remote['candidates']
        if not isinstance(candidates, list) or len(candidates) > 64:
            raise OnboardingError('discovery-failed', 'Remote candidate inventory is invalid.')
        public = []
        for item in candidates:
            if (not isinstance(item, dict) or not isinstance(item.get('id'), str)
                    or not re.fullmatch(r'[a-f0-9]{24}', item['id'])
                    or type(item.get('pid')) is not int or item['pid'] <= 0
                    or type(item.get('port')) is not int or not 1 <= item['port'] <= 65535):
                raise OnboardingError('discovery-failed', 'Remote candidate inventory is invalid.')
            state, daemon = setup.remote_path(item.get('state')), setup.remote_path(item.get('daemon_socket'))
            if len(state) > 4096 or len(daemon) > 4096:
                raise OnboardingError('discovery-failed', 'Remote candidate paths exceed their limit.')
            public.append({'id': item['id'], 'label': 'Tern service PID %d · UDP %d' % (item['pid'], item['port']),
                           'detail': state + ' → ' + daemon})
        return {'code': 'choose', 'candidates': public}
    if not isinstance(remote.get('candidate_id'), str) or not re.fullmatch(r'[a-f0-9]{24}', remote['candidate_id']):
        raise OnboardingError('discovery-failed', 'Remote discovery did not verify a stable process selection.')
    same = previous is not None and previous['ssh_destination'] == alias
    args.name = previous['target']['name'] if same else (alias if len(alias) <= 64 else 'server-' + hashlib.sha256(alias.encode()).hexdigest()[:16])
    args.listen_port = request.get('listen_port', previous['listen_port'] if previous else 18377)
    same_workspace = (previous is not None and previous['target']['host'] == remote['host']
                      and previous['target']['user'] == remote['user']
                      and previous['target']['fingerprint'] == remote['fingerprint']
                      and previous['target']['port'] == remote['target_port']
                      and previous['gateway']['daemon_socket'] == remote['daemon_socket'])
    if same_workspace:
        args.gateway_state_dir = previous['gateway']['state_dir']
    else:
        binding = [socket.gethostname(), str(owned_path(paths['data_dir'], directory=True)),
                   remote['host'], remote['user'], remote['daemon_socket'],
                   remote['original_state_dir'], remote['fingerprint'], remote['target_port']]
        namespace = hashlib.sha256(json.dumps(binding, separators=(',', ':')).encode()).hexdigest()[:24]
        args.gateway_state_dir = setup.remote_path(remote['home']) + '/.local/state/tern-turn-relay/workspaces/' + namespace
    args.credential_file = owned_path(previous['credential_file'] if previous else paths['credential_file'])
    args.dependency_dir = owned_path(previous['dependency_dir'] if previous else paths['dependency_dir'], directory=True)
    config = setup.configuration(args, remote)
    if same_workspace:
        config['gateway']['fingerprint'] = previous['gateway']['fingerprint']
    registered = registration(paths)
    review = {'schema': 1, 'ssh_destination': alias, 'candidate_id': remote['candidate_id'],
              'listen_port': args.listen_port,
              'configuration': config, 'original_state_dir': setup.remote_path(remote['original_state_dir']),
              'paths': dict(paths, credential_file=str(args.credential_file), dependency_dir=str(args.dependency_dir)),
              'previous_config_sha256': config_digest(paths),
              'registration': registered, 'migrate_native': registered == 'linked',
              'changes': ['Install pinned local Python dependencies in the reviewed dependency directory.',
                          'Provision the dedicated TURN gateway in the reviewed remote gateway state directory.',
                          'Write private plugin configuration and the managed SSH compatibility block.',
                          'Preserve the original Tern identity and existing session daemon; do not start a connection.']}
    if previous is not None and not same_workspace:
        review['changes'].append('Preserve the previous gateway state and daemon pin without modification: ' + previous['gateway']['state_dir'])
    if review['migrate_native']:
        review['changes'].append('Migrate the owned legacy .path registration to a native plugin copy; retain the durable old package for recovery.')
    return {'code': 'review', 'review': review, 'candidates': [],
            'summary': '%s · %s:%d · existing daemon %s' % (alias, config['target']['host'], config['target']['port'], config['gateway']['daemon_socket'])}


def require_stopped(paths):
    if running(paths):
        raise OnboardingError('stopped-required', 'Disconnect TURN explicitly before changing its configuration or credentials.', 6)


def apply(paths, request, args):
    fields(request, ('review', 'authorize_replace'), ('review',))
    replace = boolean(request, 'authorize_replace')
    review = request['review']
    if not isinstance(review, dict):
        raise OnboardingError('invalid-request', 'Apply requires the complete reviewed configuration.')
    require_stopped(paths)
    if current_configuration(paths) is not None and not replace:
        raise OnboardingError('replacement-consent-required', 'Replacing installed configuration requires explicit consent.', 6)
    fresh = discover(paths, {'ssh_destination': review.get('ssh_destination'),
                            'candidate_id': review.get('candidate_id'), 'listen_port': review.get('listen_port')})
    if fresh.get('code') != 'review' or fresh['review'] != review:
        raise OnboardingError('review-changed', 'Target, ownership or configuration changed; discover and review again.', 6)
    data = Path(paths['data_dir'])
    from install import install, private_directory
    private_directory(data)
    fd, name = tempfile.mkstemp(prefix='.onboarding-', suffix='.json', dir=data)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(review['configuration'], stream)
        load_config(name, allow_unprovisioned=True)
        # Do not forward installer diagnostics (including subprocess exception text).
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = install(SimpleNamespace(config=Path(name), replace_config=replace,
                tern=args.tern, config_dir=Path(paths['config_dir']), ssh_config=Path(paths['ssh_config']),
                data_dir=data, package_dir=Path(paths['package_dir']),
                migrate_native=review['migrate_native'],
                expected_config_sha256=review['previous_config_sha256']))
        return dict(result, configured=True)
    finally:
        Path(name).unlink(missing_ok=True)


@contextlib.contextmanager
def lifecycle_change(paths):
    """Hold the same lifecycle locks as install/start; never stop a running relay."""
    from install import private_directory
    from relay_config import lock_file
    data = owned_path(paths['data_dir'], directory=True)
    private_directory(data)
    # These operations create regular lock files, not a UNIX control socket.
    # Keep the daemon's socket-length restriction at actual socket startup.
    runtime = owned_path(data / 'runtime', directory=True)
    private_directory(runtime)
    descriptors = []
    try:
        for name in ('command.lock', 'service.lock'):
            fd = lock_file(runtime / name)
            descriptors.append(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise OnboardingError('stopped-required', 'Disconnect TURN and finish other lifecycle operations before changing this installation.', 6) from None
        yield
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def management_registration(paths, native_only=False):
    from install import plugin_link
    plugins = owned_path(Path(paths['config_dir']) / 'plugins', directory=True)
    package = owned_path(paths['package_dir'], directory=True)
    marker, source = plugin_link(plugins)
    if marker is None or source != package or not package.is_dir():
        raise OnboardingError('registration-changed', 'The current plugin registration does not match this setup helper context.', 6)
    native = marker == plugins / PLUGIN_ID and not marker.is_symlink() and package == marker
    if native_only and not native:
        raise OnboardingError('migration-required', 'Update requires a native installation; complete the reviewed legacy migration first.', 6)
    return native


def management_environment(paths, args):
    from install import tern_environment
    tern, environment, plugins, data = tern_environment(args.tern, Path(paths['config_dir']))
    if plugins != Path(paths['config_dir']) / 'plugins' or data != Path(paths['data_dir']):
        raise OnboardingError('context-mismatch', 'Tern resolved a different plugin profile; no management operation was performed.', 6)
    return tern, environment


def manage(paths, request, args):
    fields(request, ('confirm',), ('confirm',))
    if request['confirm'] is not True:
        raise OnboardingError('confirmation-required', 'Explicit confirmation is required for plugin update or removal.', 6)
    require_stopped(paths)
    management_registration(paths, native_only=args.action == 'update')
    manifest = owned_path(Path(paths['data_dir']) / 'installation.json')
    config_path = owned_path(paths['config_file'])
    if args.action == 'uninstall' and manifest.exists():
        # The owned uninstaller acquires its own lifecycle locks and revalidates
        # registration. Its no-stop mode is mandatory for this UI boundary.
        management_environment(paths, args)
        from uninstall import uninstall
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = uninstall(SimpleNamespace(tern=args.tern,
                config_dir=Path(paths['config_dir']), ssh_config=Path(paths['ssh_config']),
                data_dir=Path(paths['data_dir']), package_dir=Path(paths['package_dir']),
                require_stopped_only=True))
        return dict(result, reload_expected=True)
    if args.action == 'uninstall' and config_path.exists():
        raise OnboardingError('ownership-required', 'A configured installation requires its ownership record before removal.', 6)
    from install import run
    with lifecycle_change(paths):
        management_registration(paths, native_only=True)
        tern, environment = management_environment(paths, args)
        if args.action == 'update':
            # Fixed first-party source: never accept a repository, URL or path
            # from JSON input, and never touch plugin-data during replacement.
            run([str(tern), 'plugin', 'install', 'github.com/jiwangyihao/tern-turn-relay', '--force'], environment)
            management_registration(paths, native_only=True)
            result = {'updated': True, 'registration': 'native'}
        else:
            if owned_path(manifest).exists() or owned_path(config_path).exists():
                raise OnboardingError('registration-changed', 'Installation state changed before removal; inspect and confirm again.', 6)
            run([str(tern), 'plugin', 'remove', PLUGIN_ID], environment)
            from install import plugin_link
            if plugin_link(Path(paths['config_dir']) / 'plugins')[0] is not None:
                raise OnboardingError('removal-unconfirmed', 'Tern did not remove the native registration; private data was preserved.', 7)
            result = {'plugin_removed': True, 'marked_ssh_rule_removed': False}
    return dict(result, configuration_preserved=True, credentials_preserved=True,
                managed_runtime_preserved=True, data_preserved=True,
                remote_daemon_preserved=True, remote_gateway_state_preserved=True,
                connection_started=False, stop_requested=False, reload_expected=True)


def execute(args, request):
    paths = context(args)
    if args.action == 'inspect':
        fields(request, ())
        return inspect(paths)
    if args.action == 'discover':
        return discover(paths, request)
    if args.action == 'apply':
        return apply(paths, request, args)
    if args.action in ('update', 'uninstall'):
        return manage(paths, request, args)
    fields(request, ('replace',))
    replace = boolean(request, 'replace')
    require_stopped(paths)
    with lifecycle_change(paths):
        config = current_configuration(paths)
        path = owned_path(config['credential_file'] if config else paths['credential_file'])
        result = credentials.configure_native(path, replace=replace)
    return dict(result, credential_configured=True)


def main(argv=None):
    action = None
    try:
        args = parser().parse_args(argv)
        action = args.action
        request = read_request(getattr(sys.stdin, 'buffer', sys.stdin))
        result = dict(execute(args, request), ok=True)
        result.setdefault('code', 'ok')
        exit_code = 0
    except OnboardingError as exc:
        result, exit_code = {'ok': False, 'code': exc.code, 'error': str(exc)}, exc.exit_code
    except credentials.CredentialError as exc:
        code = 'cancelled' if str(exc) == 'Local credential change cancelled.' else 'credential-error'
        result, exit_code = {'ok': False, 'code': code, 'error': str(exc)}, exc.exit_code
    except KeyboardInterrupt:
        result, exit_code = {'ok': False, 'code': 'cancelled', 'error': 'Onboarding cancelled.'}, 130
    except Exception:
        result, exit_code = {'ok': False, 'code': 'operation-failed',
                             'error': 'Onboarding failed; verify the trusted SSH alias, existing service, and private path ownership. No diagnostics or secrets were disclosed.'}, 7
    result.update(action=action, exit_code=exit_code)
    encoded = json.dumps(result, separators=(',', ':'))
    if len(encoded.encode('utf-8')) > MAX_JSON:
        result = {'ok': False, 'action': action, 'code': 'response-limit', 'exit_code': 7,
                  'error': 'Onboarding response exceeded its bounded output limit.'}
        encoded, exit_code = json.dumps(result, separators=(',', ':')), 7
    print(encoded)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
