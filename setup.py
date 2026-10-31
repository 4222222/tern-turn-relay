#!/usr/bin/env python3
"""Discover an existing Tern service through already-trusted SSH and write private configuration.

This command never accepts a new SSH host key, launches a daemon, or generates
an original Tern identity. JSON diagnostics redact endpoints, paths and pins.
"""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import tempfile

from relay_config import load_config, private_file, validate_ssh_destination

# Executed only through authenticated SSH. No package deployment or daemon start.
REMOTE_DISCOVERY = r'''
import base64, hashlib, ipaddress, json, os, pwd, re, socket, stat, struct, subprocess, sys
from pathlib import Path

def fail(message):
    raise ValueError(message)

def option(argv, name):
    values = []
    for index, item in enumerate(argv):
        if item == name and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif item.startswith(name + '='):
            values.append(item[len(name) + 1:])
    if len(values) > 1:
        fail('Ambiguous service options; select an explicit original service')
    return values[0] if values else None

def path(value):
    if (not isinstance(value, str) or not value.startswith('/') or value == '/'
            or any(part in ('', '.', '..') for part in value[1:].split('/'))
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        fail('Remote paths must be canonical absolute paths')
    return Path(value)

def regular(value):
    info = value.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        fail('Original identity files must be owned non-symlink files without public write access')

def directory(value):
    for component in [value] + list(value.parents):
        info = component.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            fail('Remote state or socket directory has unsafe ancestors')

def select_service(services, override):
    selected = services
    if override:
        state = str(path(override))
        selected = [item for item in services if item['state'] in (None, state)]
    if len(selected) != 1:
        fail('Original Tern service is absent or ambiguous; pass --original-state-dir for one existing remote serve process')
    return selected[0]

def select_daemon(daemons, wanted):
    selected = daemons
    if wanted:
        wanted = str(path(wanted))
        selected = [item for item in daemons if item['socket'] == wanted]
    if len(selected) != 1:
        fail('Existing session daemon is absent or ambiguous; pass --daemon-socket')
    return selected[0]

def udp_listeners(entry, uid):
    """Join kernel UDP rows to this process's open socket inodes, never argv defaults."""
    inodes = set()
    for fd in (entry / 'fd').iterdir():
        try:
            match = re.fullmatch(r'socket:\[([0-9]+)\]', os.readlink(fd))
            if match:
                inodes.add(match[1])
        except (FileNotFoundError, PermissionError):
            continue
    result = []
    for name, family in (('udp', socket.AF_INET), ('udp6', socket.AF_INET6)):
        table = entry / 'net' / name
        if not table.exists():
            continue
        with table.open() as stream:
            next(stream, None)
            for index, line in enumerate(stream):
                if index >= 16384:
                    fail('UDP inventory exceeded its limit')
                fields = line.split()
                if len(fields) < 10 or fields[9] not in inodes or int(fields[7]) != uid:
                    continue
                # Only unconnected bound sockets can be the original UDP listener.
                if fields[3] != '07' or int(fields[2].replace(':', ''), 16) != 0:
                    continue
                address, port = fields[1].split(':')
                packed = bytes.fromhex(address)
                packed = b''.join(packed[i:i + 4][::-1] for i in range(0, len(packed), 4))
                address = socket.inet_ntop(family, packed)
                port = int(port, 16)
                if port:
                    result.append({'port': port, 'address': address, 'inode': fields[9]})
    return sorted(result, key=lambda item: (item['port'], item['inode']))

def native_listeners(service, host):
    """Separate native QUIC from Iroh: a default is useful only when observed."""
    allowed = {'0.0.0.0', '127.0.0.1', '::', '::1', str(ipaddress.IPv4Address(host))}
    listen = service['listen']
    address = None
    port = 8376  # Native remote endpoint default; never synthesize a socket.
    if listen is not None:
        match = re.fullmatch(r'(\[[0-9a-fA-F:]+\]|[^:]+):([0-9]{1,5})', listen)
        if not match:
            return []
        try:
            address = str(ipaddress.ip_address(match[1].strip('[]')))
            port = int(match[2])
        except ValueError:
            return []
        if address not in allowed or not 1 <= port <= 65535:
            return []
    return [item for item in service['listeners']
            if item['port'] == port and item['address'] in allowed
            and (address is None or item['address'] == address)]

def gateway_frontend(service, home, excluded):
    if not service['state']:
        return False
    state = path(service['state'])
    reserved = {str(path(value)) for value in excluded}
    reserved.add(str(path(home) / '.local/state/tern-turn-relay/native'))
    if str(state) in reserved:
        return True
    # Custom/per-workspace gateways retain this ownership record beside native/.
    # Its presence makes this reserved state ineligible even if the pin is stale.
    marker = state.parent / 'daemon-identity.json'
    if state.name == 'native' and (marker.exists() or marker.is_symlink()):
        try:
            directory(state.parent)
            regular(marker)
        except (OSError, ValueError):
            return True
        return True
    return False

def candidate_id(service, daemon, listener):
    binding = [service['pid'], service['start'], service['state'], daemon['pid'],
               daemon['start'], daemon['socket'], listener['inode'], listener['port']]
    return hashlib.sha256(json.dumps(binding, separators=(',', ':')).encode()).hexdigest()[:24]

def verify_daemon(daemon):
    endpoint = path(daemon['socket'])
    directory(endpoint.parent)
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        fail('Existing daemon socket has unsafe ownership or permissions')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(2)
        probe.connect(str(endpoint))
        peer_pid, peer_uid, _ = struct.unpack('3i', probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if peer_pid != daemon['pid'] or peer_uid != os.getuid():
        fail('Existing daemon socket does not belong to the selected process')
    return endpoint

def related_daemons(service, daemons):
    if service['daemon']:
        return [item for item in daemons if item['socket'] == service['daemon']]
    return [item for item in daemons if item['ppid'] == service['pid']
            and int(item['start']) >= int(service['start'])]

try:
    request = json.loads(sys.stdin.buffer.read(65537))
    uid = os.getuid()
    user = pwd.getpwuid(uid).pw_name
    home = str(path(os.environ.get('HOME') or pwd.getpwuid(uid).pw_dir))
    services, daemons = [], []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            with (entry / 'cmdline').open('rb') as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                continue
            argv = [part.decode() for part in raw.split(b'\0') if part]
            executable = (entry / 'exe').resolve(strict=True)
            if not argv or Path(argv[0]).name != 'tern':
                continue
            process_stat = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            start = process_stat[19]
            if 'daemon' in argv and option(argv, '--socket'):
                daemons.append({'pid': int(entry.name), 'ppid': int(process_stat[1]),
                                'start': start, 'socket': option(argv, '--socket')})
            if argv[1:3] == ['remote', 'serve']:
                with (entry / 'environ').open('rb') as stream:
                    environ = stream.read(1024 * 1024 + 1)
                if len(environ) > 1024 * 1024:
                    fail('Service environment exceeded its discovery limit')
                # Read only endpoint selection, never return process environment.
                values = dict(item.split(b'=', 1) for item in environ.split(b'\0') if b'=' in item)
                daemon = values.get(b'TERN_DAEMON_SOCKET') or values.get(b'TERN_PANE_SOCKET')
                services.append({'pid': int(entry.name), 'start': start, 'state': option(argv, '--state-dir'),
                                 'listen': option(argv, '--listen'), 'binary': str(executable),
                                 'daemon': daemon.decode() if daemon else None,
                                 'listeners': udp_listeners(entry, uid)})
        except (FileNotFoundError, ProcessLookupError, PermissionError, UnicodeError):
            continue
    candidates = []
    for service in services:
        if not service['state'] or gateway_frontend(service, home, request.get('excluded_state_dirs', [])):
            continue  # Never use our own frontend as the original service.
        if request.get('original_state_dir') not in (None, service['state']):
            continue
        for daemon in related_daemons(service, daemons):
            if request.get('daemon_socket') not in (None, daemon['socket']):
                continue
            try:
                state = path(service['state'])
                directory(state)
                for name in ('host_key', 'host_cert.der'):
                    regular(state / name)
                verify_daemon(daemon)
            except (OSError, ValueError):
                continue
            for listener in native_listeners(service, request['target_host']):
                if request.get('target_port') not in (None, listener['port']):
                    continue
                candidates.append((candidate_id(service, daemon, listener), service, daemon, listener))
    if len(candidates) > 64:
        fail('Too many verified service candidates')
    selected = [item for item in candidates if item[0] == request.get('candidate_id')] if request.get('candidate_id') else candidates
    if request.get('inventory') and not request.get('candidate_id') and len(selected) != 1:
        print(json.dumps({'ok': True, 'home': home, 'uid': uid, 'user': user,
                          'candidates': [{'id': item[0], 'pid': item[1]['pid'],
                                          'state': str(path(item[1]['state'])), 'daemon_socket': str(path(item[2]['socket'])),
                                          'port': item[3]['port']} for item in candidates]}))
        sys.exit(0)
    if len(selected) != 1:
        fail('Original Tern service is absent or ambiguous; pass --original-state-dir for one existing remote serve process')
    selected_id, service, daemon, listener = selected[0]
    state = path(service['state'])
    endpoint = verify_daemon(daemon)
    port = listener['port']
    binary = path(service['binary'])
    directory(binary.parent)
    binary_info = binary.stat()
    if not stat.S_ISREG(binary_info.st_mode) or binary_info.st_uid not in (0, uid) or binary_info.st_mode & 0o022:
        fail('Original Tern executable has unsafe ownership or permissions')
    environment = dict(os.environ, TERN_DAEMON_SOCKET=str(endpoint), TERN_PANE_SOCKET=str(endpoint))
    identity = subprocess.run([str(binary), 'remote', 'host-key', '--state-dir', str(state)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=environment, timeout=10, check=True)
    if len(identity.stdout) > 65536:
        fail('Original host identity response exceeded its limit')
    fingerprint = json.loads(identity.stdout).get('fingerprint')
    if not isinstance(fingerprint, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint):
        fail('Original host fingerprint is invalid')
    raw = base64.b64decode(fingerprint[7:] + '=', validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode().rstrip('=') != fingerprint[7:]:
        fail('Original host fingerprint is not canonical')
    for process in (service, daemon):
        entry = Path('/proc') / str(process['pid'])
        current_stat = entry.joinpath('stat').read_text().rsplit(')', 1)[1].split()
        if entry.stat().st_uid != uid or current_stat[19] != process['start']:
            fail('Selected process changed during discovery')
        if process is daemon and not service['daemon'] and int(current_stat[1]) != service['pid']:
            fail('Selected daemon relationship changed during discovery')
    if listener not in udp_listeners(Path('/proc') / str(service['pid']), uid):
        fail('Selected UDP listener changed during discovery')
    verify_daemon(daemon)
    print(json.dumps({'ok': True, 'home': home, 'uid': uid, 'user': user,
                      'original_state_dir': str(state), 'daemon_socket': str(endpoint),
                      'target_port': port, 'fingerprint': fingerprint, 'candidate_id': selected_id}))
except ValueError as error:
    print(json.dumps({'ok': False, 'error': str(error)}))
    sys.exit(1)
except Exception:
    print(json.dumps({'ok': False, 'error': 'Read-only remote discovery failed; confirm existing service, identity files and daemon socket'}))
    sys.exit(1)
'''


class SetupError(ValueError):
    pass


def ssh_options():
    return ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UpdateHostKeys=no', '-o', 'ForwardAgent=no',
            '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'NumberOfPasswordPrompts=0', '-o', 'ClearAllForwardings=yes',
            '-o', 'PermitLocalCommand=no', '-o', 'RequestTTY=no',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'EscapeChar=none']


def resolve_destination(alias, runner=subprocess.run):
    validate_ssh_destination(alias)
    result = runner(['/usr/bin/ssh', '-G', *ssh_options(), alias],
                    capture_output=True, text=True, timeout=15)
    if result.returncode or len(result.stdout) > 1024 * 1024:
        raise SetupError('SSH alias resolution failed; no SSH diagnostics were disclosed')
    fields = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition(' ')
        if key in ('hostname', 'user', 'port', 'proxyjump', 'proxycommand'):
            if not separator or key in fields:
                raise SetupError('SSH alias has ambiguous endpoint settings')
            fields[key] = value.strip()
    if any(fields.get(key, 'none').lower() != 'none' for key in ('proxyjump', 'proxycommand')):
        raise SetupError('Use a direct SSH alias; ProxyJump/ProxyCommand are unsupported and were not executed')
    try:
        address = ipaddress.IPv4Address(fields['hostname'])
        if not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError()
        port = int(fields['port'])
        if not 1 <= port <= 65535 or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', fields['user']):
            raise ValueError()
    except (KeyError, ValueError):
        raise SetupError('Direct SSH alias must resolve to a public IPv4 literal, safe User and valid Port') from None
    return {'host': str(address), 'user': fields['user'], 'ssh_port': port}


def discover(args, runner=subprocess.run):
    endpoint = resolve_destination(args.ssh_destination, runner)
    request = {'original_state_dir': args.original_state_dir, 'daemon_socket': args.daemon_socket,
               'target_port': args.target_port, 'inventory': getattr(args, 'inventory', False),
               'candidate_id': getattr(args, 'candidate_id', None), 'target_host': endpoint['host'],
               'excluded_state_dirs': getattr(args, 'excluded_state_dirs', [])}
    command = shlex.join(['python3', '-B', '-c', REMOTE_DISCOVERY])
    result = runner(['/usr/bin/ssh', '-T', *ssh_options(), args.ssh_destination, command],
                    input=json.dumps(request), capture_output=True, text=True, timeout=40)
    if len(result.stdout) > 65536:
        raise SetupError('Remote discovery response exceeded its limit')
    try:
        remote = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise SetupError('Strict SSH discovery failed; verify the alias is already trusted and public-key authentication works') from None
    if result.returncode or remote.get('ok') is not True:
        # Only fixed script diagnostics are returned, never stderr or arbitrary JSON.
        known = (
            'Original Tern service is absent or ambiguous; pass --original-state-dir for one existing remote serve process',
            'Existing session daemon is absent or ambiguous; pass --daemon-socket',
            'Original UDP listener port is not explicit; pass --target-port',
        )
        message = remote.get('error', '')
        if isinstance(message, str) and message in known:
            raise SetupError(message)
        raise SetupError('Remote discovery failed; verify the original state directory, existing identity and daemon socket')
    if remote.get('user') != endpoint['user'] or type(remote.get('uid')) is not int or remote['uid'] < 0:
        raise SetupError('Authenticated remote user differs from the SSH alias')
    return dict(remote, host=endpoint['host'])


def remote_path(value):
    if (not isinstance(value, str) or not value.startswith('/') or value == '/'
            or str(PurePosixPath(value)) != value or '..' in PurePosixPath(value).parts
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise SetupError('Discovered remote paths must be canonical absolute paths')
    return value


def configuration(args, discovered):
    home = remote_path(discovered['home'])
    original = remote_path(discovered['original_state_dir'])
    gateway = remote_path(args.gateway_state_dir or home + '/.local/state/tern-turn-relay')
    if gateway == original or PurePosixPath(gateway) in PurePosixPath(original).parents or PurePosixPath(original) in PurePosixPath(gateway).parents:
        raise SetupError('Gateway state must be separate from the original service state')
    from credentials import default_credential_path
    credential = (args.credential_file or default_credential_path()).expanduser().absolute()
    dependency = (args.dependency_dir or default_credential_path().parent.parent / 'python-deps-py3').expanduser().absolute()
    for port, minimum in ((discovered['target_port'], 1), (args.listen_port, 1024)):
        if type(port) is not int or not minimum <= port <= 65535:
            raise SetupError('Invalid listener port')
    for value in (args.name or args.ssh_destination, discovered['user']):
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', value):
            raise SetupError('Target name and user must be safe identifiers of at most 64 characters; use --name for a longer SSH alias')
    fingerprint = discovered['fingerprint']
    if not isinstance(fingerprint, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint):
        raise SetupError('Original fingerprint is invalid; no pin was invented')
    raw = base64.b64decode(fingerprint[7:] + '=', validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode().rstrip('=') != fingerprint[7:]:
        raise SetupError('Original fingerprint is not canonical; no pin was invented')
    return {'schema': 3, 'ssh_destination': args.ssh_destination,
            'target': {'name': args.name or args.ssh_destination, 'host': discovered['host'],
                       'port': discovered['target_port'], 'user': discovered['user'],
                       'fingerprint': discovered['fingerprint']},
            'listen_port': args.listen_port,
            'gateway': {'state_dir': gateway, 'daemon_socket': remote_path(discovered['daemon_socket'])},
            'credential_file': str(credential), 'dependency_dir': str(dependency)}


def write_configuration(destination, config, replace=False):
    destination = destination.expanduser().absolute()
    if destination.is_symlink():
        raise SetupError('Refusing a symlink output configuration')
    if destination.exists() and not replace:
        raise SetupError('Output already exists; inspect it and explicitly pass --replace to replace configuration')
    parent = destination.parent
    for item in [parent] + list(parent.parents):
        if item.is_symlink():
            raise SetupError('Output directory must not contain symlinks')
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise SetupError('Output parent must be owned by this user with mode 0700')
    if destination.exists():
        private_file(destination)
    private_file(config['credential_file'])
    fd, temporary = tempfile.mkstemp(prefix='.setup-', dir=str(parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(config, stream, indent=2)
            stream.write('\n')
        load_config(temporary, allow_unprovisioned=True)
        if replace:
            if destination.is_symlink():
                raise SetupError('Output configuration changed during setup')
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--ssh-destination', required=True, help='existing, already-trusted direct SSH Host alias')
    result.add_argument('--credential-file', type=Path, help='private file created by credentials.py; contents are never printed')
    result.add_argument('--output', type=Path, help='private output path; required unless discovering or dry-running')
    result.add_argument('--discover', action='store_true', help='read-only discovery; emit only redacted JSON')
    result.add_argument('--dry-run', action='store_true', help='discover and plan without writing; emit only redacted JSON')
    result.add_argument('--json', action='store_true', help='JSON is the default output for humans and agents')
    result.add_argument('--replace', action='store_true', help='explicitly replace only the output configuration')
    result.add_argument('--original-state-dir', help='absolute state directory of the running original remote service')
    result.add_argument('--daemon-socket', help='absolute socket of the existing session daemon; never creates one')
    result.add_argument('--target-port', type=int, help='original UDP port, when it cannot be discovered from the process')
    result.add_argument('--gateway-state-dir', help='separate private remote gateway directory')
    result.add_argument('--dependency-dir', type=Path, help='local dependency location; installer installs exact pins if absent')
    result.add_argument('--listen-port', type=int, default=18377)
    result.add_argument('--name', help='safe display identifier; defaults to SSH alias')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if not args.output and not (args.discover or args.dry_run):
            raise SetupError('--output is required unless --discover or --dry-run is selected')
        if args.target_port is not None and not 1 <= args.target_port <= 65535:
            raise SetupError('--target-port must be in 1..65535')
        discovered = discover(args)
        config = configuration(args, discovered)
        dry = args.discover or args.dry_run
        if not dry:
            write_configuration(args.output, config, args.replace)
        print(json.dumps({'ok': True, 'written': not dry, 'redacted': True,
                          'ssh_trust': 'existing-strict', 'original_identity_verified': True,
                          'existing_daemon_verified': True, 'gateway_pin': 'pending-installer-verification',
                          'credential_file': '[redacted]', 'configuration': '[redacted]',
                          'daemon_started': False, 'remote_uid_discovered': True}))
        return 0
    except SetupError as error:
        message = str(error)
    except Exception:
        message = 'Setup failed; private diagnostics were withheld. Check SSH access, private paths and credential file permissions.'
    print(json.dumps({'ok': False, 'redacted': True, 'error': message}))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
