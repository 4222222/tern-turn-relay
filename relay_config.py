"""Validated, non-secret configuration and private runtime storage."""
import base64
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile


class RelayError(Exception):
    """A deliberately non-secret error safe for the public status contract."""


def private_file(path, read=False):
    """Check the opened inode, not just a potentially replaceable pathname."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 65536):
            raise RelayError('Management key must be an owned, non-symlink regular file with mode 0600 (max 64 KiB).')
        if read:
            with os.fdopen(fd, 'rb') as stream:
                fd = None
                raw = stream.read(65537)
                if len(raw) > 65536:
                    raise RelayError('Management key exceeds the 64 KiB limit.')
                try:
                    return json.loads(raw)
                except (ValueError, UnicodeError):
                    raise RelayError('Management key file is not valid JSON.') from None
    finally:
        if fd is not None:
            os.close(fd)


def validate_ssh_destination(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}', value):
        raise RelayError('ssh_destination must be a safe SSH Host alias (1..253 letters, digits, underscores, dots or hyphens; no options or user@ prefix).')
    return value


def load_config(path, check_key=True, allow_unprovisioned=False):
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or info.st_size > 65536):
                raise RelayError('Relay config must be an owned regular file without group/world write access (max 64 KiB).')
            raw = stream.read(65537)
            if len(raw) > 65536:
                raise RelayError('Relay config exceeds the 64 KiB limit.')
            value = json.loads(raw)
    except (OSError, ValueError, UnicodeError):
        raise RelayError('Cannot securely read a valid relay config JSON file.') from None
    fields = {'schema', 'target', 'gateway', 'listen_port', 'credential_file', 'dependency_dir', 'ssh_destination'}
    if not isinstance(value, dict) or set(value) != fields or type(value['schema']) is not int or value['schema'] != 3:
        raise RelayError('Config must contain exactly the schema-3 fields from config.example.json.')
    validate_ssh_destination(value['ssh_destination'])
    target = value['target']
    if not isinstance(target, dict) or set(target) != {'name', 'host', 'port', 'user', 'fingerprint'}:
        raise RelayError('Target must contain name, host, port, user and verified fingerprint.')
    if not isinstance(target['host'], str):
        raise RelayError('Target host must be a public IPv4 literal.')
    try:
        address = ipaddress.IPv4Address(target['host'])
        if not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError()
    except ValueError:
        raise RelayError('Target host must be a public unicast IPv4 literal.') from None
    for port, minimum in ((target['port'], 1), (value['listen_port'], 1024)):
        if type(port) is not int or not minimum <= port <= 65535:
            raise RelayError('Ports must be integers in 1..65535; loopback listener must be unprivileged.')
    for field in ('name', 'user'):
        if not isinstance(target[field], str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', target[field]):
            raise RelayError('Target name and user must be safe nonempty identifiers (max 64 characters).')
    gateway = value['gateway']
    gateway_fields = {'state_dir', 'daemon_socket', 'fingerprint'}
    if (not isinstance(gateway, dict)
            or (set(gateway) != gateway_fields
                and not (allow_unprovisioned and set(gateway) == gateway_fields - {'fingerprint'}))):
        raise RelayError('Gateway must contain state_dir, daemon_socket and independently verified fingerprint.')
    for label, binding in (('Target', target), ('Gateway', gateway)):
        # Only the installer may omit a not-yet-provisioned dedicated pin.
        # An explicitly supplied null, empty or malformed pin is never accepted.
        if label == 'Gateway' and allow_unprovisioned and 'fingerprint' not in binding:
            continue
        fingerprint = binding['fingerprint']
        if not isinstance(fingerprint, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint):
            raise RelayError(label + ' fingerprint must be an independently verified SHA256 fingerprint.')
        decoded = base64.b64decode(fingerprint[7:] + '=', validate=True)
        if len(decoded) != 32 or base64.b64encode(decoded).decode().rstrip('=') != fingerprint[7:]:
            raise RelayError(label + ' SHA256 fingerprint is not canonical.')
    if gateway.get('fingerprint') == target['fingerprint']:
        raise RelayError('Gateway requires a dedicated identity distinct from the original target fingerprint.')
    for field in ('state_dir', 'daemon_socket'):
        path = gateway[field]
        if (not isinstance(path, str) or not path.startswith('/') or path.startswith('//')
                or path == '/' or any(ord(char) < 32 or ord(char) == 127 for char in path)
                or '..' in PurePosixPath(path).parts or str(PurePosixPath(path)) != path):
            raise RelayError('Gateway paths must be canonical absolute remote paths without control characters.')
    for field in ('credential_file', 'dependency_dir'):
        if not isinstance(value[field], str) or not os.path.isabs(value[field]) or '\x00' in value[field]:
            raise RelayError('Credential and dependency paths must be absolute local paths.')
    # Foreground commands check metadata only; only the daemon reads key bytes.
    if check_key:
        try:
            private_file(value['credential_file'])
        except OSError:
            raise RelayError('Cannot securely open the management key file.') from None
    return value


def state_directory(path):
    directory = Path(os.path.abspath(path))
    # Reject symlink components so the security boundary cannot silently move.
    for component in reversed([directory] + list(directory.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            component.mkdir(mode=0o700)
            info = component.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RelayError('Runtime directory must not contain symlink components.')
    info = directory.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RelayError('Runtime directory must be owned by this user with mode 0700.')
    if len(os.fsencode(str(directory / 'control.sock'))) >= 104:
        raise RelayError('Runtime directory path is too long for a macOS UNIX control socket.')
    return directory


def lock_file(path):
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise RelayError('Runtime lock must be an owned regular file with mode 0600.')
    return fd


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def public_status(config=None, state='stopped', mode=None, service_id=None, error=None):
    return {
        'ok': state != 'error', 'state': state, 'mode': mode,
        'address': ('%s@127.0.0.1:%d' % (config['target']['user'], config['listen_port'])) if config else None,
        'target': dict(config['target']) if config else None,
        'ssh_destination': config['ssh_destination'] if config else None,
        'relay_fingerprint': config['gateway']['fingerprint'] if config else None,
        'daemon_socket': config['gateway']['daemon_socket'] if config else None,
        'route_policy': 'exclusive',
        'ssh_connections': 0,
        'queue_dropped_packets': 0, 'queue_dropped_bytes': 0,
        'queued_packets': 0, 'queued_bytes': 0, 'congested': False,
        'bytes_up': 0, 'bytes_down': 0, 'flows': 0, 'error': error,
        'service_id': service_id, 'credentials_expires_at': None,
    }
