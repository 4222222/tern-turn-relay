"""SSH-owned Linux gateway to an already-running Tern daemon (Python 3.9+).

Only this process's native frontend is terminated. The existing daemon and its
original frontend are never signalled, installed, restarted, or reconfigured.
Public UDP accepts authenticated gateway frames, never native QUIC datagrams.
"""
import argparse
import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

from gateway_protocol import (
    CLIENT_TO_SERVER, SERVER_TO_CLIENT, MAX_FRAME, MAX_PAYLOAD,
    ReplayWindow, decode_frame, encode_frame,
)

CONTROL_LIMIT = 8192
HEARTBEAT_TIMEOUT = 45.0
FLOW_IDLE = 60.0
MAX_FLOWS = 16
MAX_FLOW_IDENTITIES = 4096

# Wire codes, not exception text, are consumed by gateway_client. Unknown or
# missing codes are deliberately fatal for compatibility with older helpers.
FAILURE_REASONS = frozenset({
    'unknown', 'protocol_error', 'identity_mismatch', 'security_error',
    'authorization_denied', 'control_eof', 'heartbeat_timeout', 'send_timeout',
    'frontend_exit', 'state_lock_busy', 'connectivity_uncertain',
})


class GatewayError(Exception):
    """Only fixed, non-secret messages may cross the SSH control channel."""

    def __init__(self, message, reason='unknown'):
        super().__init__(message)
        self.reason = reason if isinstance(reason, str) and reason in FAILURE_REASONS else 'unknown'


def error_response(error):
    reason = error.reason if isinstance(error, GatewayError) else 'unknown'
    if not isinstance(reason, str) or reason not in FAILURE_REASONS:
        reason = 'unknown'
    return {'ok': False, 'reason': reason,
            'error': 'Remote gateway failed its security or availability checks.'}


class ControlStopped(Exception):
    pass


def emit(value):
    sys.stdout.write(json.dumps(value, separators=(',', ':'), allow_nan=False) + '\n')
    sys.stdout.flush()


def checked_path(value):
    if (not isinstance(value, str) or not value.startswith('/')
            or '\x00' in value or len(value) > 4096
            or any(part in ('.', '..') for part in value.split('/'))):
        raise GatewayError('Invalid absolute filesystem path.')
    return Path(value)


def check_ancestors(path):
    for item in reversed([path] + list(path.parents)):
        info = item.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o022):
            raise GatewayError('Filesystem ancestry is not trusted.', 'security_error')


def private_directory(path):
    check_ancestors(path.parent)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise GatewayError('Gateway directory must be owned and mode 0700.', 'security_error')
    return path


def private_file(path, flags=os.O_RDONLY, create=False):
    fd = os.open(str(path), flags | os.O_NOFOLLOW | os.O_NONBLOCK
                 | (os.O_CREAT if create else 0), 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise GatewayError('Gateway file must be owned, private and regular.', 'security_error')
    return fd


def check_native_tree(path):
    count = 0
    for root, directories, files in os.walk(str(path), followlinks=False):
        for name in directories + files:
            count += 1
            if count > 256:
                raise GatewayError('Native gateway state exceeds its file limit.')
            info = (Path(root) / name).lstat()
            if (info.st_uid != os.getuid() or info.st_mode & 0o077
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                    or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                raise GatewayError('Native gateway state contains an unsafe entry.', 'security_error')


def process_identity(pid, daemon_socket):
    root = Path('/proc') / str(pid)
    text = (root / 'stat').read_text()
    fields = text[text.rfind(')') + 2:].split()
    if len(fields) < 20 or fields[0] == 'Z':
        raise GatewayError('Original daemon is unavailable.', 'identity_mismatch')
    # Tern may exec an upgraded binary in place. Its executable inode is not
    # workspace identity, but its canonical path and trust checks remain pinned.
    executable = root / 'exe'
    fd = os.open(str(executable), os.O_RDONLY | os.O_CLOEXEC)
    try:
        # Path and metadata must describe the same opened executable even if
        # the daemon execs between these reads; never mix two /proc snapshots.
        raw_path = os.readlink('/proc/self/fd/%d' % fd)
        running = os.fstat(fd)
    finally:
        os.close(fd)
    # Atomic replacement can unlink the mapped old binary before the daemon
    # execs its upgrade. Normalize only the kernel's deleted-file suffix on an
    # actually unlinked executable; its canonical path remains identity.
    if raw_path.endswith(' (deleted)'):
        if running.st_nlink != 0:
            raise GatewayError('Original daemon executable path changed.', 'identity_mismatch')
        raw_path = raw_path[:-len(' (deleted)')]
    path = checked_path(raw_path)
    if str(path) != raw_path or path.name != 'tern':
        raise GatewayError('Original daemon executable path changed.', 'identity_mismatch')
    check_ancestors(path.parent)
    installed = path.lstat()
    for info in (installed, running):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o022 or not info.st_mode & 0o111):
            raise GatewayError('Original daemon executable is unsafe.', 'security_error')
    # Both files must be independently trusted, but their inodes may differ
    # during replacement-before-exec. Neither inode is a workspace binding.
    if not os.access(str(path), os.X_OK):
        raise GatewayError('Original daemon executable path changed.', 'identity_mismatch')
    raw_command = (root / 'cmdline').read_bytes()
    if not raw_command.endswith(b'\0') or len(raw_command) > 8192:
        raise GatewayError('Original daemon arguments are invalid.', 'identity_mismatch')
    command = raw_command[:-1].split(b'\0')
    expected = os.fsencode(str(daemon_socket))
    if (not command or command[0] not in (os.fsencode(str(path)), b'tern')
            or command.count(b'daemon') != 1 or command.count(b'--socket') != 1
            or not any(command[index:index + 2] == [b'--socket', expected]
                       for index in range(len(command) - 1))):
        raise GatewayError('Socket owner is not the expected existing daemon.', 'identity_mismatch')
    try:
        arguments = [item.decode('utf-8') for item in command]
    except UnicodeError:
        raise GatewayError('Original daemon arguments are invalid.', 'identity_mismatch') from None
    return {
        'pid': pid, 'start_time': fields[19],
        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'executable_path': str(path), 'daemon_argv': arguments,
    }


class DaemonPin:
    def __init__(self, path):
        self.path = checked_path(path)
        check_ancestors(self.path.parent)
        info = self.path.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise GatewayError('Existing daemon socket is unsafe or unavailable.', 'security_error')
        self.socket_identity = (info.st_dev, info.st_ino)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(2.0)
            probe.connect(str(self.path))
            pid, uid, _ = struct.unpack('3i', probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.getuid() or pid <= 1:
            raise GatewayError('Existing daemon socket has an unexpected owner.', 'identity_mismatch')
        self.identity = process_identity(pid, self.path)
        self.pid = pid
        self.check()

    def check(self, responsive=False):
        try:
            info = self.path.lstat()
            if ((info.st_dev, info.st_ino) != self.socket_identity
                    or not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or process_identity(self.pid, self.path) != self.identity):
                raise GatewayError('Original daemon identity changed.', 'identity_mismatch')
            if responsive:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(1.0)
                    probe.connect(str(self.path))
                    pid, uid, _ = struct.unpack('3i', probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if pid != self.pid or uid != os.getuid():
                        raise GatewayError('Original daemon identity changed.', 'identity_mismatch')
        except OSError:
            raise GatewayError('Original daemon is unavailable.', 'identity_mismatch') from None

    def persist(self, directory):
        # Called under control.lock. Recheck live executable, process and peer
        # before accepting or migrating any on-disk binding.
        self.check(responsive=True)
        value = dict(self.identity, version=2, daemon_socket=str(self.path),
                     socket_device=self.socket_identity[0], socket_inode=self.socket_identity[1])
        path = directory / 'daemon-identity.json'
        try:
            fd = private_file(path)
        except FileNotFoundError:
            pass
        else:
            with os.fdopen(fd, 'rb') as stream:
                raw = stream.read(8193)

            def unique_fields(pairs):
                result = {}
                for name, item in pairs:
                    if name in result:
                        raise ValueError()
                    result[name] = item
                return result

            try:
                if len(raw) > 8192:
                    raise ValueError()
                saved = json.loads(raw, object_pairs_hook=unique_fields)
                if not isinstance(saved, dict):
                    raise ValueError()
                if set(saved) == set(value):
                    if (saved != value or any(type(saved[name]) is not type(value[name])
                                              for name in value)):
                        raise ValueError()
                    return
                # One-way legacy migration, never a second runtime identity
                # model: exact old shape, all stable fields equal, inode only
                # validated as legacy metadata and removed from the new record.
                stable = {'pid', 'start_time', 'boot_id', 'daemon_socket',
                          'socket_device', 'socket_inode'}
                if set(saved) != stable | {'exe_device', 'exe_inode'}:
                    raise ValueError()
                if any(saved[name] != value[name] or type(saved[name]) is not type(value[name])
                       for name in stable):
                    raise ValueError()
                if (type(saved['exe_device']) is not int or saved['exe_device'] < 0
                        or type(saved['exe_inode']) is not int or saved['exe_inode'] <= 0):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise GatewayError('Provisioned daemon identity no longer matches.', 'identity_mismatch') from None
        self.check(responsive=True)
        fd, temporary = tempfile.mkstemp(prefix='.daemon-', dir=str(directory))
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(value, stream, separators=(',', ':'))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def discover_tern(pin):
    # No PATH fallback: run only the checked executable of this pinned daemon.
    pin.check()
    return pin.identity['executable_path']


def daemon_environment(pin):
    # Explicit daemon endpoints override both pane-client and CLI discovery.
    environment = dict(os.environ)
    environment['TERN_DAEMON_SOCKET'] = str(pin.path)
    environment['TERN_PANE_SOCKET'] = str(pin.path)
    return environment


def reap_owned(child):
    if child is None:
        return
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
    child.wait()


def capture(arguments, environment, pin, maximum=4 * 1024 * 1024, control=None):
    pin.check(responsive=True)
    child = None
    with tempfile.TemporaryFile() as output:
        try:
            if control is not None:
                check_startup_control(control)
            child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=subprocess.DEVNULL, env=environment, close_fds=True)
            deadline = time.monotonic() + 10
            while child.poll() is None:
                if control is not None:
                    check_startup_control(control)
                pin.check()
                if time.monotonic() >= deadline or output.tell() > maximum:
                    raise GatewayError('Native inspection exceeded its bounded limits.')
                time.sleep(0.05)
            if child.returncode != 0:
                raise GatewayError('Native inspection failed.')
            output.seek(0)
            raw = output.read(maximum + 1)
            if len(raw) > maximum:
                raise GatewayError('Native inspection exceeded its bounded limits.')
            pin.check(responsive=True)
            return json.loads(raw)
        finally:
            reap_owned(child)


def host_fingerprint(binary, native, environment, pin, control=None):
    check_native_tree(native)
    result = capture([binary, 'remote', 'host-key', '--state-dir', str(native)],
                     environment, pin, maximum=65536, control=control)
    check_native_tree(native)
    fingerprint = result.get('fingerprint') if isinstance(result, dict) else None
    if not isinstance(fingerprint, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint):
        raise GatewayError('Native host fingerprint is invalid.')
    decoded = base64.b64decode(fingerprint[7:] + '=', validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded).decode().rstrip('=') != fingerprint[7:]:
        raise GatewayError('Native host fingerprint is noncanonical.')
    return fingerprint


class ControlInput:
    def __init__(self):
        self.fd = sys.stdin.fileno()
        os.set_blocking(self.fd, False)
        self.buffer = bytearray()
        self.closed = False

    def receive(self):
        try:
            data = os.read(self.fd, CONTROL_LIMIT + 1)
        except BlockingIOError:
            return []
        if not data:
            self.closed = True
            raise ControlStopped()
        self.buffer.extend(data)
        if len(self.buffer) > CONTROL_LIMIT:
            raise GatewayError('SSH control input exceeded its limit.', 'protocol_error')
        values = []
        while b'\n' in self.buffer:
            raw, _, remaining = self.buffer.partition(b'\n')
            self.buffer = bytearray(remaining)
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                raise GatewayError('SSH control input is invalid.', 'protocol_error') from None
            if not isinstance(value, dict):
                raise GatewayError('SSH control input is invalid.', 'protocol_error')
            values.append(value)
        return values

    def initial(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.fd, selectors.EVENT_READ)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline - time.monotonic())):
                    break
                values = self.receive()
                if values:
                    if len(values) != 1 or self.buffer:
                        raise GatewayError('Initial SSH control request is invalid.', 'protocol_error')
                    return values[0]
        raise GatewayError('Initial SSH control request timed out.')


def owned_loopback_listener(child, port):
    inodes = set()
    for item in (Path('/proc') / str(child.pid) / 'fd').iterdir():
        try:
            target = os.readlink(item)
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            inodes.add(target[8:-1])
    for line in Path('/proc/net/udp').read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 10 and fields[9] in inodes:
            address, hexadecimal_port = fields[1].split(':')
            if address == '0100007F' and int(hexadecimal_port, 16) == port:
                return True
    return False


class Flow:
    def __init__(self):
        self.replay = ReplayWindow()
        self.sequence = 0
        self.peer = None
        self.socket = None
        self.last_active = time.monotonic()


def close_flow(selector, flow):
    if flow.socket is not None:
        selector.unregister(flow.socket)
        flow.socket.close()
        flow.socket = None


def forward(selector, public, native_port, key, flows):
    try:
        packet, peer = public.recvfrom(MAX_FRAME + 1)
    except BlockingIOError:
        return
    decoded = decode_frame(key, CLIENT_TO_SERVER, packet)
    if decoded is None:
        return
    flow_id, sequence, payload = decoded
    flow = flows.get(flow_id)
    if flow is None:
        if len(flows) >= MAX_FLOW_IDENTITIES:
            return
        flow = Flow()
        flows[flow_id] = flow
    newer = sequence > flow.replay.highest
    if not flow.replay.accept(sequence):
        return
    if newer:
        # TURN egress may differ from its advertised allocation address. Only
        # the authenticated, observed source is a valid return destination.
        flow.peer = peer
    if flow.socket is None:
        if sum(item.socket is not None for item in flows.values()) >= MAX_FLOWS:
            return
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            connection.setblocking(False)
            connection.bind(('127.0.0.1', 0))
            connection.connect(('127.0.0.1', native_port))
            selector.register(connection, selectors.EVENT_READ, flow_id)
        except BaseException:
            connection.close()
            raise
        flow.socket = connection
    flow.last_active = time.monotonic()
    try:
        flow.socket.send(payload)
    except (BlockingIOError, ConnectionRefusedError):
        pass


def reply(public, key, flow_id, flow):
    try:
        payload = flow.socket.recv(MAX_PAYLOAD + 1)
    except (BlockingIOError, ConnectionRefusedError):
        return
    if len(payload) > MAX_PAYLOAD:
        return
    flow.sequence += 1
    if flow.sequence >= 1 << 64:
        raise GatewayError('Gateway flow exhausted its sequence space.')
    packet = encode_frame(key, SERVER_TO_CLIENT, flow_id, flow.sequence, payload)
    try:
        public.sendto(packet, flow.peer)
    except (BlockingIOError, ConnectionRefusedError):
        pass
    flow.last_active = time.monotonic()


def inventory(binary, environment, pin, control=None):
    result = capture([binary, 'ls', '--json'], environment, pin, control=control)
    if not isinstance(result, dict) or not isinstance(result.get('sessions'), list):
        raise GatewayError('Existing daemon inventory has an unsupported schema.')
    sessions, tabs, panes = set(), set(), set()

    def add_id(value, destination):
        if not isinstance(value, dict):
            raise GatewayError('Existing daemon inventory contains an invalid entry.')
        identifier = value.get('id')
        if type(identifier) is int and identifier >= 0:
            identifier = str(identifier)
        if not isinstance(identifier, str) or not identifier or len(identifier) > 256:
            raise GatewayError('Existing daemon inventory contains an invalid identity.')
        destination.add(identifier)

    def entries(value, field):
        items = value.get(field, [])
        if not isinstance(items, list):
            raise GatewayError('Existing daemon inventory has an unsupported schema.')
        return items

    for session in result['sessions']:
        add_id(session, sessions)
        for tab in entries(session, 'tabs'):
            add_id(tab, tabs)
            for block in entries(tab, 'blocks'):
                add_id(block, panes)
    for pane in entries(result, 'detached'):
        add_id(pane, panes)
    if not sessions or not tabs or not panes:
        raise GatewayError('Existing daemon has no complete workspace inventory.')
    return {'session_ids': sorted(sessions), 'tab_ids': sorted(tabs), 'pane_ids': sorted(panes)}


def existing_authorized_keys():
    # Reuse the account's existing OpenSSH authorization, never copy, create,
    # append to, chmod, or otherwise modify that user's trust policy.
    import pwd
    path = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.ssh' / 'authorized_keys'
    check_ancestors(path.parent)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size == 0):
            raise GatewayError('Existing account authorized_keys is unsafe or unavailable.', 'security_error')
    finally:
        os.close(fd)
    return path


def check_startup_control(control):
    with selectors.DefaultSelector() as selector:
        selector.register(control.fd, selectors.EVENT_READ)
        if selector.select(0):
            if control.receive():
                raise GatewayError('Unexpected control message during startup.', 'protocol_error')


def serve(binary, native, authorized_keys, environment, pin, control, key, host, descriptor):
    child = None
    flows = {}
    with selectors.DefaultSelector() as selector, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as public:
        try:
            check_startup_control(control)
            pin.check(responsive=True)
            public.bind((host, 0))
            public.setblocking(False)
            if public.getsockname()[1] < 1024:
                raise GatewayError('Gateway UDP port is not unprivileged.')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(('127.0.0.1', 0))
                native_port = reservation.getsockname()[1]
            child = subprocess.Popen(
                [binary, 'remote', 'serve', '--user', '--listen', '127.0.0.1:%d' % native_port,
                 '--state-dir', str(native), '--authorized-keys', str(authorized_keys),
                 '--no-iroh', '--relay', 'none', '--pkarr', 'none'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=environment, close_fds=True,
            )
            deadline = time.monotonic() + 10
            while True:
                check_startup_control(control)
                pin.check()
                if child.poll() is not None:
                    raise GatewayError('Owned native frontend exited before readiness.', 'frontend_exit')
                if owned_loopback_listener(child, native_port):
                    break
                if time.monotonic() >= deadline:
                    raise GatewayError('Owned native frontend did not bind loopback.')
                time.sleep(0.05)
            pin.check(responsive=True)
            selector.register(control.fd, selectors.EVENT_READ, 'control')
            selector.register(public, selectors.EVENT_READ, 'public')
            emit(dict(descriptor, host=host, port=public.getsockname()[1], native_frontend_pid=child.pid))
            last_heartbeat = time.monotonic()
            last_check = last_heartbeat
            last_probe = last_heartbeat
            while True:
                now = time.monotonic()
                if child.poll() is not None:
                    raise GatewayError('Owned native frontend exited.', 'frontend_exit')
                if now - last_heartbeat > HEARTBEAT_TIMEOUT:
                    raise GatewayError('SSH control heartbeat expired.', 'heartbeat_timeout')
                if now - last_check >= 1:
                    pin.check(responsive=now - last_probe >= 5)
                    if now - last_probe >= 5:
                        last_probe = now
                    last_check = now
                    for flow in flows.values():
                        if flow.socket is not None and now - flow.last_active >= FLOW_IDLE:
                            close_flow(selector, flow)
                for event, _ in selector.select(0.5):
                    if event.data == 'control':
                        for message in control.receive():
                            if message == {'op': 'stop'}:
                                return
                            if message != {'op': 'ping'}:
                                raise GatewayError('SSH control operation is invalid.', 'protocol_error')
                            last_heartbeat = time.monotonic()
                            emit({'ok': True, 'op': 'pong'})
                    elif event.data == 'public':
                        forward(selector, public, native_port, key, flows)
                    else:
                        flow = flows[event.data]
                        if flow.socket is not None:
                            reply(public, key, event.data, flow)
        finally:
            for flow in flows.values():
                close_flow(selector, flow)
            reap_owned(child)


def stop_signal(_number, _frame):
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, signal.SIG_IGN)
    raise ControlStopped()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', required=True)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument('--provision', action='store_true')
    operation.add_argument('--serve', action='store_true')
    arguments = parser.parse_args()
    os.umask(0o077)
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, stop_signal)
    control = ControlInput()
    request = control.initial()
    expected = {'daemon_socket', 'bind_host'} | ({'session_key'} if arguments.serve else set())
    if set(request) != expected:
        raise GatewayError('Initial SSH control request has invalid fields.', 'protocol_error')
    host = request['bind_host']
    if not isinstance(host, str):
        raise GatewayError('Public bind address must be a global IPv4 literal.')
    address = ipaddress.IPv4Address(host)
    if not address.is_global or address.is_multicast or address.is_reserved or str(address) != host:
        raise GatewayError('Public bind address must be a global IPv4 literal.')
    key = None
    if arguments.serve:
        encoded = request.pop('session_key')
        if not isinstance(encoded, str) or len(encoded) != 44:
            raise GatewayError('SSH session key is invalid.')
        key = base64.b64decode(encoded, validate=True)
        if len(key) != 32 or base64.b64encode(key).decode() != encoded:
            raise GatewayError('SSH session key is invalid.')
        del encoded
    pin = DaemonPin(request['daemon_socket'])
    binary = discover_tern(pin)
    environment = daemon_environment(pin)
    directory = private_directory(checked_path(arguments.state_dir))
    lock = private_file(directory / 'control.lock', os.O_RDWR, create=True)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise GatewayError('Gateway state is already controlled by another SSH session.', 'state_lock_busy') from None
        native = private_directory(directory / 'native')
        pin.persist(directory)
        startup_control = control if arguments.serve else None
        baseline = inventory(binary, environment, pin, control=startup_control)
        fingerprint = host_fingerprint(binary, native, environment, pin, control=startup_control)
        authorized_keys = existing_authorized_keys()
        descriptor = dict(baseline, ok=True, fingerprint=fingerprint,
                          daemon_socket=str(pin.path), daemon_pid=pin.pid)
        if arguments.provision:
            emit(descriptor)
            return
        pin.check(responsive=True)
        serve(binary, native, authorized_keys, environment, pin, control, key, host, descriptor)
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except (ControlStopped, BrokenPipeError):
        pass
    except Exception as error:
        try:
            emit(error_response(error))
        except BrokenPipeError:
            pass
        sys.exit(1)
