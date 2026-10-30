"""Private SSH control plane for the dedicated authenticated UDP gateway.

Only the two remote modules are deployed. Session keys travel in SSH stdin,
never command arguments, files, public descriptors or diagnostic messages.
"""
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat

from relay_config import RelayError, validate_ssh_destination
from relay_ssh import resolve_ssh_destination

STARTUP_TIMEOUT = 50  # Leave room for bounded owned-child shutdown within 60s.
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT = 35
MAX_LINE = 65536
MAX_SOURCE = 512 * 1024
MODULES = ('remote_gateway.py', 'gateway_protocol.py')

RECOVERABLE_REASONS = frozenset({
    'control_eof', 'heartbeat_timeout', 'send_timeout', 'frontend_exit',
    'state_lock_busy', 'connectivity_uncertain',
})
_FAILURE_MESSAGES = {
    'unknown': 'Dedicated gateway failed an unspecified control check.',
    'protocol_error': 'Dedicated gateway returned an invalid control response.',
    'identity_mismatch': 'Gateway identity, existing daemon or public endpoint verification failed.',
    'security_error': 'Dedicated gateway failed a security check.',
    'authorization_denied': 'Dedicated gateway authorization was denied.',
    'control_eof': 'Dedicated gateway control channel closed.',
    'heartbeat_timeout': 'Dedicated gateway control heartbeat expired.',
    'send_timeout': 'Dedicated gateway control send timed out.',
    'frontend_exit': 'Dedicated gateway owned frontend exited.',
    'state_lock_busy': 'Dedicated gateway state is still controlled by an SSH session.',
    'connectivity_uncertain': 'Dedicated gateway startup connectivity could not be established.',
}
FAILURE_REASONS = frozenset(_FAILURE_MESSAGES)


class GatewayControlError(RelayError):
    """Allowlisted cause only; never include SSH, provider or peer error text."""

    def __init__(self, reason='unknown'):
        self.reason = reason if isinstance(reason, str) and reason in FAILURE_REASONS else 'unknown'
        self.recoverable = self.reason in RECOVERABLE_REASONS
        super().__init__(_FAILURE_MESSAGES[self.reason])

# This fixed program is public code, not configuration or key material. The
# package and destination arrive through authenticated SSH stdin. Directory-fd
# operations prevent symlink traversal while preserving unrelated remote files.
_INSTALLER = r'''
import base64, hashlib, json, os, secrets, stat, sys
os.umask(0o077)
NAMES = ('remote_gateway.py', 'gateway_protocol.py')
LIMIT = 512 * 1024

def directory(parent, name, private=False):
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    safe = info.st_uid in (0, os.getuid())
    if private:
        safe = info.st_uid == os.getuid() and mode == 0o700
    elif mode & 0o022:
        safe = safe and info.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if not safe:
        os.close(fd)
        raise ValueError()
    return fd

def existing(fd, name, expected):
    try:
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return False
    with os.fdopen(source, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size != len(expected) or stream.read(LIMIT + 1) != expected):
            raise ValueError()
    return True

def install():
    raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError()
    data = json.loads(raw)
    if set(data) != {'state_dir', 'digest', 'files'} or set(data['files']) != set(NAMES):
        raise ValueError()
    path = data['state_dir']
    if (not isinstance(path, str) or not path.startswith('/') or path == '/'
            or any(part in ('', '.', '..') for part in path[1:].split('/'))
            or any(ord(char) < 32 or ord(char) == 127 for char in path)):
        raise ValueError()
    files = {}
    digest = hashlib.sha256()
    for name in NAMES:
        value = base64.b64decode(data['files'][name], validate=True)
        if not value or len(value) > LIMIT:
            raise ValueError()
        files[name] = value
        digest.update(name.encode() + b'\0' + value + b'\0')
    if data['digest'] != digest.hexdigest():
        raise ValueError()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = path[1:].split('/')
        for index, part in enumerate(parts):
            child = directory(fd, part, private=index == len(parts) - 1)
            os.close(fd)
            fd = child
        child = directory(fd, 'releases', private=True)
        os.close(fd)
        fd = child
        child = directory(fd, data['digest'], private=True)
        os.close(fd)
        fd = child
        if set(os.listdir(fd)) - set(NAMES):
            raise ValueError()
        for name, value in files.items():
            if existing(fd, name, value):
                continue
            temporary = '.' + name + '.' + secrets.token_hex(16)
            output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fd)
            try:
                with os.fdopen(output, 'wb') as stream:
                    stream.write(value)
                    stream.flush()
                    os.fsync(stream.fileno())
                # Never replace preexisting content, including unsafe paths.
                if not existing(fd, name, value):
                    os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            finally:
                os.unlink(temporary, dir_fd=fd)
        os.fsync(fd)
        for name, value in files.items():
            if not existing(fd, name, value):
                raise ValueError()
        return {'ok': True, 'digest': data['digest']}
    finally:
        os.close(fd)

try:
    result = install()
except Exception:
    result = {'ok': False, 'reason': 'security_error', 'error': 'Private gateway package installation failed.'}
print(json.dumps(result, separators=(',', ':')), flush=True)
sys.exit(0 if result['ok'] else 1)
'''


def _path(value):
    return (isinstance(value, str) and value.startswith('/') and value != '/'
            and len(value) <= 4096
            and all(part not in ('', '.', '..') for part in value[1:].split('/'))
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def _fingerprint(value):
    if not isinstance(value, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', value):
        return False
    decoded = base64.b64decode(value[7:] + '=', validate=True)
    return len(decoded) == 32 and base64.b64encode(decoded).decode().rstrip('=') == value[7:]


def _settings(config, pinned):
    try:
        gateway = config['gateway']
        target = config['target']
        address = ipaddress.IPv4Address(target['host'])
        valid = (bool(validate_ssh_destination(config['ssh_destination']))
                 and str(address) == target['host'] and address.is_global
                 and not address.is_multicast and not address.is_reserved
                 and _fingerprint(target['fingerprint'])
                 and _path(gateway['state_dir']) and _path(gateway['daemon_socket']))
        pin = gateway.get('fingerprint')
        if not valid or (pinned and not pin) or (pin is not None and not _fingerprint(pin)):
            raise ValueError()
        return gateway, target
    except (KeyError, TypeError, ValueError):
        raise RelayError('Gateway requires a valid SSH alias, a public IPv4 target, private absolute remote paths and a verified service pin.') from None


def _package(config):
    gateway, _ = _settings(config, pinned=False)
    directory = Path(__file__).resolve().parent
    files = {}
    digest = hashlib.sha256()
    for name in MODULES:
        fd = os.open(str(directory / name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or not 0 < info.st_size <= MAX_SOURCE):
                raise RelayError('Gateway source modules must be owned, non-writable regular files.')
            source = stream.read(MAX_SOURCE + 1)
            if len(source) > MAX_SOURCE:
                raise RelayError('Gateway source module exceeds the package limit.')
        digest.update(name.encode() + b'\0' + source + b'\0')
        files[name] = base64.b64encode(source).decode('ascii')
    return {'state_dir': gateway['state_dir'], 'digest': digest.hexdigest(), 'files': files}


def _ssh_argv(config, command):
    return ['/usr/bin/ssh', '-T', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'ForwardAgent=no',
            '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'NumberOfPasswordPrompts=0', '-o', 'ClearAllForwardings=yes',
            '-o', 'PermitLocalCommand=no', '-o', 'RequestTTY=no',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
            '-o', 'EscapeChar=none', config['ssh_destination'], shlex.join(command)]


async def _spawn(config, command):
    return await asyncio.create_subprocess_exec(
        *_ssh_argv(config, command), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        limit=MAX_LINE, start_new_session=True)


async def _bounded(awaitable, timeout):
    """Bound an operation without Python 3.9 wait_for's cancellation race."""
    task = asyncio.create_task(awaitable)
    try:
        done, _ = await asyncio.wait((task,), timeout=timeout)
        if not done:
            raise asyncio.TimeoutError()
        return task.result()
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def _send(process, value):
    try:
        process.stdin.write(json.dumps(value, separators=(',', ':'), allow_nan=False).encode() + b'\n')
        await _bounded(process.stdin.drain(), 5)
    except asyncio.TimeoutError:
        raise GatewayControlError('send_timeout') from None
    except (BrokenPipeError, ConnectionResetError):
        raise GatewayControlError('control_eof') from None


async def _receive(process):
    try:
        line = await process.stdout.readline()
    except (BrokenPipeError, ConnectionResetError):
        raise GatewayControlError('control_eof') from None
    except ValueError:
        raise GatewayControlError('protocol_error') from None
    if not line:
        raise GatewayControlError('control_eof')
    if len(line) > MAX_LINE or not line.endswith(b'\n'):
        raise GatewayControlError('protocol_error')
    try:
        value = json.loads(line)
    except (ValueError, UnicodeError):
        raise GatewayControlError('protocol_error') from None
    if not isinstance(value, dict):
        raise GatewayControlError('protocol_error')
    if value.get('ok') is False:
        raise GatewayControlError(value.get('reason'))
    if value.get('ok') is not True:
        raise GatewayControlError('protocol_error')
    return value


async def _discard(reader):
    while await reader.read(MAX_LINE):
        pass


async def _reap_child(process):
    if process is None:
        return
    if process.stdin is not None:
        process.stdin.close()
    # Keep stdout flowing while waiting, even if a malformed peer filled its pipe.
    drain = asyncio.create_task(_discard(process.stdout))
    try:
        for timeout, signal in ((2, None), (2, 'terminate')):
            if signal and process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
            try:
                await _bounded(process.wait(), timeout)
                return
            except asyncio.TimeoutError:
                pass
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.wait()
    finally:
        drain.cancel()
        await asyncio.gather(drain, return_exceptions=True)


async def _reap(process):
    # Cancellation of startup/shutdown must not strand the SSH child.
    cleanup = asyncio.create_task(_reap_child(process))
    try:
        await asyncio.shield(cleanup)
    except asyncio.CancelledError:
        await cleanup
        raise


async def _deploy(config):
    package = _package(config)
    await resolve_ssh_destination(config)
    process = await _spawn(config, ['python3', '-B', '-c', _INSTALLER])
    try:
        await _send(process, package)
        process.stdin.close()
        result = await _receive(process)
        if set(result) != {'ok', 'digest'} or result['digest'] != package['digest']:
            raise GatewayControlError('identity_mismatch')
        if await process.wait() != 0:
            raise GatewayControlError('security_error')
    finally:
        await _reap(process)
    return package['state_dir'] + '/releases/' + package['digest'] + '/remote_gateway.py'


def _descriptor(config, value, serving):
    gateway, target = _settings(config, pinned=serving)
    fields = {'ok', 'fingerprint', 'daemon_socket', 'daemon_pid',
              'session_ids', 'tab_ids', 'pane_ids'}
    if serving:
        fields |= {'host', 'port'}
        if 'native_frontend_pid' in value:
            fields.add('native_frontend_pid')
    valid = (set(value) == fields and value.get('ok') is True
             and _fingerprint(value.get('fingerprint'))
             and value.get('fingerprint') != target['fingerprint']
             and value.get('daemon_socket') == gateway['daemon_socket']
             and type(value.get('daemon_pid')) is int and value['daemon_pid'] > 0)
    pin = gateway.get('fingerprint')
    if pin is not None:
        valid = valid and value.get('fingerprint') == pin
    for name in ('session_ids', 'tab_ids', 'pane_ids'):
        ids = value.get(name)
        valid = valid and isinstance(ids, list) and len(ids) <= 4096
        if isinstance(ids, list):
            valid = valid and all(
                (isinstance(item, str) and 0 < len(item) <= 256
                 and not any(ord(char) < 32 or ord(char) == 127 for char in item))
                or (type(item) is int and 0 <= item < 2 ** 64) for item in ids)
    if serving:
        valid = (valid and value.get('host') == target['host']
                 and type(value.get('port')) is int and 1024 <= value['port'] <= 65535)
        if 'native_frontend_pid' in value:
            valid = (valid and type(value['native_frontend_pid']) is int
                     and value['native_frontend_pid'] > 0
                     and value['native_frontend_pid'] != value['daemon_pid'])
    if not valid:
        raise GatewayControlError('identity_mismatch')
    # Only this explicitly validated allowlist can become public status.
    return {name: list(value[name]) if isinstance(value[name], list) else value[name]
            for name in fields}


async def _provision(config):
    gateway, target = _settings(config, pinned=False)
    script = await _deploy(config)
    process = await _spawn(config, ['python3', '-B', script, '--state-dir',
                                    gateway['state_dir'], '--provision'])
    try:
        await _send(process, {'daemon_socket': gateway['daemon_socket'],
                              'bind_host': target['host']})
        process.stdin.close()
        descriptor = _descriptor(config, await _receive(process), serving=False)
        if await process.wait() != 0:
            raise RelayError('Remote gateway provisioning failed.')
        return descriptor
    finally:
        await _reap(process)


async def provision(config):
    """Deploy the exact helper package and discover its SSH-verified identity."""
    try:
        return await _bounded(_provision(config), STARTUP_TIMEOUT)
    except asyncio.CancelledError:
        raise
    except RelayError:
        raise
    except asyncio.TimeoutError:
        raise RelayError('Gateway provisioning timed out; the original remote service was not changed.') from None
    except Exception:
        raise RelayError('Cannot provision the private gateway through strict SSH authentication.') from None


class GatewayControl:
    """One SSH-owned remote frontend, with no direct-route fallback."""

    def __init__(self, config, directory):
        self.config = config
        self.directory = directory
        self.peer = None
        self.fingerprint = None
        self.key = None
        self.descriptor = None
        self.failure = None
        self.failure_reason = 'unknown'
        self.failure_recoverable = False
        self._process = None
        self._supervisor = None
        self._shutdown = None
        self._cleanup = None
        self._closing = False
        self._opened = False

    async def _open(self):
        gateway, target = _settings(self.config, pinned=True)
        script = await _deploy(self.config)
        self.key = secrets.token_bytes(32)
        self._process = await _spawn(self.config, [
            'python3', '-B', script, '--state-dir', gateway['state_dir'], '--serve'])
        await _send(self._process, {
            'daemon_socket': gateway['daemon_socket'], 'bind_host': target['host'],
            'session_key': base64.b64encode(self.key).decode('ascii')})
        descriptor = _descriptor(self.config, await _receive(self._process), serving=True)
        if self._process.returncode is not None:
            raise GatewayControlError('control_eof')
        self.peer = descriptor['host'], descriptor['port']
        self.fingerprint = descriptor['fingerprint']
        self.descriptor = descriptor
        self._supervisor = asyncio.create_task(self._supervise())
        return descriptor

    async def open(self):
        if self._opened or self._closing:
            raise GatewayControlError('protocol_error')
        self._opened = True
        self.failure = asyncio.get_running_loop().create_future()
        try:
            return await _bounded(self._open(), STARTUP_TIMEOUT)
        except asyncio.CancelledError:
            await self.close()
            raise
        except Exception as exc:
            await self.close()
            if isinstance(exc, GatewayControlError):
                if exc.reason == 'control_eof':
                    raise GatewayControlError('connectivity_uncertain') from None
                raise
            if isinstance(exc, asyncio.TimeoutError):
                raise GatewayControlError('connectivity_uncertain') from None
            if isinstance(exc, RelayError):
                raise GatewayControlError('security_error') from None
            raise GatewayControlError('unknown') from None

    async def _heartbeat(self):
        while not self._closing:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            if self._closing:
                return
            await _send(self._process, {'op': 'ping'})

    async def _observe(self):
        while not self._closing:
            try:
                value = await _bounded(_receive(self._process), HEARTBEAT_TIMEOUT)
            except asyncio.TimeoutError:
                raise GatewayControlError('heartbeat_timeout') from None
            if value != {'ok': True, 'op': 'pong'}:
                raise GatewayControlError('protocol_error')

    async def _supervise(self):
        tasks = [asyncio.create_task(self._heartbeat()), asyncio.create_task(self._observe())]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if not self._closing and not self.failure.done():
                causes = []
                for task in tasks:
                    if task in done:
                        error = None if task.cancelled() else task.exception()
                        causes.append(error if isinstance(error, GatewayControlError)
                                      else GatewayControlError('unknown'))
                # A simultaneous security/protocol failure always wins over a
                # transient cause. Never infer recoverability from exception text.
                cause = next((error for error in causes if not error.recoverable), causes[0])
                self.failure_reason = cause.reason
                self.failure_recoverable = cause.recoverable
                self.failure.set_result(str(cause) + ' The exclusive route is closed.')
        finally:
            # Python 3.9 wait_for can consume a cancellation racing with a
            # completed drain/read. Explicit state prevents another iteration.
            self._closing = True
            try:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                process, self._process = self._process, None
                self._shutdown = asyncio.create_task(_reap(process))
                await asyncio.shield(self._shutdown)

    async def close(self):
        # One cleanup owner: concurrent close/cancellation must not interrupt a
        # supervisor already cancelling its children or reaping its SSH process.
        if self._cleanup is None:
            self._cleanup = asyncio.create_task(self._close())
        try:
            await asyncio.shield(self._cleanup)
        except asyncio.CancelledError:
            await self._cleanup
            raise

    async def _close(self):
        was_closing = self._closing
        self._closing = True
        if self._supervisor is not None:
            supervisor, self._supervisor = self._supervisor, None
            if not was_closing and not supervisor.done():
                supervisor.cancel()
            await asyncio.gather(supervisor, return_exceptions=True)
        if self._shutdown is not None:
            await asyncio.shield(self._shutdown)
        process, self._process = self._process, None
        if process is not None:
            await _reap(process)
        self.key = None
        if self.failure is not None and not self.failure.done():
            self.failure.cancel()
