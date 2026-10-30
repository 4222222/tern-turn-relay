"""Resolve a direct SSH endpoint and forward bytes without handling SSH authentication."""
import asyncio
import os
import re
import signal
import socket

from relay_config import RelayError, validate_ssh_destination

SSH_CONFIG_TIMEOUT = 5
SSH_CONNECT_TIMEOUT = 10
MAX_SSH_CONNECTIONS = 16
STREAM_LIMIT = 64 * 1024


async def resolve_ssh_destination(config):
    """Evaluate the user's SSH config, but never run its ProxyCommand/ProxyJump."""
    destination = validate_ssh_destination(config['ssh_destination'])
    try:
        process = await asyncio.create_subprocess_exec(
            '/usr/bin/ssh', '-G', destination,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
    except OSError:
        raise RelayError('Cannot run /usr/bin/ssh -G to resolve ssh_destination.') from None
    try:
        output, _ = await asyncio.wait_for(process.communicate(), SSH_CONFIG_TIMEOUT)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        # Match exec can leave children holding stdout open even after ssh exits.
        # The resolver owns this session; never signal the caller's process group.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.communicate(), 1)
        except asyncio.TimeoutError:
            pass
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise RelayError('SSH configuration resolution timed out; check the local SSH Host alias.') from None
    if process.returncode != 0 or len(output) > 1024 * 1024:
        raise RelayError('SSH configuration resolution failed; check the local SSH Host alias.')
    try:
        text = output.decode('utf-8')
    except UnicodeError:
        raise RelayError('SSH configuration resolution returned invalid text.') from None
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(' ')
        if key in ('hostname', 'user', 'port', 'proxyjump', 'proxycommand'):
            if not separator or key in fields:
                raise RelayError('SSH configuration resolution returned ambiguous endpoint settings.')
            fields[key] = value.strip()
    if any(fields.get(key, 'none').lower() != 'none' for key in ('proxyjump', 'proxycommand')):
        raise RelayError('SSH ProxyJump/ProxyCommand is not supported: the loopback relay only forwards directly to the verified target. No proxy command was executed; use a direct SSH Host alias.')
    target = config['target']
    if fields.get('hostname') != target['host'] or fields.get('user') != target['user']:
        raise RelayError('Resolved SSH HostName/User does not match the configured target host/user; refusing to forward SSH to a different endpoint.')
    port = fields.get('port', '')
    if not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
        raise RelayError('Resolved SSH Port must be numeric and in 1..65535.')
    return {'host': fields['hostname'], 'port': int(port), 'user': fields['user']}


class SshForwarder:
    """Bounded loopback TCP forwarding with backpressure and independent half-closes."""

    def __init__(self, fail, changed, accepting):
        self.fail, self.changed, self.accepting = fail, changed, accepting
        self.server = None
        self.endpoint = None
        self.tasks = {}
        self.closing = False

    @property
    def connections(self):
        return len(self.tasks)

    async def open(self, listen_port, endpoint):
        self.endpoint = dict(endpoint)
        self.server = await asyncio.start_server(
            self.accept, '127.0.0.1', listen_port, family=socket.AF_INET,
            limit=STREAM_LIMIT)

    def accept(self, reader, writer):
        peer = writer.get_extra_info('peername')
        if self.closing or not self.accepting() or not peer or peer[0] != '127.0.0.1':
            writer.transport.abort()
            return
        if self.connections >= MAX_SSH_CONNECTIONS:
            writer.transport.abort()
            self.fail('Concurrent SSH connection limit reached; disconnect unused SSH sessions and reconnect.')
            return
        # Reserve synchronously before the connection coroutine can run.
        task = asyncio.create_task(self.forward(reader, writer))
        self.tasks[task] = writer
        task.add_done_callback(self.finished)
        self.changed()

    def finished(self, task):
        # Also covers cancellation before forward() executes its first line.
        writer = self.tasks.pop(task, None)
        if writer is not None:
            writer.transport.abort()
        self.changed()

    @staticmethod
    async def pump(reader, writer):
        while True:
            data = await reader.read(STREAM_LIMIT)
            if not data:
                # A FIN in one direction must not discard the other direction.
                writer.write_eof()
                await writer.drain()
                return
            writer.write(data)
            await writer.drain()

    async def forward(self, reader, writer):
        upstream = None
        pumps = []
        try:
            remote_reader, upstream = await asyncio.wait_for(
                asyncio.open_connection(self.endpoint['host'], self.endpoint['port'],
                                        family=socket.AF_INET, limit=STREAM_LIMIT),
                SSH_CONNECT_TIMEOUT)
            pumps = [asyncio.create_task(self.pump(reader, upstream)),
                     asyncio.create_task(self.pump(remote_reader, writer))]
            await asyncio.gather(*pumps)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            self.fail('Connecting to the original SSH endpoint timed out; no SSH authentication or direct TURN fallback was attempted.')
        except Exception:
            self.fail('Raw SSH forwarding failed; check the original SSH endpoint and reconnect. SSH credentials are handled only by the SSH client.')
        finally:
            for task in pumps:
                if not task.done():
                    task.cancel()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            writers = [writer] + ([upstream] if upstream is not None else [])
            for stream in writers:
                stream.close()
            await asyncio.gather(*(self.close_writer(stream) for stream in writers))

    @staticmethod
    async def close_writer(writer):
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (Exception, asyncio.CancelledError):
            writer.transport.abort()

    async def close(self):
        self.closing = True
        if self.server is not None:
            self.server.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for task in list(self.tasks):
            self.finished(task)
        if self.server is not None:
            await self.server.wait_closed()
            self.server = None
