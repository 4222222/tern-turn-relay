"""Cloudflare credential cache and explicitly owned aioice TURN allocations."""
import asyncio
import importlib.metadata
import logging
from pathlib import Path
import socket
import ssl
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

from relay_config import RelayError
from credentials import CredentialError, load_management_key, issue_turn_credentials
from gateway_protocol import ClientCodec

API_TIMEOUT = 12
ALLOCATION_TIMEOUT = 18
CREDENTIAL_TTL = 86400


def load_aioice(directory):
    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise RelayError('dependency_dir is not a directory.')
    distributions = list(importlib.metadata.distributions(path=[str(root)]))
    versions = [item.version for item in distributions if item.metadata['Name'].lower() == 'aioice']
    if versions != ['0.10.2']:
        raise RelayError('dependency_dir must contain exactly aioice 0.10.2.')
    sys.path.insert(0, str(root))
    from aioice import turn
    if root not in Path(turn.__file__).resolve().parents:
        raise RelayError('aioice was imported outside the configured dependency_dir.')
    logging.getLogger('aioice').disabled = True
    logging.getLogger('aioice.turn').disabled = True
    logging.getLogger('aioice.stun').disabled = True
    return turn


class TransientTurnError(RelayError):
    """A network failure eligible for bounded allocation retries, never bypass."""


def fetch_credentials(path):
    try:
        return issue_turn_credentials(load_management_key(path), ttl=CREDENTIAL_TTL)
    except CredentialError as exc:
        raise RelayError(str(exc)) from None


def select_turn(entries, mode):
    candidates = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        urls = entry.get('urls', [])
        if isinstance(urls, str):
            urls = [urls]
        if not isinstance(urls, list):
            continue
        for url in urls:
            if not isinstance(url, str):
                continue
            try:
                scheme, rest = url.split(':', 1)
                if scheme not in ('turn', 'turns') or rest.startswith('//'):
                    continue
                parsed = urlsplit(scheme + '://' + rest)
                query = parse_qs(parsed.query, strict_parsing=True)
                wire = query.get('transport', ['tcp' if scheme == 'turns' else 'udp'])
                if set(query) - {'transport'} or parsed.username or parsed.password or parsed.path or parsed.fragment or not parsed.hostname:
                    continue
                if mode == 'tls' and (scheme != 'turns' or wire != ['tcp']):
                    continue
                if mode == 'udp' and (scheme != 'turn' or wire != ['udp']):
                    continue
                port = parsed.port or (5349 if scheme == 'turns' else 3478)
                username, password = entry.get('username'), entry.get('credential')
                if not 1 <= port <= 65535 or not isinstance(username, str) or not username or not isinstance(password, str) or not password:
                    continue
                if entry.get('credentialType', 'password') != 'password':
                    continue
                candidates.append((port != 443, parsed.hostname, port, username, password))
            except (ValueError, TypeError):
                continue
    if not candidates:
        raise RelayError('Credential API returned no genuine matching TURN URL for the requested mode.')
    return sorted(candidates, key=lambda item: item[0])[0][1:]


async def bounded_fetch(path):
    """A blocked system resolver cannot prevent the daemon's shutdown."""
    loop = asyncio.get_running_loop()
    result = loop.create_future()

    def complete(value, error):
        if not result.done():
            if error:
                result.set_exception(error)
            else:
                result.set_result(value)

    def worker():
        try:
            value, error = fetch_credentials(path), None
        except RelayError as exc:
            value, error = None, exc
        except Exception:
            value, error = None, RelayError('Credential retrieval failed.')
        try:
            loop.call_soon_threadsafe(complete, value, error)
        except RuntimeError:
            pass

    threading.Thread(target=worker, name='turn-credentials', daemon=True).start()
    try:
        return await asyncio.wait_for(result, API_TIMEOUT + 2)
    except asyncio.TimeoutError:
        raise RelayError('Credential API timed out.') from None


class CredentialCache:
    def __init__(self, path):
        self.path = path
        self.entries = None
        self.expires = None
        self.retry_at = 0.0
        self.lock = asyncio.Lock()

    async def get(self, renew=False):
        async with self.lock:
            now = time.time()
            if self.entries and self.expires > now + (300 if renew else 60):
                return self.entries, self.expires
            if time.monotonic() < self.retry_at:
                if self.entries and self.expires > now + 60:
                    return self.entries, self.expires
                raise RelayError('Credential retry is cooling down; reconnect after one minute.')
            try:
                self.entries, self.expires = await bounded_fetch(self.path)
            except (RelayError, asyncio.CancelledError):
                self.retry_at = time.monotonic() + 60
                raise
            return self.entries, self.expires


class Endpoint(asyncio.DatagramProtocol):
    def __init__(self, turn, mode, peer, receive, codec):
        if not isinstance(codec, ClientCodec):
            raise RelayError('An authenticated gateway codec is required for every TURN flow.')
        self.turn, self.mode, self.peer, self.receive = turn, mode, peer, receive
        self.codec = codec
        self.inner = None
        self.native = None
        self.transport = None
        self.expires = None
        self.failure = asyncio.get_running_loop().create_future()
        self.closed = asyncio.get_running_loop().create_future()
        self.closing = False
        self.writable = asyncio.Event()
        self.writable.set()

    def fail(self, message):
        if not self.closing and not self.failure.done():
            self.failure.set_result(message)
            self.writable.set()

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        if not self.closed.done():
            self.closed.set_result(None)
        self.fail('TURN connection closed; disconnect and reconnect to recover.')

    def datagram_received(self, data, addr):
        if addr == self.peer and not self.closing and not self.failure.done():
            payload = self.codec.decode(data)
            if payload is not None:
                self.receive(payload)

    def error_received(self, exc):
        self.fail('TURN socket reported an asynchronous transport error.')

    async def open(self, entries, expires):
        self.expires = expires
        host, port, username, password = select_turn(entries, self.mode)
        turn, endpoint = self.turn, self
        original = turn.TurnClientTcpProtocol if self.mode == 'tls' else turn.TurnClientUdpProtocol

        class OwnedProtocol(original):
            def connection_made(self, transport):
                endpoint.native = transport
                super().connection_made(transport)
                if endpoint.mode == 'tls':
                    transport.set_write_buffer_limits(high=256 * 1024, low=64 * 1024)

            def pause_writing(self):
                endpoint.writable.clear()

            def resume_writing(self):
                endpoint.writable.set()

            async def channel_bind(self, channel_number, addr):
                # Bound only actual network transactions, not every warm packet.
                await asyncio.wait_for(super().channel_bind(channel_number, addr), ALLOCATION_TIMEOUT)

            def connection_lost(self, exc):
                super().connection_lost(exc)
                endpoint.connection_lost(exc)

            def error_received(self, exc):
                endpoint.error_received(exc)

            async def refresh(self, lifetime):
                try:
                    while True:
                        if not isinstance(lifetime, int) or lifetime <= 0:
                            raise RelayError('TURN server expired an allocation.')
                        await asyncio.sleep(lifetime * 5 / 6)
                        request = turn.stun.Message(message_method=turn.stun.Method.REFRESH,
                                                    message_class=turn.stun.Class.REQUEST)
                        request.attributes['LIFETIME'] = self.lifetime
                        response, _ = await asyncio.wait_for(self.request_with_retry(request), min(18, lifetime / 12))
                        lifetime = response.attributes['LIFETIME']
                except asyncio.CancelledError:
                    raise
                except Exception:
                    endpoint.fail('TURN allocation refresh failed; disconnect and reconnect to recover.')

        self.inner = OwnedProtocol((host, port), username=username, password=password,
                                   lifetime=120, channel_refresh_time=90)
        loop = asyncio.get_running_loop()
        try:
            async def allocate():
                if self.mode == 'tls':
                    await loop.create_connection(lambda: self.inner, host=host, port=port,
                                                 ssl=ssl.create_default_context(), server_hostname=host)
                else:
                    await loop.create_datagram_endpoint(lambda: self.inner, remote_addr=(host, port), family=socket.AF_INET)
                    self.native.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                # Construct directly rather than monkey-patching shared aioice
                # globals: concurrent flow allocations must not steal ownership.
                transport = turn.TurnTransport(self.inner)
                await transport._connect(self)
                if self.failure.done():
                    raise RelayError(self.failure.result())
            await asyncio.wait_for(allocate(), ALLOCATION_TIMEOUT)
        except asyncio.CancelledError:
            await self.close()
            raise
        except Exception as exc:
            await self.close()
            if isinstance(exc, ssl.SSLError):
                raise RelayError('TURN TLS verification or handshake failed; no direct fallback was attempted.') from None
            if isinstance(exc, (asyncio.TimeoutError, OSError, self.turn.stun.TransactionTimeout)):
                raise TransientTurnError('TURN network allocation failed or timed out; no direct fallback was attempted.') from None
            raise RelayError('TURN allocation was rejected or failed; check provider authorization and quota. No direct fallback was attempted.') from None

    async def send(self, data):
        if self.closing:
            raise RelayError('TURN endpoint is closed; no packet was sent.')
        if self.failure.done():
            raise RelayError(self.failure.result())
        if time.time() >= self.expires - 15:
            raise RelayError('TURN credentials expired; reconnect to establish a new allocation.')
        try:
            if not self.writable.is_set():
                await asyncio.wait_for(self.writable.wait(), ALLOCATION_TIMEOUT)
                if self.failure.done():
                    raise RelayError(self.failure.result())
            if self.closing:
                raise RelayError('TURN endpoint is closed; no packet was sent.')
            await self.inner.send_data(self.codec.encode(data), self.peer)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RelayError('TURN send or channel binding failed; reconnect to recover.') from None
        if self.failure.done():
            raise RelayError(self.failure.result())

    async def close(self):
        if self.closing:
            return
        self.closing = True
        self.writable.set()
        refresh = self.inner.refresh_task if self.inner else None
        if refresh:
            refresh.cancel()
        try:
            if self.inner and self.native and not self.native.is_closing():
                try:
                    await asyncio.wait_for(self.inner.delete(), 2)
                except (Exception, asyncio.CancelledError):
                    pass
        finally:
            if refresh:
                await asyncio.gather(refresh, return_exceptions=True)
            if self.native:
                self.native.close()
                try:
                    await asyncio.wait_for(asyncio.shield(self.closed), 1)
                except asyncio.TimeoutError:
                    if hasattr(self.native, 'abort'):
                        self.native.abort()
