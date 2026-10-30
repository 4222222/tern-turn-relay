"""Bounded retry of transient TURN allocation failure without a direct route."""
import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from relay import Service
from relay_config import RelayError


class AllocationRecovery(unittest.IsolatedAsyncioTestCase):
    async def test_transient_allocation_retries_a_fresh_endpoint_then_forwards(self):
        import relay_transport
        transient = getattr(relay_transport, 'TransientTurnError', RelayError)
        service = Service({'credential_file': '/unused', 'target': {'name': 'test', 'host': '1.1.1.1', 'port': 8376, 'user': 'test', 'fingerprint': 'original'}, 'gateway': {'fingerprint': 'dedicated', 'daemon_socket': '/run/test.sock'}, 'listen_port': 18377, 'ssh_destination': 'example'}, Path('/unused'), 'tls', 'test')
        endpoints = []
        received = []
        class Endpoint:
            def __init__(self, receive):
                self.receive = receive
                self.closed = False
                endpoints.append(self)
            async def open(self, entries, expires):
                if len(endpoints) < 3:
                    raise transient('TURN allocation timed out')
            async def close(self):
                self.closed = True
            async def send(self, data):
                self.receive(data)
        service.endpoint = Endpoint
        with patch('relay.ALLOCATION_RETRY_DELAYS', (0, 0), create=True):
            endpoint = await service.open_endpoint(received.append, [], 9999999999)
        await endpoint.send(b'recovered payload')
        self.assertEqual(received, [b'recovered payload'])
        self.assertEqual(len(endpoints), 3)
        self.assertTrue(all(e.closed for e in endpoints[:-1]))
        self.assertFalse(endpoint.closed)

    async def test_security_failure_is_not_retried(self):
        service = object.__new__(Service)
        service.stopping = asyncio.Event()
        calls = []
        class Endpoint:
            async def open(self, entries, expires):
                calls.append('open')
                raise RelayError('TLS verification failed')
            async def close(self):
                calls.append('close')
        service.endpoint = lambda receive: Endpoint()
        with self.assertRaises(RelayError):
            await service.open_endpoint(lambda data: None, [], 1)
        self.assertEqual(calls, ['open', 'close'])


if __name__ == '__main__':
    unittest.main()
