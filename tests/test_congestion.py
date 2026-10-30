"""Consumer-visible UDP congestion recovery with a controlled TURN provider."""
import asyncio
from pathlib import Path
import socket
import tempfile
import time
import unittest

from types import SimpleNamespace
from relay import Service, LocalProtocol, MAX_FLOWS, MAX_PENDING_PACKETS, MAX_PENDING_BYTES
from relay_config import RelayError


class CongestionRecovery(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='ttr-congestion-test-')
        config = {
            'schema': 3, 'ssh_destination': 'test-ssh',
            'target': {'name': 'test', 'host': '1.1.1.1', 'port': 8376, 'user': 'tester',
                       'fingerprint': 'SHA256:' + 'A' * 43},
            'gateway': {'state_dir': '/home/tester/.tern-gateway',
                        'daemon_socket': '/run/user/1000/tern/daemon.sock',
                        'fingerprint': 'SHA256:' + 'A' * 42 + 'E'},
            'listen_port': 18379, 'credential_file': '/unused', 'dependency_dir': '/unused',
        }
        self.service = Service(config, Path(self.scratch.name), 'udp', 'controlled-provider')
        self.service.gateway = SimpleNamespace(failure=asyncio.get_running_loop().create_future())
        self.service.gateway_ready = True
        self.service.status.update(ok=True, state='ready')
        self.gate = asyncio.Event()
        self.sent = []
        gate, sent = self.gate, self.sent
        class Provider:
            expires = None
            async def open(self, entries, expires):
                pass
            async def send(self, data):
                await gate.wait()
                if data == b'provider-failure':
                    raise RelayError('Controlled TURN transport failure')
                sent.append(data)
            async def close(self):
                pass
        self.provider = Provider
        self.service.warm = Provider()
        async def credentials():
            return [], None
        self.service.credentials.get = credentials
        self.service.endpoint = lambda receive: Provider()
        self.transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: LocalProtocol(self.service), local_addr=('127.0.0.1', 0))
        self.service.local = self.transport
        self.address = self.transport.get_extra_info('sockname')
        self.clients = []

    def client(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(('127.0.0.1', 0))
        self.clients.append(client)
        return client

    async def until(self, predicate):
        deadline = time.monotonic() + 3
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail('UDP behavior did not settle before deadline')
            await asyncio.sleep(.001)

    async def asyncTearDown(self):
        self.transport.close()
        for client in self.clients:
            client.close()
        tasks = [flow.task for flow in list(self.service.flows.values())]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.scratch.cleanup()

    async def test_burst_drops_are_bounded_and_new_flow_works_after_drain(self):
        client = self.client()
        for sequence in range(MAX_PENDING_PACKETS * 3):
            client.sendto(sequence.to_bytes(4, 'big') + b'x' * 1196, self.address)
            await asyncio.sleep(.001)
        snapshot = self.service.snapshot()
        self.assertEqual(snapshot['state'], 'ready', 'A bounded UDP drop must not poison the service')
        self.assertGreater(snapshot['queue_dropped_packets'], 0)
        self.assertEqual(snapshot['queue_dropped_bytes'], snapshot['queue_dropped_packets'] * 1200)
        self.assertLessEqual(snapshot['queued_packets'], MAX_PENDING_PACKETS)
        self.assertLessEqual(snapshot['queued_bytes'], MAX_PENDING_BYTES)
        self.gate.set()
        await self.until(lambda: self.service.snapshot()['queued_packets'] == 0)
        self.client().sendto(b'recovered-new-flow', self.address)
        await self.until(lambda: b'recovered-new-flow' in self.sent)
        self.assertEqual(self.service.snapshot()['state'], 'ready')
        self.assertEqual(self.service.snapshot()['flows'], 2)
        self.assertIsNone(self.service.snapshot()['error'])

    async def test_provider_failure_is_not_downgraded_to_congestion(self):
        self.gate.set()
        self.client().sendto(b'provider-failure', self.address)
        await self.until(lambda: self.service.snapshot()['state'] == 'error')
        self.assertEqual(self.service.snapshot()['error'], 'Controlled TURN transport failure')
        self.assertFalse(self.service.snapshot()['ok'])

    async def test_flow_capacity_drops_new_packets_without_poisoning_existing_flows(self):
        self.gate.set()
        first = self.client()
        first.sendto(b'first-active', self.address)
        await self.until(lambda: b'first-active' in self.sent)
        for index in range(MAX_FLOWS - 1):
            self.client().sendto(b'fill-' + bytes([index]), self.address)
        await self.until(lambda: len(self.service.flows) == MAX_FLOWS)
        extra = self.client()
        extra.sendto(b'over-capacity', self.address)
        await asyncio.sleep(.02)
        self.assertEqual(self.service.snapshot()['state'], 'ready')
        self.assertEqual(len(self.service.flows), MAX_FLOWS)
        self.assertNotIn(b'over-capacity', self.sent)
        first.sendto(b'still-usable', self.address)
        await self.until(lambda: b'still-usable' in self.sent)
        retired = next(flow for address, flow in self.service.flows.items()
                       if address != first.getsockname())
        retired.task.cancel()
        await retired.task
        extra.sendto(b'capacity-recovered', self.address)
        await self.until(lambda: b'capacity-recovered' in self.sent)
        self.assertEqual(self.service.snapshot()['state'], 'ready')
