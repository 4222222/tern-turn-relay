"""Authenticated Endpoint payloads retain TURN backpressure and inner counters."""
import asyncio
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from gateway_protocol import ClientCodec, CLIENT_TO_SERVER, SERVER_TO_CLIENT, encode_frame, decode_frame
from relay_config import RelayError
from relay_transport import Endpoint


class AuthenticatedEndpoint(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.key = b'k' * 32
        self.peer = ('1.1.1.1', 42817)
        self.received = []
        self.endpoint = Endpoint(None, 'tls', self.peer, self.received.append,
                                 ClientCodec(self.key, flow_id=7))
        self.endpoint.expires = int(time.time()) + 3600
        self.endpoint.inner = SimpleNamespace(send_data=AsyncMock(), refresh_task=None)

    async def test_every_endpoint_requires_a_real_codec(self):
        with self.assertRaises(TypeError):
            Endpoint(None, 'udp', self.peer, self.received.append)
        with self.assertRaises(RelayError):
            Endpoint(None, 'udp', self.peer, self.received.append, None)

    async def test_send_wraps_payload_and_never_uses_original_target(self):
        await self.endpoint.send(b'native-inner-payload')
        frame, peer = self.endpoint.inner.send_data.await_args.args
        self.assertEqual(peer, self.peer)
        self.assertNotEqual(frame, b'native-inner-payload')
        self.assertEqual(decode_frame(self.key, CLIENT_TO_SERVER, frame),
                         (7, 1, b'native-inner-payload'))
        await self.endpoint.send(b'second')
        frame, _ = self.endpoint.inner.send_data.await_args.args
        self.assertEqual(decode_frame(self.key, CLIENT_TO_SERVER, frame), (7, 2, b'second'))

    async def test_receive_rejects_raw_wrong_peer_flow_direction_key_and_replay(self):
        valid = encode_frame(self.key, SERVER_TO_CLIENT, 7, 1, b'inner')
        for frame, peer in (
                (b'raw-native-quic', self.peer),
                (valid, ('1.1.1.1', 8376)),
                (encode_frame(self.key, SERVER_TO_CLIENT, 8, 1, b'wrong-flow'), self.peer),
                (encode_frame(self.key, CLIENT_TO_SERVER, 7, 1, b'wrong-direction'), self.peer),
                (encode_frame(b'x' * 32, SERVER_TO_CLIENT, 7, 1, b'wrong-key'), self.peer),
                (valid[:-1], self.peer)):
            self.endpoint.datagram_received(frame, peer)
        self.assertEqual(self.received, [])
        self.endpoint.datagram_received(valid, self.peer)
        self.endpoint.datagram_received(valid, self.peer)
        self.assertEqual(self.received, [b'inner'])
        self.endpoint.fail('gateway closed')
        self.endpoint.datagram_received(encode_frame(self.key, SERVER_TO_CLIENT, 7, 2, b'late'), self.peer)
        self.assertEqual(self.received, [b'inner'])

    async def test_tls_backpressure_delays_encoding_and_actual_send(self):
        self.endpoint.writable.clear()
        task = asyncio.create_task(self.endpoint.send(b'pending'))
        await asyncio.sleep(0)
        self.endpoint.inner.send_data.assert_not_awaited()
        self.endpoint.writable.set()
        await task
        frame, _ = self.endpoint.inner.send_data.await_args.args
        self.assertEqual(decode_frame(self.key, CLIENT_TO_SERVER, frame), (7, 1, b'pending'))

    async def test_failure_wakes_backpressure_without_sending(self):
        self.endpoint.writable.clear()
        task = asyncio.create_task(self.endpoint.send(b'never-send'))
        await asyncio.sleep(0)
        self.endpoint.fail('gateway closed')
        with self.assertRaises(RelayError):
            await task
        self.endpoint.inner.send_data.assert_not_awaited()

    async def test_closed_endpoint_never_sends(self):
        await self.endpoint.close()
        with self.assertRaises(RelayError):
            await self.endpoint.send(b'never-send')
        self.endpoint.inner.send_data.assert_not_awaited()


if __name__ == '__main__':
    unittest.main()
