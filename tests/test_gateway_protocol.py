"""Wire contract regression tests; no network or remote daemon required."""
import unittest

from gateway_protocol import (
    CLIENT_TO_SERVER, SERVER_TO_CLIENT, MAX_PAYLOAD, ClientCodec,
    ReplayWindow, decode_frame, encode_frame,
)


class GatewayProtocolTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))

    def test_round_trip_and_direction_binding(self):
        frame = encode_frame(self.key, CLIENT_TO_SERVER, 4, 1, b'quic')
        self.assertEqual(decode_frame(self.key, CLIENT_TO_SERVER, frame), (4, 1, b'quic'))
        self.assertIsNone(decode_frame(self.key, SERVER_TO_CLIENT, frame))
        self.assertIsNone(decode_frame(b'x' * 32, CLIENT_TO_SERVER, frame))

    def test_tampering_truncation_and_raw_quic_are_rejected(self):
        frame = encode_frame(self.key, SERVER_TO_CLIENT, 4, 1, b'quic')
        for index in range(len(frame)):
            altered = bytearray(frame)
            altered[index] ^= 1
            self.assertIsNone(decode_frame(self.key, SERVER_TO_CLIENT, bytes(altered)))
        for end in range(len(frame)):
            self.assertIsNone(decode_frame(self.key, SERVER_TO_CLIENT, frame[:end]))
        self.assertIsNone(decode_frame(self.key, SERVER_TO_CLIENT, frame + b'x'))
        self.assertIsNone(decode_frame(self.key, SERVER_TO_CLIENT, b'raw-quic'))

    def test_payload_boundaries(self):
        for payload in (b'', b'x' * MAX_PAYLOAD):
            frame = encode_frame(self.key, CLIENT_TO_SERVER, 0, 1, payload)
            self.assertEqual(decode_frame(self.key, CLIENT_TO_SERVER, frame), (0, 1, payload))
        with self.assertRaises(ValueError):
            encode_frame(self.key, CLIENT_TO_SERVER, 0, 1, b'x' * (MAX_PAYLOAD + 1))

    def test_invalid_sequences(self):
        for sequence in (0, -1, 1 << 64, True):
            with self.assertRaises(ValueError):
                encode_frame(self.key, CLIENT_TO_SERVER, 0, sequence, b'x')
            self.assertFalse(ReplayWindow().accept(sequence))

    def test_replay_window_reordering_and_expiry(self):
        window = ReplayWindow()
        self.assertTrue(window.accept(2000))
        self.assertTrue(window.accept(1999))
        self.assertFalse(window.accept(1999))
        self.assertTrue(window.accept(977))
        self.assertFalse(window.accept(976))
        self.assertTrue(window.accept(4000))
        self.assertFalse(window.accept(2000))

    def test_client_flow_authentication_and_replay(self):
        codec = ClientCodec(self.key, flow_id=42)
        self.assertEqual(decode_frame(self.key, CLIENT_TO_SERVER, codec.encode(b'a')), (42, 1, b'a'))
        self.assertEqual(decode_frame(self.key, CLIENT_TO_SERVER, codec.encode(b'b')), (42, 2, b'b'))
        wrong_flow = encode_frame(self.key, SERVER_TO_CLIENT, 43, 1, b'wrong')
        self.assertIsNone(codec.decode(wrong_flow))
        reply = encode_frame(self.key, SERVER_TO_CLIENT, 42, 1, b'reply')
        self.assertEqual(codec.decode(reply), b'reply')
        self.assertIsNone(codec.decode(reply))
        for malformed in (None, 1, 'text', b'', bytearray(reply)):
            self.assertIsNone(codec.decode(malformed))


if __name__ == '__main__':
    unittest.main()
