"""Authenticated, direction-bound UDP framing for the exclusive gateway.

The shared session key is delivered only through SSH stdin. Native QUIC is never
valid framing, and replay state is independent for each direction and flow.
"""
import hashlib
import hmac
import secrets
import struct

MAX_PAYLOAD = 65000
CLIENT_TO_SERVER = 1
SERVER_TO_CLIENT = 2
_MAGIC = b'TTRG'
_VERSION = 1
_HEADER = struct.Struct('!4sBBQQH')
_TAG_SIZE = 16
MAX_FRAME = _HEADER.size + MAX_PAYLOAD + _TAG_SIZE
_MAX_UINT64 = (1 << 64) - 1


def _valid_uint64(value, minimum=0):
    return type(value) is int and minimum <= value <= _MAX_UINT64


def encode_frame(key, direction, flow_id, sequence, payload):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('Gateway key must contain 32 bytes.')
    if type(direction) is not int or direction not in (CLIENT_TO_SERVER, SERVER_TO_CLIENT):
        raise ValueError('Invalid gateway direction.')
    if not _valid_uint64(flow_id) or not _valid_uint64(sequence, 1):
        raise ValueError('Invalid gateway flow or sequence.')
    if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD:
        raise ValueError('Invalid gateway payload.')
    body = _HEADER.pack(_MAGIC, _VERSION, direction, flow_id, sequence, len(payload)) + payload
    return body + hmac.new(key, body, hashlib.sha256).digest()[:_TAG_SIZE]


def decode_frame(key, direction, frame):
    if (not isinstance(key, bytes) or len(key) != 32
            or type(direction) is not int or direction not in (CLIENT_TO_SERVER, SERVER_TO_CLIENT)
            or not isinstance(frame, bytes)
            or not _HEADER.size + _TAG_SIZE <= len(frame) <= MAX_FRAME):
        return None
    magic, version, actual_direction, flow_id, sequence, size = _HEADER.unpack_from(frame)
    if (magic != _MAGIC or version != _VERSION or actual_direction != direction
            or sequence == 0 or size > MAX_PAYLOAD
            or len(frame) != _HEADER.size + size + _TAG_SIZE):
        return None
    body = frame[:-_TAG_SIZE]
    expected = hmac.new(key, body, hashlib.sha256).digest()[:_TAG_SIZE]
    if not hmac.compare_digest(expected, frame[-_TAG_SIZE:]):
        return None
    return flow_id, sequence, frame[_HEADER.size:-_TAG_SIZE]


class ReplayWindow:
    """Fixed-memory sliding window accepting up to 1024 reordered packets."""

    def __init__(self):
        self.highest = 0
        self._seen = 0

    def accept(self, sequence):
        if not _valid_uint64(sequence, 1):
            return False
        if sequence > self.highest:
            distance = sequence - self.highest
            self._seen = 0 if distance >= 1024 else (self._seen << distance) & ((1 << 1024) - 1)
            self._seen |= 1
            self.highest = sequence
            return True
        distance = self.highest - sequence
        if distance >= 1024 or self._seen & (1 << distance):
            return False
        self._seen |= 1 << distance
        return True


class ClientCodec:
    """One client flow; authenticated receive state never advances on rejection."""

    def __init__(self, key, flow_id=None):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError('Gateway key must contain 32 bytes.')
        if flow_id is None:
            flow_id = secrets.randbits(64)
        if not _valid_uint64(flow_id):
            raise ValueError('Invalid gateway flow.')
        self._key = key
        self.flow_id = flow_id
        self._sequence = 0
        self._replay = ReplayWindow()

    def encode(self, payload):
        sequence = self._sequence + 1
        frame = encode_frame(self._key, CLIENT_TO_SERVER, self.flow_id, sequence, payload)
        self._sequence = sequence
        return frame

    def decode(self, frame):
        decoded = decode_frame(self._key, SERVER_TO_CLIENT, frame)
        if decoded is None:
            return None
        flow_id, sequence, payload = decoded
        if flow_id != self.flow_id or not self._replay.accept(sequence):
            return None
        return payload
