import binascii
import io
import os
import unittest.mock as mock

from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa import NIST256p, VerifyingKey, SigningKey
from ecdsa.ecdsa import Public_key, Private_key
from ecdsa.ellipticcurve import Point
import pytest

from confidentiality import exchange, _write_ecc_public_key


def _exchange(stream, queue):
    queue.put(exchange(stream))


def vectors():
    path = os.path.join(os.path.dirname(__file__), '..', '..',
                        'testdata', 'exchange_test.txt')

    tests = []
    with open(path) as handle:
        for line in handle:
            if line.strip() == '' or line.startswith('#'):
                continue

            line = line.strip()
            tests.append(list(map(binascii.unhexlify, line.split(':'))))
            break

    return tests


class MockStream:
    def __init__(self, buffer):
        self.w = io.BytesIO()
        self.r = buffer

    def read(self, size=None):
        data = self.r.read(size)
        return data

    def write(self, data):
        self.w.write(data)


@pytest.mark.parametrize('vector', vectors())
def test_exchange(vector):
    r1, d1, x1, y1, r2, d2, x2, y2, wanted = vector


    def _import(d, x, y):
        public_key = Public_key(NIST256p.generator, Point(
            curve=NIST256p.curve,
            x=bytes_to_long(x),
            y=bytes_to_long(y),
        ))
        private_key = Private_key(public_key, bytes_to_long(d))
        return private_key


    def _mock_signingkey_generate(*args, **kwargs):
        key = SigningKey(True)
        key.privkey = _import(d2, x2, y2)
        key.verifying_key = VerifyingKey.from_public_point(key.privkey.public_key.point, NIST256p)
        return key


    with mock.patch('ecdsa.SigningKey.generate', _mock_signingkey_generate):
        # Generate ECDSA key and write it to wire format to our stream
        private_key = _import(d1, x1, y1)
        public_key = private_key.public_key
        point = public_key.point
        assert long_to_bytes(point.x()) == x1
        assert long_to_bytes(point.y()) == y1

        # Write our first public key to the wire
        buffer = io.BytesIO()
        _write_ecc_public_key(buffer, public_key)
        assert len(buffer.getvalue()) == 65

        # Stream contains our wire format key
        stream = MockStream(io.BytesIO(buffer.getvalue()))
        shared = exchange(stream)
        assert shared, 'no key was returned by exchange()'
        assert shared == wanted