import binascii
import io
import os
import unittest.mock as mock

from Crypto.Util.number import bytes_to_long, long_to_bytes
import donna25519
import pytest

from confidentiality import exchange, _write_public_key


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
    _, k1b, p1b, _, k2b, _, wanted = vector

    k1 = donna25519.PrivateKey.load(k1b)
    k2 = donna25519.PrivateKey.load(k2b)
    
    def _mock_private_key(*args, **kwargs):
        return k2

    with mock.patch('donna25519.PrivateKey', _mock_private_key):
        # Generate key and write it to wire format to our stream
        private_key = k1
        public_key = private_key.get_public()
        assert public_key.public == p1b
        
        # Write our first public key to the wire
        buffer = io.BytesIO()
        _write_public_key(buffer, public_key)
        assert len(buffer.getvalue()) == 33

        # Stream contains our wire format key
        stream = MockStream(io.BytesIO(buffer.getvalue()))
        shared = exchange(stream)
        assert shared, 'no key was returned by exchange()'
        assert shared == wanted