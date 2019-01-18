import binascii
import collections
import io
import os

from Crypto.Random import get_random_bytes
import pytest

import confidentiality


def vectors():
    path = os.path.join(os.path.dirname(__file__), '..', '..', 
                        'testdata', 'stream_test.txt')

    tests = []
    with open(path) as handle:
        for line in handle:
            if line.strip() == '' or line.startswith('#'):
                continue
            
            tests.append(list(map(binascii.unhexlify, line.strip().split(':')[1:])))
    
    return tests


@pytest.mark.parametrize('vector', vectors())
def test_encrypter(vector):
    # Decode vectors
    k, iv, p, e = vector

    # Monkey patch the random reader to read our test iv.
    iv_bytes = io.BytesIO(iv)

    #def _read_iv_bytes(n):
    #    data = iv_bytes.read(n)
    #    print('_read_iv_bytes', n, data)
    #    return data

    confidentiality._get_random_bytes = lambda n: iv_bytes.read(n)
    #confidentiality._get_random_bytes = _read_iv_bytes

    buffer = io.BytesIO()
    stream = confidentiality.Encrypter(buffer, k)
    stream.write(p)

    assert buffer.getvalue() == e


@pytest.mark.parametrize('vector', vectors())
def test_decrypter(vector):
    # Decode vectors
    k, iv, p, e = vector

    # Monkey patch the random reader to read our test iv.
    iv_bytes = io.BytesIO(iv)
    confidentiality._get_random_bytes = lambda n: iv_bytes.read(n)
    
    buffer = io.BytesIO(e)
    stream = confidentiality.Decrypter(buffer, k)
    output = stream.read()

    assert output == p
