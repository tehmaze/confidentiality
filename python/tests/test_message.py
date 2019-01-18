import binascii
import collections
import os

from Crypto.Random import get_random_bytes
import pytest

import confidentiality


def vectors():
    path = os.path.join(os.path.dirname(__file__), '..', '..', 
                        'testdata', 'message_test.txt')

    tests = []
    with open(path) as handle:
        for line in handle:
            if line.strip() == '' or line.startswith('#'):
                continue
            
            tests.append(list(map(binascii.unhexlify, line.strip().split(':')[1:])))
    
    return tests


@pytest.mark.parametrize('vector', vectors())
def test_encrypt(vector):
    # Decode vectors
    k, iv, p, e = vector

    # Monkey patch the random reader to read our test iv.
    confidentiality._get_random_bytes = lambda n: iv[:n]

    encrypted = confidentiality.encrypt(p, k)
    assert encrypted == (iv + e)


@pytest.mark.parametrize('vector', vectors())
def test_decrypt(vector):
    # Decode vectors
    k, iv, p, e = vector

    decrypted = confidentiality.decrypt(iv + e, k)
    assert decrypted == p