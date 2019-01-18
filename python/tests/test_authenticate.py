import binascii
import collections
import os

from Crypto.Random import get_random_bytes
import pytest

import confidentiality


def vectors():
    path = os.path.join(os.path.dirname(__file__), '..', '..', 
                        'testdata', 'authenticate_test.txt')

    tests = []
    with open(path) as handle:
        for line in handle:
            if line.strip() == '' or line.startswith('#'):
                continue
            
            print(line)
            tests.append(list(map(binascii.unhexlify, line.strip().split(':'))))
    
    return tests


@pytest.mark.parametrize('vector', vectors())
def test_sign(vector):
    (key, message, digest) = vector
    assert confidentiality.sign(message, key) == message + digest


@pytest.mark.parametrize('vector', vectors())
def test_verify(vector):
    (key, message, digest) = vector
    assert confidentiality.verify(message + digest, key)