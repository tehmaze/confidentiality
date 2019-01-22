import struct
import time
import warnings

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long, long_to_bytes
import donna25519


#: Constants
_ECC_CURVE_TYPE = 0x19
_AES_BLOCK_SIZE = 16
_GCM_NONCE_SIZE = 12
_GCM_TAG_SIZE = 16


def _get_random_bytes(n):
    return get_random_bytes(n)


def exchange(stream):
    '''Exchange an ephemeral session key.'''

    # Generate an emphemeral ECDSA NIST P-256 private key
    private_key = donna25519.PrivateKey()
    public_key = private_key.get_public()
    
    # Write the public part on the wire
    _write_public_key(stream, public_key)

    # Read peer's public key from the wire
    peers_public_key = _read_public_key(stream)

    # Compute the scalar product of our private key with peer's
    shared_point = private_key.do_exchange(peers_public_key)

    # public key as our shared key.
    return shared_point


def _read_public_key(stream):
    bytes_length = 33
    block = b''
    while len(block) == 0:
        block += stream.read(bytes_length)
        if len(block) == 0:
            time.sleep(0.1)

    return _unmarshal_public_key(block)


def _write_public_key(stream, key):
    assert isinstance(key, donna25519.PublicKey)
    stream.write(bytearray([_ECC_CURVE_TYPE]) + key.public)


def _marshal_public_key(key):
    assert isinstance(key, donna25519.PublicKey)
    return bytearray([_ECC_CURVE_TYPE]) + key.public


def _unmarshal_public_key(marshaled):
    if marshaled[0] != _ECC_CURVE_TYPE:
        raise ValueError('Unsupported curve type {!02x}'.format(marshaled[0]))

    if len(marshaled[1:]) != 32:
        raise ValueError('Expected 32 ECC point bytes, got {}'.format(
                    len(marshaled[1:])))

    return donna25519.PublicKey(marshaled[1:])


def encrypt(message, key):
    '''Encrypt a message.'''

    # Generate a random nonce.
    nonce = _get_random_bytes(_GCM_NONCE_SIZE)

    # Load the AES key.
    aead = AES.new(key, AES.MODE_GCM, nonce)

    # Encrypt the message.
    ciphertext, tag = aead.encrypt_and_digest(message)

    return nonce + ciphertext + tag


def decrypt(message, key):
    '''Decrypt a message.'''

    # Split the nonce, message and ciphertext
    nonce, remainder = message[:_GCM_NONCE_SIZE], message[_GCM_NONCE_SIZE:]
    ciphertext, tag = remainder[:-_GCM_TAG_SIZE], remainder[-_GCM_TAG_SIZE:]

    # Load the AES key.
    aead = AES.new(key, AES.MODE_GCM, nonce=nonce)

    return aead.decrypt_and_verify(ciphertext, tag)


class Encrypter:
    '''Encrypt a stream.'''

    def __init__(self, stream, key):
        self.stream = stream

        # Generate IV
        iv = _get_random_bytes(_AES_BLOCK_SIZE)

        # Generate nonce
        nonce = _get_random_bytes(_GCM_NONCE_SIZE)

        # Write encrypted IV
        aead = AES.new(key, AES.MODE_GCM, nonce=nonce)
        encrypted_iv, tag = aead.encrypt_and_digest(iv)
        self.stream.write(nonce + encrypted_iv + tag)

        # Switch to AES-CBC mode
        ctr = Counter.new(128, initial_value=bytes_to_long(iv))
        self.cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    def send(self, data):
        self.stream.send(self.cipher.encrypt(data))

    def write(self, data):
        self.stream.write(self.cipher.encrypt(data))


class Decrypter:
    '''Decrypt a stream.'''

    def __init__(self, stream, key):
        self.stream = stream

        # Read nonce and encrypted IV
        nonce_and_encrypted_iv_size = _GCM_NONCE_SIZE + _AES_BLOCK_SIZE + _GCM_TAG_SIZE
        nonce_and_encrypted_iv = self.stream.read(nonce_and_encrypted_iv_size)
        nonce = nonce_and_encrypted_iv[:_GCM_NONCE_SIZE]
        encrypted_iv = nonce_and_encrypted_iv[_GCM_NONCE_SIZE:]
        encrypted_iv = encrypted_iv[:-_GCM_TAG_SIZE]
        tag = nonce_and_encrypted_iv[-_GCM_TAG_SIZE:]

        # Decrypt IV
        aead = AES.new(key, AES.MODE_GCM, nonce=nonce)
        iv = aead.decrypt_and_verify(encrypted_iv, tag)

        # Switch to AES-CBC mode
        ctr = Counter.new(128, initial_value=bytes_to_long(iv))
        self.cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    def read(self, size=None):
        encrypted = self.stream.read(size)
        return self.cipher.decrypt(encrypted)

    def recv(self, size=None):
        encrypted = self.stream.recv(size)
        return self.cipher.decrypt(encrypted)


class Secure:
    '''Secure a stream with an ephemeral session key.'''

    def __init__(self, stream):
        session_key = exchange(stream)
        self.reader = Decrypter(stream, session_key)
        self.writer = Encrypter(stream, session_key)

    def read(self, size=None):
        return self.reader.read(size)

    def recv(self, size=None):
        return self.reader.recv(size)

    def send(self, data):
        self.writer.send(data)

    def write(self, data):
        self.writer.write(data)


def _constant_time_compare(a, b):
    '''Compare a and b in constant time.'''

    for t in (bytes, str, bytearray):
        if isinstance(a, t) and isinstance(b, t):
            break
    
    else:
        raise TypeError('Arguments must be of same type (bytes, str)')

    if len(a) != len(b):
        return False
    
    equal = True
    for x, y in zip(a, b):
        equal &= (x == y)
    return equal


def sign(message, key):
    '''Sign a message.'''

    hmac = HMAC.new(key, msg=message, digestmod=SHA256)
    return message + hmac.digest()


def verify(message, key):
    '''Verify a signed message.'''

    if len(message) < 32:
        raise ValueError('Message contains no signature')

    message, digest = message[:-32], message[-32:]
    hmac = HMAC.new(key, msg=message, digestmod=SHA256)
    
    if not _constant_time_compare(hmac.digest(), digest):
        raise ValueError('Signature verification failed')

    return True
