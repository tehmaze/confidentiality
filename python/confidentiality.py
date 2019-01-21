import struct
import time
import warnings

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long, long_to_bytes

from ecdsa import SigningKey, VerifyingKey, NIST256p
from ecdsa.ellipticcurve import Point

_ECC_CURVE = 'P-256'
_ECC_CURVE_POINT_BYTES = 32
_ECC_PRIME = 0x115792089210356248762697446949407573530086143415290314195533631308867097853951
_ECC_LINEAR = 0x03
_AES_BLOCK_SIZE = 16
_GCM_NONCE_SIZE = 12
_GCM_TAG_SIZE = 16

# Allow (test) to monkeypatch our random reader.


def _get_random_bytes(n):
    return get_random_bytes(n)


def exchange(stream):
    '''Exchange a shared key.'''

    # Generate an emphemeral ECDSA NIST P-256 private key
    private_key = SigningKey.generate(curve=NIST256p).privkey
    public_key = private_key.public_key

    # Write the public part on the wire
    _write_ecc_public_key(stream, public_key)

    # Read peer's public key from the wire
    peers_public_key = _read_ecc_public_key(stream)

    # Compute the scalar product of our private key with peer's
    shared_point = private_key.secret_multiplier * peers_public_key

    # public key as our shared key.
    return long_to_bytes(shared_point.x())


def _read_ecc_public_key(stream):
    bytes_length = 1 + 2 * _ECC_CURVE_POINT_BYTES

    block = b''
    while len(block) == 0:
        block += stream.read(bytes_length)
        if len(block) == 0:
            time.sleep(0.1)

    return _unmarshal_ecc_public_key(block)


def _write_ecc_public_key(stream, key):
    stream.write(_marshal_ecc_public_key(key))


def _marshal_ecc_public_key(key):
    '''Convert a point into the uncompressed form specified in section 4.3.6 of ANSI X9.62.'''
    marshaled = bytearray([4])  # Uncompressed
    marshaled.extend(bytearray(long_to_bytes(key.point.x())))
    marshaled.extend(bytearray(long_to_bytes(key.point.y())))
    return marshaled


def _unmarshal_ecc_public_key(marshaled):
    if marshaled[0] != 4:
        raise ValueError('Expected uncompressed ECC point')

    if len(marshaled[1:]) != 2 * _ECC_CURVE_POINT_BYTES:
        raise ValueError('Expected {} ECC point bytes, got {}'.format(
                    2 * _ECC_CURVE_POINT_BYTES,
                    len(marshaled[1:])))

    marshaled = marshaled[1:]
    return Point(
        curve=NIST256p.curve,
        x=bytes_to_long(marshaled[:_ECC_CURVE_POINT_BYTES]),
        y=bytes_to_long(marshaled[_ECC_CURVE_POINT_BYTES:]),
    )


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

    def write(self, data):
        self.stream.write(self.cipher.encrypt(data))


class Decrypter:
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


def constant_time_compare(a, b):
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
    
    if not constant_time_compare(hmac.digest(), digest):
        raise ValueError('Signature verification failed')

    return True
