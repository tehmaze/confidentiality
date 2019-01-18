import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long

_AES_BLOCK_SIZE = 16
_GCM_NONCE_SIZE = 12
_GCM_TAG_SIZE = 16

# Allow (test) to monkeypatch our random reader.


def _get_random_bytes(n):
    return get_random_bytes(n)


def encrypt(message, key):
    '''encrypt a message.'''

    # Generate a random nonce.
    nonce = _get_random_bytes(_GCM_NONCE_SIZE)

    # Load the AES key.
    aead = AES.new(key, AES.MODE_GCM, nonce)

    # Encrypt the message.
    ciphertext, tag = aead.encrypt_and_digest(message)

    return nonce + ciphertext + tag


def decrypt(message, key):
    '''decrypt a message.'''

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

    hmac = HMAC.new(key, msg=message, digestmod=SHA1)
    return message + hmac.digest()


def verify(message, key):
    '''Verify a signed message.'''

    if len(message) < 20:
        raise ValueError('Message contains no signature')

    message, digest = message[:-20], message[-20:]
    hmac = HMAC.new(key, msg=message, digestmod=SHA1)
    
    if not constant_time_compare(hmac.digest(), digest):
        raise ValueError('Signature verification failed')

    return True