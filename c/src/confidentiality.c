#include <string.h>
#include <stdio.h>
#if !defined(WITHOUT_MALLOC)
#include <stdlib.h>
#endif

#include "confidentiality.h"
#include "backend.h"
#include "internal/compare.h"
#include "internal/x25519.h"

#define RANGE(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)

static const uint8_t zero[128] = {0,};

void confidentiality_error(int code, char *buffer, size_t length)
{
    switch (code)
    {
    case 0:
        memset(buffer, 0, length);
        return;
    case CONFIDENTIALITY_ERR_KEY_SIZE:
        snprintf(buffer, length, "KEY - Key size invalid");
        return;
    case CONFIDENTIALITY_ERR_KEY_TYPE:
        snprintf(buffer, length, "KEY - Key type invalid");
        return;
    default:
        // Ask the backend
        return error_string(code, buffer, length);
    }
}

int confidentiality_signature(
    uint8_t signature[CONFIDENTIALITY_SIGNATURE_LEN],
    const uint8_t *message, size_t message_size,
    const uint8_t *key, size_t key_size)
{
    return hmac_sha256(signature, message, message_size, key, key_size);
}

int confidentiality_verify(
    uint8_t signature[CONFIDENTIALITY_SIGNATURE_LEN],
    const uint8_t *message, size_t message_size,
    const uint8_t *key, size_t key_size)
{
    uint8_t verify[CONFIDENTIALITY_SIGNATURE_LEN];

    if (message_size < CONFIDENTIALITY_SIGNATURE_LEN) {
        // Not signed.
        return 1;
    }

    if (hmac_sha256(verify, message, message_size - CONFIDENTIALITY_SIGNATURE_LEN, key, key_size)) {
        // Error.
        return 1;
    }

    return constant_time_compare(verify, signature, CONFIDENTIALITY_SIGNATURE_LEN) != 0;
}

/*
 * Message encryption.
 */

int confidentiality_encrypt(
    uint8_t *encrypted,
    const uint8_t *message, size_t message_size,
    const uint8_t *key, size_t key_size)
{
    uint8_t *nonce = encrypted;
    uint8_t *dst = encrypted + MESSAGE_NONCE_SIZE;
    uint8_t *tag = encrypted + MESSAGE_NONCE_SIZE + message_size;
    return message_encrypt(dst, nonce, tag, message, message_size, key, key_size);
}

int confidentiality_decrypt(
    uint8_t *dst,
    const uint8_t *message, size_t message_size,
    const uint8_t *key, size_t key_size)
{
    const uint8_t *nonce = message;
    const uint8_t *src = message + MESSAGE_NONCE_SIZE;
    const uint8_t *tag = message + MESSAGE_NONCE_SIZE + message_size;
    size_t src_size = message_decrypted_size(message_size);
    return message_decrypt(dst, nonce, tag, src, src_size, key, key_size);
}

/*
 * Key exchange.
 */

int confidentiality_exchange(int fd, uint8_t sharedSecret[32])
{
    uint8_t localSecret[32];
    uint8_t localPublic[32];
    uint8_t peersPublic[32];
    uint8_t sharedPoint[32];
    uint8_t wireFormat[33];

    // Generate key pair.
    if (x25519_keypair(localPublic, localSecret)) {
        return 1;
    }
    
    // Write it to the fd in wire format.
    wireFormat[0] = 0x19;
    memcpy(wireFormat + 1, localPublic, 32);
    if (write(fd, wireFormat, 33) != 33) {
        return 1;
    }

    // Read peer's public key.
    if (read(fd, wireFormat, 33) != 33) {
        return 1;
    } else if (wireFormat[0] != 0x19) {
        return 1;
    }
    memcpy(peersPublic, wireFormat + 1, 32);

    // Calculate shared point.
    if (x25519_kex(sharedPoint, localSecret, peersPublic)) {
        return 1;
    }

    // Destroy our secret key.
    wipe(localSecret, 32);

    // Derive key.
    if (derive_key(sharedSecret, sharedPoint, 32, 4096)) {
        return 1;
    }

    return 0;
}

/*
 * Stream encryption.
 */

confidentiality_stream *confidentiality_secure(int fd)
{
#if defined(WITHOUT_MALLOC)
    static confidentiality_stream singleton;
    confidentiality_stream *stream = &singleton;
#else
    confidentiality_stream *stream = malloc(sizeof(confidentiality_stream));
    if (stream == NULL) {
        return NULL;
    }
#endif

    // Exchange a shared secret.
    uint8_t sharedSecret[32];
    if (!confidentiality_exchange(fd, sharedSecret)) {
#if !defined(WITHOUT_MALLOC)
        free(stream);
#endif
        return NULL;
    }

    // Return a R/W AES-CTR stream.
    return stream;
}

confidentiality_stream *confidentiality_encrypter(
    int fd,
    const uint8_t *key, size_t key_size);

confidentiality_stream *confidentiality_decrypter(
    int fd,
    const uint8_t *key, size_t key_size);

ssize_t confidentiality_stream_read(
    confidentiality_stream *stream,
    uint8_t *buffer, size_t nbytes);

ssize_t confidentiality_stream_write(
    confidentiality_stream *stream,
    const uint8_t *buffer, size_t nbytes);
