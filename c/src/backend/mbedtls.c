#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/entropy.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pkcs5.h>

#include "backend.h"
#if !defined(WITHOUT_MALLOC)
#include <stdlib.h>
#endif

static mbedtls_entropy_context entropy;
static int random_ready = 0;

/**
 * Errors.
 */

CONFIDENTIALITY_INTERNAL
void error_string(int code, char *buffer, size_t length)
{
    mbedtls_strerror(code, buffer, length);
}

/**
 * Random
 */

CONFIDENTIALITY_INTERNAL
void random_init(void)
{
    if (random_ready)
    {
        return;
    }

    mbedtls_entropy_init(&entropy);
    random_ready = 1;
}

CONFIDENTIALITY_INTERNAL
int random_read(void *buffer, size_t size)
{
    random_init();
    return mbedtls_entropy_func(&entropy, (uint8_t *)buffer, size);
}

/**
 * Message authentication.
 */

CONFIDENTIALITY_INTERNAL
int hmac_sha256(
    uint8_t digest[DIGEST_SIZE],
    const uint8_t *src, size_t src_size,
    const uint8_t *key, size_t key_size)
{
    int ret = 0;
    mbedtls_md_context_t context;
    mbedtls_md_setup(&context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

    if ((ret = mbedtls_md_hmac_starts(&context, key, key_size)))
    {
        goto bail;
    }

    if ((ret = mbedtls_md_hmac_update(&context, src, src_size)))
    {
        goto bail;
    }

    if ((ret = mbedtls_md_hmac_finish(&context, digest)))
    {
        goto bail;
    }

bail:
    mbedtls_md_free(&context);
    return ret;
}

/**
 * Message encryption.
 */

CONFIDENTIALITY_INTERNAL
int message_encrypt(
    uint8_t *dst,
    uint8_t nonce[MESSAGE_NONCE_SIZE],
    uint8_t tag[MESSAGE_TAG_SIZE],
    const uint8_t *src, size_t src_size,
    const uint8_t *key, size_t key_size)
{
    int ret = 0;
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);

    // Initialize AES key.
    if ((ret = mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, key_size)))
    {
        goto bail;
    }

    // Generate nonce.
    if ((ret = random_read(nonce, MESSAGE_NONCE_SIZE)))
    {
        goto bail;
    }

    // Initialize with nonce.
    if ((ret = mbedtls_gcm_starts(&context, MBEDTLS_GCM_ENCRYPT, nonce, MESSAGE_NONCE_SIZE, NULL, 0)))
    {
        goto bail;
    }

    // Generate ciphertext.
    if ((ret = mbedtls_gcm_update(&context, src_size, src, dst)))
    {
        goto bail;
    }

    // Generate AEAD tag.
    if ((ret = mbedtls_gcm_finish(&context, tag, MESSAGE_TAG_SIZE)))
    {
        goto bail;
    }

bail:
    mbedtls_gcm_free(&context);
    return ret;
}

CONFIDENTIALITY_INTERNAL
int message_decrypt(
    uint8_t *dst,
    const uint8_t nonce[MESSAGE_NONCE_SIZE],
    const uint8_t tag[MESSAGE_TAG_SIZE],
    const uint8_t *src, size_t src_size,
    const uint8_t *key, size_t key_size)
{
    int ret = 0;
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);

    // Initialize AES key.
    if ((ret = mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, key_size)))
    {
        goto bail;
    }

    // Initialize with nonce.
    if ((ret = mbedtls_gcm_starts(&context, MBEDTLS_GCM_DECRYPT, nonce, MESSAGE_NONCE_SIZE, NULL, 0)))
    {
        goto bail;
    }

    // Decrypt ciphertext.
    if ((ret = mbedtls_gcm_update(&context, src_size, src, dst)))
    {
        goto bail;
    }

    // Verify AEAD tag.
    if ((ret = mbedtls_gcm_finish(&context, (uint8_t *)tag, MESSAGE_TAG_SIZE)))
    {
        goto bail;
    }

bail:
    mbedtls_gcm_free(&context);
    return ret;
}

/**
 * Key exchange.
 */

CONFIDENTIALITY_INTERNAL
int derive_key(
    uint8_t key[32],
    const uint8_t *password, size_t password_size,
    unsigned int iter)
{
    int ret = 0;
    mbedtls_md_context_t context;
    mbedtls_md_setup(&context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

    if ((ret = mbedtls_pkcs5_pbkdf2_hmac(&context, password, password_size, NULL, 0, iter, 32, key)))
    {
        goto bail;
    }

bail:
    mbedtls_md_free(&context);
    return ret;
}