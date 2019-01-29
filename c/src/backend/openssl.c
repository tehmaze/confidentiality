#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "backend.h"

/**
 * Errors.
 */

CONFIDENTIALITY_INTERNAL
void error_string(int code, char *buffer, size_t length)
{
    static char str[1025];
    ERR_error_string_n(code, str, sizeof(str));
    snprintf(buffer, length, "%s", str);
}

/**
 * Random.
 */

CONFIDENTIALITY_INTERNAL
void random_init(void)
{
}

CONFIDENTIALITY_INTERNAL
int random_read(void *buffer, size_t size)
{
    return RAND_bytes(buffer, size);
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
    unsigned int len;
    HMAC_CTX *context = HMAC_CTX_new();
    
    if ((ret = HMAC_Init_ex(context, key, key_size, EVP_sha256(), NULL)))
    {
        goto bail;
    }

    if ((ret = HMAC_Update(context, src, src_size)))
    {
        goto bail;
    }

    if ((ret = HMAC_Final(context, digest, &len))) {
        goto bail;
    }

bail:
    HMAC_CTX_free(context);
    return ret;
}

/**
 * Message encryption.
 */

static inline const EVP_CIPHER *aes_gcm_cipher(size_t key_size)
{
    switch (key_size) {
    case 16:
#if defined(HAVE_EVP_AES_128_GCM)
        return EVP_aes_128_gcm();
#endif
        break;
    case 24:
#if defined(HAVE_EVP_AES_192_GCM)
        return EVP_aes_192_gcm();
#endif
        break;
    case 32:
#if defined(HAVE_EVP_AES_256_GCM)
        return EVP_aes_256_gcm();
#endif
        break;
    }
    return NULL;
}

CONFIDENTIALITY_INTERNAL
int message_encrypt(
    uint8_t *dst,
    uint8_t nonce[MESSAGE_NONCE_SIZE],
    uint8_t tag[MESSAGE_TAG_SIZE],
    const uint8_t *src, size_t src_size,
    const uint8_t *key, size_t key_size)
{
    int ret = 0;
    unsigned int len = 0;
    EVP_CIPHER_CTX *context;
    const EVP_CIPHER *cipher = aes_gcm_cipher(key_size);

    if (cipher == NULL)
    {
        return 1;
    }

    if ((context = EVP_CIPHER_CTX_new()) == NULL)
    {
        return 1;
    }

    if (1 != (ret = random_read(nonce, MESSAGE_NONCE_SIZE)))
    {
        goto bail;
    }

    if (1 != (ret = EVP_EncryptInit(context, cipher, key, nonce)))
    {
        goto bail;
    }

    if (1 != (ret = EVP_EncryptUpdate(context, dst, &len, src, src_size)))
    {
        goto bail;
    }

    if (1 != (ret = EVP_EncryptFinal(context, dst + len, &len)))
    {
        goto bail;
    }

    if (1 != (ret = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, MESSAGE_TAG_SIZE, (void *) tag)))
    {
        goto bail;
    }

bail:
    EVP_CIPHER_CTX_free(context);
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
    unsigned int len = 0;
    EVP_CIPHER_CTX *context;
    const EVP_CIPHER *cipher = aes_gcm_cipher(key_size);

    if (cipher == NULL)
    {
        return 1;
    }

    if ((context = EVP_CIPHER_CTX_new()) == NULL)
    {
        return 1;
    }

    if (1 != (ret = EVP_DecryptInit_ex(context, cipher, NULL, key, nonce)))
    {
        goto bail;
    }

    if (1 != (ret = EVP_DecryptUpdate(context, dst, &len, src, src_size)))
    {
        goto bail;
    }

    if (1 != (ret = EVP_DecryptFinal(context, dst + len, &len)))
    {
        goto bail;
    }

    if (1 != (ret = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, MESSAGE_TAG_SIZE, (void *) tag)))
    {
        goto bail;
    }

bail:
    EVP_CIPHER_CTX_free(context);
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
    return PKCS5_PBKDF2_HMAC(password, password_size, NULL, 0, iter, EVP_sha256(), 32, key);
}