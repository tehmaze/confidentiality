#ifndef CONFIDENTIALITY_X25519_H
#define CONFIDENTIALITY_X25519_H

#include <stdint.h>
#include "confidentiality.h"
#include "internal/compare.h"

#define X25519_PRIVATE_KEY_LEN 32
#define X25519_PUBLIC_VALUE_LEN 32

/**
 * Generate a public/private key pair.
 * @param out_public_value generated public key.
 * @param out_private_value generated private key.
 */
CONFIDENTIALITY_INTERNAL
int x25519_keypair(
    uint8_t out_public_key[32],
    uint8_t out_private_key[32]);

/**
 * Diffie-Hellman function.
 * @param out_shared_key
 * @param private_key
 * @param out_public_value
 * @return one on success and zero on error.
 *
 * X25519() writes a shared key to @out_shared_key that is calculated from the
 * given private key and the peer's public value.
 *
 * Don't use the shared key directly, rather use a KDF and also include the two
 * public values as inputs.
 */
CONFIDENTIALITY_INTERNAL
int x25519_kex(
    uint8_t out_shared_key[32],
    const uint8_t private_key[32],
	const uint8_t peers_public_key[32]);

/**
 * Compute the matching public key.
 * @param out_public_value computed public key.
 * @param private_key private key to use.
 *
 * X25519_public_from_private() calculates a Diffie-Hellman public value from
 * the given private key and writes it to @out_public_value.
 */
CONFIDENTIALITY_INTERNAL
void x25519_public_from_private(
    uint8_t out_public_key[32],
	const uint8_t private_key[32]);

#endif