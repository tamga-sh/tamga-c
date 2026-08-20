/*
 * aes.h -- AES-256 block encryption.
 *
 * Encryption only: AES-GCM (the sole mode this library uses) builds both its
 * keystream and its authentication tag out of the forward transform, so the
 * inverse cipher would be dead code -- and dead cryptographic code is code
 * nobody tests.
 *
 * Threat model note on the S-box. This is a table-driven implementation, so
 * its memory access pattern depends on the key, which in the general case is
 * a cache-timing side channel. It is not one here: the AES key is derived from
 * the licence key, which the caller already holds and is entitled to. In the
 * licence-enforcement threat model the client *is* the adversary, and an
 * adversary who already possesses the key learns nothing by timing its use.
 * That reasoning is what makes a table-driven S-box acceptable; it would not
 * be if this key were ever a server-side secret.
 */
#ifndef TAMGA_CRYPTO_AES_H
#define TAMGA_CRYPTO_AES_H

#include <stddef.h>
#include <stdint.h>

#define TAMGA_AES_BLOCK_LEN 16u
#define TAMGA_AES256_KEY_LEN 32u
/* AES-256 is 14 rounds, so 15 round keys of 16 bytes. */
#define TAMGA_AES256_ROUND_KEYS 15u

typedef struct TamgaAes256 {
    uint8_t round_key[TAMGA_AES256_ROUND_KEYS][TAMGA_AES_BLOCK_LEN];
} TamgaAes256;

/** Expands a 32-byte key into the round-key schedule. */
void tamga_aes256_init(TamgaAes256 *ctx, const unsigned char key[TAMGA_AES256_KEY_LEN]);

/** Encrypts one 16-byte block. `in` and `out` may alias. */
void tamga_aes256_encrypt_block(const TamgaAes256 *ctx,
                                const unsigned char in[TAMGA_AES_BLOCK_LEN],
                                unsigned char out[TAMGA_AES_BLOCK_LEN]);

/** Erases the round-key schedule. */
void tamga_aes256_clear(TamgaAes256 *ctx);

#endif /* TAMGA_CRYPTO_AES_H */
