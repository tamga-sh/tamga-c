/*
 * sha256.h -- FIPS 180-4 SHA-256.
 *
 * Used for: HMAC/HKDF key derivation, the digest inside every RSA and ECDSA
 * signature this library verifies, and MGF1 for RSA-PSS.
 */
#ifndef TAMGA_CRYPTO_SHA256_H
#define TAMGA_CRYPTO_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define TAMGA_SHA256_DIGEST_LEN 32u
#define TAMGA_SHA256_BLOCK_LEN 64u

typedef struct TamgaSha256 {
    uint32_t state[8];
    uint64_t total_len;
    unsigned char block[TAMGA_SHA256_BLOCK_LEN];
    size_t block_len;
} TamgaSha256;

void tamga_sha256_init(TamgaSha256 *ctx);
void tamga_sha256_update(TamgaSha256 *ctx, const void *data, size_t len);
/** Writes the digest and wipes the context. */
void tamga_sha256_final(TamgaSha256 *ctx, unsigned char out[TAMGA_SHA256_DIGEST_LEN]);

/** One-shot convenience wrapper. */
void tamga_sha256(const void *data, size_t len, unsigned char out[TAMGA_SHA256_DIGEST_LEN]);

#endif /* TAMGA_CRYPTO_SHA256_H */
