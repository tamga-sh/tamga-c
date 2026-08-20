/*
 * sha512.h -- FIPS 180-4 SHA-512.
 *
 * Present for exactly one reason: Ed25519 is defined over SHA-512 (RFC 8032).
 * Nothing else in this library uses it.
 */
#ifndef TAMGA_CRYPTO_SHA512_H
#define TAMGA_CRYPTO_SHA512_H

#include <stddef.h>
#include <stdint.h>

#define TAMGA_SHA512_DIGEST_LEN 64u
#define TAMGA_SHA512_BLOCK_LEN  128u

typedef struct TamgaSha512 {
    uint64_t state[8];
    uint64_t total_len;
    unsigned char block[TAMGA_SHA512_BLOCK_LEN];
    size_t block_len;
} TamgaSha512;

void tamga_sha512_init(TamgaSha512 *ctx);
void tamga_sha512_update(TamgaSha512 *ctx, const void *data, size_t len);
/** Writes the digest and wipes the context. */
void tamga_sha512_final(TamgaSha512 *ctx, unsigned char out[TAMGA_SHA512_DIGEST_LEN]);

void tamga_sha512(const void *data, size_t len, unsigned char out[TAMGA_SHA512_DIGEST_LEN]);

#endif /* TAMGA_CRYPTO_SHA512_H */
