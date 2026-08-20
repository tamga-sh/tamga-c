/*
 * hmac_sha256.h -- RFC 2104 HMAC over SHA-256.
 *
 * Exists to back HKDF (RFC 5869), which is how both offline file formats
 * derive their AES key.
 */
#ifndef TAMGA_CRYPTO_HMAC_SHA256_H
#define TAMGA_CRYPTO_HMAC_SHA256_H

#include <stddef.h>

#include "crypto/sha256.h"

typedef struct TamgaHmacSha256 {
    TamgaSha256 inner;
    unsigned char outer_pad[TAMGA_SHA256_BLOCK_LEN];
} TamgaHmacSha256;

void tamga_hmac_sha256_init(TamgaHmacSha256 *ctx, const void *key, size_t key_len);
void tamga_hmac_sha256_update(TamgaHmacSha256 *ctx, const void *data, size_t len);
/** Writes the MAC and wipes the context, including the derived pads. */
void tamga_hmac_sha256_final(TamgaHmacSha256 *ctx, unsigned char out[TAMGA_SHA256_DIGEST_LEN]);

void tamga_hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len,
                       unsigned char out[TAMGA_SHA256_DIGEST_LEN]);

#endif /* TAMGA_CRYPTO_HMAC_SHA256_H */
