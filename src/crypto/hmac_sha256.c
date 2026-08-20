#include "crypto/hmac_sha256.h"

#include <string.h>

#include "tamga_mem.h"

void tamga_hmac_sha256_init(TamgaHmacSha256 *ctx, const void *key, size_t key_len) {
    unsigned char block_key[TAMGA_SHA256_BLOCK_LEN];
    unsigned char inner_pad[TAMGA_SHA256_BLOCK_LEN];
    size_t i;

    if (ctx == NULL) {
        return;
    }
    memset(block_key, 0, sizeof(block_key));

    /* RFC 2104: a key longer than the block size is replaced by its own
     * digest, and a shorter one is zero-padded. */
    if (key_len > TAMGA_SHA256_BLOCK_LEN) {
        tamga_sha256(key, key_len, block_key);
    } else if (key_len > 0u && key != NULL) {
        memcpy(block_key, key, key_len);
    }

    for (i = 0u; i < TAMGA_SHA256_BLOCK_LEN; i++) {
        inner_pad[i] = (unsigned char)(block_key[i] ^ 0x36u);
        ctx->outer_pad[i] = (unsigned char)(block_key[i] ^ 0x5cu);
    }

    tamga_sha256_init(&ctx->inner);
    tamga_sha256_update(&ctx->inner, inner_pad, sizeof(inner_pad));

    tamga_secure_zero(block_key, sizeof(block_key));
    tamga_secure_zero(inner_pad, sizeof(inner_pad));
}

void tamga_hmac_sha256_update(TamgaHmacSha256 *ctx, const void *data, size_t len) {
    if (ctx == NULL) {
        return;
    }
    tamga_sha256_update(&ctx->inner, data, len);
}

void tamga_hmac_sha256_final(TamgaHmacSha256 *ctx, unsigned char out[TAMGA_SHA256_DIGEST_LEN]) {
    unsigned char inner_digest[TAMGA_SHA256_DIGEST_LEN];
    TamgaSha256 outer;

    if (ctx == NULL || out == NULL) {
        return;
    }
    tamga_sha256_final(&ctx->inner, inner_digest);

    tamga_sha256_init(&outer);
    tamga_sha256_update(&outer, ctx->outer_pad, sizeof(ctx->outer_pad));
    tamga_sha256_update(&outer, inner_digest, sizeof(inner_digest));
    tamga_sha256_final(&outer, out);

    tamga_secure_zero(inner_digest, sizeof(inner_digest));
    tamga_secure_zero(ctx, sizeof(*ctx));
}

void tamga_hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len,
                       unsigned char out[TAMGA_SHA256_DIGEST_LEN]) {
    TamgaHmacSha256 ctx;
    tamga_hmac_sha256_init(&ctx, key, key_len);
    tamga_hmac_sha256_update(&ctx, data, data_len);
    tamga_hmac_sha256_final(&ctx, out);
}
