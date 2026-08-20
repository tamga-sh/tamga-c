#include "crypto/sha256.h"

#include <string.h>

#include "tamga_mem.h"

static const uint32_t TAMGA_SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

static uint32_t tamga_rotr32(uint32_t value, unsigned int bits) {
    return (value >> bits) | (value << (32u - bits));
}

static void tamga_sha256_compress(TamgaSha256 *ctx, const unsigned char block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned int i;

    for (i = 0u; i < 16u; i++) {
        w[i] = ((uint32_t)block[i * 4u] << 24) | ((uint32_t)block[(i * 4u) + 1u] << 16) |
               ((uint32_t)block[(i * 4u) + 2u] << 8) | (uint32_t)block[(i * 4u) + 3u];
    }
    for (i = 16u; i < 64u; i++) {
        uint32_t s0 =
            tamga_rotr32(w[i - 15u], 7) ^ tamga_rotr32(w[i - 15u], 18) ^ (w[i - 15u] >> 3);
        uint32_t s1 = tamga_rotr32(w[i - 2u], 17) ^ tamga_rotr32(w[i - 2u], 19) ^ (w[i - 2u] >> 10);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0u; i < 64u; i++) {
        uint32_t s1 = tamga_rotr32(e, 6) ^ tamga_rotr32(e, 11) ^ tamga_rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + TAMGA_SHA256_K[i] + w[i];
        uint32_t s0 = tamga_rotr32(a, 2) ^ tamga_rotr32(a, 13) ^ tamga_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    tamga_secure_zero(w, sizeof(w));
}

void tamga_sha256_init(TamgaSha256 *ctx) {
    if (ctx == NULL) {
        return;
    }
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->total_len = 0u;
    ctx->block_len = 0u;
    memset(ctx->block, 0, sizeof(ctx->block));
}

void tamga_sha256_update(TamgaSha256 *ctx, const void *data, size_t len) {
    const unsigned char *bytes = (const unsigned char *)data;
    size_t offset = 0u;

    if (ctx == NULL || (data == NULL && len > 0u)) {
        return;
    }
    ctx->total_len += (uint64_t)len;

    if (ctx->block_len > 0u) {
        size_t needed = TAMGA_SHA256_BLOCK_LEN - ctx->block_len;
        size_t take = (len < needed) ? len : needed;
        memcpy(&ctx->block[ctx->block_len], bytes, take);
        ctx->block_len += take;
        offset = take;
        if (ctx->block_len < TAMGA_SHA256_BLOCK_LEN) {
            return;
        }
        tamga_sha256_compress(ctx, ctx->block);
        ctx->block_len = 0u;
    }

    while ((len - offset) >= TAMGA_SHA256_BLOCK_LEN) {
        tamga_sha256_compress(ctx, &bytes[offset]);
        offset += TAMGA_SHA256_BLOCK_LEN;
    }

    if (offset < len) {
        ctx->block_len = len - offset;
        memcpy(ctx->block, &bytes[offset], ctx->block_len);
    }
}

void tamga_sha256_final(TamgaSha256 *ctx, unsigned char out[TAMGA_SHA256_DIGEST_LEN]) {
    uint64_t bit_len;
    unsigned int i;

    if (ctx == NULL || out == NULL) {
        return;
    }
    bit_len = ctx->total_len * 8u;

    ctx->block[ctx->block_len] = 0x80u;
    ctx->block_len++;
    if (ctx->block_len > (TAMGA_SHA256_BLOCK_LEN - 8u)) {
        memset(&ctx->block[ctx->block_len], 0, TAMGA_SHA256_BLOCK_LEN - ctx->block_len);
        tamga_sha256_compress(ctx, ctx->block);
        ctx->block_len = 0u;
    }
    memset(&ctx->block[ctx->block_len], 0, (TAMGA_SHA256_BLOCK_LEN - 8u) - ctx->block_len);
    for (i = 0u; i < 8u; i++) {
        ctx->block[(TAMGA_SHA256_BLOCK_LEN - 1u) - i] = (unsigned char)(bit_len >> (8u * i));
    }
    tamga_sha256_compress(ctx, ctx->block);

    for (i = 0u; i < 8u; i++) {
        out[i * 4u] = (unsigned char)(ctx->state[i] >> 24);
        out[(i * 4u) + 1u] = (unsigned char)(ctx->state[i] >> 16);
        out[(i * 4u) + 2u] = (unsigned char)(ctx->state[i] >> 8);
        out[(i * 4u) + 3u] = (unsigned char)ctx->state[i];
    }

    /* The context holds a partial block of the message plus the chaining
     * state; for HMAC that message is key material. */
    tamga_secure_zero(ctx, sizeof(*ctx));
}

void tamga_sha256(const void *data, size_t len, unsigned char out[TAMGA_SHA256_DIGEST_LEN]) {
    TamgaSha256 ctx;
    tamga_sha256_init(&ctx);
    tamga_sha256_update(&ctx, data, len);
    tamga_sha256_final(&ctx, out);
}
