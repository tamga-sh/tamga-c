#include "crypto/sha512.h"

#include <string.h>

#include "tamga_mem.h"

static const uint64_t TAMGA_SHA512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static uint64_t tamga_rotr64(uint64_t value, unsigned int bits) {
    return (value >> bits) | (value << (64u - bits));
}

static void tamga_sha512_compress(TamgaSha512 *ctx, const unsigned char block[128]) {
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    unsigned int i;

    for (i = 0u; i < 16u; i++) {
        unsigned int base = i * 8u;
        w[i] = ((uint64_t)block[base] << 56) | ((uint64_t)block[base + 1u] << 48) |
               ((uint64_t)block[base + 2u] << 40) | ((uint64_t)block[base + 3u] << 32) |
               ((uint64_t)block[base + 4u] << 24) | ((uint64_t)block[base + 5u] << 16) |
               ((uint64_t)block[base + 6u] << 8) | (uint64_t)block[base + 7u];
    }
    for (i = 16u; i < 80u; i++) {
        uint64_t s0 = tamga_rotr64(w[i - 15u], 1) ^ tamga_rotr64(w[i - 15u], 8) ^ (w[i - 15u] >> 7);
        uint64_t s1 = tamga_rotr64(w[i - 2u], 19) ^ tamga_rotr64(w[i - 2u], 61) ^ (w[i - 2u] >> 6);
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

    for (i = 0u; i < 80u; i++) {
        uint64_t s1 = tamga_rotr64(e, 14) ^ tamga_rotr64(e, 18) ^ tamga_rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t temp1 = h + s1 + ch + TAMGA_SHA512_K[i] + w[i];
        uint64_t s0 = tamga_rotr64(a, 28) ^ tamga_rotr64(a, 34) ^ tamga_rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = s0 + maj;

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

void tamga_sha512_init(TamgaSha512 *ctx) {
    if (ctx == NULL) {
        return;
    }
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->total_len = 0u;
    ctx->block_len = 0u;
    memset(ctx->block, 0, sizeof(ctx->block));
}

void tamga_sha512_update(TamgaSha512 *ctx, const void *data, size_t len) {
    const unsigned char *bytes = (const unsigned char *)data;
    size_t offset = 0u;

    if (ctx == NULL || (data == NULL && len > 0u)) {
        return;
    }
    ctx->total_len += (uint64_t)len;

    if (ctx->block_len > 0u) {
        size_t needed = TAMGA_SHA512_BLOCK_LEN - ctx->block_len;
        size_t take = (len < needed) ? len : needed;
        memcpy(&ctx->block[ctx->block_len], bytes, take);
        ctx->block_len += take;
        offset = take;
        if (ctx->block_len < TAMGA_SHA512_BLOCK_LEN) {
            return;
        }
        tamga_sha512_compress(ctx, ctx->block);
        ctx->block_len = 0u;
    }

    while ((len - offset) >= TAMGA_SHA512_BLOCK_LEN) {
        tamga_sha512_compress(ctx, &bytes[offset]);
        offset += TAMGA_SHA512_BLOCK_LEN;
    }

    if (offset < len) {
        ctx->block_len = len - offset;
        memcpy(ctx->block, &bytes[offset], ctx->block_len);
    }
}

void tamga_sha512_final(TamgaSha512 *ctx, unsigned char out[TAMGA_SHA512_DIGEST_LEN]) {
    uint64_t bit_len;
    unsigned int i;

    if (ctx == NULL || out == NULL) {
        return;
    }
    bit_len = ctx->total_len * 8u;

    ctx->block[ctx->block_len] = 0x80u;
    ctx->block_len++;
    /* SHA-512's length field is 128 bits. Messages long enough to use the
     * high half do not occur here (the input cap is 16 MiB), so the top 8
     * bytes are always zero -- written explicitly rather than assumed. */
    if (ctx->block_len > (TAMGA_SHA512_BLOCK_LEN - 16u)) {
        memset(&ctx->block[ctx->block_len], 0, TAMGA_SHA512_BLOCK_LEN - ctx->block_len);
        tamga_sha512_compress(ctx, ctx->block);
        ctx->block_len = 0u;
    }
    memset(&ctx->block[ctx->block_len], 0, (TAMGA_SHA512_BLOCK_LEN - 8u) - ctx->block_len);
    for (i = 0u; i < 8u; i++) {
        ctx->block[(TAMGA_SHA512_BLOCK_LEN - 1u) - i] = (unsigned char)(bit_len >> (8u * i));
    }
    tamga_sha512_compress(ctx, ctx->block);

    for (i = 0u; i < 8u; i++) {
        unsigned int base = i * 8u;
        unsigned int shift;
        for (shift = 0u; shift < 8u; shift++) {
            out[base + shift] = (unsigned char)(ctx->state[i] >> (56u - (8u * shift)));
        }
    }

    tamga_secure_zero(ctx, sizeof(*ctx));
}

void tamga_sha512(const void *data, size_t len, unsigned char out[TAMGA_SHA512_DIGEST_LEN]) {
    TamgaSha512 ctx;
    tamga_sha512_init(&ctx);
    tamga_sha512_update(&ctx, data, len);
    tamga_sha512_final(&ctx, out);
}
