#include "crypto/gcm.h"

#include <string.h>

#include "crypto/ct.h"
#include "tamga_mem.h"

/*
 * GF(2^128) multiplication, bit by bit.
 *
 * Deliberately not the usual 4-bit or 8-bit precomputed table: those index
 * memory with data derived from the ciphertext and the hash subkey, which is
 * the standard GHASH cache-timing side channel. At the sizes this library
 * handles -- a licence file is kilobytes -- the bitwise version costs
 * microseconds, which buys a data-independent access pattern for free.
 *
 * The conditional XOR and the conditional reduction are both done with masks
 * rather than branches, for the same reason.
 */
static void tamga_gcm_gf_mul(unsigned char x[16], const unsigned char y[16]) {
    unsigned char z[16];
    unsigned char v[16];
    unsigned int bit;
    unsigned int i;

    memset(z, 0, sizeof(z));
    memcpy(v, y, sizeof(v));

    for (bit = 0u; bit < 128u; bit++) {
        /* Bits of X, most significant first. */
        /* Widened to unsigned before the shift: an unsigned char promotes to
         * int, and `int & 1u` then converts a signed value to unsigned, which
         * GCC reports under -Wsign-conversion. */
        unsigned char x_bit =
            (unsigned char)(((unsigned int)x[bit / 8u] >> (7u - (bit % 8u))) & 1u);
        unsigned char mask = (unsigned char)(0u - x_bit); /* 0xFF or 0x00 */
        unsigned char lsb;
        unsigned char reduce;

        for (i = 0u; i < 16u; i++) {
            z[i] = (unsigned char)(z[i] ^ (v[i] & mask));
        }

        /* V >>= 1, then conditionally XOR the reduction polynomial R =
         * 0xE1 || 0^120 when the bit shifted out was set. */
        lsb = (unsigned char)(v[15] & 1u);
        for (i = 15u; i > 0u; i--) {
            v[i] = (unsigned char)((v[i] >> 1) | ((v[i - 1u] & 1u) << 7));
        }
        v[0] = (unsigned char)(v[0] >> 1);
        reduce = (unsigned char)(0u - lsb);
        v[0] = (unsigned char)(v[0] ^ (0xE1u & reduce));
    }

    memcpy(x, z, sizeof(z));
    tamga_secure_zero(z, sizeof(z));
    tamga_secure_zero(v, sizeof(v));
}

/* Absorbs `len` bytes into the running GHASH accumulator, zero-padding the
 * final partial block. */
static void tamga_ghash_update(unsigned char acc[16], const unsigned char h[16],
                               const unsigned char *data, size_t len) {
    size_t offset = 0u;

    while (offset < len) {
        unsigned char block[16];
        size_t take = len - offset;
        unsigned int i;

        if (take > 16u) {
            take = 16u;
        }
        memset(block, 0, sizeof(block));
        memcpy(block, &data[offset], take);
        for (i = 0u; i < 16u; i++) {
            acc[i] = (unsigned char)(acc[i] ^ block[i]);
        }
        tamga_gcm_gf_mul(acc, h);
        offset += take;
        tamga_secure_zero(block, sizeof(block));
    }
}

static void tamga_gcm_put_u64_be(unsigned char out[8], uint64_t value) {
    unsigned int i;
    for (i = 0u; i < 8u; i++) {
        out[i] = (unsigned char)(value >> (56u - (8u * i)));
    }
}

/* Increments the rightmost 32 bits of a counter block, per GCM's inc32. */
static void tamga_gcm_inc32(unsigned char counter[16]) {
    unsigned int i;
    for (i = 16u; i > 12u; i--) {
        counter[i - 1u]++;
        if (counter[i - 1u] != 0u) {
            return;
        }
    }
}

/*
 * Shared core. Encryption and decryption differ only in whether the tag is
 * produced or checked, and in whether GHASH sees the input or the output --
 * both of which are the ciphertext, so the same keystream walk serves both.
 */
static bool tamga_gcm_core(const unsigned char key[TAMGA_AES256_KEY_LEN],
                           const unsigned char nonce[TAMGA_GCM_NONCE_LEN], const unsigned char *aad,
                           size_t aad_len, const unsigned char *input, size_t input_len,
                           unsigned char *output, unsigned char tag_out[TAMGA_GCM_TAG_LEN],
                           const unsigned char *ciphertext, size_t ciphertext_len) {
    TamgaAes256 aes;
    unsigned char h[16];
    unsigned char j0[16];
    unsigned char counter[16];
    unsigned char acc[16];
    unsigned char length_block[16];
    unsigned char keystream[16];
    size_t offset = 0u;
    unsigned int i;

    tamga_aes256_init(&aes, key);

    /* H = E_K(0^128) */
    memset(h, 0, sizeof(h));
    tamga_aes256_encrypt_block(&aes, h, h);

    /* A 96-bit IV takes the short path: J0 = IV || 0^31 || 1. Every nonce
     * this library sees is 96 bits, so the GHASH-based construction for other
     * lengths is deliberately not implemented rather than left untested. */
    memset(j0, 0, sizeof(j0));
    memcpy(j0, nonce, TAMGA_GCM_NONCE_LEN);
    j0[15] = 1u;

    memcpy(counter, j0, sizeof(counter));

    while (offset < input_len) {
        size_t take = input_len - offset;
        if (take > 16u) {
            take = 16u;
        }
        tamga_gcm_inc32(counter);
        tamga_aes256_encrypt_block(&aes, counter, keystream);
        for (i = 0u; i < take; i++) {
            output[offset + i] = (unsigned char)(input[offset + i] ^ keystream[i]);
        }
        offset += take;
    }

    memset(acc, 0, sizeof(acc));
    tamga_ghash_update(acc, h, aad, aad_len);
    tamga_ghash_update(acc, h, ciphertext, ciphertext_len);

    tamga_gcm_put_u64_be(&length_block[0], (uint64_t)aad_len * 8u);
    tamga_gcm_put_u64_be(&length_block[8], (uint64_t)ciphertext_len * 8u);
    for (i = 0u; i < 16u; i++) {
        acc[i] = (unsigned char)(acc[i] ^ length_block[i]);
    }
    tamga_gcm_gf_mul(acc, h);

    tamga_aes256_encrypt_block(&aes, j0, keystream);
    for (i = 0u; i < TAMGA_GCM_TAG_LEN; i++) {
        tag_out[i] = (unsigned char)(acc[i] ^ keystream[i]);
    }

    tamga_aes256_clear(&aes);
    tamga_secure_zero(h, sizeof(h));
    tamga_secure_zero(j0, sizeof(j0));
    tamga_secure_zero(counter, sizeof(counter));
    tamga_secure_zero(acc, sizeof(acc));
    tamga_secure_zero(keystream, sizeof(keystream));
    return true;
}

bool tamga_gcm_open(const unsigned char key[TAMGA_AES256_KEY_LEN],
                    const unsigned char nonce[TAMGA_GCM_NONCE_LEN], const unsigned char *aad,
                    size_t aad_len, const unsigned char *ciphertext_and_tag, size_t ct_and_tag_len,
                    unsigned char *out, size_t *out_len) {
    unsigned char computed_tag[TAMGA_GCM_TAG_LEN];
    size_t ciphertext_len;
    const unsigned char *tag;
    bool authentic;

    if (out_len == NULL) {
        return false;
    }
    /* Cleared before any other validation, so a caller that inspects the
     * length instead of the return value cannot read a stale one on any
     * failure path. */
    *out_len = 0u;
    if (key == NULL || nonce == NULL || ciphertext_and_tag == NULL) {
        return false;
    }
    /* A null pointer with a non-zero length is a caller bug that would reach
     * memcpy inside GHASH; the plaintext pair below is already guarded and
     * this one should be too. */
    if (aad == NULL && aad_len > 0u) {
        return false;
    }
    if (ct_and_tag_len < TAMGA_GCM_TAG_LEN) {
        return false;
    }
    ciphertext_len = ct_and_tag_len - TAMGA_GCM_TAG_LEN;
    if (ciphertext_len > 0u && out == NULL) {
        return false;
    }
    tag = &ciphertext_and_tag[ciphertext_len];

    /* tamga_gcm_core has no failure path -- it returns true unconditionally,
     * and the return type exists only so a future variant (a hardware-AES
     * path, say) could report one. Discarding it is safe today and would
     * stop being safe silently, so: if that ever changes, both call sites
     * here must be revisited.
     *
     * `out` is the output buffer and `computed_tag` the tag, in that order.
     * clang-tidy's suspicious-argument check matches on name similarity, not
     * on types, and reads them as swapped. */
    /* NOLINTNEXTLINE(readability-suspicious-call-argument) */
    (void)tamga_gcm_core(key, nonce, aad, aad_len, ciphertext_and_tag, ciphertext_len, out,
                         computed_tag, ciphertext_and_tag, ciphertext_len);

    authentic = tamga_ct_memeq(computed_tag, tag, TAMGA_GCM_TAG_LEN);
    tamga_secure_zero(computed_tag, sizeof(computed_tag));

    if (!authentic) {
        /* The plaintext was written before the tag could be checked -- that
         * ordering is inherent to CTR mode. Erasing it here is what keeps the
         * "nothing is written unless the tag verifies" contract true from the
         * caller's point of view. */
        if (out != NULL && ciphertext_len > 0u) {
            tamga_secure_zero(out, ciphertext_len);
        }
        *out_len = 0u;
        return false;
    }

    *out_len = ciphertext_len;
    return true;
}

bool tamga_gcm_seal(const unsigned char key[TAMGA_AES256_KEY_LEN],
                    const unsigned char nonce[TAMGA_GCM_NONCE_LEN], const unsigned char *aad,
                    size_t aad_len, const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *out, size_t *out_len) {
    if (out_len == NULL) {
        return false;
    }
    *out_len = 0u;
    if (key == NULL || nonce == NULL || out == NULL) {
        return false;
    }
    if (plaintext_len > 0u && plaintext == NULL) {
        return false;
    }
    if (aad == NULL && aad_len > 0u) {
        return false;
    }

    (void)tamga_gcm_core(key, nonce, aad, aad_len, plaintext, plaintext_len, out,
                         &out[plaintext_len], out, plaintext_len);
    *out_len = plaintext_len + TAMGA_GCM_TAG_LEN;
    return true;
}
