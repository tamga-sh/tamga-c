#include "crypto/bn.h"

#include <stdint.h>
#include <string.h>

#include "tamga_mem.h"

/* 32-bit limbs, least significant first. */
#define TAMGA_BN_MAX_LIMBS (TAMGA_BN_MAX_BYTES / 4u)

/* Bit `index` of a big-endian byte string, counting 0 as the least
 * significant bit of the last byte. */
static unsigned int tamga_bn_be_bit(const unsigned char *bytes, size_t byte_len, size_t index)
{
    size_t byte_from_end = index / 8u;
    unsigned int shift = (unsigned int)(index % 8u);
    return ((unsigned int)bytes[byte_len - 1u - byte_from_end] >> shift) & 1u;
}

static size_t tamga_bn_limbs_for(size_t byte_len)
{
    return (byte_len + 3u) / 4u;
}

/* Loads a big-endian byte string into little-endian limbs, zero-padding the
 * top. */
static void tamga_bn_from_be(const unsigned char *bytes, size_t byte_len,
                             uint32_t *limbs, size_t limb_count)
{
    size_t i;

    memset(limbs, 0, limb_count * sizeof(uint32_t));
    for (i = 0u; i < byte_len; i++) {
        size_t offset = byte_len - 1u - i; /* distance from the least significant end */
        size_t limb = offset / 4u;
        unsigned int shift = (unsigned int)((offset % 4u) * 8u);
        if (limb < limb_count) {
            limbs[limb] |= (uint32_t)bytes[i] << shift;
        }
    }
}

static void tamga_bn_to_be(const uint32_t *limbs, size_t limb_count,
                           unsigned char *bytes, size_t byte_len)
{
    size_t i;

    for (i = 0u; i < byte_len; i++) {
        size_t offset = byte_len - 1u - i;
        size_t limb = offset / 4u;
        unsigned int shift = (unsigned int)((offset % 4u) * 8u);
        bytes[i] = (limb < limb_count) ? (unsigned char)(limbs[limb] >> shift) : 0u;
    }
}

/* Returns -1, 0 or 1. */
static int tamga_bn_cmp(const uint32_t *a, const uint32_t *b, size_t n)
{
    size_t i = n;
    while (i > 0u) {
        i--;
        if (a[i] != b[i]) {
            return (a[i] < b[i]) ? -1 : 1;
        }
    }
    return 0;
}

/* r = a - b, returning the final borrow. */
static uint32_t tamga_bn_sub(uint32_t *r, const uint32_t *a, const uint32_t *b, size_t n)
{
    uint64_t borrow = 0u;
    size_t i;

    for (i = 0u; i < n; i++) {
        uint64_t diff = (uint64_t)a[i] - (uint64_t)b[i] - borrow;
        r[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }
    return (uint32_t)borrow;
}

/* value = value * 2 mod modulus, for value < modulus. */
static void tamga_bn_double_mod(uint32_t *value, const uint32_t *modulus, size_t n)
{
    uint32_t carry = 0u;
    size_t i;

    for (i = 0u; i < n; i++) {
        uint32_t next_carry = value[i] >> 31;
        value[i] = (value[i] << 1) | carry;
        carry = next_carry;
    }
    /* The doubled value is below 2*modulus, so at most one subtraction is
     * needed. When the shift carried out of the top limb the true value
     * exceeds 2^(32n) and therefore certainly exceeds the modulus; the
     * n-limb subtraction below wraps in exactly the right way. */
    if (carry != 0u || tamga_bn_cmp(value, modulus, n) >= 0) {
        (void)tamga_bn_sub(value, value, modulus, n);
    }
}

/* -modulus[0]^-1 mod 2^32, by Newton iteration. Requires an odd modulus,
 * which every RSA modulus is. */
static uint32_t tamga_bn_n0inv(uint32_t m0)
{
    uint32_t inverse = 1u;
    int i;

    /* Each step doubles the number of correct bits: 2, 4, 8, 16, 32. */
    for (i = 0; i < 5; i++) {
        inverse *= 2u - (m0 * inverse);
    }
    return (uint32_t)(0u - inverse);
}

/*
 * Montgomery multiplication, CIOS form: r = a * b * R^-1 mod modulus, where
 * R = 2^(32n).
 */
static void tamga_bn_mont_mul(uint32_t *r, const uint32_t *a, const uint32_t *b,
                              const uint32_t *modulus, size_t n, uint32_t n0inv)
{
    uint32_t t[TAMGA_BN_MAX_LIMBS + 2];
    size_t i;
    size_t j;

    memset(t, 0, (n + 2u) * sizeof(uint32_t));

    for (i = 0u; i < n; i++) {
        uint64_t carry = 0u;
        uint32_t m;

        for (j = 0u; j < n; j++) {
            uint64_t product = (uint64_t)t[j] + ((uint64_t)a[j] * (uint64_t)b[i]) + carry;
            t[j] = (uint32_t)product;
            carry = product >> 32;
        }
        {
            uint64_t sum = (uint64_t)t[n] + carry;
            t[n] = (uint32_t)sum;
            t[n + 1u] = (uint32_t)(sum >> 32);
        }

        /* Choose m so that t + m*modulus is divisible by 2^32, then shift one
         * limb down -- that division is what Montgomery form buys. */
        m = (uint32_t)((uint64_t)t[0] * (uint64_t)n0inv);
        carry = 0u;
        {
            uint64_t product = (uint64_t)t[0] + ((uint64_t)m * (uint64_t)modulus[0]);
            carry = product >> 32;
        }
        for (j = 1u; j < n; j++) {
            uint64_t product = (uint64_t)t[j] + ((uint64_t)m * (uint64_t)modulus[j]) + carry;
            t[j - 1u] = (uint32_t)product;
            carry = product >> 32;
        }
        {
            uint64_t sum = (uint64_t)t[n] + carry;
            t[n - 1u] = (uint32_t)sum;
            t[n] = (uint32_t)(t[n + 1u] + (uint32_t)(sum >> 32));
        }
    }

    /* One conditional subtraction brings the result below the modulus. */
    if (t[n] != 0u || tamga_bn_cmp(t, modulus, n) >= 0) {
        (void)tamga_bn_sub(r, t, modulus, n);
    } else {
        memcpy(r, t, n * sizeof(uint32_t));
    }

    tamga_secure_zero(t, sizeof(t));
}

bool tamga_bn_modexp(const unsigned char *base, const unsigned char *modulus, size_t mod_len,
                     const unsigned char *exponent, size_t exp_len, unsigned char *out)
{
    uint32_t m[TAMGA_BN_MAX_LIMBS];
    uint32_t b[TAMGA_BN_MAX_LIMBS];
    uint32_t rr[TAMGA_BN_MAX_LIMBS];
    uint32_t acc[TAMGA_BN_MAX_LIMBS];
    uint32_t base_mont[TAMGA_BN_MAX_LIMBS];
    size_t n;
    size_t i;
    uint32_t n0inv;
    int highest_bit = -1;

    if (base == NULL || modulus == NULL || exponent == NULL || out == NULL) {
        return false;
    }
    if (mod_len == 0u || mod_len > TAMGA_BN_MAX_BYTES || exp_len == 0u || exp_len > mod_len) {
        return false;
    }

    n = tamga_bn_limbs_for(mod_len);
    tamga_bn_from_be(modulus, mod_len, m, n);
    tamga_bn_from_be(base, mod_len, b, n);

    /* An even modulus has no inverse mod 2^32, so Montgomery form does not
     * exist for it; a modulus without its top bit set breaks the "R - m < m"
     * shortcut below. Both are true of every real RSA modulus, so rejecting
     * them costs nothing and keeps the preconditions explicit. */
    if ((m[0] & 1u) == 0u) {
        return false;
    }
    if ((m[n - 1u] & 0x80000000u) == 0u) {
        return false;
    }
    /* RSA requires the signature representative to be less than the modulus;
     * a larger one is a malformed signature, not something to reduce. */
    if (tamga_bn_cmp(b, m, n) >= 0) {
        return false;
    }

    n0inv = tamga_bn_n0inv(m[0]);

    /* R mod m. Because the modulus has its top bit set, R/2 < m < R, so
     * R mod m is simply R - m -- which n-limb two's-complement subtraction
     * from zero produces directly. */
    memset(rr, 0, n * sizeof(uint32_t));
    (void)tamga_bn_sub(rr, rr, m, n);

    /* R^2 mod m, by doubling R mod m another 32n times. This is why no
     * general division routine is needed anywhere in this file. */
    for (i = 0u; i < (n * 32u); i++) {
        tamga_bn_double_mod(rr, m, n);
    }

    /* acc = R mod m, the Montgomery representation of 1. */
    memset(acc, 0, n * sizeof(uint32_t));
    (void)tamga_bn_sub(acc, acc, m, n);

    tamga_bn_mont_mul(base_mont, b, rr, m, n, n0inv);

    /* Square-and-multiply from the exponent's most significant set bit. The
     * exponent is public (65537 in practice), so a plain binary ladder with
     * an input-dependent branch is appropriate here. */
    for (i = exp_len * 8u; i > 0u; i--) {
        if (tamga_bn_be_bit(exponent, exp_len, i - 1u) != 0u) {
            highest_bit = (int)(i - 1u);
            break;
        }
    }
    if (highest_bit < 0) {
        return false; /* exponent zero: not a usable RSA public exponent */
    }

    for (i = 0u; i <= (size_t)highest_bit; i++) {
        size_t bit_index = (size_t)highest_bit - i;
        tamga_bn_mont_mul(acc, acc, acc, m, n, n0inv);
        if (tamga_bn_be_bit(exponent, exp_len, bit_index) != 0u) {
            tamga_bn_mont_mul(acc, acc, base_mont, m, n, n0inv);
        }
    }

    /* Convert out of Montgomery form: multiplying by 1 divides by R. */
    {
        uint32_t one[TAMGA_BN_MAX_LIMBS];
        memset(one, 0, n * sizeof(uint32_t));
        one[0] = 1u;
        tamga_bn_mont_mul(acc, acc, one, m, n, n0inv);
        tamga_secure_zero(one, n * sizeof(uint32_t));
    }

    tamga_bn_to_be(acc, n, out, mod_len);

    tamga_secure_zero(b, sizeof(b));
    tamga_secure_zero(rr, sizeof(rr));
    tamga_secure_zero(acc, sizeof(acc));
    tamga_secure_zero(base_mont, sizeof(base_mont));
    return true;
}
