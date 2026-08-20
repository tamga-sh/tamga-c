#include "crypto/fe25519.h"

#include <stddef.h>
#include <string.h>

/* p = 2^255 - 19, little-endian limbs. */
static const uint32_t TAMGA_FE_P[8] = {0xffffffedu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
                                       0xffffffffu, 0xffffffffu, 0xffffffffu, 0x7fffffffu};

/* d = -121665/121666 mod p, little-endian. */
static const unsigned char TAMGA_FE_D_BYTES[32] = {
    0xa3u, 0x78u, 0x59u, 0x13u, 0xcau, 0x4du, 0xebu, 0x75u, 0xabu, 0xd8u, 0x41u,
    0x41u, 0x4du, 0x0au, 0x70u, 0x00u, 0x98u, 0xe8u, 0x79u, 0x77u, 0x79u, 0x40u,
    0xc7u, 0x8cu, 0x73u, 0xfeu, 0x6fu, 0x2bu, 0xeeu, 0x6cu, 0x03u, 0x52u};

/* sqrt(-1) mod p, little-endian. */
static const unsigned char TAMGA_FE_SQRTM1_BYTES[32] = {
    0xb0u, 0xa0u, 0x0eu, 0x4au, 0x27u, 0x1bu, 0xeeu, 0xc4u, 0x78u, 0xe4u, 0x2fu,
    0xadu, 0x06u, 0x18u, 0x43u, 0x2fu, 0xa7u, 0xd7u, 0xfbu, 0x3du, 0x99u, 0x00u,
    0x4du, 0x2bu, 0x0bu, 0xdfu, 0xc1u, 0x4fu, 0x80u, 0x24u, 0x83u, 0x2bu};

/* Subtracts p once if the value is at least p. Applied twice by callers whose
 * input can exceed 2p. */
static void tamga_fe_conditional_sub_p(uint32_t v[8]) {
    uint32_t candidate[8];
    uint64_t borrow = 0u;
    int i;

    for (i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)v[i] - (uint64_t)TAMGA_FE_P[i] - borrow;
        candidate[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }
    if (borrow == 0u) {
        memcpy(v, candidate, sizeof(candidate));
    }
}

/*
 * Adds carry * 2^256 back into v, repeating until nothing is left over.
 *
 * ONE PASS IS NOT ENOUGH, and assuming it is was a real defect here: v at
 * this point is an arbitrary residue mod 2^256, so it can land within a few
 * hundred of 2^256, and adding 38*carry then carries out again. Discarding
 * that second carry leaves the result wrong by a multiple of 2^256 == 38.
 *
 * It is not a rare corner either. (p-38) * (p-1) must be 38, and with a
 * single fold it came out as 0 -- for two ordinary, fully reduced operands,
 * one of which is just the encoding of -1 that fe_sub and fe_neg produce
 * constantly. Random inputs almost never land in the window, which is exactly
 * why the RFC 8032 vectors passed: known-answer tests over realistic values
 * cannot find this, and only a direct extremal-operand test can. See
 * tests/unit/fe25519_test.c.
 */
static void tamga_fe_fold_carry(uint32_t v[8], uint64_t carry) {
    while (carry != 0u) {
        uint64_t c = 38ull * carry;
        int i;
        for (i = 0; i < 8; i++) {
            uint64_t t = (uint64_t)v[i] + c;
            v[i] = (uint32_t)t;
            c = t >> 32;
            if (c == 0u) {
                break;
            }
        }
        carry = c;
    }
}

/* Folds any content at or above 2^255 back down (2^255 == 19 mod p) and then
 * normalises into [0, p). */
static void tamga_fe_reduce(uint32_t v[8]) {
    int pass;

    for (pass = 0; pass < 3; pass++) {
        uint64_t carry = 19ull * (uint64_t)(v[7] >> 31);
        int i;
        if (carry == 0u) {
            break;
        }
        v[7] &= 0x7fffffffu;
        for (i = 0; i < 8 && carry != 0u; i++) {
            uint64_t t = (uint64_t)v[i] + carry;
            v[i] = (uint32_t)t;
            carry = t >> 32;
        }
    }
    v[7] &= 0x7fffffffu;
    tamga_fe_conditional_sub_p(v);
}

void tamga_fe_zero(TamgaFe *r) {
    memset(r->v, 0, sizeof(r->v));
}

void tamga_fe_one(TamgaFe *r) {
    memset(r->v, 0, sizeof(r->v));
    r->v[0] = 1u;
}

void tamga_fe_copy(TamgaFe *r, const TamgaFe *a) {
    memcpy(r->v, a->v, sizeof(r->v));
}

void tamga_fe_add(TamgaFe *r, const TamgaFe *a, const TamgaFe *b) {
    uint64_t carry = 0u;
    int i;

    for (i = 0; i < 8; i++) {
        uint64_t t = (uint64_t)a->v[i] + (uint64_t)b->v[i] + carry;
        r->v[i] = (uint32_t)t;
        carry = t >> 32;
    }
    /* a and b are both < p < 2^255, so the sum cannot reach 2^256 and the
     * carry out is always zero; folding it in anyway keeps this correct if a
     * caller ever passes a partially reduced value. */
    tamga_fe_fold_carry(r->v, carry);
    tamga_fe_reduce(r->v);
}

void tamga_fe_sub(TamgaFe *r, const TamgaFe *a, const TamgaFe *b) {
    uint64_t borrow = 0u;
    int i;

    for (i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)a->v[i] - (uint64_t)b->v[i] - borrow;
        r->v[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }
    if (borrow != 0u) {
        /* a - b went negative; add p to land back in [0, p). */
        uint64_t carry = 0u;
        for (i = 0; i < 8; i++) {
            uint64_t t = (uint64_t)r->v[i] + (uint64_t)TAMGA_FE_P[i] + carry;
            r->v[i] = (uint32_t)t;
            carry = t >> 32;
        }
    }
    tamga_fe_reduce(r->v);
}

void tamga_fe_neg(TamgaFe *r, const TamgaFe *a) {
    TamgaFe zero;
    tamga_fe_zero(&zero);
    tamga_fe_sub(r, &zero, a);
}

void tamga_fe_mul(TamgaFe *r, const TamgaFe *a, const TamgaFe *b) {
    uint32_t product[16];
    uint64_t carry;
    int i;
    int j;

    memset(product, 0, sizeof(product));

    /* Schoolbook 8x8 -> 16 limbs. The inner loop carries as it goes, so no
     * accumulator ever needs more than 64 bits: the worst case term is
     * (2^32-1)^2 + 2*(2^32-1), which is exactly 2^64 - 1. */
    for (i = 0; i < 8; i++) {
        carry = 0u;
        for (j = 0; j < 8; j++) {
            uint64_t t = ((uint64_t)a->v[i] * (uint64_t)b->v[j]) + (uint64_t)product[i + j] + carry;
            product[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        /* product[i + 8] has not been written yet by any earlier i, so this
         * is an assignment rather than an addition. */
        product[i + 8] = (uint32_t)carry;
    }

    /* Fold the high half down: 2^256 == 38 (mod p). */
    carry = 0u;
    for (i = 0; i < 8; i++) {
        uint64_t t = (uint64_t)product[i] + (38ull * (uint64_t)product[i + 8]) + carry;
        r->v[i] = (uint32_t)t;
        carry = t >> 32;
    }
    /* The leftover carry is small, but folding it can carry out again -- see
     * tamga_fe_fold_carry, which is why this is a loop and not an if. */
    tamga_fe_fold_carry(r->v, carry);
    tamga_fe_reduce(r->v);
}

void tamga_fe_sq(TamgaFe *r, const TamgaFe *a) {
    tamga_fe_mul(r, a, a);
}

/* Square-and-multiply over a little-endian 32-byte exponent, most significant
 * bit first. The exponents used here are the two fixed field constants below,
 * both public, so a simple binary ladder is appropriate. */
static void tamga_fe_pow(TamgaFe *r, const TamgaFe *a, const unsigned char exponent[32]) {
    TamgaFe result;
    TamgaFe base;
    int bit;

    tamga_fe_one(&result);
    tamga_fe_copy(&base, a);

    for (bit = 255; bit >= 0; bit--) {
        unsigned int e = ((unsigned int)exponent[bit / 8] >> (bit % 8)) & 1u;
        tamga_fe_sq(&result, &result);
        if (e != 0u) {
            tamga_fe_mul(&result, &result, &base);
        }
    }
    tamga_fe_copy(r, &result);
}

void tamga_fe_invert(TamgaFe *r, const TamgaFe *a) {
    /* p - 2 = 2^255 - 21 */
    static const unsigned char exponent[32] = {
        0xebu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0x7fu};
    tamga_fe_pow(r, a, exponent);
}

void tamga_fe_pow_p58(TamgaFe *r, const TamgaFe *a) {
    /* (p - 5) / 8 = 2^252 - 3 */
    static const unsigned char exponent[32] = {
        0xfdu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0x0fu};
    tamga_fe_pow(r, a, exponent);
}

bool tamga_fe_is_zero(const TamgaFe *a) {
    uint32_t accumulated = 0u;
    int i;
    for (i = 0; i < 8; i++) {
        accumulated |= a->v[i];
    }
    return accumulated == 0u;
}

bool tamga_fe_equal(const TamgaFe *a, const TamgaFe *b) {
    uint32_t difference = 0u;
    int i;
    for (i = 0; i < 8; i++) {
        difference |= (a->v[i] ^ b->v[i]);
    }
    return difference == 0u;
}

bool tamga_fe_is_negative(const TamgaFe *a) {
    return (a->v[0] & 1u) != 0u;
}

void tamga_fe_to_bytes(const TamgaFe *a, unsigned char out[32]) {
    uint32_t v[8];
    size_t i;

    memcpy(v, a->v, sizeof(v));
    tamga_fe_reduce(v);
    for (i = 0u; i < 8u; i++) {
        out[i * 4u] = (unsigned char)v[i];
        out[(i * 4u) + 1u] = (unsigned char)(v[i] >> 8);
        out[(i * 4u) + 2u] = (unsigned char)(v[i] >> 16);
        out[(i * 4u) + 3u] = (unsigned char)(v[i] >> 24);
    }
}

void tamga_fe_from_bytes(TamgaFe *r, const unsigned char in[32]) {
    size_t i;
    for (i = 0u; i < 8u; i++) {
        r->v[i] = (uint32_t)in[i * 4u] | ((uint32_t)in[(i * 4u) + 1u] << 8) |
                  ((uint32_t)in[(i * 4u) + 2u] << 16) | ((uint32_t)in[(i * 4u) + 3u] << 24);
    }
    r->v[7] &= 0x7fffffffu; /* the top bit is the sign flag, never part of y */
    tamga_fe_reduce(r->v);
}

void tamga_fe_d(TamgaFe *r) {
    tamga_fe_from_bytes(r, TAMGA_FE_D_BYTES);
}

void tamga_fe_sqrtm1(TamgaFe *r) {
    tamga_fe_from_bytes(r, TAMGA_FE_SQRTM1_BYTES);
}
