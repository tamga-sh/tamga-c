#include "crypto/ed25519.h"

#include <string.h>

#include "crypto/fe25519.h"
#include "crypto/sha512.h"

/* --- scalars mod L ------------------------------------------------------
 *
 * L = 2^252 + 27742317777372353535851937790883648493, the order of the prime
 * order subgroup.
 */
static const unsigned char TAMGA_SC_L[32] = {
    0xedu, 0xd3u, 0xf5u, 0x5cu, 0x1au, 0x63u, 0x12u, 0x58u, 0xd6u, 0x9cu, 0xf7u,
    0xa2u, 0xdeu, 0xf9u, 0xdeu, 0x14u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x10u};

/* True when the little-endian 32-byte scalar is strictly below L. */
static bool tamga_sc_is_canonical(const unsigned char s[32]) {
    int i;
    for (i = 31; i >= 0; i--) {
        if (s[i] < TAMGA_SC_L[i]) {
            return true;
        }
        if (s[i] > TAMGA_SC_L[i]) {
            return false;
        }
    }
    return false; /* exactly L is not canonical either */
}

static void tamga_sc_load_l(uint32_t out[8]) {
    size_t i;
    for (i = 0u; i < 8u; i++) {
        out[i] = (uint32_t)TAMGA_SC_L[i * 4u] | ((uint32_t)TAMGA_SC_L[(i * 4u) + 1u] << 8) |
                 ((uint32_t)TAMGA_SC_L[(i * 4u) + 2u] << 16) |
                 ((uint32_t)TAMGA_SC_L[(i * 4u) + 3u] << 24);
    }
}

/*
 * Reduces a 64-byte little-endian value modulo L by binary long division:
 * shift one bit of the dividend in at a time, subtracting L whenever the
 * remainder reaches it.
 *
 * This is the slow way -- Barrett reduction with precomputed constants is the
 * usual choice -- and it is here on purpose: it is 30 lines whose correctness
 * is self-evident, it runs 512 iterations of trivial work (microseconds), and
 * the value being reduced is a public hash output, so nothing about it needs
 * to be constant-time. A subtly wrong Barrett constant is a bug that only
 * shows up on a fraction of inputs.
 */
static void tamga_sc_reduce512(const unsigned char in[64], unsigned char out[32]) {
    uint32_t remainder[8];
    uint32_t l[8];
    int bit;
    size_t i;

    memset(remainder, 0, sizeof(remainder));
    tamga_sc_load_l(l);

    for (bit = 511; bit >= 0; bit--) {
        uint32_t carry = (uint32_t)((in[bit / 8] >> (bit % 8)) & 1u);
        uint32_t candidate[8];
        uint64_t borrow = 0u;

        /* remainder = remainder * 2 + next bit. The remainder stays below L,
         * so doubling it cannot exceed 2L < 2^254 and never overflows. */
        for (i = 0u; i < 8u; i++) {
            uint32_t next_carry = remainder[i] >> 31;
            remainder[i] = (remainder[i] << 1) | carry;
            carry = next_carry;
        }

        for (i = 0u; i < 8u; i++) {
            uint64_t diff = (uint64_t)remainder[i] - (uint64_t)l[i] - borrow;
            candidate[i] = (uint32_t)diff;
            borrow = (diff >> 63) & 1u;
        }
        if (borrow == 0u) {
            memcpy(remainder, candidate, sizeof(candidate));
        }
    }

    for (i = 0u; i < 8u; i++) {
        out[i * 4u] = (unsigned char)remainder[i];
        out[(i * 4u) + 1u] = (unsigned char)(remainder[i] >> 8);
        out[(i * 4u) + 2u] = (unsigned char)(remainder[i] >> 16);
        out[(i * 4u) + 3u] = (unsigned char)(remainder[i] >> 24);
    }
}

/* --- group elements -----------------------------------------------------
 *
 * Extended twisted Edwards coordinates (X : Y : Z : T) with x = X/Z,
 * y = Y/Z and x*y = T/Z.
 */
typedef struct TamgaGe {
    TamgaFe x;
    TamgaFe y;
    TamgaFe z;
    TamgaFe t;
} TamgaGe;

/* The compressed base point B: y = 4/5 with the sign bit clear. Decompressed
 * at use rather than carried as a precomputed table -- one decompression per
 * verification is immaterial next to the scalar multiplication, and a wrong
 * digit in a hardcoded table is invisible on inspection. */
static const unsigned char TAMGA_GE_BASE[32] = {
    0x58u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u,
    0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u,
    0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u};

static void tamga_ge_identity(TamgaGe *r) {
    tamga_fe_zero(&r->x);
    tamga_fe_one(&r->y);
    tamga_fe_one(&r->z);
    tamga_fe_zero(&r->t);
}

static void tamga_ge_copy(TamgaGe *r, const TamgaGe *a) {
    tamga_fe_copy(&r->x, &a->x);
    tamga_fe_copy(&r->y, &a->y);
    tamga_fe_copy(&r->z, &a->z);
    tamga_fe_copy(&r->t, &a->t);
}

static void tamga_ge_neg(TamgaGe *r, const TamgaGe *a) {
    tamga_fe_neg(&r->x, &a->x);
    tamga_fe_copy(&r->y, &a->y);
    tamga_fe_copy(&r->z, &a->z);
    tamga_fe_neg(&r->t, &a->t);
}

/*
 * Unified addition (Hisil-Wong-Carter-Dawson, extended coordinates, a = -1).
 *
 * "Unified" is load-bearing: because a = -1 and d is a non-square on this
 * curve, this one formula is complete -- it is correct for P == Q, for the
 * identity, and for inverse pairs, with no exceptional cases to special-case.
 * That is why doubling below just calls this with both arguments equal
 * instead of using a separate, faster dedicated formula: one code path, no
 * exceptional-input branch to get wrong.
 */
static void tamga_ge_add(TamgaGe *r, const TamgaGe *p, const TamgaGe *q) {
    TamgaFe a;
    TamgaFe b;
    TamgaFe c;
    TamgaFe d;
    TamgaFe e;
    TamgaFe f;
    TamgaFe g;
    TamgaFe h;
    TamgaFe tmp;
    TamgaFe two_d;

    tamga_fe_d(&two_d);
    tamga_fe_add(&two_d, &two_d, &two_d);

    tamga_fe_sub(&a, &p->y, &p->x);
    tamga_fe_sub(&tmp, &q->y, &q->x);
    tamga_fe_mul(&a, &a, &tmp);

    tamga_fe_add(&b, &p->y, &p->x);
    tamga_fe_add(&tmp, &q->y, &q->x);
    tamga_fe_mul(&b, &b, &tmp);

    tamga_fe_mul(&c, &p->t, &q->t);
    tamga_fe_mul(&c, &c, &two_d);

    tamga_fe_mul(&d, &p->z, &q->z);
    tamga_fe_add(&d, &d, &d);

    tamga_fe_sub(&e, &b, &a);
    tamga_fe_sub(&f, &d, &c);
    tamga_fe_add(&g, &d, &c);
    tamga_fe_add(&h, &b, &a);

    tamga_fe_mul(&r->x, &e, &f);
    tamga_fe_mul(&r->y, &g, &h);
    tamga_fe_mul(&r->t, &e, &h);
    tamga_fe_mul(&r->z, &f, &g);
}

static void tamga_ge_double(TamgaGe *r, const TamgaGe *p) {
    tamga_ge_add(r, p, p);
}

/* Compresses to the 32-byte encoding: y in little-endian, with the top bit
 * carrying x's sign. */
static void tamga_ge_compress(const TamgaGe *p, unsigned char out[32]) {
    TamgaFe z_inv;
    TamgaFe x;
    TamgaFe y;

    tamga_fe_invert(&z_inv, &p->z);
    tamga_fe_mul(&x, &p->x, &z_inv);
    tamga_fe_mul(&y, &p->y, &z_inv);

    tamga_fe_to_bytes(&y, out);
    out[31] = (unsigned char)(out[31] | (tamga_fe_is_negative(&x) ? 0x80u : 0x00u));
}

/*
 * Decompresses a 32-byte encoding, recovering x from y.
 *
 * x^2 = (y^2 - 1) / (d*y^2 + 1). The square root is taken via the standard
 * candidate-then-correct method: raise to (p+3)/8, and if the candidate
 * squares to -u/v rather than u/v, multiply by sqrt(-1). If neither works
 * there is no square root and the encoding does not name a curve point.
 *
 * Returns false for any encoding that is not a point on the curve -- which is
 * the check that stops an attacker-supplied "public key" from moving the
 * arithmetic onto a different, weaker curve.
 */
static bool tamga_ge_decompress(TamgaGe *r, const unsigned char in[32]) {
    TamgaFe u;
    TamgaFe v;
    TamgaFe v3;
    TamgaFe vxx;
    TamgaFe check;
    TamgaFe d;
    TamgaFe one;
    TamgaFe x;
    unsigned int sign = ((unsigned int)in[31] >> 7) & 1u;

    tamga_fe_from_bytes(&r->y, in); /* clears the sign bit itself */
    tamga_fe_one(&one);
    tamga_fe_d(&d);

    tamga_fe_sq(&u, &r->y);
    tamga_fe_mul(&v, &u, &d);
    tamga_fe_sub(&u, &u, &one); /* u = y^2 - 1 */
    tamga_fe_add(&v, &v, &one); /* v = d*y^2 + 1 */

    /* x = u * v^3 * (u * v^7)^((p-5)/8) -- the standard formulation, which
     * folds the inversion into the exponentiation. */
    tamga_fe_sq(&v3, &v);
    tamga_fe_mul(&v3, &v3, &v); /* v^3 */
    tamga_fe_sq(&x, &v3);
    tamga_fe_mul(&x, &x, &v);
    tamga_fe_mul(&x, &x, &u); /* u * v^7 */
    tamga_fe_pow_p58(&x, &x);
    tamga_fe_mul(&x, &x, &v3);
    tamga_fe_mul(&x, &x, &u);

    tamga_fe_sq(&vxx, &x);
    tamga_fe_mul(&vxx, &vxx, &v);
    tamga_fe_sub(&check, &vxx, &u);
    if (!tamga_fe_is_zero(&check)) {
        TamgaFe sqrtm1;
        tamga_fe_add(&check, &vxx, &u);
        if (!tamga_fe_is_zero(&check)) {
            return false; /* not a square: no such point */
        }
        tamga_fe_sqrtm1(&sqrtm1);
        tamga_fe_mul(&x, &x, &sqrtm1);
    }

    /* x = 0 with the sign bit set has no canonical meaning -- it would be
     * "negative zero". RFC 8032 requires rejecting it. */
    if (tamga_fe_is_zero(&x) && sign != 0u) {
        return false;
    }
    if (tamga_fe_is_negative(&x) != (sign != 0u)) {
        tamga_fe_neg(&x, &x);
    }

    tamga_fe_copy(&r->x, &x);
    tamga_fe_one(&r->z);
    tamga_fe_mul(&r->t, &r->x, &r->y);
    return true;
}

/*
 * Double-and-add, most significant bit first.
 *
 * Not constant-time, and does not need to be: both scalars used during
 * verification are public (one is the signature's own S, the other a hash of
 * public inputs). A signing implementation could not reuse this.
 */
static void tamga_ge_scalarmul(TamgaGe *r, const TamgaGe *p, const unsigned char scalar[32]) {
    TamgaGe accumulator;
    int bit;

    tamga_ge_identity(&accumulator);
    for (bit = 255; bit >= 0; bit--) {
        tamga_ge_double(&accumulator, &accumulator);
        if ((((unsigned int)scalar[bit / 8] >> (bit % 8)) & 1u) != 0u) {
            tamga_ge_add(&accumulator, &accumulator, p);
        }
    }
    tamga_ge_copy(r, &accumulator);
}

bool tamga_ed25519_verify(const unsigned char public_key[TAMGA_ED25519_PUBKEY_LEN],
                          const unsigned char *message, size_t message_len,
                          const unsigned char signature[TAMGA_ED25519_SIG_LEN]) {
    TamgaGe a_point;
    TamgaGe base;
    TamgaGe sb;
    TamgaGe ka;
    TamgaGe computed;
    TamgaSha512 hash;
    unsigned char hash_output[TAMGA_SHA512_DIGEST_LEN];
    unsigned char k[32];
    unsigned char recomputed_r[32];
    int i;
    int difference = 0;

    if (public_key == NULL || signature == NULL) {
        return false;
    }
    if (message == NULL && message_len > 0u) {
        return false;
    }

    /* A non-canonical S is the classic malleability route: it lets a third
     * party derive a different byte string that still verifies. */
    if (!tamga_sc_is_canonical(&signature[32])) {
        return false;
    }

    if (!tamga_ge_decompress(&a_point, public_key)) {
        return false;
    }
    if (!tamga_ge_decompress(&base, TAMGA_GE_BASE)) {
        return false; /* unreachable: the base point is a compile-time constant */
    }

    /* k = SHA-512(R || A || message) mod L */
    tamga_sha512_init(&hash);
    tamga_sha512_update(&hash, signature, 32u);
    tamga_sha512_update(&hash, public_key, TAMGA_ED25519_PUBKEY_LEN);
    tamga_sha512_update(&hash, message, message_len);
    tamga_sha512_final(&hash, hash_output);
    tamga_sc_reduce512(hash_output, k);

    /* R' = [S]B - [k]A */
    tamga_ge_scalarmul(&sb, &base, &signature[32]);
    tamga_ge_neg(&a_point, &a_point);
    tamga_ge_scalarmul(&ka, &a_point, k);
    tamga_ge_add(&computed, &sb, &ka);
    tamga_ge_compress(&computed, recomputed_r);

    /* Compared byte-wise against the signature's own R, which also rejects a
     * non-canonical encoding of R: the recomputed form is always canonical.
     * Accumulated rather than short-circuited -- there is no secret here, but
     * a comparison loop that can be told where to stop is a habit worth not
     * forming. */
    for (i = 0; i < 32; i++) {
        difference |= (int)(recomputed_r[i] ^ signature[i]);
    }
    return difference == 0;
}
