#include "crypto/p256.h"

#include <string.h>

#include "tamga_mem.h"

#define P256_LIMBS 8

/* p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
static const unsigned char P256_P[32] = {0xffu, 0xffu, 0xffu, 0xffu, 0x00u, 0x00u, 0x00u, 0x01u,
                                         0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                                         0x00u, 0x00u, 0x00u, 0x00u, 0xffu, 0xffu, 0xffu, 0xffu,
                                         0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu};

/* n, the order of the base point */
static const unsigned char P256_N[32] = {0xffu, 0xffu, 0xffu, 0xffu, 0x00u, 0x00u, 0x00u, 0x00u,
                                         0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
                                         0xbcu, 0xe6u, 0xfau, 0xadu, 0xa7u, 0x17u, 0x9eu, 0x84u,
                                         0xf3u, 0xb9u, 0xcau, 0xc2u, 0xfcu, 0x63u, 0x25u, 0x51u};

/* b, the curve constant in y^2 = x^3 - 3x + b */
static const unsigned char P256_B[32] = {0x5au, 0xc6u, 0x35u, 0xd8u, 0xaau, 0x3au, 0x93u, 0xe7u,
                                         0xb3u, 0xebu, 0xbdu, 0x55u, 0x76u, 0x98u, 0x86u, 0xbcu,
                                         0x65u, 0x1du, 0x06u, 0xb0u, 0xccu, 0x53u, 0xb0u, 0xf6u,
                                         0x3bu, 0xceu, 0x3cu, 0x3eu, 0x27u, 0xd2u, 0x60u, 0x4bu};

static const unsigned char P256_GX[32] = {0x6bu, 0x17u, 0xd1u, 0xf2u, 0xe1u, 0x2cu, 0x42u, 0x47u,
                                          0xf8u, 0xbcu, 0xe6u, 0xe5u, 0x63u, 0xa4u, 0x40u, 0xf2u,
                                          0x77u, 0x03u, 0x7du, 0x81u, 0x2du, 0xebu, 0x33u, 0xa0u,
                                          0xf4u, 0xa1u, 0x39u, 0x45u, 0xd8u, 0x98u, 0xc2u, 0x96u};

static const unsigned char P256_GY[32] = {0x4fu, 0xe3u, 0x42u, 0xe2u, 0xfeu, 0x1au, 0x7fu, 0x9bu,
                                          0x8eu, 0xe7u, 0xebu, 0x4au, 0x7cu, 0x0fu, 0x9eu, 0x16u,
                                          0x2bu, 0xceu, 0x33u, 0x57u, 0x6bu, 0x31u, 0x5eu, 0xceu,
                                          0xcbu, 0xb6u, 0x40u, 0x68u, 0x37u, 0xbfu, 0x51u, 0xf5u};

/* --- generic Montgomery arithmetic over a 256-bit odd modulus ---------- */

typedef struct P256Mod {
    uint32_t m[P256_LIMBS];
    uint32_t rr[P256_LIMBS];  /* R^2 mod m */
    uint32_t one[P256_LIMBS]; /* R mod m, i.e. 1 in Montgomery form */
    uint32_t n0inv;
} P256Mod;

typedef uint32_t P256Num[P256_LIMBS];

static void p256_from_be(const unsigned char bytes[32], uint32_t out[P256_LIMBS]) {
    int i;
    for (i = 0; i < P256_LIMBS; i++) {
        size_t offset = (size_t)(28 - (i * 4));
        out[i] = ((uint32_t)bytes[offset] << 24) | ((uint32_t)bytes[offset + 1u] << 16) |
                 ((uint32_t)bytes[offset + 2u] << 8) | (uint32_t)bytes[offset + 3u];
    }
}

static void p256_to_be(const uint32_t value[P256_LIMBS], unsigned char bytes[32]) {
    int i;
    for (i = 0; i < P256_LIMBS; i++) {
        size_t offset = (size_t)(28 - (i * 4));
        bytes[offset] = (unsigned char)(value[i] >> 24);
        bytes[offset + 1u] = (unsigned char)(value[i] >> 16);
        bytes[offset + 2u] = (unsigned char)(value[i] >> 8);
        bytes[offset + 3u] = (unsigned char)value[i];
    }
}

static int p256_cmp(const uint32_t a[P256_LIMBS], const uint32_t b[P256_LIMBS]) {
    int i;
    for (i = P256_LIMBS - 1; i >= 0; i--) {
        if (a[i] != b[i]) {
            return (a[i] < b[i]) ? -1 : 1;
        }
    }
    return 0;
}

static bool p256_is_zero(const uint32_t a[P256_LIMBS]) {
    uint32_t accumulated = 0u;
    int i;
    for (i = 0; i < P256_LIMBS; i++) {
        accumulated |= a[i];
    }
    return accumulated == 0u;
}

static uint32_t p256_sub_raw(uint32_t r[P256_LIMBS], const uint32_t a[P256_LIMBS],
                             const uint32_t b[P256_LIMBS]) {
    uint64_t borrow = 0u;
    int i;
    for (i = 0; i < P256_LIMBS; i++) {
        uint64_t diff = (uint64_t)a[i] - (uint64_t)b[i] - borrow;
        r[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }
    return (uint32_t)borrow;
}

static uint32_t p256_add_raw(uint32_t r[P256_LIMBS], const uint32_t a[P256_LIMBS],
                             const uint32_t b[P256_LIMBS]) {
    uint64_t carry = 0u;
    int i;
    for (i = 0; i < P256_LIMBS; i++) {
        uint64_t sum = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        r[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return (uint32_t)carry;
}

static void p256_mod_add(const P256Mod *ctx, uint32_t r[P256_LIMBS], const uint32_t a[P256_LIMBS],
                         const uint32_t b[P256_LIMBS]) {
    uint32_t carry = p256_add_raw(r, a, b);
    if (carry != 0u || p256_cmp(r, ctx->m) >= 0) {
        (void)p256_sub_raw(r, r, ctx->m);
    }
}

static void p256_mod_sub(const P256Mod *ctx, uint32_t r[P256_LIMBS], const uint32_t a[P256_LIMBS],
                         const uint32_t b[P256_LIMBS]) {
    if (p256_sub_raw(r, a, b) != 0u) {
        (void)p256_add_raw(r, r, ctx->m);
    }
}

static void p256_double_mod(const P256Mod *ctx, uint32_t value[P256_LIMBS]) {
    uint32_t carry = 0u;
    int i;
    for (i = 0; i < P256_LIMBS; i++) {
        uint32_t next = value[i] >> 31;
        value[i] = (value[i] << 1) | carry;
        carry = next;
    }
    if (carry != 0u || p256_cmp(value, ctx->m) >= 0) {
        (void)p256_sub_raw(value, value, ctx->m);
    }
}

static uint32_t p256_n0inv(uint32_t m0) {
    uint32_t inverse = 1u;
    int i;
    for (i = 0; i < 5; i++) {
        inverse *= 2u - (m0 * inverse);
    }
    return (uint32_t)(0u - inverse);
}

/* r = a * b * R^-1 mod m (CIOS). */
static void p256_mont_mul(const P256Mod *ctx, uint32_t r[P256_LIMBS], const uint32_t a[P256_LIMBS],
                          const uint32_t b[P256_LIMBS]) {
    uint32_t t[P256_LIMBS + 2];
    int i;
    int j;

    memset(t, 0, sizeof(t));
    for (i = 0; i < P256_LIMBS; i++) {
        uint64_t carry = 0u;
        uint32_t m;

        for (j = 0; j < P256_LIMBS; j++) {
            uint64_t product = (uint64_t)t[j] + ((uint64_t)a[j] * (uint64_t)b[i]) + carry;
            t[j] = (uint32_t)product;
            carry = product >> 32;
        }
        {
            uint64_t sum = (uint64_t)t[P256_LIMBS] + carry;
            t[P256_LIMBS] = (uint32_t)sum;
            t[P256_LIMBS + 1] = (uint32_t)(sum >> 32);
        }

        m = (uint32_t)((uint64_t)t[0] * (uint64_t)ctx->n0inv);
        carry = ((uint64_t)t[0] + ((uint64_t)m * (uint64_t)ctx->m[0])) >> 32;
        for (j = 1; j < P256_LIMBS; j++) {
            uint64_t product = (uint64_t)t[j] + ((uint64_t)m * (uint64_t)ctx->m[j]) + carry;
            t[j - 1] = (uint32_t)product;
            carry = product >> 32;
        }
        {
            uint64_t sum = (uint64_t)t[P256_LIMBS] + carry;
            t[P256_LIMBS - 1] = (uint32_t)sum;
            t[P256_LIMBS] = (uint32_t)(t[P256_LIMBS + 1] + (uint32_t)(sum >> 32));
        }
    }

    if (t[P256_LIMBS] != 0u || p256_cmp(t, ctx->m) >= 0) {
        (void)p256_sub_raw(r, t, ctx->m);
    } else {
        memcpy(r, t, sizeof(P256Num));
    }
    tamga_secure_zero(t, sizeof(t));
}

static void p256_mod_init(P256Mod *ctx, const unsigned char modulus_be[32]) {
    int i;

    p256_from_be(modulus_be, ctx->m);
    ctx->n0inv = p256_n0inv(ctx->m[0]);

    /* R mod m = R - m, valid because both moduli here have their top bit
     * set, so R/2 < m < R. */
    memset(ctx->one, 0, sizeof(ctx->one));
    (void)p256_sub_raw(ctx->one, ctx->one, ctx->m);

    /* R^2 mod m by doubling R mod m another 256 times -- no division. */
    memcpy(ctx->rr, ctx->one, sizeof(ctx->rr));
    for (i = 0; i < 256; i++) {
        p256_double_mod(ctx, ctx->rr);
    }
}

static void p256_to_mont(const P256Mod *ctx, uint32_t r[P256_LIMBS], const uint32_t a[P256_LIMBS]) {
    p256_mont_mul(ctx, r, a, ctx->rr);
}

static void p256_from_mont(const P256Mod *ctx, uint32_t r[P256_LIMBS],
                           const uint32_t a[P256_LIMBS]) {
    uint32_t one[P256_LIMBS];
    memset(one, 0, sizeof(one));
    one[0] = 1u;
    p256_mont_mul(ctx, r, a, one);
}

/* r = a^-1 in Montgomery form, via Fermat: a^(m-2). Both moduli are prime. */
static void p256_mont_inv(const P256Mod *ctx, uint32_t r[P256_LIMBS],
                          const uint32_t a[P256_LIMBS]) {
    uint32_t exponent[P256_LIMBS];
    uint32_t accumulator[P256_LIMBS];
    uint32_t base[P256_LIMBS];
    uint32_t two[P256_LIMBS];
    int bit;

    memset(two, 0, sizeof(two));
    two[0] = 2u;
    (void)p256_sub_raw(exponent, ctx->m, two);

    memcpy(accumulator, ctx->one, sizeof(accumulator));
    memcpy(base, a, sizeof(base));

    for (bit = 255; bit >= 0; bit--) {
        p256_mont_mul(ctx, accumulator, accumulator, accumulator);
        if (((exponent[bit / 32] >> (bit % 32)) & 1u) != 0u) {
            p256_mont_mul(ctx, accumulator, accumulator, base);
        }
    }
    memcpy(r, accumulator, sizeof(P256Num));
}

/* --- curve points, Jacobian coordinates --------------------------------
 *
 * (X : Y : Z) represents the affine point (X/Z^2, Y/Z^3); Z = 0 is the point
 * at infinity. All field values are held in Montgomery form.
 */
typedef struct P256Point {
    uint32_t x[P256_LIMBS];
    uint32_t y[P256_LIMBS];
    uint32_t z[P256_LIMBS];
} P256Point;

static void p256_point_set_infinity(P256Point *p) {
    memset(p->x, 0, sizeof(p->x));
    memset(p->y, 0, sizeof(p->y));
    memset(p->z, 0, sizeof(p->z));
}

static bool p256_point_is_infinity(const P256Point *p) {
    return p256_is_zero(p->z);
}

/* Doubling for a = -3 (the standard formulas; P-256's a is exactly -3, which
 * is why this shorter chain is available). */
static void p256_point_double(const P256Mod *fp, P256Point *r, const P256Point *p) {
    uint32_t delta[P256_LIMBS];
    uint32_t gamma[P256_LIMBS];
    uint32_t beta[P256_LIMBS];
    uint32_t alpha[P256_LIMBS];
    uint32_t t0[P256_LIMBS];
    uint32_t t1[P256_LIMBS];

    if (p256_point_is_infinity(p)) {
        p256_point_set_infinity(r);
        return;
    }

    p256_mont_mul(fp, delta, p->z, p->z); /* delta = Z^2 */
    p256_mont_mul(fp, gamma, p->y, p->y); /* gamma = Y^2 */
    p256_mont_mul(fp, beta, p->x, gamma); /* beta  = X*gamma */

    p256_mod_sub(fp, t0, p->x, delta);
    p256_mod_add(fp, t1, p->x, delta);
    p256_mont_mul(fp, alpha, t0, t1);
    p256_mod_add(fp, t0, alpha, alpha);
    p256_mod_add(fp, alpha, t0, alpha); /* alpha = 3(X-delta)(X+delta) */

    p256_mont_mul(fp, t0, alpha, alpha);
    p256_mod_add(fp, t1, beta, beta);
    p256_mod_add(fp, t1, t1, t1); /* t1 = 4*beta */
    p256_mod_sub(fp, t0, t0, t1);
    p256_mod_sub(fp, r->x, t0, t1); /* X' = alpha^2 - 8*beta */

    p256_mod_add(fp, t0, p->y, p->z);
    p256_mont_mul(fp, t0, t0, t0);
    p256_mod_sub(fp, t0, t0, gamma);
    p256_mod_sub(fp, r->z, t0, delta); /* Z' = (Y+Z)^2 - gamma - delta */

    p256_mod_sub(fp, t0, t1, r->x); /* 4*beta - X' */
    p256_mont_mul(fp, t0, alpha, t0);
    p256_mont_mul(fp, t1, gamma, gamma);
    p256_mod_add(fp, t1, t1, t1);
    p256_mod_add(fp, t1, t1, t1);
    p256_mod_add(fp, t1, t1, t1); /* 8*gamma^2 */
    p256_mod_sub(fp, r->y, t0, t1);
}

/* Jacobian addition, with the equal-input and infinity cases handled
 * explicitly -- the general formula produces (0:0:0) for P == Q rather than
 * the correct doubling, which is the classic way an ECDSA verifier silently
 * accepts or rejects the wrong thing. */
static void p256_point_add(const P256Mod *fp, P256Point *r, const P256Point *p,
                           const P256Point *q) {
    uint32_t z1z1[P256_LIMBS];
    uint32_t z2z2[P256_LIMBS];
    uint32_t u1[P256_LIMBS];
    uint32_t u2[P256_LIMBS];
    uint32_t s1[P256_LIMBS];
    uint32_t s2[P256_LIMBS];
    uint32_t h[P256_LIMBS];
    uint32_t i[P256_LIMBS];
    uint32_t j[P256_LIMBS];
    uint32_t rr[P256_LIMBS];
    uint32_t v[P256_LIMBS];
    uint32_t t0[P256_LIMBS];

    if (p256_point_is_infinity(p)) {
        memcpy(r, q, sizeof(*r));
        return;
    }
    if (p256_point_is_infinity(q)) {
        memcpy(r, p, sizeof(*r));
        return;
    }

    p256_mont_mul(fp, z1z1, p->z, p->z);
    p256_mont_mul(fp, z2z2, q->z, q->z);
    p256_mont_mul(fp, u1, p->x, z2z2);
    p256_mont_mul(fp, u2, q->x, z1z1);
    p256_mont_mul(fp, s1, p->y, q->z);
    p256_mont_mul(fp, s1, s1, z2z2);
    p256_mont_mul(fp, s2, q->y, p->z);
    p256_mont_mul(fp, s2, s2, z1z1);

    p256_mod_sub(fp, h, u2, u1);
    p256_mod_sub(fp, rr, s2, s1);

    if (p256_is_zero(h)) {
        if (p256_is_zero(rr)) {
            p256_point_double(fp, r, p);
        } else {
            /* Q == -P, so the sum is the point at infinity. */
            p256_point_set_infinity(r);
        }
        return;
    }

    p256_mod_add(fp, i, h, h);
    p256_mont_mul(fp, i, i, i);   /* I = (2H)^2 */
    p256_mont_mul(fp, j, h, i);   /* J = H*I */
    p256_mod_add(fp, rr, rr, rr); /* r = 2(S2-S1) */
    p256_mont_mul(fp, v, u1, i);

    p256_mont_mul(fp, t0, rr, rr);
    p256_mod_sub(fp, t0, t0, j);
    p256_mod_sub(fp, t0, t0, v);
    p256_mod_sub(fp, r->x, t0, v); /* X3 = r^2 - J - 2V */

    p256_mod_sub(fp, t0, v, r->x);
    p256_mont_mul(fp, t0, rr, t0);
    p256_mont_mul(fp, s1, s1, j);
    p256_mod_add(fp, s1, s1, s1);
    p256_mod_sub(fp, r->y, t0, s1); /* Y3 = r*(V-X3) - 2*S1*J */

    p256_mod_add(fp, t0, p->z, q->z);
    p256_mont_mul(fp, t0, t0, t0);
    p256_mod_sub(fp, t0, t0, z1z1);
    p256_mod_sub(fp, t0, t0, z2z2);
    p256_mont_mul(fp, r->z, t0, h); /* Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*H */
}

/* Simultaneous double-and-add of two scalars (Shamir's trick). Not
 * constant-time; both scalars are public. */
static void p256_double_scalar_mul(const P256Mod *fp, P256Point *out, const uint32_t k1[P256_LIMBS],
                                   const P256Point *p1, const uint32_t k2[P256_LIMBS],
                                   const P256Point *p2) {
    P256Point accumulator;
    P256Point sum;
    int bit;

    p256_point_set_infinity(&accumulator);
    p256_point_add(fp, &sum, p1, p2);

    for (bit = 255; bit >= 0; bit--) {
        unsigned int b1 = (k1[bit / 32] >> (bit % 32)) & 1u;
        unsigned int b2 = (k2[bit / 32] >> (bit % 32)) & 1u;

        p256_point_double(fp, &accumulator, &accumulator);
        if (b1 != 0u && b2 != 0u) {
            p256_point_add(fp, &accumulator, &accumulator, &sum);
        } else if (b1 != 0u) {
            p256_point_add(fp, &accumulator, &accumulator, p1);
        } else if (b2 != 0u) {
            p256_point_add(fp, &accumulator, &accumulator, p2);
        }
    }
    memcpy(out, &accumulator, sizeof(*out));
}

/* y^2 == x^3 - 3x + b, with everything in Montgomery form. */
static bool p256_point_is_on_curve(const P256Mod *fp, const uint32_t x[P256_LIMBS],
                                   const uint32_t y[P256_LIMBS]) {
    uint32_t b[P256_LIMBS];
    uint32_t left[P256_LIMBS];
    uint32_t right[P256_LIMBS];
    uint32_t three_x[P256_LIMBS];

    p256_from_be(P256_B, b);
    p256_to_mont(fp, b, b);

    p256_mont_mul(fp, left, y, y);

    p256_mont_mul(fp, right, x, x);
    p256_mont_mul(fp, right, right, x);
    p256_mod_add(fp, three_x, x, x);
    p256_mod_add(fp, three_x, three_x, x);
    p256_mod_sub(fp, right, right, three_x);
    p256_mod_add(fp, right, right, b);

    return p256_cmp(left, right) == 0;
}

bool tamga_p256_verify(const unsigned char public_x[32], const unsigned char public_y[32],
                       const unsigned char digest[32], const unsigned char r[32],
                       const unsigned char s[32]) {
    P256Mod fp;
    P256Mod fn;
    P256Point q;
    P256Point g;
    P256Point point;
    uint32_t r_value[P256_LIMBS];
    uint32_t s_value[P256_LIMBS];
    uint32_t e_value[P256_LIMBS];
    uint32_t w[P256_LIMBS];
    uint32_t u1[P256_LIMBS];
    uint32_t u2[P256_LIMBS];
    uint32_t qx[P256_LIMBS];
    uint32_t qy[P256_LIMBS];
    uint32_t z_inv[P256_LIMBS];
    uint32_t affine_x[P256_LIMBS];
    unsigned char x_bytes[32];
    bool matches;

    if (public_x == NULL || public_y == NULL || digest == NULL || r == NULL || s == NULL) {
        return false;
    }

    p256_mod_init(&fp, P256_P);
    p256_mod_init(&fn, P256_N);

    /* Both coordinates must be proper field elements before they are used --
     * a value at or above p is not a point, it is an encoding error or an
     * attempt to reach an unintended representative. */
    p256_from_be(public_x, qx);
    p256_from_be(public_y, qy);
    if (p256_cmp(qx, fp.m) >= 0 || p256_cmp(qy, fp.m) >= 0) {
        return false;
    }

    p256_to_mont(&fp, q.x, qx);
    p256_to_mont(&fp, q.y, qy);
    memcpy(q.z, fp.one, sizeof(q.z));

    if (!p256_point_is_on_curve(&fp, q.x, q.y)) {
        return false;
    }
    /* The identity is not a valid public key. */
    if (p256_is_zero(qx) && p256_is_zero(qy)) {
        return false;
    }

    /* r and s must lie in [1, n-1]. Zero or out-of-range values are how a
     * verifier that skips this check ends up accepting forged signatures. */
    p256_from_be(r, r_value);
    p256_from_be(s, s_value);
    if (p256_is_zero(r_value) || p256_cmp(r_value, fn.m) >= 0) {
        return false;
    }
    if (p256_is_zero(s_value) || p256_cmp(s_value, fn.m) >= 0) {
        return false;
    }

    /* e is the digest as an integer, reduced mod n. P-256's order and the
     * SHA-256 digest are both 256 bits, so no bit truncation is needed --
     * only the reduction. */
    p256_from_be(digest, e_value);
    if (p256_cmp(e_value, fn.m) >= 0) {
        (void)p256_sub_raw(e_value, e_value, fn.m);
    }

    /* w = s^-1, u1 = e*w, u2 = r*w, all mod n. */
    p256_to_mont(&fn, w, s_value);
    p256_mont_inv(&fn, w, w);
    p256_to_mont(&fn, u1, e_value);
    p256_mont_mul(&fn, u1, u1, w);
    p256_from_mont(&fn, u1, u1);
    p256_to_mont(&fn, u2, r_value);
    p256_mont_mul(&fn, u2, u2, w);
    p256_from_mont(&fn, u2, u2);

    p256_from_be(P256_GX, g.x);
    p256_from_be(P256_GY, g.y);
    p256_to_mont(&fp, g.x, g.x);
    p256_to_mont(&fp, g.y, g.y);
    memcpy(g.z, fp.one, sizeof(g.z));

    p256_double_scalar_mul(&fp, &point, u1, &g, u2, &q);

    if (p256_point_is_infinity(&point)) {
        return false;
    }

    /* Recover the affine x: X/Z^2. */
    p256_mont_mul(&fp, z_inv, point.z, point.z);
    p256_mont_inv(&fp, z_inv, z_inv);
    p256_mont_mul(&fp, affine_x, point.x, z_inv);
    p256_from_mont(&fp, affine_x, affine_x);

    /* The comparison is against r mod n, so a valid x that happens to exceed
     * n must be reduced first. */
    if (p256_cmp(affine_x, fn.m) >= 0) {
        (void)p256_sub_raw(affine_x, affine_x, fn.m);
    }
    p256_to_be(affine_x, x_bytes);

    matches = p256_cmp(affine_x, r_value) == 0;

    tamga_secure_zero(x_bytes, sizeof(x_bytes));
    return matches;
}
