/*
 * P-256's modular arithmetic, tested directly rather than only through ECDSA.
 *
 * p256_mont_mul is a hand-written CIOS carry chain -- the same shape of code
 * as tamga_fe_mul, where a folded-once-instead-of-twice carry survived the
 * entire RFC 8032 suite and cost real time to find. This file exists so that
 * the same class of defect here is found by arithmetic that names it, not by
 * a signature that mysteriously stops verifying.
 *
 * What this file is measured to be worth, rather than assumed to be:
 *
 *  - Two carry-chain mutations of p256_mont_mul (dropping the reduction's
 *    final carry-out; ignoring the overflow limb in the conditional
 *    subtraction) are caught by every test here. Both are also caught by the
 *    existing ECDSA and fixture suites -- so unlike fe25519_test.c, this file
 *    is not closing a hole those suites cannot reach.
 *
 *  - The reason is quantitative. One P-256 verification performs ~2400
 *    modular multiplications, and the conditional reduction fires on about
 *    14% of them, so a defect with any appreciable operand incidence is hit
 *    with near-certainty by a single real signature. Curve25519's defect
 *    escaped because it needed the intermediate to land within a few hundred
 *    of 2^256; the analogous P-256 window ([m, m+2^32)) measured 0 hits in
 *    2400 calls, which makes a defect confined to it unreachable in
 *    production as well as in tests.
 *
 * So the value here is precision and reach, not raw coverage: a failure
 * points at the multiplication instead of at a verdict, the operand regions
 * exercised (values immediately below the modulus, and the scalar modulus n,
 * whose limb pattern is dense where p's is all-ones and all-zeros) are ones
 * real signatures do not visit, and the inverse chain and the curve equation
 * get checked against identities that need no external reference.
 *
 * The source is included rather than linked because the arithmetic is
 * static, as it should be: nothing outside p256.c needs it, and exposing it
 * for a test would put a test-only symbol in the library.
 */
#include "tamga_test.h"

#include "crypto/p256.c" /* NOLINT(bugprone-suspicious-include) -- whitebox, see above */

/* Multiplies through the Montgomery domain, so the result is an ordinary
 * residue and the vectors below can be written as plain integers. */
static void mod_mul(const P256Mod *ctx, uint32_t r[P256_LIMBS], const uint32_t a[P256_LIMBS],
                    const uint32_t b[P256_LIMBS]) {
    P256Num am;
    P256Num bm;
    p256_to_mont(ctx, am, a);
    p256_to_mont(ctx, bm, b);
    p256_mont_mul(ctx, r, am, bm);
    p256_from_mont(ctx, r, r);
}

static void num_small(uint32_t out[P256_LIMBS], uint32_t value) {
    memset(out, 0, sizeof(uint32_t) * P256_LIMBS);
    out[0] = value;
}

/* m - value, for a small value. */
static void num_near_modulus(const P256Mod *ctx, uint32_t out[P256_LIMBS], uint32_t value) {
    P256Num small;
    num_small(small, value);
    (void)p256_sub_raw(out, ctx->m, small);
}

static bool num_eq(const uint32_t a[P256_LIMBS], const uint32_t b[P256_LIMBS]) {
    return memcmp(a, b, sizeof(uint32_t) * P256_LIMBS) == 0;
}

static void report(const char *what, unsigned int i, unsigned int j) {
    tt_failures_++;
    (void)fprintf(stderr, "FAIL %s: %s at (%u, %u)\n", tt_current_, what, i, j);
}

/*
 * (m-a)(m-b) == ab mod m, for every small a and b.
 *
 * The identity is exact -- (m-a)(m-b) = m^2 - (a+b)m + ab -- so no external
 * reference is needed, and every operand sits in the top few hundred values
 * below the modulus, which is precisely the window a mishandled final carry
 * gets wrong. This is the shape of test that catches the Curve25519 defect;
 * running it against both p and n is the point of the file.
 */
static void check_near_modulus_products(const P256Mod *ctx) {
    unsigned int a;
    unsigned int b;

    for (a = 1u; a <= 24u; a++) {
        for (b = 1u; b <= 24u; b++) {
            P256Num left_a;
            P256Num left_b;
            P256Num got;
            P256Num expected;

            num_near_modulus(ctx, left_a, a);
            num_near_modulus(ctx, left_b, b);
            mod_mul(ctx, got, left_a, left_b);

            num_small(expected, a * b);
            if (!num_eq(got, expected)) {
                report("(m-a)(m-b) != ab", a, b);
                return;
            }
        }
    }
}

TT_TEST(products_just_below_the_modulus_are_exact) {
    P256Mod fp;
    P256Mod fn;

    p256_mod_init(&fp, P256_P);
    p256_mod_init(&fn, P256_N);

    check_near_modulus_products(&fp);
    check_near_modulus_products(&fn);
}

/*
 * a(b + c) == ab + ac, over operands that cluster under the modulus.
 *
 * Distributivity constrains the multiplication against the (much simpler,
 * separately reviewable) modular addition, so it fails loudly for a carry
 * that is dropped in one path and not the other -- without anyone having to
 * enumerate which operands are dangerous.
 */
static void check_distributive(const P256Mod *ctx, unsigned int rounds) {
    unsigned int round;
    uint32_t seed = 0x9e3779b9u;

    for (round = 0u; round < rounds; round++) {
        P256Num a;
        P256Num b;
        P256Num c;
        P256Num sum;
        P256Num left;
        P256Num ab;
        P256Num ac;
        P256Num right;
        int i;

        /* A quarter of the rounds are pinned just under the modulus, the
         * rest spread out; a modulus-adjacent operand is what makes the
         * intermediate land near 2^256. */
        for (i = 0; i < P256_LIMBS; i++) {
            seed = (seed * 1664525u) + 1013904223u;
            a[i] = seed;
            seed = (seed * 1664525u) + 1013904223u;
            b[i] = seed;
            seed = (seed * 1664525u) + 1013904223u;
            c[i] = seed;
        }
        if ((round % 4u) == 0u) {
            num_near_modulus(ctx, a, (round % 17u) + 1u);
        }
        if ((round % 4u) == 1u) {
            num_near_modulus(ctx, b, (round % 13u) + 1u);
        }
        /* Reduce anything that landed at or above the modulus. */
        while (p256_cmp(a, ctx->m) >= 0) {
            (void)p256_sub_raw(a, a, ctx->m);
        }
        while (p256_cmp(b, ctx->m) >= 0) {
            (void)p256_sub_raw(b, b, ctx->m);
        }
        while (p256_cmp(c, ctx->m) >= 0) {
            (void)p256_sub_raw(c, c, ctx->m);
        }

        p256_mod_add(ctx, sum, b, c);
        mod_mul(ctx, left, a, sum);

        mod_mul(ctx, ab, a, b);
        mod_mul(ctx, ac, a, c);
        p256_mod_add(ctx, right, ab, ac);

        if (!num_eq(left, right)) {
            report("a(b+c) != ab+ac", round, 0u);
            return;
        }
    }
}

TT_TEST(multiplication_distributes_over_addition) {
    P256Mod fp;
    P256Mod fn;

    p256_mod_init(&fp, P256_P);
    p256_mod_init(&fn, P256_N);

    check_distributive(&fp, 1500u);
    check_distributive(&fn, 1500u);
}

/*
 * x * x^-1 == 1.
 *
 * p256_mont_inv is a long exponentiation chain built out of the same
 * multiplication, so this composes hundreds of products per value and
 * checks the whole chain against a result that is known without a
 * reference. The inverse is also the one place a wrong result silently
 * turns a valid signature into an invalid one rather than crashing.
 */
static void check_inverses(const P256Mod *ctx) {
    unsigned int round;
    uint32_t seed = 0x243f6a88u;

    for (round = 0u; round < 24u; round++) {
        P256Num x;
        P256Num xm;
        P256Num inv;
        P256Num product;
        int i;

        if (round < 8u) {
            num_near_modulus(ctx, x, round + 1u);
        } else if (round < 12u) {
            num_small(x, round - 7u);
        } else {
            for (i = 0; i < P256_LIMBS; i++) {
                seed = (seed * 1664525u) + 1013904223u;
                x[i] = seed;
            }
            while (p256_cmp(x, ctx->m) >= 0) {
                (void)p256_sub_raw(x, x, ctx->m);
            }
        }
        if (p256_is_zero(x)) {
            continue;
        }

        p256_to_mont(ctx, xm, x);
        p256_mont_inv(ctx, inv, xm);
        p256_mont_mul(ctx, product, xm, inv);
        p256_from_mont(ctx, product, product);

        {
            P256Num one;
            num_small(one, 1u);
            if (!num_eq(product, one)) {
                report("x * x^-1 != 1", round, 0u);
                return;
            }
        }
    }
}

TT_TEST(every_nonzero_value_has_a_working_inverse) {
    P256Mod fp;
    P256Mod fn;

    p256_mod_init(&fp, P256_P);
    p256_mod_init(&fn, P256_N);

    check_inverses(&fp);
    check_inverses(&fn);
}

/*
 * Conversion into and out of the Montgomery domain must be the identity, and
 * must stay so for values immediately below the modulus -- to_mont is itself
 * a multiplication by R^2, so this is another direct exercise of the same
 * carry chain with a result nobody has to look up.
 */
TT_TEST(montgomery_conversion_round_trips) {
    static const unsigned char *const moduli[2] = {P256_P, P256_N};
    unsigned int which;

    for (which = 0u; which < 2u; which++) {
        P256Mod ctx;
        unsigned int k;

        p256_mod_init(&ctx, moduli[which]);
        for (k = 1u; k <= 64u; k++) {
            P256Num x;
            P256Num round_tripped;

            num_near_modulus(&ctx, x, k);
            p256_to_mont(&ctx, round_tripped, x);
            p256_from_mont(&ctx, round_tripped, round_tripped);
            if (!num_eq(round_tripped, x)) {
                report("to_mont/from_mont is not the identity", which, k);
                return;
            }
        }
    }
}

/*
 * The curve constant b is not an arbitrary number: it is defined so that the
 * curve has the published order, and NIST publishes SHA-1(seed) as its
 * provenance. What is checkable here without a second implementation is that
 * the generator satisfies the curve equation under this file's own
 * arithmetic -- which pins the constant, the field modulus and the
 * multiplication together. A transposed byte in any of the three breaks it.
 */
TT_TEST(the_generator_satisfies_the_curve_equation) {
    P256Mod fp;
    P256Num x;
    P256Num y;
    P256Num b;
    P256Num three;
    P256Num lhs;
    P256Num rhs;
    P256Num tmp;

    p256_mod_init(&fp, P256_P);
    p256_from_be(P256_GX, x);
    p256_from_be(P256_GY, y);
    p256_from_be(P256_B, b);
    num_small(three, 3u);

    /* y^2 */
    mod_mul(&fp, lhs, y, y);

    /* x^3 - 3x + b */
    mod_mul(&fp, rhs, x, x);
    mod_mul(&fp, rhs, rhs, x);
    mod_mul(&fp, tmp, three, x);
    p256_mod_sub(&fp, rhs, rhs, tmp);
    p256_mod_add(&fp, rhs, rhs, b);

    if (!num_eq(lhs, rhs)) {
        report("G is not on the curve", 0u, 0u);
    }
}

int main(void) {
    TT_RUN(products_just_below_the_modulus_are_exact);
    TT_RUN(multiplication_distributes_over_addition);
    TT_RUN(every_nonzero_value_has_a_working_inverse);
    TT_RUN(montgomery_conversion_round_trips);
    TT_RUN(the_generator_satisfies_the_curve_equation);
    return TT_SUMMARY();
}
