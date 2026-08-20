/*
 * Field arithmetic in GF(2^255-19), tested directly rather than only through
 * Ed25519.
 *
 * This file exists because of a specific defect. tamga_fe_mul folded its
 * high-half carry once and discarded whatever that fold carried out again --
 * wrong whenever the intermediate lands within a few hundred of 2^256.
 * (p-38) * (p-1) must be 38; it came out as 0, for two ordinary, fully
 * reduced operands, one of them just the encoding of -1 that fe_sub and
 * fe_neg produce constantly.
 *
 * The entire RFC 8032 suite passed throughout. Known-answer vectors exercise
 * the field over realistic values, which essentially never land in that
 * window, so they cannot find this class of bug at all -- only extremal
 * operands and algebraic identities can. That is what this file is for, and
 * why the vectors below cluster just under p rather than spreading out.
 *
 * Expected products were computed with arbitrary-precision arithmetic outside
 * this codebase.
 */
#include "tamga_test.h"

#include "crypto/fe25519.h"

/* Big-endian hex, the way the vectors are written, rather than the
 * little-endian byte order the field's own encoding uses. */
static void fe_from_be_hex(const char *hex, TamgaFe *out) {
    unsigned char be[32];
    unsigned char le[32];
    size_t i;

    if (tt_hex2bin(hex, be, sizeof(be)) != 32u) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: malformed vector %s\n", tt_current_, hex);
        tamga_fe_zero(out);
        return;
    }
    for (i = 0u; i < 32u; i++) {
        le[i] = be[31u - i];
    }
    tamga_fe_from_bytes(out, le);
}

static void expect_product(const char *a_hex, const char *b_hex, const char *expected_hex) {
    TamgaFe a;
    TamgaFe b;
    TamgaFe expected;
    TamgaFe actual;

    fe_from_be_hex(a_hex, &a);
    fe_from_be_hex(b_hex, &b);
    fe_from_be_hex(expected_hex, &expected);

    tamga_fe_mul(&actual, &a, &b);
    if (!tamga_fe_equal(&actual, &expected)) {
        unsigned char got[32];
        unsigned char want[32];
        tamga_fe_to_bytes(&actual, got);
        tamga_fe_to_bytes(&expected, want);
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s\n  a = %s\n  b = %s\n", tt_current_, a_hex, b_hex);
        tt_print_hex_("    expected (le)", want, 32u);
        tt_print_hex_("    actual   (le)", got, 32u);
        return;
    }

    /* Multiplication commutes; a carry bug that depended on operand order
     * would show here even if the vector happened to pass one way round. */
    tamga_fe_mul(&actual, &b, &a);
    if (!tamga_fe_equal(&actual, &expected)) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: b*a differs from a*b\n", tt_current_);
    }
}

TT_TEST(multiplication_is_correct_for_operands_near_the_modulus) {
    static const char *const vectors[][3] = {
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000000000000000000000000000000000001"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "0000000000000000000000000000000000000000000000000000000000000026"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "0000000000000000000000000000000000000000000000000000000000000002"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000000000000000000000000000000000002"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "000000000000000000000000000000000000000000000000000000000000004c"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "0000000000000000000000000000000000000000000000000000000000000004"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000000000000000000000000000000000013"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "00000000000000000000000000000000000000000000000000000000000002d2"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "0000000000000000000000000000000000000000000000000000000000000026"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc8",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000000000000000000000000000000000025"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc8",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "000000000000000000000000000000000000000000000000000000000000057e"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc8",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "000000000000000000000000000000000000000000000000000000000000004a"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000000000000000000000000000000000026"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "00000000000000000000000000000000000000000000000000000000000005a4"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "000000000000000000000000000000000000000000000000000000000000004c"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc6",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000000000000000000000000000000000027"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc6",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "00000000000000000000000000000000000000000000000000000000000005ca"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc6",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "000000000000000000000000000000000000000000000000000000000000004e"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffad",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000000000000000000000000000000000040"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffad",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "0000000000000000000000000000000000000000000000000000000000000980"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffad",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "0000000000000000000000000000000000000000000000000000000000000080"},
        {"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeee",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "00000000000000000000000000000000000000000000000000000000000000ff"},
        {"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeee",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "00000000000000000000000000000000000000000000000000000000000025da"},
        {"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeee",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "00000000000000000000000000000000000000000000000000000000000001fe"},
        {"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeed",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000000000000000000000000000000000100"},
        {"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeed",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "0000000000000000000000000000000000000000000000000000000000002600"},
        {"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeed",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
         "0000000000000000000000000000000000000000000000000000000000000200"},
        {"0000000000000000000000000000000000000000000000000000000000000000",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000000000000000000000000000000000000"},
        {"0000000000000000000000000000000000000000000000000000000000000001",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"},
        {"0000000000000000000000000000000000000000000000000000000000000002",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb"},
        {"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
         "0000000000000000000000000000000100000000000000000000000000000000",
         "7ffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffed"},
        {"4000000000000000000000000000000000000000000000000000000000000000",
         "4000000000000000000000000000000000000000000000000000000000000000",
         "600000000000000000000000000000000000000000000000000000000000004c"},
        {"0000000000000000000000000000000000000000000000000000000000000026",
         "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7",
         "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa49"},
    };
    size_t i;

    for (i = 0u; i < (sizeof(vectors) / sizeof(vectors[0])); i++) {
        expect_product(vectors[i][0], vectors[i][1], vectors[i][2]);
    }
}

/* Fills `bytes` with a deterministic pseudo-random pattern. Reproducible on
 * purpose: the point is coverage of carry patterns, not statistical quality,
 * and a failure has to be reproducible to be debuggable. */
static void fill_pattern(unsigned char bytes[32], unsigned int *seed) {
    size_t i;
    for (i = 0u; i < 32u; i++) {
        *seed = (*seed * 1103515245u) + 12345u;
        bytes[i] = (unsigned char)(*seed >> 16);
    }
}

/* Writes p - k, the region where the carry behaviour actually differs. */
static void fill_near_modulus(unsigned char bytes[32], unsigned int k) {
    memset(bytes, 0xffu, 31u);
    bytes[0] = (unsigned char)(0xedu - (k & 0x3fu));
    bytes[31] = 0x7fu;
}

/*
 * Distributivity across a wide spread of values, many of them near p.
 *
 * a*(b+c) == a*b + a*c holds in every field, and a dropped carry breaks it.
 * Unlike a fixed vector this covers combinations nobody enumerated -- it is
 * the property that would have caught the original defect without anyone
 * knowing where to look.
 */
TT_TEST(multiplication_distributes_over_addition) {
    TamgaFe a;
    TamgaFe b;
    TamgaFe c;
    TamgaFe sum;
    TamgaFe left;
    TamgaFe right;
    TamgaFe scratch;
    unsigned char bytes[32];
    unsigned int seed = 0x5eed1234u;
    int round;

    for (round = 0; round < 2000; round++) {
        fill_pattern(bytes, &seed);
        if ((round % 4) == 0) {
            fill_near_modulus(bytes, (unsigned int)round);
        }
        tamga_fe_from_bytes(&a, bytes);

        fill_pattern(bytes, &seed);
        if ((round % 4) == 1) {
            fill_near_modulus(bytes, (unsigned int)round);
        }
        tamga_fe_from_bytes(&b, bytes);

        fill_pattern(bytes, &seed);
        tamga_fe_from_bytes(&c, bytes);

        tamga_fe_add(&sum, &b, &c);
        tamga_fe_mul(&left, &a, &sum);

        tamga_fe_mul(&right, &a, &b);
        tamga_fe_mul(&scratch, &a, &c);
        tamga_fe_add(&right, &right, &scratch);

        if (!tamga_fe_equal(&left, &right)) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: distributivity broken at round %d\n", tt_current_,
                          round);
            return;
        }
    }
}

/* Every non-zero element times its inverse is one, across the same extremal
 * spread -- an independent check on both multiplication and exponentiation. */
TT_TEST(inversion_undoes_multiplication_near_the_modulus) {
    TamgaFe value;
    TamgaFe inverse;
    TamgaFe product;
    TamgaFe one;
    unsigned char bytes[32];
    unsigned int k;

    tamga_fe_one(&one);
    for (k = 1u; k <= 63u; k++) {
        fill_near_modulus(bytes, k);
        tamga_fe_from_bytes(&value, bytes);

        tamga_fe_invert(&inverse, &value);
        tamga_fe_mul(&product, &value, &inverse);
        if (!tamga_fe_equal(&product, &one)) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: (p-%u) times its inverse is not 1\n", tt_current_, k);
            return;
        }
    }
}

/* Squaring shares the multiplication path and must agree with it. */
TT_TEST(squaring_agrees_with_multiplication) {
    TamgaFe value;
    TamgaFe squared;
    TamgaFe multiplied;
    unsigned char bytes[32];
    unsigned int k;

    for (k = 1u; k <= 63u; k++) {
        fill_near_modulus(bytes, k);
        tamga_fe_from_bytes(&value, bytes);

        tamga_fe_sq(&squared, &value);
        tamga_fe_mul(&multiplied, &value, &value);
        if (!tamga_fe_equal(&squared, &multiplied)) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: sq and mul disagree at p-%u\n", tt_current_, k);
            return;
        }
    }
}

int main(void) {
    TT_RUN(multiplication_is_correct_for_operands_near_the_modulus);
    TT_RUN(multiplication_distributes_over_addition);
    TT_RUN(inversion_undoes_multiplication_near_the_modulus);
    TT_RUN(squaring_agrees_with_multiplication);
    return TT_SUMMARY();
}
