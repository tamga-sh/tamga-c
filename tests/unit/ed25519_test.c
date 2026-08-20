/*
 * Ed25519 verification tests.
 *
 * The positive vectors are RFC 8032 section 7.1, regenerated through
 * ed25519-dalek -- the implementation tamga-rust uses -- so this suite pins
 * interoperability with the rest of the fleet, not just conformance to the
 * RFC in the abstract.
 */
#include "tamga_test.h"

#include "crypto/ed25519.h"
#include "crypto/fe25519.h"

static void verifies(const char *pubkey_hex, const char *message_hex, const char *sig_hex)
{
    unsigned char pubkey[32];
    unsigned char signature[64];
    unsigned char message[256];
    size_t message_len;

    TT_ASSERT_EQ_SIZE(tt_hex2bin(pubkey_hex, pubkey, sizeof(pubkey)), 32u);
    TT_ASSERT_EQ_SIZE(tt_hex2bin(sig_hex, signature, sizeof(signature)), 64u);
    message_len = tt_hex2bin(message_hex, message, sizeof(message));
    TT_ASSERT(message_len != (size_t)-1);

    if (!tamga_ed25519_verify(pubkey, message, message_len, signature)) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: signature rejected\n  pubkey: %s\n  sig:    %s\n",
                      tt_current_, pubkey_hex, sig_hex);
    }
}

TT_TEST(accepts_rfc8032_vectors)
{
    /* Empty message. */
    verifies("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a3"
             "3bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    /* One-byte message. */
    verifies("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15"
             "996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    /* Two-byte message. */
    verifies("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
             "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16"
             "f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
    /* 96-byte message: spans more than one SHA-512 block. */
    verifies("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
             "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
             "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
             "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d",
             "f35b8b58cff047f8185f17acc239e92e43b4c6fa36468a40fa62ffc223f7cd144bcb74317d31"
             "b052a2935c1c57486a1c4705fb693fb122605ed3bb685390da01");
}

/*
 * The shape the .lic format actually signs: the ASCII bytes of a base64
 * string. Included as a distinct case because getting the "sign the string,
 * not the decoded bytes" rule wrong is this format's defining failure mode,
 * and it is worth having a vector at this layer as well as at the checkout
 * layer.
 */
TT_TEST(accepts_a_signature_over_base64_string_bytes)
{
    verifies("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
             "65794a6b59585268496a7037496d6c6b496a6f694d534a3966513d3d",
             "c93a739131b7f8360bb99411c57557f543b9a570d13d2424cf87eac87474c8913c1aa99dcd7d"
             "667520ed432c7704ac9a2c23f4804534affcf2d7df3ecde74407");
}

TT_TEST(rejects_a_tampered_message)
{
    unsigned char pubkey[32];
    unsigned char signature[64];
    unsigned char message[2];

    (void)tt_hex2bin("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                     pubkey, sizeof(pubkey));
    (void)tt_hex2bin("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff"
                     "9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                     signature, sizeof(signature));
    (void)tt_hex2bin("af82", message, sizeof(message));

    TT_ASSERT(tamga_ed25519_verify(pubkey, message, sizeof(message), signature));
    message[0] ^= 0x01u;
    TT_ASSERT_FALSE(tamga_ed25519_verify(pubkey, message, sizeof(message), signature));
    /* Truncating the message must fail too -- length is part of what is
     * signed, not just content. */
    message[0] ^= 0x01u;
    TT_ASSERT_FALSE(tamga_ed25519_verify(pubkey, message, 1u, signature));
}

TT_TEST(rejects_a_tampered_signature)
{
    unsigned char pubkey[32];
    unsigned char signature[64];
    unsigned char message[2];
    size_t i;

    (void)tt_hex2bin("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                     pubkey, sizeof(pubkey));
    (void)tt_hex2bin("af82", message, sizeof(message));

    /* Flip one bit in each of the R half and the S half. */
    for (i = 0u; i < 2u; i++) {
        (void)tt_hex2bin("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                         signature, sizeof(signature));
        signature[i * 32u] ^= 0x01u;
        TT_ASSERT_FALSE(tamga_ed25519_verify(pubkey, message, sizeof(message), signature));
    }
}

TT_TEST(rejects_a_wrong_public_key)
{
    unsigned char pubkey[32];
    unsigned char signature[64];
    unsigned char message[2];

    /* A different, valid public key from the RFC set. */
    (void)tt_hex2bin("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                     pubkey, sizeof(pubkey));
    (void)tt_hex2bin("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff"
                     "9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                     signature, sizeof(signature));
    (void)tt_hex2bin("af82", message, sizeof(message));

    TT_ASSERT_FALSE(tamga_ed25519_verify(pubkey, message, sizeof(message), signature));
}

/*
 * S must be strictly below the group order. Adding L to a valid signature's
 * scalar half yields a different byte string that satisfies the verification
 * equation just as well -- signature malleability. ed25519-dalek rejects it
 * (confirmed directly), so this implementation must too, or the two disagree
 * about whether a given file is authentic.
 */
TT_TEST(rejects_a_non_canonical_scalar)
{
    unsigned char pubkey[32];
    unsigned char signature[64];
    unsigned char malleable[64];
    unsigned char message[28];
    size_t message_len;

    (void)tt_hex2bin("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
                     pubkey, sizeof(pubkey));
    (void)tt_hex2bin("c93a739131b7f8360bb99411c57557f543b9a570d13d2424cf87eac87474c8913c1a"
                     "a99dcd7d667520ed432c7704ac9a2c23f4804534affcf2d7df3ecde74407",
                     signature, sizeof(signature));
    message_len = tt_hex2bin("65794a6b59585268496a7037496d6c6b496a6f694d534a3966513d3d",
                             message, sizeof(message));
    TT_ASSERT_EQ_SIZE(message_len, 28u);

    TT_ASSERT(tamga_ed25519_verify(pubkey, message, message_len, signature));

    /* Same signature with L added to S, produced by ed25519-dalek's own
     * arithmetic and confirmed rejected by it. */
    (void)tt_hex2bin("c93a739131b7f8360bb99411c57557f543b9a570d13d2424cf87eac87474c89129ee"
                     "9efae7e078cdf6893bcf55fe8aaf2c23f4804534affcf2d7df3ecde74417",
                     malleable, sizeof(malleable));
    TT_ASSERT_FALSE(tamga_ed25519_verify(pubkey, message, message_len, malleable));
}

/*
 * A public key that does not decode to a curve point must be refused before
 * any arithmetic runs. Accepting one is how an attacker moves the computation
 * onto a different, weaker curve. y = 2 has no corresponding x on ed25519 --
 * confirmed against ed25519-dalek, which rejects the same encoding.
 */
TT_TEST(rejects_a_public_key_that_is_not_on_the_curve)
{
    unsigned char pubkey[32];
    unsigned char signature[64];

    memset(signature, 0, sizeof(signature));
    (void)tt_hex2bin("0200000000000000000000000000000000000000000000000000000000000000",
                     pubkey, sizeof(pubkey));
    TT_ASSERT_FALSE(tamga_ed25519_verify(pubkey, (const unsigned char *)"x", 1u, signature));
}

TT_TEST(rejects_null_arguments)
{
    unsigned char pubkey[32];
    unsigned char signature[64];

    memset(pubkey, 0, sizeof(pubkey));
    memset(signature, 0, sizeof(signature));
    TT_ASSERT_FALSE(tamga_ed25519_verify(NULL, (const unsigned char *)"x", 1u, signature));
    TT_ASSERT_FALSE(tamga_ed25519_verify(pubkey, (const unsigned char *)"x", 1u, NULL));
    TT_ASSERT_FALSE(tamga_ed25519_verify(pubkey, NULL, 1u, signature));
}

/* --- field self-checks -------------------------------------------------
 *
 * The two hardcoded field constants are the kind of thing a transcription
 * error hides in silently: a wrong d or sqrt(-1) makes decompression fail for
 * most inputs and succeed for a few, which looks like a signature problem.
 * Both are verified by their defining property rather than by inspection.
 */

TT_TEST(sqrt_minus_one_squares_to_minus_one)
{
    TamgaFe sqrtm1;
    TamgaFe squared;
    TamgaFe one;
    TamgaFe minus_one;

    tamga_fe_sqrtm1(&sqrtm1);
    tamga_fe_sq(&squared, &sqrtm1);
    tamga_fe_one(&one);
    tamga_fe_neg(&minus_one, &one);
    TT_ASSERT(tamga_fe_equal(&squared, &minus_one));
}

TT_TEST(the_curve_constant_d_satisfies_its_definition)
{
    /* d = -121665 / 121666, i.e. d * 121666 + 121665 == 0. */
    TamgaFe d;
    TamgaFe denominator;
    TamgaFe numerator;
    TamgaFe product;
    TamgaFe sum;
    unsigned char bytes[32];

    tamga_fe_d(&d);

    memset(bytes, 0, sizeof(bytes));
    bytes[0] = (unsigned char)(121666u & 0xFFu);
    bytes[1] = (unsigned char)((121666u >> 8) & 0xFFu);
    bytes[2] = (unsigned char)((121666u >> 16) & 0xFFu);
    tamga_fe_from_bytes(&denominator, bytes);

    memset(bytes, 0, sizeof(bytes));
    bytes[0] = (unsigned char)(121665u & 0xFFu);
    bytes[1] = (unsigned char)((121665u >> 8) & 0xFFu);
    bytes[2] = (unsigned char)((121665u >> 16) & 0xFFu);
    tamga_fe_from_bytes(&numerator, bytes);

    tamga_fe_mul(&product, &d, &denominator);
    tamga_fe_add(&sum, &product, &numerator);
    TT_ASSERT(tamga_fe_is_zero(&sum));
}

TT_TEST(field_inversion_round_trips)
{
    TamgaFe value;
    TamgaFe inverse;
    TamgaFe product;
    unsigned char bytes[32];
    int i;

    for (i = 0; i < 32; i++) {
        bytes[i] = (unsigned char)((i * 7) + 3);
    }
    tamga_fe_from_bytes(&value, bytes);
    tamga_fe_invert(&inverse, &value);
    tamga_fe_mul(&product, &value, &inverse);

    {
        TamgaFe one;
        tamga_fe_one(&one);
        TT_ASSERT(tamga_fe_equal(&product, &one));
    }
}

/* p - 1 and p + 1 must reduce to p - 1 and 1 respectively; getting the
 * boundary wrong is the classic field-arithmetic bug that only shows up for a
 * vanishing fraction of random inputs. */
TT_TEST(field_arithmetic_handles_the_modulus_boundary)
{
    TamgaFe p_minus_one;
    TamgaFe one;
    TamgaFe sum;
    TamgaFe zero;
    unsigned char bytes[32];

    /* p - 1 = 2^255 - 20 */
    memset(bytes, 0xffu, sizeof(bytes));
    bytes[0] = 0xecu;
    bytes[31] = 0x7fu;
    tamga_fe_from_bytes(&p_minus_one, bytes);
    tamga_fe_one(&one);
    tamga_fe_zero(&zero);

    tamga_fe_add(&sum, &p_minus_one, &one);
    TT_ASSERT(tamga_fe_equal(&sum, &zero));

    tamga_fe_sub(&sum, &zero, &one);
    TT_ASSERT(tamga_fe_equal(&sum, &p_minus_one));

    /* An encoding of p itself is not canonical and must normalise to 0. */
    memset(bytes, 0xffu, sizeof(bytes));
    bytes[0] = 0xedu;
    bytes[31] = 0x7fu;
    tamga_fe_from_bytes(&sum, bytes);
    TT_ASSERT(tamga_fe_is_zero(&sum));
}

int main(void)
{
    TT_RUN(accepts_rfc8032_vectors);
    TT_RUN(accepts_a_signature_over_base64_string_bytes);
    TT_RUN(rejects_a_tampered_message);
    TT_RUN(rejects_a_tampered_signature);
    TT_RUN(rejects_a_wrong_public_key);
    TT_RUN(rejects_a_non_canonical_scalar);
    TT_RUN(rejects_a_public_key_that_is_not_on_the_curve);
    TT_RUN(rejects_null_arguments);
    TT_RUN(sqrt_minus_one_squares_to_minus_one);
    TT_RUN(the_curve_constant_d_satisfies_its_definition);
    TT_RUN(field_inversion_round_trips);
    TT_RUN(field_arithmetic_handles_the_modulus_boundary);
    return TT_SUMMARY();
}
