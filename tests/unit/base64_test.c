#include "tamga_test.h"

#include "tamga_mem.h"
#include "util/base64.h"

/* RFC 4648 section 10 test vectors. */
static void roundtrip(const char *plain, const char *encoded) {
    char enc[64];
    unsigned char dec[64];
    size_t dec_len = 0u;
    size_t plain_len = strlen(plain);

    tamga_base64_encode((const unsigned char *)plain, plain_len, enc);
    if (strcmp(enc, encoded) != 0) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: encode(\"%s\") = \"%s\", expected \"%s\"\n", tt_current_,
                      plain, enc, encoded);
        return;
    }
    if (!tamga_base64_decode(encoded, strlen(encoded), dec, &dec_len)) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: decode(\"%s\") rejected\n", tt_current_, encoded);
        return;
    }
    if (dec_len != plain_len || memcmp(dec, plain, plain_len) != 0) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: decode(\"%s\") did not round-trip\n", tt_current_, encoded);
    }
}

TT_TEST(rfc4648_vectors_round_trip) {
    roundtrip("", "");
    roundtrip("f", "Zg==");
    roundtrip("fo", "Zm8=");
    roundtrip("foo", "Zm9v");
    roundtrip("foob", "Zm9vYg==");
    roundtrip("fooba", "Zm9vYmE=");
    roundtrip("foobar", "Zm9vYmFy");
}

TT_TEST(rejects_characters_outside_the_alphabet) {
    unsigned char out[32];
    size_t len = 0u;
    TT_ASSERT_FALSE(tamga_base64_decode("Zm9v!g==", 8u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("Zm9-vg==", 8u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("Zm9_vg==", 8u, out, &len));
}

/*
 * A line-wrapped PEM body reaches this decoder only after checkout/pem.c has
 * stripped the whitespace. Accepting it here too would put the leniency in
 * two places and make the strict/lenient boundary impossible to reason about.
 */
TT_TEST(rejects_embedded_whitespace) {
    unsigned char out[32];
    size_t len = 0u;
    TT_ASSERT_FALSE(tamga_base64_decode("Zm9v\nYmFy", 9u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("Zm9v YmFy", 9u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("\tZm9v", 5u, out, &len));
}

TT_TEST(rejects_misplaced_or_excessive_padding) {
    unsigned char out[32];
    size_t len = 0u;
    TT_ASSERT_FALSE(tamga_base64_decode("Zm=9v", 5u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("Zg===", 5u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("Zg=", 3u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("Zm8==", 5u, out, &len));
}

TT_TEST(rejects_a_four_n_plus_one_length) {
    unsigned char out[32];
    size_t len = 0u;
    TT_ASSERT_FALSE(tamga_base64_decode("Z", 1u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("Zm9vZ", 5u, out, &len));
}

/*
 * "Zg=@" and "Zh==" would decode to the same byte under a lenient decoder
 * because the trailing bits are ignored. Canonical-form enforcement means one
 * byte string has exactly one encoding.
 */
TT_TEST(rejects_non_canonical_trailing_bits) {
    unsigned char out[32];
    size_t len = 0u;
    TT_ASSERT(tamga_base64_decode("Zg==", 4u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("Zh==", 4u, out, &len));
    TT_ASSERT(tamga_base64_decode("Zm8=", 4u, out, &len));
    TT_ASSERT_FALSE(tamga_base64_decode("Zm9=", 4u, out, &len));
}

TT_TEST(accepts_unpadded_input) {
    unsigned char out[32];
    size_t len = 0u;
    TT_ASSERT(tamga_base64_decode("Zm9vYmE", 7u, out, &len));
    TT_ASSERT_EQ_SIZE(len, 5u);
    TT_ASSERT_EQ_MEM(out, "fooba", 5u);
}

TT_TEST(alloc_helpers_round_trip_binary_data) {
    unsigned char raw[256];
    char *encoded;
    unsigned char *decoded;
    size_t decoded_len = 0u;
    int i;

    for (i = 0; i < 256; i++) {
        raw[i] = (unsigned char)i;
    }
    encoded = tamga_base64_encode_alloc(raw, sizeof(raw));
    TT_ASSERT_NOT_NULL(encoded);
    decoded = tamga_base64_decode_alloc(encoded, strlen(encoded), &decoded_len);
    TT_ASSERT_NOT_NULL(decoded);
    TT_ASSERT_EQ_SIZE(decoded_len, sizeof(raw));
    TT_ASSERT_EQ_MEM(decoded, raw, sizeof(raw));
    tamga_free(encoded);
    tamga_free(decoded);
}

TT_TEST(decode_alloc_returns_null_on_bad_input) {
    size_t len = 0u;
    TT_ASSERT_NULL(tamga_base64_decode_alloc("!!!!", 4u, &len));
}

int main(void) {
    TT_RUN(rfc4648_vectors_round_trip);
    TT_RUN(rejects_characters_outside_the_alphabet);
    TT_RUN(rejects_embedded_whitespace);
    TT_RUN(rejects_misplaced_or_excessive_padding);
    TT_RUN(rejects_a_four_n_plus_one_length);
    TT_RUN(rejects_non_canonical_trailing_bits);
    TT_RUN(accepts_unpadded_input);
    TT_RUN(alloc_helpers_round_trip_binary_data);
    TT_RUN(decode_alloc_returns_null_on_bad_input);
    return TT_SUMMARY();
}
