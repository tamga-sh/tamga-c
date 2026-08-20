/*
 * AES-256 and AES-256-GCM known-answer tests.
 *
 * The block-cipher vector is FIPS 197 Appendix C.3. The GCM vectors are the
 * NIST SP 800-38D AES-256 cases plus a few shapes this library actually sees
 * (non-block-multiple payloads, a licence-file-sized payload), all generated
 * against an independent implementation rather than derived from this one.
 */
#include "tamga_test.h"

#include "crypto/aes.h"
#include "crypto/gcm.h"
#include "tamga_mem.h"

TT_TEST(aes256_matches_fips197) {
    unsigned char key[32];
    unsigned char plaintext[16];
    unsigned char expected[16];
    unsigned char actual[16];
    TamgaAes256 ctx;

    TT_ASSERT_EQ_SIZE(tt_hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                                 key, sizeof(key)),
                      32u);
    TT_ASSERT_EQ_SIZE(tt_hex2bin("00112233445566778899aabbccddeeff", plaintext, sizeof(plaintext)),
                      16u);
    TT_ASSERT_EQ_SIZE(tt_hex2bin("8ea2b7ca516745bfeafc49904b496089", expected, sizeof(expected)),
                      16u);

    tamga_aes256_init(&ctx, key);
    tamga_aes256_encrypt_block(&ctx, plaintext, actual);
    tamga_aes256_clear(&ctx);
    TT_ASSERT_EQ_MEM(actual, expected, sizeof(expected));
}

/* in and out may alias; the CTR loop relies on it not corrupting the block
 * halfway through. */
TT_TEST(aes256_tolerates_aliased_input_and_output) {
    unsigned char key[32];
    unsigned char block[16];
    unsigned char expected[16];
    TamgaAes256 ctx;

    (void)tt_hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key,
                     sizeof(key));
    (void)tt_hex2bin("00112233445566778899aabbccddeeff", block, sizeof(block));
    (void)tt_hex2bin("8ea2b7ca516745bfeafc49904b496089", expected, sizeof(expected));

    tamga_aes256_init(&ctx, key);
    tamga_aes256_encrypt_block(&ctx, block, block);
    tamga_aes256_clear(&ctx);
    TT_ASSERT_EQ_MEM(block, expected, sizeof(expected));
}

static void gcm_vector(const char *key_hex, const char *nonce_hex, const char *aad_hex,
                       const char *plaintext_hex, const char *expected_hex) {
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char aad[64];
    unsigned char plaintext[512];
    unsigned char expected[560];
    unsigned char sealed[560];
    unsigned char opened[512];
    size_t aad_len;
    size_t plaintext_len;
    size_t expected_len;
    size_t sealed_len = 0u;
    size_t opened_len = 0u;

    TT_ASSERT_EQ_SIZE(tt_hex2bin(key_hex, key, sizeof(key)), 32u);
    TT_ASSERT_EQ_SIZE(tt_hex2bin(nonce_hex, nonce, sizeof(nonce)), 12u);
    aad_len = tt_hex2bin(aad_hex, aad, sizeof(aad));
    plaintext_len = tt_hex2bin(plaintext_hex, plaintext, sizeof(plaintext));
    expected_len = tt_hex2bin(expected_hex, expected, sizeof(expected));
    TT_ASSERT(aad_len != (size_t)-1);
    TT_ASSERT(plaintext_len != (size_t)-1);
    TT_ASSERT(expected_len != (size_t)-1);

    /* Seal must reproduce the reference ciphertext and tag exactly. */
    TT_ASSERT(
        tamga_gcm_seal(key, nonce, aad, aad_len, plaintext, plaintext_len, sealed, &sealed_len));
    TT_ASSERT_EQ_SIZE(sealed_len, expected_len);
    TT_ASSERT_EQ_MEM(sealed, expected, expected_len);

    /* Open must recover the plaintext from the reference bytes -- not merely
     * from what seal just produced. */
    TT_ASSERT(
        tamga_gcm_open(key, nonce, aad, aad_len, expected, expected_len, opened, &opened_len));
    TT_ASSERT_EQ_SIZE(opened_len, plaintext_len);
    if (plaintext_len > 0u) {
        TT_ASSERT_EQ_MEM(opened, plaintext, plaintext_len);
    }
}

TT_TEST(gcm_matches_nist_vectors) {
    /* Empty plaintext: tag only. */
    gcm_vector("0000000000000000000000000000000000000000000000000000000000000000",
               "000000000000000000000000", "", "", "530f8afbc74536b9a963b4f1c4cb738b");
    /* Single all-zero block. */
    gcm_vector("0000000000000000000000000000000000000000000000000000000000000000",
               "000000000000000000000000", "", "00000000000000000000000000000000",
               "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
    /* SP 800-38D case 15: 60-byte plaintext, no AAD. */
    gcm_vector("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
               "cafebabefacedbaddecaf888", "",
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959568"
               "09532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
               "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590d"
               "bb3da7b08b1056828838c5f61e6393ba7a0abcc9f662eb9f796c8d356fc31a8433884b696f4f");
    /* SP 800-38D case 16: the same, with additional authenticated data. */
    gcm_vector("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
               "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959568"
               "09532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
               "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590d"
               "bb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b");
}

/* A payload whose length is not a multiple of 16 exercises both the partial
 * keystream block and GHASH's zero-padded final block -- the two places a
 * hand-written GCM most often gets the last few bytes wrong. */
TT_TEST(gcm_handles_partial_final_blocks) {
    gcm_vector("1111111111111111111111111111111111111111111111111111111111111111",
               "222222222222222222222222", "", "0102030405",
               "16f5044dc5cbe4c2c76d09423fa7252e2ee928a79f");
    /* 17 bytes: one full block plus one byte. */
    gcm_vector("1111111111111111111111111111111111111111111111111111111111111111",
               "222222222222222222222222", "", "00112233445566778899aabbccddeeff00",
               "17e6257a849af9286da67487847b072a1fb98732862f65eb97314fa6e9a860c741");
}

TT_TEST(gcm_rejects_a_tampered_tag) {
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char sealed[64];
    unsigned char opened[64];
    size_t sealed_len = 0u;
    size_t opened_len = 0u;

    memset(key, 0x2a, sizeof(key));
    memset(nonce, 0x3b, sizeof(nonce));
    TT_ASSERT(tamga_gcm_seal(key, nonce, NULL, 0u, (const unsigned char *)"payload", 7u, sealed,
                             &sealed_len));
    TT_ASSERT_EQ_SIZE(sealed_len, 7u + TAMGA_GCM_TAG_LEN);

    sealed[sealed_len - 1u] ^= 0x01u;
    TT_ASSERT_FALSE(tamga_gcm_open(key, nonce, NULL, 0u, sealed, sealed_len, opened, &opened_len));
    TT_ASSERT_EQ_SIZE(opened_len, 0u);
}

TT_TEST(gcm_rejects_tampered_ciphertext) {
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char sealed[64];
    unsigned char opened[64];
    size_t sealed_len = 0u;
    size_t opened_len = 0u;

    memset(key, 0x2a, sizeof(key));
    memset(nonce, 0x3b, sizeof(nonce));
    TT_ASSERT(tamga_gcm_seal(key, nonce, NULL, 0u, (const unsigned char *)"payload", 7u, sealed,
                             &sealed_len));
    sealed[0] ^= 0x80u;
    TT_ASSERT_FALSE(tamga_gcm_open(key, nonce, NULL, 0u, sealed, sealed_len, opened, &opened_len));
}

TT_TEST(gcm_rejects_a_wrong_key_or_nonce) {
    unsigned char key[32];
    unsigned char other_key[32];
    unsigned char nonce[12];
    unsigned char other_nonce[12];
    unsigned char sealed[64];
    unsigned char opened[64];
    size_t sealed_len = 0u;
    size_t opened_len = 0u;

    memset(key, 0x2a, sizeof(key));
    memset(other_key, 0x2a, sizeof(other_key));
    other_key[31] ^= 0x01u;
    memset(nonce, 0x3b, sizeof(nonce));
    memset(other_nonce, 0x3b, sizeof(other_nonce));
    other_nonce[11] ^= 0x01u;

    TT_ASSERT(tamga_gcm_seal(key, nonce, NULL, 0u, (const unsigned char *)"payload", 7u, sealed,
                             &sealed_len));
    TT_ASSERT_FALSE(
        tamga_gcm_open(other_key, nonce, NULL, 0u, sealed, sealed_len, opened, &opened_len));
    TT_ASSERT_FALSE(
        tamga_gcm_open(key, other_nonce, NULL, 0u, sealed, sealed_len, opened, &opened_len));
}

/* AAD is authenticated but not encrypted, so changing it must invalidate the
 * tag even though the ciphertext is untouched. */
TT_TEST(gcm_authenticates_the_associated_data) {
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char sealed[64];
    unsigned char opened[64];
    size_t sealed_len = 0u;
    size_t opened_len = 0u;

    memset(key, 0x2a, sizeof(key));
    memset(nonce, 0x3b, sizeof(nonce));
    TT_ASSERT(tamga_gcm_seal(key, nonce, (const unsigned char *)"header", 6u,
                             (const unsigned char *)"payload", 7u, sealed, &sealed_len));
    TT_ASSERT(tamga_gcm_open(key, nonce, (const unsigned char *)"header", 6u, sealed, sealed_len,
                             opened, &opened_len));
    TT_ASSERT_FALSE(tamga_gcm_open(key, nonce, (const unsigned char *)"heager", 6u, sealed,
                                   sealed_len, opened, &opened_len));
    TT_ASSERT_FALSE(tamga_gcm_open(key, nonce, NULL, 0u, sealed, sealed_len, opened, &opened_len));
}

/*
 * A wire payload shorter than the tag itself must be refused before any length
 * arithmetic runs -- computing ct_len = total - 16 on a 4-byte input would
 * wrap to an enormous size_t and read far past the buffer.
 */
TT_TEST(gcm_rejects_input_shorter_than_the_tag) {
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char tiny[4] = {1u, 2u, 3u, 4u};
    unsigned char opened[16];
    size_t opened_len = 0u;

    memset(key, 0x2a, sizeof(key));
    memset(nonce, 0x3b, sizeof(nonce));
    TT_ASSERT_FALSE(tamga_gcm_open(key, nonce, NULL, 0u, tiny, sizeof(tiny), opened, &opened_len));
    TT_ASSERT_FALSE(tamga_gcm_open(key, nonce, NULL, 0u, tiny, 0u, opened, &opened_len));
}

TT_TEST(gcm_opens_an_empty_payload) {
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char sealed[TAMGA_GCM_TAG_LEN];
    size_t sealed_len = 0u;
    size_t opened_len = 99u;

    memset(key, 0u, sizeof(key));
    memset(nonce, 0u, sizeof(nonce));
    TT_ASSERT(tamga_gcm_seal(key, nonce, NULL, 0u, NULL, 0u, sealed, &sealed_len));
    TT_ASSERT_EQ_SIZE(sealed_len, TAMGA_GCM_TAG_LEN);
    TT_ASSERT(tamga_gcm_open(key, nonce, NULL, 0u, sealed, sealed_len, NULL, &opened_len));
    TT_ASSERT_EQ_SIZE(opened_len, 0u);
}

/* Roughly the size of a real licence-file payload, to cover the multi-block
 * counter walk rather than only the first block or two. */
TT_TEST(gcm_round_trips_a_licence_sized_payload) {
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char plaintext[300];
    unsigned char sealed[sizeof(plaintext) + TAMGA_GCM_TAG_LEN];
    unsigned char opened[sizeof(plaintext)];
    size_t sealed_len = 0u;
    size_t opened_len = 0u;

    memset(key, 0xab, sizeof(key));
    memset(nonce, 0xcd, sizeof(nonce));
    memset(plaintext, 0x5a, sizeof(plaintext));

    TT_ASSERT(
        tamga_gcm_seal(key, nonce, NULL, 0u, plaintext, sizeof(plaintext), sealed, &sealed_len));
    TT_ASSERT_EQ_SIZE(sealed_len, sizeof(sealed));
    TT_ASSERT(tamga_gcm_open(key, nonce, NULL, 0u, sealed, sealed_len, opened, &opened_len));
    TT_ASSERT_EQ_SIZE(opened_len, sizeof(plaintext));
    TT_ASSERT_EQ_MEM(opened, plaintext, sizeof(plaintext));
}

int main(void) {
    TT_RUN(aes256_matches_fips197);
    TT_RUN(aes256_tolerates_aliased_input_and_output);
    TT_RUN(gcm_matches_nist_vectors);
    TT_RUN(gcm_handles_partial_final_blocks);
    TT_RUN(gcm_rejects_a_tampered_tag);
    TT_RUN(gcm_rejects_tampered_ciphertext);
    TT_RUN(gcm_rejects_a_wrong_key_or_nonce);
    TT_RUN(gcm_authenticates_the_associated_data);
    TT_RUN(gcm_rejects_input_shorter_than_the_tag);
    TT_RUN(gcm_opens_an_empty_payload);
    TT_RUN(gcm_round_trips_a_licence_sized_payload);
    return TT_SUMMARY();
}
