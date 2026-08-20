/*
 * Known-answer tests for SHA-256, SHA-512, HMAC-SHA256 and HKDF-SHA256.
 *
 * Vectors come from FIPS 180-4, RFC 4231 and RFC 5869, regenerated against a
 * reference implementation rather than transcribed from memory.
 */
#include "tamga_test.h"

#include "crypto/ct.h"
#include "crypto/hkdf.h"
#include "crypto/hmac_sha256.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "tamga_mem.h"

static void expect_digest_hex(const unsigned char *actual, size_t len, const char *expected_hex)
{
    unsigned char expected[128];
    size_t n = tt_hex2bin(expected_hex, expected, sizeof(expected));
    if (n != len) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: expected-hex length %zu, digest length %zu\n",
                      tt_current_, n, len);
        return;
    }
    if (memcmp(actual, expected, len) != 0) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: digest mismatch\n", tt_current_);
        tt_print_hex_("    expected", expected, len);
        tt_print_hex_("    actual  ", actual, len);
    }
}

static void sha256_is(const char *message, const char *expected_hex)
{
    unsigned char digest[TAMGA_SHA256_DIGEST_LEN];
    tamga_sha256(message, strlen(message), digest);
    expect_digest_hex(digest, sizeof(digest), expected_hex);
}

static void sha512_is(const char *message, const char *expected_hex)
{
    unsigned char digest[TAMGA_SHA512_DIGEST_LEN];
    tamga_sha512(message, strlen(message), digest);
    expect_digest_hex(digest, sizeof(digest), expected_hex);
}

TT_TEST(sha256_matches_fips_vectors)
{
    sha256_is("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    sha256_is("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    /* 448-bit message: the padding case that needs one extra block. */
    sha256_is("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    /* 896-bit message: spans two blocks before padding. */
    sha256_is("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
              "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

/* One million 'a' -- the FIPS long-message vector. Catches a broken length
 * counter or a mishandled block boundary, which short vectors do not. */
TT_TEST(sha256_matches_the_long_message_vector)
{
    TamgaSha256 ctx;
    unsigned char digest[TAMGA_SHA256_DIGEST_LEN];
    unsigned char chunk[1000];
    int i;

    memset(chunk, 'a', sizeof(chunk));
    tamga_sha256_init(&ctx);
    for (i = 0; i < 1000; i++) {
        tamga_sha256_update(&ctx, chunk, sizeof(chunk));
    }
    tamga_sha256_final(&ctx, digest);
    expect_digest_hex(digest, sizeof(digest),
                      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

/* Feeding a message one byte at a time must produce the same digest as one
 * call -- the buffering path is where streaming hash implementations break. */
TT_TEST(sha256_streams_identically_to_one_shot)
{
    static const char message[] =
        "the quick brown fox jumps over the lazy dog, repeatedly, until it "
        "crosses several block boundaries and then some more for good measure";
    unsigned char one_shot[TAMGA_SHA256_DIGEST_LEN];
    unsigned char streamed[TAMGA_SHA256_DIGEST_LEN];
    TamgaSha256 ctx;
    size_t i;

    tamga_sha256(message, sizeof(message) - 1u, one_shot);
    tamga_sha256_init(&ctx);
    for (i = 0u; i < (sizeof(message) - 1u); i++) {
        tamga_sha256_update(&ctx, &message[i], 1u);
    }
    tamga_sha256_final(&ctx, streamed);
    TT_ASSERT_EQ_MEM(streamed, one_shot, sizeof(one_shot));
}

TT_TEST(sha512_matches_fips_vectors)
{
    sha512_is("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                  "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    sha512_is("abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    sha512_is("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
              "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
              "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

TT_TEST(sha512_streams_identically_to_one_shot)
{
    unsigned char one_shot[TAMGA_SHA512_DIGEST_LEN];
    unsigned char streamed[TAMGA_SHA512_DIGEST_LEN];
    unsigned char message[300];
    TamgaSha512 ctx;
    size_t i;

    for (i = 0u; i < sizeof(message); i++) {
        message[i] = (unsigned char)(i & 0xFFu);
    }
    tamga_sha512(message, sizeof(message), one_shot);
    tamga_sha512_init(&ctx);
    for (i = 0u; i < sizeof(message); i++) {
        tamga_sha512_update(&ctx, &message[i], 1u);
    }
    tamga_sha512_final(&ctx, streamed);
    TT_ASSERT_EQ_MEM(streamed, one_shot, sizeof(one_shot));
}

TT_TEST(hmac_sha256_matches_rfc4231)
{
    unsigned char key[131];
    unsigned char data[50];
    unsigned char mac[TAMGA_SHA256_DIGEST_LEN];
    size_t i;

    /* Case 1 */
    memset(key, 0x0b, 20u);
    tamga_hmac_sha256(key, 20u, "Hi There", 8u, mac);
    expect_digest_hex(mac, sizeof(mac),
                      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /* Case 2: a short, printable key */
    tamga_hmac_sha256("Jefe", 4u, "what do ya want for nothing?", 28u, mac);
    expect_digest_hex(mac, sizeof(mac),
                      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    /* Case 3 */
    memset(key, 0xaa, 20u);
    memset(data, 0xdd, sizeof(data));
    tamga_hmac_sha256(key, 20u, data, sizeof(data), mac);
    expect_digest_hex(mac, sizeof(mac),
                      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /* Case 6: a 131-byte key, longer than the 64-byte block, so RFC 2104
     * requires hashing it first rather than truncating or padding. */
    memset(key, 0xaa, sizeof(key));
    tamga_hmac_sha256(key, sizeof(key),
                      "Test Using Larger Than Block-Size Key - Hash Key First", 54u, mac);
    expect_digest_hex(mac, sizeof(mac),
                      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    /* Case 7: oversized key and oversized data together */
    tamga_hmac_sha256(key, sizeof(key),
                      "This is a test using a larger than block-size key and a larger "
                      "than block-size data. The key needs to be hashed before being "
                      "used by the HMAC algorithm.",
                      152u, mac);
    expect_digest_hex(mac, sizeof(mac),
                      "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");

    (void)i;
}

TT_TEST(hkdf_matches_rfc5869)
{
    unsigned char salt[80];
    unsigned char ikm[80];
    unsigned char info[80];
    unsigned char okm[82];
    size_t i;

    /* Case 1: basic, 42 bytes out */
    TT_ASSERT_EQ_SIZE(tt_hex2bin("000102030405060708090a0b0c", salt, sizeof(salt)), 13u);
    memset(ikm, 0x0b, 22u);
    TT_ASSERT_EQ_SIZE(tt_hex2bin("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info)), 10u);
    TT_ASSERT(tamga_hkdf_sha256(salt, 13u, ikm, 22u, info, 10u, okm, 42u));
    expect_digest_hex(okm, 42u,
                      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                      "34007208d5b887185865");

    /* Case 2: longer inputs, 82 bytes out -- exercises the multi-block
     * expand loop and the counter increment. */
    for (i = 0u; i < 80u; i++) {
        ikm[i] = (unsigned char)i;
        salt[i] = (unsigned char)(0x60u + i);
        info[i] = (unsigned char)(0xb0u + i);
    }
    TT_ASSERT(tamga_hkdf_sha256(salt, 80u, ikm, 80u, info, 80u, okm, 82u));
    expect_digest_hex(okm, 82u,
                      "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                      "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                      "cc30c58179ec3e87c14c01d5c1f3434f1d87");

    /* Case 3: zero-length salt and info. An absent salt is defined as
     * HashLen zero bytes, not as "skip the extract step". */
    memset(ikm, 0x0b, 22u);
    TT_ASSERT(tamga_hkdf_sha256(NULL, 0u, ikm, 22u, NULL, 0u, okm, 42u));
    expect_digest_hex(okm, 42u,
                      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                      "9d201395faa4b61a96c8");
}

TT_TEST(hkdf_rejects_an_oversized_request)
{
    unsigned char ikm[4] = {1u, 2u, 3u, 4u};
    unsigned char out[8161];
    /* RFC 5869 caps output at 255 * HashLen = 8160 bytes. */
    TT_ASSERT(tamga_hkdf_sha256(NULL, 0u, ikm, sizeof(ikm), NULL, 0u, out, 8160u));
    TT_ASSERT_FALSE(tamga_hkdf_sha256(NULL, 0u, ikm, sizeof(ikm), NULL, 0u, out, 8161u));
    TT_ASSERT_FALSE(tamga_hkdf_sha256(NULL, 0u, ikm, sizeof(ikm), NULL, 0u, out, 0u));
}

/*
 * Cross-implementation vectors: every expected value below was produced by
 * calling tamga-rust's own derive_license_file_key / derive_machine_file_key.
 * These are the fleet's interop anchor -- a divergence here means this SDK
 * cannot decrypt a file any other SDK can.
 */
static void derivations_are(const char *license_key, const char *fingerprint,
                            const char *expected_license_hex, const char *expected_machine_hex)
{
    unsigned char key[TAMGA_FILE_KEY_LEN];

    if (!tamga_derive_license_file_key(license_key, key)) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: licence-file derivation failed\n", tt_current_);
        return;
    }
    expect_digest_hex(key, sizeof(key), expected_license_hex);

    if (!tamga_derive_machine_file_key(license_key, fingerprint, key)) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: machine-file derivation failed\n", tt_current_);
        return;
    }
    expect_digest_hex(key, sizeof(key), expected_machine_hex);
}

TT_TEST(file_key_derivations_match_tamga_rust)
{
    derivations_are("", "",
                    "10d1cfeb54588d72f6762e5a3a9ff3194a2e306862dc28058260c2992751d8ee",
                    "c366b09c04a88dad31330a0bd46c83d3de074acb53c5c8e9c5b5171e271535d0");
    derivations_are("LICENSE-KEY-123", "fp-abc",
                    "9f026c11f182780e383ba9bc9107c3c2f46461d6f9bba1095cc98f3f267709c0",
                    "020ab9be017707762fb1002e3beea7e8fc0d34b71e0be09b530b8a1a8450d477");
    derivations_are("a", "b",
                    "1ab644e42c29b0a9a2ca46346f93aefe90b94b4daf6095ea8d6e523606361bbd",
                    "70abe2c1eb5d4632d58083b05ff641f767702653dfabafb3b41b671237a5d799");
    derivations_are("MUP7-2TQK-7FBF-4Q6H-Y7ZR-9C3V", "9f8e7d6c5b4a39281706",
                    "ce9b22c217476b6ee5cb816333d090c24dae14e45566468baf47b4f9383ca688",
                    "87abf977ee0a16f086e72d4bfe61e0cfc202a98a8269ada736043bcff9be3342");
    /* Licence key exactly one HMAC block long, then one byte longer -- the
     * boundary where RFC 2104 switches from padding the key to hashing it. */
    derivations_are("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "x",
                    "55b76cad2028b695d952363c69395e14ce2e41ae95f3bc954d6bb2019647e69b",
                    "2a83c6e3f6e2279fc28529ab2082015e818fca346ee120b7cb59d6a455579a3a");
    derivations_are("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefX", "x",
                    "77e7c63b680f0711c367939f78357fae007f6c1e8e244a8b2a88e5f943ce3aff",
                    "870d85fbb4466e90481cef94a9db4691a5216eafd36a699cf1801d41d3978ca7");
    /* Multi-byte UTF-8 on both sides: the derivation is over raw bytes, so
     * any encoding normalisation would break interop. */
    derivations_are("anahtar-\xC3\xA7\xC3\xB6\xC4\x9F", "parmak-izi-\xF0\x9F\x98\x80",
                    "ef0db78ce77c0ee42893eaa476c17b5e886e54156de8d06e87f76ceacac5ad38",
                    "1f3648cf7dc3f6a3105ac17b7334196a27162dffc7021213d712e9809aeb348b");
}

/*
 * The two derivations must never coincide. Swapping them produces code that
 * compiles, looks plausible, and silently decrypts nothing -- so the property
 * is asserted directly rather than left implied by the vectors above.
 */
TT_TEST(the_two_derivations_are_distinct)
{
    unsigned char license_key[TAMGA_FILE_KEY_LEN];
    unsigned char machine_key[TAMGA_FILE_KEY_LEN];

    TT_ASSERT(tamga_derive_license_file_key("same", license_key));
    TT_ASSERT(tamga_derive_machine_file_key("same", "license-file", machine_key));
    TT_ASSERT_FALSE(tamga_ct_memeq(license_key, machine_key, TAMGA_FILE_KEY_LEN));
}

/* The fingerprint is bound into the machine-file key, which is what makes a
 * machine file undecryptable on a machine it was not issued for. */
TT_TEST(the_machine_key_depends_on_the_fingerprint)
{
    unsigned char a[TAMGA_FILE_KEY_LEN];
    unsigned char b[TAMGA_FILE_KEY_LEN];

    TT_ASSERT(tamga_derive_machine_file_key("k", "fingerprint-one", a));
    TT_ASSERT(tamga_derive_machine_file_key("k", "fingerprint-two", b));
    TT_ASSERT_FALSE(tamga_ct_memeq(a, b, TAMGA_FILE_KEY_LEN));
}

/* Concatenation must not be ambiguous: ("ab","c") and ("a","bc") are
 * different inputs and must produce different keys. */
TT_TEST(key_and_fingerprint_boundaries_do_not_collide)
{
    unsigned char a[TAMGA_FILE_KEY_LEN];
    unsigned char b[TAMGA_FILE_KEY_LEN];

    TT_ASSERT(tamga_derive_machine_file_key("ab", "c", a));
    TT_ASSERT(tamga_derive_machine_file_key("a", "bc", b));
    TT_ASSERT_FALSE(tamga_ct_memeq(a, b, TAMGA_FILE_KEY_LEN));
}

TT_TEST(derivations_reject_null_arguments)
{
    unsigned char key[TAMGA_FILE_KEY_LEN];
    TT_ASSERT_FALSE(tamga_derive_license_file_key(NULL, key));
    TT_ASSERT_FALSE(tamga_derive_machine_file_key(NULL, "f", key));
    TT_ASSERT_FALSE(tamga_derive_machine_file_key("k", NULL, key));
}

TT_TEST(constant_time_compare_agrees_with_memcmp)
{
    const unsigned char a[4] = {1u, 2u, 3u, 4u};
    const unsigned char b[4] = {1u, 2u, 3u, 4u};
    const unsigned char c[4] = {1u, 2u, 3u, 5u};
    const unsigned char d[4] = {9u, 2u, 3u, 4u};

    TT_ASSERT(tamga_ct_memeq(a, b, sizeof(a)));
    TT_ASSERT_FALSE(tamga_ct_memeq(a, c, sizeof(a)));
    TT_ASSERT_FALSE(tamga_ct_memeq(a, d, sizeof(a)));
    TT_ASSERT(tamga_ct_memeq(a, c, 3u));
    TT_ASSERT(tamga_ct_memeq(a, b, 0u));
    TT_ASSERT_FALSE(tamga_ct_memeq(NULL, b, sizeof(a)));
    TT_ASSERT_FALSE(tamga_ct_memeq(a, NULL, sizeof(a)));
}

int main(void)
{
    TT_RUN(sha256_matches_fips_vectors);
    TT_RUN(sha256_matches_the_long_message_vector);
    TT_RUN(sha256_streams_identically_to_one_shot);
    TT_RUN(sha512_matches_fips_vectors);
    TT_RUN(sha512_streams_identically_to_one_shot);
    TT_RUN(hmac_sha256_matches_rfc4231);
    TT_RUN(hkdf_matches_rfc5869);
    TT_RUN(hkdf_rejects_an_oversized_request);
    TT_RUN(file_key_derivations_match_tamga_rust);
    TT_RUN(the_two_derivations_are_distinct);
    TT_RUN(the_machine_key_depends_on_the_fingerprint);
    TT_RUN(key_and_fingerprint_boundaries_do_not_collide);
    TT_RUN(derivations_reject_null_arguments);
    TT_RUN(constant_time_compare_agrees_with_memcmp);
    return TT_SUMMARY();
}
