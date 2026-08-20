/*
 * Modular exponentiation tests.
 *
 * The reference values are computed independently (arbitrary-precision
 * arithmetic outside this codebase) for moduli shaped like real RSA keys:
 * odd, with the top bit set.
 */
#include "tamga_test.h"

#include "crypto/bn.h"

static void modexp_is(const char *modulus_hex, const char *base_hex, const char *exponent_hex,
                      const char *expected_hex) {
    unsigned char modulus[256];
    unsigned char base[256];
    unsigned char exponent[8];
    unsigned char expected[256];
    unsigned char actual[256];
    size_t mod_len;
    size_t exp_len;

    mod_len = tt_hex2bin(modulus_hex, modulus, sizeof(modulus));
    TT_ASSERT(mod_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_hex2bin(base_hex, base, sizeof(base)), mod_len);
    TT_ASSERT_EQ_SIZE(tt_hex2bin(expected_hex, expected, sizeof(expected)), mod_len);
    exp_len = tt_hex2bin(exponent_hex, exponent, sizeof(exponent));
    TT_ASSERT(exp_len != (size_t)-1);

    TT_ASSERT(tamga_bn_modexp(base, modulus, mod_len, exponent, exp_len, actual));
    TT_ASSERT_EQ_MEM(actual, expected, mod_len);
}

TT_TEST(modexp_matches_a_2048_bit_reference) {
    modexp_is("ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
              "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
              "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
              "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
              "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
              "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
              "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
              "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05112f",
              "00c803f2da43d27f9f8d246ce3dd126c32b49941d814e5064d33f69f8cfa739a"
              "ecf69fdab950d758bcf95c7f7149bebac96232df058c0eeda361401ec0280cd8"
              "993956c197fb85d281bae1fde01d18a6022299e2b8b5ce807e8f811c0b56be23"
              "c02ab5e6acd0bb60675f56bcc86483160c013ee6c9947802c819f1f4b35ec415"
              "15403cb102f5658751f65dc263b339031e143db568a81244d5a36d743754f5f7"
              "97e5d5854b19aa20c654c06e4a45f73f06e9b3d7ea53d74726fdd1684acd870a"
              "2f8e4f3035d869b12f869be96fd5c517456ce09150a332c90c4a9a23d6ec0366"
              "f6e4c333afbad55dbe450ac69c73fa6b4b0f665bca9d1964dbf67e7d128e3730",
              "00010001",
              "0e88bbe23d3607e876fd38a29c37516c557b7fcfb9f1e8dc3f5a0ff4b1c43afb"
              "b629b2f65cbff8e1264bb1bb86ce3c2361ba347247dc5572234ced852d9d0e49"
              "51de406de776adf58fdc0a637f98d0e6d1984037e7c6262f00952e5175c66341"
              "25dad305721bb0c9a980d78db30502b71c905913a5bb5741efda440734933b0b"
              "3ceb86dd459b04178337e309571dd0a182b411425066a3e5fd46b44a8d60707f"
              "f7ad98d9a7acce7533a49d5ee5e527b14158dd4e85ed26fd8439eb4cbf4259a5"
              "4e719ac3bad92482f5678b9d61442c4d965974fed67239ded277b22f8b4cfc7f"
              "8edd2be0e0a82ff32c8b9a4501ad7dbc2e351500ac7dfaafed41d35a2bb446ff");
}

TT_TEST(modexp_matches_a_1024_bit_reference_with_exponent_three) {
    modexp_is("c40abd638f81efe20109a3490ade118a700f3a6bb11f16cdb8e560169434acaa"
              "812e99b8865bf24f6e947bc1e610f19ada45c10242cde6637928690569802bef"
              "9d9c06d6b0f058c2c7c882fc25747fb2b25c78308c61ac18a2e9be275ffe3d80"
              "084cb5e2dd4412ff7cd7144a85b8283df4a1fe16fc7105161b404afa8a32ac11",
              "000000e76cd126049acd82ecbd71ce56d8b19b03a62b6468e865f127bdd51899"
              "12bc2c842e1f229c67511863286201533653b1d49af45e3871b7546ea932a614"
              "2e80d6a440fe5253dd80f4bb7d558aafbc41086e6883509bca6b8ca0beb244f5"
              "e4b8c0cc07622440d13cec7257d4f337d9e38d1cb1d485cc413fd4bfacd89674",
              "03",
              "65881158866f6464fe50df166bc336ff29b06f66b19c4f2029595ffebe038b0e"
              "e855c54395bd50f1e83618798974eb7a4b9c265fdb88ac48774c5328c8521fde"
              "edac97c2919c2a512a2942db2c148e6332051a81bfe1b94eb7a5290b0ace23e5"
              "9898e69261d0aa680fb7e50d40ea55d44b779bc015dc7b84152a63be65b45088");
}

TT_TEST(modexp_handles_the_trivial_bases) {
    unsigned char modulus[256];
    unsigned char value[256];
    unsigned char out[256];
    const unsigned char exponent[3] = {0x01u, 0x00u, 0x01u};
    size_t mod_len;

    mod_len = tt_hex2bin("ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
                         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
                         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
                         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
                         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
                         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
                         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
                         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05112f",
                         modulus, sizeof(modulus));
    TT_ASSERT_EQ_SIZE(mod_len, 256u);

    /* 0^e = 0 */
    memset(value, 0, mod_len);
    TT_ASSERT(tamga_bn_modexp(value, modulus, mod_len, exponent, sizeof(exponent), out));
    TT_ASSERT_EQ_MEM(out, value, mod_len);

    /* 1^e = 1 */
    memset(value, 0, mod_len);
    value[mod_len - 1u] = 1u;
    TT_ASSERT(tamga_bn_modexp(value, modulus, mod_len, exponent, sizeof(exponent), out));
    TT_ASSERT_EQ_MEM(out, value, mod_len);
}

/*
 * The preconditions Montgomery form depends on. An even modulus has no
 * inverse mod 2^32; a modulus without its top bit set breaks the shortcut
 * used to compute R mod n; and a base at or above the modulus is a malformed
 * signature representative, not something to silently reduce.
 */
TT_TEST(modexp_rejects_inputs_that_break_its_preconditions) {
    unsigned char modulus[256];
    unsigned char base[256];
    unsigned char out[256];
    const unsigned char exponent[3] = {0x01u, 0x00u, 0x01u};

    memset(modulus, 0xffu, sizeof(modulus));
    memset(base, 0x01u, sizeof(base));

    /* even modulus */
    modulus[255] = 0xfeu;
    TT_ASSERT_FALSE(
        tamga_bn_modexp(base, modulus, sizeof(modulus), exponent, sizeof(exponent), out));

    /* top bit clear */
    memset(modulus, 0xffu, sizeof(modulus));
    modulus[0] = 0x7fu;
    TT_ASSERT_FALSE(
        tamga_bn_modexp(base, modulus, sizeof(modulus), exponent, sizeof(exponent), out));

    /* base >= modulus */
    memset(modulus, 0xffu, sizeof(modulus));
    memset(base, 0xffu, sizeof(base));
    TT_ASSERT_FALSE(
        tamga_bn_modexp(base, modulus, sizeof(modulus), exponent, sizeof(exponent), out));

    /* zero exponent */
    memset(base, 0x01u, sizeof(base));
    {
        const unsigned char zero_exponent[2] = {0x00u, 0x00u};
        TT_ASSERT_FALSE(tamga_bn_modexp(base, modulus, sizeof(modulus), zero_exponent,
                                        sizeof(zero_exponent), out));
    }

    /* out-of-range lengths */
    TT_ASSERT_FALSE(tamga_bn_modexp(base, modulus, 0u, exponent, sizeof(exponent), out));
    TT_ASSERT_FALSE(tamga_bn_modexp(NULL, modulus, 256u, exponent, sizeof(exponent), out));
}

int main(void) {
    TT_RUN(modexp_matches_a_2048_bit_reference);
    TT_RUN(modexp_matches_a_1024_bit_reference_with_exponent_three);
    TT_RUN(modexp_handles_the_trivial_bases);
    TT_RUN(modexp_rejects_inputs_that_break_its_preconditions);
    return TT_SUMMARY();
}
