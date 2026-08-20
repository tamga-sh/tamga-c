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

/*
 * Extremal-base modular exponentiation.
 *
 * Added after a security review found that the Curve25519 field
 * multiplication dropped a carry for operands within a few hundred of 2^256 --
 * a defect the entire RFC 8032 suite passed straight through, because
 * realistic values essentially never land in that window. The Montgomery code
 * here is a different algorithm, but the blind spot is the same shape, so the
 * bases below cluster against the modulus instead of spreading out.
 *
 * Expected results were computed with arbitrary-precision arithmetic outside
 * this codebase.
 */
TT_TEST(modexp_is_correct_for_bases_near_the_modulus) {
    static const char *const modulus_hex =
        "ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
        "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
        "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
        "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
        "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
        "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
        "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
        "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05112f";
    static const char *const vectors[][2] = {
        {"ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05112e",
         "ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05112e"},
        {"ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05112d",
         "5cae24856d161b8c18632a2f78ae34bd99c5d23234c049d6e3d07d3ea3529921"
         "b452d08c9af7478dd8bfe8e690fee440d3329304e17e42f92ab9cdd7728da261"
         "8ecf19dbfeffa8a723f913841427fc293786cc1692537e9d51df2e5a814463be"
         "61dfbe1c010f15605ad22a366df60dee3728d599b3532fc0a4d3d3a1be07237a"
         "89ed2841d120dd083ac7d82246ac5b9382eca9788ba7ec13ee12021a233763ac"
         "bb7bdf39fea292a6354cfa6da0ce66ade0604889998ce0070197f38e7e547457"
         "09681ac9524447f45dcfc7e63cc6abdb6d2610bea879dd23f938f25c06dc2831"
         "8e1ce73c200732a5237bbb933a13268c75ce5cc41fbdc8fb0720f47e180dd63c"},
        {"ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05112c",
         "4ee53bcb2752afa0a8dbd609cf10110b3cb75547ed6f77b315b2175294b57684"
         "2b90758fb46ee34ff8609bd895ad36a70e90b1f18c9c73388101d719761389c1"
         "3ac815d378f466730853dfd6993af9acee56e74e43b8040334c48e626716a89c"
         "dc28bc107979e73d353f0e02ce7faa60bf2635817480c3a4821ca1f56030af50"
         "7112cd9c599f20c11ff46c9f1d01bbe45e7b6f0bf6fae30c4c1684497011b1f4"
         "b9ddce54a5ac2cbc61f7a1f08e67877991fa9e7a6c89da890c517bb1779e2688"
         "b17770fdadc324fe63e7783efd49c90721907c65bc3317665735b410d5e22481"
         "919b62dd71bb6383b31761d053580742cf29849ae7c6be3094f5d1c277b5b239"},
        {"ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05111c",
         "022999482378a8773fc33490c9b3741cc8198c16a636d70403c10333bf35b1fa"
         "65e199ea7b99bb8427c83b3d8a96af8271245df7adf96f5b32d49b8a415622eb"
         "a430ed16e34d846b181fedf9e305cea0477626b38de8b2b477a2c3b0d67e6aa4"
         "11a08a0ce2fafb620d36e0770c75d69ffccc75ba69e6564ac0f4cfd9f379f821"
         "7d0a894dca41faacd7d55d20159ea05c4ceabedecf48dbae16a90f282976466d"
         "4ba0f8ba5852133bed5dc790f196943090c29dcec0a303e5052ccc98c0b590f1"
         "eff2b069075618e539d308da214777361cf4aa15de86f8ca283e3e657d0ba7d8"
         "fdb435e3e96e90c7e1a729d29ca2147798123b269b388b60dc69da95d558f161"},
        {"ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea051109",
         "7e0ca297e7d5a069bf4934a90a59b08266198203a12b338bb2de103ed7c6997c"
         "d356563cd54e6e90496e20f0d887e3b9652e0521a4ecffa676a44469a4ddb952"
         "a27dce5e397b0f1bd29d8c682c148a9d7510f0160facb70ea54b3ed957815361"
         "60b1898f13334eed4751479e0e4c39954da49104720969be0e46ef861a3a5a7f"
         "0e5e2f37c760a9665bc4b73d892afb852e807e77375de558caa948a89c165a64"
         "a84c9e8c0ad22f48472fd17dd81ea326d365d850d89617762643f11d59850c23"
         "198a8c9a51a98c9bd71adfbf4d9f2124f58eb992cf511acea95984dca7e35e01"
         "61ea96f126dd39c9121bd1e880868456c1aaa8318a8caa60e7f48efad28b0330"},
        {"ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea051030",
         "77cb3aa76854ba58007a1805f08ee1d876ea5e42d991014de5f9ad21bfac36d2"
         "bd61b4fa2d2d7ddaf7f863765f7833c2f340a069e4cb41bb69afdaa347d1cc77"
         "e2c25e98e11afa64d932f9b428bf2f79f3de47348587690c5e8d009f3645b89d"
         "5324561a2a0de98c678aa3d1664d2ec27851e704c5883cbbd6255b5401c10429"
         "07ac129c26819509a85761c5d843863d2e8cfa125bade8a70ed762d17c229ead"
         "e5f583f47b8932013ff343684348903ab89b51dd4c9e9323b6bb6ce03187ada9"
         "23f328f3b03f50a0f98d0a82e358c2e5c3820a4edec9cf06ea5e8419b40c6985"
         "a201d55c47f0c417bc60f7183553fb70b0db20ac0b952420f9cb4dac2d9c3036"},
        {"ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05102f",
         "1818975cc78dbdd86dbf99e1d5ce5022c18b1b9adeb83eda2e2b84aeb2564eb9"
         "317b5bd4978601c107d734c9905f01389b6aedb2d639740f725e7d34d9bf1839"
         "83847b4fa2c9df3e60966f66f415fa14864cf4bdece976d64f410986b36e5a1b"
         "603d52839db8d82fbef09413998ec0cfa1cc2a53443104a9b56346aaa9f7d134"
         "6a5dec446ba44304d46a7c25c09f9161e15585df090e4dccfd8fb2fddb8c2032"
         "f1f3246ae597cd7a888159b6d1010316717d0b5196ee3b09186a589a3914077e"
         "de89dcf0dbba477746a6c18a6bb22e17d28f59426ce94eac60374a81ae5cd168"
         "6bd94bfad2c2e96cabdc0b01b88ded277d7a782ba8aadecaeedf0d169ba1cea6"},
        {"ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
         "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
         "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
         "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
         "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
         "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
         "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
         "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea04112e",
         "351a37795c27d8176bed002dd9f553bdf235666370c5c41c2dfdc103d989fdf4"
         "8e4ebcd16f469ddb5f4cfa88975503eb810ca3b9952ad8f4a4efd8c593417ef9"
         "68babfbaa2684677224f159c7e6d4f789aa3ed03027e9cd88adb530b624b69f8"
         "70d438e7e469ff36a41089e978078b10d30d6a87618dbf46dcc0f009c2a12e80"
         "cde891309d48b2426702bfdf507eceb34e6a5cfb38cc728f635d937f89d56b30"
         "55b4a33651b527493f3d7b76ccc6e120d5ef92bbc6497aa4cdf16429ed189ed6"
         "b4c343fc8589a5f97eb249d8790fee1a87370cd083a5dd7216762b065712dc97"
         "3c050cdc4c82e605940efa5d0d9627152584a0864b999e11d5289ac9f79b8aa2"},
        {"0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000",
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"},
        {"0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000001",
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000001"},
        {"0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000002",
         "90327106a0b46343311c8fb6d6ce117cd3df23225151b982c0b135550c2648d9"
         "9b5db53751bdd714fbd7936704e5f765385167db889121b743c4f0a9191f7cd3"
         "d887fe7b8e98a77961c8a795b6e8f4d81c9fe63302f5ad7b322c0cba17c9273b"
         "afdf2d2eb9d0b16794b0853e858e560f3157a7b4c7708f66b0859e75d66d8c1d"
         "63b9a5e39295e67cf6c07582ae21c8f7263e52602beefc9bb98d6712a644589f"
         "00be53ea6b6360b9dd2bf5c4588860c6a6cc0b76f858e81b61849b2942aa6480"
         "b731892d4f4d327c17b85378317828953c1bd655f425847ef1e9381e673ad744"
         "25fc3149d82f0a281c4925397575b6221dfb7dcf603d5093e8a0331ad1f73af3"},
        {"76704ac606e53f67a4bfdcf327be231d36d27aaa430901acd240d949d7bc70fd"
         "a7d842e1f65a8f516a4bbe26caf26dd305c1fd703507b258373f5f4045d68f9a"
         "b3ab8c2bc6cc281042e0dd8ce5887880aa135924caa4960c42059d8a4c86c57d"
         "08df75a55d6fe363f7c157ba79c231feb4403ea73d61df93aaacb90bca3a57cb"
         "f6d36712b1db61c298c426d27a67124554957dec5bcb7457d3cfb49664bdde25"
         "de1d19923502f9b0093c7818fcab63ba43962a0048f2e411318e475be07f6c6b"
         "e04cd1fb50c8bd383ac40daf371f6a3854a0f38a4e4fb0d17591153d370b7fba"
         "da0c8c42fc1b1e669fe2706657c46e5749e4ed49bffd8cc777e093cc75028897",
         "7bbd352633fc45b6da0af01f242b2f2dd053f8f9031872233895c4e69ce77833"
         "6efe34a86984feae7ac05c60df36e9696ac48db15a24b1be63ab44f37d91cd89"
         "b3ef4e2c0a9de990f18a3db577df665116e94c73884b5d866cac7427635b013e"
         "4d032643ee522ca930c80d7178f57fac6d6b1f304d504415db651dfa97cf1cdc"
         "7d9fb1ccc52becbe8ef4db9afba44497a84deec43b068b850770e7421e700abe"
         "ba28710946532fc4d0434496c37cfd910da10748e510e29f2b819a9b44fe44d1"
         "b937c875c43141bd374298c779b035823a8c9041eef8a46323a202934d9f6c47"
         "8a6aef04d67b26a3ec31e694aaf101c9750c92dc4cbf0423343fafcfe9ec3893"},
        {"76704ac606e53f67a4bfdcf327be231d36d27aaa430901acd240d949d7bc70fd"
         "a7d842e1f65a8f516a4bbe26caf26dd305c1fd703507b258373f5f4045d68f9a"
         "b3ab8c2bc6cc281042e0dd8ce5887880aa135924caa4960c42059d8a4c86c57d"
         "08df75a55d6fe363f7c157ba79c231feb4403ea73d61df93aaacb90bca3a57cb"
         "f6d36712b1db61c298c426d27a67124554957dec5bcb7457d3cfb49664bdde25"
         "de1d19923502f9b0093c7818fcab63ba43962a0048f2e411318e475be07f6c6b"
         "e04cd1fb50c8bd383ac40daf371f6a3854a0f38a4e4fb0d17591153d370b7fba"
         "da0c8c42fc1b1e669fe2706657c46e5749e4ed49bffd8cc777e093cc75028897",
         "7bbd352633fc45b6da0af01f242b2f2dd053f8f9031872233895c4e69ce77833"
         "6efe34a86984feae7ac05c60df36e9696ac48db15a24b1be63ab44f37d91cd89"
         "b3ef4e2c0a9de990f18a3db577df665116e94c73884b5d866cac7427635b013e"
         "4d032643ee522ca930c80d7178f57fac6d6b1f304d504415db651dfa97cf1cdc"
         "7d9fb1ccc52becbe8ef4db9afba44497a84deec43b068b850770e7421e700abe"
         "ba28710946532fc4d0434496c37cfd910da10748e510e29f2b819a9b44fe44d1"
         "b937c875c43141bd374298c779b035823a8c9041eef8a46323a202934d9f6c47"
         "8a6aef04d67b26a3ec31e694aaf101c9750c92dc4cbf0423343fafcfe9ec3893"},
    };
    static const unsigned char exponent[3] = {0x01u, 0x00u, 0x01u};
    unsigned char modulus[256];
    unsigned char base[256];
    unsigned char expected[256];
    unsigned char actual[256];
    size_t i;

    TT_ASSERT_EQ_SIZE(tt_hex2bin(modulus_hex, modulus, sizeof(modulus)), 256u);

    for (i = 0u; i < (sizeof(vectors) / sizeof(vectors[0])); i++) {
        TT_ASSERT_EQ_SIZE(tt_hex2bin(vectors[i][0], base, sizeof(base)), 256u);
        TT_ASSERT_EQ_SIZE(tt_hex2bin(vectors[i][1], expected, sizeof(expected)), 256u);
        TT_ASSERT(
            tamga_bn_modexp(base, modulus, sizeof(modulus), exponent, sizeof(exponent), actual));
        TT_ASSERT_EQ_MEM(actual, expected, sizeof(expected));
    }
}

/*
 * (b^i)^j == b^(i*j) mod n.
 *
 * Only exponentiation is exposed, so products of distinct values cannot be
 * checked directly -- but this identity needs nothing else, and it is a real
 * constraint rather than a smoke test: the left side runs two independent
 * ladders whose intermediate is an essentially uniform 2048-bit value, and
 * the right side runs one. A carry dropped anywhere in the Montgomery
 * multiplication makes the two disagree, over bases nobody enumerated.
 *
 * An earlier version of this test asserted only b^1 == b and b^3 != b^2 while
 * its comment claimed to check exponent additivity. Those two assertions hold
 * for a badly broken ladder; this one does not.
 */
TT_TEST(modexp_is_consistent_across_exponents) {
    static const char *const modulus_hex =
        "ece0958c0dca7ecf497fb9e64f7c463a6da4f55486120359a481b293af78e1fb"
        "4fb085c3ecb51ea2d4977c4d95e4dba60b83fae06a0f64b06e7ebe808bad1f35"
        "675718578d98502085c1bb19cb10f1015426b24995492c18840b3b14990d8afa"
        "11beeb4abadfc6c7ef82af74f38463fd68807d4e7ac3bf27555972179474af97"
        "eda6ce2563b6c38531884da4f4ce248aa92afbd8b796e8afa79f692cc97bbc4b"
        "bc3a33246a05f3601278f031f956c774872c540091e5c822631c8eb7c0fed8d7"
        "c099a3f6a1917a7075881b5e6e3ed470a941e7149c9f61a2eb222a7a6e16ff75"
        "b4191885f8363ccd3fc4e0ccaf88dcae93c9da937ffb198eefc12798ea05112f";
    /* (i, j, i*j). Deliberately not all powers of two: an exponent whose bits
     * are all set walks a different path through the square-and-multiply
     * ladder than one with a single bit. */
    static const struct {
        unsigned char i;
        unsigned char j;
        unsigned char product;
    } PAIRS[] = {{2u, 2u, 4u},   {3u, 5u, 15u},   {7u, 11u, 77u},
                 {5u, 13u, 65u}, {9u, 17u, 153u}, {15u, 15u, 225u}};
    unsigned char modulus[256];
    unsigned char base[256];
    unsigned char inner[256];
    unsigned char left[256];
    unsigned char right[256];
    unsigned char one_result[256];
    unsigned int round;
    unsigned int seed = 0xc0ffeeu;

    TT_ASSERT_EQ_SIZE(tt_hex2bin(modulus_hex, modulus, sizeof(modulus)), 256u);

    for (round = 0u; round < 36u; round++) {
        static const unsigned char one[1] = {0x01u};
        const unsigned char exp_i[1] = {PAIRS[round % 6u].i};
        const unsigned char exp_j[1] = {PAIRS[round % 6u].j};
        const unsigned char exp_ij[1] = {PAIRS[round % 6u].product};
        size_t k;

        /* Half the rounds sit right under the modulus, half are spread out.
         * A base adjacent to the modulus is what drives the ladder's
         * intermediates into the range where a reduction decision is made. */
        if ((round % 2u) == 0u) {
            memcpy(base, modulus, sizeof(base));
            base[255] = (unsigned char)(base[255] - (unsigned char)((round / 2u) + 1u));
        } else {
            for (k = 0u; k < sizeof(base); k++) {
                seed = (seed * 1103515245u) + 12345u;
                base[k] = (unsigned char)(seed >> 16);
            }
            base[0] &= 0x7fu; /* keep it below the modulus */
        }

        /* (b^i)^j */
        TT_ASSERT(tamga_bn_modexp(base, modulus, sizeof(modulus), exp_i, sizeof(exp_i), inner));
        TT_ASSERT(tamga_bn_modexp(inner, modulus, sizeof(modulus), exp_j, sizeof(exp_j), left));
        /* b^(i*j) */
        TT_ASSERT(tamga_bn_modexp(base, modulus, sizeof(modulus), exp_ij, sizeof(exp_ij), right));

        if (memcmp(left, right, sizeof(left)) != 0) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: (b^%u)^%u != b^%u at round %u\n", tt_current_,
                          (unsigned int)exp_i[0], (unsigned int)exp_j[0], (unsigned int)exp_ij[0],
                          round);
            return;
        }

        /* b^1 must be b reduced. Cheap, and it pins the one case where a
         * ladder that returned its input unchanged would satisfy everything
         * above. */
        TT_ASSERT(tamga_bn_modexp(base, modulus, sizeof(modulus), one, sizeof(one), one_result));
        TT_ASSERT_EQ_MEM(one_result, base, sizeof(base));
    }
}

int main(void) {
    TT_RUN(modexp_matches_a_2048_bit_reference);
    TT_RUN(modexp_matches_a_1024_bit_reference_with_exponent_three);
    TT_RUN(modexp_handles_the_trivial_bases);
    TT_RUN(modexp_rejects_inputs_that_break_its_preconditions);
    TT_RUN(modexp_is_correct_for_bases_near_the_modulus);
    TT_RUN(modexp_is_consistent_across_exponents);
    return TT_SUMMARY();
}
