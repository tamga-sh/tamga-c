/*
 * Machine-file verification across all four signature schemes.
 *
 * Fixtures come from tests/fixtures/offline, produced independently and
 * confirmed against tamga-rust's verifier before being written out.
 */
#include "tamga_test.h"

#include "checkout/machine_file.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/json.h"

#define FILE_CAP 8192
#define KEY_CAP 512

static const char LICENCE_KEY[] = "MUP7-2TQK-7FBF-4Q6H-Y7ZR-9C3V";
static const char FINGERPRINT[] = "9f8e7d6c5b4a39281706";

/* Verifies one fixture with one scheme and key, and checks the decoded
 * resource is the machine rather than the envelope. */
static void verifies(const char *file, uint32_t scheme, const char *key_file,
                     const char *license_key, const char *fingerprint) {
    char pem[FILE_CAP];
    unsigned char pubkey[KEY_CAP];
    size_t pem_len;
    size_t pubkey_len;
    TamgaJson *resource = NULL;
    TamgaErrorCode status;

    pem_len = tt_read_fixture(file, (unsigned char *)pem, sizeof(pem));
    pubkey_len = tt_read_fixture(key_file, pubkey, sizeof(pubkey));
    if (pem_len == (size_t)-1 || pubkey_len == (size_t)-1) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: could not load %s / %s\n", tt_current_, file, key_file);
        return;
    }

    status = tamga_machine_file_verify_into(pem, pem_len, scheme, pubkey, pubkey_len, license_key,
                                            fingerprint, &resource);
    if (status != TAMGA_OK) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: %s rejected with %s (%s)\n", tt_current_, file,
                      tamga_error_name(status),
                      tamga_last_error_message() ? tamga_last_error_message() : "");
        return;
    }
    if (strcmp(tamga_json_as_string(tamga_json_object_get(resource, "type"), NULL), "machines") !=
        0) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: %s did not decode to a machine resource\n", tt_current_,
                      file);
    }
    tamga_json_free(resource);
}

TT_TEST(verifies_every_signature_scheme) {
    verifies("offline/machine_ed25519.mach", (uint32_t)TAMGA_SCHEME_ED25519_SIGN,
             "offline/ed25519_pubkey.bin", NULL, NULL);
    verifies("offline/machine_rsa_pkcs1.mach", (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_SIGN,
             "offline/rsa_spki.der", NULL, NULL);
    verifies("offline/machine_rsa_pss.mach", (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN,
             "offline/rsa_spki.der", NULL, NULL);
    verifies("offline/machine_ecdsa.mach", (uint32_t)TAMGA_SCHEME_ECDSA_P256_SIGN,
             "offline/ecdsa_point.bin", NULL, NULL);
}

TT_TEST(verifies_an_encrypted_machine_file) {
    verifies("offline/machine_ed25519_encrypted.mach", (uint32_t)TAMGA_SCHEME_ED25519_SIGN,
             "offline/ed25519_pubkey.bin", LICENCE_KEY, FINGERPRINT);
}

/*
 * The machine-file key binds the fingerprint, which is what stops a file
 * issued for one machine from decrypting on another even when the attacker
 * holds the licence key.
 */
TT_TEST(an_encrypted_file_will_not_decrypt_for_another_machine) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    pem_len = tt_read_fixture("offline/machine_ed25519_encrypted.mach", (unsigned char *)pem,
                              sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", pubkey, sizeof(pubkey)), 32u);

    TT_ASSERT_EQ_INT(tamga_machine_file_verify_into(
                         pem, pem_len, (uint32_t)TAMGA_SCHEME_ED25519_SIGN, pubkey, sizeof(pubkey),
                         LICENCE_KEY, "a-different-fingerprint", &resource),
                     TAMGA_ERR_DECRYPTION_FAILED);
    TT_ASSERT_NULL(resource);

    /* And the licence key alone is not enough. */
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_into(pem, pem_len,
                                                    (uint32_t)TAMGA_SCHEME_ED25519_SIGN, pubkey,
                                                    sizeof(pubkey), LICENCE_KEY, NULL, &resource),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_NULL(resource);
}

/*
 * The scheme comes from the caller (the licence's own field), never from the
 * file. A file that declares one suffix must not verify when the licence says
 * another -- otherwise whoever controls the file controls which primitive
 * runs.
 */
TT_TEST(the_declared_algorithm_must_match_the_caller_supplied_scheme) {
    char pem[FILE_CAP];
    unsigned char pubkey[512];
    size_t pem_len;
    size_t pubkey_len;
    TamgaJson *resource = NULL;

    pem_len = tt_read_fixture("offline/machine_rsa_pkcs1.mach", (unsigned char *)pem, sizeof(pem));
    pubkey_len = tt_read_fixture("offline/rsa_spki.der", pubkey, sizeof(pubkey));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT(pubkey_len != (size_t)-1);

    /* The file says rsa-sha256; asking for PSS must fail on the suffix check
     * before any verification is attempted. */
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_into(pem, pem_len,
                                                    (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN,
                                                    pubkey, pubkey_len, NULL, NULL, &resource),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_NULL(resource);
}

/*
 * RSA_2048_JWT_RS256 is a real LicenseScheme value but never a legal
 * machine-file input -- the server itself returns 422 SCHEME_NOT_SUPPORTED
 * for it. It shares the "rsa-sha256" alg suffix with RSA_2048_PKCS1_SIGN,
 * which is precisely why the file cannot be trusted to declare the scheme.
 */
TT_TEST(rejects_the_jwt_scheme_and_the_none_scheme) {
    char pem[FILE_CAP];
    unsigned char pubkey[512];
    size_t pem_len;
    size_t pubkey_len;
    TamgaJson *resource = NULL;

    pem_len = tt_read_fixture("offline/machine_rsa_pkcs1.mach", (unsigned char *)pem, sizeof(pem));
    pubkey_len = tt_read_fixture("offline/rsa_spki.der", pubkey, sizeof(pubkey));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT(pubkey_len != (size_t)-1);

    TT_ASSERT_EQ_INT(tamga_machine_file_verify_into(pem, pem_len,
                                                    (uint32_t)TAMGA_SCHEME_RSA_2048_JWT_RS256,
                                                    pubkey, pubkey_len, NULL, NULL, &resource),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_into(pem, pem_len, (uint32_t)TAMGA_SCHEME_NONE,
                                                    pubkey, pubkey_len, NULL, NULL, &resource),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    /* A value outside the enum entirely. A C enum has no validity range at
     * the ABI level, so this is a reachable input, not a hypothetical. */
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_into(pem, pem_len, 9999u, pubkey, pubkey_len, NULL,
                                                    NULL, &resource),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_NULL(resource);
}

TT_TEST(rejects_a_wrong_key_and_a_tampered_body) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;
    size_t i;

    pem_len = tt_read_fixture("offline/machine_ed25519.mach", (unsigned char *)pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", pubkey, sizeof(pubkey)), 32u);

    pubkey[5] ^= 0x01u;
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_into(pem, pem_len,
                                                    (uint32_t)TAMGA_SCHEME_ED25519_SIGN, pubkey,
                                                    sizeof(pubkey), NULL, NULL, &resource),
                     TAMGA_ERR_SIGNATURE_INVALID);
    pubkey[5] ^= 0x01u;

    for (i = 0u; i < pem_len; i++) {
        if (pem[i] == '\n') {
            pem[i + 40u] = (pem[i + 40u] == 'A') ? 'B' : 'A';
            break;
        }
    }
    TT_ASSERT(tamga_machine_file_verify_into(pem, pem_len, (uint32_t)TAMGA_SCHEME_ED25519_SIGN,
                                             pubkey, sizeof(pubkey), NULL, NULL,
                                             &resource) != TAMGA_OK);
    TT_ASSERT_NULL(resource);
}

/* The wrong marker text must be rejected, so a licence file cannot be
 * verified as a machine file or vice versa. */
TT_TEST(rejects_a_licence_file_presented_as_a_machine_file) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    pem_len = tt_read_fixture("offline/license_plain.lic", (unsigned char *)pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", pubkey, sizeof(pubkey)), 32u);

    TT_ASSERT_EQ_INT(tamga_machine_file_verify_into(pem, pem_len,
                                                    (uint32_t)TAMGA_SCHEME_ED25519_SIGN, pubkey,
                                                    sizeof(pubkey), NULL, NULL, &resource),
                     TAMGA_ERR_INVALID_PEM);
    TT_ASSERT_NULL(resource);
}

TT_TEST(the_ttl_range_matches_the_server) {
    TT_ASSERT_FALSE(tamga_machine_file_ttl_is_valid(0));
    TT_ASSERT_FALSE(tamga_machine_file_ttl_is_valid(-1));
    TT_ASSERT(tamga_machine_file_ttl_is_valid(1));
    TT_ASSERT(tamga_machine_file_ttl_is_valid(TAMGA_MACHINE_FILE_MAX_TTL_SECONDS));
    TT_ASSERT_FALSE(tamga_machine_file_ttl_is_valid(TAMGA_MACHINE_FILE_MAX_TTL_SECONDS + 1));
}

int main(void) {
    TT_RUN(verifies_every_signature_scheme);
    TT_RUN(verifies_an_encrypted_machine_file);
    TT_RUN(an_encrypted_file_will_not_decrypt_for_another_machine);
    TT_RUN(the_declared_algorithm_must_match_the_caller_supplied_scheme);
    TT_RUN(rejects_the_jwt_scheme_and_the_none_scheme);
    TT_RUN(rejects_a_wrong_key_and_a_tampered_body);
    TT_RUN(rejects_a_licence_file_presented_as_a_machine_file);
    TT_RUN(the_ttl_range_matches_the_server);
    return TT_SUMMARY();
}
