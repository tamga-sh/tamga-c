/*
 * Cross-SDK conformance.
 *
 * Every fixture here was produced by tamga-go -- a third implementation,
 * written independently of both this SDK and tamga-rust, from the same
 * protocol specification. Nothing in this repository generated any of it.
 *
 * That independence is the whole value. The fixtures in
 * tests/fixtures/offline/ prove agreement with tamga-rust, which is the
 * reference; these prove that three implementations that never shared code
 * agree on the same bytes. A format detail all three got wrong the same way
 * would still slip through, but a detail any one of them got wrong
 * differently shows up here.
 *
 * Provenance and parameters: tests/fixtures/cross-sdk/README.md.
 */
#include "tamga_test.h"

#include "checkout/license_file.h"
#include "checkout/machine_file.h"
#include "proof.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/json.h"

#define CAP 4096

static const char LICENCE_KEY[] = "lic-abc123";
static const char FINGERPRINT[] = "fp-abc123";
/* After the fixtures' iat (2026-01-01) and before any expiry they carry. */
static const int64_t NOW = 1780000000;

/* Reads a fixture, asserting it loaded. Returns the length. */
static size_t load(const char *name, unsigned char *out, size_t cap) {
    size_t len = tt_read_fixture(name, out, cap);
    if (len == (size_t)-1) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: could not load %s\n", tt_current_, name);
    }
    return len;
}

/* The licence resource inside every licence fixture carries this key. */
static void expect_licence_key(const TamgaJson *resource, const char *expected) {
    const TamgaJson *attributes = tamga_json_object_get(resource, "attributes");
    const char *key = tamga_json_as_string(tamga_json_object_get(attributes, "key"), NULL);

    if (key == NULL || strcmp(key, expected) != 0) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: licence key is %s, expected %s\n", tt_current_,
                      key ? key : "(absent)", expected);
    }
}

TT_TEST(verifies_a_plain_licence_file_from_another_sdk) {
    unsigned char pem[CAP];
    unsigned char pubkey[32];
    size_t pem_len = load("cross-sdk/license_file_plain.lic", pem, sizeof(pem));
    TamgaJson *resource = NULL;

    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(load("cross-sdk/ed25519_pubkey.bin", pubkey, sizeof(pubkey)), 32u);

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at((const char *)pem, pem_len, pubkey, NULL, NOW,
                                                  &resource, NULL),
                     TAMGA_OK);
    TT_ASSERT_NOT_NULL(resource);
    expect_licence_key(resource, LICENCE_KEY);
    tamga_json_free(resource);
}

/* Exercises the HKDF derivation and AES-GCM open against bytes a different
 * implementation encrypted -- the strongest possible check that the salt,
 * info and nonce layout all match. */
TT_TEST(decrypts_an_encrypted_licence_file_from_another_sdk) {
    unsigned char pem[CAP];
    unsigned char pubkey[32];
    size_t pem_len = load("cross-sdk/license_file_encrypted.lic", pem, sizeof(pem));
    TamgaJson *resource = NULL;

    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(load("cross-sdk/ed25519_pubkey.bin", pubkey, sizeof(pubkey)), 32u);

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at((const char *)pem, pem_len, pubkey, LICENCE_KEY,
                                                  NOW, &resource, NULL),
                     TAMGA_OK);
    TT_ASSERT_NOT_NULL(resource);
    expect_licence_key(resource, LICENCE_KEY);
    tamga_json_free(resource);

    /* The wrong key must fail the tag check rather than yield anything. */
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at((const char *)pem, pem_len, pubkey, "wrong-key",
                                                  NOW, &resource, NULL),
                     TAMGA_ERR_DECRYPTION_FAILED);
}

static void verifies_machine_file(const char *fixture, const char *key_fixture, uint32_t scheme,
                                  const char *license_key, const char *fingerprint) {
    unsigned char pem[CAP];
    unsigned char pubkey[CAP];
    size_t pem_len = load(fixture, pem, sizeof(pem));
    size_t pubkey_len = load(key_fixture, pubkey, sizeof(pubkey));
    TamgaJson *resource = NULL;
    TamgaErrorCode status;

    if (pem_len == (size_t)-1 || pubkey_len == (size_t)-1) {
        return;
    }

    status = tamga_machine_file_verify_into((const char *)pem, pem_len, scheme, pubkey, pubkey_len,
                                            license_key, fingerprint, &resource);
    if (status != TAMGA_OK) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: %s rejected with %s (%s)\n", tt_current_, fixture,
                      tamga_error_name(status),
                      tamga_last_error_message() ? tamga_last_error_message() : "");
        return;
    }
    {
        const TamgaJson *attributes = tamga_json_object_get(resource, "attributes");
        const char *value =
            tamga_json_as_string(tamga_json_object_get(attributes, "fingerprint"), NULL);
        if (value == NULL || strcmp(value, FINGERPRINT) != 0) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s decoded the wrong machine\n", tt_current_, fixture);
        }
    }
    tamga_json_free(resource);
}

TT_TEST(verifies_every_machine_file_scheme_from_another_sdk) {
    verifies_machine_file("cross-sdk/machine_file_ed25519.machine", "cross-sdk/ed25519_pubkey.bin",
                          (uint32_t)TAMGA_SCHEME_ED25519_SIGN, NULL, NULL);
    verifies_machine_file("cross-sdk/machine_file_rsa_pkcs1.machine",
                          "cross-sdk/rsa_pkcs1_pubkey.der",
                          (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_SIGN, NULL, NULL);
    /* RSA-PSS is deliberately absent -- see
     * rejects_a_pss_signature_with_a_salt_the_reference_rejects below. */
    /* The ECDSA fixture is the encrypted variant, so this one covers the
     * machine-file HKDF derivation as well as the signature. */
    verifies_machine_file("cross-sdk/machine_file_ecdsa.machine", "cross-sdk/ecdsa_point.bin",
                          (uint32_t)TAMGA_SCHEME_ECDSA_P256_SIGN, LICENCE_KEY, FINGERPRINT);
}

/*
 * A documented divergence, not a passing case.
 *
 * tamga-go's RSA-PSS fixture is signed with a 222-byte salt: Go's
 * rsa.SignPSS with nil options means PSSSaltLengthAuto, which on the signing
 * side makes the salt as large as the modulus allows. Go verifies with
 * PSSSaltLengthAuto too, so it accepts its own fixture.
 *
 * The reference implementation does not. Checked directly: tamga-rust, via
 * aws-lc-rs's RSA_PSS_2048_8192_SHA256, REJECTS this exact file, and accepts
 * a 32-byte-salt signature over the same message. So salt length equal to the
 * digest length is the fleet's convention, and this SDK matching the
 * reference is correct while being stricter than tamga-go's verifier.
 *
 * Asserted rather than deleted, because "we skipped that one" loses the
 * finding. If a future change made this file verify, this SDK would be
 * accepting signatures the reference rejects -- which is a divergence worth
 * failing a test over, whichever direction it runs in.
 */
TT_TEST(rejects_a_pss_signature_with_a_salt_the_reference_rejects) {
    unsigned char pem[CAP];
    unsigned char pubkey[CAP];
    size_t pem_len = load("cross-sdk/machine_file_rsa_pss.machine", pem, sizeof(pem));
    size_t pubkey_len = load("cross-sdk/rsa_pss_pubkey.der", pubkey, sizeof(pubkey));
    TamgaJson *resource = NULL;

    TT_ASSERT(pem_len != (size_t)-1 && pubkey_len != (size_t)-1);

    TT_ASSERT_EQ_INT(tamga_machine_file_verify_into((const char *)pem, pem_len,
                                                    (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN,
                                                    pubkey, pubkey_len, NULL, NULL, &resource),
                     TAMGA_ERR_SIGNATURE_INVALID);
    TT_ASSERT_NULL(resource);
}

/*
 * The canonical serialization, checked against a third implementation's
 * golden bytes.
 *
 * This is the single most valuable assertion in the file. The proof's
 * signature covers a byte-exact JSON payload whose object keys are sorted at
 * every level, and getting that ordering wrong produces a verifier that
 * rejects every real proof while looking like a key problem. Three
 * independent implementations agreeing on these bytes is what makes the
 * ordering a fact rather than an assumption.
 */
TT_TEST(verifies_an_offline_proof_from_another_sdk) {
    unsigned char proof[CAP];
    unsigned char dataset[CAP];
    unsigned char spki[CAP];
    unsigned char params[CAP];
    size_t proof_len = load("cross-sdk/proof.txt", proof, sizeof(proof) - 1u);
    size_t dataset_len = load("cross-sdk/proof_dataset.json", dataset, sizeof(dataset) - 1u);
    size_t spki_len = load("cross-sdk/proof_rsa_pubkey.der", spki, sizeof(spki));
    size_t params_len = load("cross-sdk/proof_params.txt", params, sizeof(params) - 1u);
    char *account_id;
    char *machine_id;
    char *fingerprint;
    bool valid = false;

    TT_ASSERT(proof_len != (size_t)-1 && dataset_len != (size_t)-1);
    TT_ASSERT(spki_len != (size_t)-1 && params_len != (size_t)-1);
    proof[proof_len] = '\0';
    dataset[dataset_len] = '\0';
    params[params_len] = '\0';

    /* proof_params.txt is account id, machine id and fingerprint, one per
     * line, in that order. */
    account_id = strtok((char *)params, "\n");
    machine_id = strtok(NULL, "\n");
    fingerprint = strtok(NULL, "\n");
    TT_ASSERT_NOT_NULL(account_id);
    TT_ASSERT_NOT_NULL(machine_id);
    TT_ASSERT_NOT_NULL(fingerprint);

    TT_ASSERT_EQ_INT(tamga_proof_verify((const char *)proof, spki, spki_len, account_id, machine_id,
                                        fingerprint, (const char *)dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT(valid);

    /* And the tuple is genuinely bound: a different fingerprint must not
     * verify against the same proof. */
    valid = true;
    TT_ASSERT_EQ_INT(tamga_proof_verify((const char *)proof, spki, spki_len, account_id, machine_id,
                                        "fp-different", (const char *)dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);
}

/*
 * The golden payload, byte for byte.
 *
 * tamga-go committed the exact bytes it signed. Rebuilding them here from the
 * same inputs and comparing character by character localises a canonical-JSON
 * divergence to the serializer, instead of leaving it as "the signature did
 * not verify" -- which could be the serializer, the hash, or the RSA maths.
 */
TT_TEST(reproduces_another_sdks_canonical_payload_exactly) {
    unsigned char expected[CAP];
    size_t expected_len = load("cross-sdk/proof_payload.json", expected, sizeof(expected) - 1u);
    TamgaJson *root;
    TamgaJson *account;
    TamgaJson *machine;
    TamgaJson *dataset;
    char *actual;
    const char *error = NULL;

    TT_ASSERT(expected_len != (size_t)-1);
    expected[expected_len] = '\0';

    root = tamga_json_new_object();
    account = tamga_json_new_object();
    machine = tamga_json_new_object();
    dataset = tamga_json_parse("{\"cores\":4}", 11u, &error);
    TT_ASSERT_NOT_NULL(root);
    TT_ASSERT_NOT_NULL(account);
    TT_ASSERT_NOT_NULL(machine);
    TT_ASSERT_NOT_NULL(dataset);

    /* Deliberately inserted in the order the server's source writes them, so
     * the sort is doing the work rather than the insertion order. */
    TT_ASSERT(tamga_json_object_set(
        account, "id", tamga_json_new_string("01926b3e-0000-7000-8000-000000000000", 36u)));
    TT_ASSERT(tamga_json_object_set(
        machine, "id", tamga_json_new_string("01926b3e-1111-7000-8000-000000000000", 36u)));
    TT_ASSERT(tamga_json_object_set(machine, "fingerprint", tamga_json_new_string("fp-abc", 6u)));
    TT_ASSERT(tamga_json_object_set(root, "account", account));
    TT_ASSERT(tamga_json_object_set(root, "machine", machine));
    TT_ASSERT(tamga_json_object_set(root, "dataset", dataset));

    actual = tamga_json_write_canonical(root, NULL);
    tamga_json_free(root);
    TT_ASSERT_NOT_NULL(actual);
    TT_ASSERT_EQ_STR(actual, (const char *)expected);
    tamga_free(actual);
}

int main(void) {
    TT_RUN(verifies_a_plain_licence_file_from_another_sdk);
    TT_RUN(decrypts_an_encrypted_licence_file_from_another_sdk);
    TT_RUN(verifies_every_machine_file_scheme_from_another_sdk);
    TT_RUN(rejects_a_pss_signature_with_a_salt_the_reference_rejects);
    TT_RUN(verifies_an_offline_proof_from_another_sdk);
    TT_RUN(reproduces_another_sdks_canonical_payload_exactly);
    return TT_SUMMARY();
}
