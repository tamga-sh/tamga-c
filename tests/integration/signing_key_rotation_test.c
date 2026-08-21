/*
 * The rotation scenario, end to end -- M22.
 *
 * When an account rotates its Ed25519 signing key, a `.lic` or machine file
 * checked out BEFORE the rotation is still authentic and its licence may still
 * be perfectly valid. Verified against one embedded key it fails with exactly
 * the error a forged file produces, so a paying customer is locked out and
 * support is sent looking for tampering.
 *
 * These tests assert the distinction rather than the happy path: the same file
 * that reports TAMGA_ERR_SIGNATURE_INVALID through the single-key entry point
 * reports TAMGA_ERR_UNKNOWN_SIGNING_KEY through a key set that has not caught
 * up, and a genuinely tampered file whose `kid` IS known still reports
 * TAMGA_ERR_SIGNATURE_INVALID. A test that only proved the good file verifies
 * would pass against an implementation that reported every failure the same
 * way, which is the bug.
 *
 * The machine fixtures here came out of the SERVER's own encoder -- see
 * tests/fixtures/server-machine-files/README.md. They were issued with a
 * one-hour ttl, so every assertion supplies its own `now`.
 */
#include "tamga_test.h"

#include "checkout/key_set.h"
#include "checkout/license_file.h"
#include "checkout/machine_file.h"
#include "tamga.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"
#include "util/json.h"

#include <stdio.h>
#include <string.h>

#define FILE_CAP 8192

/* Before any fixture's exp, and past the skew tolerance so the expiry check is
 * genuinely exercised rather than short-circuited. */
#define BEFORE_ANY_EXPIRY 1000

/* The Ed25519 machine fixture, from that directory's manifest.json. */
static const char ED25519_KEY_B64[] = "AQAg/HkMCKUVnpDfZAVDWheJo2UmA6fiBHTUDgCFC0g=";
static const char ED25519_KID[] = "dc45aa88aa947b02";
static const char FINGERPRINT[] = "fixture-fingerprint-a1b2c3";

/* A different, equally well-formed key -- the one an account would be signing
 * with AFTER a rotation. */
static const char ROTATED_KEY_B64[] = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/* The kid the repository's own .lic fixtures carry. Not sixteen hex
 * characters, because those files were generated here rather than issued --
 * which is precisely why a kid's shape is matched as an opaque string and
 * never validated. */
static const char LICENCE_FIXTURE_KID[] = "key-1";

/*
 * Base64 of 64 zero bytes: a signature of exactly the length Ed25519 requires
 * and of no other merit. The structural length check runs before any key is
 * chosen, so a short one would be refused for that reason instead of reaching
 * the selection these tests are about.
 */
static const char DUMMY_SIGNATURE_B64[] =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAA==";

static size_t load(const char *name, char *out, size_t cap) {
    return tt_read_fixture(name, (unsigned char *)out, cap);
}

/* Builds a one-key `signing-keys` collection in the server's own shape, so the
 * set under test is populated the way a real one would be. */
static bool add_served_key(TamgaSigningKeySet *set, const char *kid, const char *public_key_b64) {
    char document[1024];
    int written = snprintf(document, sizeof(document),
                           "{\"data\":[{\"type\":\"signing-keys\",\"id\":\"%s\",\"attributes\":{"
                           "\"algorithm\":\"ed25519\",\"publicKey\":\"%s\","
                           "\"status\":\"retired\",\"created\":\"2026-01-01T00:00:00Z\","
                           "\"retired\":\"2026-06-01T00:00:00Z\"}}]}",
                           kid, public_key_b64);

    if (written <= 0 || (size_t)written >= sizeof(document)) {
        return false;
    }
    return tamga_signing_key_set_add_json(set, document, (uintptr_t)written, NULL, NULL, NULL) ==
           TAMGA_OK;
}

/* --- the licence file ---------------------------------------------------- */

TT_TEST(a_licence_file_verifies_through_the_key_its_kid_names) {
    char pem[FILE_CAP];
    unsigned char raw_key[32];
    char *key_b64;
    size_t pem_len;
    TamgaSigningKeySet *set = NULL;
    TamgaJson *resource = NULL;

    pem_len = load("offline/license_plain.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", raw_key, 32u), 32u);
    key_b64 = tamga_base64_encode_alloc(raw_key, 32u);
    TT_ASSERT_NOT_NULL(key_b64);

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    /* Two keys, and only one of them signed this file. Selection has to pick
     * the right one -- a set holding a single key could not tell the
     * difference between selecting and simply having no choice. */
    TT_ASSERT(add_served_key(set, "0f0f0f0f0f0f0f0f", ROTATED_KEY_B64));
    TT_ASSERT(add_served_key(set, LICENCE_FIXTURE_KID, key_b64));
    TT_ASSERT_EQ_SIZE(tamga_signing_key_set_count(set), 2u);
    tamga_string_free(key_b64);

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at_with_key_set(pem, pem_len, set, NULL,
                                                               BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_OK);
    TT_ASSERT_NOT_NULL(resource);
    tamga_json_free(resource);
    tamga_signing_key_set_free(set);
}

TT_TEST(a_stale_key_set_is_reported_as_stale_and_not_as_a_forgery) {
    char pem[FILE_CAP];
    unsigned char raw_key[32];
    unsigned char wrong_key[32];
    size_t pem_len;
    TamgaSigningKeySet *set = NULL;
    TamgaJson *resource = NULL;
    size_t i;

    pem_len = load("offline/license_plain.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", raw_key, 32u), 32u);
    for (i = 0u; i < 32u; i++) {
        wrong_key[i] = (unsigned char)(raw_key[i] ^ 0xFFu);
    }

    /*
     * THE assertion this whole change exists for. One authentic file, two
     * entry points, two different answers:
     *
     *   - against a single wrong key it is indistinguishable from a forgery;
     *   - against a key set that does not hold its kid it is named as what it
     *     is, so the caller knows to refetch the keys rather than accuse the
     *     customer.
     */
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(pem, pem_len, wrong_key, NULL, BEFORE_ANY_EXPIRY,
                                                  &resource, NULL),
                     TAMGA_ERR_SIGNATURE_INVALID);
    TT_ASSERT_NULL(resource);

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT(add_served_key(set, "0f0f0f0f0f0f0f0f", ROTATED_KEY_B64));
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at_with_key_set(pem, pem_len, set, NULL,
                                                               BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_ERR_UNKNOWN_SIGNING_KEY);
    TT_ASSERT_NULL(resource);
    /* The diagnostic names the kid, so a support log says which key to go and
     * fetch. */
    TT_ASSERT_NOT_NULL(tamga_last_error_message());
    TT_ASSERT_NOT_NULL(strstr(tamga_last_error_message(), LICENCE_FIXTURE_KID));

    tamga_signing_key_set_free(set);
}

TT_TEST(an_empty_key_set_still_reports_the_condition_rather_than_a_forgery) {
    char pem[FILE_CAP];
    size_t pem_len;
    TamgaSigningKeySet *set = NULL;
    TamgaJson *resource = NULL;

    pem_len = load("offline/license_plain.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at_with_key_set(pem, pem_len, set, NULL,
                                                               BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_ERR_UNKNOWN_SIGNING_KEY);
    TT_ASSERT_NULL(resource);
    tamga_signing_key_set_free(set);
}

TT_TEST(a_tampered_file_whose_key_is_known_is_still_a_forgery) {
    char pem[FILE_CAP];
    unsigned char raw_key[32];
    char *key_b64;
    size_t pem_len;
    TamgaSigningKeySet *set = NULL;
    TamgaJson *resource = NULL;
    TamgaJson *cert = NULL;
    char *body;
    size_t body_len = 0u;
    unsigned char *decoded;
    size_t decoded_len = 0u;
    char forged[FILE_CAP];
    char *cert_json;
    char *cert_b64;
    const char *sig;
    TamgaJson *replacement;
    int written;

    pem_len = load("offline/license_plain.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", raw_key, 32u), 32u);
    key_b64 = tamga_base64_encode_alloc(raw_key, 32u);
    TT_ASSERT_NOT_NULL(key_b64);

    /*
     * Rewrite the SIGNATURE rather than the payload. Corrupting `enc` would
     * change the bytes the kid is read from too, so the file would fail
     * earlier and for a different reason -- and the point here is a file whose
     * kid resolves perfectly and whose signature does not.
     */
    body = pem + strlen("-----BEGIN LICENSE FILE-----");
    while (*body == '\n' || *body == '\r') {
        body++;
    }
    body_len = strcspn(body, "\n\r");
    decoded = tamga_base64_decode_alloc(body, body_len, &decoded_len);
    TT_ASSERT_NOT_NULL(decoded);
    cert = tamga_json_parse((const char *)decoded, decoded_len, NULL);
    tamga_free(decoded);
    TT_ASSERT_NOT_NULL(cert);

    sig = tamga_json_as_string(tamga_json_object_get(cert, "sig"), NULL);
    TT_ASSERT_NOT_NULL(sig);
    /* A well-formed 64-byte signature that is simply not the right one. */
    replacement = tamga_json_new_string(DUMMY_SIGNATURE_B64, strlen(DUMMY_SIGNATURE_B64));
    TT_ASSERT_NOT_NULL(replacement);
    TT_ASSERT(tamga_json_object_set(cert, "sig", replacement));
    cert_json = tamga_json_write(cert, NULL);
    tamga_json_free(cert);
    TT_ASSERT_NOT_NULL(cert_json);
    cert_b64 = tamga_base64_encode_alloc((const unsigned char *)cert_json, strlen(cert_json));
    tamga_free(cert_json);
    TT_ASSERT_NOT_NULL(cert_b64);
    written = snprintf(forged, sizeof(forged),
                       "-----BEGIN LICENSE FILE-----\n%s\n-----END LICENSE FILE-----\n", cert_b64);
    tamga_free(cert_b64);
    TT_ASSERT(written > 0 && (size_t)written < sizeof(forged));

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT(add_served_key(set, LICENCE_FIXTURE_KID, key_b64));
    tamga_string_free(key_b64);

    /* The kid resolves, so the key set is not the problem -- and the answer
     * says so. Reporting this as an unknown key would send a caller chasing
     * keys forever for a file that was altered. */
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at_with_key_set(forged, (size_t)written, set, NULL,
                                                               BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_ERR_SIGNATURE_INVALID);
    TT_ASSERT_NULL(resource);
    tamga_signing_key_set_free(set);
}

TT_TEST(an_account_that_published_no_key_is_told_apart_from_a_stale_set) {
    /*
     * A file whose kid is SHA-256("") -- what both server checkout handlers
     * stamp in when `account.ed25519_public_key` is unset. Refetching the key
     * set will never produce a match, so it must not be reported as a set that
     * needs refetching.
     *
     * The signature here is deliberately not a real one: key selection happens
     * BEFORE verification on this path, which is exactly what this asserts.
     */
    char payload[512];
    char cert[1024];
    char pem[FILE_CAP];
    char *payload_b64;
    char *cert_b64;
    int written;
    TamgaSigningKeySet *set = NULL;
    TamgaJson *resource = NULL;

    written = snprintf(payload, sizeof(payload),
                       "{\"data\":{\"type\":\"licenses\",\"id\":\"x\"},"
                       "\"meta\":{\"iat\":1700000000,\"kid\":\"%s\"}}",
                       TAMGA_UNPUBLISHED_KEY_ID);
    TT_ASSERT(written > 0 && (size_t)written < sizeof(payload));
    payload_b64 = tamga_base64_encode_alloc((const unsigned char *)payload, (size_t)written);
    TT_ASSERT_NOT_NULL(payload_b64);

    written = snprintf(cert, sizeof(cert),
                       "{\"enc\":\"%s\",\"sig\":\"%s\",\"alg\":\"base64+ed25519+v2\"}", payload_b64,
                       DUMMY_SIGNATURE_B64);
    tamga_free(payload_b64);
    TT_ASSERT(written > 0 && (size_t)written < sizeof(cert));
    cert_b64 = tamga_base64_encode_alloc((const unsigned char *)cert, (size_t)written);
    TT_ASSERT_NOT_NULL(cert_b64);
    written = snprintf(pem, sizeof(pem),
                       "-----BEGIN LICENSE FILE-----\n%s\n-----END LICENSE FILE-----\n", cert_b64);
    tamga_free(cert_b64);
    TT_ASSERT(written > 0 && (size_t)written < sizeof(pem));

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT(add_served_key(set, "0f0f0f0f0f0f0f0f", ROTATED_KEY_B64));
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at_with_key_set(pem, (size_t)written, set, NULL,
                                                               BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_ERR_SIGNING_KEY_NOT_PUBLISHED);
    TT_ASSERT_NULL(resource);
    tamga_signing_key_set_free(set);
}

TT_TEST(the_public_entry_point_verifies_against_the_wall_clock) {
    char pem[FILE_CAP];
    unsigned char raw_key[32];
    char *key_b64;
    size_t pem_len;
    TamgaSigningKeySet *set = NULL;
    TamgaLicenseFile *handle = NULL;
    char *json = NULL;
    uintptr_t json_len = 0u;

    /* license_plain.lic carries no `exp`, so a checkout made without a ttl
     * genuinely never expires and this stays true indefinitely. */
    pem_len = load("offline/license_plain.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", raw_key, 32u), 32u);
    key_b64 = tamga_base64_encode_alloc(raw_key, 32u);
    TT_ASSERT_NOT_NULL(key_b64);

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT(add_served_key(set, LICENCE_FIXTURE_KID, key_b64));
    tamga_string_free(key_b64);

    TT_ASSERT_EQ_INT(
        tamga_license_file_verify_with_key_set(pem, (uintptr_t)pem_len, set, NULL, &handle),
        TAMGA_OK);
    TT_ASSERT_NOT_NULL(handle);
    /* TAMGA_OK implies no message, on this entry point as on every other. */
    TT_ASSERT_NULL(tamga_last_error_message());
    TT_ASSERT_EQ_INT(tamga_license_file_get_json(handle, &json, &json_len), TAMGA_OK);
    TT_ASSERT_NOT_NULL(json);
    TT_ASSERT(json_len > 0u);
    tamga_string_free(json);
    tamga_license_file_free(handle);
    tamga_signing_key_set_free(set);
}

TT_TEST(an_encrypted_licence_file_is_decrypted_before_its_key_is_chosen) {
    char pem[FILE_CAP];
    unsigned char raw_key[32];
    char *key_b64;
    size_t pem_len;
    TamgaSigningKeySet *set = NULL;
    TamgaJson *resource = NULL;
    static const char LICENCE_KEY[] = "MUP7-2TQK-7FBF-4Q6H-Y7ZR-9C3V";

    /* The kid lives inside the ciphertext, so this path has to decrypt before
     * it can choose a key at all -- and therefore needs the licence key
     * BEFORE the signature is checked rather than after. */
    pem_len = load("offline/license_encrypted.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", raw_key, 32u), 32u);
    key_b64 = tamga_base64_encode_alloc(raw_key, 32u);
    TT_ASSERT_NOT_NULL(key_b64);

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT(add_served_key(set, LICENCE_FIXTURE_KID, key_b64));
    tamga_string_free(key_b64);

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at_with_key_set(pem, pem_len, set, LICENCE_KEY,
                                                               BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_OK);
    TT_ASSERT_NOT_NULL(resource);
    tamga_json_free(resource);

    /* Without the licence key it cannot get as far as the kid, and says so as
     * a missing argument rather than as an unknown signing key. */
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at_with_key_set(pem, pem_len, set, NULL,
                                                               BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_NULL(resource);
    tamga_signing_key_set_free(set);
}

/* --- machine files ------------------------------------------------------- */

TT_TEST(an_ed25519_machine_file_verifies_through_the_key_its_kid_names) {
    char pem[FILE_CAP];
    size_t pem_len;
    TamgaSigningKeySet *set = NULL;
    TamgaJson *resource = NULL;
    char computed[TAMGA_KEY_ID_SIZE];

    pem_len = load("server-machine-files/ed25519_plain_valid.machine", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    /*
     * The server's own file names this kid, and the hash rule reproduces it
     * from the manifest's key -- so the two halves of this feature agree on
     * material this repository did not generate.
     *
     * The Ed25519 fixture is the ONE case where the fixture generator's rule
     * and the live server's rule coincide, because this file's own signing key
     * IS the account's Ed25519 key. For the RSA and ECDSA fixtures they
     * diverge, which is why those are exercised below only as a refusal.
     */
    TT_ASSERT_EQ_INT(tamga_signing_key_id(ED25519_KEY_B64, computed), TAMGA_OK);
    TT_ASSERT_EQ_STR(computed, ED25519_KID);

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT(add_served_key(set, "0f0f0f0f0f0f0f0f", ROTATED_KEY_B64));
    /* Added by the pinned-key path, which computes the id itself -- the route
     * an embedded client must take, because a licence key cannot call
     * GET /signing-keys at all. */
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, ED25519_KEY_B64), TAMGA_OK);

    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at_with_key_set(
                         pem, pem_len, (uint32_t)TAMGA_SCHEME_ED25519_SIGN, set, NULL, FINGERPRINT,
                         BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_OK);
    TT_ASSERT_NOT_NULL(resource);
    tamga_json_free(resource);
    tamga_signing_key_set_free(set);
}

TT_TEST(a_machine_file_signed_under_another_scheme_is_refused_by_name) {
    char pem[FILE_CAP];
    size_t pem_len;
    TamgaSigningKeySet *set = NULL;
    TamgaJson *resource = NULL;

    pem_len = load("server-machine-files/rsa_pkcs1_plain_valid.machine", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, ED25519_KEY_B64), TAMGA_OK);

    /*
     * An RSA-signed machine file's kid names the account's ED25519 key -- both
     * checkout handlers compute it from `account.ed25519_public_key` whatever
     * scheme signed the bytes -- so it cannot select the RSA key that actually
     * signed this file. Saying that precisely is the difference between a
     * caller reaching for the right entry point and one believing its file is
     * unsupported.
     */
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at_with_key_set(
                         pem, pem_len, (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_SIGN, set, NULL,
                         FINGERPRINT, BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_ERR_KEY_ID_NOT_APPLICABLE);
    TT_ASSERT_NULL(resource);
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at_with_key_set(
                         pem, pem_len, (uint32_t)TAMGA_SCHEME_ECDSA_P256_SIGN, set, NULL,
                         FINGERPRINT, BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_ERR_KEY_ID_NOT_APPLICABLE);

    /* A scheme this library refuses outright stays refused the same way on
     * both paths: NONE and JWT_RS256 are not "a kid problem". */
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at_with_key_set(
                         pem, pem_len, (uint32_t)TAMGA_SCHEME_NONE, set, NULL, FINGERPRINT,
                         BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at_with_key_set(
                         pem, pem_len, (uint32_t)TAMGA_SCHEME_RSA_2048_JWT_RS256, set, NULL,
                         FINGERPRINT, BEFORE_ANY_EXPIRY, &resource, NULL),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at_with_key_set(pem, pem_len, 4242u, set, NULL,
                                                               FINGERPRINT, BEFORE_ANY_EXPIRY,
                                                               &resource, NULL),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_NULL(resource);
    tamga_signing_key_set_free(set);
}

TT_TEST(a_machine_files_signed_exp_is_still_enforced_through_a_key_set) {
    char pem[FILE_CAP];
    size_t pem_len;
    TamgaSigningKeySet *set = NULL;
    TamgaJson *resource = NULL;
    TamgaFileClaims claims;

    pem_len = load("server-machine-files/ed25519_plain_valid.machine", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, ED25519_KEY_B64), TAMGA_OK);

    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at_with_key_set(
                         pem, pem_len, (uint32_t)TAMGA_SCHEME_ED25519_SIGN, set, NULL, FINGERPRINT,
                         BEFORE_ANY_EXPIRY, &resource, &claims),
                     TAMGA_OK);
    tamga_json_free(resource);
    resource = NULL;
    TT_ASSERT(claims.has_expiry);

    /*
     * Choosing the key by kid must not quietly cost the expiry check. A file
     * that verifies forever is the v1 defect, and it would be an easy thing to
     * lose while reordering the steps around it.
     */
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at_with_key_set(
                         pem, pem_len, (uint32_t)TAMGA_SCHEME_ED25519_SIGN, set, NULL, FINGERPRINT,
                         claims.expiry + 3600, &resource, NULL),
                     TAMGA_ERR_EXPIRED);
    TT_ASSERT_NULL(resource);
    tamga_signing_key_set_free(set);
}

int main(void) {
    TT_RUN(a_licence_file_verifies_through_the_key_its_kid_names);
    TT_RUN(a_stale_key_set_is_reported_as_stale_and_not_as_a_forgery);
    TT_RUN(an_empty_key_set_still_reports_the_condition_rather_than_a_forgery);
    TT_RUN(a_tampered_file_whose_key_is_known_is_still_a_forgery);
    TT_RUN(an_account_that_published_no_key_is_told_apart_from_a_stale_set);
    TT_RUN(the_public_entry_point_verifies_against_the_wall_clock);
    TT_RUN(an_encrypted_licence_file_is_decrypted_before_its_key_is_chosen);
    TT_RUN(an_ed25519_machine_file_verifies_through_the_key_its_kid_names);
    TT_RUN(a_machine_file_signed_under_another_scheme_is_refused_by_name);
    TT_RUN(a_machine_files_signed_exp_is_still_enforced_through_a_key_set);
    return TT_SUMMARY();
}
