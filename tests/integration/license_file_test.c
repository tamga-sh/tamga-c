/*
 * Licence-file verification, end to end.
 *
 * Every fixture in tests/fixtures/offline was produced in the server's format
 * by an independent generator and then run through tamga-rust's own verifier
 * before being written out -- see that directory's README. Testing against
 * files this implementation did not create is what makes these tests evidence
 * of interoperability rather than of self-consistency.
 */
#include "tamga_test.h"

#include "checkout/license_file.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"
#include "util/json.h"

#include <stdio.h>

#define FILE_CAP 8192

static const char LICENCE_KEY[] = "MUP7-2TQK-7FBF-4Q6H-Y7ZR-9C3V";
/* Comfortably after the fixtures' iat and before any non-expired exp. */
static const int64_t NOW = 1750000000;

static size_t load_text(const char *name, char *out, size_t cap) {
    return tt_read_fixture(name, (unsigned char *)out, cap);
}

static bool load_pubkey(unsigned char out[32]) {
    return tt_read_fixture("offline/ed25519_pubkey.bin", out, 32u) == 32u;
}

TT_TEST(verifies_a_plain_licence_file) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;
    TamgaFileClaims claims;
    char *json;

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_plain.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    TT_ASSERT_EQ_INT(
        tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, NOW, &resource, &claims),
        TAMGA_OK);
    TT_ASSERT_NOT_NULL(resource);
    TT_ASSERT_NULL(tamga_last_error_message());

    /* The decoded resource is the licence, not the envelope. */
    TT_ASSERT_EQ_STR(tamga_json_as_string(tamga_json_object_get(resource, "type"), NULL),
                     "licenses");
    TT_ASSERT_EQ_STR(tamga_json_as_string(tamga_json_object_get(resource, "id"), NULL),
                     "01926b3e-0000-7000-8000-000000000001");
    {
        const TamgaJson *attributes = tamga_json_object_get(resource, "attributes");
        int64_t machines = 0;
        TT_ASSERT_NOT_NULL(attributes);
        TT_ASSERT_EQ_STR(tamga_json_as_string(tamga_json_object_get(attributes, "name"), NULL),
                         "Acme Pro");
        TT_ASSERT(
            tamga_json_as_int(tamga_json_object_get(attributes, "machines_count"), &machines));
        TT_ASSERT_EQ_INT(machines, 2);
    }
    TT_ASSERT_EQ_INT(claims.issued_at, 1700000000);
    TT_ASSERT_FALSE(claims.has_expiry);

    json = tamga_json_write(resource, NULL);
    TT_ASSERT_NOT_NULL(json);
    tamga_free(json);
    tamga_json_free(resource);
}

TT_TEST(verifies_an_encrypted_licence_file) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_encrypted.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    TT_ASSERT_EQ_INT(
        tamga_license_file_verify_at(pem, pem_len, pubkey, LICENCE_KEY, NOW, &resource, NULL),
        TAMGA_OK);
    TT_ASSERT_NOT_NULL(resource);
    TT_ASSERT_EQ_STR(tamga_json_as_string(tamga_json_object_get(resource, "type"), NULL),
                     "licenses");
    tamga_json_free(resource);
}

TT_TEST(an_encrypted_file_needs_the_licence_key) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_encrypted.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, NOW, &resource, NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_NULL(resource);
    /* And the wrong key must fail the tag check, not produce garbage. */
    TT_ASSERT_EQ_INT(
        tamga_license_file_verify_at(pem, pem_len, pubkey, "WRONG-KEY", NOW, &resource, NULL),
        TAMGA_ERR_DECRYPTION_FAILED);
    TT_ASSERT_NULL(resource);
}

/*
 * An authentic file whose signed exp has passed. Reported as TAMGA_ERR_EXPIRED
 * rather than as a signature failure on purpose: a caller that cannot tell
 * "expired" from "forged" either accuses the user of tampering when their
 * trial ran out, or treats a forgery as a renewal prompt.
 */
TT_TEST(rejects_an_expired_file_distinguishably) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_expired.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, NOW, &resource, NULL),
                     TAMGA_ERR_EXPIRED);
    TT_ASSERT_NULL(resource);
    TT_ASSERT_NOT_NULL(tamga_last_error_message());

    /* The same file verifies when the clock is before the expiry, which
     * proves the rejection is the claim and not the signature. */
    TT_ASSERT_EQ_INT(
        tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, 1700000000, &resource, NULL),
        TAMGA_OK);
    tamga_json_free(resource);
}

/* The skew allowance is 60 seconds and no more: the client's clock is under
 * the adversary's control, so a generous allowance is a free extension on
 * every expired file. */
TT_TEST(the_expiry_check_allows_exactly_sixty_seconds_of_skew) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;
    const int64_t exp = 1700000100; /* the fixture's exp */

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_expired.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    TT_ASSERT_EQ_INT(
        tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, exp + 60, &resource, NULL),
        TAMGA_OK);
    tamga_json_free(resource);
    resource = NULL;
    TT_ASSERT_EQ_INT(
        tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, exp + 61, &resource, NULL),
        TAMGA_ERR_EXPIRED);
    TT_ASSERT_NULL(resource);
}

/*
 * Format v1 is refused outright. In v1 the ttl lived in the JSON envelope
 * around the certificate, outside the signature, so a 24-hour trial file was
 * cryptographically valid forever. Accepting both formats would hand that
 * back, which is why there is no fallback path.
 */
TT_TEST(rejects_format_v1) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_v1.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, NOW, &resource, NULL),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_NULL(resource);
}

/*
 * A JSON string may carry an interior NUL, and this parser accepts \u0000 in a
 * value (only keys reject it). Comparing `alg` with strcmp therefore stops at
 * that NUL, so "base64+ed25519+v2" followed by a NUL and arbitrary trailing
 * bytes compared equal to the algorithm it merely prefixes -- the length check
 * the surrounding comment claims to make was not actually being made. The
 * comparison is length-aware now; this pins that.
 *
 * The certificate is built here rather than loaded as a fixture because the
 * generator emits only well-formed algorithm strings. The alg dispatch runs
 * before the signature is even decoded, so the empty enc/sig below never get
 * that far -- which the companion assertion proves by showing the same shape
 * with an honest alg fails later, at the signature, not here.
 */
TT_TEST(rejects_an_algorithm_with_an_interior_nul) {
    static const char CERT_WITH_NUL[] =
        "{\"enc\":\"\",\"sig\":\"\",\"alg\":\"base64+ed25519+v2\\u0000junk\"}";
    static const char CERT_HONEST[] = "{\"enc\":\"\",\"sig\":\"\",\"alg\":\"base64+ed25519+v2\"}";
    unsigned char pubkey[32];
    char pem[FILE_CAP];
    char *encoded;
    TamgaJson *resource = NULL;
    int written;

    TT_ASSERT(load_pubkey(pubkey));

    encoded =
        tamga_base64_encode_alloc((const unsigned char *)CERT_WITH_NUL, sizeof(CERT_WITH_NUL) - 1u);
    TT_ASSERT_NOT_NULL(encoded);
    written = snprintf(pem, sizeof(pem),
                       "-----BEGIN LICENSE FILE-----\n%s\n-----END LICENSE FILE-----\n", encoded);
    tamga_string_free(encoded);
    TT_ASSERT(written > 0 && (size_t)written < sizeof(pem));

    TT_ASSERT_EQ_INT(
        tamga_license_file_verify_at(pem, (size_t)written, pubkey, NULL, NOW, &resource, NULL),
        TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_NULL(resource);

    /* Same certificate, honest alg: it gets past the dispatch and dies on the
     * empty signature instead. Without this the test above would still pass if
     * the file were rejected for some unrelated reason. */
    encoded =
        tamga_base64_encode_alloc((const unsigned char *)CERT_HONEST, sizeof(CERT_HONEST) - 1u);
    TT_ASSERT_NOT_NULL(encoded);
    written = snprintf(pem, sizeof(pem),
                       "-----BEGIN LICENSE FILE-----\n%s\n-----END LICENSE FILE-----\n", encoded);
    tamga_string_free(encoded);
    TT_ASSERT(written > 0 && (size_t)written < sizeof(pem));

    TT_ASSERT_EQ_INT(
        tamga_license_file_verify_at(pem, (size_t)written, pubkey, NULL, NOW, &resource, NULL),
        TAMGA_ERR_SIGNATURE_INVALID);
    TT_ASSERT_NULL(resource);
}

/*
 * THE format gotcha, as a fixture.
 *
 * This file is signed correctly in every respect except that the signature
 * covers enc's base64-DECODED bytes instead of the base64 string itself. An
 * implementation that decodes before verifying accepts this one and rejects
 * every real server-issued file -- the failure is total but looks like a key
 * problem, which is why it has cost this format's implementers so much time.
 */
TT_TEST(rejects_a_signature_over_the_decoded_bytes) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_signed_over_decoded_bytes.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, NOW, &resource, NULL),
                     TAMGA_ERR_SIGNATURE_INVALID);
    TT_ASSERT_NULL(resource);
}

TT_TEST(rejects_a_wrong_public_key) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_plain.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    pubkey[0] ^= 0x01u;

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, NOW, &resource, NULL),
                     TAMGA_ERR_SIGNATURE_INVALID);
}

TT_TEST(rejects_a_tampered_body) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;
    size_t i;

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_plain.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    /* Flip a character well inside the base64 body. */
    for (i = 0u; i < pem_len; i++) {
        if (pem[i] == '\n') {
            pem[i + 40u] = (pem[i + 40u] == 'A') ? 'B' : 'A';
            break;
        }
    }
    TT_ASSERT(tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, NOW, &resource, NULL) !=
              TAMGA_OK);
    TT_ASSERT_NULL(resource);
}

TT_TEST(rejects_malformed_envelopes) {
    unsigned char pubkey[32];
    TamgaJson *resource = NULL;
    static const char no_markers[] = "just some text";
    static const char begin_only[] = "-----BEGIN LICENSE FILE-----\nabc\n";
    /* Short enough that the two markers would overlap: prefix and suffix both
     * match, but there is no body between them. Without an explicit combined
     * length check this computes a negative body length. */
    static const char overlapping[] = "-----BEGIN LICENSE FILE---------END LICENSE FILE-----";
    static const char empty_body[] = "-----BEGIN LICENSE FILE-----\n\n-----END LICENSE FILE-----";

    TT_ASSERT(load_pubkey(pubkey));

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(no_markers, sizeof(no_markers) - 1u, pubkey, NULL,
                                                  NOW, &resource, NULL),
                     TAMGA_ERR_INVALID_PEM);
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(begin_only, sizeof(begin_only) - 1u, pubkey, NULL,
                                                  NOW, &resource, NULL),
                     TAMGA_ERR_INVALID_PEM);
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(overlapping, sizeof(overlapping) - 1u, pubkey,
                                                  NULL, NOW, &resource, NULL),
                     TAMGA_ERR_INVALID_PEM);
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(empty_body, sizeof(empty_body) - 1u, pubkey, NULL,
                                                  NOW, &resource, NULL),
                     TAMGA_ERR_INVALID_JSON);
    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(NULL, 10u, pubkey, NULL, NOW, &resource, NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_NULL(resource);
}

/*
 * A line-wrapped body. tamga-rust rejects this -- its parser trims only the
 * ends and hands the rest to a strict base64 decoder -- while tamga-swift and
 * tamga-java strip embedded whitespace and accept it. This SDK follows the
 * lenient majority, so a wrapped file from any tool still verifies.
 */
TT_TEST(accepts_a_line_wrapped_body) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    TT_ASSERT(load_pubkey(pubkey));
    pem_len = load_text("offline/license_plain_wrapped.lic", pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);

    TT_ASSERT_EQ_INT(tamga_license_file_verify_at(pem, pem_len, pubkey, NULL, NOW, &resource, NULL),
                     TAMGA_OK);
    tamga_json_free(resource);
}

int main(void) {
    TT_RUN(verifies_a_plain_licence_file);
    TT_RUN(verifies_an_encrypted_licence_file);
    TT_RUN(an_encrypted_file_needs_the_licence_key);
    TT_RUN(rejects_an_expired_file_distinguishably);
    TT_RUN(the_expiry_check_allows_exactly_sixty_seconds_of_skew);
    TT_RUN(rejects_format_v1);
    TT_RUN(rejects_an_algorithm_with_an_interior_nul);
    TT_RUN(rejects_a_signature_over_the_decoded_bytes);
    TT_RUN(rejects_a_wrong_public_key);
    TT_RUN(rejects_a_tampered_body);
    TT_RUN(rejects_malformed_envelopes);
    TT_RUN(accepts_a_line_wrapped_body);
    return TT_SUMMARY();
}
