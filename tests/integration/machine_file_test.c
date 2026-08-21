/*
 * The machine-file checks that do not need a well-formed v2 file.
 *
 * ⚠️ Every `.mach` in tests/fixtures/offline/ is offline format **v1** --
 * `alg` of `base64+ed25519` with no `+v2` -- because tools/fixture-generator/
 * built them to match what this SDK believed the format was. They are kept,
 * and this file now asserts that each one is REFUSED, which is the only thing
 * they are still evidence of.
 *
 * The positive coverage moved to server_machine_files_test.c, which runs
 * against files the server itself produced. A fixture generated and verified
 * by the same implementation proves only self-consistency, and here it proved
 * exactly that for two years while no real file would open.
 */
#include "tamga_test.h"

#include "checkout/machine_file.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"
#include "util/json.h"

#define FILE_CAP 8192
#define KEY_CAP 512

/* Any time at all: none of these files gets far enough for the clock to
 * matter. */
#define ANY_TIME 1750000000

static const char LICENCE_KEY[] = "MUP7-2TQK-7FBF-4Q6H-Y7ZR-9C3V";
static const char FINGERPRINT[] = "9f8e7d6c5b4a39281706";

static void refuses_as_v1(const char *file, uint32_t scheme, const char *key_file,
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

    status = tamga_machine_file_verify_at(pem, pem_len, scheme, pubkey, pubkey_len, license_key,
                                          fingerprint, ANY_TIME, &resource, NULL);
    if (status != TAMGA_ERR_UNSUPPORTED_SCHEME) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: %s should be refused as format v1, got %s\n", tt_current_,
                      file, tamga_error_name(status));
    }
    if (resource != NULL) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: %s left a resource behind\n", tt_current_, file);
        tamga_json_free(resource);
    }
}

/*
 * A v1 file is refused with no fallback, exactly as a v1 licence file is. Its
 * payload carried no signed `exp`, so a file with a ttl was cryptographically
 * valid forever, and it derived its AES key by zero-padding the licence key
 * instead of running HKDF. Accepting one silently reinstates both.
 *
 * The signature on each of these is genuine and the key is the right one --
 * the rejection can only be the missing version marker.
 */
TT_TEST(every_v1_fixture_is_refused_whatever_its_scheme) {
    refuses_as_v1("offline/machine_ed25519.mach", (uint32_t)TAMGA_SCHEME_ED25519_SIGN,
                  "offline/ed25519_pubkey.bin", NULL, NULL);
    refuses_as_v1("offline/machine_rsa_pkcs1.mach", (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_SIGN,
                  "offline/rsa_spki.der", NULL, NULL);
    refuses_as_v1("offline/machine_rsa_pss.mach", (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN,
                  "offline/rsa_spki.der", NULL, NULL);
    refuses_as_v1("offline/machine_ecdsa.mach", (uint32_t)TAMGA_SCHEME_ECDSA_P256_SIGN,
                  "offline/ecdsa_point.bin", NULL, NULL);
    refuses_as_v1("offline/machine_ed25519_encrypted.mach", (uint32_t)TAMGA_SCHEME_ED25519_SIGN,
                  "offline/ed25519_pubkey.bin", LICENCE_KEY, FINGERPRINT);
}

/*
 * RSA_2048_JWT_RS256 is a real LicenseScheme value but never a legal
 * machine-file input -- the server itself returns 422 SCHEME_NOT_SUPPORTED
 * for it. It shares the "rsa-sha256" alg suffix with RSA_2048_PKCS1_SIGN,
 * which is precisely why the file cannot be trusted to declare the scheme.
 *
 * All three rejections happen before a single byte of the file is parsed,
 * which is why a v1 fixture is a perfectly good input here.
 */
TT_TEST(rejects_the_jwt_scheme_and_the_none_scheme) {
    char pem[FILE_CAP];
    unsigned char pubkey[KEY_CAP];
    size_t pem_len;
    size_t pubkey_len;
    TamgaJson *resource = NULL;

    pem_len = tt_read_fixture("offline/machine_rsa_pkcs1.mach", (unsigned char *)pem, sizeof(pem));
    pubkey_len = tt_read_fixture("offline/rsa_spki.der", pubkey, sizeof(pubkey));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT(pubkey_len != (size_t)-1);

    TT_ASSERT_EQ_INT(
        tamga_machine_file_verify_at(pem, pem_len, (uint32_t)TAMGA_SCHEME_RSA_2048_JWT_RS256,
                                     pubkey, pubkey_len, NULL, NULL, ANY_TIME, &resource, NULL),
        TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at(pem, pem_len, (uint32_t)TAMGA_SCHEME_NONE, pubkey,
                                                  pubkey_len, NULL, NULL, ANY_TIME, &resource,
                                                  NULL),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    /* A value outside the enum entirely. A C enum has no validity range at
     * the ABI level, so this is a reachable input, not a hypothetical. */
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at(pem, pem_len, 9999u, pubkey, pubkey_len, NULL,
                                                  NULL, ANY_TIME, &resource, NULL),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    TT_ASSERT_NULL(resource);
}

/* The wrong marker text must be rejected, so a licence file cannot be
 * verified as a machine file or vice versa -- and that check runs before the
 * algorithm is looked at. */
TT_TEST(rejects_a_licence_file_presented_as_a_machine_file) {
    char pem[FILE_CAP];
    unsigned char pubkey[32];
    size_t pem_len;
    TamgaJson *resource = NULL;

    pem_len = tt_read_fixture("offline/license_plain.lic", (unsigned char *)pem, sizeof(pem));
    TT_ASSERT(pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", pubkey, sizeof(pubkey)), 32u);

    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at(pem, pem_len, (uint32_t)TAMGA_SCHEME_ED25519_SIGN,
                                                  pubkey, sizeof(pubkey), NULL, NULL, ANY_TIME,
                                                  &resource, NULL),
                     TAMGA_ERR_INVALID_PEM);
    TT_ASSERT_NULL(resource);
}

/* The argument guards, which run before anything is read. */
TT_TEST(rejects_missing_and_oversized_arguments) {
    unsigned char pubkey[32];
    TamgaJson *resource = NULL;
    static const char PEM[] = "-----BEGIN MACHINE FILE-----\ne30=\n-----END MACHINE FILE-----";

    memset(pubkey, 0, sizeof(pubkey));

    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at(NULL, 10u, (uint32_t)TAMGA_SCHEME_ED25519_SIGN,
                                                  pubkey, sizeof(pubkey), NULL, NULL, ANY_TIME,
                                                  &resource, NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at(PEM, sizeof(PEM) - 1u,
                                                  (uint32_t)TAMGA_SCHEME_ED25519_SIGN, NULL, 32u,
                                                  NULL, NULL, ANY_TIME, &resource, NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_machine_file_verify_at(PEM, sizeof(PEM) - 1u,
                                                  (uint32_t)TAMGA_SCHEME_ED25519_SIGN, pubkey, 0u,
                                                  NULL, NULL, ANY_TIME, &resource, NULL),
                     TAMGA_ERR_LENGTH_INVALID);
    TT_ASSERT_NULL(resource);
}

/*
 * The alg parser itself, over synthetic certificates.
 *
 * The fixture-driven suite in server_machine_files_test.c rewrites each real
 * file's version marker, but every alg it starts from is well formed. These
 * are the shapes a real file never has and an attacker can still present:
 * empty segments, a doubled marker, and -- the one a length-unaware parser
 * gets wrong -- an interior NUL. A JSON string may contain one, so
 * `strlen(alg)` would make "base64+ed25519+v2\u0000junk" compare equal to the
 * algorithm it merely prefixes. TamgaCert carries alg_len for this reason and
 * every comparison in tamga_machine_alg_split() honours it.
 *
 * enc and sig are empty, so anything that gets PAST the alg check fails later
 * with a different code -- which is what distinguishes "refused here" from
 * "refused eventually".
 */
static TamgaErrorCode status_for_alg(const char *alg_json_literal) {
    char json[512];
    char pem[1024];
    char *body;
    int written;
    TamgaJson *resource = NULL;
    unsigned char pubkey[32];
    TamgaErrorCode status;

    memset(pubkey, 0, sizeof(pubkey));
    written = snprintf(json, sizeof(json), "{\"enc\":\"\",\"sig\":\"\",\"alg\":\"%s\"}",
                       alg_json_literal);
    if (written <= 0 || (size_t)written >= sizeof(json)) {
        return TAMGA_ERR_UNKNOWN;
    }

    body = tamga_base64_encode_alloc((const unsigned char *)json, (size_t)written);
    if (body == NULL) {
        return TAMGA_ERR_OUT_OF_MEMORY;
    }
    written = snprintf(pem, sizeof(pem),
                       "-----BEGIN MACHINE FILE-----\n%s\n-----END MACHINE FILE-----", body);
    tamga_free(body);
    if (written <= 0 || (size_t)written >= sizeof(pem)) {
        return TAMGA_ERR_UNKNOWN;
    }

    status =
        tamga_machine_file_verify_at(pem, (size_t)written, (uint32_t)TAMGA_SCHEME_ED25519_SIGN,
                                     pubkey, sizeof(pubkey), NULL, NULL, ANY_TIME, &resource, NULL);
    if (resource != NULL) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: a failing verify still wrote a resource\n", tt_current_);
        tamga_json_free(resource);
    }
    return status;
}

static void alg_is_refused(const char *alg_json_literal) {
    TamgaErrorCode status = status_for_alg(alg_json_literal);
    if (status != TAMGA_ERR_UNSUPPORTED_SCHEME) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: alg \"%s\" was not refused, got %s\n", tt_current_,
                      alg_json_literal, tamga_error_name(status));
    }
}

TT_TEST(the_alg_parser_is_length_aware_and_rejects_every_malformed_shape) {
    /*
     * The control, and it is not optional. Every case below is asserted to be
     * refused AT THE ALG CHECK -- but if this harness never reached that check
     * (a typo in the JSON, a PEM that does not parse) they would all be
     * refused for some other reason and the test would pass while proving
     * nothing. A well-formed alg must get PAST it and die later, on the
     * signature, against this all-zero key. Both encoding prefixes, because
     * they are checked separately.
     */
    static const char *const REFUSED[] = {
        /* no version segment at all */
        "base64+ed25519",
        "base64",
        "",
        /* a version segment that is not exactly v2 */
        "base64+ed25519+v1",
        "base64+ed25519+v3",
        "base64+ed25519+V2",
        "base64+ed25519+v2junk",
        "base64+ed25519+v2+v2",
        /* empty segments */
        "+v2",
        "++v2",
        "base64++v2",
        "+ed25519+v2",
        /* an encoding prefix that only looks right */
        "xbase64+ed25519+v2",
        "base6+ed25519+v2",
        "aes-256-gcm-x+ed25519+v2",
        /* a signing suffix belonging to another scheme */
        "base64+ecdsa-p256+v2",
        "base64+rsa-sha256+v2",
        /* an interior NUL: only alg_len can tell these from the real thing */
        "base64+ed25519+v2\\u0000junk",
        "base64+ed25519+v2\\u0000+v2",
        "base64+ed25519\\u0000+v2",
        "base64\\u0000+ed25519+v2",
    };
    size_t i;

    TT_ASSERT_EQ_INT(status_for_alg("base64+ed25519+v2"), TAMGA_ERR_SIGNATURE_INVALID);
    TT_ASSERT_EQ_INT(status_for_alg("aes-256-gcm+ed25519+v2"), TAMGA_ERR_SIGNATURE_INVALID);

    for (i = 0u; i < (sizeof(REFUSED) / sizeof(REFUSED[0])); i++) {
        alg_is_refused(REFUSED[i]);
    }
}

TT_TEST(the_ttl_range_matches_the_server) {
    TT_ASSERT_FALSE(tamga_machine_file_ttl_is_valid(0));
    TT_ASSERT_FALSE(tamga_machine_file_ttl_is_valid(-1));
    TT_ASSERT(tamga_machine_file_ttl_is_valid(1));
    TT_ASSERT(tamga_machine_file_ttl_is_valid(TAMGA_MACHINE_FILE_MAX_TTL_SECONDS));
    TT_ASSERT_FALSE(tamga_machine_file_ttl_is_valid(TAMGA_MACHINE_FILE_MAX_TTL_SECONDS + 1));
}

int main(void) {
    TT_RUN(every_v1_fixture_is_refused_whatever_its_scheme);
    TT_RUN(rejects_the_jwt_scheme_and_the_none_scheme);
    TT_RUN(rejects_a_licence_file_presented_as_a_machine_file);
    TT_RUN(rejects_missing_and_oversized_arguments);
    TT_RUN(the_alg_parser_is_length_aware_and_rejects_every_malformed_shape);
    TT_RUN(the_ttl_range_matches_the_server);
    return TT_SUMMARY();
}
