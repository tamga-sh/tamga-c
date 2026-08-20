/*
 * The public entry points' own contracts, exercised through tamga.h only.
 *
 * The layer under test here is not licensing logic -- that is covered by the
 * integration suites -- but the part specific to being a C library: rejecting
 * bad pointers and lengths before anything dereferences them, keeping the
 * per-thread error contract, and owning handles correctly.
 */
#include "tamga_test.h"

#include "tamga.h"

TT_TEST(every_error_code_has_a_distinct_name) {
    /* The names are part of the diagnostic contract: they appear in logs and
     * in the fallback message when a caller passes no format. Two codes
     * sharing a name, or a code falling through to UNKNOWN, makes a log
     * entry point at the wrong failure. */
    static const TamgaErrorCode codes[] = {
        TAMGA_OK,
        TAMGA_ERR_INVALID_PEM,
        TAMGA_ERR_INVALID_BASE64,
        TAMGA_ERR_INVALID_JSON,
        TAMGA_ERR_SIGNATURE_INVALID,
        TAMGA_ERR_DECRYPTION_FAILED,
        TAMGA_ERR_UNSUPPORTED_SCHEME,
        TAMGA_ERR_NULL_ARGUMENT,
        TAMGA_ERR_PANIC,
        TAMGA_ERR_UNKNOWN,
        TAMGA_ERR_LENGTH_INVALID,
        TAMGA_ERR_EXPIRED,
        TAMGA_ERR_OUT_OF_MEMORY,
        TAMGA_ERR_TRANSPORT,
        TAMGA_ERR_NO_TRANSPORT,
        TAMGA_ERR_API,
        TAMGA_ERR_RATE_LIMITED,
        TAMGA_ERR_UNAUTHORIZED,
        TAMGA_ERR_FORBIDDEN,
        TAMGA_ERR_NOT_FOUND,
        TAMGA_ERR_SERVER,
        TAMGA_ERR_CHECK_IN_NOT_REQUIRED,
        TAMGA_ERR_LICENSE_NOT_ENCRYPTED,
        TAMGA_ERR_LICENSE_KEY_MISSING,
        TAMGA_ERR_TTL_INVALID,
        TAMGA_ERR_SCHEME_NOT_SUPPORTED,
        TAMGA_ERR_FINGERPRINT_TAKEN,
        TAMGA_ERR_DATASET_INVALID,
        TAMGA_ERR_PID_TAKEN,
    };
    size_t i;
    size_t j;

    for (i = 0u; i < (sizeof(codes) / sizeof(codes[0])); i++) {
        const char *name = tamga_error_name(codes[i]);
        TT_ASSERT_NOT_NULL(name);
        /* Only TAMGA_ERR_UNKNOWN itself may carry that name. */
        if (codes[i] != TAMGA_ERR_UNKNOWN) {
            TT_ASSERT_FALSE(strcmp(name, "TAMGA_ERR_UNKNOWN") == 0);
        }
        for (j = 0u; j < i; j++) {
            TT_ASSERT_FALSE(strcmp(name, tamga_error_name(codes[j])) == 0);
        }
    }
    /* An out-of-range value still produces something printable. */
    TT_ASSERT_EQ_STR(tamga_error_name((TamgaErrorCode)12345), "TAMGA_ERR_UNKNOWN");
}

TT_TEST(key_derivation_rejects_bad_arguments) {
    uint8_t key[32];

    TT_ASSERT_EQ_INT(tamga_hkdf_derive_license_file_key(NULL, key), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_hkdf_derive_license_file_key("k", NULL), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_hkdf_derive_machine_file_key(NULL, "f", key), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_hkdf_derive_machine_file_key("k", NULL, key), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_hkdf_derive_machine_file_key("k", "f", NULL), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_NOT_NULL(tamga_last_error_message());
}

/* A zero or absurd length gets its own code, separate from a null pointer:
 * they are different caller bugs and a shared code sends the caller looking
 * in the wrong place. */
TT_TEST(lengths_and_pointers_have_distinct_error_codes) {
    TamgaLicenseFile *handle = (TamgaLicenseFile *)0x1;
    TamgaMachineFile *machine = (TamgaMachineFile *)0x1;
    const uint8_t pubkey[32] = {0};

    TT_ASSERT_EQ_INT(tamga_license_file_verify(NULL, 10u, pubkey, NULL, &handle),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_license_file_verify("x", 0u, pubkey, NULL, &handle),
                     TAMGA_ERR_LENGTH_INVALID);
    TT_ASSERT_EQ_INT(tamga_license_file_verify("x", (uintptr_t)1u << 40, pubkey, NULL, &handle),
                     TAMGA_ERR_LENGTH_INVALID);
    TT_ASSERT_EQ_INT(tamga_license_file_verify("x", 1u, NULL, NULL, &handle),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_license_file_verify("x", 1u, pubkey, NULL, NULL),
                     TAMGA_ERR_NULL_ARGUMENT);

    TT_ASSERT_EQ_INT(tamga_machine_file_verify("x", 1u, 1u, NULL, 1u, NULL, NULL, &machine),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_machine_file_verify("x", 1u, 1u, pubkey, 0u, NULL, NULL, &machine),
                     TAMGA_ERR_LENGTH_INVALID);
}

TT_TEST(get_json_and_free_reject_a_null_handle) {
    char *json = (char *)0x1;
    uintptr_t len = 99u;

    TT_ASSERT_EQ_INT(tamga_license_file_get_json(NULL, &json, &len), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_machine_file_get_json(NULL, &json, &len), TAMGA_ERR_NULL_ARGUMENT);
    /* Null is a documented no-op for every free. */
    tamga_license_file_free(NULL);
    tamga_machine_file_free(NULL);
    tamga_string_free(NULL);
}

TT_TEST(offline_proof_verify_validates_its_arguments) {
    const uint8_t key[32] = {0};
    bool valid = true;

    TT_ASSERT_EQ_INT(
        tamga_offline_proof_verify("v1x0.AAAA", NULL, 10u, "a", "b", "c", "{}", &valid),
        TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_offline_proof_verify("v1x0.AAAA", key, 0u, "a", "b", "c", "{}", &valid),
                     TAMGA_ERR_LENGTH_INVALID);
    TT_ASSERT_EQ_INT(
        tamga_offline_proof_verify("v1x0.AAAA", key, sizeof(key), "a", "b", "c", "{}", NULL),
        TAMGA_ERR_NULL_ARGUMENT);
}

/* Local proof generation is a deliberate non-implementation: proofs are
 * issued by the server, and this SDK holds no signing keys. It must say so
 * rather than crash or appear to succeed. */
TT_TEST(local_proof_generation_reports_its_own_absence) {
    char *proof = (char *)0x1;

    TT_ASSERT_EQ_INT(tamga_offline_proof_generate("key", "account", "machine", "fp", "{}", &proof),
                     TAMGA_ERR_UNKNOWN);
    TT_ASSERT_NULL(proof);
    TT_ASSERT_NOT_NULL(tamga_last_error_message());
    /* The message has to point at the alternative, or the caller is stuck. */
    TT_ASSERT_NOT_NULL(strstr(tamga_last_error_message(), "tamga_client_generate_offline_proof"));
}

/* No secret is ever formatted into a diagnostic: callers log these. */
TT_TEST(error_messages_never_quote_the_licence_key) {
    uint8_t key[32];
    static const char secret[] = "SUPER-SECRET-LICENCE-KEY";
    const char *message;

    /* Force a failure on a path that has the key in hand. */
    TT_ASSERT_EQ_INT(tamga_hkdf_derive_machine_file_key(secret, NULL, key),
                     TAMGA_ERR_NULL_ARGUMENT);
    message = tamga_last_error_message();
    TT_ASSERT_NOT_NULL(message);
    TT_ASSERT_NULL(strstr(message, secret));
}

TT_TEST(the_builtin_transport_query_answers_for_this_build) {
    /* Whatever it reports, it must not crash and must be callable before any
     * client exists -- integrators use it to decide whether to register one. */
    bool has = tamga_has_builtin_transport();
    TT_ASSERT(has == true || has == false);
}

int main(void) {
    TT_RUN(every_error_code_has_a_distinct_name);
    TT_RUN(key_derivation_rejects_bad_arguments);
    TT_RUN(lengths_and_pointers_have_distinct_error_codes);
    TT_RUN(get_json_and_free_reject_a_null_handle);
    TT_RUN(offline_proof_verify_validates_its_arguments);
    TT_RUN(local_proof_generation_reports_its_own_absence);
    TT_RUN(error_messages_never_quote_the_licence_key);
    TT_RUN(the_builtin_transport_query_answers_for_this_build);
    return TT_SUMMARY();
}
