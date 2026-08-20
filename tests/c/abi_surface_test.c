/*
 * ABI surface assertions.
 *
 * Two things a compiler will not tell you on its own:
 *
 *   1. that an enum value still has the number it shipped with. Appending is
 *      safe; renumbering silently changes what a binary compiled against the
 *      old header means by TAMGA_ERR_EXPIRED. Every frozen value is pinned
 *      here as a compile-time assertion, so the check cannot be skipped by
 *      not running the test;
 *   2. that every exported entry point is still exported. Taking each
 *      function's address forces the link, so a symbol dropped from the
 *      library fails the build rather than surfacing as a runtime error in
 *      somebody's application.
 *
 * This file uses ONLY tamga.h -- no internal headers -- because that is the
 * whole surface a consumer has.
 */
#include <stddef.h>
#include <stdio.h>

#include "tamga.h"

/* --- frozen error codes (v1.0 through v1.2) ---------------------------- */
_Static_assert(TAMGA_OK == 0, "TAMGA_OK must stay 0");
_Static_assert(TAMGA_ERR_INVALID_PEM == 1, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_INVALID_BASE64 == 2, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_INVALID_JSON == 3, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_SIGNATURE_INVALID == 4, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_DECRYPTION_FAILED == 5, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_UNSUPPORTED_SCHEME == 6, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_NULL_ARGUMENT == 7, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_PANIC == 8, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_UNKNOWN == 9, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_LENGTH_INVALID == 10, "frozen ABI value changed");
_Static_assert(TAMGA_ERR_EXPIRED == 11, "frozen ABI value changed");
/* Appended in 1.3. New codes go after this one, never in front of it. */
_Static_assert(TAMGA_ERR_OUT_OF_MEMORY == 12, "appended ABI value changed");

/* --- frozen scheme values ---------------------------------------------- */
_Static_assert(TAMGA_SCHEME_NONE == 0, "frozen ABI value changed");
_Static_assert(TAMGA_SCHEME_ED25519_SIGN == 1, "frozen ABI value changed");
_Static_assert(TAMGA_SCHEME_RSA_2048_PKCS1_SIGN == 2, "frozen ABI value changed");
_Static_assert(TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN == 3, "frozen ABI value changed");
_Static_assert(TAMGA_SCHEME_ECDSA_P256_SIGN == 4, "frozen ABI value changed");
_Static_assert(TAMGA_SCHEME_RSA_2048_JWT_RS256 == 5, "frozen ABI value changed");

int main(void) {
    /*
     * Taking each address forces the linker to resolve it. A dropped export
     * becomes a link failure here instead of a consumer's runtime crash.
     *
     * They are held as a generic FUNCTION pointer, not as void *. Converting
     * a function pointer to an object pointer is a GNU extension that ISO C
     * forbids outright, so the void * array this used to be compiled on Apple
     * clang and was rejected by GCC under -Wpedantic -- which is how this
     * file, whose whole job is to be the portable ABI gate, failed to build
     * on the platform it most needed to guard.
     */
    typedef void (*AnyFn)(void);
    AnyFn exports[] = {
        (AnyFn)tamga_last_error_message,
        (AnyFn)tamga_error_name,
        (AnyFn)tamga_string_free,
        (AnyFn)tamga_hkdf_derive_machine_file_key,
        (AnyFn)tamga_hkdf_derive_license_file_key,
        (AnyFn)tamga_license_file_verify,
        (AnyFn)tamga_license_file_get_json,
        (AnyFn)tamga_license_file_free,
        (AnyFn)tamga_machine_file_verify,
        (AnyFn)tamga_machine_file_get_json,
        (AnyFn)tamga_machine_file_free,
        (AnyFn)tamga_offline_proof_verify,
        (AnyFn)tamga_offline_proof_generate,
    };
    size_t i;
    int failures = 0;

    for (i = 0u; i < (sizeof(exports) / sizeof(exports[0])); i++) {
        if (exports[i] == NULL) {
            (void)fprintf(stderr, "export %zu is null\n", i);
            failures++;
        }
    }

    /* The free functions accept null as a documented no-op. */
    tamga_string_free(NULL);
    tamga_license_file_free(NULL);
    tamga_machine_file_free(NULL);

    /* Nothing has failed yet on this thread, so there must be no message. */
    if (tamga_last_error_message() != NULL) {
        (void)fprintf(stderr, "a fresh thread reported an error message\n");
        failures++;
    }

    /* A failing call must set one, and a subsequent successful call must
     * clear it -- the contract every consumer's error handling is built on. */
    {
        TamgaErrorCode code = tamga_hkdf_derive_license_file_key(NULL, NULL);
        if (code == TAMGA_OK || tamga_last_error_message() == NULL) {
            (void)fprintf(stderr, "a failing call did not record an error\n");
            failures++;
        }
    }
    {
        uint8_t key[32];
        TamgaErrorCode code = tamga_hkdf_derive_license_file_key("k", key);
        if (code != TAMGA_OK || tamga_last_error_message() != NULL) {
            (void)fprintf(stderr, "a successful call did not clear the error\n");
            failures++;
        }
    }

    /* Local proof generation is a documented non-implementation. It must
     * report that rather than crash or pretend to succeed. */
    {
        char *proof = (char *)0x1;
        TamgaErrorCode code =
            tamga_offline_proof_generate("key", "account", "machine", "fp", "{}", &proof);
        if (code != TAMGA_ERR_UNKNOWN || proof != NULL) {
            (void)fprintf(stderr, "offline_proof_generate did not report its own absence\n");
            failures++;
        }
    }

    if (failures != 0) {
        (void)fprintf(stderr, "FAILED: %d ABI surface problem(s)\n", failures);
        return 1;
    }
    (void)fprintf(stderr, "ok: ABI surface intact\n");
    return 0;
}
