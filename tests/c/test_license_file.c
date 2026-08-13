/**
 * test_license_file.c
 *
 * CTest harness for Section C of docs/plans/tamga-c.plan.md ("License
 * Checkout FFI"). Drives tamga_license_file_verify/_get_json/_free purely
 * through the public C ABI in tamga.h.
 *
 * The fixture PEM/pubkey below were generated with a real Ed25519 keypair
 * and signed the same way the real server signs a `.lic` file (see
 * tests/license_file_verify.rs::verifies_a_known_good_plain_fixture on the
 * Rust side for the equivalent, and this repo's CLAUDE.md for the
 * base64-string-not-decoded-bytes signing convention this fixture
 * exercises).
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "tamga.h"

static const uint8_t LICENSE_PUBKEY[32] = {
    0xc3, 0xa6, 0x1e, 0xe4, 0xad, 0xb2, 0x22, 0x39, 0x42, 0x75, 0x05, 0xd6, 0xd8, 0xb8, 0xcd, 0xd0,
    0x6c, 0xcc, 0xdb, 0xa4, 0xee, 0x27, 0x8a, 0x7e, 0x28, 0x16, 0x02, 0x9f, 0xde, 0xb3, 0x6c, 0xcf,
};

/* Format v2 (alg ends "+v2", signed meta.{iat,jti,kid} inside the payload) --
 * regenerated when the license-file key derivation moved off naive_key onto
 * HKDF and the verifier started requiring the v2 alg suffix. The old v1
 * fixture here (no +v2, no meta) started failing with "unsupported
 * algorithm: base64+ed25519" once that landed -- the verifier correctly
 * doing its job, not a regression. Fresh Ed25519 keypair signing a v2
 * payload built the same way tamga-rust's own build_pem test helper does
 * (src/checkout/license_file.rs). */
static const char *LICENSE_PEM =
    "-----BEGIN LICENSE FILE-----\n"
    "eyJhbGciOiJiYXNlNjQrZWQyNTUxOSt2MiIsImVuYyI6ImV5SmtZWFJoSWpwN0ltRjBkSEpwWW5W"
    "MFpYTWlPbnNpWTNKbFlYUmxaQ0k2SWpJd01qWXRNREV0TURGVU1EQTZNREE2TURCYUlpd2laVzVq"
    "Y25sd2RHVmtJanBtWVd4elpTd2laWGh3YVhKNUlqcHVkV3hzTENKbWJHOWhkR2x1WnlJNlptRnNj"
    "MlVzSW10bGVTSTZJbXhwWXkxaFltTXhNak1pTENKc1lYTjBYMk5vWldOclgybHVYMkYwSWpwdWRX"
    "eHNMQ0pzWVhOMFgyTm9aV05yWDI5MWRGOWhkQ0k2Ym5Wc2JDd2liR0Z6ZEY5MllXeHBaR0YwWldS"
    "ZllYUWlPbTUxYkd3c0ltMWhZMmhwYm1WelgyTnZkVzUwSWpvd0xDSnRZWGhmYldGamFHbHVaWE1p"
    "T201MWJHd3NJbTFoZUY5MWMyVnljeUk2Ym5Wc2JDd2liV0Y0WDNWelpYTWlPbTUxYkd3c0ltMWxk"
    "R0ZrWVhSaElqcDdmU3dpYm1GdFpTSTZJa0ZqYldVZ1EyOXljQ0lzSW5CeWIzUmxZM1JsWkNJNlpt"
    "RnNjMlVzSW5OamFHVnRaU0k2Ym5Wc2JDd2ljM1JoZEhWeklqb2lRVU5VU1ZaRklpd2ljM1J5YVdO"
    "MElqcG1ZV3h6WlN3aWMzVnpjR1Z1WkdWa0lqcG1ZV3h6WlN3aWRYQmtZWFJsWkNJNklqSXdNall0"
    "TURFdE1ERlVNREE2TURBNk1EQmFJaXdpZFhObGN5STZNSDBzSW1sa0lqb2lNREU1TWpaaU0yVXRN"
    "REF3TUMwM01EQXdMVGd3TURBdE1EQXdNREF3TURBd01EQXdJaXdpZEhsd1pTSTZJbXhwWTJWdWMy"
    "VnpJbjBzSW0xbGRHRWlPbnNpYVdGMElqb3hOelkzTWpJMU5qQXdMQ0pxZEdraU9pSjBaWE4wTFdw"
    "MGFTSXNJbXRwWkNJNkluUmxjM1F0YTJsa0luMTkiLCJzaWciOiJRbEpZbS8rTUJLZloySnlVcmdn"
    "V1ZhUnVJVG9oNHkwbW1hdGsxaDZvcy9VTy9LMkFHYjlRVDRodTJrWXBPRTh4d3h2SVRUREU3RndB"
    "aVd5NVNVRC9BQT09In0="
    "\n-----END LICENSE FILE-----";

int main(void) {
    TamgaLicenseFile *handle = NULL;
    TamgaErrorCode code =
        tamga_license_file_verify(LICENSE_PEM, strlen(LICENSE_PEM), LICENSE_PUBKEY, NULL, &handle);
    if (code != TAMGA_OK) {
        const char *err = tamga_last_error_message();
        fprintf(stderr, "test_license_file: verify failed, code=%d, err=%s\n", (int)code,
                err ? err : "(none)");
        return 1;
    }
    assert(handle != NULL);

    char *json = NULL;
    uintptr_t json_len = 0;
    code = tamga_license_file_get_json(handle, &json, &json_len);
    if (code != TAMGA_OK) {
        fprintf(stderr, "test_license_file: get_json failed, code=%d\n", (int)code);
        return 1;
    }
    assert(json != NULL);
    assert(json_len == strlen(json));
    if (strstr(json, "lic-abc123") == NULL) {
        fprintf(stderr, "test_license_file: decoded JSON missing expected key: %s\n", json);
        return 1;
    }
    tamga_string_free(json);
    tamga_license_file_free(handle);

    /* Negative cases: malformed PEM, wrong pubkey, tampered signature. */
    TamgaLicenseFile *bad_handle = NULL;
    code = tamga_license_file_verify("not a pem file", 14, LICENSE_PUBKEY, NULL, &bad_handle);
    if (code != TAMGA_ERR_INVALID_PEM || bad_handle != NULL) {
        fprintf(stderr, "test_license_file: malformed PEM not rejected as expected\n");
        return 1;
    }

    uint8_t wrong_pubkey[32] = {0};
    TamgaLicenseFile *wrong_key_handle = NULL;
    code = tamga_license_file_verify(LICENSE_PEM, strlen(LICENSE_PEM), wrong_pubkey, NULL,
                                     &wrong_key_handle);
    if (code != TAMGA_ERR_SIGNATURE_INVALID || wrong_key_handle != NULL) {
        fprintf(stderr, "test_license_file: wrong pubkey not rejected as expected\n");
        return 1;
    }

    printf("test_license_file: OK\n");
    return 0;
}
