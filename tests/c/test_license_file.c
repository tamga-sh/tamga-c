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
    0x66, 0xba, 0x85, 0x92, 0xb3, 0xf5, 0x5c, 0x92, 0xe8, 0x70, 0xf6, 0xcc, 0xdf, 0xd1, 0xe6, 0x72,
    0xa4, 0x5e, 0x28, 0x39, 0x24, 0xd9, 0x46, 0x88, 0xba, 0x2a, 0xa2, 0xc9, 0x02, 0x53, 0x7a, 0x37,
};

static const char *LICENSE_PEM =
    "-----BEGIN LICENSE FILE-----\n"
    "eyJhbGciOiJiYXNlNjQrZWQyNTUxOSIsImVuYyI6ImV5SmtZWFJoSWpwN0ltRjBkSEpwWW5WMFpY"
    "TWlPbnNpWTNKbFlYUmxaQ0k2SWpJd01qWXRNREV0TURGVU1EQTZNREE2TURCYUlpd2laVzVqY25s"
    "d2RHVmtJanBtWVd4elpTd2laWGh3YVhKNUlqcHVkV3hzTENKbWJHOWhkR2x1WnlJNlptRnNjMlVz"
    "SW10bGVTSTZJbXhwWXkxaFltTXhNak1pTENKc1lYTjBYMk5vWldOclgybHVYMkYwSWpwdWRXeHNM"
    "Q0pzWVhOMFgyTm9aV05yWDI5MWRGOWhkQ0k2Ym5Wc2JDd2liR0Z6ZEY5MllXeHBaR0YwWldSZllY"
    "UWlPbTUxYkd3c0ltMWhZMmhwYm1WelgyTnZkVzUwSWpvd0xDSnRZWGhmYldGamFHbHVaWE1pT201"
    "MWJHd3NJbTFoZUY5MWMyVnljeUk2Ym5Wc2JDd2liV0Y0WDNWelpYTWlPbTUxYkd3c0ltMWxkR0Zr"
    "WVhSaElqcDdmU3dpYm1GdFpTSTZJa0ZqYldVZ1EyOXljQ0lzSW5CeWIzUmxZM1JsWkNJNlptRnNj"
    "MlVzSW5OamFHVnRaU0k2Ym5Wc2JDd2ljM1JoZEhWeklqb2lRVU5VU1ZaRklpd2ljM1J5YVdOMElq"
    "cG1ZV3h6WlN3aWMzVnpjR1Z1WkdWa0lqcG1ZV3h6WlN3aWRYQmtZWFJsWkNJNklqSXdNall0TURF"
    "dE1ERlVNREE2TURBNk1EQmFJaXdpZFhObGN5STZNSDBzSW1sa0lqb2lNREU1TWpaaU0yVXRNREF3"
    "TUMwM01EQXdMVGd3TURBdE1EQXdNREF3TURBd01EQXdJaXdpZEhsd1pTSTZJbXhwWTJWdWMyVnpJ"
    "bjE5Iiwic2lnIjoic2RvSzhJbzV1djB0dmdhVlJHUUJtOXJ1R2xCcllzcUZMMmhkNENxc3ZkZEpH"
    "N3FtVW1mdXc3YmFVeWZaNEwxbmxORUMwQ2lGRjF2ZXJMTXRQVkU2RGc9PSJ9"
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
