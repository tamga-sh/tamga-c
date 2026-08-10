/**
 * test_machine_file.c
 *
 * CTest harness for Section D of docs/plans/tamga-c.plan.md ("Machine
 * Checkout FFI"). Drives tamga_machine_file_verify/_get_json/_free purely
 * through the public C ABI in tamga.h. Only the Ed25519 scheme is fixtured
 * here (the Rust-side tests/machine_file_verify.rs already exercises all 4
 * schemes plus encrypted round-trips exhaustively — this C harness exists
 * to prove the ABI itself links and behaves correctly from a real C
 * translation unit, not to duplicate that coverage).
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "tamga.h"

static const uint8_t MACHINE_PUBKEY[32] = {
    0x8a, 0x11, 0x7c, 0x0a, 0xfc, 0x90, 0x0c, 0xaf, 0xb0, 0xd8, 0xbf, 0x65, 0x8f, 0x14, 0x7d, 0xbe,
    0xfc, 0x81, 0xcf, 0x6e, 0x17, 0x5d, 0xc7, 0xd3, 0xd2, 0xbc, 0xae, 0x7b, 0xb2, 0x67, 0x21, 0xc8,
};

static const char *MACHINE_PEM =
    "-----BEGIN MACHINE FILE-----\n"
    "eyJhbGciOiJiYXNlNjQrZWQyNTUxOSIsImVuYyI6ImV5SmtZWFJoSWpwN0ltRjBkSEpwWW5W"
    "MFpYTWlPbnNpWTI5eVpYTWlPalFzSW1OeVpXRjBaV1FpT2lJeU1ESTJMVEF4TFRBeFZEQXdP"
    "akF3T2pBd1dpSXNJbVJwYzJzaU9tNTFiR3dzSW1acGJtZGxjbkJ5YVc1MElqb2labkF0WVdK"
    "ak1USXpJaXdpYUdWaGNuUmlaV0YwWDNOMFlYUjFjeUk2SWs1UFZGOVRWRUZTVkVWRUlpd2lh"
    "Rzl6ZEc1aGJXVWlPaUpvYjNOME1TSXNJbWx3SWpwdWRXeHNMQ0pzWVhOMFgyTm9aV05yWDI5"
    "MWRGOWhkQ0k2Ym5Wc2JDd2liR0Z6ZEY5b1pXRnlkR0psWVhSZllYUWlPbTUxYkd3c0ltMWxi"
    "Vzl5ZVNJNmJuVnNiQ3dpYldWMFlXUmhkR0VpT250OUxDSnVZVzFsSWpwdWRXeHNMQ0p1Wlho"
    "MFgyaGxZWEowWW1WaGRGOWhkQ0k2Ym5Wc2JDd2ljR3hoZEdadmNtMGlPaUpzYVc1MWVDSXNJ"
    "blZ3WkdGMFpXUWlPaUl5TURJMkxUQXhMVEF4VkRBd09qQXdPakF3V2lKOUxDSnBaQ0k2SWpB"
    "eE9USTJZak5sTFRJeU1qSXROekF3TUMwNE1EQXdMVEF3TURBd01EQXdNREF3TUNJc0luUjVj"
    "R1VpT2lKdFlXTm9hVzVsY3lKOWZRPT0iLCJzaWciOiJ6eXFmNlNiQjJ6V2thU1B2QmhJc0VX"
    "NGNjTU1aaUhpM2k4VDNzdnFiejdwOFROa2EzeFVQelFQSmtGVDdoSEcvTDBmVEZscTgzenR1"
    "VTNVdmZyUlpEQT09In0=\n"
    "-----END MACHINE FILE-----";

int main(void) {
    TamgaMachineFile *handle = NULL;
    TamgaErrorCode code =
        tamga_machine_file_verify(MACHINE_PEM, strlen(MACHINE_PEM), TAMGA_SCHEME_ED25519_SIGN,
                                  MACHINE_PUBKEY, sizeof(MACHINE_PUBKEY), NULL, NULL, &handle);
    if (code != TAMGA_OK) {
        const char *err = tamga_last_error_message();
        fprintf(stderr, "test_machine_file: verify failed, code=%d, err=%s\n", (int)code,
                err ? err : "(none)");
        return 1;
    }
    assert(handle != NULL);

    char *json = NULL;
    uintptr_t json_len = 0;
    code = tamga_machine_file_get_json(handle, &json, &json_len);
    if (code != TAMGA_OK) {
        fprintf(stderr, "test_machine_file: get_json failed, code=%d\n", (int)code);
        return 1;
    }
    assert(json != NULL);
    assert(json_len == strlen(json));
    if (strstr(json, "fp-abc123") == NULL) {
        fprintf(stderr, "test_machine_file: decoded JSON missing expected key: %s\n", json);
        return 1;
    }
    tamga_string_free(json);
    tamga_machine_file_free(handle);

    /* RSA_2048_JWT_RS256 must be rejected outright, never attempted. */
    TamgaMachineFile *jwt_handle = NULL;
    code =
        tamga_machine_file_verify(MACHINE_PEM, strlen(MACHINE_PEM), TAMGA_SCHEME_RSA_2048_JWT_RS256,
                                  MACHINE_PUBKEY, sizeof(MACHINE_PUBKEY), NULL, NULL, &jwt_handle);
    if (code != TAMGA_ERR_UNSUPPORTED_SCHEME || jwt_handle != NULL) {
        fprintf(stderr, "test_machine_file: RSA_2048_JWT_RS256 not rejected as expected\n");
        return 1;
    }

    /* An out-of-range raw scheme value must also be rejected, not treated
     * as undefined behavior -- see TamgaScheme::from_raw in src/lib.rs. */
    TamgaMachineFile *bad_scheme_handle = NULL;
    code = tamga_machine_file_verify(MACHINE_PEM, strlen(MACHINE_PEM), 999, MACHINE_PUBKEY,
                                     sizeof(MACHINE_PUBKEY), NULL, NULL, &bad_scheme_handle);
    if (code != TAMGA_ERR_UNSUPPORTED_SCHEME || bad_scheme_handle != NULL) {
        fprintf(stderr, "test_machine_file: out-of-range scheme not rejected as expected\n");
        return 1;
    }

    printf("test_machine_file: OK\n");
    return 0;
}
