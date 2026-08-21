/**
 * test_machine_file.c
 *
 * CTest harness for the machine-file FFI. Drives
 * tamga_machine_file_verify/_free purely through the public C ABI in tamga.h,
 * from a real C translation unit -- this is the ABI gate, not the place that
 * duplicates the format coverage in tests/integration/.
 *
 * ⚠️ One behavioural change, deliberately made and deliberately recorded
 * here: MACHINE_PEM_V1 below is the fixture this harness shipped with, and it
 * used to VERIFY. It is offline format v1 -- `alg` of "base64+ed25519", with
 * no "+v2" -- and a v1 machine file is now refused, exactly as a v1 licence
 * file already was. Its payload carried no signed `exp`, so a time-limited
 * file was cryptographically valid forever, and its AES key came from
 * zero-padding the licence key rather than from HKDF. The ABI did not change;
 * what a v1 file means did.
 */
#include <stdio.h>
#include <string.h>

#include "tamga.h"

static const uint8_t MACHINE_PUBKEY[32] = {
    0x8a, 0x11, 0x7c, 0x0a, 0xfc, 0x90, 0x0c, 0xaf, 0xb0, 0xd8, 0xbf, 0x65, 0x8f, 0x14, 0x7d, 0xbe,
    0xfc, 0x81, 0xcf, 0x6e, 0x17, 0x5d, 0xc7, 0xd3, 0xd2, 0xbc, 0xae, 0x7b, 0xb2, 0x67, 0x21, 0xc8,
};

static const char *MACHINE_PEM_V1 =
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

/*
 * A file the SERVER produced: alg "base64+ed25519+v2", Ed25519, and issued
 * already expired. Copied byte-for-byte out of
 * tests/fixtures/server-machine-files/ed25519_plain_expired.machine.
 *
 * It is the expired one on purpose. TAMGA_ERR_EXPIRED is only reachable after
 * the PEM, the certificate, the "+v2" marker, the Ed25519 signature, the
 * base64 payload and the signed claims have all been handled correctly, so it
 * exercises the whole path from a public-ABI caller -- and unlike the valid
 * fixtures, whose ttl is one hour, its verdict never changes with the wall
 * clock this entry point reads.
 */
static const char *MACHINE_PEM_V2_EXPIRED =
    "-----BEGIN MACHINE FILE-----\n"
    "eyJlbmMiOiJleUprWVhSaElqcDdJbUYwZEhKcFluVjBaWE1pT25zaVkyOXlaWE1pT2pnc0lt"
    "TnlaV0YwWldRaU9pSXlNREkyTFRBNExUSXhWREF5T2pJME9qSTVMakEzTlRNeU5Wb2lMQ0pr"
    "YVhOcklqbzFNVEl3TURBc0ltWnBibWRsY25CeWFXNTBJam9pWm1sNGRIVnlaUzFtYVc1blpY"
    "SndjbWx1ZEMxaE1XSXlZek1pTENKb1pXRnlkR0psWVhSZmMzUmhkSFZ6SWpvaVFVeEpWa1Vp"
    "TENKb2IzTjBibUZ0WlNJNkltWnBlSFIxY21VdGFHOXpkQ0lzSW1sd0lqb2lNakF6TGpBdU1U"
    "RXpMakV3SWl3aWJHRnpkRjlqYUdWamExOXZkWFJmWVhRaU9pSXlNREkyTFRBNExUSXhWREF5"
    "T2pJME9qSTVMakEzTlRNeU5Wb2lMQ0pzWVhOMFgyaGxZWEowWW1WaGRGOWhkQ0k2SWpJd01q"
    "WXRNRGd0TWpGVU1ESTZNalE2TWprdU1EYzFNekkxV2lJc0ltMWxiVzl5ZVNJNk1UWXpPRFFz"
    "SW0xbGRHRmtZWFJoSWpwN0luUnBaWElpT2lKbmIyeGtJbjBzSW01aGJXVWlPaUptYVhoMGRY"
    "SmxJRzFoWTJocGJtVWlMQ0p1WlhoMFgyaGxZWEowWW1WaGRGOWhkQ0k2SWpJd01qWXRNRGd0"
    "TWpGVU1ESTZNalE2TWprdU1EYzFNekkxV2lJc0luQnNZWFJtYjNKdElqb2liR2x1ZFhnaUxD"
    "SjFjR1JoZEdWa0lqb2lNakF5Tmkwd09DMHlNVlF3TWpveU5Eb3lPUzR3TnpVek1qVmFJbjBz"
    "SW1sa0lqb2lNREU1TXpabU1tRXRNREF3TUMwM01EQXdMVGd3TURBdE1EQXdNREF3TURBd01E"
    "QXhJaXdpZEhsd1pTSTZJbTFoWTJocGJtVnpJbjBzSW0xbGRHRWlPbnNpWlhod0lqb3hOemcz"
    "TWpjMU5EWTVMQ0pwWVhRaU9qRTNPRGN5Tnprd05qa3NJbXAwYVNJNklqQXhZVEF5TWpJeUxU"
    "Um1PVE10TnpSaU1DMDRZVE01TFRVeE4ySTBPR0kwWW1VeE9DSXNJbXRwWkNJNkltUmpORFZo"
    "WVRnNFlXRTVORGRpTURJaWZYMD0iLCJzaWciOiJ2STQrOU9VR0dldldLSHhhakc1QXBkTjAw"
    "ZTVlazkxOUt3b3A2ZXRuWTk4TTBSQmkzUWhIalR0OWYya3BlMjhkQ1pyTGlleEhFOVREcmVn"
    "UUNvditDUT09IiwiYWxnIjoiYmFzZTY0K2VkMjU1MTkrdjIifQ=="
    "\n-----END MACHINE FILE-----";

static const uint8_t MACHINE_PUBKEY_V2[32] = {
    0x01, 0x00, 0x20, 0xfc, 0x79, 0x0c, 0x08, 0xa5, 0x15, 0x9e, 0x90, 0xdf, 0x64, 0x05, 0x43, 0x5a,
    0x17, 0x89, 0xa3, 0x65, 0x26, 0x03, 0xa7, 0xe2, 0x04, 0x74, 0xd4, 0x0e, 0x00, 0x85, 0x0b, 0x48,
};

int main(void) {
    /* A v1 file is refused outright, with no fallback. */
    TamgaMachineFile *v1_handle = NULL;
    TamgaErrorCode code =
        tamga_machine_file_verify(MACHINE_PEM_V1, strlen(MACHINE_PEM_V1), TAMGA_SCHEME_ED25519_SIGN,
                                  MACHINE_PUBKEY, sizeof(MACHINE_PUBKEY), NULL, NULL, &v1_handle);
    if (code != TAMGA_ERR_UNSUPPORTED_SCHEME || v1_handle != NULL) {
        fprintf(stderr, "test_machine_file: a v1 machine file was not refused, code=%d\n",
                (int)code);
        return 1;
    }
    if (tamga_last_error_message() == NULL) {
        fprintf(stderr, "test_machine_file: a failing call recorded no message\n");
        return 1;
    }

    /* A real v2 file, authentic and expired: the signature verified, the
     * claims were read, and the answer is EXPIRED rather than
     * SIGNATURE_INVALID. A caller that cannot tell those apart either nags
     * about tampering when a trial ends, or treats a forgery as a renewal
     * prompt. */
    TamgaMachineFile *expired_handle = NULL;
    code = tamga_machine_file_verify(MACHINE_PEM_V2_EXPIRED, strlen(MACHINE_PEM_V2_EXPIRED),
                                     TAMGA_SCHEME_ED25519_SIGN, MACHINE_PUBKEY_V2,
                                     sizeof(MACHINE_PUBKEY_V2), NULL, NULL, &expired_handle);
    if (code != TAMGA_ERR_EXPIRED || expired_handle != NULL) {
        const char *err = tamga_last_error_message();
        fprintf(stderr, "test_machine_file: expected TAMGA_ERR_EXPIRED, code=%d, err=%s\n",
                (int)code, err ? err : "(none)");
        return 1;
    }

    /* The same v2 file under the wrong key fails on the signature instead --
     * so the EXPIRED above really did come after a successful verification. */
    uint8_t wrong_key[32];
    memcpy(wrong_key, MACHINE_PUBKEY_V2, sizeof(wrong_key));
    wrong_key[5] ^= 0x01u;
    TamgaMachineFile *forged_handle = NULL;
    code = tamga_machine_file_verify(MACHINE_PEM_V2_EXPIRED, strlen(MACHINE_PEM_V2_EXPIRED),
                                     TAMGA_SCHEME_ED25519_SIGN, wrong_key, sizeof(wrong_key), NULL,
                                     NULL, &forged_handle);
    if (code != TAMGA_ERR_SIGNATURE_INVALID || forged_handle != NULL) {
        fprintf(stderr, "test_machine_file: expected TAMGA_ERR_SIGNATURE_INVALID, code=%d\n",
                (int)code);
        return 1;
    }

    /* RSA_2048_JWT_RS256 must be rejected outright, never attempted. */
    TamgaMachineFile *jwt_handle = NULL;
    code = tamga_machine_file_verify(MACHINE_PEM_V2_EXPIRED, strlen(MACHINE_PEM_V2_EXPIRED),
                                     TAMGA_SCHEME_RSA_2048_JWT_RS256, MACHINE_PUBKEY_V2,
                                     sizeof(MACHINE_PUBKEY_V2), NULL, NULL, &jwt_handle);
    if (code != TAMGA_ERR_UNSUPPORTED_SCHEME || jwt_handle != NULL) {
        fprintf(stderr, "test_machine_file: RSA_2048_JWT_RS256 not rejected as expected\n");
        return 1;
    }

    /* An out-of-range raw scheme value must also be rejected, not treated
     * as undefined behavior. */
    TamgaMachineFile *bad_scheme_handle = NULL;
    code = tamga_machine_file_verify(MACHINE_PEM_V2_EXPIRED, strlen(MACHINE_PEM_V2_EXPIRED), 999,
                                     MACHINE_PUBKEY_V2, sizeof(MACHINE_PUBKEY_V2), NULL, NULL,
                                     &bad_scheme_handle);
    if (code != TAMGA_ERR_UNSUPPORTED_SCHEME || bad_scheme_handle != NULL) {
        fprintf(stderr, "test_machine_file: out-of-range scheme not rejected as expected\n");
        return 1;
    }

    /* Null is a documented no-op for the free function. */
    tamga_machine_file_free(NULL);

    printf("test_machine_file: OK\n");
    return 0;
}
