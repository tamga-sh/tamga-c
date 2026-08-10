/**
 * verify_machine.c
 *
 * Same shape as verify_license.c, for machine files. Demonstrates scheme
 * selection: the caller passes the license's `scheme` field explicitly (as
 * one of the TAMGA_SCHEME_* names) -- machine-file verification is NOT
 * hardcoded to Ed25519 like license-file verification is. Only Ed25519's
 * 32-byte raw pubkey format is handled by this example's hex parsing; RSA/
 * ECDSA pubkeys (DER/uncompressed-point, variable length) would need a
 * length argument too -- left out here to keep the example focused.
 *
 * Usage: verify_machine <path-to-machine-file> <ed25519-pubkey-hex> [license-key] [fingerprint]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tamga.h"

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != out_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (uint8_t)byte;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <path-to-machine-file> <ed25519-pubkey-hex> "
                "[license-key] [fingerprint]\n",
                argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "verify_machine: failed to open %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) {
        fprintf(stderr, "verify_machine: failed to determine file size\n");
        fclose(f);
        return 1;
    }
    char *pem = malloc((size_t)size);
    if (!pem || fread(pem, 1, (size_t)size, f) != (size_t)size) {
        fprintf(stderr, "verify_machine: failed to read %s\n", argv[1]);
        fclose(f);
        free(pem);
        return 1;
    }
    fclose(f);

    uint8_t pubkey[32];
    if (hex_to_bytes(argv[2], pubkey, sizeof(pubkey)) != 0) {
        fprintf(stderr, "verify_machine: pubkey must be exactly 64 hex characters (32 bytes)\n");
        free(pem);
        return 1;
    }

    const char *license_key = argc >= 4 ? argv[3] : NULL;
    const char *fingerprint = argc >= 5 ? argv[4] : NULL;

    TamgaMachineFile *handle = NULL;
    TamgaErrorCode code =
        tamga_machine_file_verify(pem, (size_t)size, TAMGA_SCHEME_ED25519_SIGN, pubkey,
                                  sizeof(pubkey), license_key, fingerprint, &handle);
    free(pem);

    if (code != TAMGA_OK) {
        const char *err = tamga_last_error_message();
        fprintf(stderr, "verify_machine: verification failed (code=%d): %s\n", (int)code,
                err ? err : "(no detail)");
        return 1;
    }

    char *json = NULL;
    uintptr_t json_len = 0;
    code = tamga_machine_file_get_json(handle, &json, &json_len);
    tamga_machine_file_free(handle);
    if (code != TAMGA_OK) {
        fprintf(stderr, "verify_machine: get_json failed (code=%d)\n", (int)code);
        return 1;
    }

    printf("%s\n", json);
    tamga_string_free(json);
    return 0;
}
