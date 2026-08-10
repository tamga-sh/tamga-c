/**
 * verify_license.c
 *
 * Minimal end-to-end example: read a `.lic` file from disk, verify it with
 * tamga_license_file_verify, print the decoded LicenseResource JSON, then
 * free the handle. Pass an optional third argument as the license key to
 * verify an encrypted (`aes-256-gcm+ed25519`) file.
 *
 * Usage: verify_license <path-to-.lic-file> <ed25519-pubkey-hex> [license-key]
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
        fprintf(stderr, "usage: %s <path-to-.lic-file> <ed25519-pubkey-hex> [license-key]\n",
                argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "verify_license: failed to open %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) {
        fprintf(stderr, "verify_license: failed to determine file size\n");
        fclose(f);
        return 1;
    }
    char *pem = malloc((size_t)size);
    if (!pem || fread(pem, 1, (size_t)size, f) != (size_t)size) {
        fprintf(stderr, "verify_license: failed to read %s\n", argv[1]);
        fclose(f);
        free(pem);
        return 1;
    }
    fclose(f);

    uint8_t pubkey[32];
    if (hex_to_bytes(argv[2], pubkey, sizeof(pubkey)) != 0) {
        fprintf(stderr, "verify_license: pubkey must be exactly 64 hex characters (32 bytes)\n");
        free(pem);
        return 1;
    }

    const char *license_key = argc >= 4 ? argv[3] : NULL;

    TamgaLicenseFile *handle = NULL;
    TamgaErrorCode code =
        tamga_license_file_verify(pem, (size_t)size, pubkey, license_key, &handle);
    free(pem);

    if (code != TAMGA_OK) {
        const char *err = tamga_last_error_message();
        fprintf(stderr, "verify_license: verification failed (code=%d): %s\n", (int)code,
                err ? err : "(no detail)");
        return 1;
    }

    char *json = NULL;
    uintptr_t json_len = 0;
    code = tamga_license_file_get_json(handle, &json, &json_len);
    tamga_license_file_free(handle);
    if (code != TAMGA_OK) {
        fprintf(stderr, "verify_license: get_json failed (code=%d)\n", (int)code);
        return 1;
    }

    printf("%s\n", json);
    tamga_string_free(json);
    return 0;
}
