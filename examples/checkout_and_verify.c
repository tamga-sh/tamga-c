/*
 * checkout_and_verify.c -- obtain an offline licence file and verify it
 * without the network.
 *
 *   checkout_and_verify <account-id> <license-id> <license-key> \
 *                       <ed25519-pubkey-hex> [ttl-seconds] [host]
 *
 * This is the pattern for software that must keep working offline: check out
 * a file while connected, store it, and verify it locally from then on. The
 * verification below makes no network call at all -- it needs only the file
 * and the account's public key, both of which can be embedded in the
 * application.
 *
 * The ttl matters. A file checked out without one never expires, so an
 * offline grace period is really "forever" unless a ttl is requested.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tamga.h"

/* Decodes 64 hex characters into the account's 32-byte Ed25519 public key. */
static int parse_pubkey(const char *hex, uint8_t out[32]) {
    size_t i;
    if (strlen(hex) != 64u) {
        return 0;
    }
    for (i = 0u; i < 32u; i++) {
        unsigned int byte;
        if (sscanf(&hex[i * 2u], "%2x", &byte) != 1) {
            return 0;
        }
        out[i] = (uint8_t)byte;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *host = "api.tamga.sh";
    long ttl = 86400;
    uint8_t pubkey[32];
    TamgaClient *client = NULL;
    TamgaResponse *response = NULL;
    TamgaLicenseFile *file = NULL;
    TamgaErrorCode code;
    int exit_status = 2;

    if (argc < 5) {
        (void)fprintf(stderr,
                      "usage: %s <account-id> <license-id> <license-key> "
                      "<ed25519-pubkey-hex> [ttl-seconds] [host]\n",
                      argv[0]);
        return 2;
    }
    if (!parse_pubkey(argv[4], pubkey)) {
        (void)fprintf(stderr, "the public key must be 64 hex characters\n");
        return 2;
    }
    if (argc > 5) {
        ttl = strtol(argv[5], NULL, 10);
    }
    if (argc > 6) {
        host = argv[6];
    }

    code = tamga_client_new(argv[1], host, &client);
    if (code == TAMGA_OK) {
        code = tamga_client_set_auth(client, TAMGA_AUTH_LICENSE, argv[3], NULL);
    }
    if (code != TAMGA_OK) {
        (void)fprintf(stderr, "setup failed: %s\n", tamga_last_error_message());
        tamga_client_free(client);
        return 2;
    }

    /* encrypt = true means the payload is sealed with a key derived from the
     * licence key, so the file is readable only by someone who already has
     * it. */
    code = tamga_client_check_out_license(client, argv[2], true, (int64_t)ttl, &response);
    if (code != TAMGA_OK) {
        (void)fprintf(stderr, "checkout failed: %s\n", tamga_error_name(code));
        tamga_response_free(response);
        tamga_client_free(client);
        return 2;
    }

    {
        uintptr_t pem_len = 0u;
        const char *pem = tamga_response_json(response, &pem_len);

        printf("--- checked out %lu bytes; store this and verify it offline ---\n",
               (unsigned long)pem_len);

        /* Everything from here needs no network. */
        code = tamga_license_file_verify(pem, pem_len, pubkey, argv[3], &file);
        if (code != TAMGA_OK) {
            (void)fprintf(stderr, "offline verification failed: %s (%s)\n", tamga_error_name(code),
                          tamga_last_error_message());
        } else {
            char *json = NULL;
            uintptr_t json_len = 0u;
            if (tamga_license_file_get_json(file, &json, &json_len) == TAMGA_OK) {
                printf("verified offline. licence resource:\n%s\n", json);
                tamga_string_free(json);
            }
            exit_status = 0;
        }
    }

    tamga_license_file_free(file);
    tamga_response_free(response);
    tamga_client_free(client);
    return exit_status;
}
