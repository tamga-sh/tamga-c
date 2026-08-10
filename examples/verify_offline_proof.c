/**
 * verify_offline_proof.c
 *
 * Air-gapped proof-verification flow: call tamga_offline_proof_verify(...)
 * with a "v1x0.<sig>" proof string, the account's RSA-2048 public key (SPKI
 * DER, read from a file), and the same account/machine/fingerprint/dataset
 * values the server signed, then inspect the out_valid boolean.
 *
 * Usage: verify_offline_proof <proof-string> <rsa-pubkey-der-file>
 *                              <account-id> <machine-id> <fingerprint> <dataset-json>
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "tamga.h"

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr,
                "usage: %s <proof-string> <rsa-pubkey-der-file> <account-id> "
                "<machine-id> <fingerprint> <dataset-json>\n",
                argv[0]);
        return 1;
    }
    const char *proof_str = argv[1];
    const char *pubkey_path = argv[2];
    const char *account_id = argv[3];
    const char *machine_id = argv[4];
    const char *fingerprint = argv[5];
    const char *dataset_json = argv[6];

    FILE *f = fopen(pubkey_path, "rb");
    if (!f) {
        fprintf(stderr, "verify_offline_proof: failed to open %s\n", pubkey_path);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) {
        fprintf(stderr, "verify_offline_proof: failed to determine pubkey file size\n");
        fclose(f);
        return 1;
    }
    uint8_t *pubkey = malloc((size_t)size);
    if (!pubkey || fread(pubkey, 1, (size_t)size, f) != (size_t)size) {
        fprintf(stderr, "verify_offline_proof: failed to read %s\n", pubkey_path);
        fclose(f);
        free(pubkey);
        return 1;
    }
    fclose(f);

    bool valid = false;
    TamgaErrorCode code = tamga_offline_proof_verify(proof_str, pubkey, (size_t)size, account_id,
                                                     machine_id, fingerprint, dataset_json, &valid);
    free(pubkey);

    if (code != TAMGA_OK) {
        const char *err = tamga_last_error_message();
        fprintf(stderr, "verify_offline_proof: call failed (code=%d): %s\n", (int)code,
                err ? err : "(no detail)");
        return 1;
    }

    printf("proof valid: %s\n", valid ? "true" : "false");
    return valid ? 0 : 1;
}
