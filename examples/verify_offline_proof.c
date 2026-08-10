/**
 * verify_offline_proof.c
 *
 * STUB example -- illustrates an air-gapped proof-verification flow once
 * Section E of docs/plans/tamga-c.plan.md ("Machine Offline Proof FFI")
 * lands: call tamga_offline_proof_verify(...) with a "v1x0.<sig>" proof
 * string, the account's RSA-2048 public key, and the same
 * account/machine/fingerprint/dataset values the server signed, then
 * inspect the out_valid boolean.
 *
 * Deliberately does NOT `#include "tamga.h"` yet -- see include/tamga.h.
 * Not built by default (see examples/CMakeLists.txt).
 */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <proof-string>\n", argv[0]);
        return 1;
    }

    fprintf(stderr, "verify_offline_proof: STUB example, not yet functional "
                    "(see docs/plans/tamga-c.plan.md Section E)\n");
    (void)argv[1];
    return 0;
}
