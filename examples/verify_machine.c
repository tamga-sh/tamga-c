/**
 * verify_machine.c
 *
 * STUB example -- same shape as verify_license.c, for machine files, once
 * Section D of docs/plans/tamga-c.plan.md ("Machine Checkout FFI") lands.
 * Demonstrates scheme selection: the caller must pass the license's
 * `scheme` field (TamgaScheme) explicitly -- machine-file verification is
 * NOT hardcoded to Ed25519 like license-file verification is.
 *
 * Deliberately does NOT `#include "tamga.h"` yet -- see include/tamga.h.
 * Not built by default (see examples/CMakeLists.txt).
 */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path-to-machine-file>\n", argv[0]);
        return 1;
    }

    fprintf(stderr, "verify_machine: STUB example, not yet functional "
                    "(see docs/plans/tamga-c.plan.md Section D)\n");
    (void)argv[1];
    return 0;
}
