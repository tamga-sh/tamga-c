/**
 * verify_license.c
 *
 * STUB example -- illustrates the intended minimal end-to-end flow once
 * Section C of docs/plans/tamga-c.plan.md ("License Checkout FFI") lands:
 *
 *   1. read a .lic file from disk into memory
 *   2. call tamga_license_file_verify(pem, pem_len, ed25519_pubkey, &handle)
 *   3. on TAMGA_OK, call tamga_license_file_get_json(handle, &json, &len)
 *      and print it
 *   4. tamga_license_file_free(handle)
 *
 * Deliberately does NOT `#include "tamga.h"` yet -- that header has no real
 * declarations to call against (see include/tamga.h). Not built by default
 * (see examples/CMakeLists.txt / the parent TAMGA_C_BUILD_EXAMPLES option).
 */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path-to-.lic-file>\n", argv[0]);
        return 1;
    }

    fprintf(stderr, "verify_license: STUB example, not yet functional "
                    "(see docs/plans/tamga-c.plan.md Section C)\n");
    (void)argv[1];
    return 0;
}
