/**
 * test_license_file.c
 *
 * STUB -- CTest harness placeholder for Section C of
 * docs/plans/tamga-c.plan.md ("License Checkout FFI"). No assertions yet:
 * `tamga_license_file_verify` (src/license_file.rs) currently always
 * returns TAMGA_ERR_UNKNOWN, so there is nothing real to assert against.
 * Deliberately does NOT `#include "tamga.h"` yet -- that header has no
 * real declarations to call against either (see include/tamga.h).
 *
 * Intended contents once Section C lands:
 *   - load a known-good fixture .lic file (both `base64+ed25519` and
 *     `aes-256-gcm+ed25519` variants) from disk or an embedded byte array
 *   - call tamga_license_file_verify(...) and assert TAMGA_OK
 *   - call tamga_license_file_get_json(...) and assert the decoded JSON
 *     matches the fixture's expected LicenseResource fields
 *   - call tamga_license_file_free(...) and confirm zero ASAN leak reports
 *     under the -DTAMGA_C_ENABLE_ASAN=ON CTest job
 *   - negative cases: tampered `enc`, wrong pubkey, malformed PEM/base64,
 *     unsupported `alg` -- see the plan's Section C test list for the full
 *     set (mirrors tests/license_file_verify.rs on the Rust side)
 */
#include <stdio.h>

int main(void) {
    printf("test_license_file: STUB, not implemented yet "
           "(see docs/plans/tamga-c.plan.md Section C)\n");
    return 0;
}
