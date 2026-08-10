/**
 * test_machine_file.c
 *
 * STUB -- CTest harness placeholder for Section D of
 * docs/plans/tamga-c.plan.md ("Machine Checkout FFI"). No assertions yet:
 * `tamga_machine_file_verify` (src/machine_file.rs) currently always
 * returns TAMGA_ERR_UNKNOWN. Deliberately does NOT `#include "tamga.h"`
 * yet -- see include/tamga.h.
 *
 * Intended contents once Section D lands: exercise
 * tamga_machine_file_verify across all 4 supported schemes
 * (ED25519_SIGN, RSA_2048_PKCS1_SIGN, RSA_2048_PKCS1_PSS_SIGN,
 * ECDSA_P256_SIGN), confirm RSA_2048_JWT_RS256 is rejected outright, and
 * confirm encrypted-file decrypt succeeds only with the matching
 * (license_key, fingerprint) pair -- see the plan's Section D test list
 * for the full set (mirrors tests/machine_file_verify.rs on the Rust
 * side).
 */
#include <stdio.h>

int main(void) {
    printf("test_machine_file: STUB, not implemented yet "
           "(see docs/plans/tamga-c.plan.md Section D)\n");
    return 0;
}
