/**
 * test_offline_proof.c
 *
 * STUB -- CTest harness placeholder for Section E of
 * docs/plans/tamga-c.plan.md ("Machine Offline Proof FFI"). No assertions
 * yet: `tamga_offline_proof_verify`/`_generate` (src/offline_proof.rs)
 * currently always return TAMGA_ERR_UNKNOWN. Deliberately does NOT
 * `#include "tamga.h"` yet -- see include/tamga.h.
 *
 * Intended contents once Section E lands: exercise both
 * tamga_offline_proof_verify and tamga_offline_proof_generate, including a
 * known-answer fixture captured from a real tamga-api
 * `generate-offline-proof` response (cross-repo compatibility guard, not
 * just an internal round-trip) and the field-order regression case --
 * see the plan's Section E test list for the full set (mirrors
 * tests/offline_proof.rs on the Rust side).
 */
#include <stdio.h>

int main(void) {
    printf("test_offline_proof: STUB, not implemented yet "
           "(see docs/plans/tamga-c.plan.md Section E)\n");
    return 0;
}
