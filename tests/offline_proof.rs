//! Integration tests for `tamga_offline_proof_verify` / `_generate`
//! (docs/plans/tamga-c.plan.md Section E). STUB -- no fixtures exist yet.
//!
//! See `tests/license_file_verify.rs`'s module docs for the crate-type vs.
//! `cargo test` linking gotcha that applies equally here.
//!
//! Intended test cases once Section E lands:
//! - a proof generated in-process verifies against its own RSA public key
//! - a proof with a reordered-but-semantically-equivalent dataset JSON
//!   fails verification (regression test for the field-order gotcha — see
//!   CLAUDE.md)
//! - tampered `account.id` or `machine.id` fails verification
//! - tampered `dataset` fails verification
//! - malformed `v1x0.` prefix rejected
//! - a known-answer fixture captured from a real `tamga-api`
//!   `generate-offline-proof` response verifies correctly — cross-repo
//!   compatibility guard, not just an internal round-trip

#[test]
#[ignore = "stub: Section E (Machine Offline Proof FFI) not implemented yet"]
fn offline_proof_not_implemented() {
    todo!("see docs/plans/tamga-c.plan.md Section E");
}
