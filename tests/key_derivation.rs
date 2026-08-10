//! Integration tests for `tamga_hkdf_derive_machine_file_key` and
//! `tamga_naive_derive_license_file_key` (docs/plans/tamga-c.plan.md
//! Sections C and D, src/kdf.rs). STUB -- no fixtures exist yet.
//!
//! See `tests/license_file_verify.rs`'s module docs for the crate-type vs.
//! `cargo test` linking gotcha that applies equally here.
//!
//! Intended test cases once Sections C/D land:
//! - zero-pad/truncate license-file key derivation matches server behavior
//!   for license keys shorter and longer than 32 bytes
//! - HKDF-SHA256 machine-file key derivation output matches a fixed
//!   known-answer test vector (salt/ikm/info held constant)

#[test]
#[ignore = "stub: Sections C/D (key derivation) not implemented yet"]
fn key_derivation_not_implemented() {
    todo!("see docs/plans/tamga-c.plan.md Sections C and D");
}
