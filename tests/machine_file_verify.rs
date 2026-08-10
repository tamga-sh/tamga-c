//! Integration tests for `tamga_machine_file_verify` / `_get_json` /
//! `_free` (docs/plans/tamga-c.plan.md Section D). STUB -- no fixtures
//! exist yet.
//!
//! See `tests/license_file_verify.rs`'s module docs for the crate-type vs.
//! `cargo test` linking gotcha that applies equally here.
//!
//! Intended test cases once Section D lands:
//! - Ed25519-signed machine file verifies
//! - RSA-2048-PKCS1-signed machine file verifies
//! - RSA-2048-PKCS1-PSS-signed machine file verifies
//! - ECDSA-P256-signed machine file verifies
//! - `RSA_2048_JWT_RS256` scheme is rejected outright, never silently
//!   attempted as a signature scheme
//! - encrypted machine file decrypts correctly given the matching license
//!   key + fingerprint pair
//! - decrypt fails when the supplied fingerprint doesn't match the one
//!   used to derive the original key

#[test]
#[ignore = "stub: Section D (Machine Checkout FFI) not implemented yet"]
fn machine_file_verify_not_implemented() {
    todo!("see docs/plans/tamga-c.plan.md Section D");
}
