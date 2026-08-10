//! Integration tests for `tamga_license_file_verify` / `_get_json` /
//! `_free` (docs/plans/tamga-c.plan.md Section C). STUB -- no fixtures
//! exist yet.
//!
//! # KNOWN GOTCHA: crate-type vs. `cargo test`
//!
//! This crate's `[lib] crate-type` is currently `["cdylib", "staticlib"]`
//! only (see Cargo.toml) -- neither produces the rustc metadata Cargo needs
//! to link a `tests/*.rs` integration-test binary against this crate's
//! Rust API via `--extern`. As written, this file will not actually
//! compile as a `cargo test` target until that's resolved: either add
//! "rlib" to crate-type (ideally gated so it doesn't ship in release
//! artifacts), or drive these tests through the C ABI directly instead of
//! a `use tamga_c::...` style. Documented again in CLAUDE.md — do not
//! "fix" this silently by editing crate-type without reading that note.
//!
//! Intended test cases once Section C lands:
//! - valid unencrypted license file (`base64+ed25519`) round-trips and verifies
//! - valid encrypted license file (`aes-256-gcm+ed25519`) round-trips and verifies
//! - tampering with the `enc` string fails signature verification
//! - signing over the base64-*decoded* bytes instead of the base64
//!   *string* fails verification (regression test for the string-not-bytes
//!   gotcha — see CLAUDE.md)
//! - wrong Ed25519 public key fails verification
//! - malformed PEM markers rejected with `TAMGA_ERR_INVALID_PEM`
//! - malformed base64 rejected with `TAMGA_ERR_INVALID_BASE64`
//! - unsupported `alg` string rejected with `TAMGA_ERR_UNSUPPORTED_SCHEME`

#[test]
#[ignore = "stub: Section C (License Checkout FFI) not implemented yet"]
fn license_file_verify_not_implemented() {
    todo!("see docs/plans/tamga-c.plan.md Section C");
}
