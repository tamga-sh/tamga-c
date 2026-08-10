//! Regression tests for the `catch_unwind` contract every `extern "C" fn`
//! must uphold (docs/plans/tamga-c.plan.md Section F). STUB.
//!
//! See `tests/license_file_verify.rs`'s module docs for the crate-type vs.
//! `cargo test` linking gotcha that applies equally here.
//!
//! Intended test case once Section F lands: a panic inside a verify
//! function (simulated via malformed internal state) is caught by
//! [`ffi_guard`](../src/lib.rs) and surfaces as `TAMGA_ERR_PANIC`, not a
//! process abort. This is the test that proves the reference
//! `catch_unwind` pattern in `tamga_license_file_verify` (and every
//! function that copies it) actually holds under a real panic, not just by
//! code inspection.

#[test]
#[ignore = "stub: Section F (Memory & Lifecycle Management) not implemented yet"]
fn panic_is_caught_not_aborted() {
    todo!("see docs/plans/tamga-c.plan.md Section F");
}
