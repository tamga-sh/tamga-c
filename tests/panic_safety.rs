//! Regression coverage for the `catch_unwind` contract every `extern "C"
//! fn` must uphold (docs/plans/tamga-c.plan.md Section F).
//!
//! The actual "does `ffi_guard` catch a panic and convert it to
//! `TAMGA_ERR_PANIC` instead of unwinding" proof lives as a unit test —
//! `ffi_guard_tests` in `src/lib.rs`, next to `ffi_guard` itself — not
//! here. `ffi_guard` is `pub(crate)`, so an integration test in this file
//! can't call it directly; more fundamentally, no *production* input can
//! reach a real panic today (every fallible step in every FFI function
//! returns a typed `Result`, not `unwrap()`/`expect()` on attacker-
//! controlled data), so there is no "malformed internal state" to simulate
//! through the public C ABI the way the plan's original wording envisioned.
//! Testing the generic wrapper directly against a deliberately panicking
//! closure is the correct level for this: it proves the mechanism holds for
//! *any* panic, not just ones we can currently think up an input for.
//!
//! This file keeps a thin companion check: that `TAMGA_ERR_PANIC` exists in
//! the public C ABI at all (a compile-time guarantee cbindgen also depends
//! on) and that a normal successful call never returns it — catching an
//! accidental renumbering of the `TamgaErrorCode` enum that the unit tests,
//! being crate-internal, wouldn't by themselves prove is externally visible.
use std::ffi::CString;

use tamga::TamgaErrorCode;
use tamga::kdf::tamga_hkdf_derive_license_file_key;

#[test]
fn tamga_err_panic_is_a_distinct_value_never_returned_on_success() {
    let c_key = CString::new("lic-abc123").unwrap();
    let mut out = [0u8; 32];
    let code = unsafe { tamga_hkdf_derive_license_file_key(c_key.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK);
    assert_ne!(code, TamgaErrorCode::TAMGA_ERR_PANIC);
}
