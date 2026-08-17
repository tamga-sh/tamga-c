//! Alloc/free contract tests for the handle and string lifecycle.
//!
//! See `tests/license_file_verify.rs`'s module doc comment for why this
//! crate's own lib is imported here as `tamga::...`, not `tamga_c::...`.
//!
//! Double-free is documented UB, not silently tolerated — deliberately NOT
//! exercised here as a "safe" negative test. A plain debug `cargo test` run
//! can appear to "succeed" at a double-free by accident (the allocator
//! happening not to visibly corrupt anything that run) while still being
//! undefined behavior; asserting on that outcome would be actively
//! misleading. Real double-free detection belongs in the ASAN-gated C
//! harness (`tests/c/CMakeLists.txt`'s `TAMGA_C_ENABLE_ASAN` option), which
//! is built specifically to catch it.

use std::ptr;

use tamga::tamga_string_free;

#[test]
fn string_free_null_is_noop() {
    // Must not crash; there is no return value or side effect to observe
    // beyond "the process is still running after this call."
    unsafe { tamga_string_free(ptr::null_mut()) };
}
