//! Alloc/free contract tests (docs/plans/tamga-c.plan.md Section F). STUB.
//!
//! See `tests/license_file_verify.rs`'s module docs for the crate-type vs.
//! `cargo test` linking gotcha that applies equally here.
//!
//! Intended test cases once Section F lands:
//! - calling `tamga_string_free` on a null pointer is a documented no-op,
//!   not a crash (this one IS already implemented in `src/lib.rs` —
//!   promote this test out of `#[ignore]` once the crate-type gotcha above
//!   is resolved and it can actually link)
//! - double-free is documented as UB, not silently tolerated — kept as an
//!   ASAN-only negative test, never asserted as "safe" (gate behind the
//!   same ASAN CTest job tests/c/CMakeLists.txt's `TAMGA_C_ENABLE_ASAN`
//!   option covers, not a normal `cargo test` run)

#[test]
#[ignore = "stub: blocked on the crate-type/rlib gotcha documented in this file's module docs"]
fn string_free_null_is_noop() {
    todo!("see docs/plans/tamga-c.plan.md Section F and this file's module docs");
}
