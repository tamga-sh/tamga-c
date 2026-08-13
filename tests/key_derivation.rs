//! Integration tests for `tamga_hkdf_derive_license_file_key` (Section C)
//! and `tamga_hkdf_derive_machine_file_key` (Section D) —
//! `docs/plans/tamga-c.plan.md`, `src/kdf.rs`.
//!
//! See `tests/license_file_verify.rs`'s module doc comment for why this
//! crate's own lib is imported here as `tamga::...`, not `tamga_c::...`.
use std::ffi::CString;
use std::ptr;

use tamga::TamgaErrorCode;
use tamga::kdf::{tamga_hkdf_derive_license_file_key, tamga_hkdf_derive_machine_file_key};

fn derive_license(license_key: &str) -> (TamgaErrorCode, [u8; 32]) {
    let c_key = CString::new(license_key).unwrap();
    let mut out = [0u8; 32];
    let code = unsafe { tamga_hkdf_derive_license_file_key(c_key.as_ptr(), out.as_mut_ptr()) };
    (code, out)
}

#[test]
fn the_license_key_is_not_recoverable_from_the_derived_key() {
    // The v1 transform zero-padded the licence key, so the derived key
    // literally contained it in cleartext and everything past its length was
    // zero — a stolen `.lic` was a dictionary attack, not a 256-bit one.
    let (code, key) = derive_license("SHORT-KEY");
    assert_eq!(code, TamgaErrorCode::TAMGA_OK);
    assert_ne!(&key[..9], b"SHORT-KEY");
    assert!(key[9..].iter().any(|b| *b != 0));
}

#[test]
fn a_long_key_is_mixed_rather_than_truncated() {
    // v1 truncated at 32 bytes, so any two keys sharing a 32-byte prefix
    // produced the same AES key.
    let a = derive_license(&format!("{}A", "x".repeat(40))).1;
    let b = derive_license(&format!("{}B", "x".repeat(40))).1;
    assert_ne!(a, b);
}

#[test]
fn derivation_is_deterministic() {
    assert_eq!(derive_license("lic-abc123").1, derive_license("lic-abc123").1);
    assert_ne!(derive_license("lic-abc123").1, derive_license("lic-abc124").1);
}

#[test]
fn matches_tamga_rust_reference_derivation() {
    // Cross-checks this FFI wrapper against the exact function tamga-rust's
    // own tests verify against the server — proves the wrapper is not
    // silently reimplementing (and drifting from) the derivation.
    let license_key = "lic-abc123";
    let (code, key) = derive_license(license_key);
    assert_eq!(code, TamgaErrorCode::TAMGA_OK);
    let expected = tamga_rust::crypto::hkdf::derive_license_file_key(license_key);
    assert_eq!(key, *expected);
}

#[test]
fn null_license_key_pointer_rejected() {
    let mut out = [0u8; 32];
    let code = unsafe { tamga_hkdf_derive_license_file_key(ptr::null(), out.as_mut_ptr()) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
}

#[test]
fn null_out_pointer_rejected() {
    let c_key = CString::new("lic-abc123").unwrap();
    let code = unsafe { tamga_hkdf_derive_license_file_key(c_key.as_ptr(), ptr::null_mut()) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
}

fn derive_hkdf(license_key: &str, fingerprint: &str) -> (TamgaErrorCode, [u8; 32]) {
    let c_key = CString::new(license_key).unwrap();
    let c_fp = CString::new(fingerprint).unwrap();
    let mut out = [0u8; 32];
    let code = unsafe {
        tamga_hkdf_derive_machine_file_key(c_key.as_ptr(), c_fp.as_ptr(), out.as_mut_ptr())
    };
    (code, out)
}

#[test]
fn matches_tamga_rust_reference_hkdf_derivation() {
    let (code, key) = derive_hkdf("lic-abc123", "machine-fp");
    assert_eq!(code, TamgaErrorCode::TAMGA_OK);
    let expected = tamga_rust::crypto::hkdf::derive_machine_file_key("lic-abc123", "machine-fp");
    assert_eq!(key, *expected);
}

#[test]
fn hkdf_different_license_key_produces_different_key() {
    let (_, key_a) = derive_hkdf("key-a", "fp");
    let (_, key_b) = derive_hkdf("key-b", "fp");
    assert_ne!(key_a, key_b);
}

#[test]
fn hkdf_different_fingerprint_produces_different_key() {
    let (_, key_a) = derive_hkdf("lk", "fp-a");
    let (_, key_b) = derive_hkdf("lk", "fp-b");
    assert_ne!(key_a, key_b);
}

#[test]
fn hkdf_prefix_collision_inputs_produce_different_keys() {
    let (_, key_a) = derive_hkdf("ab", "cdef");
    let (_, key_b) = derive_hkdf("abc", "def");
    assert_ne!(
        key_a, key_b,
        "HKDF must prevent prefix-collision between license_key and fingerprint"
    );
}

#[test]
fn hkdf_null_license_key_pointer_rejected() {
    let fingerprint = CString::new("machine-fp").unwrap();
    let mut out = [0u8; 32];
    let code = unsafe {
        tamga_hkdf_derive_machine_file_key(ptr::null(), fingerprint.as_ptr(), out.as_mut_ptr())
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
}

#[test]
fn hkdf_null_fingerprint_pointer_rejected() {
    let license_key = CString::new("lic-abc123").unwrap();
    let mut out = [0u8; 32];
    let code = unsafe {
        tamga_hkdf_derive_machine_file_key(license_key.as_ptr(), ptr::null(), out.as_mut_ptr())
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
}

#[test]
fn hkdf_null_out_pointer_rejected() {
    let license_key = CString::new("lic-abc123").unwrap();
    let fingerprint = CString::new("machine-fp").unwrap();
    let code = unsafe {
        tamga_hkdf_derive_machine_file_key(
            license_key.as_ptr(),
            fingerprint.as_ptr(),
            ptr::null_mut(),
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
}
