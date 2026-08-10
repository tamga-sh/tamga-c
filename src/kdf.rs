//! Standalone key-derivation primitives, split out of Sections C/D of
//! `docs/plans/tamga-c.plan.md` for callers who need the raw AES key
//! without a full file-verify round-trip.
//!
//! # Two different derivations — do not confuse them
//!
//! - **License-file key** ([`tamga_naive_derive_license_file_key`]): `docs/sdk.md`
//!   §4 — ⚠️ **not a KDF**. `license.key`'s raw UTF-8 bytes, zero-padded or
//!   truncated to exactly 32 bytes. Not a hash, not PBKDF2, not HKDF — must
//!   byte-exactly replicate the server's naive transform.
//! - **Machine-file key** ([`tamga_hkdf_derive_machine_file_key`]): `docs/sdk.md`
//!   §6 — properly HKDF-SHA256 derived: `salt = "tamga:machine-file-key-v1"`,
//!   `ikm = <license key>`, `info = <machine fingerprint>` → 32 bytes.

use std::ffi::c_char;
use std::slice;

use crate::{TamgaErrorCode, ffi_guard};

/// Derives the 32-byte AES key for an encrypted machine file via
/// HKDF-SHA256: `salt = "tamga:machine-file-key-v1"`, `ikm = license_key`,
/// `info = fingerprint`.
///
/// # Parameters
/// - `license_key` / `fingerprint`: NUL-terminated C strings; both required
///   (the derivation needs both to reproduce the server's key).
/// - `out_32_bytes`: receives exactly 32 derived bytes on `TAMGA_OK`.
///
/// # Safety
/// `license_key`/`fingerprint` must be null or valid NUL-terminated C
/// strings. `out_32_bytes` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_hkdf_derive_machine_file_key(
    license_key: *const c_char,
    fingerprint: *const c_char,
    out_32_bytes: *mut u8,
) -> TamgaErrorCode {
    ffi_guard(|| {
        if out_32_bytes.is_null() {
            crate::set_last_error("tamga_hkdf_derive_machine_file_key: null argument");
            return Err(TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
        }
        // SAFETY: caller contract requires `license_key`/`fingerprint` to
        // be null or valid NUL-terminated C strings.
        let license_key_str = unsafe { crate::cstr_to_str(license_key) }.inspect_err(|_| {
            crate::set_last_error(
                "tamga_hkdf_derive_machine_file_key: license_key is null or not valid UTF-8",
            );
        })?;
        let fingerprint_str = unsafe { crate::cstr_to_str(fingerprint) }.inspect_err(|_| {
            crate::set_last_error(
                "tamga_hkdf_derive_machine_file_key: fingerprint is null or not valid UTF-8",
            );
        })?;

        let key =
            tamga_rust::crypto::hkdf::derive_machine_file_key(license_key_str, fingerprint_str);

        // SAFETY: caller contract requires `out_32_bytes` to point to at
        // least 32 writable bytes; checked non-null above.
        unsafe {
            slice::from_raw_parts_mut(out_32_bytes, 32).copy_from_slice(&key);
        }
        Ok(())
    })
}

/// Derives the 32-byte AES key for an encrypted license file via the
/// server's **naive, non-KDF** transform: `license_key`'s raw UTF-8 bytes,
/// zero-padded or truncated to exactly 32 bytes.
///
/// # Parameters
/// - `license_key`: NUL-terminated C string.
/// - `out_32_bytes`: receives exactly 32 derived bytes on `TAMGA_OK`.
///
/// # Safety
/// `license_key` must be null or a valid NUL-terminated C string.
/// `out_32_bytes` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_naive_derive_license_file_key(
    license_key: *const c_char,
    out_32_bytes: *mut u8,
) -> TamgaErrorCode {
    ffi_guard(|| {
        if out_32_bytes.is_null() {
            crate::set_last_error("tamga_naive_derive_license_file_key: null argument");
            return Err(TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
        }
        // SAFETY: caller contract requires `license_key` to be null or a
        // valid NUL-terminated C string.
        let license_key_str = unsafe { crate::cstr_to_str(license_key) }.inspect_err(|_| {
            crate::set_last_error(
                "tamga_naive_derive_license_file_key: license_key is null or not valid UTF-8",
            );
        })?;

        let key = tamga_rust::crypto::naive_key::derive_license_file_key(license_key_str);

        // SAFETY: caller contract requires `out_32_bytes` to point to at
        // least 32 writable bytes; checked non-null above.
        unsafe {
            slice::from_raw_parts_mut(out_32_bytes, 32).copy_from_slice(&key);
        }
        Ok(())
    })
}
