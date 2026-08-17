//! Standalone key-derivation primitives, for callers who need the raw AES
//! key without a full file-verify round-trip.
//!
//! # Two different derivations — do not confuse them
//!
//! Both are HKDF-SHA256 (RFC 5869) as of offline file format v2, but with
//! different parameters. Using one where the other belongs produces a
//! function that looks plausible, compiles, and silently decrypts nothing.
//!
//! - **License-file key** ([`tamga_hkdf_derive_license_file_key`]):
//!   `salt = "tamga:license-file-key-v1"`, `ikm = <license key>`,
//!   `info = "license-file"` → 32 bytes. No fingerprint is involved; a
//!   licence file is not bound to a machine.
//! - **Machine-file key** ([`tamga_hkdf_derive_machine_file_key`]):
//!   `salt = "tamga:machine-file-key-v1"`, `ikm = <license key>`,
//!   `info = <machine fingerprint>` → 32 bytes. Decryption needs **both**
//!   the licence key and the target machine's fingerprint.
//!
//! Before format v2 the license-file key was not derived at all — it was the
//! licence key's raw bytes zero-padded (or truncated) to 32, so an attacker
//! holding a stolen `.lic` was attacking the licence key's own entropy rather
//! than a 256-bit key space. That transform is **removed, not deprecated**:
//! the old `tamga_naive_derive_license_file_key` symbol is gone, which is a
//! deliberate ABI break — leaving it exported would let a caller silently
//! keep decrypting with the weaker key.
//!
//! Both derivations delegate to `tamga-rust`'s `crypto::hkdf`; nothing is
//! reimplemented here.

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
            slice::from_raw_parts_mut(out_32_bytes, 32).copy_from_slice(&key[..]);
        }
        Ok(())
    })
}

/// Derives the 32-byte AES key for an encrypted license file via HKDF-SHA256:
/// `salt = "tamga:license-file-key-v1"`, `ikm = license_key`,
/// `info = "license-file"`.
///
/// # Parameters
/// - `license_key`: NUL-terminated C string.
/// - `out_32_bytes`: receives exactly 32 derived bytes on `TAMGA_OK`.
///
/// # Safety
/// `license_key` must be null or a valid NUL-terminated C string.
/// `out_32_bytes` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_hkdf_derive_license_file_key(
    license_key: *const c_char,
    out_32_bytes: *mut u8,
) -> TamgaErrorCode {
    ffi_guard(|| {
        if out_32_bytes.is_null() {
            crate::set_last_error("tamga_hkdf_derive_license_file_key: null argument");
            return Err(TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
        }
        // SAFETY: caller contract requires `license_key` to be null or a
        // valid NUL-terminated C string.
        let license_key_str = unsafe { crate::cstr_to_str(license_key) }.inspect_err(|_| {
            crate::set_last_error(
                "tamga_hkdf_derive_license_file_key: license_key is null or not valid UTF-8",
            );
        })?;

        let key = tamga_rust::crypto::hkdf::derive_license_file_key(license_key_str);

        // SAFETY: caller contract requires `out_32_bytes` to point to at
        // least 32 writable bytes; checked non-null above.
        unsafe {
            slice::from_raw_parts_mut(out_32_bytes, 32).copy_from_slice(&key[..]);
        }
        Ok(())
    })
}
