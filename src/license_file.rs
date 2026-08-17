//! `tamga_license_file_verify` / `_get_json` / `_free` — the license-file
//! FFI surface.
//!
//! This module is a thin FFI marshalling layer over `tamga-rust`'s already
//! security-reviewed `checkout::license_file::verify_license_file` — no
//! cryptographic logic is reimplemented here. The base64-string-vs-decoded-
//! bytes gotcha and the HKDF-SHA256 key derivation both live (and are tested)
//! on the `tamga-rust` side; see that crate's `src/checkout/license_file.rs`
//! and `src/crypto/hkdf.rs`.
//!
//! # `.lic` file format
//!
//! ```text
//! -----BEGIN LICENSE FILE-----
//! <base64 of JSON: { "enc": "<base64>", "sig": "<base64 ed25519 sig over enc's UTF-8 bytes>", "alg": "<algorithm string>" }>
//! -----END LICENSE FILE-----
//! ```
//!
//! `alg` is exactly `"base64+ed25519+v2"` (plain) or
//! `"aes-256-gcm+ed25519+v2"` (encrypted) — Ed25519 only, independent of the
//! license's own key `scheme` field.
//!
//! # Offline format v2 — v1 files are refused, with no fallback
//!
//! ⚠️ A file whose `alg` does not end in `+v2` is rejected with
//! [`TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME`]. In v1 the requested
//! `ttl`/`expiry` lived only in the JSON:API envelope *around* the
//! certificate, never inside the signed bytes, so a 24-hour trial file was
//! cryptographically valid forever — the client is the attacker, and any
//! check built on the envelope is bypassed by keeping the raw certificate.
//! v2 moves those claims (`iat`, `exp`, `jti`, `kid`) inside the signature,
//! and accepting both formats would hand that back. Callers holding v1 `.lic`
//! files must check out fresh ones; this is a behavioral break, not a
//! deprecation.
//!
//! `exp` is enforced by `tamga-rust` with a 60-second clock-skew tolerance
//! and surfaced here as the dedicated
//! [`TamgaErrorCode::TAMGA_ERR_EXPIRED`] code, so callers can distinguish an
//! authentic-but-expired file from a forged one.
//!
//! # The `license_key` parameter
//!
//! `tamga-rust`'s `verify_license_file` takes `license_key: Option<&str>` to
//! decrypt an **encrypted** (`aes-256-gcm+ed25519+v2`) file, so this FFI
//! entry point carries a nullable `license_key: *const c_char` alongside the
//! PEM and public key. It is required only for encrypted files and ignored
//! for plain ones.

use std::ffi::{CString, c_char};
use std::slice;

use crate::{TamgaErrorCode, TamgaLicenseFile, ffi_guard};

/// Internal handle payload behind the opaque [`TamgaLicenseFile`] pointer.
/// Not `#[repr(C)]`, never exposed to cbindgen — callers only ever see the
/// zero-sized `TamgaLicenseFile` tag type via an opaque pointer they must
/// treat as unintrospectable.
struct LicenseFileHandle {
    /// The decoded `LicenseResource`, pre-serialized to JSON at verify time
    /// so [`tamga_license_file_get_json`] never needs to re-derive it (or
    /// hold a borrow across the FFI boundary).
    json: String,
}

/// Converts a `checkout` verification failure into the matching
/// [`TamgaErrorCode`] and records the detailed message via
/// [`crate::set_last_error`].
fn map_checkout_error(err: tamga_rust::error::CheckoutError) -> TamgaErrorCode {
    use tamga_rust::error::{CheckoutError, CryptoError};
    let code = match &err {
        CheckoutError::MalformedPem => TamgaErrorCode::TAMGA_ERR_INVALID_PEM,
        CheckoutError::InvalidBase64 => TamgaErrorCode::TAMGA_ERR_INVALID_BASE64,
        CheckoutError::InvalidJson(_) => TamgaErrorCode::TAMGA_ERR_INVALID_JSON,
        CheckoutError::UnsupportedAlgorithm(_) => TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME,
        CheckoutError::LicenseKeyMissing | CheckoutError::FingerprintMissing => {
            TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT
        }
        CheckoutError::SchemeNotSupported => TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME,
        CheckoutError::TtlOutOfRange(_) => TamgaErrorCode::TAMGA_ERR_UNKNOWN,
        CheckoutError::Expired { .. } => TamgaErrorCode::TAMGA_ERR_EXPIRED,
        CheckoutError::Crypto(CryptoError::VerificationFailed) => {
            TamgaErrorCode::TAMGA_ERR_SIGNATURE_INVALID
        }
        CheckoutError::Crypto(CryptoError::DecryptionFailed) => {
            TamgaErrorCode::TAMGA_ERR_DECRYPTION_FAILED
        }
        CheckoutError::Crypto(CryptoError::InvalidKey | CryptoError::InvalidSignature) => {
            TamgaErrorCode::TAMGA_ERR_SIGNATURE_INVALID
        }
    };
    crate::set_last_error(err.to_string());
    code
}

/// Verifies and decodes a `.lic` license file, fully offline, by delegating
/// to `tamga-rust`'s `checkout::license_file::verify_license_file`.
///
/// The file must be offline format v2 (`alg` ending in `+v2`); v1 files are
/// rejected with `TAMGA_ERR_UNSUPPORTED_SCHEME` and there is no fallback
/// path. The signed `exp` claim is enforced (60-second clock-skew tolerance)
/// and reported as `TAMGA_ERR_EXPIRED`. See this module's doc comment.
///
/// # Parameters
/// - `pem` / `pem_len`: the raw `.lic` file bytes, PEM markers included.
///   Need not be NUL-terminated; `pem_len` is authoritative.
/// - `ed25519_pubkey`: the account's 32-byte Ed25519 public key.
/// - `license_key`: NUL-terminated C string, or null. Required (non-null)
///   only when the file's `alg` is `"aes-256-gcm+ed25519+v2"` (encrypted);
///   ignored for `"base64+ed25519+v2"` (plain) files.
/// - `out_handle`: on `TAMGA_OK`, receives an owned [`TamgaLicenseFile`]
///   handle; free it with [`tamga_license_file_free`] exactly once.
///
/// # Safety
/// `pem` must point to `pem_len` readable bytes (or be null, checked
/// internally). `ed25519_pubkey` must point to 32 readable bytes (or be
/// null). `license_key`, if non-null, must be a valid NUL-terminated C
/// string. `out_handle` must be a valid pointer to a `*mut TamgaLicenseFile`
/// that this function may write to.
///
/// This is the canonical `catch_unwind` reference implementation described
/// in [`crate::ffi_guard`]'s docs — every other `extern "C" fn` in this
/// crate copies this shape, because unwinding a Rust panic across an
/// `extern "C"` boundary is undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_license_file_verify(
    pem: *const c_char,
    pem_len: usize,
    ed25519_pubkey: *const u8,
    license_key: *const c_char,
    out_handle: *mut *mut TamgaLicenseFile,
) -> TamgaErrorCode {
    ffi_guard(|| {
        if pem.is_null() || ed25519_pubkey.is_null() || out_handle.is_null() {
            crate::set_last_error("tamga_license_file_verify: null argument");
            return Err(TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
        }
        if pem_len == 0 || pem_len > crate::MAX_REASONABLE_LEN {
            crate::set_last_error("tamga_license_file_verify: pem_len out of reasonable range");
            return Err(TamgaErrorCode::TAMGA_ERR_LENGTH_INVALID);
        }

        // SAFETY: caller contract (see this function's `# Safety` section)
        // guarantees `pem` points to `pem_len` readable bytes.
        let pem_bytes = unsafe { slice::from_raw_parts(pem as *const u8, pem_len) };
        let pem_str = std::str::from_utf8(pem_bytes).map_err(|_| {
            crate::set_last_error("tamga_license_file_verify: pem is not valid UTF-8");
            TamgaErrorCode::TAMGA_ERR_INVALID_PEM
        })?;

        // SAFETY: caller contract guarantees 32 readable bytes.
        let pubkey: [u8; 32] = unsafe { slice::from_raw_parts(ed25519_pubkey, 32) }
            .try_into()
            .expect("slice::from_raw_parts(_, 32) is always exactly 32 bytes");

        let license_key_str = if license_key.is_null() {
            None
        } else {
            // SAFETY: caller contract guarantees a valid NUL-terminated
            // C string when non-null.
            Some(unsafe { crate::cstr_to_str(license_key) }.inspect_err(|_| {
                crate::set_last_error("tamga_license_file_verify: license_key is not valid UTF-8");
            })?)
        };

        let license = tamga_rust::checkout::license_file::verify_license_file(
            pem_str,
            &pubkey,
            license_key_str,
        )
        .map_err(map_checkout_error)?;

        let json = serde_json::to_string(&license).map_err(|e| {
            crate::set_last_error(format!(
                "tamga_license_file_verify: failed to serialize decoded license: {e}"
            ));
            TamgaErrorCode::TAMGA_ERR_INVALID_JSON
        })?;

        let handle = Box::new(LicenseFileHandle { json });
        // SAFETY: `out_handle` is non-null (checked above) and, per the
        // caller contract, a valid pointer this function may write to.
        unsafe {
            *out_handle = Box::into_raw(handle) as *mut TamgaLicenseFile;
        }
        Ok(())
    })
}

/// Exposes the decoded `LicenseResource` as an owned JSON C string.
///
/// # Safety
/// `handle` must be a live pointer previously returned by
/// [`tamga_license_file_verify`]. `out_ptr`/`out_len` must be valid
/// pointers this function may write to. The string written to `*out_ptr`
/// is owned by the caller; free it with [`crate::tamga_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_license_file_get_json(
    handle: *const TamgaLicenseFile,
    out_ptr: *mut *mut c_char,
    out_len: *mut usize,
) -> TamgaErrorCode {
    ffi_guard(|| {
        if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
            crate::set_last_error("tamga_license_file_get_json: null argument");
            return Err(TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
        }
        // SAFETY: caller contract requires `handle` to be a live pointer
        // previously returned by `tamga_license_file_verify`.
        let handle = unsafe { &*(handle as *const LicenseFileHandle) };
        let cstring = CString::new(handle.json.clone()).map_err(|_| {
            crate::set_last_error(
                "tamga_license_file_get_json: decoded JSON contained an interior NUL byte",
            );
            TamgaErrorCode::TAMGA_ERR_UNKNOWN
        })?;
        let len = cstring.as_bytes().len();
        // SAFETY: `out_ptr`/`out_len` are non-null (checked above) and,
        // per the caller contract, valid pointers this function may write
        // to.
        unsafe {
            *out_ptr = cstring.into_raw();
            *out_len = len;
        }
        Ok(())
    })
}

/// Frees a [`TamgaLicenseFile`] handle obtained from
/// [`tamga_license_file_verify`].
///
/// # Safety
/// `handle` must be null, or a live pointer previously returned by
/// [`tamga_license_file_verify`] and not already freed. Double-free is
/// documented undefined behavior and intentionally unguarded — see
/// CLAUDE.md and `crate::tamga_string_free`'s docs for the same policy
/// applied to strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_license_file_free(handle: *mut TamgaLicenseFile) {
    crate::ffi_guard_void(|| {
        if handle.is_null() {
            return;
        }
        // SAFETY: caller contract (documented above) requires `handle` to
        // be a live pointer previously returned by
        // `tamga_license_file_verify` and not already freed.
        drop(unsafe { Box::from_raw(handle as *mut LicenseFileHandle) });
    })
}
