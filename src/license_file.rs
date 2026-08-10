//! `tamga_license_file_verify` / `_get_json` / `_free` — Section C of
//! `docs/plans/tamga-c.plan.md` ("License Checkout FFI").
//!
//! # STUB — scaffolding only
//!
//! [`tamga_license_file_verify`] is the canonical `catch_unwind` reference
//! implementation (see [`crate::ffi_guard`]'s docs) — every other `extern
//! "C" fn` in this crate copies its shape once implemented. Its body
//! currently always returns [`TamgaErrorCode::TAMGA_ERR_UNKNOWN`] rather
//! than doing real work; [`tamga_license_file_get_json`] and
//! [`tamga_license_file_free`] are `TODO`-marked and don't even use
//! `ffi_guard` yet.
//!
//! # `.lic` file format (from `docs/sdk.md` §4 / plan §3.1)
//!
//! ```text
//! -----BEGIN LICENSE FILE-----
//! <base64 of JSON: { "enc": "<base64>", "sig": "<base64 ed25519 sig over enc's UTF-8 bytes>", "alg": "<algorithm string>" }>
//! -----END LICENSE FILE-----
//! ```
//!
//! - `alg` is exactly `"base64+ed25519"` (plain) or `"aes-256-gcm+ed25519"`
//!   (encrypted) — **Ed25519 only**, independent of the license's own key
//!   `scheme` field. Any other value is `TAMGA_ERR_UNSUPPORTED_SCHEME`.
//! - `enc` (plain): `base64(payload_json)`, `payload_json = {"data": <LicenseResource>}`.
//! - `enc` (encrypted): `base64(nonce(12B) ‖ ciphertext ‖ tag(16B))`, AES-256-GCM.
//! - ⚠️ Key derivation is **not a KDF**: `license.key`'s raw UTF-8 bytes,
//!   zero-padded/truncated to exactly 32 bytes (see [`crate::kdf`]).
//! - ⚠️ **The single most common implementation mistake in this format**:
//!   the signature is computed over `enc`'s base64 **string** — its
//!   ASCII/UTF-8 bytes as text — NOT the bytes you get from base64-decoding
//!   it. Get this backwards and every file silently fails verification.
//!   Verify the signature *before* base64-decoding `enc` at all.

use std::ffi::c_char;

use crate::{TamgaErrorCode, TamgaLicenseFile, ffi_guard};

/// Verifies and decodes a `.lic` license file.
///
/// # Parameters
/// - `pem` / `pem_len`: the raw `.lic` file bytes, PEM markers included.
/// - `ed25519_pubkey`: the account's 32-byte Ed25519 public key.
/// - `out_handle`: on `TAMGA_OK`, receives an owned [`TamgaLicenseFile`]
///   handle; free it with [`tamga_license_file_free`] exactly once.
///
/// # Safety
/// `pem` must point to `pem_len` readable bytes (or be null, checked
/// internally). `ed25519_pubkey` must point to 32 readable bytes (or be
/// null). `out_handle` must be a valid pointer to a `*mut TamgaLicenseFile`
/// that this function may write to.
///
/// This is the canonical `catch_unwind` reference implementation described
/// in [`crate::ffi_guard`]'s docs — every other `extern "C" fn` in this
/// crate MUST copy this shape once implemented (Section F; unwinding a Rust
/// panic across an `extern "C"` boundary is undefined behavior).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_license_file_verify(
    pem: *const c_char,
    pem_len: usize,
    ed25519_pubkey: *const u8,
    out_handle: *mut *mut TamgaLicenseFile,
) -> TamgaErrorCode {
    ffi_guard(|| {
        // TODO(Section C): implement the real verify flow once tamga-rust's
        // v0.1 API is frozen (exact upstream signature TBD, see this repo's
        // BLOCKED banner):
        //   1. null-check pem / ed25519_pubkey / out_handle
        //      (TAMGA_ERR_NULL_ARGUMENT)
        //   2. strip "-----BEGIN LICENSE FILE-----" / "-----END LICENSE
        //      FILE-----" markers (TAMGA_ERR_INVALID_PEM on mismatch)
        //   3. base64-decode the PEM body -> {enc, sig, alg} JSON
        //      (TAMGA_ERR_INVALID_BASE64 / TAMGA_ERR_INVALID_JSON)
        //   4. validate alg is exactly "base64+ed25519" or
        //      "aes-256-gcm+ed25519" (TAMGA_ERR_UNSUPPORTED_SCHEME
        //      otherwise — this format is Ed25519-only regardless of the
        //      license's own `scheme` field)
        //   5. base64-decode `sig` to the raw 64-byte signature
        //   6. Ed25519-verify `sig` against `enc`'s ASCII/UTF-8 STRING
        //      bytes -- NOT its base64-decoded bytes (see module docs
        //      above). TAMGA_ERR_SIGNATURE_INVALID on failure.
        //   7. only AFTER the signature check passes, base64-decode `enc`
        //      itself
        //   8. if alg contains "aes-256-gcm": split nonce(12B) / ciphertext
        //      / tag(16B), derive the AES key via
        //      kdf::naive_derive_license_file_key, AES-256-GCM-open
        //      (TAMGA_ERR_DECRYPTION_FAILED on failure)
        //   9. parse the resulting plaintext (or the plain base64-decoded
        //      `enc` bytes when alg == "base64+ed25519") as
        //      {"data": <LicenseResource>} JSON (TAMGA_ERR_INVALID_JSON)
        //  10. box the decoded payload behind `*out_handle`
        let _ = (pem, pem_len, ed25519_pubkey, out_handle);
        crate::set_last_error(
            "tamga_license_file_verify is not implemented yet (see docs/plans/tamga-c.plan.md Section C)",
        );
        Err(TamgaErrorCode::TAMGA_ERR_UNKNOWN)
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
    // TODO(Section F): wrap this body in `ffi_guard`/`catch_unwind` like
    // `tamga_license_file_verify` above — not yet done here, tracked
    // explicitly per the plan's "TODO-mark every remaining extern C fn"
    // instruction. Do not ship this function without it.
    let _ = (handle, out_ptr, out_len);
    TamgaErrorCode::TAMGA_ERR_UNKNOWN
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
    // TODO(Section F): wrap in `ffi_guard`/`catch_unwind`, null-check, and
    // `Box::from_raw` + drop the real payload once TamgaLicenseFile has
    // one. Currently a no-op since the handle is a genuinely zero-sized
    // opaque type with nothing behind it yet.
    let _ = handle;
}
