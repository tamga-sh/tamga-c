//! `tamga_machine_file_verify` / `_get_json` / `_free` — Section D of
//! `docs/plans/tamga-c.plan.md` ("Machine Checkout FFI").
//!
//! # STUB — scaffolding only
//!
//! Every function below always returns
//! [`TamgaErrorCode::TAMGA_ERR_UNKNOWN`] and is `TODO`-marked to receive
//! the `catch_unwind` treatment described in [`crate::ffi_guard`]'s docs
//! (reference implementation:
//! [`crate::license_file::tamga_license_file_verify`]).
//!
//! # Machine file format (from `docs/sdk.md` §6 / plan §3.2)
//!
//! Same `{enc, sig, alg}` inner JSON shape as license files, wrapped in
//! `-----BEGIN MACHINE FILE-----` / `-----END MACHINE FILE-----` (distinct
//! wrapper text — do not reuse the license-file marker constants).
//!
//! - Signing scheme is the **license's** `scheme` field
//!   (`ED25519_SIGN` / `RSA_2048_PKCS1_SIGN` / `RSA_2048_PKCS1_PSS_SIGN` /
//!   `ECDSA_P256_SIGN`), **not hardcoded to Ed25519** like license-file
//!   checkout. `RSA_2048_JWT_RS256` is explicitly rejected — the server
//!   itself rejects this scheme for machine-file checkout (`422
//!   SCHEME_NOT_SUPPORTED`); the verifier must mirror that rejection
//!   rather than attempt JWT verification.
//! - Encryption key (when `alg` contains `"aes-256-gcm"`) is **properly
//!   HKDF-SHA256 derived** — unlike license-file checkout's naive
//!   zero-pad/truncate: `salt = "tamga:machine-file-key-v1"`,
//!   `ikm = <license key>`, `info = <machine fingerprint>` → 32-byte AES
//!   key (see [`crate::kdf::tamga_hkdf_derive_machine_file_key`]). Needs
//!   **both** the license key and the target machine's fingerprint to
//!   decrypt.

use std::ffi::c_char;

use crate::{TamgaErrorCode, TamgaMachineFile, TamgaScheme};
// NOTE: `ffi_guard` is not yet imported/used here on purpose — this file's
// functions are TODO-marked to adopt it (see module docs above); importing
// it unused would just trade one clippy warning for another.

/// Verifies and decodes a machine file, dispatching the signature algorithm
/// from `scheme` (the license's `scheme` field — not hardcoded).
///
/// # Parameters
/// - `pem` / `pem_len`: the raw machine-file bytes, PEM markers included.
/// - `scheme`: the license's signing scheme. `TAMGA_SCHEME_RSA_2048_JWT_RS256`
///   is always rejected with `TAMGA_ERR_UNSUPPORTED_SCHEME`.
/// - `pubkey` / `pubkey_len`: the public key matching `scheme` (Ed25519: 32
///   bytes; RSA-2048: DER-encoded `SubjectPublicKeyInfo` or equivalent,
///   exact encoding TBD pending tamga-rust's frozen API; ECDSA P-256:
///   uncompressed point or DER, same caveat).
/// - `license_key` / `fingerprint`: required only to decrypt an encrypted
///   (`aes-256-gcm`) machine file; ignored for plain files. Both are
///   NUL-terminated C strings.
/// - `out_handle`: on `TAMGA_OK`, receives an owned [`TamgaMachineFile`]
///   handle; free it with [`tamga_machine_file_free`] exactly once.
///
/// # Safety
/// `pem`/`pubkey` must point to their declared lengths of readable bytes
/// (or be null). `license_key`/`fingerprint` must be null or valid
/// NUL-terminated C strings. `out_handle` must be a valid pointer this
/// function may write to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_machine_file_verify(
    pem: *const c_char,
    pem_len: usize,
    scheme: TamgaScheme,
    pubkey: *const u8,
    pubkey_len: usize,
    license_key: *const c_char,
    fingerprint: *const c_char,
    out_handle: *mut *mut TamgaMachineFile,
) -> TamgaErrorCode {
    // TODO(Section F): wrap this body in `ffi_guard`/`catch_unwind` like
    // `tamga_license_file_verify`. Left un-guarded intentionally for now so
    // this stub's shape stays visibly "not yet done" rather than silently
    // matching the reference pattern without the real logic behind it.
    //
    // TODO(Section D): implement once tamga-rust's v0.1 API is frozen:
    //   1. null-check pem / pubkey / out_handle
    //   2. strip "-----BEGIN MACHINE FILE-----" / "-----END MACHINE
    //      FILE-----" markers
    //   3. base64-decode + parse the {enc, sig, alg} JSON
    //   4. reject TAMGA_SCHEME_RSA_2048_JWT_RS256 outright
    //      (TAMGA_ERR_UNSUPPORTED_SCHEME) -- never attempt JWT verification
    //   5. dispatch the verify algorithm from `scheme`:
    //      Ed25519 (same base64-string-not-decoded-bytes convention as
    //      license files), RSA-2048 PKCS#1 v1.5/SHA-256, RSA-2048 PKCS#1
    //      PSS/SHA-256, or ECDSA P-256/SHA-256
    //   6. if alg contains "aes-256-gcm": require both license_key and
    //      fingerprint non-null, derive the key via
    //      kdf::tamga_hkdf_derive_machine_file_key, AES-256-GCM-open
    //   7. parse the resulting plaintext as {"data": <MachineResource>}
    //      JSON
    //   8. box the decoded payload behind `*out_handle`
    let _ = (
        pem,
        pem_len,
        scheme,
        pubkey,
        pubkey_len,
        license_key,
        fingerprint,
        out_handle,
    );
    crate::set_last_error(
        "tamga_machine_file_verify is not implemented yet (see docs/plans/tamga-c.plan.md Section D)",
    );
    TamgaErrorCode::TAMGA_ERR_UNKNOWN
}

/// Exposes the decoded `MachineResource` as an owned JSON C string.
///
/// # Safety
/// Same contract as [`crate::license_file::tamga_license_file_get_json`],
/// scoped to [`TamgaMachineFile`] handles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_machine_file_get_json(
    handle: *const TamgaMachineFile,
    out_ptr: *mut *mut c_char,
    out_len: *mut usize,
) -> TamgaErrorCode {
    // TODO(Section F): wrap in `ffi_guard`/`catch_unwind`. Not yet done.
    let _ = (handle, out_ptr, out_len);
    TamgaErrorCode::TAMGA_ERR_UNKNOWN
}

/// Frees a [`TamgaMachineFile`] handle obtained from
/// [`tamga_machine_file_verify`].
///
/// # Safety
/// Same contract as
/// [`crate::license_file::tamga_license_file_free`], scoped to
/// [`TamgaMachineFile`] handles. Double-free is documented undefined
/// behavior and intentionally unguarded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_machine_file_free(handle: *mut TamgaMachineFile) {
    // TODO(Section F): wrap in `ffi_guard`/`catch_unwind`, null-check, and
    // `Box::from_raw` + drop the real payload once TamgaMachineFile has
    // one. Currently a no-op.
    let _ = handle;
}
