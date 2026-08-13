//! `tamga_machine_file_verify` / `_get_json` / `_free` — Section D of
//! `docs/plans/tamga-c.plan.md` ("Machine Checkout FFI").
//!
//! Thin FFI marshalling layer over `tamga-rust`'s already security-reviewed
//! `checkout::machine_file::verify_machine_file` — no cryptographic logic
//! is reimplemented here, same shape as `src/license_file.rs`.
//!
//! # Machine file format (from `docs/sdk.md` §6 / plan §3.2)
//!
//! Same `{enc, sig, alg}` inner JSON shape as license files, wrapped in
//! `-----BEGIN MACHINE FILE-----` / `-----END MACHINE FILE-----` (distinct
//! wrapper text from license files).
//!
//! - Signing scheme is the **license's** `scheme` field
//!   (`ED25519_SIGN` / `RSA_2048_PKCS1_SIGN` / `RSA_2048_PKCS1_PSS_SIGN` /
//!   `ECDSA_P256_SIGN`), **not hardcoded to Ed25519** like license-file
//!   checkout. `RSA_2048_JWT_RS256` is explicitly rejected — the server
//!   itself rejects this scheme for machine-file checkout (`422
//!   SCHEME_NOT_SUPPORTED`); `tamga-rust`'s verifier mirrors that rejection
//!   rather than attempting JWT verification, and `TAMGA_SCHEME_NONE` (no
//!   `LicenseScheme` equivalent — that C enum value only makes sense for a
//!   legacy unsigned *license key*, not a machine file) is rejected the
//!   same way at this FFI layer before ever reaching `tamga-rust`.
//! - Encryption key (when `alg` contains `"aes-256-gcm"`) is **properly
//!   HKDF-SHA256 derived** — unlike license-file checkout's naive
//!   zero-pad/truncate: `salt = "tamga:machine-file-key-v1"`,
//!   `ikm = <license key>`, `info = <machine fingerprint>` → 32-byte AES
//!   key (see [`crate::kdf::tamga_hkdf_derive_machine_file_key`]). Needs
//!   **both** the license key and the target machine's fingerprint to
//!   decrypt.

use std::ffi::{CString, c_char};
use std::slice;

use crate::{TamgaErrorCode, TamgaMachineFile, TamgaScheme, ffi_guard};

/// Internal handle payload behind the opaque [`TamgaMachineFile`] pointer —
/// same pattern as `license_file::LicenseFileHandle`.
struct MachineFileHandle {
    json: String,
}

/// Maps the C-facing [`TamgaScheme`] to `tamga-rust`'s
/// [`tamga_rust::models::policy::LicenseScheme`]. `TAMGA_SCHEME_NONE` has no
/// equivalent — it only makes sense for a legacy unsigned *license key*, not
/// a machine file — so it's rejected here rather than reaching
/// `verify_machine_file` at all.
///
/// Takes an already-validated [`TamgaScheme`] (never a raw `u32`) — see
/// [`TamgaScheme::from_raw`]'s doc comment for why accepting the enum type
/// itself directly from a C caller would be undefined behavior.
fn map_scheme(scheme: TamgaScheme) -> Result<tamga_rust::models::policy::LicenseScheme, ()> {
    use tamga_rust::models::policy::LicenseScheme;
    match scheme {
        TamgaScheme::TAMGA_SCHEME_NONE => Err(()),
        TamgaScheme::TAMGA_SCHEME_ED25519_SIGN => Ok(LicenseScheme::Ed25519Sign),
        TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_SIGN => Ok(LicenseScheme::Rsa2048Pkcs1Sign),
        TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN => Ok(LicenseScheme::Rsa2048Pkcs1PssSign),
        TamgaScheme::TAMGA_SCHEME_ECDSA_P256_SIGN => Ok(LicenseScheme::EcdsaP256Sign),
        // Passed through deliberately, not rejected here — verify_machine_file
        // itself rejects this scheme up front (defense in depth: the
        // rejection lives in the one place the plan's security review
        // already covered, rather than being duplicated at this FFI layer).
        TamgaScheme::TAMGA_SCHEME_RSA_2048_JWT_RS256 => Ok(LicenseScheme::Rsa2048JwtRs256),
    }
}

/// Converts a `checkout` verification failure into the matching
/// [`TamgaErrorCode`] and records the detailed message via
/// [`crate::set_last_error`]. Identical dispatch table to
/// `license_file::map_checkout_error` — kept as a separate copy rather than
/// shared, since the two modules' error-message prefixes differ and a
/// shared helper would need to take the prefix as a parameter for no real
/// benefit at this size.
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
        // Machine files carry no `exp` claim today, so this is unreachable
        // here — mapped rather than left to a catch-all so that adding one
        // later cannot silently report it as an unknown failure.
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

/// Verifies and decodes a machine file, dispatching the signature algorithm
/// from `scheme` (the license's `scheme` field — not hardcoded).
///
/// # Parameters
/// - `pem` / `pem_len`: the raw machine-file bytes, PEM markers included.
/// - `scheme`: a raw [`TamgaScheme`] discriminant (**not** the enum type
///   itself — see [`TamgaScheme::from_raw`]'s doc comment for why accepting
///   `TamgaScheme` by value directly from a C caller would be undefined
///   behavior; this function validates the value before using it). Any
///   value outside the declared range, `TAMGA_SCHEME_RSA_2048_JWT_RS256`,
///   and `TAMGA_SCHEME_NONE` are all rejected with
///   `TAMGA_ERR_UNSUPPORTED_SCHEME`.
/// - `pubkey` / `pubkey_len`: the public key matching `scheme` (Ed25519: 32
///   bytes; RSA-2048: a `SubjectPublicKeyInfo` DER blob for either RSA
///   variant; ECDSA P-256: a 65-byte uncompressed point).
/// - `license_key` / `fingerprint`: required only to decrypt an encrypted
///   (`aes-256-gcm`) machine file; ignored for plain files. Both are
///   NUL-terminated C strings, nullable.
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
    scheme: u32,
    pubkey: *const u8,
    pubkey_len: usize,
    license_key: *const c_char,
    fingerprint: *const c_char,
    out_handle: *mut *mut TamgaMachineFile,
) -> TamgaErrorCode {
    ffi_guard(|| {
        if pem.is_null() || pubkey.is_null() || out_handle.is_null() {
            crate::set_last_error("tamga_machine_file_verify: null argument");
            return Err(TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
        }
        if pem_len == 0
            || pem_len > crate::MAX_REASONABLE_LEN
            || pubkey_len == 0
            || pubkey_len > crate::MAX_REASONABLE_LEN
        {
            crate::set_last_error("tamga_machine_file_verify: length out of reasonable range");
            return Err(TamgaErrorCode::TAMGA_ERR_LENGTH_INVALID);
        }

        let scheme = TamgaScheme::from_raw(scheme).ok_or_else(|| {
            crate::set_last_error("tamga_machine_file_verify: scheme is not a recognized value");
            TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME
        })?;
        let scheme_rust = map_scheme(scheme).map_err(|()| {
            crate::set_last_error(
                "tamga_machine_file_verify: TAMGA_SCHEME_NONE has no machine-file equivalent",
            );
            TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME
        })?;

        // SAFETY: caller contract guarantees `pem` points to `pem_len`
        // readable bytes.
        let pem_bytes = unsafe { slice::from_raw_parts(pem as *const u8, pem_len) };
        let pem_str = std::str::from_utf8(pem_bytes).map_err(|_| {
            crate::set_last_error("tamga_machine_file_verify: pem is not valid UTF-8");
            TamgaErrorCode::TAMGA_ERR_INVALID_PEM
        })?;

        // SAFETY: caller contract guarantees `pubkey` points to `pubkey_len`
        // readable bytes.
        let pubkey_bytes = unsafe { slice::from_raw_parts(pubkey, pubkey_len) };

        let license_key_str = if license_key.is_null() {
            None
        } else {
            // SAFETY: caller contract guarantees a valid NUL-terminated C
            // string when non-null.
            Some(unsafe { crate::cstr_to_str(license_key) }.inspect_err(|_| {
                crate::set_last_error("tamga_machine_file_verify: license_key is not valid UTF-8");
            })?)
        };
        let fingerprint_str = if fingerprint.is_null() {
            None
        } else {
            // SAFETY: caller contract guarantees a valid NUL-terminated C
            // string when non-null.
            Some(unsafe { crate::cstr_to_str(fingerprint) }.inspect_err(|_| {
                crate::set_last_error("tamga_machine_file_verify: fingerprint is not valid UTF-8");
            })?)
        };

        let machine = tamga_rust::checkout::machine_file::verify_machine_file(
            pem_str,
            scheme_rust,
            pubkey_bytes,
            license_key_str,
            fingerprint_str,
        )
        .map_err(map_checkout_error)?;

        let json = serde_json::to_string(&machine).map_err(|e| {
            crate::set_last_error(format!(
                "tamga_machine_file_verify: failed to serialize decoded machine: {e}"
            ));
            TamgaErrorCode::TAMGA_ERR_INVALID_JSON
        })?;

        let handle = Box::new(MachineFileHandle { json });
        // SAFETY: `out_handle` is non-null (checked above) and, per the
        // caller contract, a valid pointer this function may write to.
        unsafe {
            *out_handle = Box::into_raw(handle) as *mut TamgaMachineFile;
        }
        Ok(())
    })
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
    ffi_guard(|| {
        if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
            crate::set_last_error("tamga_machine_file_get_json: null argument");
            return Err(TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
        }
        // SAFETY: caller contract requires `handle` to be a live pointer
        // previously returned by `tamga_machine_file_verify`.
        let handle = unsafe { &*(handle as *const MachineFileHandle) };
        let cstring = CString::new(handle.json.clone()).map_err(|_| {
            crate::set_last_error(
                "tamga_machine_file_get_json: decoded JSON contained an interior NUL byte",
            );
            TamgaErrorCode::TAMGA_ERR_UNKNOWN
        })?;
        let len = cstring.as_bytes().len();
        // SAFETY: `out_ptr`/`out_len` are non-null (checked above) and, per
        // the caller contract, valid pointers this function may write to.
        unsafe {
            *out_ptr = cstring.into_raw();
            *out_len = len;
        }
        Ok(())
    })
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
    crate::ffi_guard_void(|| {
        if handle.is_null() {
            return;
        }
        // SAFETY: caller contract (documented above) requires `handle` to
        // be a live pointer previously returned by
        // `tamga_machine_file_verify` and not already freed.
        drop(unsafe { Box::from_raw(handle as *mut MachineFileHandle) });
    })
}
