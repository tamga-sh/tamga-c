//! `tamga-c`: C ABI bindings for the Tamga licensing SDK.
//!
//! Exposes `tamga-rust`'s offline-verification primitives through a stable
//! C ABI (`cdylib` + `staticlib` + a committed `include/tamga.h`), so C/C++
//! applications, `tamga-java` (via JNI), and `tamga-swift` (via a Swift/ObjC
//! bridge) can all call into one audited crypto core instead of each
//! re-implementing signature verification.
//!
//! **This is NOT an HTTP client.** There is no auth-transport, `validate`,
//! `check-in`, or machine-management surface here — see README.md and
//! `docs/plans/tamga-c.plan.md` Section 3.4 ("Out of scope for this repo").
//! The entire surface is four offline, deterministic crypto operations:
//!
//! 1. Verify (and decode) a `.lic` license file — [`license_file`].
//! 2. Verify (and decode) a machine file, across 4 signing schemes — [`machine_file`].
//! 3. Verify — and, for air-gapped tooling, generate — a machine offline proof — [`offline_proof`].
//! 4. Derive the two AES keys those file formats depend on — [`kdf`].
//!
//! # STUB — scaffolding only
//!
//! Every `extern "C" fn` in this crate and its submodules currently returns
//! [`TamgaErrorCode::TAMGA_ERR_UNKNOWN`] (or is left as a bare signature)
//! rather than doing real work. This crate is blocked on `tamga-rust`'s
//! public API being frozen — see the plan's top-of-file banner. Real
//! implementation is deferred to a future session per
//! `docs/plans/tamga-c.plan.md` Sections C–F.
//!
//! # The `catch_unwind` rule
//!
//! Every `pub extern "C" fn` in this crate MUST wrap its body in
//! [`std::panic::catch_unwind`] (via the [`ffi_guard`] helper below),
//! converting a caught panic into [`TamgaErrorCode::TAMGA_ERR_PANIC`] plus a
//! last-error message instead of unwinding across the FFI boundary —
//! unwinding a Rust panic into C is undefined behavior. [`license_file::tamga_license_file_verify`]
//! is the canonical reference implementation of this pattern; every other
//! FFI entry point is `TODO`-marked until it copies the same shape (Section
//! F of the plan — `security-reviewer` is mandatory on that section before
//! merge).

#![allow(dead_code)] // TODO: remove once Sections C–F wire these up for real.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{self, AssertUnwindSafe};

pub mod kdf;
pub mod license_file;
pub mod machine_file;
pub mod offline_proof;

/// Error codes returned by every `tamga_*` FFI function.
///
/// `TAMGA_OK` (0) means success; every other value has a corresponding
/// detailed message retrievable via [`tamga_last_error_message`] on the
/// calling thread.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)] // deliberate: matches the C-side SCREAMING_SNAKE_CASE convention cbindgen emits into tamga.h.
pub enum TamgaErrorCode {
    /// Success.
    TAMGA_OK = 0,
    /// `-----BEGIN ...-----`/`-----END ...-----` PEM markers missing or malformed.
    TAMGA_ERR_INVALID_PEM = 1,
    /// A base64-encoded field failed to decode.
    TAMGA_ERR_INVALID_BASE64 = 2,
    /// Decoded bytes were not valid JSON, or didn't match the expected shape.
    TAMGA_ERR_INVALID_JSON = 3,
    /// Signature verification failed (wrong key, tampered payload, or the
    /// base64-string-vs-decoded-bytes gotcha — see CLAUDE.md).
    TAMGA_ERR_SIGNATURE_INVALID = 4,
    /// AES-256-GCM open failed (wrong key/nonce, or tampered ciphertext/tag).
    TAMGA_ERR_DECRYPTION_FAILED = 5,
    /// `alg`/`scheme` value not supported by this operation (e.g.
    /// `RSA_2048_JWT_RS256` for machine files, or an unrecognized offline
    /// proof version prefix).
    TAMGA_ERR_UNSUPPORTED_SCHEME = 6,
    /// A required pointer argument was null.
    TAMGA_ERR_NULL_ARGUMENT = 7,
    /// A Rust panic was caught at the FFI boundary via [`ffi_guard`] instead
    /// of unwinding into the caller.
    TAMGA_ERR_PANIC = 8,
    /// Unclassified/internal error — a stub-only value while Sections C–F
    /// are unimplemented (see module docs above); should shrink toward zero
    /// call sites as those sections land.
    TAMGA_ERR_UNKNOWN = 9,
}

/// Signing/key scheme, mirroring the wire `LicenseScheme` strings from
/// `docs/sdk.md` (License Scheme, Section 10). Present for completeness —
/// `TAMGA_SCHEME_RSA_2048_JWT_RS256` is never a legal input for machine
/// files; it must be rejected outright (`422 SCHEME_NOT_SUPPORTED` is what
/// the server itself does for this scheme at machine-file-checkout time).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)] // deliberate: matches the C-side SCREAMING_SNAKE_CASE convention cbindgen emits into tamga.h.
pub enum TamgaScheme {
    /// Legacy unsigned key string (`LicenseScheme::None` server-side).
    TAMGA_SCHEME_NONE = 0,
    TAMGA_SCHEME_ED25519_SIGN = 1,
    TAMGA_SCHEME_RSA_2048_PKCS1_SIGN = 2,
    TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN = 3,
    TAMGA_SCHEME_ECDSA_P256_SIGN = 4,
    /// Explicitly rejected for machine-file verification — see
    /// [`machine_file::tamga_machine_file_verify`].
    TAMGA_SCHEME_RSA_2048_JWT_RS256 = 5,
}

/// Opaque handle wrapping a verified/decoded `.lic` license-file payload.
///
/// Obtained from [`license_file::tamga_license_file_verify`]; must be freed
/// with [`license_file::tamga_license_file_free`] exactly once.
#[repr(C)]
pub struct TamgaLicenseFile {
    _private: [u8; 0],
    // TODO(Section C): the real decoded LicenseResource JSON (or a parsed
    // representation of it) lives here once src/license_file.rs's verify
    // path is implemented. Kept as a genuinely zero-sized opaque type for
    // now so cbindgen emits a valid incomplete-type forward declaration
    // without leaking field layout to C callers ahead of the real design.
}

/// Opaque handle wrapping a verified/decoded machine-file payload.
///
/// Obtained from [`machine_file::tamga_machine_file_verify`]; must be freed
/// with [`machine_file::tamga_machine_file_free`] exactly once.
#[repr(C)]
pub struct TamgaMachineFile {
    _private: [u8; 0],
    // TODO(Section D): see TamgaLicenseFile's TODO — same story, decoded
    // MachineResource JSON instead of LicenseResource.
}

/// Opaque handle for a parsed `v1x0.<sig>` offline proof plus its
/// verification result.
///
/// NOTE: as currently specified in Section E of the plan,
/// [`offline_proof::tamga_offline_proof_verify`] reports its result via an
/// `out_valid: *mut bool` parameter rather than returning a handle, and
/// [`offline_proof::tamga_offline_proof_generate`] returns an owned
/// `*mut c_char` (freed via [`tamga_string_free`]) rather than a handle
/// either. This type is declared per Section B's checklist for forward
/// compatibility but has no current producer/consumer function — there is
/// deliberately no `tamga_offline_proof_free` exported yet. If a
/// handle-returning variant of verify/generate is introduced later, wire
/// this type up then; otherwise remove it before the real Section E lands.
#[repr(C)]
pub struct TamgaOfflineProof {
    _private: [u8; 0],
}

thread_local! {
    /// Last-error message for the calling thread. Cleared at the start of
    /// every [`ffi_guard`]-wrapped call and set on every error path.
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Records `msg` as the calling thread's last-error message. Internal only
/// — call sites are the various `TODO`/error-returning FFI bodies.
pub(crate) fn set_last_error(msg: impl Into<Vec<u8>>) {
    // A message containing an interior NUL can't become a CString; fall
    // back to a fixed string rather than panicking inside error-reporting
    // code (that would be a particularly unhelpful place to introduce a
    // second panic to catch).
    let cstring = CString::new(msg).unwrap_or_else(|_| {
        CString::new("tamga-c: last-error message contained an interior NUL byte")
            .expect("static string has no interior NUL")
    });
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(cstring));
}

/// Clears the calling thread's last-error message. Called at the start of
/// every [`ffi_guard`]-wrapped call so a stale message from a previous,
/// unrelated call can never be misread as belonging to the current one.
pub(crate) fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

/// Returns a pointer to the detailed message behind the last non-`TAMGA_OK`
/// code returned **on the calling thread**.
///
/// # Ownership
///
/// The returned pointer is **borrowed**, not owned: it is valid only until
/// the next `tamga_*` call on this same thread. Do not call
/// [`tamga_string_free`] on it, and do not retain it across calls. Copy the
/// string out immediately if you need it to outlive the next call. Returns
/// null if no error has been recorded yet on this thread (or after
/// [`clear_last_error`] ran at the start of a call that then succeeded).
///
/// This is the one convention picked for error-string ownership across this
/// crate, per Section F of `docs/plans/tamga-c.plan.md` — every error path
/// must populate [`LAST_ERROR`] via [`set_last_error`] so this accessor
/// stays meaningful.
#[unsafe(no_mangle)]
pub extern "C" fn tamga_last_error_message() -> *const c_char {
    LAST_ERROR.with(|slot| match slot.borrow().as_ref() {
        Some(cstring) => cstring.as_ptr(),
        None => std::ptr::null(),
    })
}

/// Frees a string previously returned as an **owned** pointer by this
/// library (decoded JSON payloads, generated proof strings — anything
/// documented as caller-owned in `include/tamga.h`).
///
/// Calling this on a null pointer is a documented no-op, not a crash.
/// Calling it twice on the same pointer (double-free), or calling libc
/// `free()` on a pointer this library returned instead of this function, is
/// undefined behavior and intentionally not guarded against — guarding
/// would hide caller bugs. See CLAUDE.md.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: caller contract (documented above and in tamga.h) requires
    // `ptr` to be a pointer this library previously returned via
    // `CString::into_raw` and not already freed.
    drop(unsafe { CString::from_raw(ptr) });
}

/// Shared UTF-8 validation + null-check helper for every `*const c_char`
/// argument. Never assume a caller-supplied C string is valid UTF-8 or
/// non-null without going through this.
///
/// # Safety
///
/// `ptr`, if non-null, must point to a valid, NUL-terminated C string.
pub(crate) unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, TamgaErrorCode> {
    if ptr.is_null() {
        return Err(TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
    }
    // SAFETY: forwarded from this function's own safety contract.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| TamgaErrorCode::TAMGA_ERR_INVALID_JSON)
    // TODO(Section B): TAMGA_ERR_INVALID_JSON is a placeholder mapping for
    // "argument was not valid UTF-8" — it's not really a JSON error. Add a
    // dedicated code (or repurpose TAMGA_ERR_UNKNOWN) once real call sites
    // in Sections C/D/E exist and this stops being purely theoretical.
}

/// Canonical `catch_unwind` reference pattern — every `extern "C" fn` in
/// this crate must wrap its body in this (or an equivalent) once
/// implemented. See [`license_file::tamga_license_file_verify`] for the one
/// FFI entry point that already does this; every other exported function
/// is `TODO`-marked to receive the same treatment (Section F).
///
/// Clears the calling thread's last-error message, runs `f` under
/// [`panic::catch_unwind`], and converts:
/// - `Ok(Ok(()))` → [`TamgaErrorCode::TAMGA_OK`]
/// - `Ok(Err(code))` → `code` (the caller is expected to have already
///   called [`set_last_error`] with a detailed message before returning
///   `Err`)
/// - `Err(_)` (a caught panic) → [`TamgaErrorCode::TAMGA_ERR_PANIC`], with a
///   generic last-error message (the panic payload itself is not
///   necessarily `Send`/coherent to stringify safely in every case)
pub(crate) fn ffi_guard<F>(f: F) -> TamgaErrorCode
where
    F: FnOnce() -> Result<(), TamgaErrorCode>,
{
    clear_last_error();
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => TamgaErrorCode::TAMGA_OK,
        Ok(Err(code)) => code,
        Err(_) => {
            set_last_error(
                "internal panic caught at the FFI boundary (see tamga_last_error_message)",
            );
            TamgaErrorCode::TAMGA_ERR_PANIC
        }
    }
}
