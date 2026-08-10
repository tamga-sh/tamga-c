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
//! 3. Verify a machine offline proof — [`offline_proof`]. (Local *generation*
//!    is deliberately unimplemented — `tamga-rust` has no signing primitive
//!    to delegate to; see that module's doc comment.)
//! 4. Derive the two AES keys those file formats depend on — [`kdf`].
//!
//! # Status
//!
//! Sections C (license-file FFI), D (machine-file FFI), and E's
//! `tamga_offline_proof_verify` are implemented, delegating all
//! cryptographic logic to `tamga-rust`'s already security-reviewed
//! `checkout`/`proof`/`crypto` modules — this crate is a marshalling layer,
//! not a second implementation. `tamga_offline_proof_generate` remains
//! unimplemented by design (see [`offline_proof`]'s module doc comment).
//! Section F (memory/lifecycle) is in progress; see
//! `docs/plans/tamga-c.plan.md` for the current per-item checklist.
//!
//! # The `catch_unwind` rule
//!
//! Every `pub extern "C" fn` in this crate wraps its body in
//! [`std::panic::catch_unwind`] via the [`ffi_guard`] helper below,
//! converting a caught panic into [`TamgaErrorCode::TAMGA_ERR_PANIC`] plus a
//! last-error message instead of unwinding across the FFI boundary —
//! unwinding a Rust panic into C is undefined behavior.
//! [`license_file::tamga_license_file_verify`] is the reference
//! implementation of this pattern; every other exported function copies the
//! same shape. See [`ffi_guard`]'s own unit tests for the mechanism proven
//! against a deliberately panicking closure.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{self, AssertUnwindSafe};

pub mod kdf;
pub mod license_file;
pub mod machine_file;
pub mod offline_proof;

/// Upper bound on any caller-supplied `(*const u8, len)` buffer this crate
/// accepts (PEM bodies, JSON blobs, etc.). Purely a sanity guard against a
/// garbage/corrupted length value causing an absurd `slice::from_raw_parts`
/// call before any real parsing runs — real `.lic`/`.mach` files are at most
/// a few KB. 16 MiB comfortably covers any legitimate input.
pub(crate) const MAX_REASONABLE_LEN: usize = 16 * 1024 * 1024;

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
    /// Unclassified/internal error. Returned today by
    /// [`offline_proof::tamga_offline_proof_generate`] (deliberately
    /// unimplemented — see that function's doc comment) and by a small
    /// number of genuinely uncommon error paths (e.g. decoded JSON
    /// containing an interior NUL byte) that don't warrant a dedicated code.
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

impl TamgaScheme {
    /// Validates a raw C-side scheme value against the known discriminants.
    ///
    /// `TamgaScheme` is never accepted as an `extern "C" fn` **parameter
    /// type** directly — a C `enum` has no validity range (it's just an
    /// `int` at the ABI level), so a caller passing an out-of-range value
    /// (a stale header, a buggy binding, corrupted memory) would produce a
    /// Rust value violating `TamgaScheme`'s enum-validity invariant the
    /// instant it's loaded into a typed parameter — undefined behavior
    /// before any of this crate's own defensive code even runs. Every FFI
    /// entry point that takes a scheme instead takes a plain `u32` and
    /// converts it through this fallible function first (see
    /// [`machine_file::tamga_machine_file_verify`]).
    pub(crate) fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::TAMGA_SCHEME_NONE),
            1 => Some(Self::TAMGA_SCHEME_ED25519_SIGN),
            2 => Some(Self::TAMGA_SCHEME_RSA_2048_PKCS1_SIGN),
            3 => Some(Self::TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN),
            4 => Some(Self::TAMGA_SCHEME_ECDSA_P256_SIGN),
            5 => Some(Self::TAMGA_SCHEME_RSA_2048_JWT_RS256),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tamga_scheme_tests {
    use super::*;

    #[test]
    fn from_raw_accepts_every_declared_discriminant() {
        assert_eq!(
            TamgaScheme::from_raw(0),
            Some(TamgaScheme::TAMGA_SCHEME_NONE)
        );
        assert_eq!(
            TamgaScheme::from_raw(1),
            Some(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN)
        );
        assert_eq!(
            TamgaScheme::from_raw(2),
            Some(TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_SIGN)
        );
        assert_eq!(
            TamgaScheme::from_raw(3),
            Some(TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN)
        );
        assert_eq!(
            TamgaScheme::from_raw(4),
            Some(TamgaScheme::TAMGA_SCHEME_ECDSA_P256_SIGN)
        );
        assert_eq!(
            TamgaScheme::from_raw(5),
            Some(TamgaScheme::TAMGA_SCHEME_RSA_2048_JWT_RS256)
        );
    }

    #[test]
    fn from_raw_rejects_values_outside_the_declared_range() {
        assert_eq!(TamgaScheme::from_raw(6), None);
        assert_eq!(TamgaScheme::from_raw(999), None);
        assert_eq!(TamgaScheme::from_raw(u32::MAX), None);
    }
}

/// Opaque handle wrapping a verified/decoded `.lic` license-file payload.
///
/// Obtained from [`license_file::tamga_license_file_verify`]; must be freed
/// with [`license_file::tamga_license_file_free`] exactly once.
#[repr(C)]
pub struct TamgaLicenseFile {
    _private: [u8; 0],
    // Genuinely zero-sized and opaque by design: cbindgen emits a valid
    // incomplete-type forward declaration without leaking field layout to C
    // callers. The real payload (decoded LicenseResource JSON) lives behind
    // this pointer as a private, non-`#[repr(C)]` `LicenseFileHandle` in
    // license_file.rs, reached only via pointer cast — callers must never
    // introspect this type's layout.
}

/// Opaque handle wrapping a verified/decoded machine-file payload.
///
/// Obtained from [`machine_file::tamga_machine_file_verify`]; must be freed
/// with [`machine_file::tamga_machine_file_free`] exactly once.
#[repr(C)]
pub struct TamgaMachineFile {
    _private: [u8; 0],
    // Same pattern as TamgaLicenseFile — see its doc comment. The real
    // payload is a private `MachineFileHandle` in machine_file.rs.
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
/// stays meaningful. `TAMGA_OK` always implies this returns null on the
/// calling thread, with no exceptions — including
/// [`offline_proof::tamga_offline_proof_verify`], whose `*out_valid`
/// out-param (not this accessor) is the correct signal for "the proof
/// didn't verify," which is not itself a call failure.
///
/// Does not go through [`ffi_guard`] — `ffi_guard` clears the last-error
/// message on entry, which would make this specific accessor erase the very
/// value it's about to return. Instead wraps its (currently infallible)
/// body directly in [`panic::catch_unwind`] so a future change here still
/// can't unwind across the FFI boundary, without the clear-on-entry
/// behavior that would defeat this function's entire purpose.
#[unsafe(no_mangle)]
pub extern "C" fn tamga_last_error_message() -> *const c_char {
    panic::catch_unwind(AssertUnwindSafe(|| {
        LAST_ERROR.with(|slot| match slot.borrow().as_ref() {
            Some(cstring) => cstring.as_ptr(),
            None => std::ptr::null(),
        })
    }))
    .unwrap_or(std::ptr::null())
}

/// Frees a string previously returned as an **owned** pointer by this
/// library (decoded JSON payloads, generated proof strings — anything
/// documented as caller-owned in `include/tamga.h`).
///
/// Calling this on a null pointer is a documented no-op, not a crash.
///
/// # Safety
/// `ptr` must be null, or a pointer previously returned by this library via
/// `CString::into_raw` and not already freed. Calling this twice on the same
/// pointer (double-free), or calling libc `free()` on a pointer this library
/// returned instead of this function, is undefined behavior and
/// intentionally not guarded against — guarding would hide caller bugs. See
/// CLAUDE.md.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_string_free(ptr: *mut c_char) {
    ffi_guard_void(|| {
        if ptr.is_null() {
            return;
        }
        // SAFETY: caller contract (documented above and in tamga.h)
        // requires `ptr` to be a pointer this library previously returned
        // via `CString::into_raw` and not already freed.
        drop(unsafe { CString::from_raw(ptr) });
    })
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
    // NOTE: TAMGA_ERR_INVALID_JSON is a placeholder mapping for "argument
    // was not valid UTF-8" — it's not really a JSON error. Every call site
    // in Sections C/D/E immediately overwrites the last-error message with
    // a more specific one via `.inspect_err(...)`, so the coarse code here
    // is only ever seen by a caller who ignores `tamga_last_error_message`.
    // Not worth a dedicated code for that case alone.
}

/// Canonical `catch_unwind` wrapper every `extern "C" fn` in this crate
/// calls its body through.
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
///
/// No production code path inside this crate is expected to ever actually
/// panic — every fallible step (parsing, verification, decryption) returns
/// a typed `Result` instead. This wrapper exists as defense-in-depth against
/// an unexpected panic (a future `tamga-rust` regression, an unreachable!()
/// that turns out reachable, an allocation failure) still being memory-safe
/// to propagate to a C caller, per this crate's `catch_unwind` rule (see
/// module doc comment). Its own correctness — that it really does catch and
/// convert a panic rather than let it unwind — is proven directly below
/// against a deliberately panicking closure, since no real call site can
/// exercise that path by design.
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

/// [`ffi_guard`]'s counterpart for `extern "C" fn`s with no return value —
/// the `tamga_*_free` functions and [`tamga_string_free`]. There is no
/// `TamgaErrorCode` slot to report a caught panic through (the function
/// signature is `-> ()`), so a caught panic here is silently swallowed
/// after being converted to a last-error message on a best-effort basis —
/// the point is solely to prevent the panic from unwinding across the FFI
/// boundary (undefined behavior), not to report it. A free function
/// panicking at all already means a caller violated its documented pointer
/// contract (a live, correctly-typed, not-already-freed pointer); this is
/// the difference between "caller bug turns into memory corruption" and
/// "caller bug turns into a memory-safe no-op."
pub(crate) fn ffi_guard_void<F>(f: F)
where
    F: FnOnce(),
{
    if panic::catch_unwind(AssertUnwindSafe(f)).is_err() {
        set_last_error(
            "internal panic caught at the FFI boundary in a free function (see tamga_last_error_message)",
        );
    }
}

#[cfg(test)]
mod ffi_guard_tests {
    use super::*;

    #[test]
    fn catches_a_panic_and_returns_tamga_err_panic() {
        let code = ffi_guard(|| panic!("boom"));
        assert_eq!(code, TamgaErrorCode::TAMGA_ERR_PANIC);
    }

    #[test]
    fn a_caught_panic_populates_the_last_error_message() {
        ffi_guard(|| panic!("boom"));
        let ptr = tamga_last_error_message();
        assert!(!ptr.is_null());
        // SAFETY: ffi_guard just populated LAST_ERROR on this thread via
        // set_last_error, which always produces a valid NUL-terminated
        // CString.
        let msg = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(msg.contains("panic"));
    }

    #[test]
    fn success_clears_a_stale_last_error_from_an_earlier_call_on_the_same_thread() {
        ffi_guard(|| panic!("leave a stale message"));
        let code = ffi_guard(|| Ok(()));
        assert_eq!(code, TamgaErrorCode::TAMGA_OK);
        assert!(tamga_last_error_message().is_null());
    }

    #[test]
    fn typed_error_passes_through_unchanged() {
        let code = ffi_guard(|| Err(TamgaErrorCode::TAMGA_ERR_INVALID_PEM));
        assert_eq!(code, TamgaErrorCode::TAMGA_ERR_INVALID_PEM);
    }

    #[test]
    fn void_guard_catches_a_panic_without_unwinding_out() {
        // The only observable success criterion is "this test function
        // itself doesn't panic" — ffi_guard_void has no return value to
        // assert on, by design (see its doc comment).
        ffi_guard_void(|| panic!("boom"));
    }

    #[test]
    fn void_guard_runs_a_non_panicking_closure_normally() {
        let mut ran = false;
        ffi_guard_void(|| ran = true);
        assert!(ran);
    }
}
