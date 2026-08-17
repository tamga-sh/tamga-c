//! `tamga_offline_proof_verify` / `_generate` — the machine offline-proof
//! FFI surface.
//!
//! # Offline proof format
//!
//! Response shape: `meta.proof = "v1x0.<base64 signature>"`. Always signed
//! with **RSA-2048 PKCS#1 v1.5 / SHA-256**, regardless of the license's own
//! `scheme` field. The signature covers:
//!
//! ```json
//! {"account":{"id":...},"machine":{"id":...,"fingerprint":...},"dataset":<client dataset>}
//! ```
//!
//! serialized **exactly** as the server produces it — ⚠️ field order
//! matters (and it's alphabetical, not the source's literal
//! account/machine/dataset order — see `tamga-rust`'s `src/proof.rs` module
//! doc comment for the full explanation). `tamga_offline_proof_verify`
//! delegates entirely to `tamga_rust::proof::verify_offline_proof`, which
//! already builds this payload correctly via `serde_json::Value` — no
//! canonical-serialization logic is duplicated here.
//!
//! ⚠️ **`tamga_offline_proof_generate` is intentionally still a stub.**
//! `tamga-rust` exposes no local RSA-signing primitive — its `crypto::rsa`
//! module only has `verify_pkcs1`/`verify_pss` (this SDK is a client that
//! verifies server-issued material; it was never built to sign). Real proof
//! generation happens server-side via `Client::generate_offline_proof`
//! (HTTP), which is out of scope for this HTTP-free crate. Implementing
//! `_generate` here would mean re-deriving the byte-exact canonical JSON
//! payload a **second** time in this crate — exactly the kind of
//! independent reimplementation `tamga-c`'s whole architecture exists to
//! avoid (see this repo's `CLAUDE.md`), and exactly the bug class
//! (field-order drift) `tamga-rust/src/proof.rs`'s module doc comment
//! warns about. If air-gapped proof generation is truly needed, the right
//! fix is adding a security-reviewed local-signing primitive to
//! `tamga-rust` first, then wrapping *that* here — not duplicating the
//! payload construction independently in this crate.
//!
//! [`TamgaOfflineProof`](crate::TamgaOfflineProof) is declared in `lib.rs`
//! but has no producer/consumer here — `_verify` reports its result via
//! `out_valid: *mut bool` and `_generate` (once implemented) would return an
//! owned `*mut c_char`, neither of which needs a handle. See that type's doc
//! comment.

use std::ffi::c_char;
use std::slice;

use crate::{TamgaErrorCode, ffi_guard};

/// Verifies a `"v1x0.<base64 signature>"` offline proof string against the
/// exact canonical JSON the server would have signed.
///
/// # Parameters
/// - `proof_str`: the full `"v1x0.<base64 signature>"` string, NUL-terminated.
/// - `rsa_pubkey` / `rsa_pubkey_len`: the account's RSA-2048 public key as a
///   raw `SubjectPublicKeyInfo` DER blob — same convention as
///   [`crate::machine_file::tamga_machine_file_verify`]'s RSA pubkey
///   parameter.
/// - `account_id`, `machine_id`: UUID strings (NUL-terminated), parsed via
///   `uuid::Uuid::parse_str`.
/// - `fingerprint`: NUL-terminated C string.
/// - `dataset_json`: the client dataset as a NUL-terminated JSON string,
///   parsed and re-embedded into the canonical payload (see module docs —
///   field order matters, and is handled entirely by `tamga-rust`).
/// - `out_valid`: on `TAMGA_OK`, receives whether the proof is valid.
///   Distinguish "the FFI call itself failed" (non-`TAMGA_OK` return) from
///   "the call succeeded but the proof is invalid" (`TAMGA_OK` +
///   `*out_valid == false`) — callers must check both.
///
/// # Safety
/// `proof_str`/`account_id`/`machine_id`/`fingerprint`/`dataset_json` must
/// be null or valid NUL-terminated C strings. `rsa_pubkey` must point to
/// `rsa_pubkey_len` readable bytes (or be null). `out_valid` must be a
/// valid pointer this function may write to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_offline_proof_verify(
    proof_str: *const c_char,
    rsa_pubkey: *const u8,
    rsa_pubkey_len: usize,
    account_id: *const c_char,
    machine_id: *const c_char,
    fingerprint: *const c_char,
    dataset_json: *const c_char,
    out_valid: *mut bool,
) -> TamgaErrorCode {
    ffi_guard(|| {
        if proof_str.is_null()
            || rsa_pubkey.is_null()
            || account_id.is_null()
            || machine_id.is_null()
            || fingerprint.is_null()
            || dataset_json.is_null()
            || out_valid.is_null()
        {
            crate::set_last_error("tamga_offline_proof_verify: null argument");
            return Err(TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
        }
        if rsa_pubkey_len == 0 || rsa_pubkey_len > crate::MAX_REASONABLE_LEN {
            crate::set_last_error(
                "tamga_offline_proof_verify: rsa_pubkey_len out of reasonable range",
            );
            return Err(TamgaErrorCode::TAMGA_ERR_LENGTH_INVALID);
        }

        // SAFETY: all pointers checked non-null above; caller contract
        // guarantees valid NUL-terminated C strings.
        let proof_str = unsafe { crate::cstr_to_str(proof_str) }.inspect_err(|_| {
            crate::set_last_error("tamga_offline_proof_verify: proof_str is not valid UTF-8");
        })?;
        let account_id_str = unsafe { crate::cstr_to_str(account_id) }.inspect_err(|_| {
            crate::set_last_error("tamga_offline_proof_verify: account_id is not valid UTF-8");
        })?;
        let machine_id_str = unsafe { crate::cstr_to_str(machine_id) }.inspect_err(|_| {
            crate::set_last_error("tamga_offline_proof_verify: machine_id is not valid UTF-8");
        })?;
        let fingerprint_str = unsafe { crate::cstr_to_str(fingerprint) }.inspect_err(|_| {
            crate::set_last_error("tamga_offline_proof_verify: fingerprint is not valid UTF-8");
        })?;
        let dataset_json_str = unsafe { crate::cstr_to_str(dataset_json) }.inspect_err(|_| {
            crate::set_last_error("tamga_offline_proof_verify: dataset_json is not valid UTF-8");
        })?;

        let account_id_uuid: uuid::Uuid = account_id_str.parse().map_err(|_| {
            crate::set_last_error("tamga_offline_proof_verify: account_id is not a valid UUID");
            TamgaErrorCode::TAMGA_ERR_INVALID_JSON
        })?;
        let machine_id_uuid: uuid::Uuid = machine_id_str.parse().map_err(|_| {
            crate::set_last_error("tamga_offline_proof_verify: machine_id is not a valid UUID");
            TamgaErrorCode::TAMGA_ERR_INVALID_JSON
        })?;
        let dataset: serde_json::Value = serde_json::from_str(dataset_json_str).map_err(|e| {
            crate::set_last_error(format!(
                "tamga_offline_proof_verify: dataset_json is not valid JSON: {e}"
            ));
            TamgaErrorCode::TAMGA_ERR_INVALID_JSON
        })?;

        // SAFETY: caller contract guarantees `rsa_pubkey` points to
        // `rsa_pubkey_len` readable bytes; checked non-null/non-zero above.
        let rsa_pubkey_bytes = unsafe { slice::from_raw_parts(rsa_pubkey, rsa_pubkey_len) };

        let result = tamga_rust::proof::verify_offline_proof(
            proof_str,
            account_id_uuid,
            machine_id_uuid,
            fingerprint_str,
            &dataset,
            rsa_pubkey_bytes,
        );

        // SAFETY: `out_valid` is non-null (checked above) and, per the
        // caller contract, a valid pointer this function may write to.
        unsafe {
            *out_valid = result.is_ok();
        }
        // Deliberately NOT calling set_last_error here even when `result`
        // is `Err`: an invalid proof is not a call failure — this function
        // still returns TAMGA_OK, and `tamga_last_error_message`'s
        // documented contract is "the message behind the last *non-OK*
        // code." `*out_valid` is the correct, sufficient signal for "the
        // proof didn't verify"; populating the error message here as well
        // would make `TAMGA_OK` an exception to its own crate-wide
        // invariant (see the ffi_guard_tests::success_clears_a_stale_last_error
        // test in lib.rs, which asserts that invariant generally).
        Ok(())
    })
}

/// Generates a `"v1x0.<base64 signature>"` offline proof, mirroring
/// server-side generation. **Not implemented** — see this module's doc
/// comment for why: `tamga-rust` exposes no local RSA-signing primitive,
/// and hand-rolling the byte-exact canonical payload a second time in this
/// crate would reintroduce the exact field-order risk `tamga-rust`'s own
/// `src/proof.rs` warns against. Most consumers only need
/// [`tamga_offline_proof_verify`] — proof *generation* is a server-side
/// concern (`POST .../machines/{id}/actions/generate-offline-proof`),
/// reachable via `tamga-rust`'s `Client::generate_offline_proof` in the
/// full (HTTP-capable) SDKs, not this HTTP-free crate.
///
/// # Safety
/// All pointer parameters must be null or valid NUL-terminated C strings.
/// `out_proof_str` must be a valid pointer this function may write to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_offline_proof_generate(
    rsa_privkey: *const c_char,
    account_id: *const c_char,
    machine_id: *const c_char,
    fingerprint: *const c_char,
    dataset_json: *const c_char,
    out_proof_str: *mut *mut c_char,
) -> TamgaErrorCode {
    ffi_guard(|| {
        let _ = (
            rsa_privkey,
            account_id,
            machine_id,
            fingerprint,
            dataset_json,
            out_proof_str,
        );
        crate::set_last_error(
            "tamga_offline_proof_generate is not implemented: tamga-rust exposes no local RSA-signing primitive (see this module's doc comment in src/offline_proof.rs)",
        );
        Err(TamgaErrorCode::TAMGA_ERR_UNKNOWN)
    })
}
