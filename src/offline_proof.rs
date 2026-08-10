//! `tamga_offline_proof_verify` / `_generate` — Section E of
//! `docs/plans/tamga-c.plan.md` ("Machine Offline Proof FFI").
//!
//! # STUB — scaffolding only
//!
//! Both functions below always return
//! [`TamgaErrorCode::TAMGA_ERR_UNKNOWN`] and are `TODO`-marked to receive
//! the `catch_unwind` treatment described in [`crate::ffi_guard`]'s docs
//! (reference implementation:
//! [`crate::license_file::tamga_license_file_verify`]).
//!
//! # Offline proof format (from `docs/sdk.md` §7 / plan §3.3)
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
//! matters, not just field set. A verifier that re-serializes with a
//! different (even semantically equivalent) key order fails every check.
//! `_verify` and `_generate` MUST share one canonical-serialization helper
//! so the two paths can never drift from each other's field ordering.
//!
//! [`TamgaOfflineProof`](crate::TamgaOfflineProof) is declared in `lib.rs`
//! per Section B's checklist but has no producer/consumer here yet — see
//! that type's doc comment for why neither function below currently
//! returns/accepts a handle.

use std::ffi::c_char;

use crate::TamgaErrorCode;

/// Verifies a `"v1x0.<base64 signature>"` offline proof string against the
/// exact canonical JSON the server would have signed.
///
/// # Parameters
/// - `proof_str`: the full `"v1x0.<base64 signature>"` string.
/// - `rsa_pubkey` / (implicit length via NUL or a future explicit-length
///   param, TBD pending tamga-rust's frozen API): the account's RSA-2048
///   public key.
/// - `account_id`, `machine_id`, `fingerprint`: the values that must appear
///   in the canonical signed JSON, as NUL-terminated C strings.
/// - `dataset_json`: the client dataset as a NUL-terminated JSON string,
///   re-serialized internally in the server's exact field order before
///   verification (see module docs above — field order matters).
/// - `out_valid`: on `TAMGA_OK`, receives whether the proof is valid.
///   Distinguish "the FFI call itself failed" (non-`TAMGA_OK` return) from
///   "the call succeeded but the proof is invalid" (`TAMGA_OK` +
///   `*out_valid == false`) — callers must check both.
///
/// # Safety
/// All pointer parameters must be null or valid NUL-terminated C strings
/// (`rsa_pubkey`'s exact contract TBD). `out_valid` must be a valid pointer
/// this function may write to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_offline_proof_verify(
    proof_str: *const c_char,
    rsa_pubkey: *const c_char,
    account_id: *const c_char,
    machine_id: *const c_char,
    fingerprint: *const c_char,
    dataset_json: *const c_char,
    out_valid: *mut bool,
) -> TamgaErrorCode {
    // TODO(Section F): wrap in `ffi_guard`/`catch_unwind`. Not yet done.
    //
    // TODO(Section E): implement once tamga-rust's v0.1 API is frozen:
    //   1. null-check every pointer argument
    //   2. parse the "v1x0." version prefix; reject unrecognized versions
    //      with TAMGA_ERR_UNSUPPORTED_SCHEME
    //   3. base64-decode the signature portion following the prefix
    //   4. reconstruct the canonical signed JSON via the SAME shared
    //      serialization helper `_generate` uses (see below) --
    //      {"account":{"id":...},"machine":{"id":...,"fingerprint":...},
    //      "dataset":<dataset_json>}, field order exactly as shown
    //   5. RSA-2048 PKCS#1 v1.5/SHA-256 verify -- always this scheme,
    //      regardless of the license's own `scheme` field
    //   6. write the boolean result to *out_valid
    let _ = (
        proof_str,
        rsa_pubkey,
        account_id,
        machine_id,
        fingerprint,
        dataset_json,
        out_valid,
    );
    crate::set_last_error(
        "tamga_offline_proof_verify is not implemented yet (see docs/plans/tamga-c.plan.md Section E)",
    );
    TamgaErrorCode::TAMGA_ERR_UNKNOWN
}

/// Generates a `"v1x0.<base64 signature>"` offline proof, mirroring
/// server-side generation. Intended for air-gapped/test tooling that needs
/// to produce proofs without hitting the API — most consumers only need
/// [`tamga_offline_proof_verify`].
///
/// # Safety
/// All pointer parameters must be null or valid NUL-terminated C strings
/// (`rsa_privkey`'s exact contract TBD). `out_proof_str` must be a valid
/// pointer this function may write to; on `TAMGA_OK` it receives an owned
/// string, freed via [`crate::tamga_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tamga_offline_proof_generate(
    rsa_privkey: *const c_char,
    account_id: *const c_char,
    machine_id: *const c_char,
    fingerprint: *const c_char,
    dataset_json: *const c_char,
    out_proof_str: *mut *mut c_char,
) -> TamgaErrorCode {
    // TODO(Section F): wrap in `ffi_guard`/`catch_unwind`. Not yet done.
    //
    // TODO(Section E): implement once tamga-rust's v0.1 API is frozen.
    // MUST reuse the exact same canonical-serialization helper as
    // `tamga_offline_proof_verify` above -- these two paths can never be
    // allowed to drift from each other's field ordering, or a proof
    // generated by this function would fail to verify against itself.
    let _ = (
        rsa_privkey,
        account_id,
        machine_id,
        fingerprint,
        dataset_json,
        out_proof_str,
    );
    crate::set_last_error(
        "tamga_offline_proof_generate is not implemented yet (see docs/plans/tamga-c.plan.md Section E)",
    );
    TamgaErrorCode::TAMGA_ERR_UNKNOWN
}

// TODO(Section E): a single shared canonical-serialization helper, e.g.
//   fn canonical_proof_json(account_id: &str, machine_id: &str,
//                            fingerprint: &str, dataset_json: &str) -> String
// used by both functions above. Not written yet since it depends on
// tamga-rust's JSON serialization choices (serde_json field order is
// insertion order for structs, but a raw `dataset_json` re-embed needs
// care not to silently reformat/reorder the caller-supplied dataset).
