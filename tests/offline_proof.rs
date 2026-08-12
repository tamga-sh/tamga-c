//! Integration tests for `tamga_offline_proof_verify` (Section E) —
//! `tamga_offline_proof_generate` is intentionally unimplemented (see
//! `src/offline_proof.rs`'s module doc comment: `tamga-rust` exposes no
//! local RSA-signing primitive), so proof fixtures here are built directly
//! with `aws-lc-rs`, mirroring `tamga-rust/src/proof.rs`'s own test helpers
//! and the server's `serde_json::json!`-based canonical payload
//! construction (see that module's doc comment for why field order is
//! alphabetical, not source-declaration order).
//!
//! See `tests/license_file_verify.rs`'s module doc comment for why this
//! crate's own lib is imported here as `tamga::...`, not `tamga_c::...`.
use std::ffi::CString;
use std::ptr;

use tamga::offline_proof::{tamga_offline_proof_generate, tamga_offline_proof_verify};
use tamga::{TamgaErrorCode, tamga_last_error_message};

fn last_error() -> String {
    unsafe {
        let ptr = tamga_last_error_message();
        if ptr.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

fn gen_rsa_keypair() -> (Vec<u8>, aws_lc_rs::rsa::KeyPair) {
    use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
    use aws_lc_rs::signature::KeyPair as _;
    let kp = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let pubkey = kp.public_key().as_ref().to_vec();
    (pubkey, kp)
}

fn sign_payload(kp: &aws_lc_rs::rsa::KeyPair, payload_json: &str) -> String {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::RSA_PKCS1_SHA256;
    use base64::Engine as _;
    let rng = SystemRandom::new();
    let mut sig = vec![0u8; kp.public_modulus_len()];
    kp.sign(&RSA_PKCS1_SHA256, &rng, payload_json.as_bytes(), &mut sig)
        .unwrap();
    base64::engine::general_purpose::STANDARD.encode(&sig)
}

/// Mirrors `tamga-rust/src/proof.rs`'s private `build_payload_json` —
/// `serde_json::Value` self-normalizes to the server's actual alphabetical
/// wire order regardless of the literal `json!()` call's key order (see
/// that module's doc comment).
fn build_payload_json(
    account_id: uuid::Uuid,
    machine_id: uuid::Uuid,
    fingerprint: &str,
    dataset: &serde_json::Value,
) -> String {
    let payload = serde_json::json!({
        "account": { "id": account_id },
        "machine": { "id": machine_id, "fingerprint": fingerprint },
        "dataset": dataset,
    });
    serde_json::to_string(&payload).unwrap()
}

#[allow(clippy::too_many_arguments)]
unsafe fn verify(
    proof: &str,
    rsa_pubkey: &[u8],
    account_id: &str,
    machine_id: &str,
    fingerprint: &str,
    dataset_json: &str,
) -> (TamgaErrorCode, bool) {
    let proof_c = CString::new(proof).unwrap();
    let account_id_c = CString::new(account_id).unwrap();
    let machine_id_c = CString::new(machine_id).unwrap();
    let fingerprint_c = CString::new(fingerprint).unwrap();
    let dataset_c = CString::new(dataset_json).unwrap();
    let mut out_valid = false;
    let code = unsafe {
        tamga_offline_proof_verify(
            proof_c.as_ptr(),
            rsa_pubkey.as_ptr(),
            rsa_pubkey.len(),
            account_id_c.as_ptr(),
            machine_id_c.as_ptr(),
            fingerprint_c.as_ptr(),
            dataset_c.as_ptr(),
            &mut out_valid,
        )
    };
    (code, out_valid)
}

#[test]
fn accepts_a_known_good_fixture() {
    let (pubkey, kp) = gen_rsa_keypair();
    let account_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::nil();
    let dataset = serde_json::json!({ "cores": 4 });
    let payload_json = build_payload_json(account_id, machine_id, "fp-abc", &dataset);
    let proof = format!("v1x0.{}", sign_payload(&kp, &payload_json));

    let (code, valid) = unsafe {
        verify(
            &proof,
            &pubkey,
            &account_id.to_string(),
            &machine_id.to_string(),
            "fp-abc",
            &dataset.to_string(),
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(valid);
}

#[test]
fn rejects_tampered_dataset() {
    let (pubkey, kp) = gen_rsa_keypair();
    let account_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::nil();
    let signed_dataset = serde_json::json!({ "cores": 4 });
    let payload_json = build_payload_json(account_id, machine_id, "fp-abc", &signed_dataset);
    let proof = format!("v1x0.{}", sign_payload(&kp, &payload_json));

    let tampered_dataset = serde_json::json!({ "cores": 999 });
    let (code, valid) = unsafe {
        verify(
            &proof,
            &pubkey,
            &account_id.to_string(),
            &machine_id.to_string(),
            "fp-abc",
            &tampered_dataset.to_string(),
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!valid);
}

#[test]
fn rejects_tampered_account_id() {
    let (pubkey, kp) = gen_rsa_keypair();
    let account_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::nil();
    let dataset = serde_json::json!({ "cores": 4 });
    let payload_json = build_payload_json(account_id, machine_id, "fp-abc", &dataset);
    let proof = format!("v1x0.{}", sign_payload(&kp, &payload_json));

    let wrong_account_id = uuid::Uuid::from_u128(1);
    let (code, valid) = unsafe {
        verify(
            &proof,
            &pubkey,
            &wrong_account_id.to_string(),
            &machine_id.to_string(),
            "fp-abc",
            &dataset.to_string(),
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!valid);
}

#[test]
fn rejects_signature_computed_over_reordered_json() {
    // Field-order sensitivity: a signature computed over a
    // manually-reordered (but semantically-identical) JSON string must NOT
    // verify against the canonically-ordered payload this crate
    // reconstructs (delegated to tamga-rust). Regression test for the
    // field-order gotcha documented in CLAUDE.md.
    let (pubkey, kp) = gen_rsa_keypair();
    let account_id = uuid::Uuid::nil();
    let machine_id = uuid::Uuid::nil();
    let dataset = serde_json::json!({ "cores": 4 });

    let canonical_json = build_payload_json(account_id, machine_id, "fp-abc", &dataset);
    let reordered_json = format!(
        "{{\"account\":{{\"id\":\"{account_id}\"}},\"machine\":{{\"id\":\"{machine_id}\",\"fingerprint\":\"fp-abc\"}},\"dataset\":{{\"cores\":4}}}}"
    );
    assert_ne!(canonical_json, reordered_json);

    let proof = format!("v1x0.{}", sign_payload(&kp, &reordered_json));
    let (code, valid) = unsafe {
        verify(
            &proof,
            &pubkey,
            &account_id.to_string(),
            &machine_id.to_string(),
            "fp-abc",
            &dataset.to_string(),
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(
        !valid,
        "a signature over reordered JSON must not verify against the canonical payload"
    );
}

#[test]
fn malformed_prefix_rejected_before_any_crypto() {
    let (pubkey, _kp) = gen_rsa_keypair();
    let (code, valid) = unsafe {
        verify(
            "not-v1x0-prefixed",
            &pubkey,
            &uuid::Uuid::nil().to_string(),
            &uuid::Uuid::nil().to_string(),
            "fp",
            "{}",
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!valid);
}

#[test]
fn malformed_account_id_uuid_rejected() {
    let (pubkey, _kp) = gen_rsa_keypair();
    let (code, _valid) = unsafe {
        verify(
            "v1x0.abc",
            &pubkey,
            "not-a-uuid",
            &uuid::Uuid::nil().to_string(),
            "fp",
            "{}",
        )
    };
    assert_ne!(code, TamgaErrorCode::TAMGA_OK);
}

#[test]
fn malformed_dataset_json_rejected() {
    let (pubkey, _kp) = gen_rsa_keypair();
    let (code, _valid) = unsafe {
        verify(
            "v1x0.abc",
            &pubkey,
            &uuid::Uuid::nil().to_string(),
            &uuid::Uuid::nil().to_string(),
            "fp",
            "{not valid json",
        )
    };
    assert_ne!(code, TamgaErrorCode::TAMGA_OK);
}

#[test]
fn null_proof_str_pointer_rejected() {
    let (pubkey, _kp) = gen_rsa_keypair();
    let account_id_c = CString::new(uuid::Uuid::nil().to_string()).unwrap();
    let machine_id_c = CString::new(uuid::Uuid::nil().to_string()).unwrap();
    let fingerprint_c = CString::new("fp").unwrap();
    let dataset_c = CString::new("{}").unwrap();
    let mut out_valid = false;
    let code = unsafe {
        tamga_offline_proof_verify(
            ptr::null(),
            pubkey.as_ptr(),
            pubkey.len(),
            account_id_c.as_ptr(),
            machine_id_c.as_ptr(),
            fingerprint_c.as_ptr(),
            dataset_c.as_ptr(),
            &mut out_valid,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
}

#[test]
fn zero_rsa_pubkey_len_rejected_with_length_specific_code_not_null_argument() {
    // Regression test: rsa_pubkey_len == 0 used to be reported as
    // TAMGA_ERR_NULL_ARGUMENT even though rsa_pubkey itself is a valid
    // non-null pointer -- the actual problem is the length.
    let (pubkey, _kp) = gen_rsa_keypair();
    let account_id_c = CString::new(uuid::Uuid::nil().to_string()).unwrap();
    let machine_id_c = CString::new(uuid::Uuid::nil().to_string()).unwrap();
    let fingerprint_c = CString::new("fp").unwrap();
    let dataset_c = CString::new("{}").unwrap();
    let mut out_valid = false;
    let code = unsafe {
        tamga_offline_proof_verify(
            CString::new("v1x0.dummy").unwrap().as_ptr(),
            pubkey.as_ptr(),
            0, // rsa_pubkey_len
            account_id_c.as_ptr(),
            machine_id_c.as_ptr(),
            fingerprint_c.as_ptr(),
            dataset_c.as_ptr(),
            &mut out_valid,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_LENGTH_INVALID);
}

#[test]
fn oversized_rsa_pubkey_len_rejected_with_length_specific_code_not_null_argument() {
    let (pubkey, _kp) = gen_rsa_keypair();
    let account_id_c = CString::new(uuid::Uuid::nil().to_string()).unwrap();
    let machine_id_c = CString::new(uuid::Uuid::nil().to_string()).unwrap();
    let fingerprint_c = CString::new("fp").unwrap();
    let dataset_c = CString::new("{}").unwrap();
    let mut out_valid = false;
    let code = unsafe {
        tamga_offline_proof_verify(
            CString::new("v1x0.dummy").unwrap().as_ptr(),
            pubkey.as_ptr(),
            usize::MAX, // absurd length, well past MAX_REASONABLE_LEN
            account_id_c.as_ptr(),
            machine_id_c.as_ptr(),
            fingerprint_c.as_ptr(),
            dataset_c.as_ptr(),
            &mut out_valid,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_LENGTH_INVALID);
}

#[test]
fn generate_is_not_implemented() {
    // tamga-rust exposes no local RSA-signing primitive (see
    // src/offline_proof.rs's module doc comment) — this documents the
    // current, deliberate non-implementation rather than silently skipping
    // coverage of the function's error path.
    let rsa_privkey = CString::new("dummy").unwrap();
    let account_id_c = CString::new(uuid::Uuid::nil().to_string()).unwrap();
    let machine_id_c = CString::new(uuid::Uuid::nil().to_string()).unwrap();
    let fingerprint_c = CString::new("fp").unwrap();
    let dataset_c = CString::new("{}").unwrap();
    let mut out_proof: *mut i8 = ptr::null_mut();
    let code = unsafe {
        tamga_offline_proof_generate(
            rsa_privkey.as_ptr(),
            account_id_c.as_ptr(),
            machine_id_c.as_ptr(),
            fingerprint_c.as_ptr(),
            dataset_c.as_ptr(),
            &mut out_proof,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_UNKNOWN);
    assert!(out_proof.is_null());
}
