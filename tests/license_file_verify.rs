//! Integration tests for `tamga_license_file_verify` / `_get_json` /
//! `_free` (docs/plans/tamga-c.plan.md Section C).
//!
//! This crate's own `[lib] name` is `"tamga"` (chosen so the built shared
//! library is `libtamga.so`/`tamga.h`, matching the C-facing product name),
//! so integration tests import the crate under test as `tamga::...`, not
//! `tamga_c::...`. The `tamga-rust` reference implementation is a separate
//! dependency keyed as `tamga_rust` in Cargo.toml specifically to avoid
//! colliding with that self-import (see Cargo.toml's dependency comment) —
//! used here only to build known-good fixtures the same way the real server
//! does.
use std::ffi::{CStr, CString};
use std::ptr;

use tamga::license_file::{
    tamga_license_file_free, tamga_license_file_get_json, tamga_license_file_verify,
};
use tamga::{TamgaErrorCode, tamga_last_error_message, tamga_string_free};

fn last_error() -> String {
    unsafe {
        let ptr = tamga_last_error_message();
        if ptr.is_null() {
            String::new()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

/// Builds a `.lic` PEM the same way the real server does — signature over
/// `enc`'s base64 **string**, optional AES-256-GCM encryption keyed by the
/// server's naive zero-pad/truncate transform. Mirrors
/// `tamga-rust/src/checkout/license_file.rs`'s own test helper so these
/// tests exercise the real wire format, not this crate's assumptions about
/// it.
fn build_pem(
    payload_json: &str,
    signing_key: &ed25519_dalek::SigningKey,
    encryption_key: Option<&[u8; 32]>,
) -> String {
    use base64::Engine as _;
    use ed25519_dalek::Signer;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    const PEM_HEADER: &str = "-----BEGIN LICENSE FILE-----";
    const PEM_FOOTER: &str = "-----END LICENSE FILE-----";

    let (enc, alg) = match encryption_key {
        None => (B64.encode(payload_json.as_bytes()), "base64+ed25519+v2"),
        Some(key) => {
            use aes_gcm::aead::{Aead, OsRng as AeadOsRng, rand_core::RngCore as _};
            use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
            let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
            let mut nonce_bytes = [0u8; 12];
            AeadOsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from(nonce_bytes);
            let ciphertext_and_tag = cipher.encrypt(&nonce, payload_json.as_bytes()).unwrap();
            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ciphertext_and_tag);
            (B64.encode(&out), "aes-256-gcm+ed25519+v2")
        }
    };

    let sig = B64.encode(signing_key.sign(enc.as_bytes()).to_bytes());
    let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": alg });
    let cert_json = serde_json::to_string(&cert).unwrap();
    let pem_body = B64.encode(cert_json.as_bytes());
    format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}")
}

fn representative_payload_json() -> String {
    serde_json::json!({
        "data": {
            "type": "licenses",
            "id": "01926b3e-0000-7000-8000-000000000000",
            "attributes": {
                "name": "Acme Corp", "key": "lic-abc123", "status": "ACTIVE",
                "expiry": null, "suspended": false, "protected": false, "uses": 0,
                "scheme": null, "encrypted": false, "strict": false, "floating": false,
                "max_machines": null, "max_uses": null, "max_users": null,
                "last_validated_at": null, "last_check_in_at": null, "last_check_out_at": null,
                "machines_count": 0, "metadata": {},
                "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
            }
        },
        // Format v2 puts the claims inside the signed bytes; a payload without
        // them is a v1 file and no longer verifies.
        "meta": { "iat": 1_767_225_600, "jti": "test-jti", "kid": "test-kid" }
    })
    .to_string()
}

fn gen_keypair() -> ([u8; 32], ed25519_dalek::SigningKey) {
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    use rand::rngs::OsRng;
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    (signing_key.verifying_key().to_bytes(), signing_key)
}

unsafe fn verify(
    pem: &str,
    pubkey: &[u8; 32],
    license_key: Option<&str>,
) -> (TamgaErrorCode, *mut tamga::TamgaLicenseFile) {
    let license_key_c = license_key.map(|k| CString::new(k).unwrap());
    let mut handle: *mut tamga::TamgaLicenseFile = ptr::null_mut();
    let code = unsafe {
        tamga_license_file_verify(
            pem.as_ptr() as *const i8,
            pem.len(),
            pubkey.as_ptr(),
            license_key_c
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(ptr::null()),
            &mut handle,
        )
    };
    (code, handle)
}

#[test]
fn verifies_a_known_good_plain_fixture() {
    let (pubkey, signing_key) = gen_keypair();
    let pem = build_pem(&representative_payload_json(), &signing_key, None);
    let (code, handle) = unsafe { verify(&pem, &pubkey, None) };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!handle.is_null());

    let mut json_ptr: *mut i8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let json_code = unsafe { tamga_license_file_get_json(handle, &mut json_ptr, &mut json_len) };
    assert_eq!(json_code, TamgaErrorCode::TAMGA_OK);
    let json = unsafe { CStr::from_ptr(json_ptr) }.to_str().unwrap();
    assert!(json.contains("lic-abc123"));
    unsafe {
        tamga_string_free(json_ptr);
        tamga_license_file_free(handle);
    }
}

#[test]
fn verifies_a_known_good_encrypted_fixture() {
    let (pubkey, signing_key) = gen_keypair();
    let license_key = "lic-abc123";
    let enc_key = tamga_rust::crypto::hkdf::derive_license_file_key(license_key);
    let pem = build_pem(&representative_payload_json(), &signing_key, Some(&enc_key));
    let (code, handle) = unsafe { verify(&pem, &pubkey, Some(license_key)) };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!handle.is_null());
    unsafe { tamga_license_file_free(handle) };
}

#[test]
fn missing_license_key_for_encrypted_file_fails() {
    let (pubkey, signing_key) = gen_keypair();
    let license_key = "lic-abc123";
    let enc_key = tamga_rust::crypto::hkdf::derive_license_file_key(license_key);
    let pem = build_pem(&representative_payload_json(), &signing_key, Some(&enc_key));
    let (code, handle) = unsafe { verify(&pem, &pubkey, None) };
    assert_ne!(code, TamgaErrorCode::TAMGA_OK);
    assert!(handle.is_null());
}

#[test]
fn tampered_signature_is_rejected() {
    let (pubkey, signing_key) = gen_keypair();
    let mut pem = build_pem(&representative_payload_json(), &signing_key, None);
    let mid = pem.len() / 2;
    let corrupted_char = if pem.as_bytes()[mid] == b'A' {
        'B'
    } else {
        'A'
    };
    pem.replace_range(mid..mid + 1, &corrupted_char.to_string());
    let (code, handle) = unsafe { verify(&pem, &pubkey, None) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_SIGNATURE_INVALID);
    assert!(handle.is_null());
}

#[test]
fn wrong_public_key_is_rejected() {
    let (_pubkey, signing_key) = gen_keypair();
    let (wrong_pubkey, _) = gen_keypair();
    let pem = build_pem(&representative_payload_json(), &signing_key, None);
    let (code, handle) = unsafe { verify(&pem, &wrong_pubkey, None) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_SIGNATURE_INVALID);
    assert!(handle.is_null());
}

#[test]
fn malformed_pem_markers_rejected() {
    let (pubkey, _signing_key) = gen_keypair();
    let (code, handle) = unsafe { verify("not a pem file", &pubkey, None) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_INVALID_PEM);
    assert!(handle.is_null());
}

#[test]
fn malformed_base64_body_rejected() {
    let (pubkey, _signing_key) = gen_keypair();
    let pem = "-----BEGIN LICENSE FILE-----\n!!!not-base64!!!\n-----END LICENSE FILE-----";
    let (code, handle) = unsafe { verify(pem, &pubkey, None) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_INVALID_BASE64);
    assert!(handle.is_null());
}

#[test]
fn unsupported_algorithm_rejected() {
    use base64::Engine as _;
    use ed25519_dalek::Signer;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    let (pubkey, signing_key) = gen_keypair();
    let enc = B64.encode(representative_payload_json().as_bytes());
    let sig = B64.encode(signing_key.sign(enc.as_bytes()).to_bytes());
    let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": "rot13+carrier-pigeon" });
    let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
    let pem = format!("-----BEGIN LICENSE FILE-----\n{pem_body}\n-----END LICENSE FILE-----");
    let (code, handle) = unsafe { verify(&pem, &pubkey, None) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME);
    assert!(handle.is_null());
}

#[test]
fn decoded_bytes_signature_verification_fails_proving_the_string_bytes_gotcha() {
    // Regression test for the single most common implementation mistake in
    // this format: signing over the base64-*decoded* bytes instead of the
    // base64 *string* must NOT verify. See CLAUDE.md.
    use base64::Engine as _;
    use ed25519_dalek::Signer;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    let (pubkey, signing_key) = gen_keypair();
    let payload = representative_payload_json();
    let enc = B64.encode(payload.as_bytes());
    let decoded_enc_bytes = B64.decode(&enc).unwrap();

    // Sign over the DECODED bytes -- the wrong way to do it.
    let wrong_sig = signing_key.sign(&decoded_enc_bytes);
    let sig = B64.encode(wrong_sig.to_bytes());
    let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": "base64+ed25519+v2" });
    let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
    let pem = format!("-----BEGIN LICENSE FILE-----\n{pem_body}\n-----END LICENSE FILE-----");

    let (code, handle) = unsafe { verify(&pem, &pubkey, None) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_SIGNATURE_INVALID);
    assert!(handle.is_null());
}

#[test]
fn null_pem_pointer_rejected() {
    let (pubkey, _signing_key) = gen_keypair();
    let mut handle: *mut tamga::TamgaLicenseFile = ptr::null_mut();
    let code = unsafe {
        tamga_license_file_verify(ptr::null(), 0, pubkey.as_ptr(), ptr::null(), &mut handle)
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
    assert!(handle.is_null());
}

#[test]
fn zero_pem_len_rejected_with_length_specific_code_not_null_argument() {
    // Regression test: pem_len == 0 used to be reported as
    // TAMGA_ERR_NULL_ARGUMENT even though `pem` itself is a valid non-null
    // pointer -- the actual problem is the length, not the pointer. A
    // caller branching on the numeric error code alone (not the string
    // message) would have misdiagnosed this as a null-pointer bug.
    let (pubkey, signing_key) = gen_keypair();
    let pem = build_pem(&representative_payload_json(), &signing_key, None);
    let mut handle: *mut tamga::TamgaLicenseFile = ptr::null_mut();
    let code = unsafe {
        tamga_license_file_verify(
            pem.as_ptr() as *const i8,
            0, // pem_len
            pubkey.as_ptr(),
            ptr::null(),
            &mut handle,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_LENGTH_INVALID);
    assert!(handle.is_null());
}

#[test]
fn oversized_pem_len_rejected_with_length_specific_code_not_null_argument() {
    let (pubkey, signing_key) = gen_keypair();
    let pem = build_pem(&representative_payload_json(), &signing_key, None);
    let mut handle: *mut tamga::TamgaLicenseFile = ptr::null_mut();
    let code = unsafe {
        tamga_license_file_verify(
            pem.as_ptr() as *const i8,
            usize::MAX, // absurd length, well past MAX_REASONABLE_LEN
            pubkey.as_ptr(),
            ptr::null(),
            &mut handle,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_LENGTH_INVALID);
    assert!(handle.is_null());
}

// ── Format v2: expiry is inside the signature ────────────────────────────────

#[test]
fn an_expired_file_is_refused_with_its_own_error_code() {
    // In v1 the requested TTL lived only in the JSON:API envelope around the
    // certificate, so a 24-hour trial file stayed cryptographically valid
    // forever and the client — which is the attacker — simply kept the PEM.
    let (pubkey, signing_key) = gen_keypair();

    let mut payload: serde_json::Value =
        serde_json::from_str(&representative_payload_json()).unwrap();
    // An hour after `iat`, and `iat` is in the past.
    payload["meta"]["exp"] = serde_json::json!(1_767_229_200_i64);

    let pem = build_pem(&payload.to_string(), &signing_key, None);
    let (code, _handle) = unsafe { verify(&pem, &pubkey, None) };

    assert_eq!(
        code,
        TamgaErrorCode::TAMGA_ERR_EXPIRED,
        "an expired file must be distinguishable from a forged one"
    );
}

#[test]
fn a_v1_file_is_refused_outright() {
    // Accepting both formats would hand back the permanent-file problem: any
    // certificate issued before v2 could be kept and reused forever.
    let (pubkey, signing_key) = gen_keypair();
    let pem = build_pem(&representative_payload_json(), &signing_key, None);

    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let mut cert: serde_json::Value =
        serde_json::from_slice(&B64.decode(body.trim()).unwrap()).unwrap();
    cert["alg"] = serde_json::json!("base64+ed25519");
    let repacked = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
    let v1_pem =
        format!("-----BEGIN LICENSE FILE-----\n{repacked}\n-----END LICENSE FILE-----");

    let (code, _handle) = unsafe { verify(&v1_pem, &pubkey, None) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME);
}
