//! Integration tests for `tamga_machine_file_verify` / `_get_json` /
//! `_free` (docs/plans/tamga-c.plan.md Section D).
//!
//! See `tests/license_file_verify.rs`'s module doc comment for why this
//! crate's own lib is imported here as `tamga::...`, not `tamga_c::...`.
use std::ffi::{CStr, CString};
use std::ptr;

use tamga::machine_file::{
    tamga_machine_file_free, tamga_machine_file_get_json, tamga_machine_file_verify,
};
use tamga::{TamgaErrorCode, TamgaScheme, tamga_last_error_message};

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

const PEM_HEADER: &str = "-----BEGIN MACHINE FILE-----";
const PEM_FOOTER: &str = "-----END MACHINE FILE-----";

fn scheme_alg_suffix(scheme: TamgaScheme) -> &'static str {
    match scheme {
        TamgaScheme::TAMGA_SCHEME_ED25519_SIGN => "ed25519",
        TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_SIGN
        | TamgaScheme::TAMGA_SCHEME_RSA_2048_JWT_RS256 => "rsa-sha256",
        TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN => "rsa-pss-sha256",
        TamgaScheme::TAMGA_SCHEME_ECDSA_P256_SIGN => "ecdsa-p256",
        TamgaScheme::TAMGA_SCHEME_NONE => unreachable!("not exercised by these tests"),
    }
}

/// Signs `enc` with a scheme-appropriate freshly-generated key, mirroring
/// `tamga-api`'s own signing dispatch and `tamga-rust`'s equivalent test
/// helper — same pubkey-extraction gotcha noted there (`.public_key()`, NOT
/// `.as_der()`, which is the PKCS8 *private* key DER).
fn sign_for_scheme(scheme: TamgaScheme, enc: &str) -> (Vec<u8>, Vec<u8>) {
    use aws_lc_rs::rand::SystemRandom;
    match scheme {
        TamgaScheme::TAMGA_SCHEME_ED25519_SIGN => {
            use ed25519_dalek::{Signer, SigningKey};
            use rand::RngCore;
            use rand::rngs::OsRng;
            let mut secret = [0u8; 32];
            OsRng.fill_bytes(&mut secret);
            let signing_key = SigningKey::from_bytes(&secret);
            let pubkey = signing_key.verifying_key().to_bytes().to_vec();
            let sig = signing_key.sign(enc.as_bytes()).to_bytes().to_vec();
            (pubkey, sig)
        }
        TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_SIGN
        | TamgaScheme::TAMGA_SCHEME_RSA_2048_JWT_RS256 => {
            use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
            use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};
            let kp = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
            let pubkey = kp.public_key().as_ref().to_vec();
            let rng = SystemRandom::new();
            let mut sig = vec![0u8; kp.public_modulus_len()];
            kp.sign(&RSA_PKCS1_SHA256, &rng, enc.as_bytes(), &mut sig)
                .unwrap();
            (pubkey, sig)
        }
        TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN => {
            use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
            use aws_lc_rs::signature::{KeyPair as _, RSA_PSS_SHA256};
            let kp = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
            let pubkey = kp.public_key().as_ref().to_vec();
            let rng = SystemRandom::new();
            let mut sig = vec![0u8; kp.public_modulus_len()];
            kp.sign(&RSA_PSS_SHA256, &rng, enc.as_bytes(), &mut sig)
                .unwrap();
            (pubkey, sig)
        }
        TamgaScheme::TAMGA_SCHEME_ECDSA_P256_SIGN => {
            use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let kp =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
            let pubkey = kp.public_key().as_ref().to_vec();
            let sig = kp.sign(&rng, enc.as_bytes()).unwrap().as_ref().to_vec();
            (pubkey, sig)
        }
        TamgaScheme::TAMGA_SCHEME_NONE => unreachable!("not exercised by these tests"),
    }
}

fn representative_payload_json() -> String {
    serde_json::json!({
        "data": {
            "type": "machines",
            "id": "01926b3e-2222-7000-8000-000000000000",
            "attributes": {
                "fingerprint": "fp-abc123", "cores": 4, "memory": null, "disk": null,
                "ip": null, "hostname": "host1", "platform": "linux", "name": null,
                "heartbeat_status": "NOT_STARTED", "last_heartbeat_at": null,
                "next_heartbeat_at": null, "last_check_out_at": null, "metadata": {},
                "created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
            }
        }
    })
    .to_string()
}

fn build_pem(scheme: TamgaScheme, encrypt_key: Option<[u8; 32]>) -> (Vec<u8>, String) {
    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    let payload = representative_payload_json();
    let suffix = scheme_alg_suffix(scheme);
    let (enc_prefix, enc) = match encrypt_key {
        None => ("base64", B64.encode(payload.as_bytes())),
        Some(key) => {
            use aes_gcm::aead::{Aead, OsRng as AeadOsRng, rand_core::RngCore as _};
            use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
            let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key));
            let mut nonce_bytes = [0u8; 12];
            AeadOsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from(nonce_bytes);
            let ciphertext_and_tag = cipher.encrypt(&nonce, payload.as_bytes()).unwrap();
            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ciphertext_and_tag);
            ("aes-256-gcm", B64.encode(&out))
        }
    };
    let (pubkey, sig_bytes) = sign_for_scheme(scheme, &enc);
    let sig = B64.encode(&sig_bytes);
    let alg = format!("{enc_prefix}+{suffix}");
    let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": alg });
    let pem_body = B64.encode(serde_json::to_string(&cert).unwrap().as_bytes());
    (pubkey, format!("{PEM_HEADER}\n{pem_body}\n{PEM_FOOTER}"))
}

#[allow(clippy::too_many_arguments)]
unsafe fn verify(
    pem: &str,
    scheme: TamgaScheme,
    pubkey: &[u8],
    license_key: Option<&str>,
    fingerprint: Option<&str>,
) -> (TamgaErrorCode, *mut tamga::TamgaMachineFile) {
    let license_key_c = license_key.map(|k| CString::new(k).unwrap());
    let fingerprint_c = fingerprint.map(|f| CString::new(f).unwrap());
    let mut handle: *mut tamga::TamgaMachineFile = ptr::null_mut();
    let code = unsafe {
        tamga_machine_file_verify(
            pem.as_ptr() as *const i8,
            pem.len(),
            scheme as u32,
            pubkey.as_ptr(),
            pubkey.len(),
            license_key_c
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(ptr::null()),
            fingerprint_c
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(ptr::null()),
            &mut handle,
        )
    };
    (code, handle)
}

#[test]
fn ed25519_machine_file_round_trip() {
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN, None);
    let (code, handle) = unsafe {
        verify(
            &pem,
            TamgaScheme::TAMGA_SCHEME_ED25519_SIGN,
            &pubkey,
            None,
            None,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!handle.is_null());

    let mut json_ptr: *mut i8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let json_code = unsafe { tamga_machine_file_get_json(handle, &mut json_ptr, &mut json_len) };
    assert_eq!(json_code, TamgaErrorCode::TAMGA_OK);
    let json = unsafe { CStr::from_ptr(json_ptr) }.to_str().unwrap();
    assert!(json.contains("fp-abc123"));
    unsafe {
        tamga::tamga_string_free(json_ptr);
        tamga_machine_file_free(handle);
    }
}

#[test]
fn rsa_pkcs1_machine_file_round_trip() {
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_SIGN, None);
    let (code, handle) = unsafe {
        verify(
            &pem,
            TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_SIGN,
            &pubkey,
            None,
            None,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!handle.is_null());
    unsafe { tamga_machine_file_free(handle) };
}

#[test]
fn rsa_pss_machine_file_round_trip() {
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN, None);
    let (code, handle) = unsafe {
        verify(
            &pem,
            TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN,
            &pubkey,
            None,
            None,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!handle.is_null());
    unsafe { tamga_machine_file_free(handle) };
}

#[test]
fn ecdsa_p256_machine_file_round_trip() {
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ECDSA_P256_SIGN, None);
    let (code, handle) = unsafe {
        verify(
            &pem,
            TamgaScheme::TAMGA_SCHEME_ECDSA_P256_SIGN,
            &pubkey,
            None,
            None,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!handle.is_null());
    unsafe { tamga_machine_file_free(handle) };
}

#[test]
fn encrypted_machine_file_requires_correct_fingerprint() {
    let license_key = "lic-abc123";
    let fingerprint = "fp-abc123";
    let key = tamga_rust::crypto::hkdf::derive_machine_file_key(license_key, fingerprint);
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN, Some(key));

    let (code, handle) = unsafe {
        verify(
            &pem,
            TamgaScheme::TAMGA_SCHEME_ED25519_SIGN,
            &pubkey,
            Some(license_key),
            Some(fingerprint),
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_OK, "error: {}", last_error());
    assert!(!handle.is_null());
    unsafe { tamga_machine_file_free(handle) };

    let (wrong_code, wrong_handle) = unsafe {
        verify(
            &pem,
            TamgaScheme::TAMGA_SCHEME_ED25519_SIGN,
            &pubkey,
            Some(license_key),
            Some("wrong-fingerprint"),
        )
    };
    assert_ne!(wrong_code, TamgaErrorCode::TAMGA_OK);
    assert!(wrong_handle.is_null());
}

#[test]
fn missing_fingerprint_for_encrypted_file_fails() {
    let license_key = "lic-abc123";
    let fingerprint = "fp-abc123";
    let key = tamga_rust::crypto::hkdf::derive_machine_file_key(license_key, fingerprint);
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN, Some(key));

    let (code, handle) = unsafe {
        verify(
            &pem,
            TamgaScheme::TAMGA_SCHEME_ED25519_SIGN,
            &pubkey,
            Some(license_key),
            None,
        )
    };
    assert_ne!(code, TamgaErrorCode::TAMGA_OK);
    assert!(handle.is_null());
}

#[test]
fn rsa_jwt_rs256_scheme_rejected_before_any_signature_attempt() {
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN, None);
    let (code, handle) = unsafe {
        verify(
            &pem,
            TamgaScheme::TAMGA_SCHEME_RSA_2048_JWT_RS256,
            &pubkey,
            None,
            None,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME);
    assert!(handle.is_null());
}

#[test]
fn scheme_none_is_rejected() {
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN, None);
    let (code, handle) =
        unsafe { verify(&pem, TamgaScheme::TAMGA_SCHEME_NONE, &pubkey, None, None) };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME);
    assert!(handle.is_null());
}

#[test]
fn out_of_range_raw_scheme_value_is_rejected() {
    // `scheme` is a raw u32 at the FFI boundary, not the TamgaScheme enum
    // type, specifically so a value with no corresponding discriminant
    // (here: 999, `TamgaScheme::TAMGA_SCHEME_RSA_2048_JWT_RS256` is the
    // highest at 5) can be validated and rejected instead of producing an
    // invalid enum value the instant it's loaded into a typed parameter —
    // see TamgaScheme::from_raw's doc comment in src/lib.rs.
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN, None);
    let mut handle: *mut tamga::TamgaMachineFile = ptr::null_mut();
    let pem_c = pem.as_str();
    let code = unsafe {
        tamga_machine_file_verify(
            pem_c.as_ptr() as *const i8,
            pem_c.len(),
            999,
            pubkey.as_ptr(),
            pubkey.len(),
            ptr::null(),
            ptr::null(),
            &mut handle,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME);
    assert!(handle.is_null());
}

#[test]
fn alg_suffix_mismatch_is_rejected() {
    let (pubkey, pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN, None);
    let (code, handle) = unsafe {
        verify(
            &pem,
            TamgaScheme::TAMGA_SCHEME_RSA_2048_PKCS1_SIGN,
            &pubkey,
            None,
            None,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_UNSUPPORTED_SCHEME);
    assert!(handle.is_null());
}

#[test]
fn malformed_pem_markers_rejected() {
    let (pubkey, _pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN, None);
    let (code, handle) = unsafe {
        verify(
            "not a pem file",
            TamgaScheme::TAMGA_SCHEME_ED25519_SIGN,
            &pubkey,
            None,
            None,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_INVALID_PEM);
    assert!(handle.is_null());
}

#[test]
fn null_pem_pointer_rejected() {
    let (pubkey, _pem) = build_pem(TamgaScheme::TAMGA_SCHEME_ED25519_SIGN, None);
    let mut handle: *mut tamga::TamgaMachineFile = ptr::null_mut();
    let code = unsafe {
        tamga_machine_file_verify(
            ptr::null(),
            0,
            TamgaScheme::TAMGA_SCHEME_ED25519_SIGN as u32,
            pubkey.as_ptr(),
            pubkey.len(),
            ptr::null(),
            ptr::null(),
            &mut handle,
        )
    };
    assert_eq!(code, TamgaErrorCode::TAMGA_ERR_NULL_ARGUMENT);
    assert!(handle.is_null());
}
