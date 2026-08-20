//! Generates the offline-file fixtures tamga-c's integration tests verify
//! against, in exactly the format the Tamga server produces, and confirms
//! tamga-rust accepts every one of them before writing it out.
//!
//! Fixtures this generator produced but tamga-rust rejects would prove the
//! generator wrong, not the SDK, so that check runs first.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs;
use std::path::Path;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn derive(salt: &str, ikm: &str, info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), ikm.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).unwrap();
    out
}

fn encrypt(key: &[u8; 32], nonce_seed: u8, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = [nonce_seed; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, Payload { msg: plaintext, aad: &[] }).unwrap();
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ct);
    out
}

fn cert_body(enc: &str, sig: &str, alg: &str) -> String {
    let cert = serde_json::json!({ "enc": enc, "sig": sig, "alg": alg });
    B64.encode(serde_json::to_string(&cert).unwrap())
}

/// The envelope as the server emits it: the body on one line.
///
/// Not line-wrapped, even though PEM conventionally is. tamga-rust's parser
/// only trims the ends of the body and passes the rest to a strict base64
/// decoder, so a wrapped body is rejected there -- which means the server
/// cannot be emitting one. tamga-swift and tamga-java both strip embedded
/// whitespace and would accept either. See wrap_lines below.
fn wrap(marker: &str, enc: &str, sig: &str, alg: &str) -> String {
    format!(
        "-----BEGIN {marker}-----\n{}\n-----END {marker}-----\n",
        cert_body(enc, sig, alg)
    )
}

/// The same envelope with the body wrapped at 64 columns.
fn wrap_lines(marker: &str, enc: &str, sig: &str, alg: &str) -> String {
    let body = cert_body(enc, sig, alg);
    let wrapped: Vec<String> = body
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect();
    format!(
        "-----BEGIN {marker}-----\n{}\n-----END {marker}-----\n",
        wrapped.join("\n")
    )
}

fn licence_payload(exp: Option<i64>) -> String {
    let mut meta = serde_json::json!({
        "iat": 1_700_000_000i64,
        "jti": "01926b3e-0000-7000-8000-00000000ffff",
        "kid": "key-1"
    });
    if let Some(exp) = exp {
        meta["exp"] = serde_json::json!(exp);
    }
    serde_json::to_string(&serde_json::json!({
        "data": {
            "id": "01926b3e-0000-7000-8000-000000000001",
            "type": "licenses",
            "attributes": {
                "name": "Acme Pro",
                "key": "MUP7-2TQK-7FBF-4Q6H-Y7ZR-9C3V",
                "status": "ACTIVE",
                "expiry": "2027-01-01T00:00:00Z",
                "suspended": false,
                "protected": true,
                "uses": 3,
                "scheme": "ED25519_SIGN",
                "encrypted": true,
                "strict": false,
                "floating": true,
                "max_machines": 5,
                "max_uses": null,
                "max_users": null,
                "last_validated_at": null,
                "last_check_in_at": null,
                "last_check_out_at": null,
                "machines_count": 2,
                "metadata": { "tier": "pro", "seats": 5 },
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-06-01T00:00:00Z"
            }
        },
        "meta": meta
    }))
    .unwrap()
}

fn machine_payload() -> String {
    serde_json::to_string(&serde_json::json!({
        "data": {
            "id": "01926b3e-0000-7000-8000-000000000002",
            "type": "machines",
            "attributes": {
                "fingerprint": "9f8e7d6c5b4a39281706",
                "cores": 8,
                "memory": 17179869184i64,
                "disk": 512000000000i64,
                "ip": "203.0.113.7",
                "hostname": "build-01",
                "platform": "linux",
                "name": "Build agent",
                "heartbeat_status": "ALIVE",
                "last_heartbeat_at": "2026-08-20T10:00:00Z",
                "next_heartbeat_at": "2026-08-20T10:10:00Z",
                "last_check_out_at": null,
                "metadata": {},
                "created": "2026-02-01T00:00:00Z",
                "updated": "2026-08-20T10:00:00Z"
            }
        }
    }))
    .unwrap()
}

const LICENCE_KEY: &str = "MUP7-2TQK-7FBF-4Q6H-Y7ZR-9C3V";
const FINGERPRINT: &str = "9f8e7d6c5b4a39281706";

fn main() {
    let out = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/offline"));
    fs::create_dir_all(out).unwrap();

    // --- Ed25519 account key ---------------------------------------------
    let ed = SigningKey::from_bytes(&[42u8; 32]);
    let ed_pub = ed.verifying_key().to_bytes();
    fs::write(out.join("ed25519_pubkey.bin"), ed_pub).unwrap();

    // --- licence files ----------------------------------------------------
    let plain_enc = B64.encode(licence_payload(None));
    let plain_sig = B64.encode(ed.sign(plain_enc.as_bytes()).to_bytes());
    let plain = wrap("LICENSE FILE", &plain_enc, &plain_sig, "base64+ed25519+v2");
    tamga::checkout::license_file::verify_license_file(&plain, &ed_pub, None).unwrap();
    fs::write(out.join("license_plain.lic"), &plain).unwrap();

    let key = derive("tamga:license-file-key-v1", LICENCE_KEY, b"license-file");
    let enc_bytes = encrypt(&key, 0x11, licence_payload(None).as_bytes());
    let enc = B64.encode(&enc_bytes);
    let sig = B64.encode(ed.sign(enc.as_bytes()).to_bytes());
    let encrypted = wrap("LICENSE FILE", &enc, &sig, "aes-256-gcm+ed25519+v2");
    tamga::checkout::license_file::verify_license_file(&encrypted, &ed_pub, Some(LICENCE_KEY))
        .unwrap();
    fs::write(out.join("license_encrypted.lic"), &encrypted).unwrap();

    // Expired: authentic signature, exp far in the past.
    let expired_enc = B64.encode(licence_payload(Some(1_700_000_100)));
    let expired_sig = B64.encode(ed.sign(expired_enc.as_bytes()).to_bytes());
    let expired = wrap("LICENSE FILE", &expired_enc, &expired_sig, "base64+ed25519+v2");
    assert!(tamga::checkout::license_file::verify_license_file(&expired, &ed_pub, None).is_err());
    fs::write(out.join("license_expired.lic"), &expired).unwrap();

    // Format v1: correct in every way except the missing +v2 suffix.
    let v1_enc = B64.encode(licence_payload(None));
    let v1_sig = B64.encode(ed.sign(v1_enc.as_bytes()).to_bytes());
    let v1 = wrap("LICENSE FILE", &v1_enc, &v1_sig, "base64+ed25519");
    assert!(tamga::checkout::license_file::verify_license_file(&v1, &ed_pub, None).is_err());
    fs::write(out.join("license_v1.lic"), &v1).unwrap();

    // The base64-decoded-bytes trap: signature computed over enc's DECODED
    // bytes instead of the base64 string. Must fail everywhere.
    let trap_enc = B64.encode(licence_payload(None));
    let trap_sig = B64.encode(ed.sign(&B64.decode(&trap_enc).unwrap()).to_bytes());
    let trap = wrap("LICENSE FILE", &trap_enc, &trap_sig, "base64+ed25519+v2");
    assert!(tamga::checkout::license_file::verify_license_file(&trap, &ed_pub, None).is_err());
    fs::write(out.join("license_signed_over_decoded_bytes.lic"), &trap).unwrap();

    // --- machine files ----------------------------------------------------
    use tamga::models::policy::LicenseScheme;

    let m_enc = B64.encode(machine_payload());
    let m_sig = B64.encode(ed.sign(m_enc.as_bytes()).to_bytes());
    let m_plain = wrap("MACHINE FILE", &m_enc, &m_sig, "base64+ed25519");
    tamga::checkout::machine_file::verify_machine_file(
        &m_plain, LicenseScheme::Ed25519Sign, &ed_pub, None, None).unwrap();
    fs::write(out.join("machine_ed25519.mach"), &m_plain).unwrap();

    let mkey = derive("tamga:machine-file-key-v1", LICENCE_KEY, FINGERPRINT.as_bytes());
    let menc_bytes = encrypt(&mkey, 0x22, machine_payload().as_bytes());
    let menc = B64.encode(&menc_bytes);
    let msig = B64.encode(ed.sign(menc.as_bytes()).to_bytes());
    let m_encrypted = wrap("MACHINE FILE", &menc, &msig, "aes-256-gcm+ed25519");
    tamga::checkout::machine_file::verify_machine_file(
        &m_encrypted, LicenseScheme::Ed25519Sign, &ed_pub, Some(LICENCE_KEY),
        Some(FINGERPRINT)).unwrap();
    fs::write(out.join("machine_ed25519_encrypted.mach"), &m_encrypted).unwrap();

    // RSA-2048, both padding modes, and ECDSA P-256.
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
    use aws_lc_rs::signature::{
        EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING, RSA_PKCS1_SHA256,
        RSA_PSS_SHA256,
    };
    let rng = SystemRandom::new();

    let rsa = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let rsa_spki = rsa.public_key().as_ref().to_vec();
    fs::write(out.join("rsa_spki.der"), &rsa_spki).unwrap();

    for (alg_suffix, scheme, name) in [
        ("rsa-sha256", LicenseScheme::Rsa2048Pkcs1Sign, "machine_rsa_pkcs1.mach"),
        ("rsa-pss-sha256", LicenseScheme::Rsa2048Pkcs1PssSign, "machine_rsa_pss.mach"),
    ] {
        let enc = B64.encode(machine_payload());
        let mut sig = vec![0u8; rsa.public_modulus_len()];
        if alg_suffix == "rsa-sha256" {
            rsa.sign(&RSA_PKCS1_SHA256, &rng, enc.as_bytes(), &mut sig).unwrap();
        } else {
            rsa.sign(&RSA_PSS_SHA256, &rng, enc.as_bytes(), &mut sig).unwrap();
        }
        let file = wrap("MACHINE FILE", &enc, &B64.encode(&sig),
                        &format!("base64+{alg_suffix}"));
        tamga::checkout::machine_file::verify_machine_file(
            &file, scheme, &rsa_spki, None, None).unwrap();
        fs::write(out.join(name), &file).unwrap();
    }

    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let ec = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
    let ec_point = ec.public_key().as_ref().to_vec();
    fs::write(out.join("ecdsa_point.bin"), &ec_point).unwrap();
    {
        let enc = B64.encode(machine_payload());
        let sig = ec.sign(&rng, enc.as_bytes()).unwrap();
        let file = wrap("MACHINE FILE", &enc, &B64.encode(sig.as_ref()), "base64+ecdsa-p256");
        tamga::checkout::machine_file::verify_machine_file(
            &file, LicenseScheme::EcdsaP256Sign, &ec_point, None, None).unwrap();
        fs::write(out.join("machine_ecdsa.mach"), &file).unwrap();
    }

    // --- offline proof ----------------------------------------------------
    let account_id = "01926b3e-0000-7000-8000-0000000000aa";
    let machine_id = "01926b3e-0000-7000-8000-000000000002";
    let dataset = serde_json::json!({ "b": 1, "a": "two", "nested": { "z": true, "y": null } });
    let payload = serde_json::to_string(&serde_json::json!({
        "account": { "id": account_id },
        "machine": { "id": machine_id, "fingerprint": FINGERPRINT },
        "dataset": dataset,
    }))
    .unwrap();
    let mut proof_sig = vec![0u8; rsa.public_modulus_len()];
    rsa.sign(&RSA_PKCS1_SHA256, &rng, payload.as_bytes(), &mut proof_sig).unwrap();
    let proof = format!("v1x0.{}", B64.encode(&proof_sig));
    tamga::proof::verify_offline_proof(
        &proof,
        account_id.parse().unwrap(),
        machine_id.parse().unwrap(),
        FINGERPRINT,
        &dataset,
        &rsa_spki,
    )
    .unwrap();
    fs::write(out.join("proof.txt"), &proof).unwrap();
    fs::write(out.join("proof_dataset.json"), serde_json::to_string(&dataset).unwrap()).unwrap();
    fs::write(out.join("proof_payload.json"), &payload).unwrap();

    // A line-wrapped variant of the plain licence file. tamga-rust rejects
    // this one -- its parser trims only the ends of the body -- while
    // tamga-swift and tamga-java strip embedded whitespace and accept it.
    // tamga-c follows the lenient majority, so this fixture exists to pin
    // that behaviour, and is deliberately NOT run through tamga-rust.
    let wrapped = wrap_lines("LICENSE FILE", &plain_enc, &plain_sig, "base64+ed25519+v2");
    assert!(tamga::checkout::license_file::verify_license_file(&wrapped, &ed_pub, None).is_err(),
            "if tamga-rust ever accepts a wrapped body, this note is out of date");
    fs::write(out.join("license_plain_wrapped.lic"), &wrapped).unwrap();

    println!("all fixtures generated and verified by tamga-rust");
    println!("canonical proof payload: {payload}");
}
