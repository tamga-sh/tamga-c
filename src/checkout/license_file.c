#include "checkout/license_file.h"

#include <string.h>

#include "checkout/cert.h"
#include "checkout/claims.h"
#include "checkout/key_set.h"
#include "checkout/pem.h"
#include "crypto/ed25519.h"
#include "crypto/gcm.h"
#include "crypto/hkdf.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"

static const char TAMGA_LICENSE_PEM_BEGIN[] = "-----BEGIN LICENSE FILE-----";
static const char TAMGA_LICENSE_PEM_END[] = "-----END LICENSE FILE-----";

static const char TAMGA_ALG_PLAIN[] = "base64+ed25519+v2";
static const char TAMGA_ALG_ENCRYPTED[] = "aes-256-gcm+ed25519+v2";

/* Unwraps the PEM envelope, parses the inner certificate and settles which of
 * the two legal algorithms it declares. */
static TamgaErrorCode tamga_license_open(const char *pem, size_t pem_len, TamgaCert *out_cert,
                                         bool *out_encrypted) {
    TamgaErrorCode status;
    char *body = NULL;
    size_t body_len = 0u;

    status = tamga_pem_extract(pem, pem_len, TAMGA_LICENSE_PEM_BEGIN, TAMGA_LICENSE_PEM_END, &body,
                               &body_len);
    if (status != TAMGA_OK) {
        return status;
    }

    status = tamga_cert_parse(body, body_len, out_cert);
    tamga_string_free(body);
    if (status != TAMGA_OK) {
        return status;
    }

    /* Exactly two algorithm strings are legal, matched in full and by length.
     * A prefix or substring match would let "base64+ed25519+v2+anything"
     * through, and a strcmp would let an interior NUL do the same. */
    if (tamga_cert_alg_equals(out_cert, TAMGA_ALG_PLAIN, sizeof(TAMGA_ALG_PLAIN) - 1u)) {
        *out_encrypted = false;
        return TAMGA_OK;
    }
    if (tamga_cert_alg_equals(out_cert, TAMGA_ALG_ENCRYPTED, sizeof(TAMGA_ALG_ENCRYPTED) - 1u)) {
        *out_encrypted = true;
        return TAMGA_OK;
    }
    tamga_cert_free(out_cert);
    return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                           "unsupported licence-file algorithm; only offline format v2 "
                           "is accepted, and there is no v1 fallback");
}

/* Decodes the signature field and checks it is the length Ed25519 requires. */
static TamgaErrorCode tamga_license_decode_signature(const TamgaCert *cert,
                                                     unsigned char **out_signature) {
    size_t signature_len = 0u;
    TamgaBase64Failure why;
    unsigned char *signature;

    *out_signature = NULL;
    signature = tamga_base64_decode_alloc_why(cert->sig, cert->sig_len, &signature_len, &why);
    if (signature == NULL) {
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the signature");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the signature field is not valid base64");
    }
    if (signature_len != TAMGA_ED25519_SIG_LEN) {
        tamga_free(signature);
        return tamga_error_set(TAMGA_ERR_SIGNATURE_INVALID, "signature is not the expected length");
    }
    *out_signature = signature;
    return TAMGA_OK;
}

/*
 * Decodes `enc`, decrypting it first when the file says so.
 *
 * ⚠️ A licence file's encrypted payload is ONE base64 blob of
 * nonce(12) || ciphertext || tag(16). The machine file's is two separately
 * encoded halves joined by a '.', and assuming either framing for the other
 * breaks it -- see machine_file.c.
 *
 * `*out_capacity` is what was ALLOCATED and `*out_len` is what was written;
 * AES-GCM shortens the second on the way out because the tag is not plaintext.
 * Every free of this buffer must use the capacity, or the tail of a buffer
 * holding licence-key-derived plaintext is left unzeroed.
 */
static TamgaErrorCode tamga_license_decode_payload(const TamgaCert *cert, bool encrypted,
                                                   const char *license_key,
                                                   unsigned char **out_plaintext, size_t *out_len,
                                                   size_t *out_capacity) {
    unsigned char *enc_bytes;
    size_t enc_len = 0u;
    unsigned char *plaintext;
    size_t plaintext_capacity;
    size_t plaintext_len;
    unsigned char key[TAMGA_FILE_KEY_LEN];
    TamgaBase64Failure why;

    *out_plaintext = NULL;
    *out_len = 0u;
    *out_capacity = 0u;

    enc_bytes = tamga_base64_decode_alloc_why(cert->enc, cert->enc_len, &enc_len, &why);
    if (enc_bytes == NULL) {
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the payload");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the enc field is not valid base64");
    }

    if (!encrypted) {
        *out_plaintext = enc_bytes;
        *out_len = enc_len;
        *out_capacity = enc_len;
        return TAMGA_OK;
    }

    if (license_key == NULL) {
        tamga_secure_free(enc_bytes, enc_len);
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "this licence file is encrypted and needs the licence key");
    }
    /* nonce(12) || ciphertext || tag(16): at least 28 bytes even for an
     * empty plaintext. */
    if (enc_len < (TAMGA_GCM_NONCE_LEN + TAMGA_GCM_TAG_LEN)) {
        tamga_secure_free(enc_bytes, enc_len);
        return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                               "encrypted payload is too short to contain a nonce and tag");
    }
    if (!tamga_derive_license_file_key(license_key, key)) {
        tamga_secure_free(enc_bytes, enc_len);
        return tamga_error_set(TAMGA_ERR_UNKNOWN, "key derivation failed");
    }

    plaintext_capacity = enc_len - TAMGA_GCM_NONCE_LEN;
    plaintext_len = plaintext_capacity;
    plaintext = (unsigned char *)tamga_malloc(plaintext_capacity);
    if (plaintext == NULL) {
        tamga_secure_zero(key, sizeof(key));
        tamga_secure_free(enc_bytes, enc_len);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the payload");
    }

    if (!tamga_gcm_open(key, enc_bytes, NULL, 0u, &enc_bytes[TAMGA_GCM_NONCE_LEN],
                        enc_len - TAMGA_GCM_NONCE_LEN, plaintext, &plaintext_len)) {
        tamga_secure_zero(key, sizeof(key));
        tamga_secure_free(plaintext, plaintext_capacity);
        tamga_secure_free(enc_bytes, enc_len);
        return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                               "could not decrypt the licence file; the licence key is "
                               "wrong or the payload was altered");
    }
    tamga_secure_zero(key, sizeof(key));
    tamga_secure_free(enc_bytes, enc_len);

    *out_plaintext = plaintext;
    *out_len = plaintext_len;
    *out_capacity = plaintext_capacity;
    return TAMGA_OK;
}

/* Parses the signed payload, keeping "this machine is out of memory" distinct
 * from "your licence file is corrupt". */
static TamgaErrorCode tamga_license_parse_payload(const unsigned char *plaintext, size_t len,
                                                  TamgaJson **out_payload) {
    const char *parse_error = NULL;

    *out_payload = tamga_json_parse((const char *)plaintext, len, &parse_error);
    if (*out_payload != NULL) {
        return TAMGA_OK;
    }
    if (tamga_json_error_is_out_of_memory(parse_error)) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not parse the licence payload");
    }
    return tamga_error_set(TAMGA_ERR_INVALID_JSON, "licence payload is malformed: %s",
                           (parse_error != NULL) ? parse_error : "unknown");
}

/* Everything after the signature has verified: the claims, the expiry check
 * and the copy of the resource. Consumes `payload` on every path. */
static TamgaErrorCode tamga_license_finish(TamgaJson *payload, int64_t now_unix,
                                           TamgaJson **out_resource, TamgaFileClaims *out_claims) {
    TamgaFileClaims claims;
    const TamgaJson *data;
    TamgaErrorCode status;

    status = tamga_claims_read(tamga_json_object_get(payload, "meta"), &claims);
    if (status != TAMGA_OK) {
        tamga_json_free(payload);
        return status;
    }

    /*
     * The signature proves the file is authentic. It does not prove it is
     * still valid -- that is this check, and skipping it is exactly what made
     * v1 files permanent. The machine-file path runs the same check through
     * the same helper, so the two grace periods cannot drift apart.
     */
    if (tamga_claims_are_expired(&claims, now_unix)) {
        tamga_json_free(payload);
        return tamga_error_set(TAMGA_ERR_EXPIRED,
                               "the licence file is authentic but expired; check out a fresh one");
    }

    data = tamga_json_object_get(payload, "data");
    if (data == NULL || tamga_json_type(data) != TAMGA_JSON_OBJECT) {
        tamga_json_free(payload);
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "the licence payload has no data object");
    }

    *out_resource = tamga_json_clone(data);
    tamga_json_free(payload);
    if (*out_resource == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not copy the licence resource");
    }
    if (out_claims != NULL) {
        *out_claims = claims;
    }
    return TAMGA_OK;
}

/*
 * The shared body of both entry points. Exactly one of `ed25519_pubkey` and
 * `keys` is non-NULL, and which one decides the ORDER of the two steps below.
 *
 * With a single key, the signature is checked first and nothing parses bytes
 * an attacker chose -- the order this format is designed for, and the one the
 * public tamga_license_file_verify() keeps.
 *
 * With a key set, the key to check against is named inside the payload, so the
 * payload has to be decoded (and, when encrypted, decrypted) first. That is
 * sound because the only value taken from those bytes before verification is
 * the `kid`, which can SELECT from keys the caller already trusts and can
 * never SUPPLY one. It does mean the JSON parser sees unverified bytes, which
 * is why that parser is fuzzed, depth-capped and length-capped.
 */
static TamgaErrorCode tamga_license_file_verify_core(const char *pem, size_t pem_len,
                                                     const unsigned char *ed25519_pubkey,
                                                     const TamgaSigningKeySet *keys,
                                                     const char *license_key, int64_t now_unix,
                                                     TamgaJson **out_resource,
                                                     TamgaFileClaims *out_claims) {
    TamgaErrorCode status;
    TamgaCert cert;
    bool encrypted = false;
    unsigned char *signature = NULL;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0u;
    size_t plaintext_capacity = 0u;
    TamgaJson *payload = NULL;
    unsigned char selected[TAMGA_ED25519_PUBKEY_LEN];
    const unsigned char *verifier = ed25519_pubkey;

    if (pem == NULL || out_resource == NULL || (ed25519_pubkey == NULL && keys == NULL)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    *out_resource = NULL;

    status = tamga_license_open(pem, pem_len, &cert, &encrypted);
    if (status != TAMGA_OK) {
        return status;
    }

    status = tamga_license_decode_signature(&cert, &signature);
    if (status != TAMGA_OK) {
        tamga_cert_free(&cert);
        return status;
    }

    if (keys != NULL) {
        status = tamga_license_decode_payload(&cert, encrypted, license_key, &plaintext,
                                              &plaintext_len, &plaintext_capacity);
        if (status == TAMGA_OK) {
            status = tamga_license_parse_payload(plaintext, plaintext_len, &payload);
            /* Freed at the CAPACITY it was allocated with, never at the length
             * AES-GCM reported -- the difference is the tag, and leaving it
             * behind leaves licence-key-derived plaintext in freed memory. */
            tamga_secure_free(plaintext, plaintext_capacity);
        }
        if (status == TAMGA_OK) {
            status = tamga_key_set_select(
                keys, tamga_claims_key_id(tamga_json_object_get(payload, "meta")), selected);
            verifier = selected;
        }
    }

    /*
     * ⚠️ Verify against enc's base64 STRING bytes, without decoding them.
     * Decoding first and verifying the decoded bytes is the classic mistake
     * with this format and fails against every real server-issued file.
     */
    if (status == TAMGA_OK &&
        !tamga_ed25519_verify(verifier, (const unsigned char *)cert.enc, cert.enc_len, signature)) {
        status =
            tamga_error_set(TAMGA_ERR_SIGNATURE_INVALID, "licence-file signature did not verify");
    }
    tamga_free(signature);

    /* The single-key path decodes only now, with the signature behind it. */
    if (status == TAMGA_OK && payload == NULL) {
        status = tamga_license_decode_payload(&cert, encrypted, license_key, &plaintext,
                                              &plaintext_len, &plaintext_capacity);
        if (status == TAMGA_OK) {
            status = tamga_license_parse_payload(plaintext, plaintext_len, &payload);
            tamga_secure_free(plaintext, plaintext_capacity);
        }
    }
    tamga_cert_free(&cert);

    if (status != TAMGA_OK) {
        tamga_json_free(payload);
        return status;
    }
    return tamga_license_finish(payload, now_unix, out_resource, out_claims);
}

TamgaErrorCode tamga_license_file_verify_at(const char *pem, size_t pem_len,
                                            const unsigned char ed25519_pubkey[32],
                                            const char *license_key, int64_t now_unix,
                                            TamgaJson **out_resource, TamgaFileClaims *out_claims) {
    if (ed25519_pubkey == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    return tamga_license_file_verify_core(pem, pem_len, ed25519_pubkey, NULL, license_key, now_unix,
                                          out_resource, out_claims);
}

TamgaErrorCode tamga_license_file_verify_at_with_key_set(const char *pem, size_t pem_len,
                                                         const TamgaSigningKeySet *keys,
                                                         const char *license_key, int64_t now_unix,
                                                         TamgaJson **out_resource,
                                                         TamgaFileClaims *out_claims) {
    if (keys == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a key set is required");
    }
    return tamga_license_file_verify_core(pem, pem_len, NULL, keys, license_key, now_unix,
                                          out_resource, out_claims);
}
