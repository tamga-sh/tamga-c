#include "checkout/license_file.h"

#include <string.h>

#include "checkout/cert.h"
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

/*
 * How much clock skew to tolerate on the expiry check.
 *
 * Deliberately small. The client's clock is under the adversary's control in
 * this threat model, so a generous allowance is simply a free extension on
 * every expired file. Sixty seconds covers ordinary NTP drift and nothing
 * more.
 */
#define TAMGA_CLOCK_SKEW_TOLERANCE_SECONDS 60

static TamgaErrorCode tamga_license_read_claims(const TamgaJson *meta, TamgaLicenseClaims *out) {
    const TamgaJson *exp;
    int64_t value = 0;

    out->issued_at = 0;
    out->has_expiry = false;
    out->expiry = 0;

    if (meta == NULL || tamga_json_type(meta) != TAMGA_JSON_OBJECT) {
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "the signed payload has no claims object");
    }
    if (tamga_json_as_int(tamga_json_object_get(meta, "iat"), &value)) {
        out->issued_at = value;
    }
    exp = tamga_json_object_get(meta, "exp");
    /* An absent exp means the file never expires -- checkout was requested
     * without a ttl. An explicit null means the same thing. */
    if (exp != NULL && !tamga_json_is_null(exp)) {
        if (!tamga_json_as_int(exp, &value)) {
            return tamga_error_set(TAMGA_ERR_INVALID_JSON,
                                   "the signed exp claim is not an integer");
        }
        out->has_expiry = true;
        out->expiry = value;
    }
    return TAMGA_OK;
}

TamgaErrorCode tamga_license_file_verify_at(const char *pem, size_t pem_len,
                                            const unsigned char ed25519_pubkey[32],
                                            const char *license_key, int64_t now_unix,
                                            TamgaJson **out_resource,
                                            TamgaLicenseClaims *out_claims) {
    TamgaErrorCode status;
    char *body = NULL;
    size_t body_len = 0u;
    TamgaCert cert;
    unsigned char *signature = NULL;
    size_t signature_len = 0u;
    unsigned char *enc_bytes = NULL;
    size_t enc_len = 0u;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0u;
    /* Tracked separately from plaintext_len because AES-GCM shortens the
     * value on the way out (the tag is not plaintext) while the buffer that
     * has to be freed is the one that was allocated. */
    size_t plaintext_capacity = 0u;
    TamgaJson *payload = NULL;
    const TamgaJson *data;
    TamgaLicenseClaims claims;
    const char *parse_error = NULL;
    TamgaBase64Failure why;
    bool encrypted;

    if (pem == NULL || ed25519_pubkey == NULL || out_resource == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    *out_resource = NULL;

    status = tamga_pem_extract(pem, pem_len, TAMGA_LICENSE_PEM_BEGIN, TAMGA_LICENSE_PEM_END, &body,
                               &body_len);
    if (status != TAMGA_OK) {
        return status;
    }

    status = tamga_cert_parse(body, body_len, &cert);
    tamga_string_free(body);
    if (status != TAMGA_OK) {
        return status;
    }

    /* Exactly two algorithm strings are legal, matched in full and by length.
     * A prefix or substring match would let "base64+ed25519+v2+anything"
     * through, and a strcmp would let an interior NUL do the same. */
    if (tamga_cert_alg_equals(&cert, TAMGA_ALG_PLAIN, sizeof(TAMGA_ALG_PLAIN) - 1u)) {
        encrypted = false;
    } else if (tamga_cert_alg_equals(&cert, TAMGA_ALG_ENCRYPTED,
                                     sizeof(TAMGA_ALG_ENCRYPTED) - 1u)) {
        encrypted = true;
    } else {
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                               "unsupported licence-file algorithm; only offline format v2 "
                               "is accepted, and there is no v1 fallback");
    }

    signature = tamga_base64_decode_alloc_why(cert.sig, cert.sig_len, &signature_len, &why);
    if (signature == NULL) {
        tamga_cert_free(&cert);
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the signature");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the signature field is not valid base64");
    }
    if (signature_len != TAMGA_ED25519_SIG_LEN) {
        tamga_free(signature);
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_SIGNATURE_INVALID, "signature is not the expected length");
    }

    /*
     * ⚠️ Verify against enc's base64 STRING bytes, before decoding it.
     * Decoding first and verifying the decoded bytes is the classic mistake
     * with this format and fails against every real server-issued file.
     */
    if (!tamga_ed25519_verify(ed25519_pubkey, (const unsigned char *)cert.enc, cert.enc_len,
                              signature)) {
        tamga_free(signature);
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_SIGNATURE_INVALID,
                               "licence-file signature did not verify");
    }
    tamga_free(signature);

    enc_bytes = tamga_base64_decode_alloc_why(cert.enc, cert.enc_len, &enc_len, &why);
    if (enc_bytes == NULL) {
        tamga_cert_free(&cert);
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the payload");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the enc field is not valid base64");
    }

    if (!encrypted) {
        plaintext = enc_bytes;
        plaintext_len = enc_len;
        plaintext_capacity = enc_len;
        enc_bytes = NULL;
    } else {
        unsigned char key[TAMGA_FILE_KEY_LEN];

        if (license_key == NULL) {
            tamga_secure_free(enc_bytes, enc_len);
            tamga_cert_free(&cert);
            return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                                   "this licence file is encrypted and needs the licence key");
        }
        /* nonce(12) || ciphertext || tag(16): at least 28 bytes even for an
         * empty plaintext. */
        if (enc_len < (TAMGA_GCM_NONCE_LEN + TAMGA_GCM_TAG_LEN)) {
            tamga_secure_free(enc_bytes, enc_len);
            tamga_cert_free(&cert);
            return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                                   "encrypted payload is too short to contain a nonce and tag");
        }
        if (!tamga_derive_license_file_key(license_key, key)) {
            tamga_secure_free(enc_bytes, enc_len);
            tamga_cert_free(&cert);
            return tamga_error_set(TAMGA_ERR_UNKNOWN, "key derivation failed");
        }

        plaintext_capacity = enc_len - TAMGA_GCM_NONCE_LEN;
        plaintext_len = plaintext_capacity;
        plaintext = (unsigned char *)tamga_malloc(plaintext_capacity);
        if (plaintext == NULL) {
            tamga_secure_zero(key, sizeof(key));
            tamga_secure_free(enc_bytes, enc_len);
            tamga_cert_free(&cert);
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the payload");
        }

        if (!tamga_gcm_open(key, enc_bytes, NULL, 0u, &enc_bytes[TAMGA_GCM_NONCE_LEN],
                            enc_len - TAMGA_GCM_NONCE_LEN, plaintext, &plaintext_len)) {
            tamga_secure_zero(key, sizeof(key));
            tamga_secure_free(plaintext, plaintext_capacity);
            tamga_secure_free(enc_bytes, enc_len);
            tamga_cert_free(&cert);
            return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                                   "could not decrypt the licence file; the licence key is "
                                   "wrong or the payload was altered");
        }
        tamga_secure_zero(key, sizeof(key));
        tamga_secure_free(enc_bytes, enc_len);
        enc_bytes = NULL;
    }

    payload = tamga_json_parse((const char *)plaintext, plaintext_len, &parse_error);
    tamga_secure_free(plaintext, plaintext_capacity);
    tamga_cert_free(&cert);

    if (payload == NULL) {
        if (tamga_json_error_is_out_of_memory(parse_error)) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not parse the licence payload");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "licence payload is malformed: %s",
                               (parse_error != NULL) ? parse_error : "unknown");
    }

    status = tamga_license_read_claims(tamga_json_object_get(payload, "meta"), &claims);
    if (status != TAMGA_OK) {
        tamga_json_free(payload);
        return status;
    }

    /*
     * The signature proves the file is authentic. It does not prove it is
     * still valid -- that is this check, and skipping it is exactly what made
     * v1 files permanent.
     */
    if (claims.has_expiry && ((now_unix - TAMGA_CLOCK_SKEW_TOLERANCE_SECONDS) > claims.expiry)) {
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
