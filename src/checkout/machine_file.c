#include "checkout/machine_file.h"

#include <string.h>

#include "checkout/cert.h"
#include "checkout/pem.h"
#include "crypto/ecdsa.h"
#include "crypto/ed25519.h"
#include "crypto/gcm.h"
#include "crypto/hkdf.h"
#include "crypto/rsa.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"

static const char TAMGA_MACHINE_PEM_BEGIN[] = "-----BEGIN MACHINE FILE-----";
static const char TAMGA_MACHINE_PEM_END[] = "-----END MACHINE FILE-----";

bool tamga_machine_file_ttl_is_valid(int64_t ttl_seconds) {
    return ttl_seconds > 0 && ttl_seconds <= TAMGA_MACHINE_FILE_MAX_TTL_SECONDS;
}

/*
 * The alg suffix each scheme is required to declare, mirroring the server's
 * own mapping.
 *
 * Note that RSA_2048_PKCS1_SIGN and RSA_2048_JWT_RS256 share "rsa-sha256"
 * server-side. That collision is precisely why the scheme is a parameter here
 * rather than something read out of the file: the file's own alg string
 * cannot tell those two apart.
 */
static const char *tamga_machine_alg_suffix(uint32_t scheme) {
    switch (scheme) {
    case (uint32_t)TAMGA_SCHEME_ED25519_SIGN:
        return "ed25519";
    case (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_SIGN:
        return "rsa-sha256";
    case (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN:
        return "rsa-pss-sha256";
    case (uint32_t)TAMGA_SCHEME_ECDSA_P256_SIGN:
        return "ecdsa-p256";
    default:
        return NULL;
    }
}

static bool tamga_machine_check_signature(uint32_t scheme, const unsigned char *pubkey,
                                          size_t pubkey_len, const unsigned char *message,
                                          size_t message_len, const unsigned char *signature,
                                          size_t signature_len) {
    switch (scheme) {
    case (uint32_t)TAMGA_SCHEME_ED25519_SIGN:
        if (pubkey_len != TAMGA_ED25519_PUBKEY_LEN || signature_len != TAMGA_ED25519_SIG_LEN) {
            return false;
        }
        return tamga_ed25519_verify(pubkey, message, message_len, signature);
    case (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_SIGN:
        return tamga_rsa_verify_pkcs1_sha256(pubkey, pubkey_len, message, message_len, signature,
                                             signature_len);
    case (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN:
        return tamga_rsa_verify_pss_sha256(pubkey, pubkey_len, message, message_len, signature,
                                           signature_len);
    case (uint32_t)TAMGA_SCHEME_ECDSA_P256_SIGN:
        return tamga_ecdsa_p256_verify(pubkey, pubkey_len, message, message_len, signature,
                                       signature_len);
    default:
        return false;
    }
}

TamgaErrorCode tamga_machine_file_verify_into(const char *pem, size_t pem_len, uint32_t scheme,
                                              const unsigned char *pubkey, size_t pubkey_len,
                                              const char *license_key, const char *fingerprint,
                                              TamgaJson **out_resource) {
    TamgaErrorCode status;
    char *body = NULL;
    size_t body_len = 0u;
    TamgaCert cert;
    const char *expected_suffix;
    const char *separator;
    size_t prefix_len;
    size_t suffix_len;
    size_t expected_suffix_len;
    bool encrypted;
    unsigned char *signature = NULL;
    size_t signature_len = 0u;
    unsigned char *enc_bytes = NULL;
    size_t enc_len = 0u;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0u;
    size_t plaintext_capacity = 0u;
    TamgaJson *payload = NULL;
    const TamgaJson *data;
    const char *parse_error = NULL;
    TamgaBase64Failure why;

    if (pem == NULL || pubkey == NULL || out_resource == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    *out_resource = NULL;

    if (pubkey_len == 0u || pubkey_len > TAMGA_MAX_REASONABLE_LEN) {
        return tamga_error_set(TAMGA_ERR_LENGTH_INVALID,
                               "public key length is zero or exceeds the accepted maximum");
    }

    /* Rejected before any parsing: the server itself refuses this scheme for
     * machine files, and attempting a JWT-shaped verification here would fail
     * confusingly several layers down. */
    expected_suffix = tamga_machine_alg_suffix(scheme);
    if (expected_suffix == NULL) {
        return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                               "this signing scheme is not valid for a machine file");
    }

    status = tamga_pem_extract(pem, pem_len, TAMGA_MACHINE_PEM_BEGIN, TAMGA_MACHINE_PEM_END, &body,
                               &body_len);
    if (status != TAMGA_OK) {
        return status;
    }

    status = tamga_cert_parse(body, body_len, &cert);
    tamga_string_free(body);
    if (status != TAMGA_OK) {
        return status;
    }

    /* alg is "<encryption>+<signature>". The suffix must be the one the
     * caller's scheme implies -- a mismatch means the file was issued for a
     * different scheme than the licence says. */
    separator = (const char *)memchr(cert.alg, '+', cert.alg_len);
    if (separator == NULL) {
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME, "machine-file algorithm is malformed");
    }
    prefix_len = (size_t)(separator - cert.alg);
    suffix_len = cert.alg_len - prefix_len - 1u;
    expected_suffix_len = strlen(expected_suffix);
    if (suffix_len != expected_suffix_len ||
        memcmp(separator + 1, expected_suffix, expected_suffix_len) != 0) {
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                               "the machine file was signed with a different scheme than the "
                               "licence declares");
    }
    if (prefix_len == 6u && memcmp(cert.alg, "base64", 6u) == 0) {
        encrypted = false;
    } else if (prefix_len == 11u && memcmp(cert.alg, "aes-256-gcm", 11u) == 0) {
        encrypted = true;
    } else {
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                               "unsupported machine-file encryption mode");
    }

    signature = tamga_base64_decode_alloc_why(cert.sig, cert.sig_len, &signature_len, &why);
    if (signature == NULL) {
        tamga_cert_free(&cert);
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the signature");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the signature field is not valid base64");
    }

    /* ⚠️ Over enc's base64 STRING bytes, before decoding -- same rule as the
     * licence file. */
    if (!tamga_machine_check_signature(scheme, pubkey, pubkey_len, (const unsigned char *)cert.enc,
                                       cert.enc_len, signature, signature_len)) {
        tamga_free(signature);
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_SIGNATURE_INVALID,
                               "machine-file signature did not verify");
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

        if (license_key == NULL || fingerprint == NULL) {
            tamga_secure_free(enc_bytes, enc_len);
            tamga_cert_free(&cert);
            return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                                   "this machine file is encrypted and needs both the licence "
                                   "key and the machine fingerprint");
        }
        if (enc_len < (TAMGA_GCM_NONCE_LEN + TAMGA_GCM_TAG_LEN)) {
            tamga_secure_free(enc_bytes, enc_len);
            tamga_cert_free(&cert);
            return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                                   "encrypted payload is too short to contain a nonce and tag");
        }
        if (!tamga_derive_machine_file_key(license_key, fingerprint, key)) {
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
                                   "could not decrypt the machine file; the licence key or "
                                   "fingerprint is wrong, or the payload was altered");
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
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not parse the machine payload");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "machine payload is malformed: %s",
                               (parse_error != NULL) ? parse_error : "unknown");
    }

    data = tamga_json_object_get(payload, "data");
    if (data == NULL || tamga_json_type(data) != TAMGA_JSON_OBJECT) {
        tamga_json_free(payload);
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "the machine payload has no data object");
    }

    *out_resource = tamga_json_clone(data);
    tamga_json_free(payload);
    if (*out_resource == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not copy the machine resource");
    }
    return TAMGA_OK;
}
