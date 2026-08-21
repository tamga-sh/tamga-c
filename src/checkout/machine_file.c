#include "checkout/machine_file.h"

#include <string.h>

#include "checkout/cert.h"
#include "checkout/claims.h"
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

/*
 * The offline-format version every machine file must declare, as the LAST
 * `+`-separated segment of `alg`.
 *
 * A v1 file is refused outright, with no fallback, for the same two reasons
 * the licence file refuses one: its payload carried no signed `exp`, so a
 * time-limited file was cryptographically valid forever, and it derived its
 * AES key by zero-padding the licence key instead of running HKDF. Accepting
 * one silently reinstates both weaknesses.
 */
static const char TAMGA_MACHINE_ALG_VERSION[] = "v2";

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

/*
 * Splits `alg` into its three parts:
 *
 *     <encoding>+<signing suffix>+v2
 *
 * The delimiters are the FIRST '+' and the LAST '+', and nothing else will
 * do. Both outer parts contain hyphens of their own ("aes-256-gcm",
 * "rsa-pss-sha256"), and the encoding prefix is not a fixed width, so:
 *
 *   - splitting once and comparing the whole remainder against the signing
 *     suffix rejects every real file, because the remainder still carries
 *     "+v2". That was this function's predecessor;
 *   - a substring/"contains" test accepts "base64+ed25519+v3" and
 *     "xbase64+ed25519+v2junk" as readily as the real thing.
 *
 * `alg_len` is authoritative rather than any NUL inside it -- see the note on
 * TamgaCert::alg_len -- so every comparison here is length-aware.
 *
 * Returns false when the string is not three `+`-separated parts ending in
 * exactly "v2"; the two spans are written only on success.
 */
static bool tamga_machine_alg_split(const char *alg, size_t alg_len, const char **out_prefix,
                                    size_t *out_prefix_len, const char **out_suffix,
                                    size_t *out_suffix_len) {
    const char *first;
    const char *last = NULL;
    size_t version_len;
    size_t i;

    if (alg == NULL || alg_len == 0u) {
        return false;
    }
    first = (const char *)memchr(alg, '+', alg_len);
    if (first == NULL) {
        return false;
    }
    /* memrchr is a GNU extension, and this has to build with anything C11. */
    for (i = alg_len; i > 0u; i--) {
        if (alg[i - 1u] == '+') {
            last = &alg[i - 1u];
            break;
        }
    }
    /* `last` cannot be NULL once `first` is not, but say so rather than
     * leaving the reader -- or the analyser -- to prove it. One '+' only means
     * there is no version segment at all: a v1 file, or something shaped like
     * one. */
    if (last == NULL || last == first) {
        return false;
    }

    version_len = alg_len - (size_t)(last - alg) - 1u;
    if (version_len != (sizeof(TAMGA_MACHINE_ALG_VERSION) - 1u) ||
        memcmp(last + 1, TAMGA_MACHINE_ALG_VERSION, version_len) != 0) {
        return false;
    }

    *out_prefix = alg;
    *out_prefix_len = (size_t)(first - alg);
    *out_suffix = first + 1;
    *out_suffix_len = (size_t)(last - first) - 1u;
    return true;
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

/*
 * Opens the encrypted form of `enc`.
 *
 * ⚠️ The encrypted payload is "<nonce_b64>.<cipher_b64>": two halves, each
 * base64-encoded SEPARATELY, joined by a literal '.'. It is NOT one base64
 * blob of nonce||ciphertext||tag, and slicing a 12-byte nonce off the front of
 * a single decode -- which is what this SDK did, and what the server's own
 * stale doc comment still describes -- cannot open a single real file. The
 * ciphertext half already carries the 16-byte GCM tag.
 *
 * Called only after the signature over the whole `enc` string has verified, so
 * nothing here decodes bytes an attacker chose.
 */
static TamgaErrorCode tamga_machine_open_encrypted(const char *enc, size_t enc_len,
                                                   const char *license_key, const char *fingerprint,
                                                   unsigned char **out_plaintext,
                                                   size_t *out_plaintext_len,
                                                   size_t *out_plaintext_capacity) {
    unsigned char key[TAMGA_FILE_KEY_LEN];
    const char *dot;
    const char *cipher_b64;
    size_t nonce_b64_len;
    size_t cipher_b64_len;
    unsigned char *nonce = NULL;
    size_t nonce_len = 0u;
    unsigned char *cipher = NULL;
    size_t cipher_len = 0u;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0u;
    size_t plaintext_capacity = 0u;
    TamgaBase64Failure why;
    bool opened;

    *out_plaintext = NULL;
    *out_plaintext_len = 0u;
    *out_plaintext_capacity = 0u;

    if (license_key == NULL || fingerprint == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "this machine file is encrypted and needs both the licence "
                               "key and the machine fingerprint");
    }

    dot = (const char *)memchr(enc, '.', enc_len);
    if (dot == NULL) {
        return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                               "an encrypted machine file's payload must be "
                               "\"<nonce>.<ciphertext>\"; this one has no separator");
    }
    nonce_b64_len = (size_t)(dot - enc);
    cipher_b64 = dot + 1;
    cipher_b64_len = enc_len - nonce_b64_len - 1u;
    if (nonce_b64_len == 0u || cipher_b64_len == 0u) {
        return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                               "an encrypted machine file's payload has an empty half");
    }
    /* Exactly one separator. Neither half is base64 that could legitimately
     * contain a '.', so a second one means this is not the format it claims. */
    if (memchr(cipher_b64, '.', cipher_b64_len) != NULL) {
        return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                               "an encrypted machine file's payload has more than one separator");
    }

    nonce = tamga_base64_decode_alloc_why(enc, nonce_b64_len, &nonce_len, &why);
    if (nonce == NULL) {
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the nonce");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the nonce is not valid base64");
    }
    if (nonce_len != TAMGA_GCM_NONCE_LEN) {
        tamga_secure_free(nonce, nonce_len);
        return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED, "the nonce is not 12 bytes");
    }

    cipher = tamga_base64_decode_alloc_why(cipher_b64, cipher_b64_len, &cipher_len, &why);
    if (cipher == NULL) {
        tamga_secure_free(nonce, nonce_len);
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the ciphertext");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the ciphertext is not valid base64");
    }
    /* Strictly greater: the tag alone would decrypt to an empty payload, which
     * is never valid JSON, and it would ask for a zero-length buffer. */
    if (cipher_len <= TAMGA_GCM_TAG_LEN) {
        tamga_secure_free(cipher, cipher_len);
        tamga_secure_free(nonce, nonce_len);
        return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                               "the ciphertext is too short to contain a tag and a payload");
    }

    if (!tamga_derive_machine_file_key(license_key, fingerprint, key)) {
        tamga_secure_free(cipher, cipher_len);
        tamga_secure_free(nonce, nonce_len);
        return tamga_error_set(TAMGA_ERR_UNKNOWN, "key derivation failed");
    }

    plaintext_capacity = cipher_len - TAMGA_GCM_TAG_LEN;
    plaintext_len = plaintext_capacity;
    plaintext = (unsigned char *)tamga_malloc(plaintext_capacity);
    if (plaintext == NULL) {
        tamga_secure_zero(key, sizeof(key));
        tamga_secure_free(cipher, cipher_len);
        tamga_secure_free(nonce, nonce_len);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the payload");
    }

    opened = tamga_gcm_open(key, nonce, NULL, 0u, cipher, cipher_len, plaintext, &plaintext_len);
    tamga_secure_zero(key, sizeof(key));
    tamga_secure_free(cipher, cipher_len);
    tamga_secure_free(nonce, nonce_len);
    if (!opened) {
        tamga_secure_free(plaintext, plaintext_capacity);
        return tamga_error_set(TAMGA_ERR_DECRYPTION_FAILED,
                               "could not decrypt the machine file; the licence key or "
                               "fingerprint is wrong, or the payload was altered");
    }

    *out_plaintext = plaintext;
    *out_plaintext_len = plaintext_len;
    *out_plaintext_capacity = plaintext_capacity;
    return TAMGA_OK;
}

TamgaErrorCode tamga_machine_file_verify_at(const char *pem, size_t pem_len, uint32_t scheme,
                                            const unsigned char *pubkey, size_t pubkey_len,
                                            const char *license_key, const char *fingerprint,
                                            int64_t now_unix, TamgaJson **out_resource,
                                            TamgaFileClaims *out_claims) {
    TamgaErrorCode status;
    char *body = NULL;
    size_t body_len = 0u;
    TamgaCert cert;
    const char *expected_suffix;
    const char *alg_prefix = NULL;
    size_t alg_prefix_len = 0u;
    const char *alg_suffix = NULL;
    size_t alg_suffix_len = 0u;
    size_t expected_suffix_len;
    bool encrypted;
    unsigned char *signature = NULL;
    size_t signature_len = 0u;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0u;
    size_t plaintext_capacity = 0u;
    TamgaJson *payload = NULL;
    const TamgaJson *data;
    TamgaFileClaims claims;
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

    /* alg is "<encoding>+<signing suffix>+v2". */
    if (!tamga_machine_alg_split(cert.alg, cert.alg_len, &alg_prefix, &alg_prefix_len, &alg_suffix,
                                 &alg_suffix_len)) {
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                               "unsupported machine-file algorithm; only offline format v2 "
                               "is accepted, and there is no v1 fallback");
    }
    /* The suffix must be the one the caller's scheme implies -- a mismatch
     * means the file was issued for a different scheme than the licence says.
     * This is a cross-check on the caller's scheme, never a source for it. */
    expected_suffix_len = strlen(expected_suffix);
    if (alg_suffix_len != expected_suffix_len ||
        memcmp(alg_suffix, expected_suffix, expected_suffix_len) != 0) {
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                               "the machine file was signed with a different scheme than the "
                               "licence declares");
    }
    if (alg_prefix_len == 6u && memcmp(alg_prefix, "base64", 6u) == 0) {
        encrypted = false;
    } else if (alg_prefix_len == 11u && memcmp(alg_prefix, "aes-256-gcm", 11u) == 0) {
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
     * licence file. Verify, THEN split, THEN decode, THEN decrypt: nothing
     * below this point parses bytes an attacker chose. */
    if (!tamga_machine_check_signature(scheme, pubkey, pubkey_len, (const unsigned char *)cert.enc,
                                       cert.enc_len, signature, signature_len)) {
        tamga_free(signature);
        tamga_cert_free(&cert);
        return tamga_error_set(TAMGA_ERR_SIGNATURE_INVALID,
                               "machine-file signature did not verify");
    }
    tamga_free(signature);

    if (!encrypted) {
        /* A plain payload is one base64 blob, with no separator. Branching on
         * the alg prefix rather than on whether a '.' happens to be present
         * keeps the file's shape a consequence of what it declared. */
        plaintext = tamga_base64_decode_alloc_why(cert.enc, cert.enc_len, &plaintext_len, &why);
        if (plaintext == NULL) {
            tamga_cert_free(&cert);
            if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
                return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the payload");
            }
            return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the enc field is not valid base64");
        }
        plaintext_capacity = plaintext_len;
    } else {
        status = tamga_machine_open_encrypted(cert.enc, cert.enc_len, license_key, fingerprint,
                                              &plaintext, &plaintext_len, &plaintext_capacity);
        if (status != TAMGA_OK) {
            tamga_cert_free(&cert);
            return status;
        }
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

    status = tamga_claims_read(tamga_json_object_get(payload, "meta"), &claims);
    if (status != TAMGA_OK) {
        tamga_json_free(payload);
        return status;
    }

    /*
     * A machine file now carries the same signed claims a licence file does,
     * and its `exp` is enforced through the same helper and the same skew
     * tolerance. Before this, a machine file verified forever: the signature
     * proves it is authentic, never that it is still current.
     *
     * `exp` is legitimately absent when the checkout asked for no ttl, and
     * that file genuinely never expires -- absence is not an error.
     */
    if (tamga_claims_are_expired(&claims, now_unix)) {
        tamga_json_free(payload);
        return tamga_error_set(TAMGA_ERR_EXPIRED,
                               "the machine file is authentic but expired; check out a fresh one");
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
    if (out_claims != NULL) {
        *out_claims = claims;
    }
    return TAMGA_OK;
}
