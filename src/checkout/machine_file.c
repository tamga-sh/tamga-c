#include "checkout/machine_file.h"

#include <string.h>

#include "checkout/cert.h"
#include "checkout/claims.h"
#include "checkout/key_set.h"
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
 * ⚠️ Called AFTER the signature has verified on the single-key path, and
 * BEFORE it on the key-set path -- there, the `kid` that names the key lives
 * inside this very payload, so there is no way round it. The bytes are
 * attacker-chosen in that second case, which is why nothing below leaves the
 * strict base64 decoder and the AEAD: an altered ciphertext fails the GCM tag,
 * and the only value read out of the plaintext before verification is the
 * `kid`, which selects from keys the caller already trusts.
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

/* Unwraps the PEM envelope, parses the certificate, and cross-checks its `alg`
 * against the scheme the CALLER supplied -- never the other way round. */
static TamgaErrorCode tamga_machine_open(const char *pem, size_t pem_len, uint32_t scheme,
                                         TamgaCert *out_cert, bool *out_encrypted) {
    TamgaErrorCode status;
    char *body = NULL;
    size_t body_len = 0u;
    const char *expected_suffix;
    size_t expected_suffix_len;
    const char *alg_prefix = NULL;
    size_t alg_prefix_len = 0u;
    const char *alg_suffix = NULL;
    size_t alg_suffix_len = 0u;

    /* Emptied first, because the scheme check below returns before anything
     * would otherwise touch it. A caller reading a certificate back out of a
     * failed call gets an empty one rather than an indeterminate one, and the
     * function has no path that leaves its out-parameter unwritten. */
    memset(out_cert, 0, sizeof(*out_cert));

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

    status = tamga_cert_parse(body, body_len, out_cert);
    tamga_string_free(body);
    if (status != TAMGA_OK) {
        return status;
    }

    /* alg is "<encoding>+<signing suffix>+v2". */
    if (!tamga_machine_alg_split(out_cert->alg, out_cert->alg_len, &alg_prefix, &alg_prefix_len,
                                 &alg_suffix, &alg_suffix_len)) {
        tamga_cert_free(out_cert);
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
        tamga_cert_free(out_cert);
        return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                               "the machine file was signed with a different scheme than the "
                               "licence declares");
    }
    if (alg_prefix_len == 6u && memcmp(alg_prefix, "base64", 6u) == 0) {
        *out_encrypted = false;
        return TAMGA_OK;
    }
    if (alg_prefix_len == 11u && memcmp(alg_prefix, "aes-256-gcm", 11u) == 0) {
        *out_encrypted = true;
        return TAMGA_OK;
    }
    tamga_cert_free(out_cert);
    return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                           "unsupported machine-file encryption mode");
}

/*
 * Decodes `enc` into the signed payload's bytes.
 *
 * `*out_capacity` is what was ALLOCATED and `*out_len` what was written; the
 * two differ for an encrypted file because the GCM tag is not plaintext, and
 * every free of this buffer must use the capacity or leave licence-key-derived
 * plaintext behind in freed memory.
 */
static TamgaErrorCode tamga_machine_decode_payload(const TamgaCert *cert, bool encrypted,
                                                   const char *license_key, const char *fingerprint,
                                                   unsigned char **out_plaintext, size_t *out_len,
                                                   size_t *out_capacity) {
    TamgaBase64Failure why;

    *out_plaintext = NULL;
    *out_len = 0u;
    *out_capacity = 0u;

    if (encrypted) {
        return tamga_machine_open_encrypted(cert->enc, cert->enc_len, license_key, fingerprint,
                                            out_plaintext, out_len, out_capacity);
    }
    /* A plain payload is one base64 blob, with no separator. Branching on
     * the alg prefix rather than on whether a '.' happens to be present
     * keeps the file's shape a consequence of what it declared. */
    *out_plaintext = tamga_base64_decode_alloc_why(cert->enc, cert->enc_len, out_len, &why);
    if (*out_plaintext == NULL) {
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the payload");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the enc field is not valid base64");
    }
    *out_capacity = *out_len;
    return TAMGA_OK;
}

/* Parses the signed payload, keeping "this machine is out of memory" distinct
 * from "your machine file is corrupt". */
static TamgaErrorCode tamga_machine_parse_payload(const unsigned char *plaintext, size_t len,
                                                  TamgaJson **out_payload) {
    const char *parse_error = NULL;

    *out_payload = tamga_json_parse((const char *)plaintext, len, &parse_error);
    if (*out_payload != NULL) {
        return TAMGA_OK;
    }
    if (tamga_json_error_is_out_of_memory(parse_error)) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not parse the machine payload");
    }
    return tamga_error_set(TAMGA_ERR_INVALID_JSON, "machine payload is malformed: %s",
                           (parse_error != NULL) ? parse_error : "unknown");
}

/* Everything after the signature has verified. Consumes `payload` on every
 * path. */
static TamgaErrorCode tamga_machine_finish(TamgaJson *payload, int64_t now_unix,
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

/*
 * The shared body of both entry points. Exactly one of `pubkey` and `keys` is
 * non-NULL, and which one decides the ORDER of the two steps below -- see
 * license_file.c's core, which makes the same trade for the same reason.
 */
static TamgaErrorCode
tamga_machine_file_verify_core(const char *pem, size_t pem_len, uint32_t scheme,
                               const unsigned char *pubkey, size_t pubkey_len,
                               const TamgaSigningKeySet *keys, const char *license_key,
                               const char *fingerprint, int64_t now_unix, TamgaJson **out_resource,
                               TamgaFileClaims *out_claims) {
    TamgaErrorCode status;
    TamgaCert cert;
    bool encrypted = false;
    unsigned char *signature = NULL;
    size_t signature_len = 0u;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0u;
    size_t plaintext_capacity = 0u;
    TamgaJson *payload = NULL;
    unsigned char selected[TAMGA_ED25519_PUBKEY_LEN];
    const unsigned char *verifier = pubkey;
    size_t verifier_len = pubkey_len;
    TamgaBase64Failure why;

    if (pem == NULL || out_resource == NULL || (pubkey == NULL && keys == NULL)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    *out_resource = NULL;

    if (keys == NULL && (pubkey_len == 0u || pubkey_len > TAMGA_MAX_REASONABLE_LEN)) {
        return tamga_error_set(TAMGA_ERR_LENGTH_INVALID,
                               "public key length is zero or exceeds the accepted maximum");
    }

    status = tamga_machine_open(pem, pem_len, scheme, &cert, &encrypted);
    if (status != TAMGA_OK) {
        return status;
    }

    signature = tamga_base64_decode_alloc_why(cert.sig, cert.sig_len, &signature_len, &why);
    if (signature == NULL) {
        tamga_cert_free(&cert);
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the signature");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64, "the signature field is not valid base64");
    }

    if (keys != NULL) {
        status = tamga_machine_decode_payload(&cert, encrypted, license_key, fingerprint,
                                              &plaintext, &plaintext_len, &plaintext_capacity);
        if (status == TAMGA_OK) {
            status = tamga_machine_parse_payload(plaintext, plaintext_len, &payload);
            /* At the CAPACITY it was allocated with, not the length GCM
             * reported -- the difference is the tag. */
            tamga_secure_free(plaintext, plaintext_capacity);
        }
        if (status == TAMGA_OK) {
            status = tamga_key_set_select(
                keys, tamga_claims_key_id(tamga_json_object_get(payload, "meta")), selected);
            verifier = selected;
            verifier_len = sizeof(selected);
        }
    }

    /* ⚠️ Over enc's base64 STRING bytes, before decoding -- same rule as the
     * licence file. On the single-key path below nothing has yet parsed bytes
     * an attacker chose. */
    if (status == TAMGA_OK && !tamga_machine_check_signature(
                                  scheme, verifier, verifier_len, (const unsigned char *)cert.enc,
                                  cert.enc_len, signature, signature_len)) {
        status =
            tamga_error_set(TAMGA_ERR_SIGNATURE_INVALID, "machine-file signature did not verify");
    }
    tamga_free(signature);

    if (status == TAMGA_OK && payload == NULL) {
        status = tamga_machine_decode_payload(&cert, encrypted, license_key, fingerprint,
                                              &plaintext, &plaintext_len, &plaintext_capacity);
        if (status == TAMGA_OK) {
            status = tamga_machine_parse_payload(plaintext, plaintext_len, &payload);
            tamga_secure_free(plaintext, plaintext_capacity);
        }
    }
    tamga_cert_free(&cert);

    if (status != TAMGA_OK) {
        tamga_json_free(payload);
        return status;
    }
    return tamga_machine_finish(payload, now_unix, out_resource, out_claims);
}

TamgaErrorCode tamga_machine_file_verify_at(const char *pem, size_t pem_len, uint32_t scheme,
                                            const unsigned char *pubkey, size_t pubkey_len,
                                            const char *license_key, const char *fingerprint,
                                            int64_t now_unix, TamgaJson **out_resource,
                                            TamgaFileClaims *out_claims) {
    if (pubkey == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    return tamga_machine_file_verify_core(pem, pem_len, scheme, pubkey, pubkey_len, NULL,
                                          license_key, fingerprint, now_unix, out_resource,
                                          out_claims);
}

TamgaErrorCode
tamga_machine_file_verify_at_with_key_set(const char *pem, size_t pem_len, uint32_t scheme,
                                          const TamgaSigningKeySet *keys, const char *license_key,
                                          const char *fingerprint, int64_t now_unix,
                                          TamgaJson **out_resource, TamgaFileClaims *out_claims) {
    if (keys == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a key set is required");
    }
    /*
     * Ed25519 only, and the refusal is deliberately not TAMGA_ERR_UNSUPPORTED_
     * SCHEME: RSA and ECDSA are perfectly good machine-file schemes, and
     * tamga_machine_file_verify() takes them. What cannot be done is SELECTING
     * their key by `kid`, because the server computes that claim from
     * `account.ed25519_public_key` whatever scheme actually signed the bytes --
     * so for those files the claim names a key that had no part in the
     * signature. Saying so precisely is the difference between a caller
     * reaching for the right entry point and a caller believing its file is
     * unsupported.
     */
    if (scheme != (uint32_t)TAMGA_SCHEME_ED25519_SIGN) {
        /* A scheme this library refuses outright stays refused the same way on
         * both paths -- NONE and JWT_RS256 are not "a kid problem". */
        if (tamga_machine_alg_suffix(scheme) == NULL) {
            return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME,
                                   "this signing scheme is not valid for a machine file");
        }
        return tamga_error_set(TAMGA_ERR_KEY_ID_NOT_APPLICABLE,
                               "a machine file's kid names the account's Ed25519 key whatever "
                               "scheme signed the file, so it cannot select an RSA or ECDSA "
                               "key; verify this one with the account's own key for its "
                               "algorithm");
    }
    return tamga_machine_file_verify_core(pem, pem_len, scheme, NULL, 0u, keys, license_key,
                                          fingerprint, now_unix, out_resource, out_claims);
}
