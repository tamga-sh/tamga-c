/*
 * rsa.h -- RSA signature verification, PKCS#1 v1.5 and PSS, both over
 * SHA-256.
 *
 * Verification only, and only with the public key: this library never holds
 * an RSA private key. That is why there is no signing entry point here and
 * why tamga_offline_proof_generate() is documented as a deliberate
 * non-implementation rather than a gap.
 *
 * Used for two of the four machine-file signature schemes, and for the
 * machine offline proof -- which is always RSA-2048 PKCS#1 v1.5 / SHA-256
 * regardless of the licence's own scheme.
 *
 * Keys are supplied as raw SubjectPublicKeyInfo DER, matching the convention
 * the rest of the fleet uses. Modulus sizes from 2048 to 8192 bits are
 * accepted, which is the range the reference implementation's verifier
 * (aws-lc-rs RSA_PKCS1_2048_8192_SHA256) accepts; anything smaller is refused
 * rather than verified weakly.
 */
#ifndef TAMGA_CRYPTO_RSA_H
#define TAMGA_CRYPTO_RSA_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

/**
 * Verifies an RSASSA-PKCS1-v1_5 signature over SHA-256(message).
 *
 * The expected padded block is constructed and compared in full, rather than
 * parsed out of the recovered value. Parsing is how Bleichenbacher-style
 * forgeries get in: a lenient parser that skips over the padding and looks
 * for the digest accepts blocks that were never produced by the private key.
 */
TAMGA_NODISCARD bool tamga_rsa_verify_pkcs1_sha256(const unsigned char *spki, size_t spki_len,
                                                   const unsigned char *message,
                                                   size_t message_len,
                                                   const unsigned char *signature,
                                                   size_t signature_len);

/**
 * Verifies an RSASSA-PSS signature over SHA-256(message), with MGF1-SHA256
 * and a salt length equal to the digest length -- the parameters the server
 * signs with and the reference verifier requires.
 */
TAMGA_NODISCARD bool tamga_rsa_verify_pss_sha256(const unsigned char *spki, size_t spki_len,
                                                 const unsigned char *message,
                                                 size_t message_len,
                                                 const unsigned char *signature,
                                                 size_t signature_len);

#endif /* TAMGA_CRYPTO_RSA_H */
