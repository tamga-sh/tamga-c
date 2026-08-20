/*
 * ecdsa.h -- ECDSA P-256 / SHA-256 signature verification.
 *
 * One of the four machine-file signature schemes.
 *
 * ⚠️ Curve pinning is the whole reason this file exists as a separate layer
 * from p256.c. A generic "parse the key, then verify" implementation runs its
 * arithmetic on whatever curve the key claims to belong to. An
 * attacker-supplied SubjectPublicKeyInfo that declares secp256k1 while
 * carrying a point of the right length is accepted by several widely used
 * parsers, and a cross-repo audit of this SDK family found exactly that gap
 * live in three of its from-scratch implementations. Here the algorithm OID
 * and the curve OID are both compared explicitly, and the arithmetic is
 * hardwired to P-256 regardless of what the encoding says.
 */
#ifndef TAMGA_CRYPTO_ECDSA_H
#define TAMGA_CRYPTO_ECDSA_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

/**
 * Verifies an ECDSA P-256 / SHA-256 signature over `message`.
 *
 * `public_key` is either a raw 65-byte uncompressed point (0x04 || X || Y),
 * which is the convention the machine-file format uses, or a
 * SubjectPublicKeyInfo DER blob. The DER form has both its algorithm and
 * curve OIDs checked; the raw form carries no curve claim at all, so the
 * caller's choice of scheme is what selects P-256.
 *
 * `signature` is the ASN.1 DER encoding, SEQUENCE { INTEGER r, INTEGER s }.
 */
TAMGA_NODISCARD bool tamga_ecdsa_p256_verify(const unsigned char *public_key,
                                             size_t public_key_len,
                                             const unsigned char *message, size_t message_len,
                                             const unsigned char *signature,
                                             size_t signature_len);

#endif /* TAMGA_CRYPTO_ECDSA_H */
