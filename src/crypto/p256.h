/*
 * p256.h -- NIST P-256 group arithmetic, for ECDSA verification.
 *
 * Same posture as the Ed25519 code: verification only, all inputs public, so
 * no constant-time obligation. Arithmetic is Montgomery over a generic
 * 256-bit odd modulus, which serves both the field (mod p) and the scalars
 * (mod n) without a second implementation, and avoids hand-writing the
 * Solinas fast-reduction chain for p -- a sequence of limb rearrangements
 * that is easy to mistype and hard to review.
 */
#ifndef TAMGA_CRYPTO_P256_H
#define TAMGA_CRYPTO_P256_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tamga_compat.h"

/**
 * Verifies an ECDSA P-256 / SHA-256 signature.
 *
 * `public_x` and `public_y` are the affine coordinates as 32-byte big-endian
 * values; `r` and `s` likewise. `digest` is the 32-byte SHA-256 of the
 * message.
 *
 * Returns false unless the point is on the curve, both scalars are in
 * [1, n-1], and the verification equation holds.
 */
TAMGA_NODISCARD bool tamga_p256_verify(const unsigned char public_x[32],
                                       const unsigned char public_y[32],
                                       const unsigned char digest[32],
                                       const unsigned char r[32],
                                       const unsigned char s[32]);

#endif /* TAMGA_CRYPTO_P256_H */
