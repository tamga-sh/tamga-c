/*
 * ed25519.h -- Ed25519 signature verification (RFC 8032).
 *
 * Verification only. This SDK holds no signing keys: it checks material the
 * Tamga server issued, and adding a signing primitive would create a private
 * key for this code to mishandle without any protocol need for one.
 *
 * That restriction is also what makes the implementation underneath
 * straightforward. Every input to verification -- signature, message, public
 * key -- is public, so none of the constant-time machinery that dominates a
 * signing implementation applies here. See fe25519.h.
 *
 * Ed25519 is used for the licence-file checkout signature (always, regardless
 * of the licence's own scheme) and as one of the four machine-file schemes.
 */
#ifndef TAMGA_CRYPTO_ED25519_H
#define TAMGA_CRYPTO_ED25519_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

#define TAMGA_ED25519_PUBKEY_LEN 32u
#define TAMGA_ED25519_SIG_LEN 64u

/**
 * Verifies `signature` over `message` under `public_key`.
 *
 * Checks performed, in order:
 *   1. the scalar half of the signature is canonical (S < L) -- a
 *      non-canonical S is the classic malleability route, where a third party
 *      turns one valid signature into a different valid-looking one;
 *   2. the public key decodes to a point actually on the curve;
 *   3. the cofactorless equation [S]B = R + [k]A holds, compared by
 *      re-compressing the computed R and matching bytes against the
 *      signature's own R.
 *
 * That last comparison also rejects a non-canonical encoding of R, since the
 * re-compression is always canonical. This matches the acceptance set of
 * ed25519-dalek's `verify`, which is what tamga-rust uses and therefore what
 * the rest of the fleet is interoperable with.
 *
 * Returns false for any malformed input rather than distinguishing the cases:
 * a caller has nothing useful to do with "which part was wrong", and saying
 * so is a small oracle.
 */
TAMGA_NODISCARD bool tamga_ed25519_verify(const unsigned char public_key[TAMGA_ED25519_PUBKEY_LEN],
                                          const unsigned char *message, size_t message_len,
                                          const unsigned char signature[TAMGA_ED25519_SIG_LEN]);

#endif /* TAMGA_CRYPTO_ED25519_H */
