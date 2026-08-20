/*
 * machine_file.h -- `.mach` parsing and verification.
 *
 * Same envelope and inner structure as the licence file, with three
 * differences that matter:
 *
 *   - the signature scheme comes from the LICENCE's scheme field, supplied by
 *     the caller, not from the file's own alg string. The file cannot
 *     disambiguate RSA_2048_PKCS1_SIGN from RSA_2048_JWT_RS256 (both map to
 *     the same alg suffix server-side), and letting untrusted input pick a
 *     cryptographic primitive is algorithm confusion regardless;
 *   - the encryption key is derived with a different HKDF salt and binds the
 *     machine fingerprint, so decrypting needs both the licence key and the
 *     target machine's identity;
 *   - there is no signed expiry claim. That is specific to the licence file's
 *     v2 payload.
 */
#ifndef TAMGA_CHECKOUT_MACHINE_FILE_H
#define TAMGA_CHECKOUT_MACHINE_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tamga.h"
#include "tamga_compat.h"
#include "util/json.h"

/** Maximum ttl the server accepts for a machine-file checkout: 365 days. */
#define TAMGA_MACHINE_FILE_MAX_TTL_SECONDS 31536000

/**
 * Mirrors the server's ttl validation (> 0 and <= 365 days) so a caller finds
 * out before the round trip rather than only via a 422.
 */
TAMGA_NODISCARD bool tamga_machine_file_ttl_is_valid(int64_t ttl_seconds);

/**
 * Verifies a machine file and yields the embedded machine resource.
 *
 * `scheme` must be a TamgaScheme value. `pubkey` is the key matching it: 32
 * raw bytes for Ed25519, a SubjectPublicKeyInfo DER blob for either RSA
 * variant, or a 65-byte uncompressed point (or SPKI) for ECDSA.
 *
 * `license_key` and `fingerprint` are needed only for an encrypted file.
 */
TAMGA_NODISCARD TamgaErrorCode tamga_machine_file_verify_into(
    const char *pem, size_t pem_len, uint32_t scheme, const unsigned char *pubkey,
    size_t pubkey_len, const char *license_key, const char *fingerprint, TamgaJson **out_resource);

#endif /* TAMGA_CHECKOUT_MACHINE_FILE_H */
