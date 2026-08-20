/*
 * hkdf.h -- RFC 5869 HKDF-SHA256, and the two derivations the Tamga offline
 * file formats are built on.
 *
 * ⚠️ The two derivations are NOT interchangeable, and swapping them produces
 * code that compiles, looks right, and silently decrypts nothing:
 *
 *   licence file: salt "tamga:license-file-key-v1", info "license-file"
 *   machine file: salt "tamga:machine-file-key-v1", info <machine fingerprint>
 *
 * Both take the licence key as input keying material. The machine-file
 * derivation additionally binds the fingerprint, which is why decrypting a
 * machine file needs both the licence key and the target machine's identity.
 */
#ifndef TAMGA_CRYPTO_HKDF_H
#define TAMGA_CRYPTO_HKDF_H

#include <stdbool.h>
#include <stddef.h>

#include "crypto/sha256.h"
#include "tamga_compat.h"

/** The AES-256 key size both derivations produce. */
#define TAMGA_FILE_KEY_LEN 32u

/**
 * RFC 5869 extract-then-expand. `out_len` may be at most 255*32 bytes.
 * Returns false only on a bad argument (null output, oversized request).
 */
TAMGA_NODISCARD bool tamga_hkdf_sha256(const unsigned char *salt, size_t salt_len,
                                       const unsigned char *ikm, size_t ikm_len,
                                       const unsigned char *info, size_t info_len,
                                       unsigned char *out, size_t out_len);

/** Licence-file AES key. `license_key` is a NUL-terminated string. */
TAMGA_NODISCARD bool tamga_derive_license_file_key(const char *license_key,
                                                   unsigned char out[TAMGA_FILE_KEY_LEN]);

/** Machine-file AES key. Both arguments are required. */
TAMGA_NODISCARD bool tamga_derive_machine_file_key(const char *license_key, const char *fingerprint,
                                                   unsigned char out[TAMGA_FILE_KEY_LEN]);

#endif /* TAMGA_CRYPTO_HKDF_H */
