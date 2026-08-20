/*
 * gcm.h -- AES-256-GCM (NIST SP 800-38D).
 *
 * This is how both offline file formats encrypt their payload. The wire
 * layout the Tamga server produces is
 *
 *     nonce(12) || ciphertext || tag(16)
 *
 * concatenated into the base64 `enc` field, with no additional authenticated
 * data.
 *
 * The open path verifies the tag before returning any plaintext, and compares
 * it in constant time. Returning "probably fine, here is the plaintext" ahead
 * of the tag check is the classic GCM misuse: it turns an authenticated cipher
 * back into an unauthenticated one.
 */
#ifndef TAMGA_CRYPTO_GCM_H
#define TAMGA_CRYPTO_GCM_H

#include <stdbool.h>
#include <stddef.h>

#include "crypto/aes.h"
#include "tamga_compat.h"

#define TAMGA_GCM_NONCE_LEN 12u
#define TAMGA_GCM_TAG_LEN   16u

/**
 * Decrypts and authenticates. `ciphertext_and_tag` is the ciphertext with the
 * 16-byte tag appended, exactly as it appears on the wire, and must be at
 * least TAMGA_GCM_TAG_LEN bytes.
 *
 * `out` must have room for `ct_and_tag_len - TAMGA_GCM_TAG_LEN` bytes;
 * `*out_len` receives that length. Nothing is written to `out` unless the tag
 * verifies.
 *
 * Returns false on a bad argument or a tag mismatch -- the caller cannot and
 * must not distinguish the two.
 */
TAMGA_NODISCARD bool tamga_gcm_open(const unsigned char key[TAMGA_AES256_KEY_LEN],
                                    const unsigned char nonce[TAMGA_GCM_NONCE_LEN],
                                    const unsigned char *aad, size_t aad_len,
                                    const unsigned char *ciphertext_and_tag,
                                    size_t ct_and_tag_len,
                                    unsigned char *out, size_t *out_len);

/**
 * Encrypts and authenticates, appending the tag. `out` must have room for
 * `plaintext_len + TAMGA_GCM_TAG_LEN` bytes.
 *
 * The library itself never seals -- it verifies server-issued material. This
 * exists so the open path can be tested against ciphertexts this code did not
 * also produce the expectations for, and so round-trip tests are possible
 * without checking in a key.
 */
TAMGA_NODISCARD bool tamga_gcm_seal(const unsigned char key[TAMGA_AES256_KEY_LEN],
                                    const unsigned char nonce[TAMGA_GCM_NONCE_LEN],
                                    const unsigned char *aad, size_t aad_len,
                                    const unsigned char *plaintext, size_t plaintext_len,
                                    unsigned char *out, size_t *out_len);

#endif /* TAMGA_CRYPTO_GCM_H */
