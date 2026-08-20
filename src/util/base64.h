/*
 * base64.h -- RFC 4648 standard-alphabet base64, encode and decode.
 *
 * Decoding is strict: no whitespace, no alternate alphabet, no non-canonical
 * trailing bits. Callers that legitimately have whitespace in their input
 * (the PEM body, which may be line-wrapped) strip it first -- see
 * checkout/pem.c. Leniency belongs in exactly one place, and it is not here.
 */
#ifndef TAMGA_UTIL_BASE64_H
#define TAMGA_UTIL_BASE64_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

/**
 * Upper bound on the decoded size of `encoded_len` base64 characters.
 * Returns false on overflow.
 */
TAMGA_NODISCARD bool tamga_base64_decoded_cap(size_t encoded_len, size_t *out);

/**
 * Decodes `in_len` base64 characters into `out`, which must have room for
 * tamga_base64_decoded_cap(in_len) bytes. Writes the exact decoded length to
 * `*out_len`.
 *
 * Returns false if the input contains any character outside the standard
 * alphabet (whitespace included), has misplaced padding, has a length of
 * 4n+1, or carries non-zero bits past the final decoded byte.
 */
TAMGA_NODISCARD bool tamga_base64_decode(const char *in, size_t in_len, unsigned char *out,
                                         size_t *out_len);

/**
 * Allocates and decodes in one step. Returns NULL on any decode failure or on
 * allocation failure; on success `*out_len` receives the decoded length and
 * the buffer is released with tamga_free() (or tamga_secure_free() when it
 * held sensitive bytes).
 */
/* Why a decode returned NULL. The two cases need different answers: one
 * means the caller's file is corrupt, the other means this machine is out of
 * memory, and reporting the second as the first turns an allocation failure
 * into a support ticket about a licence that stopped working. */
typedef enum TamgaBase64Failure {
    TAMGA_BASE64_FAILURE_MALFORMED = 0,
    TAMGA_BASE64_FAILURE_OUT_OF_MEMORY
} TamgaBase64Failure;

/* As tamga_base64_decode_alloc, but reports which of the two failures it was.
 * `out_failure` is written only when the return value is NULL. */
TAMGA_NODISCARD unsigned char *tamga_base64_decode_alloc_why(const char *in, size_t in_len,
                                                             size_t *out_len,
                                                             TamgaBase64Failure *out_failure);

TAMGA_NODISCARD unsigned char *tamga_base64_decode_alloc(const char *in, size_t in_len,
                                                         size_t *out_len);

/** Exact encoded length (with padding) for `decoded_len` bytes, excluding the
 *  NUL terminator. Returns false on overflow. */
TAMGA_NODISCARD bool tamga_base64_encoded_len(size_t decoded_len, size_t *out);

/**
 * Encodes `in_len` bytes into `out` as a NUL-terminated string. `out` must
 * have room for tamga_base64_encoded_len(in_len) + 1 bytes.
 */
void tamga_base64_encode(const unsigned char *in, size_t in_len, char *out);

/**
 * Allocates and encodes in one step. Returns a NUL-terminated string released
 * with tamga_free(), or NULL on overflow/allocation failure.
 */
TAMGA_NODISCARD char *tamga_base64_encode_alloc(const unsigned char *in, size_t in_len);

#endif /* TAMGA_UTIL_BASE64_H */
