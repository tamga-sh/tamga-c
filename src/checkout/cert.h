/*
 * cert.h -- the inner {"enc", "sig", "alg"} certificate both offline file
 * formats wrap in their PEM envelope.
 *
 * Shared because the structure is identical between them; what differs is the
 * marker text, the algorithm vocabulary and what the decrypted payload means.
 */
#ifndef TAMGA_CHECKOUT_CERT_H
#define TAMGA_CHECKOUT_CERT_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga.h"
#include "tamga_compat.h"
#include "util/json.h"

typedef struct TamgaCert {
    TamgaJson *root; /* owns the three views below */
    const char *enc;
    size_t enc_len;
    const char *sig;
    size_t sig_len;
    const char *alg;
    /* JSON strings may contain an interior NUL, so alg carries its length and
     * every comparison against it is length-aware. Treating it as a C string
     * would make "base64+ed25519+v2\0anything" compare equal to the algorithm
     * it only prefixes. */
    size_t alg_len;
} TamgaCert;

/**
 * Base64-decodes the PEM body and parses the certificate JSON, requiring all
 * three fields to be present and to be strings.
 *
 * A missing or null field is rejected here rather than downstream: the same
 * omission reached a null dereference in this SDK family's Java
 * implementation before an independent review caught it, and the fix there
 * was the same -- fail at the parse boundary with the documented error.
 */
TAMGA_NODISCARD TamgaErrorCode tamga_cert_parse(const char *body, size_t body_len, TamgaCert *out);

/**
 * Compares the certificate's `alg` against a literal, by length as well as by
 * content -- see the note on TamgaCert::alg_len.
 */
bool tamga_cert_alg_equals(const TamgaCert *cert, const char *expected, size_t expected_len);

void tamga_cert_free(TamgaCert *cert);

#endif /* TAMGA_CHECKOUT_CERT_H */
