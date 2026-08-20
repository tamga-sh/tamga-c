/*
 * pem.h -- the PEM envelope both offline file formats are wrapped in.
 *
 *     -----BEGIN LICENSE FILE-----
 *     <base64 of {"enc":..., "sig":..., "alg":...}>
 *     -----END LICENSE FILE-----
 *
 * (and the MACHINE FILE equivalent, with different marker text).
 */
#ifndef TAMGA_CHECKOUT_PEM_H
#define TAMGA_CHECKOUT_PEM_H

#include <stddef.h>

#include "tamga.h"
#include "tamga_compat.h"

/**
 * Strips the envelope and returns the body with all whitespace removed, as an
 * owned NUL-terminated string released with tamga_string_free().
 *
 * Whitespace is stripped because a server may line-wrap the body, and the
 * base64 decoder downstream is deliberately strict about accepting none. This
 * is the one place in the codebase where that leniency lives.
 */
TAMGA_NODISCARD TamgaErrorCode tamga_pem_extract(const char *pem, size_t pem_len,
                                                 const char *begin_marker, const char *end_marker,
                                                 char **out_body, size_t *out_body_len);

#endif /* TAMGA_CHECKOUT_PEM_H */
