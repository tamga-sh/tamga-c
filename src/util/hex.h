/*
 * hex.h -- lowercase hex encode/decode.
 *
 * Used for public keys supplied on a command line (see examples/), for UUID
 * parsing, and for rendering byte strings in diagnostics.
 */
#ifndef TAMGA_UTIL_HEX_H
#define TAMGA_UTIL_HEX_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

/**
 * Decodes `in_len` hex characters (either case) into `out`, which must have
 * room for in_len/2 bytes. Returns false on an odd length or any non-hex
 * character -- whitespace and "0x" prefixes are not accepted.
 */
TAMGA_NODISCARD bool tamga_hex_decode(const char *in, size_t in_len, unsigned char *out);

/**
 * Writes `in_len` bytes as 2*in_len lowercase hex characters plus a NUL.
 * `out` must have room for 2*in_len + 1 bytes.
 */
void tamga_hex_encode(const unsigned char *in, size_t in_len, char *out);

#endif /* TAMGA_UTIL_HEX_H */
