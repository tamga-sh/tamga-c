/*
 * tamga_mem.h -- allocation with overflow-checked size arithmetic, and the
 * secure-erase primitive that replaces Rust's `zeroize`.
 *
 * Every allocation in this library goes through here. The point is not to add
 * a layer for its own sake: it is that every size passed to malloc in this
 * codebase is derived from attacker-influenced input (a PEM body length, a
 * base64 output size, a JSON string length), and `malloc(a * b)` or
 * `malloc(len + 1)` silently wrapping is the classic route from "parser reads
 * a weird file" to "heap overflow".
 */
#ifndef TAMGA_MEM_H
#define TAMGA_MEM_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

/*
 * Upper bound on any single caller-supplied input this library will look at.
 *
 * 16 MiB, unchanged from the pre-1.3 releases where it lived in Rust as
 * MAX_REASONABLE_LEN. A licence file is a few kilobytes; a machine file the
 * same. Anything three orders of magnitude past that is a caller passing a
 * wrong length, not a real certificate, and refusing it early keeps every
 * downstream size computation comfortably inside the range where the overflow
 * checks below are a backstop rather than the only defence.
 */
#define TAMGA_MAX_REASONABLE_LEN ((size_t)(16u * 1024u * 1024u))

/* a + b, or false on overflow. */
TAMGA_NODISCARD bool tamga_checked_add(size_t a, size_t b, size_t *out);

/* a * b, or false on overflow. */
TAMGA_NODISCARD bool tamga_checked_mul(size_t a, size_t b, size_t *out);

/*
 * malloc/calloc/realloc wrappers. All return NULL on failure *and* on any
 * request that would overflow, so a caller only ever has one thing to check.
 * A zero-byte request returns a valid one-byte allocation rather than the
 * implementation-defined NULL-or-not of malloc(0), so "NULL means failure"
 * holds without exception.
 */
TAMGA_NODISCARD void *tamga_malloc(size_t size);
TAMGA_NODISCARD void *tamga_calloc(size_t count, size_t size);
TAMGA_NODISCARD void *tamga_realloc(void *ptr, size_t size);
void tamga_free(void *ptr);

/*
 * Overwrites `len` bytes at `ptr` with zeroes in a way the optimiser is not
 * permitted to remove.
 *
 * A plain memset() on a buffer that is never read again is a dead store, and
 * every mainstream compiler will delete it -- which is precisely what happens
 * to a "clear the key before returning" call. Derived AES keys, HKDF output
 * and PRK material all go through this instead.
 */
void tamga_secure_zero(void *ptr, size_t len);

/*
 * Frees a buffer after securely zeroing it. Safe on NULL (no-op), in which
 * case `len` is ignored.
 */
void tamga_secure_free(void *ptr, size_t len);

/*
 * Duplicates a NUL-terminated string with tamga_malloc. Returns NULL if
 * `src` is NULL, on allocation failure, or if the string is longer than
 * TAMGA_MAX_REASONABLE_LEN.
 */
TAMGA_NODISCARD char *tamga_strdup(const char *src);

/*
 * Duplicates `len` bytes as a NUL-terminated string (the source need not be
 * NUL-terminated, and may not contain an interior NUL -- that returns NULL,
 * because every caller here is producing a C string whose length would then
 * disagree with strlen()).
 */
TAMGA_NODISCARD char *tamga_strndup(const char *src, size_t len);

#endif /* TAMGA_MEM_H */
