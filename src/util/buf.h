/*
 * buf.h -- the one growable byte buffer this library uses.
 *
 * Every byte assembled at runtime (canonical JSON, HTTP request bodies,
 * decoded payloads) goes through here rather than through ad-hoc
 * malloc/realloc/memcpy sequences, because those are where the off-by-one and
 * missing-overflow-check bugs live in hand-written C.
 *
 * Failure handling is sticky. An append that cannot allocate sets a failure
 * flag and becomes a no-op; subsequent appends are also no-ops. This keeps
 * the construction code readable (no error check after every append) without
 * being a silent-failure pattern, because the only ways to get bytes back out
 * -- tamga_buf_detach_string() and tamga_buf_detach() -- both return NULL when
 * the buffer has failed. A caller cannot observe truncated output without
 * having ignored a NULL.
 */
#ifndef TAMGA_UTIL_BUF_H
#define TAMGA_UTIL_BUF_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

typedef struct TamgaBuf {
    unsigned char *data;
    size_t len;
    size_t cap;
    bool failed;
} TamgaBuf;

/** Zero-initialises a buffer. No allocation happens until the first append. */
void tamga_buf_init(TamgaBuf *buf);

/** Securely zeroes and releases the buffer, resetting it to the init state. */
void tamga_buf_free(TamgaBuf *buf);

/** Ensures room for `extra` more bytes. Returns false (and marks the buffer
 *  failed) on allocation failure or size overflow. */
bool tamga_buf_reserve(TamgaBuf *buf, size_t extra);

void tamga_buf_append(TamgaBuf *buf, const void *data, size_t len);
void tamga_buf_append_byte(TamgaBuf *buf, unsigned char byte);
void tamga_buf_append_str(TamgaBuf *buf, const char *str);
void tamga_buf_append_fmt(TamgaBuf *buf, const char *fmt, ...) TAMGA_PRINTF(2, 3);

/** True when every append so far succeeded. */
bool tamga_buf_ok(const TamgaBuf *buf);

/**
 * Transfers ownership of the bytes as a NUL-terminated C string, resetting
 * the buffer. `out_len` (optional) receives the length excluding the NUL.
 *
 * Returns NULL if the buffer has failed, if the terminator cannot be
 * appended, or if the contents contain an interior NUL byte -- in which case
 * strlen() on the result would disagree with `out_len`, and every caller of
 * this function is producing a C string.
 *
 * The returned pointer is released with tamga_string_free().
 */
TAMGA_NODISCARD char *tamga_buf_detach_string(TamgaBuf *buf, size_t *out_len);

/**
 * Transfers ownership of the raw bytes, resetting the buffer. Returns NULL
 * if the buffer has failed. `out_len` receives the length; it is required.
 * The returned pointer is released with tamga_free() (or tamga_secure_free()
 * when it held key material).
 */
TAMGA_NODISCARD unsigned char *tamga_buf_detach(TamgaBuf *buf, size_t *out_len);

#endif /* TAMGA_UTIL_BUF_H */
