#include "util/buf.h"

#include <stdio.h>
#include <string.h>

#include "tamga_mem.h"

/* Small enough that a short string does not over-allocate, large enough that
 * building one does not realloc more than once. */
#define TAMGA_BUF_MIN_CAP ((size_t)64)

void tamga_buf_init(TamgaBuf *buf)
{
    if (buf == NULL) {
        return;
    }
    buf->data = NULL;
    buf->len = 0u;
    buf->cap = 0u;
    buf->failed = false;
}

void tamga_buf_free(TamgaBuf *buf)
{
    if (buf == NULL) {
        return;
    }
    tamga_secure_free(buf->data, buf->cap);
    tamga_buf_init(buf);
}

bool tamga_buf_reserve(TamgaBuf *buf, size_t extra)
{
    size_t needed;
    size_t new_cap;
    unsigned char *grown;

    if (buf == NULL) {
        return false;
    }
    if (buf->failed) {
        return false;
    }
    if (!tamga_checked_add(buf->len, extra, &needed)) {
        buf->failed = true;
        return false;
    }
    if (needed <= buf->cap) {
        return true;
    }

    new_cap = (buf->cap < TAMGA_BUF_MIN_CAP) ? TAMGA_BUF_MIN_CAP : buf->cap;
    while (new_cap < needed) {
        size_t doubled;
        if (!tamga_checked_mul(new_cap, 2u, &doubled)) {
            buf->failed = true;
            return false;
        }
        new_cap = doubled;
    }

    /* Grow by hand rather than with realloc: the old allocation may hold key
     * material or plaintext, and realloc is free to copy-and-release it
     * without zeroing the original. */
    grown = (unsigned char *)tamga_malloc(new_cap);
    if (grown == NULL) {
        buf->failed = true;
        return false;
    }
    if (buf->len > 0u) {
        memcpy(grown, buf->data, buf->len);
    }
    tamga_secure_free(buf->data, buf->cap);
    buf->data = grown;
    buf->cap = new_cap;
    return true;
}

void tamga_buf_append(TamgaBuf *buf, const void *data, size_t len)
{
    if (buf == NULL || buf->failed) {
        return;
    }
    if (len == 0u) {
        return;
    }
    if (data == NULL) {
        buf->failed = true;
        return;
    }
    if (!tamga_buf_reserve(buf, len)) {
        return;
    }
    memcpy(&buf->data[buf->len], data, len);
    buf->len += len;
}

void tamga_buf_append_byte(TamgaBuf *buf, unsigned char byte)
{
    tamga_buf_append(buf, &byte, 1u);
}

void tamga_buf_append_str(TamgaBuf *buf, const char *str)
{
    if (str == NULL) {
        if (buf != NULL) {
            buf->failed = true;
        }
        return;
    }
    tamga_buf_append(buf, str, strlen(str));
}

void tamga_buf_append_fmt(TamgaBuf *buf, const char *fmt, ...)
{
    va_list args;
    va_list probe;
    int needed;
    size_t needed_sz;

    if (buf == NULL || buf->failed) {
        return;
    }
    if (fmt == NULL) {
        buf->failed = true;
        return;
    }

    va_start(args, fmt);
    va_copy(probe, args);
    needed = vsnprintf(NULL, 0, fmt, probe);
    va_end(probe);

    if (needed < 0) {
        buf->failed = true;
        va_end(args);
        return;
    }
    needed_sz = (size_t)needed;

    /* +1 for the NUL vsnprintf insists on writing; it is not counted in len,
     * so the buffer stays a pure byte sequence. */
    if (!tamga_buf_reserve(buf, needed_sz + 1u)) {
        va_end(args);
        return;
    }
    (void)vsnprintf((char *)&buf->data[buf->len], needed_sz + 1u, fmt, args);
    va_end(args);
    buf->len += needed_sz;
}

bool tamga_buf_ok(const TamgaBuf *buf)
{
    return buf != NULL && !buf->failed;
}

char *tamga_buf_detach_string(TamgaBuf *buf, size_t *out_len)
{
    char *out;
    size_t len;

    if (buf == NULL || buf->failed) {
        return NULL;
    }
    if (buf->data != NULL && memchr(buf->data, 0, buf->len) != NULL) {
        return NULL;
    }
    if (!tamga_buf_reserve(buf, 1u)) {
        return NULL;
    }
    buf->data[buf->len] = '\0';
    len = buf->len;
    out = (char *)buf->data;
    tamga_buf_init(buf);
    if (out_len != NULL) {
        *out_len = len;
    }
    return out;
}

unsigned char *tamga_buf_detach(TamgaBuf *buf, size_t *out_len)
{
    unsigned char *out;

    if (buf == NULL || buf->failed || out_len == NULL) {
        return NULL;
    }
    if (buf->data == NULL) {
        /* An empty-but-successful buffer still has to hand back a non-NULL
         * pointer, or the caller cannot tell it apart from failure. */
        if (!tamga_buf_reserve(buf, 1u)) {
            return NULL;
        }
    }
    out = buf->data;
    *out_len = buf->len;
    tamga_buf_init(buf);
    return out;
}
