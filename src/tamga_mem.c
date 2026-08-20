#include "tamga_mem.h"

#include "tamga.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <windows.h>
#endif

bool tamga_checked_add(size_t a, size_t b, size_t *out)
{
    if (out == NULL) {
        return false;
    }
    if (a > SIZE_MAX - b) {
        return false;
    }
    *out = a + b;
    return true;
}

bool tamga_checked_mul(size_t a, size_t b, size_t *out)
{
    if (out == NULL) {
        return false;
    }
    if (a != 0u && b > SIZE_MAX / a) {
        return false;
    }
    *out = a * b;
    return true;
}

void *tamga_malloc(size_t size)
{
    /* malloc(0) is implementation-defined: it may return NULL, which would
     * be indistinguishable from failure at every call site. Round up so the
     * "NULL means failure" contract holds unconditionally. */
    if (size == 0u) {
        size = 1u;
    }
    return malloc(size);
}

void *tamga_calloc(size_t count, size_t size)
{
    size_t total;
    if (!tamga_checked_mul(count, size, &total)) {
        return NULL;
    }
    if (total == 0u) {
        total = 1u;
    }
    return calloc((size_t)1, total);
}

void *tamga_realloc(void *ptr, size_t size)
{
    if (size == 0u) {
        size = 1u;
    }
    return realloc(ptr, size);
}

void tamga_free(void *ptr)
{
    free(ptr);
}

/*
 * The portable erase.
 *
 * Routing memset through a volatile function pointer means the compiler
 * cannot see that the call is memset, so it cannot classify the store as dead
 * and delete it -- which is exactly what it does to a plain
 * "memset(key, 0, 32); return;".
 *
 * Deliberately NOT using explicit_bzero()/memset_s(): both are hidden behind
 * feature-test macros (_DEFAULT_SOURCE, __STDC_WANT_LIB_EXT1__) that a strict
 * -std=c11 build turns off, so probing for them portably costs more #ifdef
 * surface than it buys. Windows is the exception -- SecureZeroMemory is
 * unconditionally available and, unlike the volatile-pointer trick, is also
 * guaranteed against link-time optimisation.
 */
#if !defined(_WIN32)
static void *(*const volatile tamga_memset_ptr)(void *, int, size_t) = memset;
#endif

void tamga_secure_zero(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0u) {
        return;
    }
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#else
    (void)tamga_memset_ptr(ptr, 0, len);
#endif
}

void tamga_secure_free(void *ptr, size_t len)
{
    if (ptr == NULL) {
        return;
    }
    tamga_secure_zero(ptr, len);
    tamga_free(ptr);
}

char *tamga_strdup(const char *src)
{
    if (src == NULL) {
        return NULL;
    }
    return tamga_strndup(src, strlen(src));
}

char *tamga_strndup(const char *src, size_t len)
{
    char *copy;
    size_t total;

    if (src == NULL || len > TAMGA_MAX_REASONABLE_LEN) {
        return NULL;
    }
    /* An interior NUL would make strlen(result) disagree with the length the
     * caller believes it has. Every consumer of this function is building a
     * C string, so that mismatch is always a bug -- refuse it here rather
     * than let it surface as a truncated JSON payload three layers up. */
    if (memchr(src, 0, len) != NULL) {
        return NULL;
    }
    if (!tamga_checked_add(len, 1u, &total)) {
        return NULL;
    }
    copy = (char *)tamga_malloc(total);
    if (copy == NULL) {
        return NULL;
    }
    if (len > 0u) {
        memcpy(copy, src, len);
    }
    copy[len] = '\0';
    return copy;
}

/*
 * Public entry point. Deliberately does NOT touch the thread's last-error
 * slot: freeing cannot fail, so it has no error to report, and clearing here
 * would silently erase a message the caller is about to print. The documented
 * "valid until the next tamga_* call" rule is an upper bound on validity, not
 * a promise to invalidate.
 *
 * Zeroes before freeing because these strings are not generic payloads: a
 * decoded licence resource carries the licence's own `key` attribute, so a
 * plain free() would leave live key material in the heap for whatever
 * allocates next.
 */
void tamga_string_free(char *ptr)
{
    if (ptr == NULL) {
        return;
    }
    tamga_secure_free(ptr, strlen(ptr));
}
