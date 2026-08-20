/*
 * A tamga_mem.c whose underlying allocator can be made to fail on demand.
 *
 * Every TAMGA_ERR_OUT_OF_MEMORY path in this library -- there are around
 * thirty-five -- was unreachable from the test suite, because nothing could
 * make an allocation fail. In C that is exactly the class of path where a
 * half-built object gets returned, an earlier allocation leaks, or a buffer
 * whose growth quietly failed is written through anyway.
 *
 * This double does not reimplement anything. It includes the real
 * tamga_mem.c and redirects only the three calls that reach the C library,
 * so tamga_strdup, tamga_strndup and tamga_memdup_terminated keep their real
 * logic and inherit the injected failure for free.
 *
 * It also counts live blocks, which turns "did a failure part-way through
 * strand the allocations that came before it?" into a portable assertion.
 * LeakSanitizer answers the same question but is unsupported on macOS, so
 * relying on it alone would mean the leak check ran only in CI.
 *
 * <stdlib.h> is included first on purpose: the macros below must not be in
 * effect when it declares malloc, and its include guard makes the copy
 * inside tamga_mem.c a no-op.
 */
#include <stdlib.h>

#include "failing_alloc.h"

unsigned long tamga_test_alloc_calls = 0uL;
unsigned long tamga_test_alloc_fail_at = 0uL;
unsigned long tamga_test_alloc_live = 0uL;

static void *tamga_test_alloc_note(void) {
    tamga_test_alloc_calls++;
    if (tamga_test_alloc_fail_at != 0uL && tamga_test_alloc_calls == tamga_test_alloc_fail_at) {
        return NULL;
    }
    return (void *)1; /* sentinel: "go ahead" */
}

static void *tamga_test_malloc(size_t size) {
    void *out;
    if (tamga_test_alloc_note() == NULL) {
        return NULL;
    }
    out = malloc(size);
    if (out != NULL) {
        tamga_test_alloc_live++;
    }
    return out;
}

static void *tamga_test_calloc(size_t count, size_t size) {
    void *out;
    if (tamga_test_alloc_note() == NULL) {
        return NULL;
    }
    out = calloc(count, size);
    if (out != NULL) {
        tamga_test_alloc_live++;
    }
    return out;
}

static void *tamga_test_realloc(void *ptr, size_t size) {
    void *out;
    if (tamga_test_alloc_note() == NULL) {
        return NULL;
    }
    out = realloc(ptr, size);
    /* A growing realloc replaces one block with one block; only the
     * NULL-pointer form is a new allocation, and a failure changes nothing. */
    if (out != NULL && ptr == NULL) {
        tamga_test_alloc_live++;
    }
    return out;
}

static void tamga_test_free(void *ptr) {
    if (ptr != NULL) {
        tamga_test_alloc_live--;
    }
    free(ptr);
}

void tamga_test_alloc_reset(void) {
    tamga_test_alloc_calls = 0uL;
    tamga_test_alloc_fail_at = 0uL;
    tamga_test_alloc_live = 0uL;
}

#define malloc(size) tamga_test_malloc(size)
#define calloc(count, size) tamga_test_calloc(count, size)
#define realloc(ptr, size) tamga_test_realloc(ptr, size)
#define free(ptr) tamga_test_free(ptr)

#include "tamga_mem.c" /* NOLINT(bugprone-suspicious-include) -- see above */
