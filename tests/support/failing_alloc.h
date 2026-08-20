/* Controls for the allocator double in failing_alloc.c. */
#ifndef TAMGA_TEST_FAILING_ALLOC_H
#define TAMGA_TEST_FAILING_ALLOC_H

#include <stddef.h>

/* How many allocations have been requested since the last reset. */
extern unsigned long tamga_test_alloc_calls;

/* When non-zero, the allocation with this 1-based index returns NULL.
 * Everything before and after it succeeds, so a test can walk the whole
 * sequence one failure at a time. */
extern unsigned long tamga_test_alloc_fail_at;

/* Blocks allocated and not yet released. Zero between operations means the
 * operation cleaned up after itself, whether it succeeded or failed. */
extern unsigned long tamga_test_alloc_live;

void tamga_test_alloc_reset(void);

#endif /* TAMGA_TEST_FAILING_ALLOC_H */
