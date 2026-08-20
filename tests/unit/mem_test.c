#include "tamga_test.h"

#include <stdint.h>
#include <string.h>

#include "tamga_mem.h"

TT_TEST(checked_add_reports_overflow) {
    size_t out = 0u;
    TT_ASSERT(tamga_checked_add(2u, 3u, &out));
    TT_ASSERT_EQ_SIZE(out, 5u);
    TT_ASSERT_FALSE(tamga_checked_add(SIZE_MAX, 1u, &out));
    TT_ASSERT_FALSE(tamga_checked_add(SIZE_MAX - 4u, 5u, &out));
}

TT_TEST(checked_mul_reports_overflow) {
    size_t out = 0u;
    TT_ASSERT(tamga_checked_mul(6u, 7u, &out));
    TT_ASSERT_EQ_SIZE(out, 42u);
    TT_ASSERT(tamga_checked_mul(0u, SIZE_MAX, &out));
    TT_ASSERT_EQ_SIZE(out, 0u);
    TT_ASSERT_FALSE(tamga_checked_mul(SIZE_MAX, 2u, &out));
}

/* malloc(0) is implementation-defined; this library promises NULL always
 * means failure, so a zero-size request must still return something. */
TT_TEST(zero_size_allocation_is_not_null) {
    void *p = tamga_malloc(0u);
    TT_ASSERT_NOT_NULL(p);
    tamga_free(p);
}

TT_TEST(secure_zero_clears_the_buffer) {
    unsigned char buf[8];
    memset(buf, 0xAB, sizeof(buf));
    tamga_secure_zero(buf, sizeof(buf));
    {
        const unsigned char expected[8] = {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u};
        TT_ASSERT_EQ_MEM(buf, expected, sizeof(buf));
    }
}

TT_TEST(secure_zero_tolerates_null_and_zero_length) {
    unsigned char buf[1] = {0x11u};
    tamga_secure_zero(NULL, 16u);
    tamga_secure_zero(buf, 0u);
    TT_ASSERT_EQ_INT(buf[0], 0x11);
}

TT_TEST(strndup_rejects_an_interior_nul) {
    /* strlen() on the result would disagree with the caller's length, and
     * every consumer here is building a C string. */
    const char raw[5] = {'a', 'b', '\0', 'c', 'd'};
    char *copy = tamga_strndup(raw, sizeof(raw));
    TT_ASSERT_NULL(copy);
}

TT_TEST(strndup_copies_exactly_the_requested_length) {
    char *copy = tamga_strndup("abcdef", 3u);
    TT_ASSERT_NOT_NULL(copy);
    TT_ASSERT_EQ_STR(copy, "abc");
    tamga_free(copy);
}

TT_TEST(strdup_of_null_is_null) {
    TT_ASSERT_NULL(tamga_strdup(NULL));
}

int main(void) {
    TT_RUN(checked_add_reports_overflow);
    TT_RUN(checked_mul_reports_overflow);
    TT_RUN(zero_size_allocation_is_not_null);
    TT_RUN(secure_zero_clears_the_buffer);
    TT_RUN(secure_zero_tolerates_null_and_zero_length);
    TT_RUN(strndup_rejects_an_interior_nul);
    TT_RUN(strndup_copies_exactly_the_requested_length);
    TT_RUN(strdup_of_null_is_null);
    return TT_SUMMARY();
}
