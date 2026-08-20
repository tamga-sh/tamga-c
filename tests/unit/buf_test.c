#include "tamga_test.h"

#include "tamga_mem.h"
#include "util/buf.h"

TT_TEST(appends_accumulate_in_order)
{
    TamgaBuf buf;
    char *out;
    size_t len = 0u;

    tamga_buf_init(&buf);
    tamga_buf_append_str(&buf, "hello");
    tamga_buf_append_byte(&buf, ' ');
    tamga_buf_append(&buf, "world", 5u);
    out = tamga_buf_detach_string(&buf, &len);

    TT_ASSERT_NOT_NULL(out);
    TT_ASSERT_EQ_STR(out, "hello world");
    TT_ASSERT_EQ_SIZE(len, 11u);
    tamga_free(out);
    tamga_buf_free(&buf);
}

TT_TEST(growth_survives_many_small_appends)
{
    TamgaBuf buf;
    char *out;
    size_t len = 0u;
    int i;

    tamga_buf_init(&buf);
    for (i = 0; i < 5000; i++) {
        tamga_buf_append_byte(&buf, 'a');
    }
    out = tamga_buf_detach_string(&buf, &len);
    TT_ASSERT_NOT_NULL(out);
    TT_ASSERT_EQ_SIZE(len, 5000u);
    TT_ASSERT_EQ_INT(out[4999], 'a');
    tamga_free(out);
    tamga_buf_free(&buf);
}

TT_TEST(formatted_append_matches_snprintf)
{
    TamgaBuf buf;
    char *out;

    tamga_buf_init(&buf);
    tamga_buf_append_fmt(&buf, "%s=%d", "n", 42);
    out = tamga_buf_detach_string(&buf, NULL);
    TT_ASSERT_NOT_NULL(out);
    TT_ASSERT_EQ_STR(out, "n=42");
    tamga_free(out);
    tamga_buf_free(&buf);
}

/* The sticky-failure design is only safe because a failed buffer cannot hand
 * its bytes back -- otherwise a caller would silently ship truncated output. */
TT_TEST(a_failed_buffer_refuses_to_detach)
{
    TamgaBuf buf;
    tamga_buf_init(&buf);
    tamga_buf_append_str(&buf, "partial");
    tamga_buf_append_str(&buf, NULL); /* marks failure */
    TT_ASSERT_FALSE(tamga_buf_ok(&buf));
    TT_ASSERT_NULL(tamga_buf_detach_string(&buf, NULL));
    tamga_buf_free(&buf);
}

TT_TEST(appends_after_failure_are_no_ops)
{
    TamgaBuf buf;
    tamga_buf_init(&buf);
    tamga_buf_append_str(&buf, NULL);
    tamga_buf_append_str(&buf, "more");
    tamga_buf_append_fmt(&buf, "%d", 1);
    TT_ASSERT_FALSE(tamga_buf_ok(&buf));
    tamga_buf_free(&buf);
}

TT_TEST(detach_string_rejects_an_interior_nul)
{
    TamgaBuf buf;
    tamga_buf_init(&buf);
    tamga_buf_append(&buf, "ab\0cd", 5u);
    TT_ASSERT_NULL(tamga_buf_detach_string(&buf, NULL));
    tamga_buf_free(&buf);
}

TT_TEST(detach_of_an_empty_buffer_is_non_null)
{
    TamgaBuf buf;
    size_t len = 99u;
    unsigned char *raw;

    tamga_buf_init(&buf);
    raw = tamga_buf_detach(&buf, &len);
    TT_ASSERT_NOT_NULL(raw);
    TT_ASSERT_EQ_SIZE(len, 0u);
    tamga_free(raw);
    tamga_buf_free(&buf);
}

TT_TEST(free_is_idempotent_and_null_safe)
{
    TamgaBuf buf;
    tamga_buf_init(&buf);
    tamga_buf_append_str(&buf, "x");
    tamga_buf_free(&buf);
    tamga_buf_free(&buf);
    tamga_buf_free(NULL);
    TT_ASSERT(tamga_buf_ok(&buf));
}

int main(void)
{
    TT_RUN(appends_accumulate_in_order);
    TT_RUN(growth_survives_many_small_appends);
    TT_RUN(formatted_append_matches_snprintf);
    TT_RUN(a_failed_buffer_refuses_to_detach);
    TT_RUN(appends_after_failure_are_no_ops);
    TT_RUN(detach_string_rejects_an_interior_nul);
    TT_RUN(detach_of_an_empty_buffer_is_non_null);
    TT_RUN(free_is_idempotent_and_null_safe);
    return TT_SUMMARY();
}
