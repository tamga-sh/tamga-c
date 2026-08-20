#include "tamga_test.h"

#include "util/rfc3339.h"

TT_TEST(parses_the_epoch)
{
    int64_t t = -1;
    TT_ASSERT(tamga_rfc3339_parse("1970-01-01T00:00:00Z", &t));
    TT_ASSERT_EQ_INT(t, 0);
}

TT_TEST(parses_a_representative_server_timestamp)
{
    int64_t t = 0;
    /* 2026-08-20T12:00:00Z */
    TT_ASSERT(tamga_rfc3339_parse("2026-08-20T12:00:00Z", &t));
    TT_ASSERT_EQ_INT(t, 1787227200);
}

TT_TEST(handles_leap_days)
{
    int64_t t = 0;
    TT_ASSERT(tamga_rfc3339_parse("2024-02-29T00:00:00Z", &t));
    TT_ASSERT_EQ_INT(t, 1709164800);
    /* 1900 was not a leap year; 2000 was. */
    TT_ASSERT_FALSE(tamga_rfc3339_parse("1900-02-29T00:00:00Z", &t));
    TT_ASSERT(tamga_rfc3339_parse("2000-02-29T00:00:00Z", &t));
}

/* A numeric offset says how far ahead of UTC the stamp is, so the UTC value
 * is the stamp minus the offset. Getting this backwards shifts every expiry
 * check by up to 14 hours in the wrong direction. */
TT_TEST(applies_numeric_offsets_in_the_right_direction)
{
    int64_t utc = 0;
    int64_t plus = 0;
    int64_t minus = 0;
    TT_ASSERT(tamga_rfc3339_parse("2026-08-20T12:00:00Z", &utc));
    TT_ASSERT(tamga_rfc3339_parse("2026-08-20T15:00:00+03:00", &plus));
    TT_ASSERT(tamga_rfc3339_parse("2026-08-20T09:00:00-03:00", &minus));
    TT_ASSERT_EQ_INT(plus, utc);
    TT_ASSERT_EQ_INT(minus, utc);
}

TT_TEST(accepts_and_truncates_fractional_seconds)
{
    int64_t a = 0;
    int64_t b = 0;
    TT_ASSERT(tamga_rfc3339_parse("2026-08-20T12:00:00.123456Z", &a));
    TT_ASSERT(tamga_rfc3339_parse("2026-08-20T12:00:00Z", &b));
    TT_ASSERT_EQ_INT(a, b);
}

TT_TEST(accepts_lowercase_separators)
{
    int64_t a = 0;
    int64_t b = 0;
    TT_ASSERT(tamga_rfc3339_parse("2026-08-20t12:00:00z", &a));
    TT_ASSERT(tamga_rfc3339_parse("2026-08-20T12:00:00Z", &b));
    TT_ASSERT_EQ_INT(a, b);
}

TT_TEST(clamps_a_leap_second)
{
    int64_t leap = 0;
    int64_t normal = 0;
    TT_ASSERT(tamga_rfc3339_parse("2016-12-31T23:59:60Z", &leap));
    TT_ASSERT(tamga_rfc3339_parse("2016-12-31T23:59:59Z", &normal));
    TT_ASSERT_EQ_INT(leap, normal);
}

TT_TEST(rejects_malformed_input)
{
    int64_t t = 0;
    TT_ASSERT_FALSE(tamga_rfc3339_parse(NULL, &t));
    TT_ASSERT_FALSE(tamga_rfc3339_parse("", &t));
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-08-20", &t));
    /* no timezone designator */
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-08-20T12:00:00", &t));
    /* single-digit fields */
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-8-20T12:00:00Z", &t));
    /* out-of-range fields */
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-13-01T00:00:00Z", &t));
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-04-31T00:00:00Z", &t));
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-08-20T24:00:00Z", &t));
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-08-20T12:60:00Z", &t));
    /* trailing garbage after the designator */
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-08-20T12:00:00Zx", &t));
    /* '.' with no digits */
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-08-20T12:00:00.Z", &t));
    /* malformed offset */
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-08-20T12:00:00+3:00", &t));
    TT_ASSERT_FALSE(tamga_rfc3339_parse("2026-08-20T12:00:00+03:60", &t));
}

TT_TEST(the_clock_is_after_this_code_was_written)
{
    /* 2026-01-01T00:00:00Z. Guards against a build where time() is stubbed
     * or the epoch conversion is wrong by decades. */
    TT_ASSERT(tamga_time_now_unix() > 1767225600);
}

int main(void)
{
    TT_RUN(parses_the_epoch);
    TT_RUN(parses_a_representative_server_timestamp);
    TT_RUN(handles_leap_days);
    TT_RUN(applies_numeric_offsets_in_the_right_direction);
    TT_RUN(accepts_and_truncates_fractional_seconds);
    TT_RUN(accepts_lowercase_separators);
    TT_RUN(clamps_a_leap_second);
    TT_RUN(rejects_malformed_input);
    TT_RUN(the_clock_is_after_this_code_was_written);
    return TT_SUMMARY();
}
