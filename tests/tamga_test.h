/*
 * tamga_test.h -- the entire test framework for this repository.
 *
 * Deliberately hand-rolled and header-only. A unit-test framework would be
 * the single largest dependency in a project whose defining property is
 * having none, and nothing here needs more than "run these functions, report
 * which assertions failed, exit non-zero if any did".
 *
 * Usage:
 *
 *     #include "tamga_test.h"
 *
 *     TT_TEST(decodes_a_known_vector) {
 *         TT_ASSERT_EQ_SIZE(base64_decoded_len("aGk="), 2u);
 *     }
 *
 *     int main(void) {
 *         TT_RUN(decodes_a_known_vector);
 *         return TT_SUMMARY();
 *     }
 *
 * A failing TT_ASSERT_* reports file/line plus the actual values and returns
 * from the current test function -- subsequent tests still run, so one broken
 * assertion does not mask the rest of the file.
 */
#ifndef TAMGA_TEST_H
#define TAMGA_TEST_H

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Not every test file uses every helper below, and an unused static function
 * is a hard error under this repo's warning settings. */
#if defined(__GNUC__) || defined(__clang__)
#  define TT_MAYBE_UNUSED __attribute__((unused))
#else
#  define TT_MAYBE_UNUSED
#endif

TT_MAYBE_UNUSED static int tt_failures_ = 0;
TT_MAYBE_UNUSED static int tt_tests_run_ = 0;
TT_MAYBE_UNUSED static const char *tt_current_ = "<none>";

#define TT_TEST(name) static void name(void)

#define TT_RUN(fn)                                                             \
    do {                                                                       \
        tt_current_ = #fn;                                                     \
        tt_tests_run_++;                                                       \
        fn();                                                                  \
    } while (0)

#define TT_FAIL_(fmt, ...)                                                     \
    do {                                                                       \
        tt_failures_++;                                                        \
        (void)fprintf(stderr, "FAIL %s\n  at %s:%d\n  " fmt "\n", tt_current_,  \
                      __FILE__, __LINE__, __VA_ARGS__);                        \
    } while (0)

#define TT_ASSERT(cond)                                                        \
    do {                                                                       \
        if (!(cond)) {                                                         \
            TT_FAIL_("expected true: %s", #cond);                              \
            return;                                                            \
        }                                                                      \
    } while (0)

#define TT_ASSERT_FALSE(cond)                                                  \
    do {                                                                       \
        if (cond) {                                                            \
            TT_FAIL_("expected false: %s", #cond);                             \
            return;                                                            \
        }                                                                      \
    } while (0)

#define TT_ASSERT_EQ_INT(actual, expected)                                     \
    do {                                                                       \
        long long tt_a_ = (long long)(actual);                                 \
        long long tt_e_ = (long long)(expected);                               \
        if (tt_a_ != tt_e_) {                                                  \
            TT_FAIL_("%s: expected %lld, got %lld", #actual, tt_e_, tt_a_);    \
            return;                                                            \
        }                                                                      \
    } while (0)

#define TT_ASSERT_EQ_SIZE(actual, expected)                                    \
    do {                                                                       \
        size_t tt_a_ = (size_t)(actual);                                       \
        size_t tt_e_ = (size_t)(expected);                                     \
        if (tt_a_ != tt_e_) {                                                  \
            TT_FAIL_("%s: expected %zu, got %zu", #actual, tt_e_, tt_a_);      \
            return;                                                            \
        }                                                                      \
    } while (0)

#define TT_ASSERT_EQ_STR(actual, expected)                                     \
    do {                                                                       \
        const char *tt_a_ = (actual);                                          \
        const char *tt_e_ = (expected);                                        \
        if (tt_a_ == NULL || tt_e_ == NULL || strcmp(tt_a_, tt_e_) != 0) {     \
            TT_FAIL_("%s: expected \"%s\", got \"%s\"", #actual,               \
                     tt_e_ ? tt_e_ : "(null)", tt_a_ ? tt_a_ : "(null)");      \
            return;                                                            \
        }                                                                      \
    } while (0)

#define TT_ASSERT_NULL(ptr)                                                    \
    do {                                                                       \
        const void *tt_p_ = (const void *)(ptr);                               \
        if (tt_p_ != NULL) {                                                   \
            TT_FAIL_("%s: expected NULL, got %p", #ptr, tt_p_);                \
            return;                                                            \
        }                                                                      \
    } while (0)

#define TT_ASSERT_NOT_NULL(ptr)                                                \
    do {                                                                       \
        if ((const void *)(ptr) == NULL) {                                     \
            TT_FAIL_("%s: expected non-NULL%s", #ptr, "");                     \
            return;                                                            \
        }                                                                      \
    } while (0)

/* Byte-buffer equality with a hex diff on failure -- the crypto known-answer
 * tests are unreadable without seeing which byte diverged. */
#define TT_ASSERT_EQ_MEM(actual, expected, len)                                \
    do {                                                                       \
        const unsigned char *tt_a_ = (const unsigned char *)(actual);          \
        const unsigned char *tt_e_ = (const unsigned char *)(expected);        \
        size_t tt_n_ = (size_t)(len);                                          \
        if (memcmp(tt_a_, tt_e_, tt_n_) != 0) {                                \
            tt_failures_++;                                                    \
            (void)fprintf(stderr, "FAIL %s\n  at %s:%d\n  %s: byte mismatch\n",\
                          tt_current_, __FILE__, __LINE__, #actual);           \
            tt_print_hex_("    expected", tt_e_, tt_n_);                       \
            tt_print_hex_("    actual  ", tt_a_, tt_n_);                       \
            return;                                                            \
        }                                                                      \
    } while (0)

#define TT_SUMMARY() tt_summary_()

TT_MAYBE_UNUSED static void tt_print_hex_(const char *label, const unsigned char *data, size_t len)
{
    size_t i;
    (void)fprintf(stderr, "%s: ", label);
    for (i = 0; i < len; i++) {
        (void)fprintf(stderr, "%02x", data[i]);
    }
    (void)fprintf(stderr, "\n");
}

/* Decodes a hex string literal into `out`, for embedding RFC/NIST test
 * vectors verbatim. Returns the number of bytes written, or SIZE_MAX on a
 * malformed input -- which is a bug in the test, not in the library, so
 * callers assert on it. */
TT_MAYBE_UNUSED static size_t tt_hex2bin(const char *hex, unsigned char *out, size_t out_cap)
{
    size_t len = strlen(hex);
    size_t i;
    if ((len % 2u) != 0u || (len / 2u) > out_cap) {
        return (size_t)-1;
    }
    for (i = 0; i < len; i += 2u) {
        unsigned int hi, lo;
        const char *digits = "0123456789abcdef";
        const char *p_hi = strchr(digits, (hex[i] >= 'A' && hex[i] <= 'F')
                                              ? (hex[i] + ('a' - 'A'))
                                              : hex[i]);
        const char *p_lo = strchr(digits, (hex[i + 1u] >= 'A' && hex[i + 1u] <= 'F')
                                              ? (hex[i + 1u] + ('a' - 'A'))
                                              : hex[i + 1u]);
        if (p_hi == NULL || p_lo == NULL || hex[i] == '\0' || hex[i + 1u] == '\0') {
            return (size_t)-1;
        }
        hi = (unsigned int)(p_hi - digits);
        lo = (unsigned int)(p_lo - digits);
        out[i / 2u] = (unsigned char)((hi << 4) | lo);
    }
    return len / 2u;
}

TT_MAYBE_UNUSED static int tt_summary_(void)
{
    if (tt_failures_ == 0) {
        (void)fprintf(stderr, "ok: %d test(s) passed\n", tt_tests_run_);
        return 0;
    }
    (void)fprintf(stderr, "FAILED: %d assertion failure(s) across %d test(s)\n",
                  tt_failures_, tt_tests_run_);
    return 1;
}

#endif /* TAMGA_TEST_H */
