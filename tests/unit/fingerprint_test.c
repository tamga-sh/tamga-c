/*
 * Fingerprint canonicalisation, driven by the published vectors.
 *
 * The vectors in tests/fixtures/fingerprint/fingerprint.json were produced by
 * an independent SHA-256 implementation, deliberately not by any SDK in this
 * family: a fixture the implementation under test generated proves only that
 * it agrees with itself, which is exactly how a two-year machine-file bug
 * survived in this repository with CI green throughout.
 *
 * Three invariants matter more than the digests, and each has a vector PAIR
 * rather than a single value -- a pair is what distinguishes "this
 * implementation is right" from "this implementation is consistently wrong":
 *
 *   - order-independence:   two_sorted        == two_unsorted
 *   - whitespace-trimming:  whitespace_trimmed == single
 *   - case preservation:    case_preserved    != single
 *
 * The rejections matter for a reason of their own. Every one of them must be
 * an error and never a repair: stripping a control character or picking one of
 * two values for a repeated label would map two different inputs onto one
 * canonical string, which is two machines sharing one seat -- the mirror image
 * of the defect this helper exists to fix.
 */
#include "tamga_test.h"

#include "tamga.h"
#include "tamga_error.h"
#include "util/json.h"

#include <string.h>

#define FIXTURE_CAP 32768
#define MAX_COMPONENTS 8

/* A writable object to point an out-parameter at, so "was it written?" is a
 * pointer comparison against a real address rather than against a string
 * literal -- whose identity the standard does not fix. */
static char tt_sentinel[] = "sentinel";

static TamgaJson *load_fixture(void) {
    static char buffer[FIXTURE_CAP];
    size_t len =
        tt_read_fixture("fingerprint/fingerprint.json", (unsigned char *)buffer, sizeof(buffer));

    if (len == (size_t)-1) {
        return NULL;
    }
    return tamga_json_parse(buffer, len, NULL);
}

/* Unpacks a vector's `components` into the two parallel arrays the API takes.
 * Returns the count, or (size_t)-1 when the vector is unreadable. */
static size_t unpack(const TamgaJson *vector, const char **labels, const char **values) {
    const TamgaJson *components = tamga_json_object_get(vector, "components");
    size_t count = tamga_json_array_len(components);
    size_t i;

    if (count > MAX_COMPONENTS) {
        return (size_t)-1;
    }
    for (i = 0u; i < count; i++) {
        const TamgaJson *pair = tamga_json_array_at(components, i);
        if (tamga_json_array_len(pair) != 2u) {
            return (size_t)-1;
        }
        labels[i] = tamga_json_as_string(tamga_json_array_at(pair, 0u), NULL);
        values[i] = tamga_json_as_string(tamga_json_array_at(pair, 1u), NULL);
        if (labels[i] == NULL || values[i] == NULL) {
            return (size_t)-1;
        }
    }
    return count;
}

/*
 * The fixture spells the separator as the literal text "<US>" so the file
 * stays diffable and greppable; the real byte is 0x1f and it is the byte that
 * gets hashed. Expanding it here rather than storing a raw control character
 * in the JSON keeps both halves honest.
 */
static void expand_separator(const char *display, char *out, size_t out_cap) {
    size_t o = 0u;
    size_t i = 0u;

    while (display[i] != '\0' && o + 1u < out_cap) {
        if (strncmp(display + i, "<US>", 4u) == 0) {
            out[o++] = (char)0x1F;
            i += 4u;
        } else {
            out[o++] = display[i++];
        }
    }
    out[o] = '\0';
}

/*
 * The vector file survives the trip from disk byte for byte.
 *
 * ⚠️ This guards a failure that shows on ONE CI leg and nowhere else, and that
 * looks like a green suite until it does. tamga-python's `non_ascii_value`
 * vector failed on windows-latest alone, because its reader decoded the file
 * through the platform locale codec (cp1252) and the `é` arrived as mojibake
 * with a different digest. Every other vector is pure ASCII, so a suite
 * without a non-ASCII one passes against a mis-decoding reader and proves
 * nothing.
 *
 * C is the least exposed of the eight -- tt_read_fixture() opens "rb" and
 * fread()s into a byte buffer, so nothing decodes and nothing translates
 * CRLF -- and `.gitattributes` marks the whole `tests/fixtures` tree `-text`,
 * so Git
 * does not rewrite line endings on a Windows checkout either. Both are load-
 * bearing and neither is visible from this file, so the bytes are asserted
 * here rather than assumed: if either regresses, this fails on Windows with a
 * message naming the cause instead of a digest mismatch naming nothing.
 */
TT_TEST(the_vector_file_reaches_the_test_as_bytes) {
    static char raw[FIXTURE_CAP];
    size_t len = tt_read_fixture("fingerprint/fingerprint.json", (unsigned char *)raw, sizeof(raw));
    size_t i;
    bool saw_high_byte = false;
    bool saw_cr = false;

    TT_ASSERT(len != (size_t)-1);
    TT_ASSERT(len > 0u);
    for (i = 0u; i < len; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (c > 0x7FU) {
            saw_high_byte = true;
        }
        if (c == '\r') {
            saw_cr = true;
        }
    }
    /* The `café` in non_ascii_value is stored as raw UTF-8, so a reader that
     * decoded and re-encoded through a single-byte codepage would show up as
     * either a missing high byte or a changed one. */
    TT_ASSERT(saw_high_byte);
    /* No CR anywhere: a Windows checkout that translated line endings would
     * put one before every LF, and a fixture whose bytes depend on the
     * platform is not a fixture. */
    TT_ASSERT_FALSE(saw_cr);
    /* And the exact two bytes of U+00E9 are present in that order. */
    TT_ASSERT_NOT_NULL(memchr(raw, (int)(unsigned char)0xC3, len));
}

TT_TEST(every_published_vector_is_reproduced) {
    TamgaJson *fixture = load_fixture();
    const TamgaJson *vectors;
    size_t count;
    size_t i;

    TT_ASSERT_NOT_NULL(fixture);
    vectors = tamga_json_object_get(fixture, "vectors");
    count = tamga_json_array_len(vectors);
    /* A fixture that stopped loading would turn this whole file into a no-op
     * that still reports success. */
    TT_ASSERT(count >= 9u);

    for (i = 0u; i < count; i++) {
        const TamgaJson *vector = tamga_json_array_at(vectors, i);
        const char *name = tamga_json_as_string(tamga_json_object_get(vector, "name"), NULL);
        const char *want_fp =
            tamga_json_as_string(tamga_json_object_get(vector, "fingerprint"), NULL);
        const char *want_canonical_display =
            tamga_json_as_string(tamga_json_object_get(vector, "canonical"), NULL);
        const char *labels[MAX_COMPONENTS];
        const char *values[MAX_COMPONENTS];
        char want_canonical[512];
        char *got_fp = NULL;
        char *got_canonical = NULL;
        size_t n;

        TT_ASSERT_NOT_NULL(name);
        TT_ASSERT_NOT_NULL(want_fp);
        TT_ASSERT_NOT_NULL(want_canonical_display);
        n = unpack(vector, labels, values);
        TT_ASSERT(n != (size_t)-1);

        if (tamga_fingerprint_compute(labels, values, (uintptr_t)n, &got_fp) != TAMGA_OK) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: vector %s did not compute: %s\n", tt_current_, name,
                          tamga_last_error_message());
            continue;
        }
        if (strcmp(got_fp, want_fp) != 0) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s\n  vector:   %s\n  got:      %s\n  expected: %s\n",
                          tt_current_, name, got_fp, want_fp);
        }
        /* 64 lowercase hex characters, always. A build that widened or
         * shortened it would compute fingerprints matching nothing any other
         * SDK produces, and a caller sizing a buffer from the constant would
         * overflow it. */
        if (strlen(got_fp) != (size_t)TAMGA_FINGERPRINT_LENGTH) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: vector %s length %zu\n", tt_current_, name,
                          strlen(got_fp));
        }
        tamga_string_free(got_fp);

        /* The canonical string is checked too, not just the digest: two
         * implementations can agree on a digest only by agreeing on the bytes,
         * but a mismatch reported at the digest says nothing about WHICH rule
         * diverged. */
        expand_separator(want_canonical_display, want_canonical, sizeof(want_canonical));
        if (tamga_fingerprint_canonical(labels, values, (uintptr_t)n, &got_canonical) != TAMGA_OK) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: vector %s canonical failed\n", tt_current_, name);
            continue;
        }
        if (strcmp(got_canonical, want_canonical) != 0) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s\n  vector:    %s\n  canonical: %s\n  expected:  %s\n",
                          tt_current_, name, got_canonical, want_canonical);
        }
        tamga_string_free(got_canonical);
    }
    tamga_json_free(fixture);
}

/* Every `rejected` case is refused, and refused as a component problem rather
 * than as a null argument or an allocation failure -- a caller that cannot
 * tell "your component is wrong" from "this machine is out of memory" retries
 * the first forever. */
TT_TEST(every_published_rejection_is_refused) {
    TamgaJson *fixture = load_fixture();
    const TamgaJson *rejected;
    size_t count;
    size_t i;

    TT_ASSERT_NOT_NULL(fixture);
    rejected = tamga_json_object_get(fixture, "rejected");
    count = tamga_json_array_len(rejected);
    TT_ASSERT(count >= 8u);

    for (i = 0u; i < count; i++) {
        const TamgaJson *vector = tamga_json_array_at(rejected, i);
        const char *name = tamga_json_as_string(tamga_json_object_get(vector, "name"), NULL);
        const char *labels[MAX_COMPONENTS];
        const char *values[MAX_COMPONENTS];
        char *out = tt_sentinel;
        size_t n;
        TamgaErrorCode status;

        TT_ASSERT_NOT_NULL(name);
        n = unpack(vector, labels, values);
        TT_ASSERT(n != (size_t)-1);

        status = tamga_fingerprint_compute(labels, values, (uintptr_t)n, &out);
        if (status != TAMGA_ERR_INVALID_FINGERPRINT_COMPONENT) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s returned %s, expected refusal\n", tt_current_, name,
                          tamga_error_name(status));
        }
        /* Nothing is written on a rejection, so a caller that ignored the
         * return value cannot free -- or send -- a fingerprint that was never
         * produced. */
        if (out != tt_sentinel) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s wrote to the out-parameter\n", tt_current_, name);
        }
        /* And it says which component, not just that one was wrong. */
        TT_ASSERT_NOT_NULL(tamga_last_error_message());

        out = tt_sentinel;
        status = tamga_fingerprint_canonical(labels, values, (uintptr_t)n, &out);
        if (status != TAMGA_ERR_INVALID_FINGERPRINT_COMPONENT) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s canonical returned %s\n", tt_current_, name,
                          tamga_error_name(status));
        }
        /* And this one writes nothing either. It is the entry point that hands
         * its caller's out-parameter straight to the builder, so a builder
         * that cleared the pointer on a rejection path would be visible here
         * and nowhere else -- tamga_fingerprint_compute() above passes a local
         * of its own and would absorb it. */
        if (out != tt_sentinel) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s canonical wrote to the out-parameter\n", tt_current_,
                          name);
        }
    }
    tamga_json_free(fixture);
}

/*
 * The three invariants, asserted directly rather than left implicit in the
 * digest table -- a table of expected values passes for an implementation that
 * is consistently wrong in the same way the table was generated wrong, while
 * an equality between two of its own outputs does not.
 */
TT_TEST(the_three_invariants_hold_between_the_vector_pairs) {
    static const char *const SORTED_L[] = {"disk", "machine-id"};
    static const char *const SORTED_V[] = {"SN-9", "abc123"};
    static const char *const UNSORTED_L[] = {"machine-id", "disk"};
    static const char *const UNSORTED_V[] = {"abc123", "SN-9"};
    static const char *const ONE_L[] = {"machine-id"};
    static const char *const PLAIN_V[] = {"abc123"};
    static const char *const PADDED_V[] = {"  abc123\t\n"};
    static const char *const UPPER_V[] = {"ABC123"};
    char *sorted = NULL;
    char *unsorted = NULL;
    char *plain = NULL;
    char *padded = NULL;
    char *upper = NULL;

    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(SORTED_L, SORTED_V, 2u, &sorted), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(UNSORTED_L, UNSORTED_V, 2u, &unsorted), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(ONE_L, PLAIN_V, 1u, &plain), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(ONE_L, PADDED_V, 1u, &padded), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(ONE_L, UPPER_V, 1u, &upper), TAMGA_OK);

    /* Order is the caller's convenience, not part of the identity. */
    TT_ASSERT_EQ_STR(sorted, unsorted);
    /* The stray newline off a command's output is the footgun this absorbs. */
    TT_ASSERT_EQ_STR(plain, padded);
    /* Case folding is deliberately absent: lowercasing a base64 or hex
     * identifier corrupts it. */
    TT_ASSERT(strcmp(plain, upper) != 0);

    tamga_string_free(sorted);
    tamga_string_free(unsorted);
    tamga_string_free(plain);
    tamga_string_free(padded);
    tamga_string_free(upper);
}

/*
 * Non-ASCII passes through as its UTF-8 bytes, and ordering across components
 * is decided by the label.
 *
 * ⚠️ This does NOT pin the comparator's signedness, and it cannot -- see
 * fingerprint_sort_test.c, which pins that directly. The reason is structural:
 * labels are unique (duplicates are rejected) and ASCII-printable excluding
 * `=`, so for any two distinct components the first differing byte always
 * falls inside the label region or at the `=` boundary, and is therefore
 * always ASCII. Two implementations that disagree only about bytes above 0x7F
 * produce identical output for every input this entry point accepts. A test
 * here claiming otherwise would pass against both and prove nothing, which is
 * exactly the "consistently wrong" failure the vector pairs exist to avoid.
 *
 * What IS worth pinning here is that the non-ASCII bytes survive the round
 * trip untouched -- neither transcoded, escaped, nor normalised -- which is
 * the promise the `unicode` clause of the spec makes to a caller.
 */
TT_TEST(non_ascii_bytes_pass_through_the_sort_untouched) {
    static const char *const L[] = {"z-ascii", "a-utf8"};
    /* 0xC3 0xA9 is U+00E9 as UTF-8, and stays those two bytes. Composed here
     * on purpose: U+0065 U+0301 is the same character in NFD and MUST produce
     * a different fingerprint, because this rule deliberately does not
     * normalise. */
    static const char *const V[] = {"plain", "caf\xC3\xA9"};
    static const char *const SWAPPED_L[] = {"a-utf8", "z-ascii"};
    static const char *const SWAPPED_V[] = {"caf\xC3\xA9", "plain"};
    static const char *const NFD_L[] = {"z-ascii", "a-utf8"};
    static const char *const NFD_V[] = {"plain", "cafe\xCC\x81"};
    char *canonical = NULL;
    char *swapped = NULL;
    char *nfd = NULL;

    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(L, V, 2u, &canonical), TAMGA_OK);
    /* 'a' (0x61) < 'z' (0x7A), so the utf8-valued component sorts first and its
     * non-ASCII bytes sit in the middle of the string, byte for byte. */
    TT_ASSERT_EQ_STR(canonical, "tamga-fingerprint-v1\x1F"
                                "a-utf8=caf\xC3\xA9\x1F"
                                "z-ascii=plain");
    /* Order is still the caller's convenience with a non-ASCII value in play. */
    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(SWAPPED_L, SWAPPED_V, 2u, &swapped), TAMGA_OK);
    TT_ASSERT_EQ_STR(canonical, swapped);

    /* NFC and NFD of the same character are different inputs and stay
     * different -- the constraint, not an oversight. A caller whose values can
     * arrive in either form must normalise before calling. */
    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(NFD_L, NFD_V, 2u, &nfd), TAMGA_OK);
    TT_ASSERT(strcmp(canonical, nfd) != 0);

    tamga_string_free(canonical);
    tamga_string_free(swapped);
    tamga_string_free(nfd);
}

/*
 * A shorter label does not jump the queue behind a longer one.
 *
 * ⚠️ Like the test above, this is NOT the comparator's prefix tiebreak: no two
 * valid components can be in a prefix relationship at all. If label L1 is a
 * proper prefix of L2, then at position strlen(L1) the first component holds
 * `=` and the second holds a label byte, which cannot be `=` -- so they
 * differ there and neither is a prefix of the other. The tiebreak is pinned
 * directly in fingerprint_sort_test.c. What this pins is the ordinary case it
 * is easy to get wrong: "a=1" before "ab=2", decided at index 1 by
 * '=' (0x3D) < 'b' (0x62), NOT by the labels' lengths.
 */
TT_TEST(a_shorter_label_sorts_by_its_bytes_not_by_its_length) {
    static const char *const L[] = {"ab", "a"};
    static const char *const V[] = {"2", "1"};
    char *canonical = NULL;

    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(L, V, 2u, &canonical), TAMGA_OK);
    TT_ASSERT_EQ_STR(canonical, "tamga-fingerprint-v1\x1F"
                                "a=1\x1F"
                                "ab=2");
    tamga_string_free(canonical);
}

/*
 * The sort key is the WHOLE `label=value` component, not the label alone.
 *
 * The published vectors cannot tell the two apart: their labels are all
 * distinct words where neither is a prefix of another, so both rules produce
 * the same order and a table of digests stays green against either. It takes a
 * label that is a proper prefix of another to separate them, and then the two
 * rules disagree outright.
 *
 * Sorting by the label alone is not a hypothetical simplification -- it is the
 * obvious one to reach for, since the label is what makes a component unique.
 * It would put this SDK's fingerprint at odds with every other port for any
 * caller whose labels happen to nest, silently costing that customer a second
 * seat per machine.
 */
TT_TEST(the_sort_key_is_the_whole_component_not_just_the_label) {
    static const char *const L[] = {"a-b", "a"};
    static const char *const V[] = {"y", "x"};
    char *canonical = NULL;

    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(L, V, 2u, &canonical), TAMGA_OK);
    /* Whole component: "a-b=y" vs "a=x" differ at index 1, '-' (0x2D) below
     * '=' (0x3D), so "a-b=y" comes FIRST.
     * Label only:      "a-b"   vs "a"   -- "a" is a prefix and therefore
     *                  shorter, so "a=x" would come first. The two rules
     *                  produce opposite orders, which is the point. */
    TT_ASSERT_EQ_STR(canonical, "tamga-fingerprint-v1\x1F"
                                "a-b=y\x1F"
                                "a=x");
    tamga_string_free(canonical);
}

/*
 * The sort is case-SENSITIVE, like every other comparison in this rule.
 *
 * The published vectors cannot tell this apart either -- their labels are all
 * lowercase, so folding changes nothing. `case_preserved` pins that a value's
 * case survives into the canonical string; it says nothing about whether case
 * is honoured when ORDERING two components, and an implementation that
 * preserved case in the output while folding it in the comparator would pass
 * every one of them.
 */
TT_TEST(the_sort_is_case_sensitive) {
    static const char *const L[] = {"B", "a"};
    static const char *const V[] = {"1", "2"};
    char *canonical = NULL;

    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(L, V, 2u, &canonical), TAMGA_OK);
    /* 'B' (0x42) is below 'a' (0x61), so "B=1" sorts first. Folded to lower
     * case it would be 'b' against 'a' and the order would reverse. */
    TT_ASSERT_EQ_STR(canonical, "tamga-fingerprint-v1\x1F"
                                "B=1\x1F"
                                "a=2");
    tamga_string_free(canonical);
}

/* Null arguments are a null-argument error, not a component one: the caller's
 * remedy is different and conflating them sends them to inspect a component
 * that was never passed. */
TT_TEST(null_arguments_are_told_apart_from_bad_components) {
    static const char *const L[] = {"id"};
    static const char *const V[] = {"a"};
    static const char *const NULL_L[] = {NULL};
    char *out = tt_sentinel;

    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(NULL, V, 1u, &out), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(L, NULL, 1u, &out), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(L, V, 1u, NULL), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(NULL, V, 1u, &out), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(L, V, 1u, NULL), TAMGA_ERR_NULL_ARGUMENT);
    /* A null INSIDE the array is also a null argument rather than an invalid
     * component -- there is no component there to call invalid. */
    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(NULL_L, V, 1u, &out), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT(out == tt_sentinel);

    /* Zero components is a component problem: the caller passed arrays, they
     * were just empty. */
    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(L, V, 0u, &out),
                     TAMGA_ERR_INVALID_FINGERPRINT_COMPONENT);
    TT_ASSERT(out == tt_sentinel);

    /* TAMGA_OK means the error slot is clear, on this path like every other. */
    out = NULL;
    TT_ASSERT_EQ_INT(tamga_fingerprint_compute(L, V, 1u, &out), TAMGA_OK);
    TT_ASSERT_NULL(tamga_last_error_message());
    tamga_string_free(out);
}

/*
 * An empty value keeps its label, and a label-only component is not the same
 * as no component at all -- otherwise a machine whose optional serial reads
 * empty would fingerprint identically to one that never had that component,
 * and the two would share a seat.
 */
TT_TEST(an_empty_value_still_contributes_its_label) {
    static const char *const L[] = {"machine-id"};
    static const char *const EMPTY[] = {""};
    static const char *const BLANK[] = {"   \t  "};
    char *empty = NULL;
    char *blank = NULL;

    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(L, EMPTY, 1u, &empty), TAMGA_OK);
    TT_ASSERT_EQ_STR(empty, "tamga-fingerprint-v1\x1F"
                            "machine-id=");
    /* Trimmed to empty is the same as empty: the trim happens first. */
    TT_ASSERT_EQ_INT(tamga_fingerprint_canonical(L, BLANK, 1u, &blank), TAMGA_OK);
    TT_ASSERT_EQ_STR(empty, blank);
    tamga_string_free(empty);
    tamga_string_free(blank);
}

int main(void) {
    TT_RUN(the_vector_file_reaches_the_test_as_bytes);
    TT_RUN(every_published_vector_is_reproduced);
    TT_RUN(every_published_rejection_is_refused);
    TT_RUN(the_three_invariants_hold_between_the_vector_pairs);
    TT_RUN(non_ascii_bytes_pass_through_the_sort_untouched);
    TT_RUN(a_shorter_label_sorts_by_its_bytes_not_by_its_length);
    TT_RUN(the_sort_key_is_the_whole_component_not_just_the_label);
    TT_RUN(the_sort_is_case_sensitive);
    TT_RUN(null_arguments_are_told_apart_from_bad_components);
    TT_RUN(an_empty_value_still_contributes_its_label);
    return TT_SUMMARY();
}
