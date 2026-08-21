/*
 * The fingerprint component comparator, reached directly.
 *
 * Whitebox because tamga_fp_compare() is static and should stay that way, and
 * because its two most dangerous properties are UNREACHABLE through the public
 * entry points -- so a test written against those would pass equally against a
 * correct and an incorrect comparator, which is worse than no test.
 *
 * Why they are unreachable: labels are unique (a duplicate is rejected) and
 * ASCII-printable excluding `=`, so for any two distinct components the first
 * differing byte always lands inside the label region or at the `=` boundary,
 * and is therefore always ASCII. Two consequences:
 *
 *   - No comparison ever reaches a byte above 0x7F, so signed-versus-unsigned
 *     cannot change the resulting order.
 *   - No component can be a strict prefix of another. If label L1 is a proper
 *     prefix of L2 then at position strlen(L1) the first component holds `=`
 *     and the second holds a label byte, which cannot be `=`; they differ
 *     there, so neither extends the other.
 *
 * Both were confirmed by mutation: replacing memcmp with a signed `char`
 * subtraction, and deleting the length tiebreak, each leave every published
 * vector and every canonicalisation test passing. tamga-js measured the same
 * property exhaustively over 8,732,016 valid component pairs and found zero
 * divergence, so this is a property of the rule rather than of one port.
 *
 * ⚠️ So do NOT write a canonicalisation-level test or a vector claiming to
 * prove the signedness. It cannot fail, and a green test that cannot fail is
 * worse than none. The assertions below are deliberately at the level where
 * the property IS observable -- the comparator, called directly with inputs
 * the builder refuses.
 *
 * ⚠️ So why pin them at all, rather than simplify the comparator to match what
 * is reachable? Because the two facts above are properties of the *label*
 * rules, not of the sort, and the sort is where the cost lands if they ever
 * change. A v2 rule that allowed `=` in a label, or that stopped rejecting
 * duplicates, would make both cases live -- and a signed comparison would then
 * order the same machine's components differently on a signed-char target
 * (ARM) than on x86, silently producing two fingerprints and consuming two
 * seats. That is precisely the class of divergence the whole spec is shaped to
 * prevent. Pinning the comparator's contract here means the rules can be
 * relaxed without the sort quietly becoming wrong.
 */
#include "tamga_test.h"

#include "util/fingerprint.c" /* NOLINT(bugprone-suspicious-include) -- whitebox, see above */

/*
 * Builds a comparator input without going through the validating builder,
 * which is the whole point: these inputs are ones the builder refuses.
 *
 * `label_len` is filled in properly rather than left zero. A zero would make a
 * label-only comparator compare no bytes at all and report everything equal,
 * so every assertion below would "catch" that mutation for the wrong reason --
 * a test that passes because the fixture is malformed proves nothing about the
 * code.
 */
static TamgaFpComponent comp(const char *text) {
    TamgaFpComponent c;
    const char *eq = strchr(text, '=');
    c.text = (char *)(size_t)(const void *)text;
    c.len = strlen(text);
    c.label_len = (eq != NULL) ? (size_t)(eq - text) : c.len;
    return c;
}

static int cmp(const char *a, const char *b) {
    TamgaFpComponent x = comp(a);
    TamgaFpComponent y = comp(b);
    return tamga_fp_compare(&x, &y);
}

/* Ascending, ASCII, the ordinary case. */
TT_TEST(the_comparator_orders_ascii_ascending) {
    TT_ASSERT(cmp("a=1", "b=1") < 0);
    TT_ASSERT(cmp("b=1", "a=1") > 0);
    TT_ASSERT(cmp("a=1", "a=1") == 0);
    /* '=' (0x3D) is below every letter, which is what puts a short label
     * before a longer one that starts with it. */
    TT_ASSERT(cmp("a=1", "ab=2") < 0);
}

/*
 * The key is the whole component, so a difference in the VALUE orders two
 * components whose labels compare equal up to the shorter one's end.
 *
 * Sorting by the label alone is the obvious simplification -- the label is what
 * makes a component unique, so it looks sufficient -- and it reverses this
 * pair: as labels, "a" is a prefix of "a-b" and therefore sorts first, while as
 * whole components "a-b=y" sorts first because '-' (0x2D) is below '=' (0x3D).
 */
TT_TEST(the_comparator_keys_on_the_whole_component) {
    TT_ASSERT(cmp("a-b=y", "a=x") < 0);
    TT_ASSERT(cmp("a=x", "a-b=y") > 0);
    /* And with labels that compare equal, the value decides. Unreachable from
     * the builder (it rejects the duplicate first) but the comparator must
     * still be a total order, or qsort's behaviour is undefined. */
    TT_ASSERT(cmp("id=a", "id=b") < 0);
}

/*
 * Case-sensitive, like every other comparison in this rule.
 *
 * An implementation that preserved case in its OUTPUT while folding it in the
 * comparator passes every published vector, because their labels are all
 * lowercase.
 */
TT_TEST(the_comparator_is_case_sensitive) {
    /* 'B' (0x42) is below 'a' (0x61). Folded to lower case the order reverses. */
    TT_ASSERT(cmp("B=1", "a=2") < 0);
    TT_ASSERT(cmp("a=2", "B=1") > 0);
    /* Upper case sorts below lower throughout, values included. */
    TT_ASSERT(cmp("x=ABC", "x=abc") < 0);
}

/*
 * A byte above 0x7F is GREATER than every ASCII byte.
 *
 * Written as a signed `char` subtraction this is backwards: 0xC3 is -61, which
 * is less than every positive ASCII value, so "x=café" would sort before
 * "x=cafa" instead of after it -- and only on targets where `char` is signed,
 * so the same input would fingerprint differently on ARM than on x86.
 */
TT_TEST(the_comparator_treats_high_bytes_as_unsigned) {
    /* 0xC3 vs 'a' (0x61): the high byte is greater. */
    TT_ASSERT(cmp("x=\xC3\xA9", "x=a") > 0);
    TT_ASSERT(cmp("x=a", "x=\xC3\xA9") < 0);
    /* 0xC3 vs 0x7F, the largest byte a signed char still reads as positive. */
    TT_ASSERT(cmp("x=\xC3", "x=\x7F") > 0);
    /* 0x80, the first byte a signed char reads as negative, versus 0x00 -- the
     * pair that a signed comparison gets wrong most starkly. */
    TT_ASSERT(cmp("x=\x80", "x=\x01") > 0);
    /* And two high bytes are still ordered among themselves. */
    TT_ASSERT(cmp("x=\xC3", "x=\xC4") < 0);
    TT_ASSERT(cmp("x=\xFF", "x=\x80") > 0);
}

/*
 * A strict prefix sorts before the string that extends it.
 *
 * memcmp over the shorter length returns 0 for a prefix pair and says nothing
 * about which is greater, so a comparator that stopped there would report them
 * equal -- and qsort would then order them by whatever the implementation
 * happened to do, differing between libcs for identical input.
 */
TT_TEST(the_comparator_puts_a_prefix_before_what_extends_it) {
    TT_ASSERT(cmp("id=a", "id=ab") < 0);
    TT_ASSERT(cmp("id=ab", "id=a") > 0);
    TT_ASSERT(cmp("id=", "id=a") < 0);
    /* Equal length and equal bytes really is equal. */
    TT_ASSERT(cmp("id=ab", "id=ab") == 0);
    /* The tiebreak must not override a difference found earlier: a longer
     * string that differs before the shorter one ends is still ordered by that
     * difference, not by length. */
    TT_ASSERT(cmp("id=b", "id=ab") > 0);
}

/* A zero-length component compares equal to itself and below everything else,
 * rather than reading past either buffer. */
TT_TEST(the_comparator_handles_an_empty_component) {
    TT_ASSERT(cmp("", "") == 0);
    TT_ASSERT(cmp("", "a") < 0);
    TT_ASSERT(cmp("a", "") > 0);
}

int main(void) {
    TT_RUN(the_comparator_orders_ascii_ascending);
    TT_RUN(the_comparator_keys_on_the_whole_component);
    TT_RUN(the_comparator_is_case_sensitive);
    TT_RUN(the_comparator_treats_high_bytes_as_unsigned);
    TT_RUN(the_comparator_puts_a_prefix_before_what_extends_it);
    TT_RUN(the_comparator_handles_an_empty_component);
    return TT_SUMMARY();
}
