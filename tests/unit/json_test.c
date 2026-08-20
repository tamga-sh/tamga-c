#include "tamga_test.h"

#include "tamga_mem.h"
#include "util/json.h"

/* Parses `text`, canonicalises it, and compares against `expected`. */
static void canonical_is(const char *text, const char *expected) {
    const char *err = NULL;
    TamgaJson *value = tamga_json_parse(text, strlen(text), &err);
    char *out;

    if (value == NULL) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: parse(%s) rejected: %s\n", tt_current_, text,
                      err ? err : "?");
        return;
    }
    out = tamga_json_write_canonical(value, NULL);
    if (out == NULL) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: canonical serialization failed\n", tt_current_);
        tamga_json_free(value);
        return;
    }
    if (strcmp(out, expected) != 0) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s\n  input:    %s\n  expected: %s\n  actual:   %s\n",
                      tt_current_, text, expected, out);
    }
    tamga_free(out);
    tamga_json_free(value);
}

static void rejects(const char *text) {
    const char *err = NULL;
    TamgaJson *value = tamga_json_parse(text, strlen(text), &err);
    if (value != NULL) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: expected rejection of: %s\n", tt_current_, text);
        tamga_json_free(value);
        return;
    }
    if (err == NULL) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: rejected without an error message: %s\n", tt_current_,
                      text);
    }
}

TT_TEST(scalars_round_trip) {
    canonical_is("null", "null");
    canonical_is("true", "true");
    canonical_is("false", "false");
    canonical_is("0", "0");
    canonical_is("-1", "-1");
    canonical_is("9223372036854775807", "9223372036854775807");
    canonical_is("-9223372036854775808", "-9223372036854775808");
    canonical_is("\"\"", "\"\"");
    canonical_is("\"hi\"", "\"hi\"");
    canonical_is("[]", "[]");
    canonical_is("{}", "{}");
}

/* An integer and a float are distinct JSON texts. Writing 8 where the
 * document had 8.0 (or the reverse) changes the bytes that get signed. */
TT_TEST(integers_and_floats_keep_their_form) {
    canonical_is("8", "8");
    canonical_is("8.0", "8.0");
    canonical_is("0.5", "0.5");
    canonical_is("-0.25", "-0.25");
    canonical_is("1.5e3", "1500.0");
}

/*
 * Every pair below was produced by running the input through serde_json 1.x
 * -- the exact library the Tamga server serialises with -- and recording its
 * output verbatim. This is the conformance anchor for the canonical writer:
 * if any of these drift, the offline proof stops verifying against real
 * server-issued material.
 *
 * Regenerate with the oracle described in CLAUDE.md rather than by reasoning
 * about what the output "should" be.
 */
TT_TEST(matches_serde_json_verbatim) {
    /* numbers: notation thresholds and the explicit exponent sign */
    canonical_is("8", "8");
    canonical_is("8.0", "8.0");
    canonical_is("0.1", "0.1");
    canonical_is("100.0", "100.0");
    canonical_is("1.5e3", "1500.0");
    canonical_is("1e15", "1000000000000000.0");
    canonical_is("1e16", "1e+16");
    canonical_is("1e17", "1e+17");
    canonical_is("1e21", "1e+21");
    canonical_is("1e30", "1e+30");
    canonical_is("0.0001", "0.0001");
    canonical_is("1e-5", "0.00001");
    canonical_is("1e-6", "1e-6");
    canonical_is("2.5e-10", "2.5e-10");
    canonical_is("-0.0", "-0.0");
    canonical_is("3.141592653589793", "3.141592653589793");
    canonical_is("1.7976931348623157e308", "1.7976931348623157e+308");
    canonical_is("5e-324", "5e-324");
    /*
     * Written as its own shortest form rather than as "123456789012345680000.0":
     * serde_json's *parser* resolves that spelling to 0x441ac53a7e04bcd9 while
     * strtod (and Python, and every other correctly-rounding parser checked)
     * resolves it to 0x441ac53a7e04bcda -- a one-ULP divergence in serde_json,
     * confirmed by comparing to_bits() output directly. Given the same f64,
     * serde_json's writer and this one agree, which is the property the signed
     * payload actually depends on. Pinning the disputed spelling here would
     * assert serde_json's parser bug rather than this writer's correctness.
     */
    canonical_is("1.2345678901234568e+20", "1.2345678901234568e+20");
    /* 2^53 + 1 -- exact as an integer, unrepresentable as a double */
    canonical_is("9007199254740993", "9007199254740993");

    /* ordering */
    canonical_is("{\"b\":1,\"a\":2}", "{\"a\":2,\"b\":1}");
    canonical_is("{\"z\":{\"y\":1,\"x\":2},\"a\":3}", "{\"a\":3,\"z\":{\"x\":2,\"y\":1}}");
    canonical_is("{\"ab\":1,\"a\":2}", "{\"a\":2,\"ab\":1}");
    canonical_is("{\"a\":1,\"\":2}", "{\"\":2,\"a\":1}");
    canonical_is("[3,1,2]", "[3,1,2]");
    canonical_is("{\"a\":1,\"a\":2}", "{\"a\":2}");

    /* strings */
    canonical_is("\"a/b\"", "\"a/b\"");
    canonical_is("\"\\u0000\"", "\"\\u0000\"");
    canonical_is("\"\\u001f\"", "\"\\u001f\"");
    canonical_is("\"\\u000b\"", "\"\\u000b\"");
    canonical_is("\"\\u00e7\"", "\"\xC3\xA7\"");
    canonical_is("\"\\ud83d\\ude00\"", "\"\xF0\x9F\x98\x80\"");
    canonical_is("\"a\\\"b\"", "\"a\\\"b\"");
    canonical_is("\"a\\\\b\"", "\"a\\\\b\"");
    canonical_is("\"a\\nb\"", "\"a\\nb\"");

    /* the offline proof payload, and the UTF-8-vs-UTF-16 ordering pair */
    canonical_is("{\"account\":{\"id\":\"a\"},\"machine\":{\"id\":\"m\",\"fingerprint\":\"f\"},"
                 "\"dataset\":{}}",
                 "{\"account\":{\"id\":\"a\"},\"dataset\":{},"
                 "\"machine\":{\"fingerprint\":\"f\",\"id\":\"m\"}}");
    canonical_is("{\"\\ud83d\\ude00\":1,\"\\ue000\":2}",
                 "{\"\xEE\x80\x80\":2,\"\xF0\x9F\x98\x80\":1}");
}

TT_TEST(arrays_keep_document_order) {
    canonical_is("[3,1,2]", "[3,1,2]");
    canonical_is("[\"b\",\"a\"]", "[\"b\",\"a\"]");
    canonical_is(" [ 1 , 2 ] ", "[1,2]");
}

TT_TEST(object_keys_sort_at_every_level) {
    canonical_is("{\"b\":1,\"a\":2}", "{\"a\":2,\"b\":1}");
    canonical_is("{\"z\":{\"y\":1,\"x\":2},\"a\":3}", "{\"a\":3,\"z\":{\"x\":2,\"y\":1}}");
    canonical_is("{\"b\":[{\"d\":1,\"c\":2}],\"a\":0}", "{\"a\":0,\"b\":[{\"c\":2,\"d\":1}]}");
}

/*
 * The exact payload the offline proof signs. The server's source writes
 * account, machine, dataset in that order, but serde_json's BTreeMap-backed
 * map emits them alphabetically -- so the wire bytes put dataset before
 * machine, and fingerprint before id. Reproducing the source order instead of
 * the serialized order is the single most likely way to get this wrong.
 */
TT_TEST(reproduces_the_offline_proof_payload_ordering) {
    canonical_is("{\"account\":{\"id\":\"a\"},\"machine\":{\"id\":\"m\",\"fingerprint\":\"f\"},"
                 "\"dataset\":{}}",
                 "{\"account\":{\"id\":\"a\"},\"dataset\":{},"
                 "\"machine\":{\"fingerprint\":\"f\",\"id\":\"m\"}}");
}

/*
 * U+E000 (private use, UTF-8 EE 80 80) versus U+10000 (astral, UTF-8
 * F0 90 80 80).
 *
 *   UTF-8 bytes:      EE... < F0...     so U+E000 sorts first.
 *   UTF-16 units:     D800  < E000      so U+10000 sorts first.
 *
 * The two orders disagree. Rust's BTreeMap<String, _> -- which is what the
 * server signs through -- uses UTF-8 byte order, so that is the only correct
 * answer here. This SDK family has already shipped the UTF-16 answer once, in
 * tamga-js.
 */
TT_TEST(keys_sort_by_utf8_bytes_not_utf16_code_units) {
    canonical_is("{\"\xF0\x90\x80\x80\":1,\"\xEE\x80\x80\":2}",
                 "{\"\xEE\x80\x80\":2,\"\xF0\x90\x80\x80\":1}");
}

/* A key that is a prefix of another sorts first, matching Rust's Ord for
 * String. Comparing only the shared prefix would make the order depend on
 * whatever byte follows the end of the shorter key. */
TT_TEST(a_prefix_key_sorts_before_its_extension) {
    canonical_is("{\"ab\":1,\"a\":2}", "{\"a\":2,\"ab\":1}");
    canonical_is("{\"a\":1,\"\":2}", "{\"\":2,\"a\":1}");
}

TT_TEST(escaping_matches_serde_json) {
    canonical_is("\"a\\\"b\"", "\"a\\\"b\"");
    canonical_is("\"a\\\\b\"", "\"a\\\\b\"");
    canonical_is("\"a\\nb\"", "\"a\\nb\"");
    canonical_is("\"a\\tb\"", "\"a\\tb\"");
    canonical_is("\"a\\rb\"", "\"a\\rb\"");
    canonical_is("\"a\\bb\"", "\"a\\bb\"");
    canonical_is("\"a\\fb\"", "\"a\\fb\"");
    /* Remaining C0 controls become lowercase \u00xx. */
    canonical_is("\"\\u0000\"", "\"\\u0000\"");
    canonical_is("\"\\u001f\"", "\"\\u001f\"");
    canonical_is("\"\\u000b\"", "\"\\u000b\"");
    /* serde_json does not escape the forward slash. */
    canonical_is("\"a/b\"", "\"a/b\"");
    /* Non-ASCII is emitted as raw UTF-8, never as a \u escape. */
    canonical_is("\"\\u00e7\"", "\"\xC3\xA7\"");
    canonical_is("\"\xC3\xA7\"", "\"\xC3\xA7\"");
    /* A surrogate pair decodes to one astral character. */
    canonical_is("\"\\ud83d\\ude00\"", "\"\xF0\x9F\x98\x80\"");
}

TT_TEST(duplicate_keys_keep_the_last_value) {
    /* serde_json's map insert overwrites, so the server reads the same
     * document the same way. */
    canonical_is("{\"a\":1,\"a\":2}", "{\"a\":2}");
}

TT_TEST(rejects_lenient_extensions) {
    rejects("");
    rejects("   ");
    rejects("{,}");
    rejects("[1,]");          /* trailing comma */
    rejects("{\"a\":1,}");    /* trailing comma */
    rejects("{'a':1}");       /* single quotes */
    rejects("{a:1}");         /* unquoted key */
    rejects("// comment\n1"); /* comments */
    rejects("NaN");
    rejects("Infinity");
    rejects("-Infinity");
    rejects("01");  /* leading zero */
    rejects("+1");  /* leading plus */
    rejects(".5");  /* no integer part */
    rejects("1.");  /* no fraction digits */
    rejects("1e");  /* no exponent digits */
    rejects("1 2"); /* trailing content */
    rejects("{} {}");
    rejects("\"unterminated");
    rejects("[1,2");
    rejects("{\"a\" 1}"); /* missing colon */
    rejects("tru");
}

TT_TEST(rejects_malformed_unicode) {
    rejects("\"\\ud800\"");          /* lone high surrogate */
    rejects("\"\\udc00\"");          /* lone low surrogate */
    rejects("\"\\ud800\\ud800\"");   /* high followed by high */
    rejects("\"\\u00\"");            /* short escape */
    rejects("\"\\q\"");              /* unknown escape */
    rejects("\"\xC3\"");             /* truncated UTF-8 sequence */
    rejects("\"\xC0\xAF\"");         /* overlong encoding of '/' */
    rejects("\"\xED\xA0\x80\"");     /* surrogate encoded directly in UTF-8 */
    rejects("\"\xF5\x80\x80\x80\""); /* above U+10FFFF */
    rejects("\"\x01\"");             /* unescaped control character */
}

/* Without a depth cap, a document made of nothing but opening brackets
 * recurses until the C stack runs out -- a crash, from a file the caller has
 * every reason to treat as untrusted. */
TT_TEST(rejects_excessive_nesting) {
    char deep[(TAMGA_JSON_MAX_DEPTH * 2) + 8];
    size_t i;
    size_t limit = TAMGA_JSON_MAX_DEPTH + 2u;

    for (i = 0u; i < limit; i++) {
        deep[i] = '[';
    }
    for (i = 0u; i < limit; i++) {
        deep[limit + i] = ']';
    }
    deep[limit * 2u] = '\0';
    rejects(deep);
}

TT_TEST(accepts_nesting_up_to_the_limit) {
    char deep[(TAMGA_JSON_MAX_DEPTH * 2) + 8];
    const char *err = NULL;
    TamgaJson *value;
    size_t i;
    size_t limit = TAMGA_JSON_MAX_DEPTH;

    for (i = 0u; i < limit; i++) {
        deep[i] = '[';
    }
    for (i = 0u; i < limit; i++) {
        deep[limit + i] = ']';
    }
    deep[limit * 2u] = '\0';

    value = tamga_json_parse(deep, strlen(deep), &err);
    TT_ASSERT_NOT_NULL(value);
    tamga_json_free(value);
}

TT_TEST(accessors_read_the_tree) {
    const char *text = "{\"n\":7,\"s\":\"x\",\"b\":true,\"a\":[1,2],\"o\":{\"k\":null}}";
    const char *err = NULL;
    TamgaJson *root = tamga_json_parse(text, strlen(text), &err);
    int64_t number = 0;

    TT_ASSERT_NOT_NULL(root);
    TT_ASSERT_EQ_INT(tamga_json_type(root), TAMGA_JSON_OBJECT);
    TT_ASSERT_EQ_SIZE(tamga_json_object_len(root), 5u);

    TT_ASSERT(tamga_json_as_int(tamga_json_object_get(root, "n"), &number));
    TT_ASSERT_EQ_INT(number, 7);
    TT_ASSERT_EQ_STR(tamga_json_as_string(tamga_json_object_get(root, "s"), NULL), "x");
    TT_ASSERT(tamga_json_bool_or(tamga_json_object_get(root, "b"), false));
    TT_ASSERT_EQ_SIZE(tamga_json_array_len(tamga_json_object_get(root, "a")), 2u);
    TT_ASSERT(tamga_json_is_null(tamga_json_object_get(tamga_json_object_get(root, "o"), "k")));
    TT_ASSERT_NULL(tamga_json_object_get(root, "missing"));

    tamga_json_free(root);
}

TT_TEST(an_integral_double_reads_as_an_int_but_writes_as_a_float) {
    const char *err = NULL;
    TamgaJson *value = tamga_json_parse("8.0", 3u, &err);
    int64_t number = 0;
    char *out;

    TT_ASSERT_NOT_NULL(value);
    TT_ASSERT(tamga_json_as_int(value, &number));
    TT_ASSERT_EQ_INT(number, 8);
    out = tamga_json_write_canonical(value, NULL);
    TT_ASSERT_NOT_NULL(out);
    TT_ASSERT_EQ_STR(out, "8.0");
    tamga_free(out);
    tamga_json_free(value);
}

TT_TEST(builders_produce_the_same_bytes_as_the_parser) {
    TamgaJson *root = tamga_json_new_object();
    TamgaJson *inner = tamga_json_new_object();
    char *out;

    TT_ASSERT_NOT_NULL(root);
    TT_ASSERT_NOT_NULL(inner);
    TT_ASSERT(tamga_json_object_set(inner, "id", tamga_json_new_string("m", 1u)));
    TT_ASSERT(tamga_json_object_set(inner, "fingerprint", tamga_json_new_string("f", 1u)));
    TT_ASSERT(tamga_json_object_set(root, "machine", inner));
    TT_ASSERT(tamga_json_object_set(root, "dataset", tamga_json_new_object()));

    out = tamga_json_write_canonical(root, NULL);
    TT_ASSERT_NOT_NULL(out);
    TT_ASSERT_EQ_STR(out, "{\"dataset\":{},\"machine\":{\"fingerprint\":\"f\",\"id\":\"m\"}}");
    tamga_free(out);
    tamga_json_free(root);
}

TT_TEST(the_compact_writer_preserves_insertion_order) {
    const char *text = "{\"b\":1,\"a\":2}";
    const char *err = NULL;
    TamgaJson *value = tamga_json_parse(text, strlen(text), &err);
    char *out;

    TT_ASSERT_NOT_NULL(value);
    out = tamga_json_write(value, NULL);
    TT_ASSERT_NOT_NULL(out);
    TT_ASSERT_EQ_STR(out, "{\"b\":1,\"a\":2}");
    tamga_free(out);
    tamga_json_free(value);
}

TT_TEST(clone_is_independent_of_its_source) {
    const char *text = "{\"a\":[1,{\"b\":\"c\"}]}";
    const char *err = NULL;
    TamgaJson *value = tamga_json_parse(text, strlen(text), &err);
    TamgaJson *copy;
    char *a;
    char *b;

    TT_ASSERT_NOT_NULL(value);
    copy = tamga_json_clone(value);
    TT_ASSERT_NOT_NULL(copy);
    a = tamga_json_write_canonical(value, NULL);
    b = tamga_json_write_canonical(copy, NULL);
    TT_ASSERT_NOT_NULL(a);
    TT_ASSERT_NOT_NULL(b);
    TT_ASSERT_EQ_STR(b, a);
    tamga_json_free(value);
    /* The copy must still be readable after its source is gone. */
    tamga_free(b);
    b = tamga_json_write_canonical(copy, NULL);
    TT_ASSERT_NOT_NULL(b);
    TT_ASSERT_EQ_STR(b, a);
    tamga_free(a);
    tamga_free(b);
    tamga_json_free(copy);
}

/* Ownership of the inserted value transfers unconditionally, including on
 * failure -- a caller that had to free it only on some paths would leak. */
TT_TEST(failed_inserts_still_consume_their_argument) {
    TamgaJson *array = tamga_json_new_array();
    TT_ASSERT_NOT_NULL(array);
    TT_ASSERT_FALSE(tamga_json_object_set(array, "k", tamga_json_new_int(1)));
    TT_ASSERT_FALSE(tamga_json_array_append(NULL, tamga_json_new_int(1)));
    tamga_json_free(array);
}

int main(void) {
    TT_RUN(scalars_round_trip);
    TT_RUN(integers_and_floats_keep_their_form);
    TT_RUN(matches_serde_json_verbatim);
    TT_RUN(arrays_keep_document_order);
    TT_RUN(object_keys_sort_at_every_level);
    TT_RUN(reproduces_the_offline_proof_payload_ordering);
    TT_RUN(keys_sort_by_utf8_bytes_not_utf16_code_units);
    TT_RUN(a_prefix_key_sorts_before_its_extension);
    TT_RUN(escaping_matches_serde_json);
    TT_RUN(duplicate_keys_keep_the_last_value);
    TT_RUN(rejects_lenient_extensions);
    TT_RUN(rejects_malformed_unicode);
    TT_RUN(rejects_excessive_nesting);
    TT_RUN(accepts_nesting_up_to_the_limit);
    TT_RUN(accessors_read_the_tree);
    TT_RUN(an_integral_double_reads_as_an_int_but_writes_as_a_float);
    TT_RUN(builders_produce_the_same_bytes_as_the_parser);
    TT_RUN(the_compact_writer_preserves_insertion_order);
    TT_RUN(clone_is_independent_of_its_source);
    TT_RUN(failed_inserts_still_consume_their_argument);
    return TT_SUMMARY();
}
