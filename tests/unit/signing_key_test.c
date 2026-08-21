/*
 * `kid` derivation and the key set that indexes by it.
 *
 * The vectors in tests/fixtures/signing-keys/ were produced by an independent
 * SHA-256 implementation and confirmed against tamga-rust's committed value --
 * deliberately not by this library, because a fixture the implementation under
 * test generated proves only that it agrees with itself. That is not a
 * hypothetical concern here: it is exactly how a two-year machine-file bug
 * survived in this repository with CI green throughout.
 *
 * The NEGATIVE vector is the one that matters. A `kid` derived by decoding the
 * base64 first is still sixteen well-formed hex characters, so a positive test
 * passes against an implementation that gets it backwards; only asserting the
 * wrong answer is NOT produced catches it.
 */
#include "tamga_test.h"

#include "checkout/key_set.h"
#include "tamga.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"
#include "util/json.h"

#include <string.h>

#define FIXTURE_CAP 16384

/* The all-zero 32-byte key and its published id, used wherever a test needs a
 * key that is well-formed and nothing else. */
static const char ZERO_KEY_B64[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
static const char ZERO_KEY_KID[] = "51643eac9777b63a";

static TamgaJson *load_json_fixture(const char *relative_path) {
    static char buffer[FIXTURE_CAP];
    size_t len = tt_read_fixture(relative_path, (unsigned char *)buffer, sizeof(buffer));

    if (len == (size_t)-1) {
        return NULL;
    }
    return tamga_json_parse(buffer, len, NULL);
}

TT_TEST(the_key_id_of_every_published_vector_is_reproduced) {
    TamgaJson *fixture = load_json_fixture("signing-keys/signing-key-ids.json");
    const TamgaJson *vectors;
    size_t count;
    size_t i;

    TT_ASSERT_NOT_NULL(fixture);
    vectors = tamga_json_object_get(fixture, "vectors");
    count = tamga_json_array_len(vectors);
    /* A fixture that stopped loading would turn this whole file into a no-op
     * that still reports success. */
    TT_ASSERT(count >= 5u);

    for (i = 0u; i < count; i++) {
        const TamgaJson *vector = tamga_json_array_at(vectors, i);
        const char *public_key =
            tamga_json_as_string(tamga_json_object_get(vector, "publicKey"), NULL);
        const char *expected = tamga_json_as_string(tamga_json_object_get(vector, "kid"), NULL);
        const char *name = tamga_json_as_string(tamga_json_object_get(vector, "name"), NULL);
        char computed[TAMGA_KEY_ID_SIZE];

        if (public_key == NULL || expected == NULL) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: vector %zu is unreadable\n", tt_current_, i);
            break;
        }
        if (tamga_signing_key_id(public_key, computed) != TAMGA_OK) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s did not compute\n", tt_current_,
                          (name != NULL) ? name : "?");
            break;
        }
        if (strcmp(computed, expected) != 0) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s expected %s, got %s\n", tt_current_,
                          (name != NULL) ? name : "?", expected, computed);
            break;
        }
        /* Sixteen characters, from the first EIGHT digest bytes -- not the
         * whole thirty-two-byte digest. */
        if (strlen(computed) != (size_t)TAMGA_KEY_ID_LENGTH) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s is %zu characters, expected %d\n", tt_current_,
                          (name != NULL) ? name : "?", strlen(computed), TAMGA_KEY_ID_LENGTH);
            break;
        }
    }
    tamga_json_free(fixture);
}

TT_TEST(the_key_id_hashes_the_base64_string_and_never_the_decoded_bytes) {
    TamgaJson *fixture = load_json_fixture("signing-keys/signing-key-ids.json");
    const TamgaJson *negative;
    const char *public_key;
    const char *correct;
    const char *wrong_if_decoded_first;
    char computed[TAMGA_KEY_ID_SIZE];
    unsigned char *decoded;
    size_t decoded_len = 0u;
    char computed_over_bytes[TAMGA_KEY_ID_SIZE];

    TT_ASSERT_NOT_NULL(fixture);
    negative = tamga_json_object_get(fixture, "negative");
    public_key = tamga_json_as_string(tamga_json_object_get(negative, "publicKey"), NULL);
    correct = tamga_json_as_string(tamga_json_object_get(negative, "correctKid"), NULL);
    wrong_if_decoded_first =
        tamga_json_as_string(tamga_json_object_get(negative, "wrongKidIfDecodedFirst"), NULL);
    TT_ASSERT_NOT_NULL(public_key);
    TT_ASSERT_NOT_NULL(correct);
    TT_ASSERT_NOT_NULL(wrong_if_decoded_first);

    TT_ASSERT_EQ_INT(tamga_signing_key_id(public_key, computed), TAMGA_OK);
    TT_ASSERT_EQ_STR(computed, correct);
    /* The assertion that actually bites: a decode-first implementation returns
     * an equally well-formed sixteen-character id, so only refusing THIS value
     * distinguishes the two. */
    TT_ASSERT(strcmp(computed, wrong_if_decoded_first) != 0);

    /*
     * And the two really are different, proved here rather than assumed. If
     * the vector's two values ever coincided the assertion above would pass
     * vacuously against any implementation at all.
     */
    decoded = tamga_base64_decode_alloc(public_key, strlen(public_key), &decoded_len);
    TT_ASSERT_NOT_NULL(decoded);
    TT_ASSERT_EQ_SIZE(decoded_len, 32u);
    tamga_signing_key_id_compute((const char *)decoded, decoded_len, computed_over_bytes);
    tamga_free(decoded);
    TT_ASSERT_EQ_STR(computed_over_bytes, wrong_if_decoded_first);
    TT_ASSERT(strcmp(computed_over_bytes, correct) != 0);

    tamga_json_free(fixture);
}

TT_TEST(an_account_with_no_published_key_stamps_the_one_sentinel_id) {
    char computed[TAMGA_KEY_ID_SIZE];

    /*
     * `key_id(account.ed25519_public_key.unwrap_or_default())` -- an account
     * whose column was never populated hashes the empty string, so every file
     * it signs names this one id. The empty key must therefore be a legal
     * input rather than a rejected one.
     */
    TT_ASSERT_EQ_INT(tamga_signing_key_id("", computed), TAMGA_OK);
    TT_ASSERT_EQ_STR(computed, TAMGA_UNPUBLISHED_KEY_ID);
}

TT_TEST(the_servers_own_machine_file_manifest_agrees_with_the_hash_rule) {
    /*
     * A second confirmation from an unrelated source: these twelve files came
     * out of the server's own encoder, and their kid claims are in a manifest
     * this repository did not compute. Every one is the hash of the base64
     * STRING; none is the hash of the decoded key.
     *
     * ⚠️ That is ALL this manifest may be used to prove. Its generator derived
     * each kid from that file's OWN signing key, so the RSA and ECDSA entries
     * carry four distinct kids where the live server emits one -- both
     * checkout handlers compute the claim from `account.ed25519_public_key`
     * whatever scheme signed the bytes. Do not extend this loop into an
     * assertion that a non-Ed25519 file's kid names its own signing key: that
     * is a fixture-generator artifact, and pinning it would bake a false claim
     * about the server into a test. It is also why the key-set machine path
     * refuses every scheme but Ed25519.
     */
    TamgaJson *manifest = load_json_fixture("server-machine-files/manifest.json");
    size_t count;
    size_t i;

    TT_ASSERT_NOT_NULL(manifest);
    count = tamga_json_object_len(manifest);
    TT_ASSERT(count >= 12u);

    for (i = 0u; i < count; i++) {
        const TamgaJson *entry = tamga_json_object_value_at(manifest, i);
        const char *name = tamga_json_object_key_at(manifest, i);
        const char *public_key =
            tamga_json_as_string(tamga_json_object_get(entry, "public_key_b64"), NULL);
        const char *expected = tamga_json_as_string(tamga_json_object_get(entry, "kid"), NULL);
        char computed[TAMGA_KEY_ID_SIZE];

        if (public_key == NULL || expected == NULL) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: manifest entry %s is unreadable\n", tt_current_,
                          (name != NULL) ? name : "?");
            break;
        }
        tamga_signing_key_id_compute(public_key, strlen(public_key), computed);
        if (strcmp(computed, expected) != 0) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s expected %s, got %s\n", tt_current_,
                          (name != NULL) ? name : "?", expected, computed);
            break;
        }
    }
    tamga_json_free(manifest);
}

/* --- the key set --------------------------------------------------------- */

TT_TEST(a_pinned_key_indexes_itself_by_its_computed_id) {
    TamgaSigningKeySet *set = NULL;
    unsigned char found[32];
    unsigned char expected[32];
    unsigned char *decoded;
    size_t decoded_len = 0u;

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_SIZE(tamga_signing_key_set_count(set), 0u);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, ZERO_KEY_B64), TAMGA_OK);
    TT_ASSERT_EQ_SIZE(tamga_signing_key_set_count(set), 1u);

    TT_ASSERT(tamga_signing_key_set_find(set, ZERO_KEY_KID, found));
    decoded = tamga_base64_decode_alloc(ZERO_KEY_B64, strlen(ZERO_KEY_B64), &decoded_len);
    TT_ASSERT_NOT_NULL(decoded);
    memcpy(expected, decoded, 32u);
    tamga_free(decoded);
    TT_ASSERT_EQ_MEM(found, expected, 32u);

    /* Membership alone, with no buffer. */
    TT_ASSERT(tamga_signing_key_set_find(set, ZERO_KEY_KID, NULL));
    tamga_signing_key_set_free(set);
}

TT_TEST(a_lookup_that_misses_writes_nothing_at_all) {
    TamgaSigningKeySet *set = NULL;
    unsigned char buffer[32];
    unsigned char untouched[32];
    size_t i;

    for (i = 0u; i < 32u; i++) {
        buffer[i] = (unsigned char)(i + 1u);
        untouched[i] = (unsigned char)(i + 1u);
    }

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, ZERO_KEY_B64), TAMGA_OK);

    /*
     * A caller that ignores the return value must read back what it already
     * had, never a half-written or zeroed key that would then verify nothing
     * and look like a signature failure.
     */
    TT_ASSERT_FALSE(tamga_signing_key_set_find(set, "0f0f0f0f0f0f0f0f", buffer));
    TT_ASSERT_EQ_MEM(buffer, untouched, 32u);
    tamga_signing_key_set_free(set);
}

TT_TEST(a_mistyped_pinned_key_fails_loudly_rather_than_silently) {
    TamgaSigningKeySet *set = NULL;

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    /*
     * The alternative -- skipping it -- produces a set that reports every
     * genuine file in the field as signed by an unknown key, at runtime, on a
     * customer's machine. A key compiled into a binary has to fail at startup.
     */
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, "not base64 at all"),
                     TAMGA_ERR_INVALID_BASE64);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, "QUJD"), TAMGA_ERR_LENGTH_INVALID);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, ""), TAMGA_ERR_LENGTH_INVALID);
    TT_ASSERT_EQ_SIZE(tamga_signing_key_set_count(set), 0u);
    tamga_signing_key_set_free(set);
}

/* A `signing-keys` collection in the server's own shape. */
static const char KEY_SET_JSON[] =
    "{\"data\":["
    "{\"type\":\"signing-keys\",\"id\":\"aaaaaaaaaaaaaaaa\",\"attributes\":{"
    "\"algorithm\":\"ed25519\","
    "\"publicKey\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
    "\"status\":\"retired\",\"created\":\"2026-01-01T00:00:00Z\","
    "\"retired\":\"2026-06-01T00:00:00Z\"}},"
    "{\"type\":\"signing-keys\",\"id\":\"bbbbbbbbbbbbbbbb\",\"attributes\":{"
    "\"algorithm\":\"ed25519\","
    "\"publicKey\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\","
    "\"status\":\"active\",\"created\":\"2026-06-01T00:00:00Z\"}}"
    "]}";

TT_TEST(a_fetched_key_set_indexes_by_the_served_id_not_the_computed_one) {
    TamgaSigningKeySet *set = NULL;
    uintptr_t added = 0u;
    uintptr_t skipped = 0u;
    uintptr_t mismatched = 0u;

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_json(set, KEY_SET_JSON,
                                                    (uintptr_t)strlen(KEY_SET_JSON), &added,
                                                    &skipped, &mismatched),
                     TAMGA_OK);
    TT_ASSERT_EQ_SIZE(added, 2u);
    TT_ASSERT_EQ_SIZE(skipped, 0u);
    TT_ASSERT_EQ_SIZE(tamga_signing_key_set_count(set), 2u);

    /* The resource id IS the kid: it is what an offline file names, so it is
     * what the set is keyed by. Nothing is hashed on this path. */
    TT_ASSERT(tamga_signing_key_set_find(set, "aaaaaaaaaaaaaaaa", NULL));
    TT_ASSERT(tamga_signing_key_set_find(set, "bbbbbbbbbbbbbbbb", NULL));
    TT_ASSERT_FALSE(tamga_signing_key_set_find(set, ZERO_KEY_KID, NULL));

    /* Both served ids were invented for this fixture, so both disagree with
     * the locally computed value -- which is the cross-check reporting, not a
     * reason to drop either entry. */
    TT_ASSERT_EQ_SIZE(mismatched, 2u);
    /*
     * And the computed id is NOT a second way in. The assertion three lines
     * above -- that the zero key's own computed kid finds nothing, even though
     * that key is in the set under a different served id -- is what pins the
     * absence of a lenient "either id matches" fallback. One reference port
     * documents the lenient rule; this one matches the served id alone,
     * because that is what the wire actually names, and because a fallback
     * would silently swallow the mismatch this counter exists to report.
     */
    tamga_signing_key_set_free(set);
}

TT_TEST(a_retired_key_is_kept_because_it_is_the_whole_point) {
    TamgaSigningKeySet *set = NULL;

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_json(
                         set, KEY_SET_JSON, (uintptr_t)strlen(KEY_SET_JSON), NULL, NULL, NULL),
                     TAMGA_OK);
    /*
     * "aaaaaaaaaaaaaaaa" carries status "retired" and a `retired` timestamp.
     * Filtering it out would leave every file checked out before the rotation
     * unverifiable -- which is the defect this module exists to fix, so a
     * filter here would reinstate it exactly.
     */
    TT_ASSERT(tamga_signing_key_set_find(set, "aaaaaaaaaaaaaaaa", NULL));
    TT_ASSERT_EQ_SIZE(tamga_signing_key_set_count(set), 2u);
    tamga_signing_key_set_free(set);
}

TT_TEST(an_unusable_row_is_skipped_without_stranding_the_usable_ones) {
    static const char MIXED[] = "{\"data\":["
                                "{\"type\":\"signing-keys\",\"id\":\"future\",\"attributes\":{"
                                "\"algorithm\":\"dilithium5\",\"publicKey\":\"AAA=\","
                                "\"status\":\"active\",\"created\":\"2026-01-01T00:00:00Z\"}},"
                                "{\"type\":\"signing-keys\",\"id\":\"undecodable\",\"attributes\":{"
                                "\"algorithm\":\"ed25519\",\"publicKey\":\"!!!not base64!!!\","
                                "\"status\":\"active\",\"created\":\"2026-01-01T00:00:00Z\"}},"
                                "{\"type\":\"signing-keys\",\"id\":\"tooshort\",\"attributes\":{"
                                "\"algorithm\":\"ed25519\",\"publicKey\":\"QUJD\","
                                "\"status\":\"active\",\"created\":\"2026-01-01T00:00:00Z\"}},"
                                "{\"type\":\"signing-keys\",\"id\":\"good\",\"attributes\":{"
                                "\"algorithm\":\"ED25519\","
                                "\"publicKey\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
                                "\"status\":\"active\",\"created\":\"2026-01-01T00:00:00Z\"}}"
                                "]}";
    TamgaSigningKeySet *set = NULL;
    uintptr_t added = 0u;
    uintptr_t skipped = 0u;

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    /* One unusable row in a whole key history must not strand every file the
     * account has already signed, so these are counted rather than fatal. */
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_json(set, MIXED, (uintptr_t)strlen(MIXED), &added,
                                                    &skipped, NULL),
                     TAMGA_OK);
    TT_ASSERT_EQ_SIZE(added, 1u);
    TT_ASSERT_EQ_SIZE(skipped, 3u);
    /* The algorithm comparison is case-insensitive: "ED25519" is the same key. */
    TT_ASSERT(tamga_signing_key_set_find(set, "good", NULL));
    tamga_signing_key_set_free(set);
}

TT_TEST(a_malformed_document_leaves_the_set_exactly_as_it_was) {
    TamgaSigningKeySet *set = NULL;
    uintptr_t added = 99u;
    uintptr_t skipped = 99u;
    uintptr_t mismatched = 99u;

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, ZERO_KEY_B64), TAMGA_OK);

    TT_ASSERT_EQ_INT(
        tamga_signing_key_set_add_json(set, "{not json", 9u, &added, &skipped, &mismatched),
        TAMGA_ERR_INVALID_JSON);
    /* An error document is well-formed JSON and still has no key set in it. */
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_json(set, "{\"errors\":[]}", 13u, NULL, NULL, NULL),
                     TAMGA_ERR_INVALID_JSON);

    /*
     * Neither counter was written, and the set is untouched. A half-merged key
     * set verifies some of an account's files and reports the rest as forged,
     * which is worse than not merging at all.
     */
    TT_ASSERT_EQ_SIZE(added, 99u);
    TT_ASSERT_EQ_SIZE(skipped, 99u);
    TT_ASSERT_EQ_SIZE(mismatched, 99u);
    TT_ASSERT_EQ_SIZE(tamga_signing_key_set_count(set), 1u);
    TT_ASSERT(tamga_signing_key_set_find(set, ZERO_KEY_KID, NULL));
    tamga_signing_key_set_free(set);
}

TT_TEST(an_empty_collection_is_a_healthy_account_and_not_an_error) {
    TamgaSigningKeySet *set = NULL;
    uintptr_t added = 99u;

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    /* `account_signing_keys` is written only by the rotation handler, so an
     * account that has never rotated answers {"data": []}. */
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_json(set, "{\"data\":[]}", 11u, &added, NULL, NULL),
                     TAMGA_OK);
    TT_ASSERT_EQ_SIZE(added, 0u);
    TT_ASSERT_EQ_SIZE(tamga_signing_key_set_count(set), 0u);
    tamga_signing_key_set_free(set);
}

TT_TEST(every_null_argument_is_refused_rather_than_dereferenced) {
    TamgaSigningKeySet *set = NULL;
    char key_id[TAMGA_KEY_ID_SIZE];

    TT_ASSERT_EQ_INT(tamga_signing_key_id(NULL, key_id), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_signing_key_id(ZERO_KEY_B64, NULL), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(NULL), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(NULL, ZERO_KEY_B64),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_json(NULL, "{}", 2u, NULL, NULL, NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_FALSE(tamga_signing_key_set_find(NULL, ZERO_KEY_KID, NULL));
    TT_ASSERT_EQ_SIZE(tamga_signing_key_set_count(NULL), 0u);
    /* Freeing null is a documented no-op, not a crash. */
    tamga_signing_key_set_free(NULL);

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, NULL), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_json(set, NULL, 2u, NULL, NULL, NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_json(set, "{}", 0u, NULL, NULL, NULL),
                     TAMGA_ERR_LENGTH_INVALID);
    TT_ASSERT_FALSE(tamga_signing_key_set_find(set, NULL, NULL));
    tamga_signing_key_set_free(set);
}

TT_TEST(selection_names_the_condition_rather_than_calling_everything_a_forgery) {
    TamgaSigningKeySet *set = NULL;
    unsigned char selected[32];

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_public_key(set, ZERO_KEY_B64), TAMGA_OK);

    TT_ASSERT_EQ_INT(tamga_key_set_select(set, ZERO_KEY_KID, selected), TAMGA_OK);
    /* A stale set: refetch and retry. */
    TT_ASSERT_EQ_INT(tamga_key_set_select(set, "0f0f0f0f0f0f0f0f", selected),
                     TAMGA_ERR_UNKNOWN_SIGNING_KEY);
    /* An account that never published a key: refetching will never help, so it
     * has to be a different answer. */
    TT_ASSERT_EQ_INT(tamga_key_set_select(set, TAMGA_UNPUBLISHED_KEY_ID, selected),
                     TAMGA_ERR_SIGNING_KEY_NOT_PUBLISHED);
    /* A payload with its claims stripped is a malformed payload, not a key
     * problem -- saying "unknown key" would send the caller to refetch a key
     * set that was never the issue. */
    TT_ASSERT_EQ_INT(tamga_key_set_select(set, NULL, selected), TAMGA_ERR_INVALID_JSON);
    TT_ASSERT_EQ_INT(tamga_key_set_select(set, "", selected), TAMGA_ERR_INVALID_JSON);
    tamga_signing_key_set_free(set);
}

TT_TEST(a_published_sentinel_key_is_used_rather_than_refused) {
    TamgaSigningKeySet *set = NULL;
    static const char SENTINEL_SET[] =
        "{\"data\":[{\"type\":\"signing-keys\",\"id\":\"e3b0c44298fc1c14\",\"attributes\":{"
        "\"algorithm\":\"ed25519\","
        "\"publicKey\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
        "\"status\":\"active\",\"created\":\"2026-01-01T00:00:00Z\"}}]}";
    unsigned char selected[32];

    TT_ASSERT_EQ_INT(tamga_signing_key_set_new(&set), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_signing_key_set_add_json(
                         set, SENTINEL_SET, (uintptr_t)strlen(SENTINEL_SET), NULL, NULL, NULL),
                     TAMGA_OK);
    /*
     * The sentinel check runs only AFTER the lookup misses. An account that
     * has since published a key under that id verifies normally, and answering
     * "not published" while actually holding the key would be wrong.
     */
    TT_ASSERT_EQ_INT(tamga_key_set_select(set, TAMGA_UNPUBLISHED_KEY_ID, selected), TAMGA_OK);
    tamga_signing_key_set_free(set);
}

int main(void) {
    TT_RUN(the_key_id_of_every_published_vector_is_reproduced);
    TT_RUN(the_key_id_hashes_the_base64_string_and_never_the_decoded_bytes);
    TT_RUN(an_account_with_no_published_key_stamps_the_one_sentinel_id);
    TT_RUN(the_servers_own_machine_file_manifest_agrees_with_the_hash_rule);
    TT_RUN(a_pinned_key_indexes_itself_by_its_computed_id);
    TT_RUN(a_lookup_that_misses_writes_nothing_at_all);
    TT_RUN(a_mistyped_pinned_key_fails_loudly_rather_than_silently);
    TT_RUN(a_fetched_key_set_indexes_by_the_served_id_not_the_computed_one);
    TT_RUN(a_retired_key_is_kept_because_it_is_the_whole_point);
    TT_RUN(an_unusable_row_is_skipped_without_stranding_the_usable_ones);
    TT_RUN(a_malformed_document_leaves_the_set_exactly_as_it_was);
    TT_RUN(an_empty_collection_is_a_healthy_account_and_not_an_error);
    TT_RUN(every_null_argument_is_refused_rather_than_dereferenced);
    TT_RUN(selection_names_the_condition_rather_than_calling_everything_a_forgery);
    TT_RUN(a_published_sentinel_key_is_used_rather_than_refused);
    return TT_SUMMARY();
}
