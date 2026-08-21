#include "checkout/key_set.h"

#include <string.h>

#include "crypto/sha256.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"
#include "util/hex.h"

/*
 * The algorithm string the server writes for every key it publishes.
 * `rotate_ed25519` hardcodes it and is the only writer, so anything else on
 * this route is a key this SDK has no verifier for.
 */
static const char TAMGA_SIGNING_KEY_ALGORITHM[] = "ed25519";

/*
 * How much of a claimed `kid` a diagnostic will quote.
 *
 * The `kid` is read out of a payload whose signature has NOT been checked, so
 * its length is whatever the file says. Sixty-four characters is four times
 * the real thing -- long enough that a genuine id is never truncated, short
 * enough that a hostile file cannot fill the 512-byte message slot with its
 * own text and push the explanation off the end.
 */
#define TAMGA_KEY_ID_DIAGNOSTIC_CAP 64

/* How many entries a set makes room for the first time it grows. Small: the
 * realistic size of an account's whole key history is one or two. */
#define TAMGA_KEY_SET_INITIAL_CAPACITY 4u

typedef struct TamgaSigningKeyEntry {
    char *key_id;
    unsigned char public_key[TAMGA_ED25519_PUBKEY_LEN];
} TamgaSigningKeyEntry;

struct TamgaSigningKeySet {
    TamgaSigningKeyEntry *entries;
    size_t count;
    /* Tracked separately from `count` because the array is grown in steps and
     * freed at the size it was ALLOCATED, never at the size it is used. */
    size_t capacity;
};

void tamga_signing_key_id_compute(const char *public_key, size_t public_key_len, char *out_key_id) {
    unsigned char digest[TAMGA_SHA256_DIGEST_LEN];

    /*
     * ⚠️ Over the base64 string's own bytes. `key_id(ed25519_public_key: &str)`
     * digests `.as_bytes()`, so the 44 ASCII characters are the message and
     * the 32 bytes they encode never enter the hash.
     */
    tamga_sha256(public_key, public_key_len, digest);
    /* The first EIGHT bytes, not the whole digest: a kid is 16 hex characters
     * because the server truncates, and rendering all 32 bytes would produce
     * an id that matches nothing. */
    tamga_hex_encode(digest, (size_t)TAMGA_KEY_ID_LENGTH / 2u, out_key_id);
}

const char *tamga_claims_key_id(const TamgaJson *meta) {
    return tamga_json_as_string(tamga_json_object_get(meta, "kid"), NULL);
}

TamgaErrorCode tamga_key_set_create(TamgaSigningKeySet **out_set) {
    TamgaSigningKeySet *set;

    if (out_set == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "out_set must not be null");
    }
    *out_set = NULL;
    set = (TamgaSigningKeySet *)tamga_calloc(1u, sizeof(*set));
    if (set == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the key set");
    }
    *out_set = set;
    return TAMGA_OK;
}

void tamga_key_set_destroy(TamgaSigningKeySet *set) {
    size_t i;

    if (set == NULL) {
        return;
    }
    for (i = 0u; i < set->count; i++) {
        tamga_free(set->entries[i].key_id);
    }
    /*
     * Freed at CAPACITY, not at count. The array is grown in steps, so the
     * two differ whenever the last growth was not filled exactly, and passing
     * the smaller of the two to a size-taking free leaves the tail of a real
     * allocation untouched. Nothing secret lives here -- a published public
     * key and its id are public by definition -- but the size still has to be
     * the allocated one for the free to describe the block it is freeing.
     */
    tamga_free(set->entries);
    tamga_secure_free(set, sizeof(*set));
}

size_t tamga_key_set_count(const TamgaSigningKeySet *set) {
    return (set == NULL) ? 0u : set->count;
}

/* Makes room for `additional` more entries without changing what the set
 * holds, so a failure here leaves it exactly as it was. */
static TamgaErrorCode tamga_key_set_reserve(TamgaSigningKeySet *set, size_t additional) {
    size_t needed;
    size_t capacity;
    size_t bytes;
    TamgaSigningKeyEntry *entries;

    if (!tamga_checked_add(set->count, additional, &needed)) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "the key set is too large to grow");
    }
    if (needed <= set->capacity) {
        return TAMGA_OK;
    }
    capacity = (set->capacity == 0u) ? TAMGA_KEY_SET_INITIAL_CAPACITY : set->capacity;
    while (capacity < needed) {
        size_t doubled;
        if (!tamga_checked_mul(capacity, 2u, &doubled)) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "the key set is too large to grow");
        }
        capacity = doubled;
    }
    if (!tamga_checked_mul(capacity, sizeof(*entries), &bytes)) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "the key set is too large to grow");
    }
    /* realloc leaves the original block intact when it fails, so the set is
     * still whole on this path. */
    entries = (TamgaSigningKeyEntry *)tamga_realloc(set->entries, bytes);
    if (entries == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not grow the key set");
    }
    set->entries = entries;
    set->capacity = capacity;
    return TAMGA_OK;
}

/* Appends one (id, key) pair, copying the id. */
static TamgaErrorCode tamga_key_set_append(TamgaSigningKeySet *set, const char *key_id,
                                           const unsigned char *public_key) {
    char *copy;
    TamgaErrorCode status = tamga_key_set_reserve(set, 1u);

    /* The array is checked as well as the status. A successful reserve always
     * leaves one, but that invariant lives in another function and reads back
     * here as an unchecked dereference -- to a static analyser and to the next
     * person alike. */
    if (status != TAMGA_OK || set->entries == NULL) {
        return (status != TAMGA_OK)
                   ? status
                   : tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not grow the key set");
    }
    copy = tamga_strdup(key_id);
    if (copy == NULL) {
        /*
         * An allocation failure is not "this key is unusable". Counting it as
         * a skipped row would leave the set quietly short of the key a genuine
         * file names, and the caller would then read the resulting
         * TAMGA_ERR_UNKNOWN_SIGNING_KEY as "this file belongs to somebody
         * else" -- a wrong and unactionable answer to being out of memory.
         */
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not copy a signing key id");
    }
    set->entries[set->count].key_id = copy;
    memcpy(set->entries[set->count].public_key, public_key, TAMGA_ED25519_PUBKEY_LEN);
    set->count++;
    return TAMGA_OK;
}

/* Decodes a published public key into its raw 32 bytes. `out_status` carries
 * why it could not be, for the strict caller; the lenient one ignores it. */
static bool tamga_signing_key_decode(const char *public_key, size_t public_key_len,
                                     unsigned char *out, TamgaErrorCode *out_status) {
    unsigned char *decoded;
    size_t decoded_len = 0u;
    TamgaBase64Failure why;

    decoded = tamga_base64_decode_alloc_why(public_key, public_key_len, &decoded_len, &why);
    if (decoded == NULL) {
        *out_status = (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) ? TAMGA_ERR_OUT_OF_MEMORY
                                                                  : TAMGA_ERR_INVALID_BASE64;
        return false;
    }
    if (decoded_len != TAMGA_ED25519_PUBKEY_LEN) {
        tamga_free(decoded);
        *out_status = TAMGA_ERR_LENGTH_INVALID;
        return false;
    }
    memcpy(out, decoded, TAMGA_ED25519_PUBKEY_LEN);
    tamga_free(decoded);
    *out_status = TAMGA_OK;
    return true;
}

TamgaErrorCode tamga_key_set_add_public_key(TamgaSigningKeySet *set, const char *public_key) {
    char key_id[TAMGA_KEY_ID_SIZE];
    unsigned char decoded[TAMGA_ED25519_PUBKEY_LEN];
    TamgaErrorCode why = TAMGA_OK;
    size_t public_key_len;

    if (set == NULL || public_key == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "set and public_key are required");
    }
    public_key_len = strlen(public_key);
    if (public_key_len > TAMGA_MAX_REASONABLE_LEN) {
        return tamga_error_set(TAMGA_ERR_LENGTH_INVALID,
                               "the public key exceeds the accepted maximum length");
    }
    if (!tamga_signing_key_decode(public_key, public_key_len, decoded, &why)) {
        if (why == TAMGA_ERR_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode the public key");
        }
        if (why == TAMGA_ERR_LENGTH_INVALID) {
            return tamga_error_set(TAMGA_ERR_LENGTH_INVALID,
                                   "an Ed25519 public key decodes to 32 bytes; this one does "
                                   "not");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64,
                               "an Ed25519 public key must be standard base64 of its raw "
                               "bytes");
    }
    /* Computed, not supplied: a key pinned in a binary has no server-issued id
     * to be indexed by, which is the whole reason this path exists. */
    tamga_signing_key_id_compute(public_key, public_key_len, key_id);
    return tamga_key_set_append(set, key_id, decoded);
}

/* Case-insensitive ASCII comparison, for the one algorithm string the server
 * emits. Written out rather than reaching for strcasecmp, which is POSIX. */
static bool tamga_ascii_equals_ignoring_case(const char *a, const char *b) {
    size_t i = 0u;

    while (a[i] != '\0' && b[i] != '\0') {
        char left = a[i];
        char right = b[i];
        if (left >= 'A' && left <= 'Z') {
            left = (char)(left + ('a' - 'A'));
        }
        if (right >= 'A' && right <= 'Z') {
            right = (char)(right + ('a' - 'A'));
        }
        if (left != right) {
            return false;
        }
        i++;
    }
    return a[i] == '\0' && b[i] == '\0';
}

/*
 * Reads one `signing-keys` resource into `staged`, or accounts for why not.
 *
 * Returns TAMGA_OK for both "added" and "skipped" -- an unusable row is a
 * normal feature of a whole key history, not a failure. Only a genuine
 * allocation failure returns non-OK, so a caller can never mistake one for
 * the other.
 */
static TamgaErrorCode tamga_key_set_stage_resource(TamgaSigningKeySet *staged,
                                                   const TamgaJson *resource, size_t *skipped,
                                                   size_t *mismatched) {
    const TamgaJson *attributes;
    const char *served_id;
    const char *algorithm;
    const char *public_key;
    size_t public_key_len = 0u;
    unsigned char decoded[TAMGA_ED25519_PUBKEY_LEN];
    char computed[TAMGA_KEY_ID_SIZE];
    TamgaErrorCode why = TAMGA_OK;

    if (resource == NULL || tamga_json_type(resource) != TAMGA_JSON_OBJECT) {
        (*skipped)++;
        return TAMGA_OK;
    }
    /* ⚠️ The resource id IS the kid, not a UUID like every other resource this
     * SDK reads. The server sets it from the same value it stamps into the
     * file's claim. */
    served_id = tamga_json_as_string(tamga_json_object_get(resource, "id"), NULL);
    attributes = tamga_json_object_get(resource, "attributes");
    algorithm = tamga_json_as_string(tamga_json_object_get(attributes, "algorithm"), NULL);
    /* ⚠️ `publicKey` is camelCase inside an otherwise snake_case resource --
     * the single per-field rename on this struct. `algorithm`, `status`,
     * `created` and `retired` are all bare. */
    public_key =
        tamga_json_as_string(tamga_json_object_get(attributes, "publicKey"), &public_key_len);
    if (served_id == NULL || served_id[0] == '\0' || algorithm == NULL || public_key == NULL) {
        (*skipped)++;
        return TAMGA_OK;
    }
    if (!tamga_ascii_equals_ignoring_case(algorithm, TAMGA_SIGNING_KEY_ALGORITHM)) {
        /* A future algorithm this build has no verifier for. Skipping it keeps
         * every Ed25519 key in the same response usable. */
        (*skipped)++;
        return TAMGA_OK;
    }
    if (!tamga_signing_key_decode(public_key, public_key_len, decoded, &why)) {
        if (why == TAMGA_ERR_OUT_OF_MEMORY) {
            /* Not a skip. See tamga_key_set_append(). */
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not decode a published key");
        }
        (*skipped)++;
        return TAMGA_OK;
    }

    /*
     * The cross-check, and it is ONLY that. The served id is authoritative
     * because it is what an offline file's `kid` is drawn from; the local
     * computation exists to notice that the two have diverged -- a server
     * whose hash rule changed, or a row whose id and key do not belong
     * together. The entry is added either way, under the served id, because
     * dropping it would strand exactly the files that name it.
     *
     * ⚠️ Deliberately NOT indexed under the computed id as well. Accepting
     * either would invent a matching rule the wire does not have, and would
     * fold this signal into a silent fallback -- so an operator whose key set
     * is corrupt, or whose server is misbehaving, would never find out. It is
     * not a security question either way (the signature still has to verify
     * against this key's bytes, so a wrong selection fails closed rather than
     * admitting a forgery); it is a diagnosability one, and the count is the
     * diagnosis. `a_fetched_key_set_indexes_by_the_served_id_not_the_computed_one`
     * pins the absence of that second path -- do not add it.
     */
    tamga_signing_key_id_compute(public_key, public_key_len, computed);
    if (strcmp(computed, served_id) != 0) {
        (*mismatched)++;
    }
    return tamga_key_set_append(staged, served_id, decoded);
}

TamgaErrorCode tamga_key_set_add_json(TamgaSigningKeySet *set, const char *json, size_t json_len,
                                      size_t *out_added, size_t *out_skipped,
                                      size_t *out_mismatched) {
    TamgaSigningKeySet *staged = NULL;
    TamgaJson *document = NULL;
    const TamgaJson *data;
    const char *parse_error = NULL;
    size_t skipped = 0u;
    size_t mismatched = 0u;
    size_t added = 0u;
    size_t count;
    size_t i;
    TamgaErrorCode status;

    if (set == NULL || json == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "set and json are required");
    }
    if (json_len == 0u || json_len > TAMGA_MAX_REASONABLE_LEN) {
        return tamga_error_set(TAMGA_ERR_LENGTH_INVALID,
                               "the key-set document's length is zero or exceeds the accepted "
                               "maximum");
    }

    document = tamga_json_parse(json, json_len, &parse_error);
    if (document == NULL) {
        if (tamga_json_error_is_out_of_memory(parse_error)) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not parse the key set");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "the key set is malformed: %s",
                               (parse_error != NULL) ? parse_error : "unknown");
    }
    data = tamga_json_object_get(document, "data");
    if (data == NULL || tamga_json_type(data) != TAMGA_JSON_ARRAY) {
        tamga_json_free(document);
        return tamga_error_set(TAMGA_ERR_INVALID_JSON,
                               "a signing-key document is a JSON:API collection with a data "
                               "array; this one has none");
    }

    /*
     * Staged into a set of its own so the merge below cannot half-happen. A
     * partially merged key set is worse than an unmerged one: it verifies some
     * of the account's files and reports the rest as forged, which is the very
     * confusion this module exists to remove.
     */
    status = tamga_key_set_create(&staged);
    if (status != TAMGA_OK || staged == NULL) {
        tamga_json_free(document);
        return (status != TAMGA_OK)
                   ? status
                   : tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the key set");
    }
    count = tamga_json_array_len(data);
    for (i = 0u; i < count; i++) {
        status = tamga_key_set_stage_resource(staged, tamga_json_array_at(data, i), &skipped,
                                              &mismatched);
        if (status != TAMGA_OK) {
            tamga_key_set_destroy(staged);
            tamga_json_free(document);
            return status;
        }
    }
    tamga_json_free(document);

    /* The only allocation the merge needs, taken before anything moves. */
    added = staged->count;
    status = tamga_key_set_reserve(set, added);
    if (status != TAMGA_OK) {
        tamga_key_set_destroy(staged);
        return status;
    }
    for (i = 0u; i < added; i++) {
        set->entries[set->count + i] = staged->entries[i];
    }
    set->count += added;
    /* The ids moved rather than being copied, so the staging set must not free
     * them; it owns nothing but its own array now. */
    staged->count = 0u;
    tamga_key_set_destroy(staged);

    if (out_added != NULL) {
        *out_added = added;
    }
    if (out_skipped != NULL) {
        *out_skipped = skipped;
    }
    if (out_mismatched != NULL) {
        *out_mismatched = mismatched;
    }
    return TAMGA_OK;
}

bool tamga_key_set_lookup(const TamgaSigningKeySet *set, const char *key_id,
                          unsigned char *out_public_key) {
    size_t i;

    if (set == NULL || key_id == NULL) {
        return false;
    }
    for (i = 0u; i < set->count; i++) {
        if (strcmp(set->entries[i].key_id, key_id) == 0) {
            if (out_public_key != NULL) {
                memcpy(out_public_key, set->entries[i].public_key, TAMGA_ED25519_PUBKEY_LEN);
            }
            return true;
        }
    }
    return false;
}

TamgaErrorCode tamga_key_set_select(const TamgaSigningKeySet *set, const char *key_id,
                                    unsigned char *out_public_key) {
    if (set == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a key set is required");
    }
    if (key_id == NULL || key_id[0] == '\0') {
        /* Every v2 file carries one. Its absence means the payload had its
         * claims stripped, which is a malformed payload rather than a key
         * problem -- saying "unknown signing key" would send the caller to
         * refetch a key set that was never the issue. */
        return tamga_error_set(TAMGA_ERR_INVALID_JSON,
                               "the signed payload names no kid, so no signing key can be "
                               "selected");
    }
    if (tamga_key_set_lookup(set, key_id, out_public_key)) {
        return TAMGA_OK;
    }
    /*
     * Checked only AFTER the lookup misses. An account that has since
     * published a key under this id would verify normally, and answering "not
     * published" while actually holding the key would be wrong.
     */
    if (strcmp(key_id, TAMGA_UNPUBLISHED_KEY_ID) == 0) {
        return tamga_error_set(TAMGA_ERR_SIGNING_KEY_NOT_PUBLISHED,
                               "this file names the key id of an account with no published "
                               "Ed25519 public key (%s), so no key set can ever match it; "
                               "verify with the account's own key instead",
                               TAMGA_UNPUBLISHED_KEY_ID);
    }
    return tamga_error_set(TAMGA_ERR_UNKNOWN_SIGNING_KEY,
                           "no signing key for kid %.*s among the %zu key(s) held; this is a "
                           "key set that has not caught up with a rotation, not a forged file",
                           (int)TAMGA_KEY_ID_DIAGNOSTIC_CAP, key_id, tamga_key_set_count(set));
}
