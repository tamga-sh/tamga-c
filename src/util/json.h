/*
 * json.h -- the JSON DOM this library parses into, plus the two serializers
 * it writes back out with.
 *
 * Scope is deliberately narrow. This is not a general-purpose JSON library:
 * it exists to read JSON:API response bodies and offline-file payloads, and
 * to reproduce -- byte for byte -- the canonical form the Tamga server signs.
 * That second requirement is why the serializer is here rather than being
 * anyone's choice of formatting.
 *
 * Parser hardening, because every input reaching it is untrusted:
 *   - nesting depth is capped (TAMGA_JSON_MAX_DEPTH), so a file made of ten
 *     thousand '[' cannot exhaust the C stack;
 *   - input length is capped at TAMGA_MAX_REASONABLE_LEN;
 *   - string contents are validated as UTF-8, including surrogate-pair rules
 *     for \uXXXX escapes;
 *   - trailing content after the top-level value is rejected, as are NaN,
 *     Infinity, comments, trailing commas and single quotes -- every
 *     extension a lenient parser might accept is a place where this
 *     implementation and the server could disagree about what a document
 *     means.
 */
#ifndef TAMGA_UTIL_JSON_H
#define TAMGA_UTIL_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tamga_compat.h"

/*
 * 64 levels. The deepest structure the protocol actually uses is about five
 * (`{data:{attributes:{metadata:{...}}}}`), and caller-supplied `dataset`
 * objects are flat in practice; this leaves an order of magnitude of headroom
 * while keeping worst-case recursion depth trivially bounded.
 */
#define TAMGA_JSON_MAX_DEPTH 64

typedef enum TamgaJsonType {
    TAMGA_JSON_NULL = 0,
    TAMGA_JSON_BOOL,
    TAMGA_JSON_NUMBER,
    TAMGA_JSON_STRING,
    TAMGA_JSON_ARRAY,
    TAMGA_JSON_OBJECT
} TamgaJsonType;

typedef struct TamgaJson TamgaJson;

/** Frees a value and everything below it. NULL-safe. */
void tamga_json_free(TamgaJson *value);

/**
 * Parses `len` bytes of JSON. Returns NULL on any malformed input; when
 * `error_out` is non-NULL it receives a short static description of what was
 * wrong (never freed, never contains input bytes -- a parse error message
 * that quotes the document is an easy way to leak a licence key into a log).
 */
TAMGA_NODISCARD TamgaJson *tamga_json_parse(const char *text, size_t len, const char **error_out);

/* --- inspection ------------------------------------------------------- */

TamgaJsonType tamga_json_type(const TamgaJson *value);
bool tamga_json_is_null(const TamgaJson *value);

/** Returns the boolean, or `fallback` if this value is not a boolean. */
bool tamga_json_bool_or(const TamgaJson *value, bool fallback);

/** Integer accessor. False if the value is not a number, is not integral, or
 *  does not fit in int64_t. An integral double (8.0) is accepted. */
TAMGA_NODISCARD bool tamga_json_as_int(const TamgaJson *value, int64_t *out);

/**
 * True only when the document expressed this number as an integer literal --
 * no decimal point, no exponent -- and it fits in int64_t.
 *
 * The serializer needs this rather than tamga_json_as_int(), which also
 * accepts an integral double: 8 and 8.0 are distinct JSON texts, and writing
 * one where the document had the other changes the signed bytes.
 */
TAMGA_NODISCARD bool tamga_json_int_literal(const TamgaJson *value, int64_t *out);

/** Double accessor. False if the value is not a number. */
TAMGA_NODISCARD bool tamga_json_as_double(const TamgaJson *value, double *out);

/**
 * String contents as UTF-8 bytes with escapes already resolved. Returns NULL
 * if this value is not a string. `out_len` is optional. The pointer belongs
 * to the tree and dies with it.
 */
const char *tamga_json_as_string(const TamgaJson *value, size_t *out_len);

size_t tamga_json_array_len(const TamgaJson *value);
const TamgaJson *tamga_json_array_at(const TamgaJson *value, size_t index);

size_t tamga_json_object_len(const TamgaJson *value);
const char *tamga_json_object_key_at(const TamgaJson *value, size_t index);
const TamgaJson *tamga_json_object_value_at(const TamgaJson *value, size_t index);

/** Looks up a member by exact key. NULL when absent or not an object. */
const TamgaJson *tamga_json_object_get(const TamgaJson *value, const char *key);

/* --- construction ----------------------------------------------------- */

TAMGA_NODISCARD TamgaJson *tamga_json_new_null(void);
TAMGA_NODISCARD TamgaJson *tamga_json_new_bool(bool value);
TAMGA_NODISCARD TamgaJson *tamga_json_new_int(int64_t value);
TAMGA_NODISCARD TamgaJson *tamga_json_new_double(double value);
TAMGA_NODISCARD TamgaJson *tamga_json_new_string(const char *utf8, size_t len);
TAMGA_NODISCARD TamgaJson *tamga_json_new_array(void);
TAMGA_NODISCARD TamgaJson *tamga_json_new_object(void);

/** Deep copy. NULL on allocation failure. */
TAMGA_NODISCARD TamgaJson *tamga_json_clone(const TamgaJson *value);

/** Appends to an array, taking ownership of `item` in all cases -- including
 *  failure, so a caller never has to decide whether to free it. */
TAMGA_NODISCARD bool tamga_json_array_append(TamgaJson *array, TamgaJson *item);

/**
 * Inserts or replaces an object member, taking ownership of `item` in all
 * cases. A repeated key replaces the previous value, matching serde_json's
 * map semantics -- so a document with duplicate keys means the same thing
 * here and on the server.
 */
TAMGA_NODISCARD bool tamga_json_object_set(TamgaJson *object, const char *key, TamgaJson *item);

/* --- serialization ---------------------------------------------------- */

/**
 * Canonical serialization: no whitespace, object keys sorted by unsigned
 * UTF-8 byte order at every nesting level, array order preserved, and
 * serde_json's exact string-escaping rules.
 *
 * This is what the offline proof's signature covers. The key ordering is not
 * a style choice: the server builds its payload with serde_json, whose map is
 * BTreeMap-backed, so the bytes it signs are byte-lexicographically sorted
 * regardless of the order the fields appear in its source. Sorting by
 * anything other than raw UTF-8 bytes (UTF-16 code units, locale collation,
 * Unicode canonical equivalence) diverges for astral-plane characters -- a
 * live bug this SDK family has already shipped once, in tamga-js.
 *
 * Returns a NUL-terminated string released with tamga_free(), or NULL on
 * allocation failure.
 *
 * Integer, string, boolean, null, array and object values reproduce the
 * server's bytes exactly. Non-integer floating-point values are formatted as
 * the shortest decimal that round-trips, which agrees with the server's
 * formatter for ordinary values but is not verified across every IEEE 754
 * edge case -- prefer integers or strings for numeric `dataset` fields.
 */
TAMGA_NODISCARD char *tamga_json_write_canonical(const TamgaJson *value, size_t *out_len);

/**
 * Compact serialization preserving member insertion order. Used for request
 * bodies and for handing decoded resources back to the caller, where nothing
 * is signed and insertion order reads more naturally than sorted order.
 */
TAMGA_NODISCARD char *tamga_json_write(const TamgaJson *value, size_t *out_len);

#endif /* TAMGA_UTIL_JSON_H */
