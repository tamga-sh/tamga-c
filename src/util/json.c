#include "util/json.h"

#include <stdlib.h>
#include <string.h>

#include "tamga_mem.h"
#include "util/buf.h"

typedef struct TamgaJsonMember {
    char *key;
    size_t key_len;
    TamgaJson *value;
} TamgaJsonMember;

struct TamgaJson {
    TamgaJsonType type;
    union {
        bool boolean;
        struct {
            /* Integers keep their exact value; anything with a fraction or an
             * exponent is carried as a double. `is_int` records which of the
             * two the document actually contained, because the canonical
             * serializer must not turn 1 into 1.0 or vice versa. */
            bool is_int;
            int64_t integer;
            double real;
        } number;
        struct {
            char *bytes; /* decoded UTF-8, NUL-terminated for convenience */
            size_t len;
        } string;
        struct {
            TamgaJson **items;
            size_t count;
            size_t cap;
        } array;
        struct {
            TamgaJsonMember *members;
            size_t count;
            size_t cap;
        } object;
    } as;
};

/* --- lifecycle -------------------------------------------------------- */

static TamgaJson *tamga_json_new(TamgaJsonType type)
{
    TamgaJson *value = (TamgaJson *)tamga_calloc(1u, sizeof(TamgaJson));
    if (value == NULL) {
        return NULL;
    }
    value->type = type;
    return value;
}

void tamga_json_free(TamgaJson *value)
{
    size_t i;

    if (value == NULL) {
        return;
    }
    switch (value->type) {
    case TAMGA_JSON_STRING:
        /* Decoded strings routinely hold licence keys and metadata, so they
         * are erased rather than merely released. */
        tamga_secure_free(value->as.string.bytes, value->as.string.len);
        break;
    case TAMGA_JSON_ARRAY:
        for (i = 0u; i < value->as.array.count; i++) {
            tamga_json_free(value->as.array.items[i]);
        }
        tamga_free(value->as.array.items);
        break;
    case TAMGA_JSON_OBJECT:
        for (i = 0u; i < value->as.object.count; i++) {
            tamga_secure_free(value->as.object.members[i].key,
                              value->as.object.members[i].key_len);
            tamga_json_free(value->as.object.members[i].value);
        }
        tamga_free(value->as.object.members);
        break;
    case TAMGA_JSON_NULL:
    case TAMGA_JSON_BOOL:
    case TAMGA_JSON_NUMBER:
    default:
        break;
    }
    tamga_secure_free(value, sizeof(*value));
}

/* --- construction ----------------------------------------------------- */

TamgaJson *tamga_json_new_null(void)
{
    return tamga_json_new(TAMGA_JSON_NULL);
}

TamgaJson *tamga_json_new_bool(bool value)
{
    TamgaJson *node = tamga_json_new(TAMGA_JSON_BOOL);
    if (node != NULL) {
        node->as.boolean = value;
    }
    return node;
}

TamgaJson *tamga_json_new_int(int64_t value)
{
    TamgaJson *node = tamga_json_new(TAMGA_JSON_NUMBER);
    if (node != NULL) {
        node->as.number.is_int = true;
        node->as.number.integer = value;
    }
    return node;
}

TamgaJson *tamga_json_new_double(double value)
{
    TamgaJson *node = tamga_json_new(TAMGA_JSON_NUMBER);
    if (node != NULL) {
        node->as.number.is_int = false;
        node->as.number.real = value;
    }
    return node;
}

TamgaJson *tamga_json_new_string(const char *utf8, size_t len)
{
    TamgaJson *node;
    char *copy;

    if (utf8 == NULL) {
        return NULL;
    }
    copy = (char *)tamga_malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    if (len > 0u) {
        memcpy(copy, utf8, len);
    }
    copy[len] = '\0';

    node = tamga_json_new(TAMGA_JSON_STRING);
    if (node == NULL) {
        tamga_secure_free(copy, len);
        return NULL;
    }
    node->as.string.bytes = copy;
    node->as.string.len = len;
    return node;
}

TamgaJson *tamga_json_new_array(void)
{
    return tamga_json_new(TAMGA_JSON_ARRAY);
}

TamgaJson *tamga_json_new_object(void)
{
    return tamga_json_new(TAMGA_JSON_OBJECT);
}

static bool tamga_json_grow(void **items, size_t *cap, size_t count, size_t elem_size)
{
    size_t new_cap;
    size_t bytes;
    void *grown;

    if (count < *cap) {
        return true;
    }
    new_cap = (*cap == 0u) ? 8u : *cap;
    if (!tamga_checked_mul(new_cap, 2u, &new_cap)) {
        return false;
    }
    if (!tamga_checked_mul(new_cap, elem_size, &bytes)) {
        return false;
    }
    grown = tamga_realloc(*items, bytes);
    if (grown == NULL) {
        return false;
    }
    *items = grown;
    *cap = new_cap;
    return true;
}

bool tamga_json_array_append(TamgaJson *array, TamgaJson *item)
{
    /* Ownership is taken unconditionally: a caller that had to free `item`
     * only on failure would eventually get one of those paths wrong. */
    if (array == NULL || array->type != TAMGA_JSON_ARRAY || item == NULL) {
        tamga_json_free(item);
        return false;
    }
    if (!tamga_json_grow((void **)&array->as.array.items, &array->as.array.cap,
                         array->as.array.count, sizeof(TamgaJson *))) {
        tamga_json_free(item);
        return false;
    }
    array->as.array.items[array->as.array.count] = item;
    array->as.array.count++;
    return true;
}

bool tamga_json_object_set(TamgaJson *object, const char *key, TamgaJson *item)
{
    size_t i;
    size_t key_len;
    char *key_copy;

    if (object == NULL || object->type != TAMGA_JSON_OBJECT || key == NULL || item == NULL) {
        tamga_json_free(item);
        return false;
    }
    key_len = strlen(key);

    for (i = 0u; i < object->as.object.count; i++) {
        if (object->as.object.members[i].key_len == key_len &&
            memcmp(object->as.object.members[i].key, key, key_len) == 0) {
            tamga_json_free(object->as.object.members[i].value);
            object->as.object.members[i].value = item;
            return true;
        }
    }

    if (!tamga_json_grow((void **)&object->as.object.members, &object->as.object.cap,
                         object->as.object.count, sizeof(TamgaJsonMember))) {
        tamga_json_free(item);
        return false;
    }
    key_copy = tamga_strndup(key, key_len);
    if (key_copy == NULL) {
        tamga_json_free(item);
        return false;
    }
    object->as.object.members[object->as.object.count].key = key_copy;
    object->as.object.members[object->as.object.count].key_len = key_len;
    object->as.object.members[object->as.object.count].value = item;
    object->as.object.count++;
    return true;
}

TamgaJson *tamga_json_clone(const TamgaJson *value)
{
    size_t i;
    TamgaJson *copy;

    if (value == NULL) {
        return NULL;
    }
    switch (value->type) {
    case TAMGA_JSON_NULL:
        return tamga_json_new_null();
    case TAMGA_JSON_BOOL:
        return tamga_json_new_bool(value->as.boolean);
    case TAMGA_JSON_NUMBER:
        return value->as.number.is_int ? tamga_json_new_int(value->as.number.integer)
                                       : tamga_json_new_double(value->as.number.real);
    case TAMGA_JSON_STRING:
        return tamga_json_new_string(value->as.string.bytes, value->as.string.len);
    case TAMGA_JSON_ARRAY:
        copy = tamga_json_new_array();
        if (copy == NULL) {
            return NULL;
        }
        for (i = 0u; i < value->as.array.count; i++) {
            TamgaJson *child = tamga_json_clone(value->as.array.items[i]);
            if (child == NULL || !tamga_json_array_append(copy, child)) {
                tamga_json_free(copy);
                return NULL;
            }
        }
        return copy;
    case TAMGA_JSON_OBJECT:
        copy = tamga_json_new_object();
        if (copy == NULL) {
            return NULL;
        }
        for (i = 0u; i < value->as.object.count; i++) {
            TamgaJson *child = tamga_json_clone(value->as.object.members[i].value);
            if (child == NULL ||
                !tamga_json_object_set(copy, value->as.object.members[i].key, child)) {
                tamga_json_free(copy);
                return NULL;
            }
        }
        return copy;
    default:
        return NULL;
    }
}

/* --- inspection ------------------------------------------------------- */

TamgaJsonType tamga_json_type(const TamgaJson *value)
{
    return (value == NULL) ? TAMGA_JSON_NULL : value->type;
}

bool tamga_json_is_null(const TamgaJson *value)
{
    return value == NULL || value->type == TAMGA_JSON_NULL;
}

bool tamga_json_bool_or(const TamgaJson *value, bool fallback)
{
    if (value == NULL || value->type != TAMGA_JSON_BOOL) {
        return fallback;
    }
    return value->as.boolean;
}

bool tamga_json_as_int(const TamgaJson *value, int64_t *out)
{
    if (value == NULL || out == NULL || value->type != TAMGA_JSON_NUMBER) {
        return false;
    }
    if (value->as.number.is_int) {
        *out = value->as.number.integer;
        return true;
    }
    /* A double that happens to be integral is still accepted -- the server
     * emits `"cores": 8` but a hand-built dataset may carry `8.0`. The bound
     * is 2^53, past which a double no longer represents consecutive
     * integers. */
    if (value->as.number.real >= -9007199254740992.0 &&
        value->as.number.real <= 9007199254740992.0) {
        double truncated = (value->as.number.real < 0.0) ? -(double)(int64_t)(-value->as.number.real)
                                                         : (double)(int64_t)value->as.number.real;
        if (truncated == value->as.number.real) {
            *out = (int64_t)value->as.number.real;
            return true;
        }
    }
    return false;
}

bool tamga_json_int_literal(const TamgaJson *value, int64_t *out)
{
    if (value == NULL || out == NULL || value->type != TAMGA_JSON_NUMBER) {
        return false;
    }
    if (!value->as.number.is_int) {
        return false;
    }
    *out = value->as.number.integer;
    return true;
}

bool tamga_json_as_double(const TamgaJson *value, double *out)
{
    if (value == NULL || out == NULL || value->type != TAMGA_JSON_NUMBER) {
        return false;
    }
    *out = value->as.number.is_int ? (double)value->as.number.integer : value->as.number.real;
    return true;
}

const char *tamga_json_as_string(const TamgaJson *value, size_t *out_len)
{
    if (value == NULL || value->type != TAMGA_JSON_STRING) {
        return NULL;
    }
    if (out_len != NULL) {
        *out_len = value->as.string.len;
    }
    return value->as.string.bytes;
}

size_t tamga_json_array_len(const TamgaJson *value)
{
    if (value == NULL || value->type != TAMGA_JSON_ARRAY) {
        return 0u;
    }
    return value->as.array.count;
}

const TamgaJson *tamga_json_array_at(const TamgaJson *value, size_t index)
{
    if (value == NULL || value->type != TAMGA_JSON_ARRAY || index >= value->as.array.count) {
        return NULL;
    }
    return value->as.array.items[index];
}

size_t tamga_json_object_len(const TamgaJson *value)
{
    if (value == NULL || value->type != TAMGA_JSON_OBJECT) {
        return 0u;
    }
    return value->as.object.count;
}

const char *tamga_json_object_key_at(const TamgaJson *value, size_t index)
{
    if (value == NULL || value->type != TAMGA_JSON_OBJECT || index >= value->as.object.count) {
        return NULL;
    }
    return value->as.object.members[index].key;
}

const TamgaJson *tamga_json_object_value_at(const TamgaJson *value, size_t index)
{
    if (value == NULL || value->type != TAMGA_JSON_OBJECT || index >= value->as.object.count) {
        return NULL;
    }
    return value->as.object.members[index].value;
}

const TamgaJson *tamga_json_object_get(const TamgaJson *value, const char *key)
{
    size_t i;
    size_t key_len;

    if (value == NULL || value->type != TAMGA_JSON_OBJECT || key == NULL) {
        return NULL;
    }
    key_len = strlen(key);
    for (i = 0u; i < value->as.object.count; i++) {
        if (value->as.object.members[i].key_len == key_len &&
            memcmp(value->as.object.members[i].key, key, key_len) == 0) {
            return value->as.object.members[i].value;
        }
    }
    return NULL;
}
