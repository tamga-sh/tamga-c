/*
 * json_write.c -- the two serializers.
 *
 * tamga_json_write_canonical() reproduces the bytes the Tamga server signs.
 * That is a compatibility contract, not a formatting preference, and the
 * rules it implements are:
 *
 *   - no whitespace anywhere;
 *   - object keys sorted by unsigned UTF-8 byte order at every nesting level,
 *     matching serde_json's BTreeMap-backed map (the server's payload is
 *     alphabetical on the wire even though its source code writes the fields
 *     in a different order);
 *   - arrays keep document order -- JSON arrays are ordered by definition and
 *     only object keys get sorted;
 *   - serde_json's exact escaping: the five short escapes, remaining C0
 *     control characters as lowercase \u00xx, everything else -- including
 *     all non-ASCII -- emitted as raw UTF-8, and '/' left alone.
 *
 * tamga_json_write() is the same minus the key sorting, for request bodies
 * and caller-facing payloads where nothing is signed.
 */
#include "util/json.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tamga_mem.h"
#include "util/buf.h"

static void tamga_json_write_value(const TamgaJson *value, TamgaBuf *out, bool canonical);

static void tamga_json_write_escaped(const char *bytes, size_t len, TamgaBuf *out) {
    size_t i;

    tamga_buf_append_byte(out, '"');
    for (i = 0u; i < len; i++) {
        unsigned char c = (unsigned char)bytes[i];
        switch (c) {
        case '"':
            tamga_buf_append(out, "\\\"", 2u);
            break;
        case '\\':
            tamga_buf_append(out, "\\\\", 2u);
            break;
        case '\b':
            tamga_buf_append(out, "\\b", 2u);
            break;
        case '\f':
            tamga_buf_append(out, "\\f", 2u);
            break;
        case '\n':
            tamga_buf_append(out, "\\n", 2u);
            break;
        case '\r':
            tamga_buf_append(out, "\\r", 2u);
            break;
        case '\t':
            tamga_buf_append(out, "\\t", 2u);
            break;
        default:
            if (c < 0x20u) {
                static const char hex[] = "0123456789abcdef";
                char escape[6];
                escape[0] = '\\';
                escape[1] = 'u';
                escape[2] = '0';
                escape[3] = '0';
                escape[4] = hex[(c >> 4) & 0x0Fu];
                escape[5] = hex[c & 0x0Fu];
                tamga_buf_append(out, escape, sizeof(escape));
            } else {
                tamga_buf_append_byte(out, c);
            }
            break;
        }
    }
    tamga_buf_append_byte(out, '"');
}

/*
 * Shortest decimal representation that round-trips back to the same double,
 * formatted the way serde_json's formatter (ryu) formats it.
 *
 * Two steps, because those are two separate problems:
 *
 * 1. Digits. Try increasing precisions with "%.*e" until strtod() returns the
 *    original value. That yields the shortest significant-digit string -- the
 *    same property ryu computes directly, reached portably.
 *
 * 2. Notation. ryu picks decimal or exponential from `kk`, the position of the
 *    decimal point relative to the digit string: decimal when 0 < kk <= 16,
 *    a leading "0.000..." form when -5 < kk <= 0, and exponential otherwise.
 *    printf's "%g" uses a different threshold, so its choice cannot be reused.
 *
 * Style agreement is not guaranteed for every IEEE 754 value; integers,
 * strings, booleans, null, arrays and objects are exact. json.h documents
 * non-integer floats inside a signed `dataset` as a compatibility hazard.
 */
static void tamga_json_write_double(double value, TamgaBuf *out) {
    char scratch[64];
    char digits[32];
    int precision;
    int exponent10 = 0;
    size_t digit_count = 0u;
    bool negative = false;
    int kk;
    const char *cursor;

    /* JSON has no non-finite numbers; serde_json maps them to null rather
     * than emitting something no parser accepts. */
    if (!isfinite(value)) {
        tamga_buf_append(out, "null", 4u);
        return;
    }

    for (precision = 0; precision <= 17; precision++) {
        int written = snprintf(scratch, sizeof(scratch), "%.*e", precision, value);
        if (written < 0 || (size_t)written >= sizeof(scratch)) {
            tamga_buf_append(out, "null", 4u);
            return;
        }
        if (strtod(scratch, NULL) == value) {
            break;
        }
    }
    if (precision > 17) {
        tamga_buf_append(out, "null", 4u);
        return;
    }

    /* scratch is now "[-]d[.ddd]e[+-]dd". Split it into a sign, a bare digit
     * string, and the base-10 exponent of the leading digit. */
    cursor = scratch;
    if (*cursor == '-') {
        negative = true;
        cursor++;
    }
    while (*cursor != '\0' && *cursor != 'e' && *cursor != 'E') {
        if (*cursor != '.') {
            if (digit_count >= sizeof(digits)) {
                tamga_buf_append(out, "null", 4u);
                return;
            }
            digits[digit_count] = *cursor;
            digit_count++;
        }
        cursor++;
    }
    if (*cursor == 'e' || *cursor == 'E') {
        exponent10 = (int)strtol(cursor + 1, NULL, 10);
    }
    if (digit_count == 0u) {
        tamga_buf_append(out, "null", 4u);
        return;
    }

    /* Trailing zeros carry no information and ryu never emits them. They can
     * appear here when the round-trip search settles on a precision whose
     * last digit happens to be zero (1e2 -> "1.00e+02" at precision 2). */
    while (digit_count > 1u && digits[digit_count - 1u] == '0') {
        digit_count--;
    }

    kk = exponent10 + 1; /* digits before the decimal point */

    if (negative) {
        tamga_buf_append_byte(out, '-');
    }

    if (kk > 0 && kk <= 16) {
        if ((size_t)kk >= digit_count) {
            /* 15 with kk=4 -> "1500.0" */
            size_t pad;
            tamga_buf_append(out, digits, digit_count);
            for (pad = digit_count; pad < (size_t)kk; pad++) {
                tamga_buf_append_byte(out, '0');
            }
            tamga_buf_append(out, ".0", 2u);
        } else {
            /* 15 with kk=1 -> "1.5" */
            tamga_buf_append(out, digits, (size_t)kk);
            tamga_buf_append_byte(out, '.');
            tamga_buf_append(out, &digits[kk], digit_count - (size_t)kk);
        }
        return;
    }

    if (kk > -5 && kk <= 0) {
        /* 15 with kk=-1 -> "0.015" */
        int zeros;
        tamga_buf_append(out, "0.", 2u);
        for (zeros = 0; zeros < -kk; zeros++) {
            tamga_buf_append_byte(out, '0');
        }
        tamga_buf_append(out, digits, digit_count);
        return;
    }

    /* Exponential: one digit, optional fraction, then the exponent with an
     * explicit sign and no leading zeros -- "1e+16", "1e-6". Verified against
     * serde_json directly; note the '+', which printf's %e also emits but
     * which several hand-rolled formatters drop. */
    tamga_buf_append(out, digits, 1u);
    if (digit_count > 1u) {
        tamga_buf_append_byte(out, '.');
        tamga_buf_append(out, &digits[1], digit_count - 1u);
    }
    tamga_buf_append_fmt(out, "e%+d", kk - 1);
}

/*
 * Unsigned byte-lexicographic comparison, with the shorter string ordering
 * first when one is a prefix of the other -- exactly Rust's Ord for String,
 * which is what the server's BTreeMap uses.
 *
 * memcmp on char* would be signed-char-dependent on some platforms, so the
 * comparison is done on unsigned char explicitly.
 */
static int tamga_json_key_cmp(const char *a, const char *b) {
    const unsigned char *ua = (const unsigned char *)a;
    const unsigned char *ub = (const unsigned char *)b;
    size_t i = 0u;

    while (ua[i] != 0u && ub[i] != 0u) {
        if (ua[i] != ub[i]) {
            return (ua[i] < ub[i]) ? -1 : 1;
        }
        i++;
    }
    if (ua[i] == ub[i]) {
        return 0;
    }
    return (ua[i] == 0u) ? -1 : 1;
}

/* Bottom-up merge sort over an index array. Merge sort rather than an
 * insertion sort because a caller-supplied `dataset` object has no bounded
 * size, and rather than qsort because qsort's comparator cannot portably
 * carry the object it is sorting against. */
static bool tamga_json_sort_keys(const TamgaJson *object, size_t count, size_t **out_order) {
    size_t *order;
    size_t *scratch;
    size_t width;
    size_t i;

    order = (size_t *)tamga_calloc(count, sizeof(size_t));
    if (order == NULL) {
        return false;
    }
    scratch = (size_t *)tamga_calloc(count, sizeof(size_t));
    if (scratch == NULL) {
        tamga_free(order);
        return false;
    }
    for (i = 0u; i < count; i++) {
        order[i] = i;
    }

    for (width = 1u; width < count; width *= 2u) {
        size_t start;
        for (start = 0u; start < count; start += (width * 2u)) {
            size_t mid = start + width;
            size_t end = start + (width * 2u);
            size_t left = start;
            size_t right;
            size_t at = start;

            if (mid > count) {
                mid = count;
            }
            if (end > count) {
                end = count;
            }
            /* Assigned after the clamp, not before it: the unclamped mid can
             * exceed count on the final, partial run. */
            right = mid;
            while (left < mid || right < end) {
                bool take_left;
                if (left >= mid) {
                    take_left = false;
                } else if (right >= end) {
                    take_left = true;
                } else {
                    const char *lk = tamga_json_object_key_at(object, order[left]);
                    const char *rk = tamga_json_object_key_at(object, order[right]);
                    take_left = (tamga_json_key_cmp(lk, rk) <= 0);
                }
                scratch[at] = take_left ? order[left++] : order[right++];
                at++;
            }
        }
        for (i = 0u; i < count; i++) {
            order[i] = scratch[i];
        }
    }

    tamga_free(scratch);
    *out_order = order;
    return true;
}

static void tamga_json_write_object(const TamgaJson *value, TamgaBuf *out, bool canonical) {
    size_t count = tamga_json_object_len(value);
    size_t *order = NULL;
    size_t i;

    tamga_buf_append_byte(out, '{');
    if (canonical && count > 1u) {
        if (!tamga_json_sort_keys(value, count, &order)) {
            /* Marking the buffer failed is what makes this safe: the detach
             * helpers refuse a failed buffer, so no caller can receive
             * unsorted -- that is, unsignable -- output. */
            tamga_buf_mark_failed(out);
            return;
        }
    }

    for (i = 0u; i < count; i++) {
        size_t index = (order != NULL) ? order[i] : i;
        const char *key = tamga_json_object_key_at(value, index);
        const TamgaJson *member = tamga_json_object_value_at(value, index);

        if (i > 0u) {
            tamga_buf_append_byte(out, ',');
        }
        if (key == NULL) {
            tamga_buf_mark_failed(out);
            break;
        }
        tamga_json_write_escaped(key, strlen(key), out);
        tamga_buf_append_byte(out, ':');
        tamga_json_write_value(member, out, canonical);
    }

    tamga_free(order);
    tamga_buf_append_byte(out, '}');
}

static void tamga_json_write_value(const TamgaJson *value, TamgaBuf *out, bool canonical) {
    size_t i;

    if (value == NULL) {
        tamga_buf_append(out, "null", 4u);
        return;
    }

    switch (tamga_json_type(value)) {
    case TAMGA_JSON_NULL:
        tamga_buf_append(out, "null", 4u);
        break;
    case TAMGA_JSON_BOOL:
        if (tamga_json_bool_or(value, false)) {
            tamga_buf_append(out, "true", 4u);
        } else {
            tamga_buf_append(out, "false", 5u);
        }
        break;
    case TAMGA_JSON_NUMBER: {
        int64_t as_int = 0;
        double as_double = 0.0;
        /* An integer must serialize without a fractional part and a float
         * must serialize with one; tamga_json_as_int() accepts an integral
         * double, so the type flag -- not the value -- decides. */
        if (tamga_json_int_literal(value, &as_int)) {
            tamga_buf_append_fmt(out, "%lld", (long long)as_int);
        } else if (tamga_json_as_double(value, &as_double)) {
            tamga_json_write_double(as_double, out);
        } else {
            tamga_buf_append(out, "null", 4u);
        }
        break;
    }
    case TAMGA_JSON_STRING: {
        size_t len = 0u;
        const char *bytes = tamga_json_as_string(value, &len);
        if (bytes == NULL) {
            tamga_buf_mark_failed(out);
            break;
        }
        tamga_json_write_escaped(bytes, len, out);
        break;
    }
    case TAMGA_JSON_ARRAY: {
        size_t count = tamga_json_array_len(value);
        tamga_buf_append_byte(out, '[');
        for (i = 0u; i < count; i++) {
            if (i > 0u) {
                tamga_buf_append_byte(out, ',');
            }
            tamga_json_write_value(tamga_json_array_at(value, i), out, canonical);
        }
        tamga_buf_append_byte(out, ']');
        break;
    }
    case TAMGA_JSON_OBJECT:
        tamga_json_write_object(value, out, canonical);
        break;
    default:
        tamga_buf_mark_failed(out);
        break;
    }
}

static char *tamga_json_write_impl(const TamgaJson *value, size_t *out_len, bool canonical) {
    TamgaBuf buf;
    char *text;

    tamga_buf_init(&buf);
    tamga_json_write_value(value, &buf, canonical);
    text = tamga_buf_detach_string(&buf, out_len);
    tamga_buf_free(&buf);
    return text;
}

char *tamga_json_write_canonical(const TamgaJson *value, size_t *out_len) {
    return tamga_json_write_impl(value, out_len, true);
}

char *tamga_json_write(const TamgaJson *value, size_t *out_len) {
    return tamga_json_write_impl(value, out_len, false);
}
