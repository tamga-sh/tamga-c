#include "util/fingerprint.h"

#include <stdlib.h>
#include <string.h>

#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/buf.h"

/* One assembled "label=trimmed_value" component. */
typedef struct TamgaFpComponent {
    char *text;       /* owned, NUL-terminated */
    size_t len;       /* strlen(text) */
    size_t label_len; /* bytes before the '=' */
} TamgaFpComponent;

/*
 * The ASCII whitespace trimmed from both ends of a value, and only these six.
 *
 * Hand-coded rather than isspace(): isspace() is locale-dependent, and passing
 * it a plain `char` that is negative is undefined behaviour outright. Neither
 * is acceptable in a rule that eight independent ports have to agree on byte
 * for byte.
 */
static bool tamga_fp_is_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

/* ASCII control characters, which a value may not contain after trimming.
 * 0x1F is in this range, so the separator is refused inside a value by the
 * same check rather than by a special case of its own. */
static bool tamga_fp_is_control(unsigned char c) {
    return c <= 0x1FU || c == 0x7FU;
}

/*
 * A label is ASCII printable, excluding '='.
 *
 * Excluding '=' is what makes the split at the FIRST '=' unambiguous, which in
 * turn is what lets a value contain one. And restricting a label to ASCII is
 * what keeps it out of reach of the normalisation problem above: a label that
 * could need normalising would reintroduce, in the one field this library
 * chooses the alphabet for, exactly the divergence the values-are-not-
 * normalised rule exists to avoid.
 */
static bool tamga_fp_label_is_valid(const char *label, size_t *out_len) {
    size_t i;

    for (i = 0u; label[i] != '\0'; i++) {
        unsigned char c = (unsigned char)label[i];
        if (c < 0x21U || c > 0x7EU || c == '=') {
            return false;
        }
    }
    *out_len = i;
    return i > 0u;
}

/*
 * Bytewise ascending over the component's UTF-8 bytes.
 *
 * memcmp is specified to compare its operands as `unsigned char` (C11
 * 7.24.4p1 covers memcmp, strcmp and strncmp alike), so this is well defined
 * for the bytes above 0x7F a UTF-8 value is full of. The trap is not the
 * library function but a hand-rolled `a[i] - b[i]` over plain `char`, which on
 * a signed-char target orders every non-ASCII byte BEFORE every ASCII one and
 * silently produces a different fingerprint on ARM than on x86 for the same
 * machine. `non_ascii_value` in the vector file is the pin.
 *
 * Not locale-aware. And NOT a different rule from code-point order: UTF-8 is
 * constructed so that byte comparison and code-point comparison always agree,
 * so a test claiming to tell them apart cannot fail and should not be written.
 * The reason the spec says "bytewise" is implementability -- it is the form a
 * port with no Unicode tables can execute -- not a different result.
 *
 * The distinctions that ARE observable, and each has a test: the key is the
 * whole `label=value` component rather than the label alone, and the
 * comparison is case-sensitive.
 */
static int tamga_fp_compare(const void *a, const void *b) {
    const TamgaFpComponent *x = (const TamgaFpComponent *)a;
    const TamgaFpComponent *y = (const TamgaFpComponent *)b;
    size_t shortest = (x->len < y->len) ? x->len : y->len;
    int order = (shortest > 0u) ? memcmp(x->text, y->text, shortest) : 0;

    if (order != 0) {
        return order;
    }
    /* A prefix sorts before the string that extends it. */
    if (x->len == y->len) {
        return 0;
    }
    return (x->len < y->len) ? -1 : 1;
}

static void tamga_fp_free_all(TamgaFpComponent *components, size_t count) {
    size_t i;

    if (components == NULL) {
        return;
    }
    for (i = 0u; i < count; i++) {
        tamga_free(components[i].text);
    }
    tamga_free(components);
}

/*
 * Assembles one "label=trimmed_value", validating both halves.
 *
 * Every rejection here is an error and never a repair. Stripping a control
 * character or trimming something the rule does not trim would map two
 * different inputs onto one canonical string -- which is one seat for two
 * machines, the mirror image of the defect this function exists to fix.
 */
static TamgaErrorCode tamga_fp_build_component(const char *label, const char *value, size_t index,
                                               TamgaFpComponent *out) {
    TamgaBuf buf;
    size_t label_len = 0u;
    size_t start = 0u;
    size_t end;
    size_t i;

    if (label == NULL || value == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "component %lu: both a label and a value are required",
                               (unsigned long)index);
    }
    if (!tamga_fp_label_is_valid(label, &label_len)) {
        return tamga_error_set(TAMGA_ERR_INVALID_FINGERPRINT_COMPONENT,
                               "component %lu: a label must be non-empty ASCII printable "
                               "(0x21-0x7E) and must not contain '='",
                               (unsigned long)index);
    }

    /* Trimmed BEFORE validation, so that a value arriving with a trailing
     * newline is accepted rather than refused as a control character -- the
     * stray newline off a command's output is the single most common way this
     * goes wrong, and it is exactly what the helper is for. */
    end = strlen(value);
    while (start < end && tamga_fp_is_space((unsigned char)value[start])) {
        start++;
    }
    while (end > start && tamga_fp_is_space((unsigned char)value[end - 1u])) {
        end--;
    }
    for (i = start; i < end; i++) {
        if (tamga_fp_is_control((unsigned char)value[i])) {
            return tamga_error_set(TAMGA_ERR_INVALID_FINGERPRINT_COMPONENT,
                                   "component %lu (label \"%s\"): a value may not contain an ASCII "
                                   "control character",
                                   (unsigned long)index, label);
        }
    }

    tamga_buf_init(&buf);
    tamga_buf_append(&buf, label, label_len);
    tamga_buf_append_byte(&buf, '=');
    tamga_buf_append(&buf, value + start, end - start);
    out->text = tamga_buf_detach_string(&buf, &out->len);
    tamga_buf_free(&buf);
    if (out->text == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the fingerprint");
    }
    out->label_len = label_len;
    return TAMGA_OK;
}

/*
 * Rejects a repeated label.
 *
 * Checked after the sort, because sorting makes every component sharing a
 * label contiguous: a label cannot contain '=', so no OTHER label can produce
 * a component that sorts between two of "id=a" and "id=b" -- it would have to
 * begin with the bytes "id=" and therefore be the label "id". One adjacent
 * pass is exact, and it names the offending label instead of just counting.
 *
 * Rejected rather than deduplicated because two values for one label is a
 * caller bug: picking one of them hides it, and picking a different one on the
 * next run moves the machine to a second seat.
 */
static TamgaErrorCode tamga_fp_reject_duplicates(const TamgaFpComponent *components, size_t count) {
    size_t i;

    for (i = 1u; i < count; i++) {
        const TamgaFpComponent *prev = &components[i - 1u];
        const TamgaFpComponent *cur = &components[i];
        if (prev->label_len == cur->label_len &&
            memcmp(prev->text, cur->text, cur->label_len) == 0) {
            return tamga_error_set(TAMGA_ERR_INVALID_FINGERPRINT_COMPONENT,
                                   "duplicate label \"%.*s\": two values for one label is a caller "
                                   "bug, not something to deduplicate",
                                   (int)cur->label_len, cur->text);
        }
    }
    return TAMGA_OK;
}

TamgaErrorCode tamga_fingerprint_build_canonical(const char *const *labels,
                                                 const char *const *values, size_t count,
                                                 char **out_canonical) {
    TamgaFpComponent *components;
    TamgaBuf buf;
    char *canonical;
    size_t built = 0u;
    size_t i;
    TamgaErrorCode status;

    if (labels == NULL || values == NULL || out_canonical == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "labels, values and out_canonical are required");
    }
    if (count == 0u) {
        return tamga_error_set(TAMGA_ERR_INVALID_FINGERPRINT_COMPONENT,
                               "at least one component is required");
    }

    components = (TamgaFpComponent *)tamga_calloc(count, sizeof(*components));
    if (components == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the fingerprint");
    }
    for (i = 0u; i < count; i++) {
        status = tamga_fp_build_component(labels[i], values[i], i, &components[i]);
        if (status != TAMGA_OK) {
            tamga_fp_free_all(components, built);
            return status;
        }
        built++;
    }

    /* Order is the caller's convenience, not part of the identity: the same
     * set of components listed in a different order is the same machine. */
    qsort(components, count, sizeof(*components), tamga_fp_compare);

    status = tamga_fp_reject_duplicates(components, count);
    if (status != TAMGA_OK) {
        tamga_fp_free_all(components, count);
        return status;
    }

    tamga_buf_init(&buf);
    tamga_buf_append_str(&buf, TAMGA_FINGERPRINT_DOMAIN);
    for (i = 0u; i < count; i++) {
        tamga_buf_append_byte(&buf, TAMGA_FINGERPRINT_SEPARATOR);
        tamga_buf_append(&buf, components[i].text, components[i].len);
    }
    canonical = tamga_buf_detach_string(&buf, NULL);
    tamga_buf_free(&buf);
    tamga_fp_free_all(components, count);
    if (canonical == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the fingerprint");
    }

    /* The single out-parameter is written last and only here, so no failure
     * above can leave the caller holding a half-built canonical string. */
    *out_canonical = canonical;
    return TAMGA_OK;
}
