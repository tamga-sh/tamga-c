#include "crypto/der.h"

#include <string.h>

void tamga_der_init(TamgaDer *reader, const unsigned char *data, size_t len) {
    if (reader == NULL) {
        return;
    }
    reader->data = data;
    reader->len = (data == NULL) ? 0u : len;
    reader->pos = 0u;
}

bool tamga_der_at_end(const TamgaDer *reader) {
    return reader == NULL || reader->pos >= reader->len;
}

bool tamga_der_read(TamgaDer *reader, unsigned int *tag, const unsigned char **content,
                    size_t *content_len) {
    size_t remaining;
    unsigned char first_length_byte;
    size_t length = 0u;

    if (reader == NULL || reader->data == NULL || tag == NULL || content == NULL ||
        content_len == NULL) {
        return false;
    }
    remaining = reader->len - reader->pos;
    if (reader->pos >= reader->len || remaining < 2u) {
        return false;
    }

    /* High-tag-number form (tag byte 0x1F in the low bits) is not used by any
     * structure this library reads, and supporting it would be untested code
     * on an attacker-reachable path. */
    if ((reader->data[reader->pos] & 0x1Fu) == 0x1Fu) {
        return false;
    }
    *tag = reader->data[reader->pos];
    reader->pos++;

    first_length_byte = reader->data[reader->pos];
    reader->pos++;

    if ((first_length_byte & 0x80u) == 0u) {
        length = first_length_byte;
    } else {
        unsigned int count = (unsigned int)(first_length_byte & 0x7Fu);
        unsigned int i;

        /* 0x80 is the indefinite form, which DER forbids. */
        if (count == 0u || count > 4u) {
            return false;
        }
        if ((reader->len - reader->pos) < count) {
            return false;
        }
        /* DER requires the shortest possible length encoding, so the first
         * byte must be non-zero and the value must not fit in the short
         * form. Accepting a padded length lets the same structure be encoded
         * two ways, which is exactly what a signature must not permit. */
        if (reader->data[reader->pos] == 0u) {
            return false;
        }
        for (i = 0u; i < count; i++) {
            length = (length << 8) | (size_t)reader->data[reader->pos];
            reader->pos++;
        }
        if (length < 0x80u) {
            return false;
        }
    }

    if ((reader->len - reader->pos) < length) {
        return false;
    }
    *content = &reader->data[reader->pos];
    *content_len = length;
    reader->pos += length;
    return true;
}

bool tamga_der_expect(TamgaDer *reader, unsigned int tag, const unsigned char **content,
                      size_t *content_len) {
    unsigned int actual = 0u;
    if (!tamga_der_read(reader, &actual, content, content_len)) {
        return false;
    }
    return actual == tag;
}

bool tamga_der_read_unsigned(TamgaDer *reader, const unsigned char **value, size_t *value_len) {
    const unsigned char *content = NULL;
    size_t content_len = 0u;

    if (!tamga_der_expect(reader, TAMGA_DER_INTEGER, &content, &content_len)) {
        return false;
    }
    if (content_len == 0u) {
        return false;
    }
    /* A set high bit on the first byte means a negative INTEGER. No field
     * this library reads is ever negative. */
    if ((content[0] & 0x80u) != 0u) {
        return false;
    }
    if (content[0] == 0u) {
        if (content_len == 1u) {
            /* The integer zero: legal, and its magnitude is the single zero
             * byte. */
            *value = content;
            *value_len = content_len;
            return true;
        }
        /* A leading zero is only minimal when the next byte has its high bit
         * set; otherwise the encoding is padded. */
        if ((content[1] & 0x80u) == 0u) {
            return false;
        }
        *value = &content[1];
        *value_len = content_len - 1u;
        return true;
    }

    *value = content;
    *value_len = content_len;
    return true;
}

bool tamga_der_read_bit_string(TamgaDer *reader, const unsigned char **value, size_t *value_len) {
    const unsigned char *content = NULL;
    size_t content_len = 0u;

    if (!tamga_der_expect(reader, TAMGA_DER_BIT_STRING, &content, &content_len)) {
        return false;
    }
    if (content_len < 1u) {
        return false;
    }
    if (content[0] != 0u) {
        return false; /* partial trailing byte: not used by any structure here */
    }
    *value = &content[1];
    *value_len = content_len - 1u;
    return true;
}

bool tamga_der_expect_oid(TamgaDer *reader, const unsigned char *expected, size_t expected_len) {
    const unsigned char *content = NULL;
    size_t content_len = 0u;

    if (expected == NULL) {
        return false;
    }
    if (!tamga_der_expect(reader, TAMGA_DER_OID, &content, &content_len)) {
        return false;
    }
    if (content_len != expected_len) {
        return false;
    }
    return memcmp(content, expected, expected_len) == 0;
}
