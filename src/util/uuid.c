#include "util/uuid.h"

#include <string.h>

#include "util/hex.h"

/* Byte offset, within the 16-byte value, that each hyphen-separated group
 * starts at -- 8-4-4-4-12 hex characters, i.e. 4-2-2-2-6 bytes. */
static const size_t TAMGA_UUID_GROUP_BYTES[5] = {4u, 2u, 2u, 2u, 6u};

static bool tamga_uuid_parse_hyphenated(const char *str, TamgaUuid *out) {
    size_t group;
    size_t src = 0u;
    size_t dst = 0u;

    for (group = 0u; group < 5u; group++) {
        size_t nbytes = TAMGA_UUID_GROUP_BYTES[group];
        if (group > 0u) {
            if (str[src] != '-') {
                return false;
            }
            src++;
        }
        if (!tamga_hex_decode(&str[src], nbytes * 2u, &out->bytes[dst])) {
            return false;
        }
        src += nbytes * 2u;
        dst += nbytes;
    }
    return true;
}

bool tamga_uuid_parse(const char *str, TamgaUuid *out) {
    size_t len;

    if (str == NULL || out == NULL) {
        return false;
    }
    len = strlen(str);

    /* urn:uuid:<hyphenated> -- compare case-insensitively on the scheme only,
     * matching the other SDKs' UUID parsers. */
    if (len == 45u) {
        static const char urn[] = "urn:uuid:";
        size_t i;
        for (i = 0u; i < 9u; i++) {
            char c = str[i];
            char lower = (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
            if (lower != urn[i]) {
                return false;
            }
        }
        return tamga_uuid_parse_hyphenated(&str[9], out);
    }

    if (len == 38u) {
        if (str[0] != '{' || str[37] != '}') {
            return false;
        }
        return tamga_uuid_parse_hyphenated(&str[1], out);
    }

    if (len == 36u) {
        return tamga_uuid_parse_hyphenated(str, out);
    }

    if (len == 32u) {
        return tamga_hex_decode(str, 32u, out->bytes);
    }

    return false;
}

void tamga_uuid_format(const TamgaUuid *uuid, char *out) {
    char hex[33];

    if (out == NULL) {
        return;
    }
    if (uuid == NULL) {
        out[0] = '\0';
        return;
    }

    tamga_hex_encode(uuid->bytes, 16u, hex);
    memcpy(&out[0], &hex[0], 8u);
    out[8] = '-';
    memcpy(&out[9], &hex[8], 4u);
    out[13] = '-';
    memcpy(&out[14], &hex[12], 4u);
    out[18] = '-';
    memcpy(&out[19], &hex[16], 4u);
    out[23] = '-';
    memcpy(&out[24], &hex[20], 12u);
    out[36] = '\0';
}

bool tamga_uuid_normalize(const char *str, char *out) {
    TamgaUuid uuid;

    if (out == NULL) {
        return false;
    }
    if (!tamga_uuid_parse(str, &uuid)) {
        return false;
    }
    tamga_uuid_format(&uuid, out);
    return true;
}
