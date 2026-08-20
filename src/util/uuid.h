/*
 * uuid.h -- UUID parsing and canonical formatting.
 *
 * The canonical form -- 36 characters, lowercase, hyphenated -- is what the
 * server emits and therefore what has to appear byte-for-byte inside the
 * offline proof's signed payload. Anything this library re-serializes goes
 * through tamga_uuid_format(), never through the caller's original spelling:
 * an uppercase or brace-wrapped UUID accepted at the API boundary must still
 * produce the same signed bytes as the server's lowercase hyphenated one.
 */
#ifndef TAMGA_UTIL_UUID_H
#define TAMGA_UTIL_UUID_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

/** 36 characters plus the NUL terminator. */
#define TAMGA_UUID_STRING_SIZE 37

typedef struct TamgaUuid {
    unsigned char bytes[16];
} TamgaUuid;

/**
 * Parses a UUID in any of the four forms the fleet's other SDKs accept:
 * hyphenated (36), simple (32), braced (38) and `urn:uuid:` (45). Returns
 * false on anything else, including a NULL input.
 */
TAMGA_NODISCARD bool tamga_uuid_parse(const char *str, TamgaUuid *out);

/** Writes the canonical lowercase hyphenated form plus NUL into `out`, which
 *  must have room for TAMGA_UUID_STRING_SIZE bytes. */
void tamga_uuid_format(const TamgaUuid *uuid, char *out);

/** Convenience: parse then re-format into canonical form. Returns false if
 *  `str` is not a UUID. */
TAMGA_NODISCARD bool tamga_uuid_normalize(const char *str, char *out);

#endif /* TAMGA_UTIL_UUID_H */
