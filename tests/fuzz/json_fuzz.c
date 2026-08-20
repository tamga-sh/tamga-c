/*
 * The JSON parser sees every API response and the decrypted contents of every
 * offline file. A round-trip is asserted as well as a parse: anything that
 * parses must re-serialise and re-parse to the same bytes, which catches a
 * writer that emits something its own reader rejects.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tamga_mem.h"
#include "util/json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    TamgaJson *value = tamga_json_parse((const char *)data, size, NULL);
    char *first;
    TamgaJson *reparsed;
    char *second;

    if (value == NULL) {
        return 0;
    }

    first = tamga_json_write_canonical(value, NULL);
    tamga_json_free(value);
    if (first == NULL) {
        return 0;
    }

    reparsed = tamga_json_parse(first, strlen(first), NULL);
    if (reparsed == NULL) {
        /* Output this parser cannot read back is a bug in the writer. */
        abort();
    }
    second = tamga_json_write_canonical(reparsed, NULL);
    tamga_json_free(reparsed);
    if (second != NULL) {
        if (strcmp(first, second) != 0) {
            /* Canonical form must be a fixed point. */
            abort();
        }
        tamga_free(second);
    }
    tamga_free(first);
    return 0;
}
