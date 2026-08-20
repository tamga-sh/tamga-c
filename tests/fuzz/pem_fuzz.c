/*
 * The PEM envelope reader is the first thing a hostile .lic file reaches. The
 * overlapping-marker case -- where a prefix and a suffix match while the
 * markers overlap -- is the one that computes a negative body length, so this
 * target is pointed straight at it.
 */
#include <stdint.h>

#include "checkout/pem.h"
#include "tamga.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *body = NULL;
    size_t body_len = 0u;

    if (tamga_pem_extract((const char *)data, size, "-----BEGIN LICENSE FILE-----",
                          "-----END LICENSE FILE-----", &body, &body_len) == TAMGA_OK) {
        tamga_string_free(body);
    }
    body = NULL;
    if (tamga_pem_extract((const char *)data, size, "-----BEGIN MACHINE FILE-----",
                          "-----END MACHINE FILE-----", &body, &body_len) == TAMGA_OK) {
        tamga_string_free(body);
    }
    return 0;
}
