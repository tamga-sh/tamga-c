#include "checkout/pem.h"

#include <string.h>

#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/buf.h"

static bool tamga_pem_is_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

TamgaErrorCode tamga_pem_extract(const char *pem, size_t pem_len, const char *begin_marker,
                                 const char *end_marker, char **out_body, size_t *out_body_len) {
    size_t start = 0u;
    size_t end;
    size_t trimmed_len;
    size_t begin_len;
    size_t end_len;
    size_t body_start;
    size_t body_len;
    size_t i;
    TamgaBuf buf;
    char *body;

    if (pem == NULL || begin_marker == NULL || end_marker == NULL || out_body == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    if (pem_len == 0u || pem_len > TAMGA_MAX_REASONABLE_LEN) {
        return tamga_error_set(TAMGA_ERR_LENGTH_INVALID,
                               "certificate length is zero or exceeds the accepted maximum");
    }

    end = pem_len;
    while (start < end && tamga_pem_is_space(pem[start])) {
        start++;
    }
    while (end > start && tamga_pem_is_space(pem[end - 1u])) {
        end--;
    }
    trimmed_len = end - start;

    begin_len = strlen(begin_marker);
    end_len = strlen(end_marker);

    /*
     * The combined-length check is not redundant with the two marker
     * comparisons below.
     *
     * Matching a prefix and matching a suffix are independent facts: a short
     * enough input can satisfy both while the markers overlap, and the body
     * span computed from them would then have a negative length -- which, as
     * a size_t, is an enormous one. The same class of bug was found and fixed
     * during the mandatory security review of this SDK family's .NET, Java
     * and Swift implementations, where it produced an unexpected exception
     * type; here it would be an out-of-bounds read.
     */
    if (trimmed_len < (begin_len + end_len)) {
        return tamga_error_set(TAMGA_ERR_INVALID_PEM,
                               "certificate is too short to contain both PEM markers");
    }
    if (memcmp(&pem[start], begin_marker, begin_len) != 0) {
        return tamga_error_set(TAMGA_ERR_INVALID_PEM, "missing the opening PEM marker");
    }
    if (memcmp(&pem[end - end_len], end_marker, end_len) != 0) {
        return tamga_error_set(TAMGA_ERR_INVALID_PEM, "missing the closing PEM marker");
    }

    body_start = start + begin_len;
    body_len = trimmed_len - begin_len - end_len;

    tamga_buf_init(&buf);
    for (i = 0u; i < body_len; i++) {
        char c = pem[body_start + i];
        if (!tamga_pem_is_space(c)) {
            tamga_buf_append_byte(&buf, (unsigned char)c);
        }
    }
    body = tamga_buf_detach_string(&buf, out_body_len);
    tamga_buf_free(&buf);
    if (body == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the certificate body");
    }

    *out_body = body;
    return TAMGA_OK;
}
