#include "checkout/claims.h"

#include "tamga_error.h"

TamgaErrorCode tamga_claims_read(const TamgaJson *meta, TamgaFileClaims *out) {
    const TamgaJson *exp;
    int64_t value = 0;

    if (out == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    out->issued_at = 0;
    out->has_expiry = false;
    out->expiry = 0;

    if (meta == NULL || tamga_json_type(meta) != TAMGA_JSON_OBJECT) {
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "the signed payload has no claims object");
    }
    if (tamga_json_as_int(tamga_json_object_get(meta, "iat"), &value)) {
        out->issued_at = value;
    }
    exp = tamga_json_object_get(meta, "exp");
    /* An absent exp means the file never expires -- checkout was requested
     * without a ttl. An explicit null means the same thing. */
    if (exp != NULL && !tamga_json_is_null(exp)) {
        if (!tamga_json_as_int(exp, &value)) {
            return tamga_error_set(TAMGA_ERR_INVALID_JSON,
                                   "the signed exp claim is not an integer");
        }
        out->has_expiry = true;
        out->expiry = value;
    }
    return TAMGA_OK;
}

bool tamga_claims_are_expired(const TamgaFileClaims *claims, int64_t now_unix) {
    if (claims == NULL || !claims->has_expiry) {
        return false;
    }
    /* `now - skew` without the signed overflow an INT64_MIN clock would cause.
     * Any reading below the tolerance itself is far enough in the past that no
     * expiry can have passed, so answering "not expired" there is correct as
     * well as safe. */
    if (now_unix < (int64_t)TAMGA_CLOCK_SKEW_TOLERANCE_SECONDS) {
        return false;
    }
    return (now_unix - TAMGA_CLOCK_SKEW_TOLERANCE_SECONDS) > claims->expiry;
}
