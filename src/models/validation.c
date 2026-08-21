/*
 * validation.c -- the validation outcome vocabulary.
 *
 * The mapping is a plain table rather than anything clever because it is a
 * protocol constant: the strings are the server's, the numbers are this SDK's
 * ABI, and neither may drift. An unrecognised string becomes UNKNOWN instead
 * of an error, so a code added server-side tomorrow does not break a caller
 * built today.
 */
#include <string.h>

#include "tamga.h"

typedef struct TamgaValidationCodeEntry {
    const char *name;
    TamgaValidationCode code;
} TamgaValidationCodeEntry;

static const TamgaValidationCodeEntry TAMGA_VALIDATION_CODES[] = {
    {"VALID", TAMGA_VALIDATION_VALID},
    {"NOT_FOUND", TAMGA_VALIDATION_NOT_FOUND},
    {"BANNED", TAMGA_VALIDATION_BANNED},
    {"SUSPENDED", TAMGA_VALIDATION_SUSPENDED},
    {"EXPIRED", TAMGA_VALIDATION_EXPIRED},
    {"OVERDUE", TAMGA_VALIDATION_OVERDUE},
    {"ENTITLEMENTS_MISSING", TAMGA_VALIDATION_ENTITLEMENTS_MISSING},
    {"TOO_MANY_MACHINES", TAMGA_VALIDATION_TOO_MANY_MACHINES},
    {"TOO_MANY_CORES", TAMGA_VALIDATION_TOO_MANY_CORES},
    {"TOO_MUCH_MEMORY", TAMGA_VALIDATION_TOO_MUCH_MEMORY},
    {"TOO_MUCH_DISK", TAMGA_VALIDATION_TOO_MUCH_DISK},
    {"TOO_MANY_PROCESSES", TAMGA_VALIDATION_TOO_MANY_PROCESSES},
    {"TOO_MANY_USERS", TAMGA_VALIDATION_TOO_MANY_USERS},
    {"HEARTBEAT_DEAD", TAMGA_VALIDATION_HEARTBEAT_DEAD},
    {"HEARTBEAT_NOT_STARTED", TAMGA_VALIDATION_HEARTBEAT_NOT_STARTED},
    {"PRODUCT_SCOPE_MISMATCH", TAMGA_VALIDATION_PRODUCT_SCOPE_MISMATCH},
    {"POLICY_SCOPE_MISMATCH", TAMGA_VALIDATION_POLICY_SCOPE_MISMATCH},
    {"USER_SCOPE_MISMATCH", TAMGA_VALIDATION_USER_SCOPE_MISMATCH},
    {"FINGERPRINT_SCOPE_MISMATCH", TAMGA_VALIDATION_FINGERPRINT_SCOPE_MISMATCH},
    {"COMPONENTS_SCOPE_MISMATCH", TAMGA_VALIDATION_COMPONENTS_SCOPE_MISMATCH},
    {"CHECKSUM_SCOPE_MISMATCH", TAMGA_VALIDATION_CHECKSUM_SCOPE_MISMATCH},
    {"VERSION_SCOPE_MISMATCH", TAMGA_VALIDATION_VERSION_SCOPE_MISMATCH},
    {"ENVIRONMENT_SCOPE_MISMATCH", TAMGA_VALIDATION_ENVIRONMENT_SCOPE_MISMATCH},
    {"TOO_MANY_USES", TAMGA_VALIDATION_TOO_MANY_USES},
};

TamgaValidationCode tamga_validation_code_parse(const char *code) {
    size_t i;

    if (code == NULL) {
        return TAMGA_VALIDATION_UNKNOWN;
    }
    for (i = 0u; i < (sizeof(TAMGA_VALIDATION_CODES) / sizeof(TAMGA_VALIDATION_CODES[0])); i++) {
        if (strcmp(code, TAMGA_VALIDATION_CODES[i].name) == 0) {
            return TAMGA_VALIDATION_CODES[i].code;
        }
    }
    return TAMGA_VALIDATION_UNKNOWN;
}

const char *tamga_validation_code_name(TamgaValidationCode code) {
    size_t i;

    for (i = 0u; i < (sizeof(TAMGA_VALIDATION_CODES) / sizeof(TAMGA_VALIDATION_CODES[0])); i++) {
        if (TAMGA_VALIDATION_CODES[i].code == code) {
            return TAMGA_VALIDATION_CODES[i].name;
        }
    }
    return "UNKNOWN";
}

TamgaValidationCode tamga_response_validation_code_enum(const TamgaResponse *response) {
    return tamga_validation_code_parse(tamga_response_validation_code(response));
}

bool tamga_validation_code_is_overage(TamgaValidationCode code) {
    /*
     * "The licence is fine, this activation is one too many." These are the
     * outcomes where undoing the machine creation is the right response;
     * every other failure means the licence itself is not usable, and
     * deleting the machine would hide that.
     *
     * A table rather than a switch: this repository compiles with
     * -Wswitch-enum, which requires every one of the 25 values to be listed
     * even when 20 of them share an answer, and a 25-case switch obscures the
     * five that matter.
     */
    static const TamgaValidationCode overage[] = {
        TAMGA_VALIDATION_TOO_MANY_MACHINES,  TAMGA_VALIDATION_TOO_MANY_CORES,
        TAMGA_VALIDATION_TOO_MUCH_MEMORY,    TAMGA_VALIDATION_TOO_MUCH_DISK,
        TAMGA_VALIDATION_TOO_MANY_PROCESSES,
    };
    size_t i;

    for (i = 0u; i < (sizeof(overage) / sizeof(overage[0])); i++) {
        if (overage[i] == code) {
            return true;
        }
    }
    return false;
}

TamgaValidationCode tamga_validation_code_from_error(TamgaErrorCode code) {
    /*
     * The server reports the same over-limit condition two different ways
     * depending on the policy's overage strategy: as a creation-time 422 with
     * an `*_LIMIT_EXCEEDED` error code under a strict strategy, or as a
     * validation `meta.code` under ALLOW_ACCESS / ALLOW_1_25X_OVERAGE. This
     * folds the first vocabulary onto the second so a caller writes one
     * branch instead of two.
     *
     * A table for the same reason as above -- -Wswitch-enum would demand all
     * 37 error codes be listed to say something about five of them.
     */
    static const struct {
        TamgaErrorCode error;
        TamgaValidationCode validation;
    } LIMITS[] = {
        {TAMGA_ERR_MACHINE_LIMIT_EXCEEDED, TAMGA_VALIDATION_TOO_MANY_MACHINES},
        {TAMGA_ERR_CORE_LIMIT_EXCEEDED, TAMGA_VALIDATION_TOO_MANY_CORES},
        {TAMGA_ERR_MEMORY_LIMIT_EXCEEDED, TAMGA_VALIDATION_TOO_MUCH_MEMORY},
        {TAMGA_ERR_DISK_LIMIT_EXCEEDED, TAMGA_VALIDATION_TOO_MUCH_DISK},
        {TAMGA_ERR_TOO_MANY_PROCESSES, TAMGA_VALIDATION_TOO_MANY_PROCESSES},
    };
    size_t i;

    for (i = 0u; i < (sizeof(LIMITS) / sizeof(LIMITS[0])); i++) {
        if (LIMITS[i].error == code) {
            return LIMITS[i].validation;
        }
    }
    /* Including TAMGA_OK. "Not a limit" is never "valid" -- a caller that
     * read it that way would treat every non-limit failure as a pass. */
    return TAMGA_VALIDATION_UNKNOWN;
}
