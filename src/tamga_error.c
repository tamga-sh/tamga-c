#include "tamga_error.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * `has_error` is separate from "the buffer is empty" on purpose: a formatting
 * failure or a zero-length message must still count as an error, otherwise a
 * non-OK return could be paired with a NULL message and break the contract in
 * the direction that hides bugs.
 */
static TAMGA_THREAD_LOCAL char tamga_error_buf[TAMGA_ERROR_MESSAGE_CAP];
static TAMGA_THREAD_LOCAL bool tamga_error_present = false;

void tamga_error_clear(void) {
    tamga_error_present = false;
    tamga_error_buf[0] = '\0';
}

TamgaErrorCode tamga_error_set(TamgaErrorCode code, const char *fmt, ...) {
    va_list args;
    int written;

    /* Setting TAMGA_OK as an "error" would break the OK-implies-NULL
     * contract. Treat it as a clear instead of recording a message nobody
     * can ever legitimately observe. */
    if (code == TAMGA_OK) {
        tamga_error_clear();
        return TAMGA_OK;
    }

    tamga_error_present = true;

    if (fmt == NULL) {
        (void)snprintf(tamga_error_buf, sizeof(tamga_error_buf), "%s", tamga_error_name(code));
        return code;
    }

    va_start(args, fmt);
    written = vsnprintf(tamga_error_buf, sizeof(tamga_error_buf), fmt, args);
    va_end(args);

    if (written < 0) {
        (void)snprintf(tamga_error_buf, sizeof(tamga_error_buf), "%s", tamga_error_name(code));
    } else if ((size_t)written >= sizeof(tamga_error_buf)) {
        /* vsnprintf already NUL-terminated at the cap; mark the truncation so
         * a reader does not mistake a cut-off message for a complete one. */
        memcpy(&tamga_error_buf[sizeof(tamga_error_buf) - 4u], "...", 4u);
    }

    return code;
}

const char *tamga_last_error_message(void) {
    if (!tamga_error_present) {
        return NULL;
    }
    return tamga_error_buf;
}

const char *tamga_error_name(TamgaErrorCode code) {
    switch (code) {
    case TAMGA_OK:
        return "TAMGA_OK";
    case TAMGA_ERR_INVALID_PEM:
        return "TAMGA_ERR_INVALID_PEM";
    case TAMGA_ERR_INVALID_BASE64:
        return "TAMGA_ERR_INVALID_BASE64";
    case TAMGA_ERR_INVALID_JSON:
        return "TAMGA_ERR_INVALID_JSON";
    case TAMGA_ERR_SIGNATURE_INVALID:
        return "TAMGA_ERR_SIGNATURE_INVALID";
    case TAMGA_ERR_DECRYPTION_FAILED:
        return "TAMGA_ERR_DECRYPTION_FAILED";
    case TAMGA_ERR_UNSUPPORTED_SCHEME:
        return "TAMGA_ERR_UNSUPPORTED_SCHEME";
    case TAMGA_ERR_NULL_ARGUMENT:
        return "TAMGA_ERR_NULL_ARGUMENT";
    case TAMGA_ERR_PANIC:
        return "TAMGA_ERR_PANIC";
    case TAMGA_ERR_UNKNOWN:
        return "TAMGA_ERR_UNKNOWN";
    case TAMGA_ERR_LENGTH_INVALID:
        return "TAMGA_ERR_LENGTH_INVALID";
    case TAMGA_ERR_EXPIRED:
        return "TAMGA_ERR_EXPIRED";
    case TAMGA_ERR_OUT_OF_MEMORY:
        return "TAMGA_ERR_OUT_OF_MEMORY";
    case TAMGA_ERR_TRANSPORT:
        return "TAMGA_ERR_TRANSPORT";
    case TAMGA_ERR_NO_TRANSPORT:
        return "TAMGA_ERR_NO_TRANSPORT";
    case TAMGA_ERR_API:
        return "TAMGA_ERR_API";
    case TAMGA_ERR_RATE_LIMITED:
        return "TAMGA_ERR_RATE_LIMITED";
    case TAMGA_ERR_UNAUTHORIZED:
        return "TAMGA_ERR_UNAUTHORIZED";
    case TAMGA_ERR_FORBIDDEN:
        return "TAMGA_ERR_FORBIDDEN";
    case TAMGA_ERR_NOT_FOUND:
        return "TAMGA_ERR_NOT_FOUND";
    case TAMGA_ERR_SERVER:
        return "TAMGA_ERR_SERVER";
    case TAMGA_ERR_CHECK_IN_NOT_REQUIRED:
        return "TAMGA_ERR_CHECK_IN_NOT_REQUIRED";
    case TAMGA_ERR_LICENSE_NOT_ENCRYPTED:
        return "TAMGA_ERR_LICENSE_NOT_ENCRYPTED";
    case TAMGA_ERR_LICENSE_KEY_MISSING:
        return "TAMGA_ERR_LICENSE_KEY_MISSING";
    case TAMGA_ERR_TTL_INVALID:
        return "TAMGA_ERR_TTL_INVALID";
    case TAMGA_ERR_SCHEME_NOT_SUPPORTED:
        return "TAMGA_ERR_SCHEME_NOT_SUPPORTED";
    case TAMGA_ERR_FINGERPRINT_TAKEN:
        return "TAMGA_ERR_FINGERPRINT_TAKEN";
    case TAMGA_ERR_DATASET_INVALID:
        return "TAMGA_ERR_DATASET_INVALID";
    case TAMGA_ERR_PID_TAKEN:
        return "TAMGA_ERR_PID_TAKEN";
    case TAMGA_ERR_MACHINE_LIMIT_EXCEEDED:
        return "TAMGA_ERR_MACHINE_LIMIT_EXCEEDED";
    case TAMGA_ERR_CORE_LIMIT_EXCEEDED:
        return "TAMGA_ERR_CORE_LIMIT_EXCEEDED";
    case TAMGA_ERR_MEMORY_LIMIT_EXCEEDED:
        return "TAMGA_ERR_MEMORY_LIMIT_EXCEEDED";
    case TAMGA_ERR_DISK_LIMIT_EXCEEDED:
        return "TAMGA_ERR_DISK_LIMIT_EXCEEDED";
    case TAMGA_ERR_TOO_MANY_PROCESSES:
        return "TAMGA_ERR_TOO_MANY_PROCESSES";
    case TAMGA_ERR_LICENSE_SUSPENDED:
        return "TAMGA_ERR_LICENSE_SUSPENDED";
    case TAMGA_ERR_LICENSE_EXPIRED:
        return "TAMGA_ERR_LICENSE_EXPIRED";
    case TAMGA_ERR_LICENSE_NOT_ALLOWED:
        return "TAMGA_ERR_LICENSE_NOT_ALLOWED";
    default:
        return "TAMGA_ERR_UNKNOWN";
    }
}
