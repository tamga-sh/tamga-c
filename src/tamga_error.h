/*
 * tamga_error.h -- the per-thread last-error slot behind
 * tamga_last_error_message().
 *
 * Contract, unchanged from v1.x and relied on by every consumer:
 *
 *   - Every public entry point calls tamga_error_clear() on entry.
 *   - Every failing path calls tamga_error_set() before returning its code.
 *   - Therefore a TAMGA_OK return always implies tamga_last_error_message()
 *     returns NULL on that thread. No exceptions.
 *
 * The message buffer is a fixed-size thread-local, not an allocation. Two
 * reasons: the error path must not itself be able to fail on OOM, and the
 * "borrowed pointer, valid until the next tamga_* call on this thread"
 * ownership rule becomes trivially true rather than something the
 * implementation has to maintain.
 */
#ifndef TAMGA_ERROR_H
#define TAMGA_ERROR_H

#include "tamga.h"
#include "tamga_compat.h"

/* Longer messages are truncated with a trailing "..." rather than allocated
 * for. Nothing this library reports needs more; the detail that does not fit
 * belongs in the caller's own logging, not in a fixed diagnostic string. */
#define TAMGA_ERROR_MESSAGE_CAP 512

/** Clears the calling thread's last-error slot. */
void tamga_error_clear(void);

/**
 * Records `code` plus a formatted message on the calling thread and returns
 * `code`, so failing paths read:
 *
 *     return tamga_error_set(TAMGA_ERR_INVALID_PEM, "missing BEGIN marker");
 *
 * Never format secret material (licence keys, tokens, passwords) into the
 * message -- it is surfaced to callers, who routinely log it.
 */
TamgaErrorCode tamga_error_set(TamgaErrorCode code, const char *fmt, ...) TAMGA_PRINTF(2, 3);

#endif /* TAMGA_ERROR_H */
