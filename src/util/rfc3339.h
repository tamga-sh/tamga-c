/*
 * rfc3339.h -- RFC 3339 timestamp parsing and the current wall clock.
 *
 * The server serialises every timestamp (`created`, `updated`, `expiry`,
 * `ts`, ...) as RFC 3339. This parser converts one to Unix epoch seconds
 * using an explicit civil-date algorithm rather than timegm()/mktime(): the
 * portable variants of those either do not exist (timegm is not standard C)
 * or interpret the input in the local timezone (mktime), which would make an
 * expiry check silently wrong by hours depending on where the user sits.
 */
#ifndef TAMGA_UTIL_RFC3339_H
#define TAMGA_UTIL_RFC3339_H

#include <stdbool.h>
#include <stdint.h>

#include "tamga_compat.h"

/**
 * Parses `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)` into Unix epoch
 * seconds. 'T' and 'Z' may be lowercase. Fractional seconds are accepted and
 * truncated -- no field this SDK reads has sub-second significance.
 *
 * A leap second (`:60`) is accepted and clamped to :59, which is what every
 * other SDK in the fleet does; rejecting it would fail a legitimate server
 * timestamp twice a decade.
 *
 * Returns false on any malformed input, including out-of-range fields.
 */
TAMGA_NODISCARD bool tamga_rfc3339_parse(const char *str, int64_t *out_epoch_seconds);

/**
 * Current wall-clock time as Unix epoch seconds.
 *
 * A clock that cannot be read, or one set before the epoch, yields 0 -- which
 * fails every expiry check closed rather than open.
 */
int64_t tamga_time_now_unix(void);

#endif /* TAMGA_UTIL_RFC3339_H */
