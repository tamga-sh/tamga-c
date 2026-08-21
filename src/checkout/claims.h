/*
 * claims.h -- the `meta` object inside an offline file's SIGNED payload.
 *
 * Both offline formats carry it, and both wrap it the same way:
 *
 *     { "data": <resource>, "meta": { "iat", "exp", "jti", "kid" } }
 *
 * It sits inside the signed bytes on purpose. In format v1 the ttl and expiry
 * a caller asked for lived in the JSON envelope *around* the certificate,
 * outside the signature -- so a 24-hour file was cryptographically valid
 * forever, because the client holds the file and can edit anything the
 * signature does not cover.
 *
 * Shared between license_file.c and machine_file.c so the skew tolerance and
 * the "an absent exp means no expiry" rule are one decision rather than two.
 * Two copies that drift hand one of the two file types a different grace
 * period, silently.
 */
#ifndef TAMGA_CHECKOUT_CLAIMS_H
#define TAMGA_CHECKOUT_CLAIMS_H

#include <stdbool.h>
#include <stdint.h>

#include "tamga.h"
#include "tamga_compat.h"
#include "util/json.h"

/*
 * How much clock skew to tolerate on the expiry check.
 *
 * Deliberately small. The client's clock is under the adversary's control in
 * this threat model, so a generous allowance is simply a free extension on
 * every expired file. Sixty seconds covers ordinary NTP drift and nothing
 * more.
 */
#define TAMGA_CLOCK_SKEW_TOLERANCE_SECONDS 60

/** The claims carried inside the signed payload. */
typedef struct TamgaFileClaims {
    int64_t issued_at;
    bool has_expiry;
    int64_t expiry;
} TamgaFileClaims;

/**
 * Reads the `meta` object of a signed payload.
 *
 * A missing or non-object `meta` is an error: every v2 file has one, and
 * treating its absence as "no claims" would accept a payload that had simply
 * had them stripped.
 *
 * An absent or explicitly null `exp` is NOT an error -- a checkout requested
 * without a ttl produces a file that genuinely never expires.
 */
TAMGA_NODISCARD TamgaErrorCode tamga_claims_read(const TamgaJson *meta, TamgaFileClaims *out);

/**
 * Whether `now_unix` is past the signed expiry, allowing for clock skew.
 *
 * A file with no expiry is never expired. The signature proves a file is
 * authentic; only this proves it is still valid, and skipping it is exactly
 * what made v1 files permanent.
 */
TAMGA_NODISCARD bool tamga_claims_are_expired(const TamgaFileClaims *claims, int64_t now_unix);

#endif /* TAMGA_CHECKOUT_CLAIMS_H */
