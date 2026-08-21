/*
 * client.h -- request construction, authentication, retry policy and the
 * JSON:API error model.
 *
 * Everything here is transport-agnostic: it decides what to send and what a
 * response means, and hands the sending to whatever backend is registered.
 * That is why this file is compiled even in a TAMGA_HTTP=none build.
 */
#ifndef TAMGA_HTTP_CLIENT_H
#define TAMGA_HTTP_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "http/transport.h"
#include "tamga.h"
#include "tamga_compat.h"
#include "util/json.h"

/** The `Tamga-Version` sent unless overridden -- the server's own default. */
#define TAMGA_DEFAULT_API_VERSION "1.8"
/*
 * Deliberately longer than the server's own 30-second request deadline.
 * Matching it exactly means racing it, and the race is lost in the least
 * useful direction: the local timeout fires first, the caller sees a
 * transport failure rather than the server's 504, and the `x-request-id` that
 * response carries -- the one correlation id a slow-call support request
 * needs -- is never seen.
 */
#define TAMGA_DEFAULT_TIMEOUT_MS 45000u
/*
 * Three retries.
 *
 * Enough to ride out a short burst without turning a sustained 429 into a
 * call that hangs for minutes. The server's credential-accepting endpoints
 * run on a tight per-IP budget (5 req/s by default) that a heartbeat timer
 * plus a retry loop reaches easily -- which is exactly the case this exists
 * for.
 */
#define TAMGA_DEFAULT_MAX_RETRIES 3u

/* Authorization, Tamga-Version, Accept, Content-Type, Tamga-OTP. */
#define TAMGA_MAX_REQUEST_HEADERS 5u

struct TamgaClient {
    char *account_id;
    char *host;
    char *api_version;
    /*
     * "{scheme}://{host}", with no path. Every account-scoped route hangs off
     * `base_url`; `origin` exists for the two routes that do not live under
     * an account -- currently only GET /v1/health, which is registered on the
     * server outside the account router and bypasses both the auth and the
     * host-header middleware.
     */
    char *origin;
    char *base_url;
    unsigned int timeout_ms;
    unsigned int max_retries;

    TamgaAuthKind auth_kind;
    char *auth_primary;   /* token, licence key, or email */
    char *auth_secondary; /* password, for the email form */
    bool auth_configured;

    TamgaHttpTransport *transport;
    bool transport_is_default;
};

struct TamgaResponse {
    int status;
    char *body;
    size_t body_len;
    TamgaJson *json; /* NULL when the body was not JSON */
    TamgaHttpHeader *headers;
    size_t header_count;
    char *api_error_code;
};

/**
 * Sanitises a `Tamga-Version` value the way the server does: keep
 * alphanumerics plus '.' and '-', drop everything else, then truncate to 32
 * characters. Dropping rather than replacing matters -- it is what the server
 * does, and a header the two sides disagree about is worse than a rejected
 * one.
 */
TAMGA_NODISCARD char *tamga_sanitize_api_version(const char *version);

/**
 * Percent-encodes everything outside RFC 3986's unreserved set.
 *
 * Used for every query-string value built from caller input. Returns a string
 * released with tamga_string_free(), or NULL on allocation failure.
 */
TAMGA_NODISCARD char *tamga_url_encode(const char *value);

/**
 * Is a value safe to place in an HTTP header?
 *
 * Rejects CR, LF and NUL. A header value carrying CRLF is header injection:
 * the transports serialise headers as "name: value\r\n" into one block, and
 * an embedded CRLF appends attacker-chosen headers -- an overridden
 * Content-Length, a header a front-end proxy trusts, or a smuggled request.
 *
 * Applied to every header value built from caller input. The two auth forms
 * that were already safe are safe by construction, not by check: Basic is
 * base64, which has no CR or LF in its alphabet, and the query transport is
 * percent-encoded.
 */
bool tamga_header_value_is_safe(const char *value);

/**
 * Is this request safe to repeat after a 429?
 *
 * Every GET is. Among the POSTs, only the licensing actions: they are
 * effectively idempotent, and they are precisely the calls made on a timer,
 * so they are the ones that hit the rate limit in the first place. Creates
 * are excluded deliberately -- repeating POST /machines after a
 * timeout-shaped failure risks burning a second seat, and only the caller
 * knows whether that is acceptable.
 */
bool tamga_request_is_retryable(const char *method, const char *path);

/**
 * How long to wait before retry number `attempt` (zero-based).
 *
 * The server's Retry-After wins when present -- it knows when the bucket
 * refills, and guessing wastes the budget -- but is capped, so a hostile or
 * misconfigured proxy cannot park the caller for an hour. Otherwise
 * exponential backoff plus jitter, because a fleet that all retries on the
 * same schedule reconverges into the spike it was backing off from.
 */
unsigned int tamga_retry_delay_ms(unsigned int attempt, int64_t retry_after_seconds);

/**
 * Which prefix a path is resolved against.
 *
 * Every URL builder in this SDK family unconditionally prepended
 * `/v1/accounts/{account_id}`, which is why no SDK could reach `/v1/health` --
 * a server-side route that is deliberately public and deliberately outside
 * the account tree. The scope is an explicit argument rather than a second
 * send function so that the auth, header, retry and error handling below have
 * exactly one implementation.
 */
typedef enum TamgaPathScope {
    /** Relative to `{origin}/v1/accounts/{account_id}` -- almost everything. */
    TAMGA_PATH_ACCOUNT = 0,
    /** Relative to `{origin}` -- the path must therefore start with `/v1/`. */
    TAMGA_PATH_ORIGIN = 1
} TamgaPathScope;

/** Sends a request, applying auth, headers and the retry policy. */
TAMGA_NODISCARD TamgaErrorCode tamga_client_send(TamgaClient *client, const char *method,
                                                 const char *path, const char *query,
                                                 const char *body, const char *otp,
                                                 bool json_api_body, TamgaResponse **out_response);

/** As tamga_client_send(), but resolves `path` against `scope`. */
TAMGA_NODISCARD TamgaErrorCode tamga_client_send_scoped(TamgaClient *client, TamgaPathScope scope,
                                                        const char *method, const char *path,
                                                        const char *query, const char *body,
                                                        const char *otp, bool json_api_body,
                                                        TamgaResponse **out_response);

#endif /* TAMGA_HTTP_CLIENT_H */
