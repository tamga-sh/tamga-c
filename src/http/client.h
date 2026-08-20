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
#define TAMGA_DEFAULT_TIMEOUT_MS 30000u
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

struct TamgaClient {
    char *account_id;
    char *host;
    char *api_version;
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

/** Sends a request, applying auth, headers and the retry policy. */
TAMGA_NODISCARD TamgaErrorCode tamga_client_send(TamgaClient *client, const char *method,
                                                 const char *path, const char *query,
                                                 const char *body, const char *otp,
                                                 bool json_api_body, TamgaResponse **out_response);

#endif /* TAMGA_HTTP_CLIENT_H */
