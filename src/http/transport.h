/*
 * transport.h -- the seam between "what to send" and "how to send it".
 *
 * Everything above this line -- the endpoint methods, the retry policy, the
 * JSON:API error model, the request signing of headers -- is
 * transport-agnostic and always compiled. Everything below it is either an
 * operating-system component or something the caller supplies.
 *
 * That split is what lets the offline surface stay dependency-free while the
 * HTTP surface exists at all. TLS is the one thing this project will not
 * hand-roll, so the built-in backends are WinHTTP (a Windows OS component)
 * and libcurl (present in macOS's base system and on essentially every Linux
 * image). With TAMGA_HTTP=none neither is compiled and the library links
 * against libc alone; a caller can still register their own transport, which
 * is also the escape hatch for an application that already has an HTTP stack
 * it would rather use.
 */
#ifndef TAMGA_HTTP_TRANSPORT_H
#define TAMGA_HTTP_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga.h"
#include "tamga_compat.h"

/* Response headers are owned by the response and freed with it. */
typedef struct TamgaHttpHeader {
    char *name;
    char *value;
} TamgaHttpHeader;

/* Request headers are borrowed for the duration of the call. Separate from
 * the response type so a literal can be a header value without a const cast,
 * and so the transport cannot accidentally take ownership of one. */
typedef struct TamgaHttpRequestHeader {
    const char *name;
    const char *value;
} TamgaHttpRequestHeader;

typedef struct TamgaHttpRequest {
    const char *method;
    const char *url;
    const TamgaHttpRequestHeader *headers;
    size_t header_count;
    const char *body; /* NULL for a body-less request */
    size_t body_len;
    unsigned int timeout_ms;
} TamgaHttpRequest;

/*
 * Why `perform` returned false.
 *
 * Without this the client reports one TAMGA_ERR_TRANSPORT for everything,
 * and a caller cannot tell "retry in a moment" (a timeout) from "this will
 * never succeed" (a response above the size cap, which is a policy decision
 * of ours rather than a network fault) from "your process is out of memory".
 * Three situations, three different things for the caller to do.
 *
 * NETWORK is the zero value, so a transport that never sets this -- every
 * caller-supplied one -- keeps the previous behaviour.
 */
typedef enum TamgaTransportFailure {
    TAMGA_TRANSPORT_FAIL_NETWORK = 0,
    TAMGA_TRANSPORT_FAIL_OVERSIZED,
    TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY
} TamgaTransportFailure;

typedef struct TamgaHttpResponse {
    int status;
    char *body;
    size_t body_len;
    TamgaHttpHeader *headers;
    size_t header_count;
    size_t header_capacity;
    /* Meaningful only when perform() returned false. */
    TamgaTransportFailure failure;
} TamgaHttpResponse;

/*
 * A transport. `perform` returns false only when the request could not be
 * made at all -- a connection failure, a timeout, a TLS handshake that did
 * not complete. Any HTTP response, including 4xx and 5xx, is a success from
 * the transport's point of view and is reported through `response->status`;
 * interpreting it is the client's job, not the transport's.
 */
typedef struct TamgaHttpTransport {
    void *user_data;
    bool (*perform)(void *user_data, const TamgaHttpRequest *request, TamgaHttpResponse *response);
    void (*destroy)(void *user_data);
} TamgaHttpTransport;

void tamga_http_response_init(TamgaHttpResponse *response);
void tamga_http_response_free(TamgaHttpResponse *response);

/** Appends a response header, taking copies of both strings. */
TAMGA_NODISCARD bool tamga_http_response_add_header(TamgaHttpResponse *response, const char *name,
                                                    const char *value);

/**
 * Case-insensitive header lookup, as HTTP field names are case-insensitive
 * and no server is obliged to match the casing this library sends. Returns
 * NULL when absent; the pointer belongs to the response.
 */
const char *tamga_http_response_header(const TamgaHttpResponse *response, const char *name);

/*
 * Backend constructors. Declared here rather than forward-declared at the one
 * call site so that the definition and the declaration are visibly the same
 * thing -- otherwise each looks like a function that could have been static.
 * Each is compiled only when CMake selected that backend.
 */
#if defined(TAMGA_HTTP_CURL)
TAMGA_NODISCARD struct TamgaHttpTransport *tamga_http_transport_create_curl(void);
#endif
#if defined(TAMGA_HTTP_WINHTTP)
TAMGA_NODISCARD struct TamgaHttpTransport *tamga_http_transport_create_winhttp(void);
#endif

/**
 * Creates the transport this build was configured with, or NULL when built
 * with TAMGA_HTTP=none. The caller owns the result and releases it with
 * tamga_http_transport_destroy().
 */
TAMGA_NODISCARD TamgaHttpTransport *tamga_http_transport_create_default(void);

void tamga_http_transport_destroy(TamgaHttpTransport *transport);

/** True when this build has a built-in backend compiled in. */
bool tamga_http_have_default_transport(void);

#endif /* TAMGA_HTTP_TRANSPORT_H */
