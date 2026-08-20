/*
 * A recording transport for the HTTP tests.
 *
 * Captures every request it is handed and replies from a scripted queue, so a
 * test can assert on exactly what would have gone over the wire and drive the
 * client through response sequences -- a 429 followed by a 200, say -- that
 * would be impractical to arrange against a real server.
 */
#ifndef TAMGA_TEST_MOCK_TRANSPORT_H
#define TAMGA_TEST_MOCK_TRANSPORT_H

#include <stdio.h>
#include <string.h>

#include "tamga.h"

/* Not every test file uses every helper, and an unused static function is a
 * hard error under this repository's warning settings. */
#if defined(__GNUC__) || defined(__clang__)
#define MOCK_MAYBE_UNUSED __attribute__((unused))
#else
#define MOCK_MAYBE_UNUSED
#endif

#define MOCK_MAX_CALLS 8
#define MOCK_MAX_HEADERS 8
#define MOCK_BUF 4096

typedef struct MockCall {
    char method[16];
    char url[MOCK_BUF];
    char body[MOCK_BUF];
    char header_names[MOCK_MAX_HEADERS][64];
    char header_values[MOCK_MAX_HEADERS][512];
    size_t header_count;
    unsigned int timeout_ms;
} MockCall;

typedef struct MockReply {
    int status;
    const char *body;
    const char *header_name;
    const char *header_value;
} MockReply;

typedef struct MockTransport {
    MockCall calls[MOCK_MAX_CALLS];
    size_t call_count;
    MockReply replies[MOCK_MAX_CALLS];
    size_t reply_count;
    bool fail_transport;
} MockTransport;

MOCK_MAYBE_UNUSED static void mock_reset(MockTransport *mock) {
    memset(mock, 0, sizeof(*mock));
}

MOCK_MAYBE_UNUSED static void mock_reply(MockTransport *mock, int status, const char *body) {
    if (mock->reply_count < MOCK_MAX_CALLS) {
        mock->replies[mock->reply_count].status = status;
        mock->replies[mock->reply_count].body = body;
        mock->reply_count++;
    }
}

MOCK_MAYBE_UNUSED static void mock_reply_with_header(MockTransport *mock, int status,
                                                     const char *body, const char *name,
                                                     const char *value) {
    mock_reply(mock, status, body);
    mock->replies[mock->reply_count - 1u].header_name = name;
    mock->replies[mock->reply_count - 1u].header_value = value;
}

MOCK_MAYBE_UNUSED static bool mock_perform(void *user_data, const char *method, const char *url,
                                           const char *const *header_names,
                                           const char *const *header_values, uintptr_t header_count,
                                           const char *body, uintptr_t body_len,
                                           unsigned int timeout_ms, TamgaHttpResult *result) {
    MockTransport *mock = (MockTransport *)user_data;
    MockCall *call;
    const MockReply *reply;
    size_t i;

    if (mock->fail_transport) {
        return false;
    }
    if (mock->call_count >= MOCK_MAX_CALLS) {
        return false;
    }
    call = &mock->calls[mock->call_count];
    mock->call_count++;

    (void)snprintf(call->method, sizeof(call->method), "%s", method);
    (void)snprintf(call->url, sizeof(call->url), "%s", url);
    if (body != NULL && (size_t)body_len < sizeof(call->body)) {
        memcpy(call->body, body, (size_t)body_len);
        call->body[(size_t)body_len] = '\0';
    }
    call->timeout_ms = timeout_ms;
    call->header_count =
        ((size_t)header_count < MOCK_MAX_HEADERS) ? (size_t)header_count : MOCK_MAX_HEADERS;
    for (i = 0u; i < call->header_count; i++) {
        (void)snprintf(call->header_names[i], sizeof(call->header_names[i]), "%s", header_names[i]);
        (void)snprintf(call->header_values[i], sizeof(call->header_values[i]), "%s",
                       header_values[i]);
    }

    /* Replies are consumed in order; the last one repeats, so a test only has
     * to script the interesting prefix. */
    if (mock->reply_count == 0u) {
        tamga_http_result_set_status(result, 200);
        (void)tamga_http_result_set_body(result, "{}", 2u);
        return true;
    }
    reply = &mock->replies[(mock->call_count - 1u < mock->reply_count) ? (mock->call_count - 1u)
                                                                       : (mock->reply_count - 1u)];
    tamga_http_result_set_status(result, reply->status);
    if (reply->body != NULL) {
        (void)tamga_http_result_set_body(result, reply->body, (uintptr_t)strlen(reply->body));
    } else {
        (void)tamga_http_result_set_body(result, "", 0u);
    }
    if (reply->header_name != NULL) {
        (void)tamga_http_result_add_header(result, reply->header_name, reply->header_value);
    }
    return true;
}

/* The header value the last call sent under `name`, or NULL. */
MOCK_MAYBE_UNUSED static const char *mock_last_header(const MockTransport *mock, const char *name) {
    const MockCall *call;
    size_t i;

    if (mock->call_count == 0u) {
        return NULL;
    }
    call = &mock->calls[mock->call_count - 1u];
    for (i = 0u; i < call->header_count; i++) {
        if (strcmp(call->header_names[i], name) == 0) {
            return call->header_values[i];
        }
    }
    return NULL;
}

#endif /* TAMGA_TEST_MOCK_TRANSPORT_H */
