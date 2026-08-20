/*
 * transport_curl.c -- the libcurl-backed transport, used on macOS and Linux.
 *
 * libcurl is chosen over hand-rolling sockets for exactly one reason: TLS.
 * On macOS it is part of the base system; on Linux it is present on
 * essentially every non-minimal image. When it is absent the build falls back
 * to no built-in backend, and the caller supplies their own.
 *
 * Certificate verification is left at libcurl's defaults, which verify both
 * the chain and the hostname. There is deliberately no option anywhere in
 * this library to turn that off: an SDK whose whole purpose is deciding
 * whether software is licensed has no business offering a switch that makes
 * its answers forgeable by anyone on the network.
 */
#include <curl/curl.h>
#include <string.h>

#include "http/transport.h"
#include "tamga_mem.h"
#include "util/buf.h"

typedef struct TamgaCurlState {
    CURL *handle;
} TamgaCurlState;

static size_t tamga_curl_write_body(char *data, size_t size, size_t count, void *user_data) {
    TamgaBuf *buf = (TamgaBuf *)user_data;
    size_t total;

    if (!tamga_checked_mul(size, count, &total)) {
        return 0u;
    }
    /* Refusing to grow past the input cap is what stops a hostile or
     * misconfigured server from turning a licence check into an
     * out-of-memory. Returning short tells libcurl to abort the transfer. */
    if ((buf->len + total) > TAMGA_MAX_REASONABLE_LEN) {
        return 0u;
    }
    tamga_buf_append(buf, data, total);
    if (!tamga_buf_ok(buf)) {
        return 0u;
    }
    return total;
}

static size_t tamga_curl_write_header(char *data, size_t size, size_t count, void *user_data) {
    TamgaHttpResponse *response = (TamgaHttpResponse *)user_data;
    size_t total;
    size_t i;
    size_t colon = (size_t)-1;
    size_t value_start;
    size_t value_end;
    char name[128];
    char value[1024];

    if (!tamga_checked_mul(size, count, &total)) {
        return 0u;
    }
    for (i = 0u; i < total; i++) {
        if (data[i] == ':') {
            colon = i;
            break;
        }
    }
    /* The status line and the blank terminator have no colon; skipping them
     * is not an error. */
    if (colon == (size_t)-1 || colon == 0u || colon >= sizeof(name)) {
        return total;
    }

    memcpy(name, data, colon);
    name[colon] = '\0';

    value_start = colon + 1u;
    while (value_start < total && (data[value_start] == ' ' || data[value_start] == '\t')) {
        value_start++;
    }
    value_end = total;
    while (value_end > value_start &&
           (data[value_end - 1u] == '\r' || data[value_end - 1u] == '\n' ||
            data[value_end - 1u] == ' ' || data[value_end - 1u] == '\t')) {
        value_end--;
    }
    if ((value_end - value_start) >= sizeof(value)) {
        return total; /* absurdly long header value: ignored, not fatal */
    }
    memcpy(value, &data[value_start], value_end - value_start);
    value[value_end - value_start] = '\0';

    (void)tamga_http_response_add_header(response, name, value);
    return total;
}

static bool tamga_curl_perform(void *user_data, const TamgaHttpRequest *request,
                               TamgaHttpResponse *response) {
    TamgaCurlState *state = (TamgaCurlState *)user_data;
    struct curl_slist *headers = NULL;
    TamgaBuf body;
    CURLcode result;
    long status = 0;
    size_t i;
    bool ok = false;

    if (state == NULL || state->handle == NULL || request == NULL || response == NULL) {
        return false;
    }

    tamga_buf_init(&body);
    curl_easy_reset(state->handle);

    for (i = 0u; i < request->header_count; i++) {
        TamgaBuf line;
        char *joined;
        struct curl_slist *appended;

        tamga_buf_init(&line);
        tamga_buf_append_str(&line, request->headers[i].name);
        tamga_buf_append_str(&line, ": ");
        tamga_buf_append_str(&line, request->headers[i].value);
        joined = tamga_buf_detach_string(&line, NULL);
        tamga_buf_free(&line);
        if (joined == NULL) {
            goto done;
        }
        appended = curl_slist_append(headers, joined);
        tamga_string_free(joined);
        if (appended == NULL) {
            goto done;
        }
        headers = appended;
    }

    (void)curl_easy_setopt(state->handle, CURLOPT_URL, request->url);
    (void)curl_easy_setopt(state->handle, CURLOPT_HTTPHEADER, headers);
    (void)curl_easy_setopt(state->handle, CURLOPT_WRITEFUNCTION, tamga_curl_write_body);
    (void)curl_easy_setopt(state->handle, CURLOPT_WRITEDATA, &body);
    (void)curl_easy_setopt(state->handle, CURLOPT_HEADERFUNCTION, tamga_curl_write_header);
    (void)curl_easy_setopt(state->handle, CURLOPT_HEADERDATA, response);
    (void)curl_easy_setopt(state->handle, CURLOPT_TIMEOUT_MS, (long)request->timeout_ms);
    (void)curl_easy_setopt(state->handle, CURLOPT_USERAGENT, "tamga-c/" TAMGA_VERSION_STRING);
    (void)curl_easy_setopt(state->handle, CURLOPT_NOSIGNAL, 1L);

    /* Explicit rather than relying on the defaults: these two are the
     * difference between a verified connection and a decorative one, and
     * making them visible here is how a reviewer confirms they are on. */
    (void)curl_easy_setopt(state->handle, CURLOPT_SSL_VERIFYPEER, 1L);
    (void)curl_easy_setopt(state->handle, CURLOPT_SSL_VERIFYHOST, 2L);

    /* Redirects are not followed. Every endpoint address is constructed by
     * this library from a configured host, so a redirect can only come from
     * someone who already controls the response -- and following one would
     * replay the Authorization header to wherever they pointed. */
    (void)curl_easy_setopt(state->handle, CURLOPT_FOLLOWLOCATION, 0L);

    if (strcmp(request->method, "GET") == 0) {
        (void)curl_easy_setopt(state->handle, CURLOPT_HTTPGET, 1L);
    } else {
        (void)curl_easy_setopt(state->handle, CURLOPT_CUSTOMREQUEST, request->method);
        if (request->body != NULL) {
            (void)curl_easy_setopt(state->handle, CURLOPT_POSTFIELDS, request->body);
            (void)curl_easy_setopt(state->handle, CURLOPT_POSTFIELDSIZE, (long)request->body_len);
        } else {
            (void)curl_easy_setopt(state->handle, CURLOPT_POSTFIELDSIZE, 0L);
            (void)curl_easy_setopt(state->handle, CURLOPT_POSTFIELDS, "");
        }
    }

    result = curl_easy_perform(state->handle);
    if (result != CURLE_OK) {
        goto done;
    }
    (void)curl_easy_getinfo(state->handle, CURLINFO_RESPONSE_CODE, &status);

    response->status = (int)status;
    response->body = tamga_buf_detach_string(&body, &response->body_len);
    if (response->body == NULL) {
        goto done;
    }
    ok = true;

done:
    curl_slist_free_all(headers);
    tamga_buf_free(&body);
    return ok;
}

static void tamga_curl_destroy(void *user_data) {
    TamgaCurlState *state = (TamgaCurlState *)user_data;
    if (state == NULL) {
        return;
    }
    if (state->handle != NULL) {
        curl_easy_cleanup(state->handle);
    }
    tamga_free(state);
}

TamgaHttpTransport *tamga_http_transport_create_curl(void) {
    TamgaHttpTransport *transport;
    TamgaCurlState *state;

    state = (TamgaCurlState *)tamga_calloc(1u, sizeof(*state));
    if (state == NULL) {
        return NULL;
    }
    state->handle = curl_easy_init();
    if (state->handle == NULL) {
        tamga_free(state);
        return NULL;
    }

    transport = (TamgaHttpTransport *)tamga_calloc(1u, sizeof(*transport));
    if (transport == NULL) {
        curl_easy_cleanup(state->handle);
        tamga_free(state);
        return NULL;
    }
    transport->user_data = state;
    transport->perform = tamga_curl_perform;
    transport->destroy = tamga_curl_destroy;
    return transport;
}
