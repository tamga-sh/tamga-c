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

/* The body writer needs the response as well as the buffer, so it can record
 * why it aborted -- "the response was too large" and "the machine is out of
 * memory" are different answers for the caller, and both look like a generic
 * transport failure from libcurl's side. */
typedef struct TamgaCurlBodySink {
    TamgaBuf *buf;
    TamgaHttpResponse *response;
} TamgaCurlBodySink;

static size_t tamga_curl_write_body(char *data, size_t size, size_t count, void *user_data) {
    TamgaCurlBodySink *sink = (TamgaCurlBodySink *)user_data;
    TamgaBuf *buf = sink->buf;
    size_t total;

    if (!tamga_checked_mul(size, count, &total)) {
        sink->response->failure = TAMGA_TRANSPORT_FAIL_OVERSIZED;
        return 0u;
    }
    /* Refusing to grow past the input cap is what stops a hostile or
     * misconfigured server from turning a licence check into an
     * out-of-memory. Returning short tells libcurl to abort the transfer. */
    if ((buf->len + total) > TAMGA_MAX_REASONABLE_LEN) {
        sink->response->failure = TAMGA_TRANSPORT_FAIL_OVERSIZED;
        return 0u;
    }
    tamga_buf_append(buf, data, total);
    if (!tamga_buf_ok(buf)) {
        sink->response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
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

    /* Discarded on purpose. The only two failures are the 512-header cap
     * (a deliberate guard against a server streaming headers forever) and an
     * allocation failure; in both cases dropping the header and carrying on
     * beats failing the whole response over a header nothing may read. The
     * one visible consequence is that a dropped Retry-After silently costs
     * the server's requested delay and falls back to exponential backoff,
     * which is a degradation rather than a wrong answer. */
    {
        /* Assigned and then discarded rather than cast to (void): GCC does not
         * accept a cast as suppression for a warn_unused_result function, and
         * this discard really is deliberate -- see above. */
        bool dropped = !tamga_http_response_add_header(response, name, value);
        (void)dropped;
    }
    return total;
}

/*
 * Confines this handle to HTTP and HTTPS.
 *
 * libcurl speaks file:, scp:, ftp:, gopher: and more, and by default it will
 * attempt whatever scheme the URL names. Nothing in this SDK builds a URL from
 * a server-supplied value today -- tamga_client_compose_origin() prepends
 * https:// to anything that does not already begin http:// or https://, and
 * CURLOPT_FOLLOWLOCATION is 0 so no Location header can introduce one either --
 * so this restriction is currently belt and braces.
 *
 * It is here because both of those are one edit away from being untrue, and
 * the failure mode is severe and silent. MEASURED on libcurl 8.7.1 by driving
 * this transport at `file:///tmp/<a file>` with this option removed: the call
 * SUCCEEDED and returned the file's contents as `response->body`. With the
 * option set the same call fails outright, and an `http://` control still
 * succeeds -- so the refusal is this restriction and not a broken handle.
 *
 * That is a local-file read driven by a remote value, handed back as if it
 * were a response. A sibling SDK found its "is this an absolute URI" check
 * accepting `/relative/path` and `C:\x\y` as file: URIs, which is exactly
 * how a value gets from a server into a scheme nobody intended.
 *
 * Checked rather than discarded, like the three options above it and for the
 * same reason: a build where this silently did nothing would still send the
 * request, with no way for anything downstream to tell a confined handle from
 * an unconfined one.
 */
static bool tamga_curl_restrict_protocols(CURL *handle) {
#if defined(CURL_AT_LEAST_VERSION) && CURL_AT_LEAST_VERSION(7, 85, 0)
    /* CURLOPT_PROTOCOLS is deprecated from 7.85; the _STR form is the
     * replacement and takes a comma-separated list. */
    return curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "http,https") == CURLE_OK;
#else
    return curl_easy_setopt(handle, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS)) ==
           CURLE_OK;
#endif
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
    TamgaCurlBodySink sink;

    if (state == NULL || state->handle == NULL || request == NULL || response == NULL) {
        return false;
    }

    tamga_buf_init(&body);
    sink.buf = &body;
    sink.response = response;
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
            /* The only way this fails is allocation. Saying so keeps the
             * caller from retrying a request that memory, not the network,
             * prevented -- the same distinction the body writer makes. */
            response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
            goto done;
        }
        appended = curl_slist_append(headers, joined);
        tamga_string_free(joined);
        if (appended == NULL) {
            response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
            goto done;
        }
        headers = appended;
    }

    (void)curl_easy_setopt(state->handle, CURLOPT_URL, request->url);
    (void)curl_easy_setopt(state->handle, CURLOPT_HTTPHEADER, headers);
    (void)curl_easy_setopt(state->handle, CURLOPT_WRITEFUNCTION, tamga_curl_write_body);
    (void)curl_easy_setopt(state->handle, CURLOPT_WRITEDATA, &sink);
    (void)curl_easy_setopt(state->handle, CURLOPT_HEADERFUNCTION, tamga_curl_write_header);
    (void)curl_easy_setopt(state->handle, CURLOPT_HEADERDATA, response);
    (void)curl_easy_setopt(state->handle, CURLOPT_TIMEOUT_MS, (long)request->timeout_ms);
    (void)curl_easy_setopt(state->handle, CURLOPT_USERAGENT, "tamga-c/" TAMGA_VERSION_STRING);
    (void)curl_easy_setopt(state->handle, CURLOPT_NOSIGNAL, 1L);

    /*
     * Explicit rather than relying on the defaults: these two are the
     * difference between a verified connection and a decorative one.
     *
     * Redirects are not followed either. Every endpoint address is constructed
     * by this library from a configured host, so a redirect can only come from
     * someone who already controls the response -- and following one would
     * replay the Authorization header to wherever they pointed.
     *
     * Unlike every other option here, these three are checked. Discarding the
     * CURLcode would mean a build where one of them is unsupported still sends
     * the request, with no way for anything downstream to tell a verified
     * connection from an unverified one. The other setopt calls fail loudly on
     * their own -- a malformed request is rejected by curl_easy_perform -- so
     * only the silent-downgrade three need this.
     */
    if (curl_easy_setopt(state->handle, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(state->handle, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(state->handle, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        !tamga_curl_restrict_protocols(state->handle)) {
        goto done;
    }

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
    /* Terminated but length-authoritative: a body containing a NUL byte is
     * still a well-formed response, and reporting it as a transport failure
     * would be a much less useful answer than handing over the bytes. */
    response->body = tamga_buf_detach_terminated(&body, &response->body_len);
    if (response->body == NULL) {
        response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
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
