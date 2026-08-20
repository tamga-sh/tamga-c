/*
 * transport_winhttp.c -- the WinHTTP-backed transport, used on Windows.
 *
 * WinHTTP is an operating-system component: winhttp.dll ships with Windows
 * and winhttp.lib with the Windows SDK, so this backend adds no dependency a
 * consumer has to acquire.
 *
 * Certificate and hostname validation are left at WinHTTP's defaults, which
 * perform both. There is deliberately no option anywhere in this library to
 * relax them -- an SDK whose purpose is deciding whether software is licensed
 * has no business offering a switch that makes its answers forgeable by
 * anyone on the network. WINHTTP_OPTION_SECURITY_FLAGS is never set.
 *
 * This file is exercised only by the Windows CI job; it cannot be compiled on
 * the other platforms at all. Treat changes here as untested locally.
 */
#include <windows.h>
#include <winhttp.h>

#include <stdlib.h>
#include <string.h>

#include "http/transport.h"
#include "tamga_mem.h"
#include "util/buf.h"

typedef struct TamgaWinHttpState {
    HINTERNET session;
} TamgaWinHttpState;

/* UTF-8 to UTF-16, allocated. Returns NULL on failure or on an empty input,
 * which callers treat as failure -- no string this transport converts is
 * legitimately empty. */
static wchar_t *tamga_widen(const char *utf8) {
    int needed;
    wchar_t *wide;

    if (utf8 == NULL) {
        return NULL;
    }
    needed = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (needed <= 0) {
        return NULL;
    }
    wide = (wchar_t *)tamga_malloc((size_t)needed * sizeof(wchar_t));
    if (wide == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, needed) <= 0) {
        tamga_free(wide);
        return NULL;
    }
    return wide;
}

static char *tamga_narrow(const wchar_t *wide) {
    int needed;
    char *utf8;

    if (wide == NULL) {
        return NULL;
    }
    needed = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (needed <= 0) {
        return NULL;
    }
    utf8 = (char *)tamga_malloc((size_t)needed);
    if (utf8 == NULL) {
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, needed, NULL, NULL) <= 0) {
        tamga_free(utf8);
        return NULL;
    }
    return utf8;
}

/* Splits the raw response header block ("Name: value\r\n...") into the
 * response's header list. */
static void tamga_winhttp_parse_headers(const char *raw, TamgaHttpResponse *response) {
    const char *line = raw;

    while (line != NULL && *line != '\0') {
        const char *end = strstr(line, "\r\n");
        const char *colon;
        size_t line_len = (end != NULL) ? (size_t)(end - line) : strlen(line);

        colon = memchr(line, ':', line_len);
        if (colon != NULL && colon != line) {
            char name[128];
            char value[1024];
            size_t name_len = (size_t)(colon - line);
            const char *value_start = colon + 1;
            size_t value_len;

            while ((size_t)(value_start - line) < line_len &&
                   (*value_start == ' ' || *value_start == '\t')) {
                value_start++;
            }
            value_len = line_len - (size_t)(value_start - line);

            if (name_len < sizeof(name) && value_len < sizeof(value)) {
                memcpy(name, line, name_len);
                name[name_len] = '\0';
                memcpy(value, value_start, value_len);
                value[value_len] = '\0';
                /* Discarded on purpose. The only two failures are the 512-header cap
                 * (a deliberate guard against a server streaming headers forever) and an
                 * allocation failure; in both cases dropping the header and carrying on
                 * beats failing the whole response over a header nothing may read. The
                 * one visible consequence is that a dropped Retry-After silently costs
                 * the server's requested delay and falls back to exponential backoff,
                 * which is a degradation rather than a wrong answer. */
                (void)tamga_http_response_add_header(response, name, value);
            }
        }

        if (end == NULL) {
            break;
        }
        line = end + 2;
    }
}

static bool tamga_winhttp_perform(void *user_data, const TamgaHttpRequest *request,
                                  TamgaHttpResponse *response) {
    TamgaWinHttpState *state = (TamgaWinHttpState *)user_data;
    URL_COMPONENTS components;
    wchar_t host[256];
    wchar_t path[4096];
    wchar_t *url = NULL;
    wchar_t *method = NULL;
    wchar_t *headers = NULL;
    HINTERNET connection = NULL;
    HINTERNET handle = NULL;
    TamgaBuf header_buf;
    TamgaBuf body;
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    DWORD flags = 0;
    bool ok = false;
    size_t i;

    if (state == NULL || state->session == NULL || request == NULL || response == NULL) {
        return false;
    }

    tamga_buf_init(&header_buf);
    tamga_buf_init(&body);

    url = tamga_widen(request->url);
    method = tamga_widen(request->method);
    if (url == NULL || method == NULL) {
        response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
        goto done;
    }

    ZeroMemory(&components, sizeof(components));
    components.dwStructSize = sizeof(components);
    components.lpszHostName = host;
    components.dwHostNameLength = (DWORD)(sizeof(host) / sizeof(host[0]));
    components.lpszUrlPath = path;
    components.dwUrlPathLength = (DWORD)(sizeof(path) / sizeof(path[0]));
    if (!WinHttpCrackUrl(url, 0, 0, &components)) {
        goto done;
    }

    connection = WinHttpConnect(state->session, host, components.nPort, 0);
    if (connection == NULL) {
        goto done;
    }

    if (components.nScheme == INTERNET_SCHEME_HTTPS) {
        flags = WINHTTP_FLAG_SECURE;
    }
    /* No redirect following: every address here is built by this library from
     * a configured host, so a redirect can only come from someone who already
     * controls the response -- and following one would replay the
     * Authorization header wherever they pointed. */
    handle = WinHttpOpenRequest(connection, method, path, NULL, WINHTTP_NO_REFERER,
                                WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (handle == NULL) {
        goto done;
    }
    {
        /* WinHTTP follows redirects by default, so this call is the whole of
         * the protection the comment above describes. Discarding its result
         * would let a failure revert silently to the default -- checked for
         * that reason, unlike the timeouts below. */
        DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        if (!WinHttpSetOption(handle, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy,
                              sizeof(redirect_policy))) {
            goto done;
        }
    }
    (void)WinHttpSetTimeouts(handle, (int)request->timeout_ms, (int)request->timeout_ms,
                             (int)request->timeout_ms, (int)request->timeout_ms);

    for (i = 0u; i < request->header_count; i++) {
        tamga_buf_append_str(&header_buf, request->headers[i].name);
        tamga_buf_append_str(&header_buf, ": ");
        tamga_buf_append_str(&header_buf, request->headers[i].value);
        tamga_buf_append_str(&header_buf, "\r\n");
    }
    /* Every failure between here and the send is an allocation failure, not a
     * network one. Saying so keeps the caller from retrying a request that
     * memory, not the network, prevented -- the same distinction the body
     * reader below makes. */
    if (!tamga_buf_ok(&header_buf)) {
        response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
        goto done;
    }
    {
        char *joined = tamga_buf_detach_string(&header_buf, NULL);
        if (joined == NULL) {
            response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
            goto done;
        }
        headers = tamga_widen(joined);
        tamga_string_free(joined);
        if (headers == NULL) {
            response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
            goto done;
        }
    }

    if (!WinHttpSendRequest(handle, headers, (DWORD)-1,
                            (LPVOID)(request->body != NULL ? (void *)request->body : NULL),
                            (DWORD)request->body_len, (DWORD)request->body_len, 0)) {
        goto done;
    }
    if (!WinHttpReceiveResponse(handle, NULL)) {
        goto done;
    }

    if (!WinHttpQueryHeaders(handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                             WINHTTP_NO_HEADER_INDEX)) {
        goto done;
    }
    response->status = (int)status;

    {
        DWORD raw_size = 0;
        (void)WinHttpQueryHeaders(handle, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                  WINHTTP_HEADER_NAME_BY_INDEX, NULL, &raw_size,
                                  WINHTTP_NO_HEADER_INDEX);
        if (raw_size > 0u && raw_size < (64u * 1024u)) {
            wchar_t *raw = (wchar_t *)tamga_malloc(raw_size);
            if (raw != NULL) {
                if (WinHttpQueryHeaders(handle, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                        WINHTTP_HEADER_NAME_BY_INDEX, raw, &raw_size,
                                        WINHTTP_NO_HEADER_INDEX)) {
                    char *narrow = tamga_narrow(raw);
                    if (narrow != NULL) {
                        tamga_winhttp_parse_headers(narrow, response);
                        tamga_free(narrow);
                    }
                }
                tamga_free(raw);
            }
        }
    }

    for (;;) {
        DWORD available = 0;
        DWORD read = 0;
        char chunk[8192];

        if (!WinHttpQueryDataAvailable(handle, &available)) {
            goto done;
        }
        if (available == 0u) {
            break;
        }
        if (available > sizeof(chunk)) {
            available = (DWORD)sizeof(chunk);
        }
        if (!WinHttpReadData(handle, chunk, available, &read)) {
            goto done;
        }
        if (read == 0u) {
            break;
        }
        /* Bounded for the same reason as the curl backend: a hostile or
         * misconfigured server must not be able to turn a licence check into
         * an out-of-memory. */
        if ((body.len + (size_t)read) > TAMGA_MAX_REASONABLE_LEN) {
            response->failure = TAMGA_TRANSPORT_FAIL_OVERSIZED;
            goto done;
        }
        tamga_buf_append(&body, chunk, (size_t)read);
        if (!tamga_buf_ok(&body)) {
            response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
            goto done;
        }
    }

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
    if (handle != NULL) {
        (void)WinHttpCloseHandle(handle);
    }
    if (connection != NULL) {
        (void)WinHttpCloseHandle(connection);
    }
    tamga_free(url);
    tamga_free(method);
    tamga_free(headers);
    tamga_buf_free(&header_buf);
    tamga_buf_free(&body);
    return ok;
}

static void tamga_winhttp_destroy(void *user_data) {
    TamgaWinHttpState *state = (TamgaWinHttpState *)user_data;
    if (state == NULL) {
        return;
    }
    if (state->session != NULL) {
        (void)WinHttpCloseHandle(state->session);
    }
    tamga_free(state);
}

TamgaHttpTransport *tamga_http_transport_create_winhttp(void) {
    TamgaHttpTransport *transport;
    TamgaWinHttpState *state;

    state = (TamgaWinHttpState *)tamga_calloc(1u, sizeof(*state));
    if (state == NULL) {
        return NULL;
    }
    state->session = WinHttpOpen(L"tamga-c/" _CRT_WIDE(TAMGA_VERSION_STRING),
                                 WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                                 WINHTTP_NO_PROXY_BYPASS, 0);
    if (state->session == NULL) {
        tamga_free(state);
        return NULL;
    }

    transport = (TamgaHttpTransport *)tamga_calloc(1u, sizeof(*transport));
    if (transport == NULL) {
        (void)WinHttpCloseHandle(state->session);
        tamga_free(state);
        return NULL;
    }
    transport->user_data = state;
    transport->perform = tamga_winhttp_perform;
    transport->destroy = tamga_winhttp_destroy;
    return transport;
}
