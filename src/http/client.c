#include "http/client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>
#include <unistd.h>
#endif

#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"
#include "util/buf.h"

/* --- small platform helpers --------------------------------------------- */

static void tamga_sleep_ms(unsigned int milliseconds) {
#if defined(_WIN32)
    Sleep((DWORD)milliseconds);
#else
    struct timespec request;
    request.tv_sec = (time_t)(milliseconds / 1000u);
    request.tv_nsec = (long)((milliseconds % 1000u) * 1000000u);
    (void)nanosleep(&request, NULL);
#endif
}

static unsigned long tamga_process_id(void) {
#if defined(_WIN32)
    return (unsigned long)GetCurrentProcessId();
#else
    return (unsigned long)getpid();
#endif
}

/* --- headers and versions ------------------------------------------------ */

char *tamga_sanitize_api_version(const char *version) {
    TamgaBuf buf;
    size_t i;
    size_t kept = 0u;

    if (version == NULL) {
        return NULL;
    }
    tamga_buf_init(&buf);
    for (i = 0u; version[i] != '\0' && kept < 32u; i++) {
        char c = version[i];
        bool allowed = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       c == '.' || c == '-';
        if (allowed) {
            tamga_buf_append_byte(&buf, (unsigned char)c);
            kept++;
        }
    }
    {
        char *result = tamga_buf_detach_string(&buf, NULL);
        tamga_buf_free(&buf);
        return result;
    }
}

bool tamga_header_value_is_safe(const char *value) {
    size_t i;

    if (value == NULL) {
        return false;
    }
    for (i = 0u; value[i] != '\0'; i++) {
        if (value[i] == '\r' || value[i] == '\n') {
            return false;
        }
    }
    return true;
}

bool tamga_request_is_retryable(const char *method, const char *path) {
    static const char *const retryable_suffixes[] = {
        "/actions/validate",  "/actions/validate-key", "/actions/check-in",
        "/actions/check-out", "/actions/ping",
    };
    size_t i;
    size_t path_len;

    if (method == NULL || path == NULL) {
        return false;
    }
    if (strcmp(method, "GET") == 0) {
        return true;
    }
    if (strcmp(method, "POST") != 0) {
        return false;
    }

    path_len = strlen(path);
    for (i = 0u; i < (sizeof(retryable_suffixes) / sizeof(retryable_suffixes[0])); i++) {
        size_t suffix_len = strlen(retryable_suffixes[i]);
        if (path_len >= suffix_len &&
            strcmp(&path[path_len - suffix_len], retryable_suffixes[i]) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Deterministic per-process jitter, 0-999 ms.
 *
 * Derived from the process id and the attempt number rather than from an RNG:
 * different processes get different offsets, which is the property that
 * matters, while one process stays predictable enough to reason about in a
 * log. It also keeps the library free of a random-number dependency it needs
 * for nothing else.
 */
static unsigned int tamga_retry_jitter_ms(unsigned int attempt) {
    uint64_t seed = (uint64_t)tamga_process_id() * 2654435761ull;
    seed += (uint64_t)attempt * 40503ull;
    return (unsigned int)(seed % 1000ull);
}

unsigned int tamga_retry_delay_ms(unsigned int attempt, int64_t retry_after_seconds) {
    unsigned int base;

    if (retry_after_seconds > 0) {
        if (retry_after_seconds > 60) {
            retry_after_seconds = 60;
        }
        return (unsigned int)(retry_after_seconds * 1000);
    }
    /* 1, 2, 4, 8, 16, 32 seconds, then flat. */
    base = 1u << ((attempt > 5u) ? 5u : attempt);
    return (base * 1000u) + tamga_retry_jitter_ms(attempt);
}

/* --- response ------------------------------------------------------------ */

static void tamga_response_release(TamgaResponse *response) {
    size_t i;

    if (response == NULL) {
        return;
    }
    tamga_secure_free(response->body, response->body_len);
    tamga_json_free(response->json);
    for (i = 0u; i < response->header_count; i++) {
        tamga_free(response->headers[i].name);
        tamga_free(response->headers[i].value);
    }
    tamga_free(response->headers);
    tamga_string_free(response->api_error_code);
    tamga_secure_free(response, sizeof(*response));
}

void tamga_response_free(TamgaResponse *response) {
    tamga_response_release(response);
}

int tamga_response_status(const TamgaResponse *response) {
    return (response == NULL) ? 0 : response->status;
}

const char *tamga_response_json(const TamgaResponse *response, uintptr_t *out_len) {
    if (response == NULL) {
        return NULL;
    }
    if (out_len != NULL) {
        *out_len = (uintptr_t)response->body_len;
    }
    return response->body;
}

const char *tamga_response_header(const TamgaResponse *response, const char *name) {
    size_t i;
    if (response == NULL || name == NULL) {
        return NULL;
    }
    for (i = 0u; i < response->header_count; i++) {
        const char *candidate = response->headers[i].name;
        size_t j = 0u;
        bool equal = true;
        while (candidate[j] != '\0' && name[j] != '\0') {
            char a = candidate[j];
            char b = name[j];
            if (a >= 'A' && a <= 'Z') {
                a = (char)(a + ('a' - 'A'));
            }
            if (b >= 'A' && b <= 'Z') {
                b = (char)(b + ('a' - 'A'));
            }
            if (a != b) {
                equal = false;
                break;
            }
            j++;
        }
        if (equal && candidate[j] == '\0' && name[j] == '\0') {
            return response->headers[i].value;
        }
    }
    return NULL;
}

const char *tamga_response_error_code(const TamgaResponse *response) {
    return (response == NULL) ? NULL : response->api_error_code;
}

/* Reaches into meta.<field> on a validation response. */
static const TamgaJson *tamga_response_meta_field(const TamgaResponse *response,
                                                  const char *field) {
    const TamgaJson *meta;

    if (response == NULL || response->json == NULL) {
        return NULL;
    }
    /* Quick-validate returns the flat body with no data envelope, so the
     * fields live at the top level; the other two nest them under meta. */
    meta = tamga_json_object_get(response->json, "meta");
    if (meta == NULL) {
        meta = response->json;
    }
    return tamga_json_object_get(meta, field);
}

bool tamga_response_validation_is_valid(const TamgaResponse *response) {
    return tamga_json_bool_or(tamga_response_meta_field(response, "valid"), false);
}

const char *tamga_response_validation_code(const TamgaResponse *response) {
    return tamga_json_as_string(tamga_response_meta_field(response, "code"), NULL);
}

const char *tamga_response_validation_detail(const TamgaResponse *response) {
    return tamga_json_as_string(tamga_response_meta_field(response, "detail"), NULL);
}

/* --- request construction ------------------------------------------------ */

static bool tamga_client_auth_header(const TamgaClient *client, char **out_name, char **out_value) {
    TamgaBuf buf;
    char *encoded = NULL;
    char *pair = NULL;

    *out_name = NULL;
    *out_value = NULL;

    switch (client->auth_kind) {
    case TAMGA_AUTH_BEARER:
        tamga_buf_init(&buf);
        tamga_buf_append_str(&buf, "Bearer ");
        tamga_buf_append_str(&buf, client->auth_primary);
        *out_value = tamga_buf_detach_string(&buf, NULL);
        tamga_buf_free(&buf);
        break;
    case TAMGA_AUTH_LICENSE:
        tamga_buf_init(&buf);
        tamga_buf_append_str(&buf, "License ");
        tamga_buf_append_str(&buf, client->auth_primary);
        *out_value = tamga_buf_detach_string(&buf, NULL);
        tamga_buf_free(&buf);
        break;
    case TAMGA_AUTH_BASIC_EMAIL_PASSWORD:
    case TAMGA_AUTH_BASIC_TOKEN:
    case TAMGA_AUTH_BASIC_LICENSE:
        tamga_buf_init(&buf);
        if (client->auth_kind == TAMGA_AUTH_BASIC_EMAIL_PASSWORD) {
            tamga_buf_append_str(&buf, client->auth_primary);
            tamga_buf_append_byte(&buf, ':');
            tamga_buf_append_str(&buf, client->auth_secondary);
        } else if (client->auth_kind == TAMGA_AUTH_BASIC_TOKEN) {
            /* The token as the username with an empty password. */
            tamga_buf_append_str(&buf, client->auth_primary);
            tamga_buf_append_byte(&buf, ':');
        } else {
            tamga_buf_append_str(&buf, "license:");
            tamga_buf_append_str(&buf, client->auth_primary);
        }
        pair = tamga_buf_detach_string(&buf, NULL);
        tamga_buf_free(&buf);
        if (pair == NULL) {
            return false;
        }
        encoded = tamga_base64_encode_alloc((const unsigned char *)pair, strlen(pair));
        tamga_string_free(pair);
        if (encoded == NULL) {
            return false;
        }
        tamga_buf_init(&buf);
        tamga_buf_append_str(&buf, "Basic ");
        tamga_buf_append_str(&buf, encoded);
        /* base64 of "email:password" or "license:<key>" is a reversible
         * encoding of the credential, not a digest of it -- erased, not just
         * released, like every other copy of it. */
        tamga_string_free(encoded);
        *out_value = tamga_buf_detach_string(&buf, NULL);
        tamga_buf_free(&buf);
        break;
    case TAMGA_AUTH_QUERY_TOKEN:
        /* Carried in the URL instead of a header. */
        return true;
    default:
        return false;
    }

    if (*out_value == NULL) {
        return false;
    }
    *out_name = tamga_strdup("Authorization");
    if (*out_name == NULL) {
        tamga_string_free(*out_value);
        *out_value = NULL;
        return false;
    }
    return true;
}

/* Percent-encodes everything outside the unreserved set, so a token or a
 * licence key carried in the query string cannot inject a parameter. */
static char *tamga_url_encode(const char *value) {
    static const char hex[] = "0123456789ABCDEF";
    TamgaBuf buf;
    size_t i;
    char *result;

    if (value == NULL) {
        return NULL;
    }
    tamga_buf_init(&buf);
    for (i = 0u; value[i] != '\0'; i++) {
        unsigned char c = (unsigned char)value[i];
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            tamga_buf_append_byte(&buf, c);
        } else {
            tamga_buf_append_byte(&buf, '%');
            tamga_buf_append_byte(&buf, (unsigned char)hex[(c >> 4) & 0x0Fu]);
            tamga_buf_append_byte(&buf, (unsigned char)hex[c & 0x0Fu]);
        }
    }
    result = tamga_buf_detach_string(&buf, NULL);
    tamga_buf_free(&buf);
    return result;
}

static char *tamga_client_build_url(const TamgaClient *client, const char *path,
                                    const char *query) {
    TamgaBuf buf;
    bool has_query = false;
    char *url;

    tamga_buf_init(&buf);
    tamga_buf_append_str(&buf, client->base_url);
    tamga_buf_append_str(&buf, path);

    if (query != NULL && query[0] != '\0') {
        tamga_buf_append_byte(&buf, '?');
        tamga_buf_append_str(&buf, query);
        has_query = true;
    }
    if (client->auth_kind == TAMGA_AUTH_QUERY_TOKEN && client->auth_configured) {
        char *encoded = tamga_url_encode(client->auth_primary);
        if (encoded == NULL) {
            tamga_buf_free(&buf);
            return NULL;
        }
        tamga_buf_append_byte(&buf, has_query ? '&' : '?');
        tamga_buf_append_str(&buf, "token=");
        tamga_buf_append_str(&buf, encoded);
        tamga_string_free(encoded);
    }

    url = tamga_buf_detach_string(&buf, NULL);
    tamga_buf_free(&buf);
    return url;
}

/*
 * Turns a JSON:API error document into a code. The server's shape is
 * {"errors":[{id,status,code,title,detail,source}]}; anything else -- an
 * empty array, a non-JSON body from a proxy -- still has to produce a usable
 * outcome rather than a parse failure the caller cannot act on.
 */
static TamgaErrorCode tamga_map_api_error(TamgaResponse *response) {
    const TamgaJson *errors;
    const TamgaJson *first;
    const char *code = NULL;

    if (response->json != NULL) {
        errors = tamga_json_object_get(response->json, "errors");
        first = tamga_json_array_at(errors, 0u);
        code = tamga_json_as_string(tamga_json_object_get(first, "code"), NULL);
    }
    if (code != NULL) {
        /* Diagnostic only, and deliberately not checked: `status` above was
         * already derived from `code`, so a failed copy costs the caller the
         * raw string in tamga_response_error_code() and nothing else. The
         * alternative -- failing the whole call because a diagnostic could
         * not be copied -- would be worse on the one path where this can
         * happen, which is an already-failing response under memory
         * pressure. */
        response->api_error_code = tamga_strdup(code);
    }

    if (response->status == 429) {
        return TAMGA_ERR_RATE_LIMITED;
    }
    if (code != NULL) {
        if (strcmp(code, "CHECK_IN_NOT_REQUIRED") == 0) {
            return TAMGA_ERR_CHECK_IN_NOT_REQUIRED;
        }
        if (strcmp(code, "LICENSE_NOT_ENCRYPTED") == 0) {
            return TAMGA_ERR_LICENSE_NOT_ENCRYPTED;
        }
        if (strcmp(code, "LICENSE_KEY_MISSING") == 0) {
            return TAMGA_ERR_LICENSE_KEY_MISSING;
        }
        if (strcmp(code, "TTL_INVALID") == 0) {
            return TAMGA_ERR_TTL_INVALID;
        }
        if (strcmp(code, "SCHEME_NOT_SUPPORTED") == 0) {
            return TAMGA_ERR_SCHEME_NOT_SUPPORTED;
        }
        if (strcmp(code, "FINGERPRINT_TAKEN") == 0) {
            return TAMGA_ERR_FINGERPRINT_TAKEN;
        }
        if (strcmp(code, "DATASET_INVALID") == 0) {
            return TAMGA_ERR_DATASET_INVALID;
        }
        if (strcmp(code, "PID_TAKEN") == 0) {
            return TAMGA_ERR_PID_TAKEN;
        }
    }

    /* Falling back on the status keeps 401 and 403 distinct: a missing
     * credential and an insufficient one are different states and must not be
     * conflated by callers deciding whether to re-prompt. */
    switch (response->status) {
    case 401:
        return TAMGA_ERR_UNAUTHORIZED;
    case 403:
        return TAMGA_ERR_FORBIDDEN;
    case 404:
        return TAMGA_ERR_NOT_FOUND;
    case 500:
    case 502:
    case 503:
    case 504:
        return TAMGA_ERR_SERVER;
    default:
        return TAMGA_ERR_API;
    }
}

static TamgaResponse *tamga_response_from_http(TamgaHttpResponse *http) {
    TamgaResponse *response = (TamgaResponse *)tamga_calloc(1u, sizeof(*response));

    if (response == NULL) {
        return NULL;
    }
    response->status = http->status;
    response->body = http->body;
    response->body_len = http->body_len;
    response->headers = http->headers;
    response->header_count = http->header_count;

    /* Ownership has moved; blank the source so its own free is a no-op. */
    http->body = NULL;
    http->body_len = 0u;
    http->headers = NULL;
    http->header_count = 0u;
    http->header_capacity = 0u;

    if (response->body != NULL && response->body_len > 0u) {
        /* A non-JSON body is not an error here: a proxy may return HTML, and
         * the status still means something. */
        response->json = tamga_json_parse(response->body, response->body_len, NULL);
    }
    return response;
}

TamgaErrorCode tamga_client_send(TamgaClient *client, const char *method, const char *path,
                                 const char *query, const char *body, const char *otp,
                                 bool json_api_body, TamgaResponse **out_response) {
    /* Authorization, Tamga-Version, Accept, Content-Type, Tamga-OTP: five at
     * most. The assertion is here so adding a sixth fails to compile rather
     * than overrunning -- re-counting branches is not a bound. */
    TamgaHttpRequestHeader headers[6];
    size_t header_count = 0u;
    _Static_assert(TAMGA_MAX_REQUEST_HEADERS <= 6, "the request header array is too small");
    char *auth_name = NULL;
    char *auth_value = NULL;
    char *url = NULL;
    char *version = NULL;
    TamgaErrorCode status = TAMGA_ERR_UNKNOWN;
    unsigned int attempt = 0u;

    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    *out_response = NULL;

    if (client->transport == NULL) {
        return tamga_error_set(TAMGA_ERR_NO_TRANSPORT,
                               "this build has no HTTP transport; register one with "
                               "tamga_client_set_transport()");
    }
    if (!client->auth_configured) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "no credentials configured; call tamga_client_set_auth() "
                               "before making a request");
    }
    /* The OTP is caller-supplied and goes verbatim into a header. An embedded
     * CRLF would let whoever supplies it append arbitrary headers to a
     * request this library authenticates -- so it is refused here rather than
     * left to each transport to notice. The value is not echoed in the
     * message: it is a one-time credential. */
    if (otp != NULL && !tamga_header_value_is_safe(otp)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "the OTP contains a line break and cannot be sent as a "
                               "header");
    }

    if (!tamga_client_auth_header(client, &auth_name, &auth_value)) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the auth header");
    }
    url = tamga_client_build_url(client, path, query);
    version = tamga_sanitize_api_version(client->api_version);
    if (url == NULL || version == NULL) {
        status = tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
        goto cleanup;
    }

    if (auth_name != NULL) {
        headers[header_count].name = auth_name;
        headers[header_count].value = auth_value;
        header_count++;
    }
    headers[header_count].name = "Tamga-Version";
    headers[header_count].value = version;
    header_count++;
    headers[header_count].name = "Accept";
    headers[header_count].value = "application/vnd.api+json, application/json";
    header_count++;
    if (body != NULL) {
        headers[header_count].name = "Content-Type";
        headers[header_count].value =
            json_api_body ? "application/vnd.api+json" : "application/json";
        header_count++;
    }
    if (otp != NULL) {
        headers[header_count].name = "Tamga-OTP";
        headers[header_count].value = otp;
        header_count++;
    }

    for (;;) {
        TamgaHttpRequest request;
        TamgaHttpResponse http;
        TamgaResponse *response;

        request.method = method;
        request.url = url;
        request.headers = headers;
        request.header_count = header_count;
        request.body = body;
        request.body_len = (body != NULL) ? strlen(body) : 0u;
        request.timeout_ms = client->timeout_ms;

        tamga_http_response_init(&http);
        if (!client->transport->perform(client->transport->user_data, &request, &http)) {
            TamgaTransportFailure reason = http.failure;
            tamga_http_response_free(&http);
            switch (reason) {
            case TAMGA_TRANSPORT_FAIL_OVERSIZED:
                /* Not a network fault and not worth repeating: the same
                 * response would be refused every time. */
                status = tamga_error_set(TAMGA_ERR_TRANSPORT,
                                         "the server's response exceeded the maximum size this "
                                         "library will accept");
                break;
            case TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY:
                status = tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY,
                                         "could not hold the server's response");
                break;
            case TAMGA_TRANSPORT_FAIL_NETWORK:
            default:
                status = tamga_error_set(TAMGA_ERR_TRANSPORT, "the request could not be completed");
                break;
            }
            goto cleanup;
        }

        /* 429 with retries left: wait and go again, but only for requests
         * that are safe to repeat. */
        if (http.status == 429 && attempt < client->max_retries &&
            tamga_request_is_retryable(method, path)) {
            const char *retry_after = tamga_http_response_header(&http, "Retry-After");
            int64_t seconds = 0;
            if (retry_after != NULL) {
                /* Delta-seconds only. The HTTP-date form is ignored rather
                 * than guessed at: misreading a date as a duration would be
                 * far worse than falling back to backoff. */
                seconds = (int64_t)strtoll(retry_after, NULL, 10);
            }
            tamga_http_response_free(&http);
            tamga_sleep_ms(tamga_retry_delay_ms(attempt, seconds));
            attempt++;
            continue;
        }

        response = tamga_response_from_http(&http);
        tamga_http_response_free(&http);
        if (response == NULL) {
            status = tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not read the response");
            goto cleanup;
        }

        if (response->status >= 200 && response->status < 300) {
            *out_response = response;
            status = TAMGA_OK;
            goto cleanup;
        }

        status = tamga_map_api_error(response);
        /* The response is still handed back on failure: it carries the
         * server's own error code and detail, which is usually the only
         * actionable part. */
        *out_response = response;
        (void)tamga_error_set(status, "the server returned HTTP %d%s%s", response->status,
                              (response->api_error_code != NULL) ? " " : "",
                              (response->api_error_code != NULL) ? response->api_error_code : "");
        goto cleanup;
    }

cleanup:
    /* Only the auth header and the sanitised version were allocated; every
     * other header value is a literal. */
    tamga_free(auth_name);
    tamga_string_free(auth_value);
    tamga_string_free(version);
    tamga_string_free(url);
    return status;
}

/* --- lifecycle and configuration ---------------------------------------- */

/*
 * Builds https://{host}/v1/accounts/{account_id}.
 *
 * An explicit http:// is preserved rather than upgraded. Production is always
 * HTTPS, but keeping the scheme the caller gave is what lets the same client
 * point at a local mock server without a test-only code path -- and silently
 * rewriting a URL is worse than honouring it.
 */
static char *tamga_client_compose_base_url(const char *host, const char *account_id) {
    TamgaBuf buf;
    const char *trimmed = host;
    size_t len;
    char *result;

    while (*trimmed == ' ') {
        trimmed++;
    }
    len = strlen(trimmed);
    while (len > 0u && (trimmed[len - 1u] == '/' || trimmed[len - 1u] == ' ')) {
        len--;
    }

    tamga_buf_init(&buf);
    /* A scheme the caller supplied is kept as-is; a bare host gets https.
     * An explicit http:// is honoured rather than upgraded -- production is
     * always HTTPS, but silently rewriting a URL is worse than obeying it,
     * and it is what makes a local mock server usable without a test-only
     * code path. */
    if (!((len > 7u && strncmp(trimmed, "http://", 7u) == 0) ||
          (len > 8u && strncmp(trimmed, "https://", 8u) == 0))) {
        tamga_buf_append_str(&buf, "https://");
    }
    tamga_buf_append(&buf, trimmed, len);
    tamga_buf_append_str(&buf, "/v1/accounts/");
    tamga_buf_append_str(&buf, account_id);

    result = tamga_buf_detach_string(&buf, NULL);
    tamga_buf_free(&buf);
    return result;
}

TamgaErrorCode tamga_client_new(const char *account_id, const char *host,
                                TamgaClient **out_client) {
    TamgaClient *client;

    tamga_error_clear();

    if (account_id == NULL || host == NULL || out_client == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "account_id, host and out_client are all required");
    }
    if (account_id[0] == '\0' || host[0] == '\0') {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "account_id and host must not be empty");
    }
    *out_client = NULL;

    client = (TamgaClient *)tamga_calloc(1u, sizeof(*client));
    if (client == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the client");
    }

    client->account_id = tamga_strdup(account_id);
    client->host = tamga_strdup(host);
    client->api_version = tamga_strdup(TAMGA_DEFAULT_API_VERSION);
    client->base_url = tamga_client_compose_base_url(host, account_id);
    client->timeout_ms = TAMGA_DEFAULT_TIMEOUT_MS;
    client->max_retries = TAMGA_DEFAULT_MAX_RETRIES;
    client->auth_configured = false;

    if (client->account_id == NULL || client->host == NULL || client->api_version == NULL ||
        client->base_url == NULL) {
        tamga_client_free(client);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the client");
    }

    /* A build with no backend still produces a usable client -- the caller
     * can register a transport, and every offline entry point is unaffected.
     * The failure surfaces at request time, with an actionable message. */
    client->transport = tamga_http_transport_create_default();
    client->transport_is_default = client->transport != NULL;

    *out_client = client;
    return TAMGA_OK;
}

void tamga_client_free(TamgaClient *client) {
    if (client == NULL) {
        return;
    }
    tamga_string_free(client->account_id);
    tamga_string_free(client->host);
    tamga_string_free(client->api_version);
    tamga_string_free(client->base_url);
    /* Credentials, so erased rather than merely released. */
    tamga_string_free(client->auth_primary);
    tamga_string_free(client->auth_secondary);
    tamga_http_transport_destroy(client->transport);
    tamga_secure_free(client, sizeof(*client));
}

TamgaErrorCode tamga_client_set_auth(TamgaClient *client, TamgaAuthKind kind, const char *primary,
                                     const char *secondary) {
    char *primary_copy;
    char *secondary_copy = NULL;

    tamga_error_clear();

    if (client == NULL || primary == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and primary are required");
    }
    switch (kind) {
    case TAMGA_AUTH_BEARER:
    case TAMGA_AUTH_LICENSE:
    case TAMGA_AUTH_BASIC_TOKEN:
    case TAMGA_AUTH_BASIC_LICENSE:
    case TAMGA_AUTH_QUERY_TOKEN:
        break;
    case TAMGA_AUTH_BASIC_EMAIL_PASSWORD:
        if (secondary == NULL) {
            return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "the email form requires a password");
        }
        break;
    default:
        /* Reached via a raw value from a stale header or a binding; a C enum
         * has no validity range at the ABI level. */
        return tamga_error_set(TAMGA_ERR_UNSUPPORTED_SCHEME, "unknown auth kind");
    }

    /* Bearer and License place the credential directly into a header value;
     * Basic base64-encodes it and the query transport percent-encodes it, so
     * only the first two can carry a line break through. Checked for all of
     * them anyway -- a credential containing CR or LF is a caller mistake in
     * every form. */
    if (!tamga_header_value_is_safe(primary) ||
        (secondary != NULL && !tamga_header_value_is_safe(secondary))) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "the credential contains a line break");
    }

    primary_copy = tamga_strdup(primary);
    if (primary_copy == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not store the credential");
    }
    if (secondary != NULL) {
        secondary_copy = tamga_strdup(secondary);
        if (secondary_copy == NULL) {
            tamga_string_free(primary_copy);
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not store the credential");
        }
    }

    tamga_string_free(client->auth_primary);
    tamga_string_free(client->auth_secondary);
    client->auth_primary = primary_copy;
    client->auth_secondary = secondary_copy;
    client->auth_kind = kind;
    client->auth_configured = true;
    return TAMGA_OK;
}

TamgaErrorCode tamga_client_set_api_version(TamgaClient *client, const char *version) {
    char *copy;

    tamga_error_clear();
    if (client == NULL || version == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and version are required");
    }
    copy = tamga_strdup(version);
    if (copy == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not store the version");
    }
    tamga_string_free(client->api_version);
    client->api_version = copy;
    return TAMGA_OK;
}

TamgaErrorCode tamga_client_set_timeout_ms(TamgaClient *client, unsigned int timeout_ms) {
    tamga_error_clear();
    if (client == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client is required");
    }
    if (timeout_ms == 0u) {
        return tamga_error_set(TAMGA_ERR_LENGTH_INVALID, "the timeout must be positive");
    }
    client->timeout_ms = timeout_ms;
    return TAMGA_OK;
}

TamgaErrorCode tamga_client_set_max_retries(TamgaClient *client, unsigned int max_retries) {
    tamga_error_clear();
    if (client == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client is required");
    }
    if (max_retries > 16u) {
        return tamga_error_set(TAMGA_ERR_LENGTH_INVALID,
                               "an unreasonable retry count would let one call block for "
                               "hours");
    }
    client->max_retries = max_retries;
    return TAMGA_OK;
}

bool tamga_has_builtin_transport(void) {
    return tamga_http_have_default_transport();
}

/* --- caller-supplied transport ------------------------------------------ */

/*
 * The bridge between the public callback signature -- which deliberately
 * exposes no struct layouts, so the ABI does not freeze them -- and the
 * internal vtable.
 */
struct TamgaHttpResult {
    TamgaHttpResponse *response;
};

typedef struct TamgaCustomTransport {
    TamgaHttpFn perform;
    void *user_data;
    void (*destroy)(void *);
} TamgaCustomTransport;

void tamga_http_result_set_status(TamgaHttpResult *result, int status) {
    if (result != NULL && result->response != NULL) {
        result->response->status = status;
    }
}

bool tamga_http_result_set_body(TamgaHttpResult *result, const char *body, uintptr_t body_len) {
    char *copy;

    if (result == NULL || result->response == NULL) {
        return false;
    }
    if (body == NULL) {
        return false;
    }
    if ((size_t)body_len > TAMGA_MAX_REASONABLE_LEN) {
        result->response->failure = TAMGA_TRANSPORT_FAIL_OVERSIZED;
        return false;
    }
    /* Length-authoritative and NUL-tolerant, matching what the built-in
     * transports do with a body containing a raw NUL. tamga_strndup would
     * reject it, which made the same response succeed through libcurl and
     * fail through a caller-supplied transport. */
    copy = tamga_memdup_terminated(body, (size_t)body_len);
    if (copy == NULL) {
        /* The reason is recorded here rather than left to the caller: a
         * transport callback can only return false, so without this the
         * client would report a machine that is out of memory as a network
         * failure, and the caller would retry it forever. */
        result->response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
        return false;
    }
    tamga_secure_free(result->response->body, result->response->body_len);
    result->response->body = copy;
    result->response->body_len = (size_t)body_len;
    return true;
}

bool tamga_http_result_add_header(TamgaHttpResult *result, const char *name, const char *value) {
    if (result == NULL || result->response == NULL) {
        return false;
    }
    if (!tamga_http_response_add_header(result->response, name, value)) {
        /* Either the 512-header cap or an allocation failure. The cap is not
         * reachable from a sane transport, so attributing this to memory is
         * the useful reading; a transport that hits the cap has bigger
         * problems than the error code. */
        result->response->failure = TAMGA_TRANSPORT_FAIL_OUT_OF_MEMORY;
        return false;
    }
    return true;
}

static bool tamga_custom_perform(void *user_data, const TamgaHttpRequest *request,
                                 TamgaHttpResponse *response) {
    TamgaCustomTransport *custom = (TamgaCustomTransport *)user_data;
    const char *names[8];
    const char *values[8];
    TamgaHttpResult result;
    size_t i;
    size_t count = request->header_count;

    if (custom == NULL || custom->perform == NULL) {
        return false;
    }
    if (count > (sizeof(names) / sizeof(names[0]))) {
        return false;
    }
    for (i = 0u; i < count; i++) {
        names[i] = request->headers[i].name;
        values[i] = request->headers[i].value;
    }

    result.response = response;
    return custom->perform(custom->user_data, request->method, request->url, names, values,
                           (uintptr_t)count, request->body, (uintptr_t)request->body_len,
                           request->timeout_ms, &result);
}

static void tamga_custom_destroy(void *user_data) {
    TamgaCustomTransport *custom = (TamgaCustomTransport *)user_data;
    if (custom == NULL) {
        return;
    }
    if (custom->destroy != NULL) {
        custom->destroy(custom->user_data);
    }
    tamga_free(custom);
}

TamgaErrorCode tamga_client_set_transport(TamgaClient *client, TamgaHttpFn perform, void *user_data,
                                          void (*destroy)(void *)) {
    TamgaHttpTransport *transport;
    TamgaCustomTransport *custom;

    tamga_error_clear();
    if (client == NULL || perform == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and perform are required");
    }

    custom = (TamgaCustomTransport *)tamga_calloc(1u, sizeof(*custom));
    if (custom == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the transport");
    }
    custom->perform = perform;
    custom->user_data = user_data;
    custom->destroy = destroy;

    transport = (TamgaHttpTransport *)tamga_calloc(1u, sizeof(*transport));
    if (transport == NULL) {
        tamga_free(custom);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the transport");
    }
    transport->user_data = custom;
    transport->perform = tamga_custom_perform;
    transport->destroy = tamga_custom_destroy;

    tamga_http_transport_destroy(client->transport);
    client->transport = transport;
    client->transport_is_default = false;
    return TAMGA_OK;
}
