#include "http/transport.h"

#include <string.h>

#include "tamga_mem.h"

#if defined(TAMGA_HTTP_CURL)
TamgaHttpTransport *tamga_http_transport_create_curl(void);
#endif
#if defined(TAMGA_HTTP_WINHTTP)
TamgaHttpTransport *tamga_http_transport_create_winhttp(void);
#endif

void tamga_http_response_init(TamgaHttpResponse *response) {
    if (response == NULL) {
        return;
    }
    response->status = 0;
    response->body = NULL;
    response->body_len = 0u;
    response->headers = NULL;
    response->header_count = 0u;
    response->header_capacity = 0u;
}

void tamga_http_response_free(TamgaHttpResponse *response) {
    size_t i;

    if (response == NULL) {
        return;
    }
    /* Response bodies routinely carry licence keys and machine metadata, so
     * they are erased rather than merely released. */
    tamga_secure_free(response->body, response->body_len);
    for (i = 0u; i < response->header_count; i++) {
        tamga_free(response->headers[i].name);
        tamga_free(response->headers[i].value);
    }
    tamga_free(response->headers);
    tamga_http_response_init(response);
}

bool tamga_http_response_add_header(TamgaHttpResponse *response, const char *name,
                                    const char *value) {
    char *name_copy;
    char *value_copy;

    if (response == NULL || name == NULL || value == NULL) {
        return false;
    }
    if (response->header_count >= response->header_capacity) {
        size_t new_capacity =
            (response->header_capacity == 0u) ? 8u : response->header_capacity * 2u;
        size_t bytes;
        TamgaHttpHeader *grown;

        /* A server that streams headers forever must not be able to make this
         * grow without bound. */
        if (new_capacity > 512u) {
            return false;
        }
        if (!tamga_checked_mul(new_capacity, sizeof(TamgaHttpHeader), &bytes)) {
            return false;
        }
        grown = (TamgaHttpHeader *)tamga_realloc(response->headers, bytes);
        if (grown == NULL) {
            return false;
        }
        response->headers = grown;
        response->header_capacity = new_capacity;
    }

    name_copy = tamga_strdup(name);
    value_copy = tamga_strdup(value);
    if (name_copy == NULL || value_copy == NULL) {
        tamga_free(name_copy);
        tamga_free(value_copy);
        return false;
    }
    response->headers[response->header_count].name = name_copy;
    response->headers[response->header_count].value = value_copy;
    response->header_count++;
    return true;
}

static bool tamga_header_name_equal(const char *a, const char *b) {
    size_t i = 0u;
    while (a[i] != '\0' && b[i] != '\0') {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return false;
        }
        i++;
    }
    return a[i] == b[i];
}

const char *tamga_http_response_header(const TamgaHttpResponse *response, const char *name) {
    size_t i;

    if (response == NULL || name == NULL) {
        return NULL;
    }
    for (i = 0u; i < response->header_count; i++) {
        if (tamga_header_name_equal(response->headers[i].name, name)) {
            return response->headers[i].value;
        }
    }
    return NULL;
}

TamgaHttpTransport *tamga_http_transport_create_default(void) {
#if defined(TAMGA_HTTP_CURL)
    return tamga_http_transport_create_curl();
#elif defined(TAMGA_HTTP_WINHTTP)
    return tamga_http_transport_create_winhttp();
#else
    return NULL;
#endif
}

void tamga_http_transport_destroy(TamgaHttpTransport *transport) {
    if (transport == NULL) {
        return;
    }
    if (transport->destroy != NULL) {
        transport->destroy(transport->user_data);
    }
    tamga_free(transport);
}

bool tamga_http_have_default_transport(void) {
#if defined(TAMGA_HTTP_CURL) || defined(TAMGA_HTTP_WINHTTP)
    return true;
#else
    return false;
#endif
}
