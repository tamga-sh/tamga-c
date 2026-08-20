#include "checkout/cert.h"

#include <string.h>

#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"

bool tamga_cert_alg_equals(const TamgaCert *cert, const char *expected, size_t expected_len) {
    if (cert == NULL || cert->alg == NULL || expected == NULL) {
        return false;
    }
    if (cert->alg_len != expected_len) {
        return false;
    }
    return memcmp(cert->alg, expected, expected_len) == 0;
}

void tamga_cert_free(TamgaCert *cert) {
    if (cert == NULL) {
        return;
    }
    tamga_json_free(cert->root);
    cert->root = NULL;
    cert->enc = NULL;
    cert->sig = NULL;
    cert->alg = NULL;
    cert->enc_len = 0u;
    cert->sig_len = 0u;
    cert->alg_len = 0u;
}

TamgaErrorCode tamga_cert_parse(const char *body, size_t body_len, TamgaCert *out) {
    unsigned char *decoded;
    size_t decoded_len = 0u;
    const char *parse_error = NULL;
    TamgaJson *root;
    TamgaBase64Failure why;
    const TamgaJson *enc;
    const TamgaJson *sig;
    const TamgaJson *alg;

    if (body == NULL || out == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    memset(out, 0, sizeof(*out));

    decoded = tamga_base64_decode_alloc_why(body, body_len, &decoded_len, &why);
    if (decoded == NULL) {
        if (why == TAMGA_BASE64_FAILURE_OUT_OF_MEMORY) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY,
                                   "could not allocate room to decode the certificate");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_BASE64,
                               "the certificate body is not valid base64");
    }

    root = tamga_json_parse((const char *)decoded, decoded_len, &parse_error);
    tamga_secure_free(decoded, decoded_len);
    if (root == NULL) {
        if (tamga_json_error_is_out_of_memory(parse_error)) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not parse the certificate");
        }
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "certificate JSON is malformed: %s",
                               (parse_error != NULL) ? parse_error : "unknown");
    }

    enc = tamga_json_object_get(root, "enc");
    sig = tamga_json_object_get(root, "sig");
    alg = tamga_json_object_get(root, "alg");

    out->enc = tamga_json_as_string(enc, &out->enc_len);
    out->sig = tamga_json_as_string(sig, &out->sig_len);
    out->alg = tamga_json_as_string(alg, &out->alg_len);

    if (out->enc == NULL || out->sig == NULL || out->alg == NULL) {
        tamga_json_free(root);
        memset(out, 0, sizeof(*out));
        return tamga_error_set(TAMGA_ERR_INVALID_JSON,
                               "certificate is missing a required string field "
                               "(enc, sig or alg)");
    }

    out->root = root;
    return TAMGA_OK;
}
