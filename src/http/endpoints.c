/*
 * endpoints.c -- one function per server endpoint.
 *
 * Each is a thin composition: build a path, build a body, hand both to
 * tamga_client_send(), which owns authentication, headers, the retry policy
 * and the error model. The interesting decisions live there; what lives here
 * is the protocol's shape, including the places where that shape is not
 * uniform.
 *
 * Two of those are worth knowing before reading:
 *
 *   - POST /components and POST /processes take FLAT bodies, not JSON:API
 *     envelopes, unlike POST /machines. That asymmetry is the server's, and
 *     following it is not an oversight here.
 *   - GET  .../actions/validate (quick-validate) returns a flat body with no
 *     data envelope, unlike the other two validation endpoints.
 */
#include <stdio.h>
#include <string.h>

#include "checkout/machine_file.h"
#include "http/client.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/buf.h"
#include "util/json.h"
#include "util/uuid.h"

/* Every identifier interpolated into a path is a UUID from the server or the
 * caller. Validating it here means a path can never be built from something
 * containing a slash or a query separator -- which is how an id turns into a
 * request against a different endpoint. */
static TamgaErrorCode tamga_require_uuid(const char *value, const char *what) {
    char canonical[TAMGA_UUID_STRING_SIZE];

    if (value == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "%s is required", what);
    }
    if (!tamga_uuid_normalize(value, canonical)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "%s must be a UUID", what);
    }
    return TAMGA_OK;
}

/* Builds "<prefix><id><suffix>" with the id normalised to canonical form. */
static char *tamga_path(const char *prefix, const char *id, const char *suffix) {
    TamgaBuf buf;
    char canonical[TAMGA_UUID_STRING_SIZE];
    char *path;

    tamga_buf_init(&buf);
    tamga_buf_append_str(&buf, prefix);
    if (id != NULL) {
        if (!tamga_uuid_normalize(id, canonical)) {
            tamga_buf_free(&buf);
            return NULL;
        }
        tamga_buf_append_str(&buf, canonical);
    }
    if (suffix != NULL) {
        tamga_buf_append_str(&buf, suffix);
    }
    path = tamga_buf_detach_string(&buf, NULL);
    tamga_buf_free(&buf);
    return path;
}

/* Parses caller-supplied JSON text into a tree, or reports why not. */
static TamgaErrorCode tamga_parse_optional_object(const char *json, const char *what,
                                                  TamgaJson **out) {
    const char *error = NULL;

    *out = NULL;
    if (json == NULL) {
        return TAMGA_OK;
    }
    *out = tamga_json_parse(json, strlen(json), &error);
    if (*out == NULL) {
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "%s is not valid JSON: %s", what,
                               (error != NULL) ? error : "unknown");
    }
    if (tamga_json_type(*out) != TAMGA_JSON_OBJECT) {
        tamga_json_free(*out);
        *out = NULL;
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "%s must be a JSON object", what);
    }
    return TAMGA_OK;
}

/* --- licence validation -------------------------------------------------- */

TamgaErrorCode tamga_client_validate_by_key(TamgaClient *client, const char *license_key,
                                            const char *otp, TamgaResponse **out_response) {
    TamgaJson *body;
    char *text;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || license_key == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "client, license_key and out_response are required");
    }

    body = tamga_json_new_object();
    if (body == NULL || !tamga_json_object_set(
                            body, "key", tamga_json_new_string(license_key, strlen(license_key)))) {
        tamga_json_free(body);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    text = tamga_json_write(body, NULL);
    tamga_json_free(body);
    if (text == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "POST", "/licenses/actions/validate-key", NULL, text, otp,
                               true, out_response);
    tamga_string_free(text);
    return status;
}

TamgaErrorCode tamga_client_validate_by_id(TamgaClient *client, const char *license_id,
                                           const char *scope_json, bool skip_touch, const char *otp,
                                           TamgaResponse **out_response) {
    TamgaJson *root;
    TamgaJson *meta;
    TamgaJson *scope = NULL;
    char *path;
    char *text;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(license_id, "license_id");
    if (status != TAMGA_OK) {
        return status;
    }
    status = tamga_parse_optional_object(scope_json, "scope_json", &scope);
    if (status != TAMGA_OK) {
        return status;
    }

    root = tamga_json_new_object();
    meta = tamga_json_new_object();
    if (root == NULL || meta == NULL ||
        !tamga_json_object_set(meta, "skip_touch", tamga_json_new_bool(skip_touch)) ||
        (scope != NULL && !tamga_json_object_set(meta, "scope", scope)) ||
        !tamga_json_object_set(root, "meta", meta)) {
        tamga_json_free(root);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    text = tamga_json_write(root, NULL);
    tamga_json_free(root);
    path = tamga_path("/licenses/", license_id, "/actions/validate");
    if (text == NULL || path == NULL) {
        tamga_string_free(text);
        tamga_string_free(path);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "POST", path, NULL, text, otp, true, out_response);
    tamga_string_free(text);
    tamga_string_free(path);
    return status;
}

TamgaErrorCode tamga_client_quick_validate(TamgaClient *client, const char *license_id,
                                           const char *otp, TamgaResponse **out_response) {
    char *path;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(license_id, "license_id");
    if (status != TAMGA_OK) {
        return status;
    }
    path = tamga_path("/licenses/", license_id, "/actions/validate");
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    status = tamga_client_send(client, "GET", path, NULL, NULL, otp, false, out_response);
    tamga_string_free(path);
    return status;
}

TamgaErrorCode tamga_client_check_in(TamgaClient *client, const char *license_id,
                                     TamgaResponse **out_response) {
    char *path;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(license_id, "license_id");
    if (status != TAMGA_OK) {
        return status;
    }
    path = tamga_path("/licenses/", license_id, "/actions/check-in");
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    status = tamga_client_send(client, "POST", path, NULL, NULL, NULL, true, out_response);
    tamga_string_free(path);
    return status;
}

/* --- checkout ------------------------------------------------------------ */

static char *tamga_checkout_query(bool encrypt, int64_t ttl_seconds) {
    TamgaBuf buf;
    char *query;

    tamga_buf_init(&buf);
    tamga_buf_append_str(&buf, encrypt ? "encrypt=true" : "encrypt=false");
    if (ttl_seconds > 0) {
        tamga_buf_append_fmt(&buf, "&ttl=%lld", (long long)ttl_seconds);
    }
    query = tamga_buf_detach_string(&buf, NULL);
    tamga_buf_free(&buf);
    return query;
}

static char *tamga_checkout_body(bool encrypt, int64_t ttl_seconds) {
    TamgaJson *root = tamga_json_new_object();
    TamgaJson *meta = tamga_json_new_object();
    char *text;

    if (root == NULL || meta == NULL) {
        tamga_json_free(root);
        tamga_json_free(meta);
        return NULL;
    }
    if (!tamga_json_object_set(meta, "encrypt", tamga_json_new_bool(encrypt)) ||
        !tamga_json_object_set(meta, "ttl",
                               (ttl_seconds > 0) ? tamga_json_new_int(ttl_seconds)
                                                 : tamga_json_new_null()) ||
        !tamga_json_object_set(root, "meta", meta)) {
        tamga_json_free(root);
        return NULL;
    }
    text = tamga_json_write(root, NULL);
    tamga_json_free(root);
    return text;
}

/* Shared by all four checkout entry points. `raw` selects the GET form, which
 * returns the certificate verbatim, over the POST form, which wraps it in a
 * JSON:API resource with ttl/expiry/issued metadata. */
static TamgaErrorCode tamga_checkout(TamgaClient *client, const char *prefix, const char *id,
                                     const char *what, bool encrypt, int64_t ttl_seconds, bool raw,
                                     TamgaResponse **out_response) {
    char *path;
    char *query = NULL;
    char *body = NULL;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(id, what);
    if (status != TAMGA_OK) {
        return status;
    }
    /* Pre-checked so a caller gets a typed error before the round trip
     * instead of only discovering the problem as a 422. */
    if (ttl_seconds > 0 && !tamga_machine_file_ttl_is_valid(ttl_seconds)) {
        return tamga_error_set(TAMGA_ERR_TTL_INVALID, "ttl must be between 1 second and 365 days");
    }

    path = tamga_path(prefix, id, "/actions/check-out");
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    if (raw) {
        query = tamga_checkout_query(encrypt, ttl_seconds);
        if (query == NULL) {
            tamga_string_free(path);
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
        }
        status = tamga_client_send(client, "GET", path, query, NULL, NULL, false, out_response);
    } else {
        body = tamga_checkout_body(encrypt, ttl_seconds);
        if (body == NULL) {
            tamga_string_free(path);
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
        }
        status = tamga_client_send(client, "POST", path, NULL, body, NULL, true, out_response);
    }

    tamga_string_free(path);
    tamga_string_free(query);
    tamga_string_free(body);
    return status;
}

TamgaErrorCode tamga_client_check_out_license(TamgaClient *client, const char *license_id,
                                              bool encrypt, int64_t ttl_seconds,
                                              TamgaResponse **out_response) {
    return tamga_checkout(client, "/licenses/", license_id, "license_id", encrypt, ttl_seconds,
                          true, out_response);
}

TamgaErrorCode tamga_client_check_out_license_json(TamgaClient *client, const char *license_id,
                                                   bool encrypt, int64_t ttl_seconds,
                                                   TamgaResponse **out_response) {
    return tamga_checkout(client, "/licenses/", license_id, "license_id", encrypt, ttl_seconds,
                          false, out_response);
}

TamgaErrorCode tamga_client_check_out_machine(TamgaClient *client, const char *machine_id,
                                              bool encrypt, int64_t ttl_seconds,
                                              TamgaResponse **out_response) {
    return tamga_checkout(client, "/machines/", machine_id, "machine_id", encrypt, ttl_seconds,
                          true, out_response);
}

TamgaErrorCode tamga_client_check_out_machine_json(TamgaClient *client, const char *machine_id,
                                                   bool encrypt, int64_t ttl_seconds,
                                                   TamgaResponse **out_response) {
    return tamga_checkout(client, "/machines/", machine_id, "machine_id", encrypt, ttl_seconds,
                          false, out_response);
}

/* --- machines ------------------------------------------------------------ */

TamgaErrorCode tamga_client_create_machine(TamgaClient *client, const char *license_id,
                                           const char *fingerprint, const char *options_json,
                                           TamgaResponse **out_response) {
    TamgaJson *options = NULL;
    TamgaJson *root;
    TamgaJson *data;
    TamgaJson *attributes;
    TamgaJson *relationships;
    TamgaJson *license;
    TamgaJson *license_data;
    char canonical[TAMGA_UUID_STRING_SIZE];
    char *text;
    TamgaErrorCode status;
    size_t i;
    static const char *const optional_fields[] = {"name",  "ip",     "hostname", "platform",
                                                  "cores", "memory", "disk",     "metadata"};

    tamga_error_clear();
    if (client == NULL || fingerprint == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "client, fingerprint and out_response are required");
    }
    status = tamga_require_uuid(license_id, "license_id");
    if (status != TAMGA_OK) {
        return status;
    }
    status = tamga_parse_optional_object(options_json, "options_json", &options);
    if (status != TAMGA_OK) {
        return status;
    }
    (void)tamga_uuid_normalize(license_id, canonical);

    root = tamga_json_new_object();
    data = tamga_json_new_object();
    attributes = tamga_json_new_object();
    relationships = tamga_json_new_object();
    license = tamga_json_new_object();
    license_data = tamga_json_new_object();
    if (root == NULL || data == NULL || attributes == NULL || relationships == NULL ||
        license == NULL || license_data == NULL) {
        tamga_json_free(root);
        tamga_json_free(data);
        tamga_json_free(attributes);
        tamga_json_free(relationships);
        tamga_json_free(license);
        tamga_json_free(license_data);
        tamga_json_free(options);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = TAMGA_OK;
    if (!tamga_json_object_set(attributes, "fingerprint",
                               tamga_json_new_string(fingerprint, strlen(fingerprint)))) {
        status = TAMGA_ERR_OUT_OF_MEMORY;
    }
    /* Only the recognised optional attributes are forwarded. Copying the
     * caller's object wholesale would let an unrelated key reach the server
     * as an attribute, which is a different request than the one they asked
     * for. */
    for (i = 0u; options != NULL && status == TAMGA_OK &&
                 i < (sizeof(optional_fields) / sizeof(optional_fields[0]));
         i++) {
        const TamgaJson *value = tamga_json_object_get(options, optional_fields[i]);
        if (value != NULL) {
            TamgaJson *copy = tamga_json_clone(value);
            if (copy == NULL || !tamga_json_object_set(attributes, optional_fields[i], copy)) {
                status = TAMGA_ERR_OUT_OF_MEMORY;
            }
        }
    }
    tamga_json_free(options);

    if (status == TAMGA_OK) {
        if (!tamga_json_object_set(license_data, "type", tamga_json_new_string("licenses", 8u)) ||
            !tamga_json_object_set(license_data, "id",
                                   tamga_json_new_string(canonical, strlen(canonical))) ||
            !tamga_json_object_set(license, "data", license_data) ||
            !tamga_json_object_set(relationships, "license", license) ||
            !tamga_json_object_set(data, "type", tamga_json_new_string("machines", 8u)) ||
            !tamga_json_object_set(data, "attributes", attributes) ||
            !tamga_json_object_set(data, "relationships", relationships) ||
            !tamga_json_object_set(root, "data", data)) {
            status = TAMGA_ERR_OUT_OF_MEMORY;
        }
    }
    if (status != TAMGA_OK) {
        tamga_json_free(root);
        return tamga_error_set(status, "could not build the request");
    }

    text = tamga_json_write(root, NULL);
    tamga_json_free(root);
    if (text == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "POST", "/machines", NULL, text, NULL, true, out_response);
    tamga_string_free(text);
    return status;
}

TamgaErrorCode tamga_client_delete_machine(TamgaClient *client, const char *machine_id,
                                           TamgaResponse **out_response) {
    char *path;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(machine_id, "machine_id");
    if (status != TAMGA_OK) {
        return status;
    }
    path = tamga_path("/machines/", machine_id, NULL);
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    status = tamga_client_send(client, "DELETE", path, NULL, NULL, NULL, false, out_response);
    tamga_string_free(path);
    return status;
}

TamgaErrorCode tamga_client_activate_machine(TamgaClient *client, const char *license_id,
                                             const char *fingerprint, const char *options_json,
                                             const char *scope_json, bool auto_delete_on_overage,
                                             TamgaResponse **out_response) {
    TamgaResponse *created = NULL;
    TamgaResponse *validated = NULL;
    TamgaErrorCode status;
    const char *machine_id = NULL;

    tamga_error_clear();
    if (out_response != NULL) {
        *out_response = NULL;
    }

    status = tamga_client_create_machine(client, license_id, fingerprint, options_json, &created);
    if (status != TAMGA_OK) {
        tamga_response_free(created);
        return status;
    }

    /*
     * Creation does not enforce seat limits -- they surface here. This is the
     * only way to find out whether an activation was one too many, which is
     * why create and validate are composed rather than left to the caller to
     * remember to pair.
     */
    status = tamga_client_validate_by_id(client, license_id, scope_json, false, NULL, &validated);

    if (auto_delete_on_overage && status == TAMGA_OK && validated != NULL &&
        tamga_validation_code_is_overage(tamga_response_validation_code_enum(validated))) {
        const TamgaJson *data = NULL;
        TamgaResponse *deleted = NULL;

        if (created->json != NULL) {
            data = tamga_json_object_get(created->json, "data");
            machine_id = tamga_json_as_string(tamga_json_object_get(data, "id"), NULL);
        }
        if (machine_id != NULL) {
            /*
             * A failed deletion is deliberately not surfaced: the validation
             * result is what the caller asked for, and replacing it with a
             * cleanup error would hide the actual answer. A machine left
             * behind is still visible to normal machine management.
             */
            (void)tamga_client_delete_machine(client, machine_id, &deleted);
            tamga_response_free(deleted);
        }
        /* The delete cleared the thread's error slot on its way through; the
         * validation succeeded, so an empty slot is the correct state. */
        tamga_error_clear();
    }

    tamga_response_free(created);
    if (out_response != NULL) {
        *out_response = validated;
    } else {
        tamga_response_free(validated);
    }
    return status;
}

static TamgaErrorCode tamga_machine_action(TamgaClient *client, const char *machine_id,
                                           const char *action, TamgaResponse **out_response) {
    char *path;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(machine_id, "machine_id");
    if (status != TAMGA_OK) {
        return status;
    }
    path = tamga_path("/machines/", machine_id, action);
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    status = tamga_client_send(client, "POST", path, NULL, NULL, NULL, true, out_response);
    tamga_string_free(path);
    return status;
}

TamgaErrorCode tamga_client_ping_heartbeat(TamgaClient *client, const char *machine_id,
                                           TamgaResponse **out_response) {
    return tamga_machine_action(client, machine_id, "/actions/ping-heartbeat", out_response);
}

TamgaErrorCode tamga_client_reset_heartbeat(TamgaClient *client, const char *machine_id,
                                            TamgaResponse **out_response) {
    return tamga_machine_action(client, machine_id, "/actions/reset-heartbeat", out_response);
}

TamgaErrorCode tamga_client_generate_offline_proof(TamgaClient *client, const char *machine_id,
                                                   const char *dataset_json,
                                                   TamgaResponse **out_response) {
    TamgaJson *dataset = NULL;
    TamgaJson *root;
    TamgaJson *meta;
    char *path;
    char *text;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(machine_id, "machine_id");
    if (status != TAMGA_OK) {
        return status;
    }
    /* The server rejects a non-object dataset with 422 DATASET_INVALID, so
     * catching it here saves a round trip and gives a clearer message. */
    status = tamga_parse_optional_object(dataset_json, "dataset_json", &dataset);
    if (status != TAMGA_OK) {
        return status;
    }
    if (dataset == NULL) {
        dataset = tamga_json_new_object();
    }

    root = tamga_json_new_object();
    meta = tamga_json_new_object();
    if (root == NULL || meta == NULL || dataset == NULL ||
        !tamga_json_object_set(meta, "dataset", dataset) ||
        !tamga_json_object_set(root, "meta", meta)) {
        tamga_json_free(root);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    text = tamga_json_write(root, NULL);
    tamga_json_free(root);
    path = tamga_path("/machines/", machine_id, "/actions/generate-offline-proof");
    if (text == NULL || path == NULL) {
        tamga_string_free(text);
        tamga_string_free(path);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "POST", path, NULL, text, NULL, true, out_response);
    tamga_string_free(text);
    tamga_string_free(path);
    return status;
}

/* --- components and processes -------------------------------------------- */

TamgaErrorCode tamga_client_create_component(TamgaClient *client, const char *machine_id,
                                             const char *fingerprint, const char *name,
                                             const char *metadata_json,
                                             TamgaResponse **out_response) {
    TamgaJson *metadata = NULL;
    TamgaJson *root;
    char canonical[TAMGA_UUID_STRING_SIZE];
    char *text;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || fingerprint == NULL || name == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "client, fingerprint, name and out_response are required");
    }
    status = tamga_require_uuid(machine_id, "machine_id");
    if (status != TAMGA_OK) {
        return status;
    }
    status = tamga_parse_optional_object(metadata_json, "metadata_json", &metadata);
    if (status != TAMGA_OK) {
        return status;
    }
    if (metadata == NULL) {
        metadata = tamga_json_new_object();
    }
    (void)tamga_uuid_normalize(machine_id, canonical);

    /* ⚠️ Flat, not JSON:API-enveloped -- unlike machine creation. The
     * server's handler expects { machine_id, fingerprint, name, metadata }. */
    root = tamga_json_new_object();
    if (root == NULL || metadata == NULL ||
        !tamga_json_object_set(root, "machine_id",
                               tamga_json_new_string(canonical, strlen(canonical))) ||
        !tamga_json_object_set(root, "fingerprint",
                               tamga_json_new_string(fingerprint, strlen(fingerprint))) ||
        !tamga_json_object_set(root, "name", tamga_json_new_string(name, strlen(name))) ||
        !tamga_json_object_set(root, "metadata", metadata)) {
        tamga_json_free(root);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    text = tamga_json_write(root, NULL);
    tamga_json_free(root);
    if (text == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "POST", "/components", NULL, text, NULL, true, out_response);
    tamga_string_free(text);
    return status;
}

/* Shared by the two keyset-paginated listings. */
static TamgaErrorCode tamga_list(TamgaClient *client, const char *prefix, const char *id,
                                 const char *what, const char *suffix, uint32_t limit,
                                 const char *after, TamgaResponse **out_response) {
    TamgaBuf query_buf;
    char *path;
    char *query = NULL;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(id, what);
    if (status != TAMGA_OK) {
        return status;
    }
    if (after != NULL) {
        status = tamga_require_uuid(after, "after");
        if (status != TAMGA_OK) {
            return status;
        }
    }

    tamga_buf_init(&query_buf);
    if (limit > 0u) {
        tamga_buf_append_fmt(&query_buf, "limit=%lu", (unsigned long)limit);
    }
    if (after != NULL) {
        char canonical[TAMGA_UUID_STRING_SIZE];
        (void)tamga_uuid_normalize(after, canonical);
        if (limit > 0u) {
            tamga_buf_append_byte(&query_buf, '&');
        }
        /* The bracket is percent-encoded: an unescaped one is legal in a
         * query string but not universally handled the same way. */
        tamga_buf_append_str(&query_buf, "page%5Bafter%5D=");
        tamga_buf_append_str(&query_buf, canonical);
    }
    if (query_buf.len > 0u) {
        query = tamga_buf_detach_string(&query_buf, NULL);
    }
    tamga_buf_free(&query_buf);

    path = tamga_path(prefix, id, suffix);
    if (path == NULL) {
        tamga_string_free(query);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "GET", path, query, NULL, NULL, false, out_response);
    tamga_string_free(path);
    tamga_string_free(query);
    return status;
}

TamgaErrorCode tamga_client_list_components(TamgaClient *client, const char *machine_id,
                                            uint32_t limit, const char *after,
                                            TamgaResponse **out_response) {
    return tamga_list(client, "/machines/", machine_id, "machine_id", "/components", limit, after,
                      out_response);
}

TamgaErrorCode tamga_client_create_process(TamgaClient *client, const char *machine_id,
                                           const char *pid, const char *metadata_json,
                                           TamgaResponse **out_response) {
    TamgaJson *metadata = NULL;
    TamgaJson *root;
    char canonical[TAMGA_UUID_STRING_SIZE];
    char *text;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || pid == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "client, pid and out_response are required");
    }
    status = tamga_require_uuid(machine_id, "machine_id");
    if (status != TAMGA_OK) {
        return status;
    }
    status = tamga_parse_optional_object(metadata_json, "metadata_json", &metadata);
    if (status != TAMGA_OK) {
        return status;
    }
    if (metadata == NULL) {
        metadata = tamga_json_new_object();
    }
    (void)tamga_uuid_normalize(machine_id, canonical);

    /* Flat body, same asymmetry as component creation. */
    root = tamga_json_new_object();
    if (root == NULL || metadata == NULL ||
        !tamga_json_object_set(root, "machine_id",
                               tamga_json_new_string(canonical, strlen(canonical))) ||
        !tamga_json_object_set(root, "pid", tamga_json_new_string(pid, strlen(pid))) ||
        !tamga_json_object_set(root, "metadata", metadata)) {
        tamga_json_free(root);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    text = tamga_json_write(root, NULL);
    tamga_json_free(root);
    if (text == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "POST", "/processes", NULL, text, NULL, true, out_response);
    tamga_string_free(text);
    return status;
}

TamgaErrorCode tamga_client_ping_process(TamgaClient *client, const char *process_id,
                                         TamgaResponse **out_response) {
    char *path;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(process_id, "process_id");
    if (status != TAMGA_OK) {
        return status;
    }
    path = tamga_path("/processes/", process_id, "/actions/ping");
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    status = tamga_client_send(client, "POST", path, NULL, NULL, NULL, true, out_response);
    tamga_string_free(path);
    return status;
}

/* --- entitlements -------------------------------------------------------- */

TamgaErrorCode tamga_client_list_entitlements(TamgaClient *client, const char *license_id,
                                              uint32_t limit, const char *after,
                                              TamgaResponse **out_response) {
    return tamga_list(client, "/licenses/", license_id, "license_id", "/entitlements", limit, after,
                      out_response);
}

TamgaErrorCode tamga_client_get_entitlement(TamgaClient *client, const char *license_id,
                                            const char *entitlement_id,
                                            TamgaResponse **out_response) {
    TamgaBuf buf;
    char canonical[TAMGA_UUID_STRING_SIZE];
    char *path;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(license_id, "license_id");
    if (status != TAMGA_OK) {
        return status;
    }
    status = tamga_require_uuid(entitlement_id, "entitlement_id");
    if (status != TAMGA_OK) {
        return status;
    }

    tamga_buf_init(&buf);
    (void)tamga_uuid_normalize(license_id, canonical);
    tamga_buf_append_str(&buf, "/licenses/");
    tamga_buf_append_str(&buf, canonical);
    tamga_buf_append_str(&buf, "/entitlements/");
    (void)tamga_uuid_normalize(entitlement_id, canonical);
    tamga_buf_append_str(&buf, canonical);
    path = tamga_buf_detach_string(&buf, NULL);
    tamga_buf_free(&buf);
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "GET", path, NULL, NULL, NULL, false, out_response);
    tamga_string_free(path);
    return status;
}

TamgaErrorCode tamga_client_has_entitlement(TamgaClient *client, const char *license_id,
                                            const char *code, uint32_t limit, bool *out_has) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status;
    const TamgaJson *data;
    size_t count;
    size_t i;

    tamga_error_clear();
    if (client == NULL || code == NULL || out_has == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client, code and out_has are required");
    }
    *out_has = false;

    /* 100 is the server's own maximum page size. A licence with more
     * entitlements than that needs real pagination, which is what
     * tamga_client_list_entitlements() is for -- silently checking only the
     * first page while looking exhaustive would be worse than saying so. */
    status = tamga_client_list_entitlements(client, license_id, (limit > 0u) ? limit : 100u, NULL,
                                            &response);
    if (status != TAMGA_OK) {
        tamga_response_free(response);
        return status;
    }

    data = tamga_json_object_get(response->json, "data");
    count = tamga_json_array_len(data);
    for (i = 0u; i < count; i++) {
        const TamgaJson *entitlement = tamga_json_array_at(data, i);
        const TamgaJson *attributes = tamga_json_object_get(entitlement, "attributes");
        /* Matched on `code`, the stable developer-facing identifier -- never
         * on `name`, which is a display label and may be reworded. */
        const char *value = tamga_json_as_string(tamga_json_object_get(attributes, "code"), NULL);
        if (value != NULL && strcmp(value, code) == 0) {
            *out_has = true;
            break;
        }
    }

    tamga_response_free(response);
    return TAMGA_OK;
}
