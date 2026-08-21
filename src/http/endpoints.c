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
        if (tamga_json_error_is_out_of_memory(error)) {
            return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not parse %s", what);
        }
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

/* GETs one resource: "<prefix><id><suffix>", with `id` normalised. */
static TamgaErrorCode tamga_get_resource(TamgaClient *client, const char *prefix, const char *id,
                                         const char *what, const char *suffix,
                                         TamgaResponse **out_response) {
    char *path;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(id, what);
    if (status != TAMGA_OK) {
        return status;
    }
    path = tamga_path(prefix, id, suffix);
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    status = tamga_client_send(client, "GET", path, NULL, NULL, NULL, false, out_response);
    tamga_string_free(path);
    return status;
}

/*
 * Appends "name=<percent-encoded value>" to a query buffer, with the
 * separator the position needs.
 *
 * `name` is a literal from this file and goes in verbatim, including the
 * percent-encoded brackets of a `filter[...]`/`page[...]` key; `value` is
 * caller input and is always encoded, so a fingerprint containing `&` cannot
 * add a parameter of its own.
 */
static bool tamga_query_add(TamgaBuf *buf, bool *first, const char *name, const char *value) {
    char *encoded = tamga_url_encode(value);

    if (encoded == NULL) {
        return false;
    }
    if (!*first) {
        tamga_buf_append_byte(buf, '&');
    }
    *first = false;
    tamga_buf_append_str(buf, name);
    tamga_buf_append_byte(buf, '=');
    tamga_buf_append_str(buf, encoded);
    tamga_string_free(encoded);
    return true;
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

    /*
     * `meta` is put inside `root` BEFORE it is populated, so that from that
     * point on freeing `root` releases everything. Populating first and
     * attaching last -- the obvious order -- means a failure part-way leaves
     * `meta` owned by nobody, and the single `tamga_json_free(root)` cleanup
     * silently leaks it. That was a real leak here, in tamga_checkout_body
     * and in tamga_proof_build_payload, all three found by the allocation
     * walk in tests/unit/alloc_failure_test.c.
     */
    root = tamga_json_new_object();
    meta = tamga_json_new_object();
    if (root == NULL || meta == NULL) {
        tamga_json_free(root);
        tamga_json_free(meta);
        tamga_json_free(scope);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    if (!tamga_json_object_set(root, "meta", meta)) {
        /* The failed setter consumed `meta`; only `scope` is still ours. */
        tamga_json_free(root);
        tamga_json_free(scope);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    /* Insertion order is the wire order, and the wire bytes are pinned by
     * tests/http/endpoints_test.c -- so `scope` is freed explicitly on this
     * path rather than being attached early to make the ownership simpler. */
    if (!tamga_json_object_set(meta, "skip_touch", tamga_json_new_bool(skip_touch))) {
        tamga_json_free(root);
        tamga_json_free(scope);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    if (scope != NULL && !tamga_json_object_set(meta, "scope", scope)) {
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

/* --- licence and policy reads -------------------------------------------- */

/*
 * ⚠️ Neither of the two licence reads below is confined to the licence the
 * credential belongs to.
 *
 * `require_license_scope` -- the server-side check that stops a licence key
 * being used against a different licence's id -- is applied to validate,
 * quick-validate, validate-key and check-out. It is NOT applied to
 * `GET /licenses/{id}` or `GET /licenses/{id}/policy`
 * (tamga-api `src/features/licenses/get_license.rs`,
 * `get_license_policy.rs`), which gate on the `license.read` permission
 * alone -- and `Role::LicenseToken` carries `license.read` by default. The
 * licence resource's `attributes.key` is the plaintext licence key.
 *
 * So a caller holding one licence key can read every other licence's key in
 * the same account by id. That is the server's behaviour, reported upstream;
 * an SDK cannot fix it, and this note exists so that nobody reads these two
 * functions as a scoped, safe surface. Do not build a feature that hands an
 * end user's licence key to code that only needs to know its policy.
 */

TamgaErrorCode tamga_client_get_license(TamgaClient *client, const char *license_id,
                                        TamgaResponse **out_response) {
    return tamga_get_resource(client, "/licenses/", license_id, "license_id", NULL, out_response);
}

TamgaErrorCode tamga_client_get_license_policy(TamgaClient *client, const char *license_id,
                                               TamgaResponse **out_response) {
    return tamga_get_resource(client, "/licenses/", license_id, "license_id", "/policy",
                              out_response);
}

/*
 * `GET /policies/{policy_id}` gates on the `policy.read` permission, which
 * `Role::LicenseToken` does NOT carry (tamga-api
 * `src/shared/authz/mod.rs`, the LicenseToken default-permission list). A
 * licence-key credential therefore gets `403` here, whatever the policy's
 * authentication strategy. Reaching a policy from a licence key is what
 * tamga_client_get_license_policy() is for: it gates on `license.read`,
 * which a licence key does carry, and returns the identical policy resource.
 */
TamgaErrorCode tamga_client_get_policy(TamgaClient *client, const char *policy_id,
                                       TamgaResponse **out_response) {
    return tamga_get_resource(client, "/policies/", policy_id, "policy_id", NULL, out_response);
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
    /* Attached before it is populated -- see the note in
     * tamga_client_validate_by_id for why the other order leaks. */
    if (!tamga_json_object_set(root, "meta", meta)) {
        tamga_json_free(root);
        return NULL;
    }
    if (!tamga_json_object_set(meta, "encrypt", tamga_json_new_bool(encrypt)) ||
        !tamga_json_object_set(meta, "ttl",
                               (ttl_seconds > 0) ? tamga_json_new_int(ttl_seconds)
                                                 : tamga_json_new_null())) {
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
    /* tamga_require_uuid above already parsed this same string with the
     * same parser, so this cannot fail -- but it is checked rather than
     * discarded, both because GCC rejects (void) as a suppression for a
     * warn_unused_result function and because an invariant that is
     * enforced survives the earlier call being moved. */
    if (!tamga_uuid_normalize(license_id, canonical)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "license_id must be a UUID");
    }

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

    /*
     * The whole tree is assembled first, empty, so that `root` owns every
     * node before any of them is populated. Everything after this point is
     * covered by a single tamga_json_free(root) -- which is what the cleanup
     * below has always assumed and, until the allocation walk in
     * tests/unit/alloc_failure_test.c, was not actually true.
     */
    if (!tamga_json_object_set(root, "data", data)) {
        tamga_json_free(root);
        tamga_json_free(attributes);
        tamga_json_free(relationships);
        tamga_json_free(license);
        tamga_json_free(license_data);
        tamga_json_free(options);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    /* "type" goes in before the two sub-objects because insertion order is
     * the wire order, and endpoints_test.c pins these bytes. */
    if (!tamga_json_object_set(data, "type", tamga_json_new_string("machines", 8u))) {
        tamga_json_free(root);
        tamga_json_free(attributes);
        tamga_json_free(relationships);
        tamga_json_free(license);
        tamga_json_free(license_data);
        tamga_json_free(options);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    if (!tamga_json_object_set(data, "attributes", attributes)) {
        tamga_json_free(root);
        tamga_json_free(relationships);
        tamga_json_free(license);
        tamga_json_free(license_data);
        tamga_json_free(options);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    if (!tamga_json_object_set(data, "relationships", relationships)) {
        tamga_json_free(root);
        tamga_json_free(license);
        tamga_json_free(license_data);
        tamga_json_free(options);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    if (!tamga_json_object_set(relationships, "license", license)) {
        tamga_json_free(root);
        tamga_json_free(license_data);
        tamga_json_free(options);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    if (!tamga_json_object_set(license, "data", license_data)) {
        tamga_json_free(root);
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

    /* Every node below already belongs to root, so these only add leaves. */
    if (status == TAMGA_OK) {
        if (!tamga_json_object_set(license_data, "type", tamga_json_new_string("licenses", 8u)) ||
            !tamga_json_object_set(license_data, "id",
                                   tamga_json_new_string(canonical, strlen(canonical)))) {
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

TamgaErrorCode tamga_client_get_machine(TamgaClient *client, const char *machine_id,
                                        TamgaResponse **out_response) {
    return tamga_get_resource(client, "/machines/", machine_id, "machine_id", NULL, out_response);
}

TamgaErrorCode tamga_client_update_machine(TamgaClient *client, const char *machine_id,
                                           const char *attributes_json,
                                           TamgaResponse **out_response) {
    TamgaJson *attributes_in = NULL;
    TamgaJson *root;
    TamgaJson *data;
    TamgaJson *attributes;
    char *path;
    char *text;
    TamgaErrorCode status;
    size_t i;
    /* The same allowlist as creation, minus `fingerprint`: the server's
     * UpdateMachineAttributes has no such field, and a machine's fingerprint
     * is the identity the licence's seat is bound to. */
    static const char *const updatable_fields[] = {"name",  "ip",     "hostname", "platform",
                                                   "cores", "memory", "disk",     "metadata"};

    tamga_error_clear();
    if (client == NULL || attributes_json == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "client, attributes_json and out_response are required");
    }
    status = tamga_require_uuid(machine_id, "machine_id");
    if (status != TAMGA_OK) {
        return status;
    }
    status = tamga_parse_optional_object(attributes_json, "attributes_json", &attributes_in);
    if (status != TAMGA_OK) {
        return status;
    }

    /* Enveloped, like creation and unlike the two flat creates -- and `type`
     * is required, not decorative: the server's UpdateMachineData declares it
     * as a non-optional String, so a body without it is rejected at
     * deserialization with 422 before the handler runs. */
    root = tamga_json_new_object();
    data = tamga_json_new_object();
    attributes = tamga_json_new_object();
    if (root == NULL || data == NULL || attributes == NULL) {
        tamga_json_free(root);
        tamga_json_free(data);
        tamga_json_free(attributes);
        tamga_json_free(attributes_in);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    /* Each child is attached before the next is populated, so a failure
     * part-way is covered by the single tamga_json_free(root) -- see the note
     * in tamga_client_validate_by_id. */
    if (!tamga_json_object_set(root, "data", data)) {
        tamga_json_free(root);
        tamga_json_free(attributes);
        tamga_json_free(attributes_in);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    if (!tamga_json_object_set(data, "type", tamga_json_new_string("machines", 8u))) {
        tamga_json_free(root);
        tamga_json_free(attributes);
        tamga_json_free(attributes_in);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    if (!tamga_json_object_set(data, "attributes", attributes)) {
        tamga_json_free(root);
        tamga_json_free(attributes_in);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = TAMGA_OK;
    for (i = 0u; attributes_in != NULL && status == TAMGA_OK &&
                 i < (sizeof(updatable_fields) / sizeof(updatable_fields[0]));
         i++) {
        const TamgaJson *value = tamga_json_object_get(attributes_in, updatable_fields[i]);
        if (value != NULL) {
            TamgaJson *copy = tamga_json_clone(value);
            if (copy == NULL || !tamga_json_object_set(attributes, updatable_fields[i], copy)) {
                status = TAMGA_ERR_OUT_OF_MEMORY;
            }
        }
    }
    tamga_json_free(attributes_in);
    if (status != TAMGA_OK) {
        tamga_json_free(root);
        return tamga_error_set(status, "could not build the request");
    }

    text = tamga_json_write(root, NULL);
    tamga_json_free(root);
    path = tamga_path("/machines/", machine_id, NULL);
    if (text == NULL || path == NULL) {
        tamga_string_free(text);
        tamga_string_free(path);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "PATCH", path, NULL, text, NULL, true, out_response);
    tamga_string_free(text);
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
    if (status != TAMGA_OK || created == NULL) {
        /*
         * Creation DOES enforce the licence's limits, and under a strict
         * overage strategy it is where an over-limit activation is rejected:
         * 422 with MACHINE_LIMIT_EXCEEDED, CORE_LIMIT_EXCEEDED,
         * MEMORY_LIMIT_EXCEEDED or DISK_LIMIT_EXCEEDED, now mapped to their
         * own error codes. There is no machine row in that case, so there is
         * nothing to validate and -- critically -- nothing to delete: issuing
         * the rollback DELETE here would address a machine that was never
         * created.
         *
         * On that path ALONE the creation response is handed back, so the
         * caller can read the server's own code and status off it and feed
         * the returned code to tamga_validation_code_from_error(). Every
         * other creation failure keeps the pre-1.3.1 behaviour exactly:
         * `created` is freed here and `*out_response` stays NULL.
         *
         * ⚠️ That is deliberately narrower than the validate-failure path
         * below, which hands its response back on every outcome. The
         * asymmetry is known and is not an oversight to tidy away. Widening
         * this branch would start handing a response to callers that have
         * read `*out_response == NULL` as "activation failed, nothing to
         * free" since 1.3.0 -- leaking one TamgaResponse per failed
         * activation in code that did not change, on a patch upgrade. The
         * limit codes are new in 1.3.1, so no caller can hold an expectation
         * about them; widening the rest is a contract change and belongs in a
         * release that announces one.
         *
         * A successful send always yields a response, but the machine id is
         * read out of it below, and a null there would be a crash rather than
         * an error -- so the invariant is checked, not assumed.
         */
        bool is_create_time_limit =
            (created != NULL) &&
            (tamga_validation_code_from_error(status) != TAMGA_VALIDATION_UNKNOWN);

        if (out_response != NULL && is_create_time_limit) {
            *out_response = created;
        } else {
            tamga_response_free(created);
        }
        return (status != TAMGA_OK)
                   ? status
                   : tamga_error_set(TAMGA_ERR_UNKNOWN,
                                     "the machine was created but the server returned no "
                                     "resource");
    }

    /*
     * Under ALLOW_ACCESS or ALLOW_1_25X_OVERAGE the creation above succeeded
     * despite the licence being over its limit, and this is where that
     * surfaces. Composing create with validate rather than leaving the pair
     * to the caller is what makes both strategies produce a usable answer.
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

/* --- the machine collection, and the way out of FINGERPRINT_TAKEN --------
 *
 * `GET /machines` is the one list in this domain that is NOT keyset-
 * paginated. It goes through the server's shared offset paginator
 * (tamga-api `src/shared/list_query.rs`), so it takes `page[number]` and
 * `page[size]` and answers with `meta.page{number,size,total,totalPages}`.
 * tamga_response_next_cursor() is the wrong tool here and would loop on the
 * first page forever; tamga_response_page() is the right one.
 */

/* The server's own ceiling (MAX_PAGE_SIZE); asking for more is clamped. */
#define TAMGA_MACHINE_PAGE_SIZE 100u

/*
 * How many pages tamga_client_find_machine_by_fingerprint() will walk.
 *
 * The search below is a substring match, not an equality filter, so in
 * principle several machines can come back for one fingerprint and the exact
 * one can sit past the first page. Ten pages of a hundred is far past any
 * real licence, and a bound is what keeps a lookup from turning into an
 * unbounded request loop against a hostile or broken `total`.
 */
#define TAMGA_MACHINE_LOOKUP_MAX_PAGES 10u

TamgaErrorCode tamga_client_list_machines(TamgaClient *client, const char *license_id,
                                          const char *search, uint32_t page_number,
                                          uint32_t page_size, TamgaResponse **out_response) {
    TamgaBuf query_buf;
    bool first = true;
    bool built = true;
    char *query;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    if (license_id != NULL) {
        status = tamga_require_uuid(license_id, "license_id");
        if (status != TAMGA_OK) {
            return status;
        }
    }

    tamga_buf_init(&query_buf);
    if (page_number > 0u) {
        tamga_buf_append_fmt(&query_buf, "page%%5Bnumber%%5D=%lu", (unsigned long)page_number);
        first = false;
    }
    if (page_size > 0u) {
        if (!first) {
            tamga_buf_append_byte(&query_buf, '&');
        }
        tamga_buf_append_fmt(&query_buf, "page%%5Bsize%%5D=%lu", (unsigned long)page_size);
        first = false;
    }
    if (license_id != NULL) {
        char canonical[TAMGA_UUID_STRING_SIZE];
        /* tamga_require_uuid above already parsed this same string with the
         * same parser, so this cannot fail -- but it is checked rather than
         * discarded, both because GCC rejects (void) as a suppression for a
         * warn_unused_result function and because an invariant that is
         * enforced survives the earlier call being moved. */
        if (!tamga_uuid_normalize(license_id, canonical)) {
            tamga_buf_free(&query_buf);
            return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "license_id must be a UUID");
        }
        built = tamga_query_add(&query_buf, &first, "filter%5Blicense%5D", canonical);
    }
    /* `filter[q]` is a case-insensitive SUBSTRING search across the machine's
     * name, hostname and fingerprint (tamga-api `list_filter.rs`, ILIKE
     * '%term%'), not an equality filter -- there is no `filter[fingerprint]`.
     * Anything matching an exact value has to be re-checked by the caller;
     * tamga_client_find_machine_by_fingerprint() below is that check. */
    if (built && search != NULL) {
        built = tamga_query_add(&query_buf, &first, "filter%5Bq%5D", search);
    }

    /* Detached unconditionally and checked -- see the note in tamga_list for
     * why gating on the buffer's length instead would silently send the
     * server's default page. */
    query = tamga_buf_detach_string(&query_buf, NULL);
    tamga_buf_free(&query_buf);
    if (!built || query == NULL) {
        tamga_string_free(query);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "GET", "/machines", query, NULL, NULL, false, out_response);
    tamga_string_free(query);
    return status;
}

/*
 * The exact-fingerprint match on one page of machines, copied out before the
 * response that owns the string is released.
 *
 * `*out_id` is NULL when this page holds no match; that is TAMGA_OK, because
 * a page without the machine is a normal step in the walk. A failed copy is
 * NOT: returning NULL for it would turn "out of memory" into "this machine is
 * not activated", and the caller above would report the fingerprint as
 * belonging to somebody else's licence.
 */
static TamgaErrorCode tamga_machine_page_exact_match(const TamgaResponse *response,
                                                     const char *fingerprint, char **out_id) {
    const TamgaJson *data;
    size_t count;
    size_t i;

    *out_id = NULL;
    data = tamga_json_object_get(response->json, "data");
    count = tamga_json_array_len(data);
    for (i = 0u; i < count; i++) {
        const TamgaJson *machine = tamga_json_array_at(data, i);
        const TamgaJson *attributes = tamga_json_object_get(machine, "attributes");
        const char *value =
            tamga_json_as_string(tamga_json_object_get(attributes, "fingerprint"), NULL);
        if (value != NULL && strcmp(value, fingerprint) == 0) {
            const char *id = tamga_json_as_string(tamga_json_object_get(machine, "id"), NULL);
            if (id != NULL) {
                *out_id = tamga_strdup(id);
                return (*out_id != NULL) ? TAMGA_OK : TAMGA_ERR_OUT_OF_MEMORY;
            }
        }
    }
    return TAMGA_OK;
}

TamgaErrorCode tamga_client_find_machine_by_fingerprint(TamgaClient *client, const char *license_id,
                                                        const char *fingerprint,
                                                        char **out_machine_id) {
    uint32_t page;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || fingerprint == NULL || out_machine_id == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "client, fingerprint and out_machine_id are required");
    }
    *out_machine_id = NULL;
    status = tamga_require_uuid(license_id, "license_id");
    if (status != TAMGA_OK) {
        return status;
    }

    for (page = 1u; page <= TAMGA_MACHINE_LOOKUP_MAX_PAGES; page++) {
        TamgaResponse *response = NULL;
        char *found;
        int64_t total_pages = 0;
        bool has_page_meta;

        status = tamga_client_list_machines(client, license_id, fingerprint, page,
                                            TAMGA_MACHINE_PAGE_SIZE, &response);
        if (status != TAMGA_OK || response == NULL) {
            tamga_response_free(response);
            return (status != TAMGA_OK)
                       ? status
                       : tamga_error_set(TAMGA_ERR_UNKNOWN,
                                         "the machine listing returned no response");
        }

        status = tamga_machine_page_exact_match(response, fingerprint, &found);
        has_page_meta = tamga_response_page(response, NULL, NULL, NULL, &total_pages);
        tamga_response_free(response);
        if (status != TAMGA_OK) {
            return tamga_error_set(status, "could not read the machine listing");
        }

        if (found != NULL) {
            *out_machine_id = found;
            return TAMGA_OK;
        }
        /* Stop at the server's own page count. Without `meta.page` -- which
         * only an unexpected body shape would omit -- one page is all that
         * can be justified, because there is nothing to say a second exists. */
        if (!has_page_meta || (int64_t)page >= total_pages) {
            return TAMGA_OK;
        }
    }
    /* The cap was reached with no exact match. Reported as "not found" rather
     * than as an error: the caller's next move is the same either way, and
     * the alternative -- a code meaning "there may be more pages" -- would be
     * a branch nobody can act on. */
    return TAMGA_OK;
}

TamgaErrorCode tamga_client_activate_machine_idempotent(
    TamgaClient *client, const char *license_id, const char *fingerprint, const char *options_json,
    const char *scope_json, bool auto_delete_on_overage, TamgaResponse **out_response) {
    char *existing_id = NULL;
    TamgaErrorCode status;
    TamgaErrorCode lookup;

    tamga_error_clear();
    if (out_response != NULL) {
        *out_response = NULL;
    }

    status = tamga_client_activate_machine(client, license_id, fingerprint, options_json,
                                           scope_json, auto_delete_on_overage, out_response);
    if (status != TAMGA_ERR_FINGERPRINT_TAKEN) {
        return status;
    }
    /*
     * The creation was refused because this fingerprint is already activated.
     * The server's own comment on that branch (tamga-api
     * `src/features/machines/service.rs`) says the conflict means "already
     * activated, carry on" -- it checks uniqueness BEFORE the seat limits
     * precisely so a re-activation is not reported as "buy more seats". This
     * is the carrying on.
     *
     * `tamga_client_activate_machine` has already freed the creation response
     * and left *out_response NULL on this path, so there is nothing to
     * reclaim before the lookup.
     */
    /*
     * The lookup is scoped to the licence being activated, using the server's
     * own `filter[license]`, and that scope is the correctness argument for
     * this whole function. Widening it to the account would be a seat-sharing
     * bug, not a better diagnostic.
     *
     * The conflict is raised under the policy's `machine_uniqueness_strategy`,
     * and all three of its scopes are SUPERSETS of "a machine on this licence
     * with this fingerprint" -- every one of the EXISTS checks in
     * tamga-api `machines/service.rs` includes the caller's own licence rows:
     * UNIQUE_PER_LICENSE matches on `license_id = $2` directly,
     * UNIQUE_PER_POLICY joins licences on the policy this licence already
     * has, and UNIQUE_PER_ACCOUNT covers every machine in the account.
     *
     * So a genuine re-activation raises the conflict under all three, and a
     * licence-scoped lookup finds it under all three. What an account-wide
     * lookup would add is exactly the cross-licence case -- and that is the
     * case the server refuses on purpose: its comment says the wider scopes
     * exist to stop a customer registering one fingerprint against N licences
     * and sharing seats. Returning that machine and reporting success would
     * leave the caller heartbeating and checking out a machine its licence
     * does not own, with its own machines_count still zero, and no way to
     * notice because the resource carries no licence id.
     *
     * The scoped lookup therefore hits in exactly the cases where carrying on
     * is legitimate and misses in exactly the cases where it is not. A caller
     * that wants to know WHICH licence holds the fingerprint can ask
     * account-wide with tamga_client_list_machines(client, NULL, fingerprint,
     * ...); that is a diagnostic, and it is deliberately a separate call.
     *
     * The machine resource carries no licence id and no relationships, so
     * asking the server to filter is also the only way to establish this at
     * all.
     */
    lookup =
        tamga_client_find_machine_by_fingerprint(client, license_id, fingerprint, &existing_id);
    if (lookup == TAMGA_ERR_OUT_OF_MEMORY) {
        return lookup;
    }
    if (lookup != TAMGA_OK) {
        /* The lookup itself failed -- most often 403, because the credential
         * carries no `machine.read`. The activation genuinely did not happen,
         * so the conflict is still the answer, but the reason it could not be
         * resolved is named rather than folded into the branch below. */
        tamga_string_free(existing_id);
        return tamga_error_set(TAMGA_ERR_FINGERPRINT_TAKEN,
                               "the fingerprint is already activated, and the existing machine "
                               "could not be looked up (%s)",
                               tamga_error_name(lookup));
    }
    if (existing_id == NULL) {
        /* This licence really has no machine with that fingerprint, so the
         * conflict belongs to another licence under a wider uniqueness scope.
         * It stands, unchanged. */
        return tamga_error_set(TAMGA_ERR_FINGERPRINT_TAKEN,
                               "the fingerprint is already activated on a different licence "
                               "under the policy's uniqueness scope");
    }

    /*
     * The machine already existed, so this call created nothing and rolls
     * nothing back. `auto_delete_on_overage` governed the creation attempt
     * above and is deliberately not applied here: deleting on an over-limit
     * verdict would destroy a seat that was already paid for and already in
     * use, on a call whose whole purpose is to be a no-op when the machine is
     * present.
     */
    tamga_string_free(existing_id);
    return tamga_client_validate_by_id(client, license_id, scope_json, false, NULL, out_response);
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
    if (root == NULL || meta == NULL || dataset == NULL) {
        tamga_json_free(root);
        tamga_json_free(meta);
        tamga_json_free(dataset);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    /* Attached before it is populated -- see the note in
     * tamga_client_validate_by_id for why the other order leaks. */
    if (!tamga_json_object_set(root, "meta", meta)) {
        tamga_json_free(root);
        tamga_json_free(dataset);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    if (!tamga_json_object_set(meta, "dataset", dataset)) {
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
    /* tamga_require_uuid above already parsed this same string with the
     * same parser, so this cannot fail -- but it is checked rather than
     * discarded, both because GCC rejects (void) as a suppression for a
     * warn_unused_result function and because an invariant that is
     * enforced survives the earlier call being moved. */
    if (!tamga_uuid_normalize(machine_id, canonical)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "machine_id must be a UUID");
    }

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
        /* tamga_require_uuid above already parsed this same string with the
         * same parser, so this cannot fail -- but it is checked rather than
         * discarded, both because GCC rejects (void) as a suppression for a
         * warn_unused_result function and because an invariant that is
         * enforced survives the earlier call being moved. */
        if (!tamga_uuid_normalize(after, canonical)) {
            return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "after must be a UUID");
        }
        if (limit > 0u) {
            tamga_buf_append_byte(&query_buf, '&');
        }
        /* The bracket is percent-encoded: an unescaped one is legal in a
         * query string but not universally handled the same way. */
        tamga_buf_append_str(&query_buf, "page%5Bafter%5D=");
        tamga_buf_append_str(&query_buf, canonical);
    }
    /*
     * Detached unconditionally, and checked. Gating on `len > 0` instead
     * looks equivalent but is not: an append that fails part-way leaves the
     * buffer's sticky failure flag set while `len` still holds the length
     * from before the failure, so the gate passes, the detach correctly
     * returns NULL -- and a NULL query is indistinguishable from "the caller
     * asked for no pagination". The request would go out with no query string
     * and return TAMGA_OK holding the server's default first page instead of
     * the requested one.
     *
     * An empty, never-appended buffer detaches to a non-NULL empty string,
     * which tamga_client_build_url already treats as no query.
     */
    query = tamga_buf_detach_string(&query_buf, NULL);
    tamga_buf_free(&query_buf);
    if (query == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

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

/* Keyset, unlike GET /machines: this nested list keeps its own hand-written
 * cursor query server-side (`limit` + `page[after]`), so
 * tamga_response_next_cursor() is the right accessor here. */
TamgaErrorCode tamga_client_list_machine_processes(TamgaClient *client, const char *machine_id,
                                                   uint32_t limit, const char *after,
                                                   TamgaResponse **out_response) {
    return tamga_list(client, "/machines/", machine_id, "machine_id", "/processes", limit, after,
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
    /* tamga_require_uuid above already parsed this same string with the
     * same parser, so this cannot fail -- but it is checked rather than
     * discarded, both because GCC rejects (void) as a suppression for a
     * warn_unused_result function and because an invariant that is
     * enforced survives the earlier call being moved. */
    if (!tamga_uuid_normalize(machine_id, canonical)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "machine_id must be a UUID");
    }

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

/*
 * Deleting a process is not optional housekeeping.
 *
 * The server has a process reaper, but it is dead code -- nothing calls it
 * (reported upstream) -- so no process row is ever removed automatically. A
 * row that is never deleted keeps counting towards the licence's process
 * total, and the count is what `TOO_MANY_PROCESSES` is checked against. An
 * application that registers a process per run and never disposes of one
 * therefore works until it does not, and the failure lands on a later,
 * innocent run.
 *
 * Pair every tamga_client_create_process() with this on the way out,
 * including on the error paths. It answers `204` whether or not the row was
 * there, so a duplicate call at shutdown is harmless.
 */
TamgaErrorCode tamga_client_delete_process(TamgaClient *client, const char *process_id,
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
    path = tamga_path("/processes/", process_id, NULL);
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }
    status = tamga_client_send(client, "DELETE", path, NULL, NULL, NULL, false, out_response);
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
    /* tamga_require_uuid above already parsed this same string with the
     * same parser, so this cannot fail -- but it is checked rather than
     * discarded, both because GCC rejects (void) as a suppression for a
     * warn_unused_result function and because an invariant that is
     * enforced survives the earlier call being moved. */
    if (!tamga_uuid_normalize(license_id, canonical)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "license_id must be a UUID");
    }
    tamga_buf_append_str(&buf, "/licenses/");
    tamga_buf_append_str(&buf, canonical);
    tamga_buf_append_str(&buf, "/entitlements/");
    /* tamga_require_uuid above already parsed this same string with the
     * same parser, so this cannot fail -- but it is checked rather than
     * discarded, both because GCC rejects (void) as a suppression for a
     * warn_unused_result function and because an invariant that is
     * enforced survives the earlier call being moved. */
    if (!tamga_uuid_normalize(entitlement_id, canonical)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "entitlement_id must be a UUID");
    }
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
    if (status != TAMGA_OK || response == NULL) {
        tamga_response_free(response);
        return (status != TAMGA_OK)
                   ? status
                   : tamga_error_set(TAMGA_ERR_UNKNOWN, "the entitlement listing returned no "
                                                        "response");
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

/* --- signing keys -------------------------------------------------------- */

/*
 * `GET /signing-keys` -- the account's whole Ed25519 key history, retired keys
 * included, which is the point: a file checked out before a rotation names the
 * key that signed it, and without that key it fails verification with the same
 * error a forged file produces.
 *
 * Not paginated and takes no cursor. The route reads the whole
 * `account_signing_keys` table for the account, which is a handful of rows,
 * and answers with no `meta` -- so neither tamga_response_page() nor
 * tamga_response_next_cursor() applies here.
 *
 * ⚠️ Needs `account.read`, which `Role::LicenseToken` does not carry, so a
 * licence-key credential gets `403`. Unlike `policy.read` there is no second
 * route to the same resource, which is why tamga_signing_key_set_add_json()
 * takes bytes rather than a client: an embedded client has to be given the
 * document rather than fetch it.
 *
 * ⚠️ `{"data": []}` is the ordinary answer for an account that has never
 * rotated -- the table is written only by the rotation handler, which
 * backfills the current key on its way through. Empty means "nothing has
 * rotated yet", not "this account has no signing key".
 */
TamgaErrorCode tamga_client_list_signing_keys(TamgaClient *client, TamgaResponse **out_response) {
    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    return tamga_client_send(client, "GET", "/signing-keys", NULL, NULL, NULL, false, out_response);
}

/* --- releases ------------------------------------------------------------ */

/*
 * `204 No Content` from this route means TWO things, and the server cannot
 * tell them apart on purpose:
 *
 *   - there is no newer release (upgrade_release.rs, the `else` on
 *     `result.next_release`); or
 *   - there IS a newer release and this licence is not entitled to it,
 *     because the licence has expired under an expiration strategy that
 *     stops new builds. The server's own comment says why it answers 204
 *     rather than denying: a denial would leak "a newer version exists but
 *     you cannot have it".
 *
 * So a `204` must NOT be reported to a user as "you are up to date". The
 * honest wording is "there is no update available to you". There is no
 * client-side way to separate the two and there is not meant to be.
 *
 * A `403` is separate again and does not mean either of those: a suspended
 * licence, or a product whose distribution strategy excludes this caller.
 */
TamgaErrorCode tamga_client_check_upgrade(TamgaClient *client, const char *product_id,
                                          const char *platform, const char *filetype,
                                          const char *version, const char *channel,
                                          const char *constraint, TamgaResponse **out_response) {
    TamgaBuf query_buf;
    bool first = true;
    bool built;
    char canonical[TAMGA_UUID_STRING_SIZE];
    char *query;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || platform == NULL || filetype == NULL || version == NULL ||
        out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT,
                               "client, platform, filetype, version and out_response are "
                               "required");
    }
    status = tamga_require_uuid(product_id, "product_id");
    if (status != TAMGA_OK) {
        return status;
    }
    /* tamga_require_uuid above already parsed this same string with the same
     * parser, so this cannot fail -- but it is checked rather than discarded,
     * both because GCC rejects (void) as a suppression for a
     * warn_unused_result function and because an invariant that is enforced
     * survives the earlier call being moved. */
    if (!tamga_uuid_normalize(product_id, canonical)) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "product_id must be a UUID");
    }

    /* All four of product/platform/filetype/version are required server-side:
     * UpgradeQuery declares them as non-Option fields, so omitting one is a
     * 400 at extraction rather than a defaulted search. */
    tamga_buf_init(&query_buf);
    built = tamga_query_add(&query_buf, &first, "product", canonical) &&
            tamga_query_add(&query_buf, &first, "platform", platform) &&
            tamga_query_add(&query_buf, &first, "filetype", filetype) &&
            tamga_query_add(&query_buf, &first, "version", version);
    if (built && channel != NULL) {
        built = tamga_query_add(&query_buf, &first, "channel", channel);
    }
    if (built && constraint != NULL) {
        built = tamga_query_add(&query_buf, &first, "constraint", constraint);
    }
    query = tamga_buf_detach_string(&query_buf, NULL);
    tamga_buf_free(&query_buf);
    if (!built || query == NULL) {
        tamga_string_free(query);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "GET", "/releases/actions/upgrade", query, NULL, NULL, false,
                               out_response);
    tamga_string_free(query);
    return status;
}

/* --- artifacts ----------------------------------------------------------- */

/*
 * Read and download only. `artifact.create`, `artifact.update` and
 * `artifact.delete` are absent from Role::LicenseToken
 * (shared/authz/mod.rs:241-268), so an embedded client cannot publish a build
 * however the SDK asks -- those routes would be a 403 for every credential
 * this library is meant to carry. `artifact.read` and `artifact.download` ARE
 * on that list, which is what makes this surface reachable.
 *
 * Only ONE of the two is new. `artifact.read` (:264) was already there, so the
 * listing and the metadata read were reachable all along and simply had no
 * SDK method; e6d317b added `artifact.download` (:265) alone. So the gap this
 * closes is not symmetric -- the metadata half was an omission on our side,
 * and the bytes half was genuinely a 403 no client could get past.
 */

TamgaErrorCode tamga_client_list_release_artifacts(TamgaClient *client, const char *release_id,
                                                   uint32_t limit, const char *after,
                                                   TamgaResponse **out_response) {
    return tamga_list(client, "/releases/", release_id, "release_id", "/artifacts", limit, after,
                      out_response);
}

TamgaErrorCode tamga_client_get_artifact(TamgaClient *client, const char *artifact_id,
                                         TamgaResponse **out_response) {
    return tamga_get_resource(client, "/artifacts/", artifact_id, "artifact_id", NULL,
                              out_response);
}

/*
 * The download action, and the reason it is not a plain GET.
 *
 * By default this route answers `303 See Other` with a Location pointing at a
 * short-lived presigned URL on the object store. A client that follows that
 * redirect with the request's headers still attached hands the caller's
 * licence key -- or bearer token -- to the storage host.
 *
 * MEASURED, against libcurl 8.7.1 driving this very transport at a local
 * server that answers 303, with CURLOPT_FOLLOWLOCATION forced to 1. Every auth
 * kind this SDK supports was driven separately, because a rule about one
 * credential is not a rule about another:
 *
 *   credential                    same-origin hop   cross-origin hop
 *   TAMGA_AUTH_LICENSE            SENT INTACT       stripped
 *   TAMGA_AUTH_BEARER             SENT INTACT       stripped
 *   TAMGA_AUTH_BASIC_*            SENT INTACT       stripped
 *   TAMGA_AUTH_QUERY_TOKEN        not sent          not sent
 *   Tamga-OTP header              SENT INTACT       SENT INTACT
 *
 * ⚠️ Read the last row before the first three. On THIS libcurl, `Tamga-OTP` --
 * which carries a one-time password -- was forwarded to a DIFFERENT HOST,
 * while `Authorization` was stripped there. So the credential most exposed is
 * the one not called `Authorization`, which is the opposite of where attention
 * naturally goes.
 *
 * Resist turning that into a rule. It is tempting to conclude that platforms
 * protect the header NAMED `Authorization` rather than credentials by nature,
 * and across this SDK family that generalisation has already failed: five
 * runtimes were measured and produced five distinct behaviours, including one
 * that strips a directly-set `Cookie` cross-origin and one that strips
 * `Authorization` even same-origin. The only claim that survived every
 * measurement is the negative one -- YOU CANNOT KNOW WHAT A REDIRECT FORWARDS
 * WITHOUT WATCHING IT -- which is precisely why the design here does not
 * depend on the answer.
 *
 * The query-token form leaks by neither route, because the Location replaces
 * the URL and the `?token=` goes with it. There is no cookie credential in
 * this SDK.
 *
 * One more thing that measurement turned up: because non-GET requests go out
 * through CURLOPT_CUSTOMREQUEST, a followed 303 was re-sent as POST rather
 * than converted to GET as 303 requires -- so a POST carrying an OTP would be
 * REPLAYED against the redirect target. Another reason the safe state is not
 * following at all.
 *
 * So the Authorization leak needs a same-origin redirect -- exactly the shape
 * the server's `s3_endpoint` + `s3_force_path_style` settings produce when
 * storage is served from the API's own origin -- while the OTP leak needs no
 * such thing. Do not generalise any of it: CURLOPT_UNRESTRICTED_AUTH's default
 * has varied across libcurl versions, and a caller-registered transport
 * follows whatever rule its own stack implements. Five runtimes measured across
 * this SDK family produced five distinct behaviours, so the table above is
 * data about one libcurl build and not a prediction about anything else.
 *
 * With FOLLOWLOCATION at 0 -- what this repo actually ships, and what the same
 * probe confirms -- no redirect is followed at all, so the question does not
 * arise and UNRESTRICTED_AUTH is moot. transport_winhttp.c sets
 * WINHTTP_OPTION_REDIRECT_POLICY_NEVER for the same reason; WinHTTP follows by
 * default, so that one is a correction rather than a default.
 *
 * But a transport registered through tamga_client_set_transport() is the
 * caller's own HTTP stack and most follow redirects out of the box, so the 303
 * is never requested in the first place: `redirect=false` makes the server
 * return the artifact resource with `redirectUrl` populated instead. The URL is
 * then the caller's to fetch with NO credentials attached -- it carries its own
 * signature, and adding an Authorization header to it is both unnecessary and
 * the leak this avoids. There is deliberately no parameter for asking for the
 * redirect form.
 *
 * There is a second reason that holds whatever any transport does about
 * headers: following the redirect streams the artifact's BYTES into the
 * response buffer before anything can reject them. Responses here are capped
 * (TAMGA_TRANSPORT_FAIL_OVERSIZED), and a real artifact routinely exceeds any
 * sane cap -- so a followed download either fails late having buffered a large
 * file, or succeeds and hands back a body no accessor in this SDK can read.
 */
TamgaErrorCode tamga_client_get_artifact_download_url(TamgaClient *client, const char *artifact_id,
                                                      uint32_t ttl_seconds,
                                                      TamgaResponse **out_response) {
    TamgaBuf query_buf;
    char *path;
    char *query;
    TamgaErrorCode status;

    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    status = tamga_require_uuid(artifact_id, "artifact_id");
    if (status != TAMGA_OK) {
        return status;
    }
    /*
     * Checked here rather than left to the server, which answers `422
     * PRESIGN_TTL_INVALID` -- a round trip that spends a request and a retry
     * budget to learn something this side already knows.
     * artifacts/service.rs's PRESIGN_TTL_MIN/PRESIGN_TTL_MAX are the bounds.
     */
    if (ttl_seconds != 0u && (ttl_seconds < TAMGA_PRESIGN_TTL_MIN_SECONDS ||
                              ttl_seconds > TAMGA_PRESIGN_TTL_MAX_SECONDS)) {
        return tamga_error_set(
            TAMGA_ERR_TTL_INVALID, "ttl must be between %u seconds and %u seconds (1 week)",
            (unsigned)TAMGA_PRESIGN_TTL_MIN_SECONDS, (unsigned)TAMGA_PRESIGN_TTL_MAX_SECONDS);
    }

    path = tamga_path("/artifacts/", artifact_id, "/actions/download");
    if (path == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    tamga_buf_init(&query_buf);
    /* Always, and never from a caller-supplied flag: see the comment above. */
    tamga_buf_append_str(&query_buf, "redirect=false");
    if (ttl_seconds != 0u) {
        tamga_buf_append_fmt(&query_buf, "&ttl=%lu", (unsigned long)ttl_seconds);
    }
    query = tamga_buf_detach_string(&query_buf, NULL);
    tamga_buf_free(&query_buf);
    if (query == NULL) {
        tamga_string_free(path);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the request");
    }

    status = tamga_client_send(client, "GET", path, query, NULL, NULL, false, out_response);
    tamga_string_free(query);
    tamga_string_free(path);
    return status;
}

/* --- health -------------------------------------------------------------- */

/*
 * The one route in this SDK that is not account-scoped.
 *
 * `/v1/health` is registered outside the account router, is on the server's
 * public-route allowlist, and bypasses the host-header middleware. Every URL
 * builder in this SDK family unconditionally prepended
 * `/v1/accounts/{account_id}`, which is why no SDK could call it -- the
 * restriction was ours, not the server's.
 *
 * Its diagnostic value is exactly that combination: if every ordinary call
 * answers `403` with "The Host header does not match any configured host"
 * while this one succeeds, the problem is the deployment's
 * `TAMGA_ALLOWED_HOSTS`, not the caller's credential.
 *
 * The body is a flat `{status, version, uptime_secs}` -- NOT a JSON:API
 * document. Do not put it through anything that expects a `data` envelope.
 *
 * A credential is still sent, because this client has no unauthenticated
 * mode and tamga_client_set_auth() is a precondition of every request. The
 * route ignores it.
 */
TamgaErrorCode tamga_client_health(TamgaClient *client, TamgaResponse **out_response) {
    tamga_error_clear();
    if (client == NULL || out_response == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "client and out_response are required");
    }
    return tamga_client_send_scoped(client, TAMGA_PATH_ORIGIN, "GET", "/v1/health", NULL, NULL,
                                    NULL, false, out_response);
}
