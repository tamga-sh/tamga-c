/*
 * One assertion per endpoint: the method, the path and the body shape that
 * would go over the wire.
 *
 * These are the tests that catch a protocol mistake -- a JSON:API envelope
 * where the server wants a flat body, a query parameter on the wrong verb, an
 * identifier interpolated without normalisation. None of that is visible from
 * the C signatures, and all of it is a silent failure against a real server.
 */
#include "tamga_test.h"

#include "mock_transport.h"
#include "tamga_error.h"

static const char ACCOUNT[] = "01926b3e-0000-7000-8000-0000000000aa";
static const char LICENSE_ID[] = "01926b3e-0000-7000-8000-000000000001";
static const char MACHINE_ID[] = "01926b3e-0000-7000-8000-000000000002";
static const char PROCESS_ID[] = "01926b3e-0000-7000-8000-000000000003";
static const char ENTITLEMENT_ID[] = "01926b3e-0000-7000-8000-000000000004";
static const char POLICY_ID[] = "01926b3e-0000-7000-8000-000000000005";
static const char PRODUCT_ID[] = "01926b3e-0000-7000-8000-000000000006";

static const char *const BASE = "https://api.tamga.sh/v1/accounts/"
                                "01926b3e-0000-7000-8000-0000000000aa";

static TamgaClient *make_client(MockTransport *mock) {
    TamgaClient *client = NULL;
    if (tamga_client_new(ACCOUNT, "api.tamga.sh", &client) != TAMGA_OK) {
        return NULL;
    }
    if (tamga_client_set_auth(client, TAMGA_AUTH_BEARER, "tok", NULL) != TAMGA_OK ||
        tamga_client_set_transport(client, mock_perform, mock, NULL) != TAMGA_OK) {
        tamga_client_free(client);
        return NULL;
    }
    return client;
}

/* Asserts the single recorded call's method and path-relative URL. */
static void expect_call(const MockTransport *mock, const char *method, const char *suffix) {
    char expected[MOCK_BUF];

    if (mock->call_count != 1u) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: expected 1 call, got %zu\n", tt_current_, mock->call_count);
        return;
    }
    (void)snprintf(expected, sizeof(expected), "%s%s", BASE, suffix);
    if (strcmp(mock->calls[0].method, method) != 0) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: method %s, expected %s\n", tt_current_,
                      mock->calls[0].method, method);
    }
    if (strcmp(mock->calls[0].url, expected) != 0) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s\n  url:      %s\n  expected: %s\n", tt_current_,
                      mock->calls[0].url, expected);
    }
}

static void expect_body(const MockTransport *mock, const char *expected) {
    if (mock->call_count == 0u) {
        return;
    }
    if (strcmp(mock->calls[0].body, expected) != 0) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s\n  body:     %s\n  expected: %s\n", tt_current_,
                      mock->calls[0].body, expected);
    }
}

#define WITH_CLIENT(block)                                                                         \
    do {                                                                                           \
        MockTransport mock;                                                                        \
        TamgaClient *client;                                                                       \
        TamgaResponse *response = NULL;                                                            \
        mock_reset(&mock);                                                                         \
        client = make_client(&mock);                                                               \
        TT_ASSERT_NOT_NULL(client);                                                                \
        block;                                                                                     \
        tamga_response_free(response);                                                             \
        tamga_client_free(client);                                                                 \
    } while (0)

TT_TEST(validate_by_key) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_validate_by_key(client, "KEY-1", NULL, &response), TAMGA_OK);
        expect_call(&mock, "POST", "/licenses/actions/validate-key");
        expect_body(&mock, "{\"key\":\"KEY-1\"}");
    });
}

TT_TEST(validate_by_id_with_and_without_scope) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_validate_by_id(client, LICENSE_ID, NULL, false, NULL, &response),
            TAMGA_OK);
        expect_call(&mock, "POST",
                    "/licenses/01926b3e-0000-7000-8000-000000000001/actions/validate");
        expect_body(&mock, "{\"meta\":{\"skip_touch\":false}}");
    });

    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_validate_by_id(client, LICENSE_ID,
                                        "{\"product\":\"01926b3e-0000-7000-8000-00000000000b\"}",
                                        true, NULL, &response),
            TAMGA_OK);
        expect_body(&mock, "{\"meta\":{\"skip_touch\":true,\"scope\":"
                           "{\"product\":\"01926b3e-0000-7000-8000-00000000000b\"}}}");
    });
}

/* Quick-validate is a GET with no body -- it returns the flat outcome and
 * skips the licence resource entirely. */
TT_TEST(quick_validate) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_quick_validate(client, LICENSE_ID, NULL, &response),
                         TAMGA_OK);
        expect_call(&mock, "GET",
                    "/licenses/01926b3e-0000-7000-8000-000000000001/actions/validate");
        expect_body(&mock, "");
    });
}

/*
 * Alone among the validation endpoints, quick-validate answers with a FLAT
 * body -- `{ts, valid, detail, code}` with no `data` envelope. A decoder that
 * assumes the envelope reads nothing out of it and reports every licence as
 * invalid, which looks like a licensing problem rather than a parsing one.
 */
TT_TEST(quick_validate_decodes_a_flat_body) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 200,
               "{\"ts\":\"2026-08-20T00:00:00Z\",\"valid\":true,"
               "\"detail\":\"is valid\",\"code\":\"VALID\"}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_quick_validate(client, LICENSE_ID, NULL, &response), TAMGA_OK);
    TT_ASSERT(tamga_response_validation_is_valid(response));
    TT_ASSERT_EQ_STR(tamga_response_validation_code(response), "VALID");
    TT_ASSERT_EQ_STR(tamga_response_validation_detail(response), "is valid");
    TT_ASSERT_EQ_INT(tamga_response_validation_code_enum(response), TAMGA_VALIDATION_VALID);

    tamga_response_free(response);
    tamga_client_free(client);
}

TT_TEST(check_in) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_OK);
        expect_call(&mock, "POST",
                    "/licenses/01926b3e-0000-7000-8000-000000000001/actions/check-in");
        expect_body(&mock, "");
    });
}

/* The raw checkout is a GET carrying its options as query parameters; the
 * JSON:API variant is a POST carrying them in a meta object. */
TT_TEST(licence_checkout_both_forms) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_check_out_license(client, LICENSE_ID, true, 3600, &response),
                         TAMGA_OK);
        expect_call(&mock, "GET",
                    "/licenses/01926b3e-0000-7000-8000-000000000001/actions/check-out"
                    "?encrypt=true&ttl=3600");
    });

    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_check_out_license_json(client, LICENSE_ID, false, 0, &response), TAMGA_OK);
        expect_call(&mock, "POST",
                    "/licenses/01926b3e-0000-7000-8000-000000000001/actions/check-out");
        expect_body(&mock, "{\"meta\":{\"encrypt\":false,\"ttl\":null}}");
    });
}

TT_TEST(machine_checkout_both_forms) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_check_out_machine(client, MACHINE_ID, false, 0, &response),
                         TAMGA_OK);
        expect_call(&mock, "GET",
                    "/machines/01926b3e-0000-7000-8000-000000000002/actions/check-out"
                    "?encrypt=false");
    });

    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_check_out_machine_json(client, MACHINE_ID, true, 60, &response), TAMGA_OK);
        expect_call(&mock, "POST",
                    "/machines/01926b3e-0000-7000-8000-000000000002/actions/check-out");
        expect_body(&mock, "{\"meta\":{\"encrypt\":true,\"ttl\":60}}");
    });
}

/* The ttl range is pre-checked client-side, so a caller gets a typed error
 * before the round trip instead of only discovering it as a 422. */
TT_TEST(an_out_of_range_ttl_never_reaches_the_server) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_check_out_machine(client, MACHINE_ID, false, 31536001, &response),
            TAMGA_ERR_TTL_INVALID);
        TT_ASSERT_EQ_SIZE(mock.call_count, 0u);
    });
}

/* Machine creation IS JSON:API-enveloped, with the licence as a
 * relationship. */
TT_TEST(create_machine_uses_the_json_api_envelope) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_create_machine(client, LICENSE_ID, "fp-1", NULL, &response),
                         TAMGA_OK);
        expect_call(&mock, "POST", "/machines");
        expect_body(&mock, "{\"data\":{\"type\":\"machines\","
                           "\"attributes\":{\"fingerprint\":\"fp-1\"},"
                           "\"relationships\":{\"license\":{\"data\":{\"type\":\"licenses\","
                           "\"id\":\"01926b3e-0000-7000-8000-000000000001\"}}}}}");
    });
}

/* Only the recognised optional attributes are forwarded. Copying the caller's
 * object wholesale would let an unrelated key reach the server as an
 * attribute -- a different request than the one they asked for. */
TT_TEST(create_machine_forwards_only_known_options) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_create_machine(client, LICENSE_ID, "fp-1",
                                                     "{\"cores\":8,\"hostname\":\"build-01\","
                                                     "\"unexpected\":\"dropped\"}",
                                                     &response),
                         TAMGA_OK);
        TT_ASSERT_NULL(strstr(mock.calls[0].body, "unexpected"));
        TT_ASSERT_NOT_NULL(strstr(mock.calls[0].body, "\"cores\":8"));
        TT_ASSERT_NOT_NULL(strstr(mock.calls[0].body, "\"hostname\":\"build-01\""));
    });
}

TT_TEST(machine_actions) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_ping_heartbeat(client, MACHINE_ID, &response), TAMGA_OK);
        expect_call(&mock, "POST",
                    "/machines/01926b3e-0000-7000-8000-000000000002/actions/ping-heartbeat");
    });
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_reset_heartbeat(client, MACHINE_ID, &response), TAMGA_OK);
        expect_call(&mock, "POST",
                    "/machines/01926b3e-0000-7000-8000-000000000002/actions/reset-heartbeat");
    });
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_delete_machine(client, MACHINE_ID, &response), TAMGA_OK);
        expect_call(&mock, "DELETE", "/machines/01926b3e-0000-7000-8000-000000000002");
    });
}

TT_TEST(generate_offline_proof_defaults_the_dataset_to_an_object) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_generate_offline_proof(client, MACHINE_ID, NULL, &response),
                         TAMGA_OK);
        expect_call(&mock, "POST",
                    "/machines/01926b3e-0000-7000-8000-000000000002"
                    "/actions/generate-offline-proof");
        expect_body(&mock, "{\"meta\":{\"dataset\":{}}}");
    });

    /* The server rejects a non-object dataset with 422; catching it here
     * saves the round trip and gives a clearer message. */
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_generate_offline_proof(client, MACHINE_ID, "[1,2]", &response),
            TAMGA_ERR_INVALID_JSON);
        TT_ASSERT_EQ_SIZE(mock.call_count, 0u);
    });
}

/*
 * ⚠️ Components and processes take FLAT bodies, unlike machine creation. That
 * asymmetry is the server's; sending a JSON:API envelope here fails.
 */
TT_TEST(components_and_processes_use_flat_bodies) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_create_component(client, MACHINE_ID, "cfp", "GPU", NULL, &response),
            TAMGA_OK);
        expect_call(&mock, "POST", "/components");
        expect_body(&mock, "{\"machine_id\":\"01926b3e-0000-7000-8000-000000000002\","
                           "\"fingerprint\":\"cfp\",\"name\":\"GPU\",\"metadata\":{}}");
    });

    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_create_process(client, MACHINE_ID, "4242",
                                                     "{\"role\":\"worker\"}", &response),
                         TAMGA_OK);
        expect_call(&mock, "POST", "/processes");
        expect_body(&mock, "{\"machine_id\":\"01926b3e-0000-7000-8000-000000000002\","
                           "\"pid\":\"4242\",\"metadata\":{\"role\":\"worker\"}}");
    });

    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_ping_process(client, PROCESS_ID, &response), TAMGA_OK);
        expect_call(&mock, "POST", "/processes/01926b3e-0000-7000-8000-000000000003/actions/ping");
    });
}

TT_TEST(listings_are_keyset_paginated) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_list_components(client, MACHINE_ID, 0u, NULL, &response),
                         TAMGA_OK);
        expect_call(&mock, "GET", "/machines/01926b3e-0000-7000-8000-000000000002/components");
    });

    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_list_components(client, MACHINE_ID, 25u, ENTITLEMENT_ID, &response),
            TAMGA_OK);
        expect_call(&mock, "GET",
                    "/machines/01926b3e-0000-7000-8000-000000000002/components"
                    "?limit=25&page%5Bafter%5D=01926b3e-0000-7000-8000-000000000004");
    });

    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_list_entitlements(client, LICENSE_ID, 10u, NULL, &response),
                         TAMGA_OK);
        expect_call(&mock, "GET",
                    "/licenses/01926b3e-0000-7000-8000-000000000001/entitlements?limit=10");
    });

    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_get_entitlement(client, LICENSE_ID, ENTITLEMENT_ID, &response), TAMGA_OK);
        expect_call(&mock, "GET",
                    "/licenses/01926b3e-0000-7000-8000-000000000001/entitlements/"
                    "01926b3e-0000-7000-8000-000000000004");
    });
}

/*
 * The next-page cursor is derived, not read: the server sends no cursor
 * metadata and no links, so it is the last item's id and ONLY when the page
 * came back exactly full.
 *
 * Both halves matter. Treating a non-empty short page as "there may be more"
 * loops forever against the same tail; treating a full page as the end drops
 * every record after the first page. The rule is easy to state and easy to
 * get subtly wrong, which is why it lives in the SDK rather than in each
 * caller.
 */
TT_TEST(the_next_page_cursor_is_derived_from_a_full_page_only) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    /* A full page: limit 2, two items -> the last item's id. */
    mock_reset(&mock);
    mock_reply(&mock, 200,
               "{\"data\":[{\"id\":\"comp-1\",\"type\":\"components\"},"
               "{\"id\":\"comp-2\",\"type\":\"components\"}]}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_list_components(client, MACHINE_ID, 2u, NULL, &response),
                     TAMGA_OK);
    TT_ASSERT_EQ_STR(tamga_response_next_cursor(response, 2u), "comp-2");
    tamga_response_free(response);
    response = NULL;
    tamga_client_free(client);

    /* A short page is the last page, even though it is not empty. */
    mock_reset(&mock);
    mock_reply(&mock, 200, "{\"data\":[{\"id\":\"comp-1\",\"type\":\"components\"}]}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_list_components(client, MACHINE_ID, 2u, NULL, &response),
                     TAMGA_OK);
    TT_ASSERT_NULL(tamga_response_next_cursor(response, 2u));
    tamga_response_free(response);
    response = NULL;
    tamga_client_free(client);

    /* An empty page, and a listing made with no limit at all -- with no limit
     * there is no "full" to compare against, so there is no cursor. */
    mock_reset(&mock);
    mock_reply(&mock, 200, "{\"data\":[]}");
    mock_reply(&mock, 200, "{\"data\":[{\"id\":\"ent-1\",\"type\":\"entitlements\"}]}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_list_components(client, MACHINE_ID, 2u, NULL, &response),
                     TAMGA_OK);
    TT_ASSERT_NULL(tamga_response_next_cursor(response, 2u));
    tamga_response_free(response);
    response = NULL;
    TT_ASSERT_EQ_INT(tamga_client_list_entitlements(client, LICENSE_ID, 0u, NULL, &response),
                     TAMGA_OK);
    TT_ASSERT_NULL(tamga_response_next_cursor(response, 0u));
    tamga_response_free(response);
    tamga_client_free(client);
}

/* Matched on `code`, the stable identifier -- never on `name`, which is a
 * display label and may be reworded. */
TT_TEST(has_entitlement_matches_on_code_not_name) {
    MockTransport mock;
    TamgaClient *client;
    bool has = false;

    mock_reset(&mock);
    mock_reply(&mock, 200,
               "{\"data\":[{\"id\":\"a\",\"type\":\"entitlements\","
               "\"attributes\":{\"code\":\"PRO_FEATURES\",\"name\":\"Pro\"}}]}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_has_entitlement(client, LICENSE_ID, "PRO_FEATURES", 0u, &has),
                     TAMGA_OK);
    TT_ASSERT(has);
    /* The display name must not match. */
    TT_ASSERT_EQ_INT(tamga_client_has_entitlement(client, LICENSE_ID, "Pro", 0u, &has), TAMGA_OK);
    TT_ASSERT_FALSE(has);
    TT_ASSERT_EQ_INT(tamga_client_has_entitlement(client, LICENSE_ID, "ABSENT", 0u, &has),
                     TAMGA_OK);
    TT_ASSERT_FALSE(has);

    tamga_client_free(client);
}

/*
 * Creation enforces the licence's limits too. Which of the two ways an
 * over-limit activation is reported depends on the policy's overage strategy,
 * and both are live -- which is why these calls are composed rather than left
 * to the caller to remember to pair.
 */
TT_TEST(activate_machine_creates_then_validates) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 201, "{\"data\":{\"id\":\"01926b3e-0000-7000-8000-000000000002\"}}");
    mock_reply(&mock, 200, "{\"data\":{},\"meta\":{\"valid\":true,\"code\":\"VALID\"}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(
        tamga_client_activate_machine(client, LICENSE_ID, "fp-1", NULL, NULL, true, &response),
        TAMGA_OK);
    TT_ASSERT_EQ_SIZE(mock.call_count, 2u);
    TT_ASSERT_EQ_STR(mock.calls[0].method, "POST");
    TT_ASSERT_NOT_NULL(strstr(mock.calls[0].url, "/machines"));
    TT_ASSERT_NOT_NULL(strstr(mock.calls[1].url, "/actions/validate"));
    TT_ASSERT(tamga_response_validation_is_valid(response));

    tamga_response_free(response);
    tamga_client_free(client);
}

/*
 * A strict overage strategy rejects the CREATE itself, so there is no machine
 * row and nothing to roll back. The rollback DELETE must not be issued --
 * it would address a machine that was never made -- and the validation must
 * not be attempted either, because the activation already failed.
 *
 * The body is the server's real shape: JSON:API `status` is the STRING "422".
 */
TT_TEST(activate_machine_reports_a_creation_time_limit_without_deleting) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 422,
               "{\"errors\":[{\"id\":\"01926b3e-0000-7000-8000-00000000000f\","
               "\"status\":\"422\",\"code\":\"MACHINE_LIMIT_EXCEEDED\","
               "\"title\":\"Unprocessable Entity\",\"detail\":\"machine limit exceeded\"}]}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(
        tamga_client_activate_machine(client, LICENSE_ID, "fp-1", NULL, NULL, true, &response),
        TAMGA_ERR_MACHINE_LIMIT_EXCEEDED);

    /* Exactly one call: the create. No validate, and above all no DELETE. */
    TT_ASSERT_EQ_SIZE(mock.call_count, 1u);
    TT_ASSERT_EQ_STR(mock.calls[0].method, "POST");
    TT_ASSERT_NOT_NULL(strstr(mock.calls[0].url, "/machines"));

    /* The creation error is handed back, so the server's own code survives. */
    TT_ASSERT_NOT_NULL(response);
    TT_ASSERT_EQ_INT(tamga_response_status(response), 422);
    TT_ASSERT_EQ_STR(tamga_response_error_code(response), "MACHINE_LIMIT_EXCEEDED");

    /* And it folds onto the validation code that means the same thing, so one
     * caller branch covers both strategies. */
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error(TAMGA_ERR_MACHINE_LIMIT_EXCEEDED),
                     TAMGA_VALIDATION_TOO_MANY_MACHINES);
    TT_ASSERT(tamga_validation_code_is_overage(
        tamga_validation_code_from_error(TAMGA_ERR_MACHINE_LIMIT_EXCEEDED)));

    tamga_response_free(response);
    tamga_client_free(client);
}

/*
 * The mirror of the test above, and the reason that one asserts a non-NULL
 * response rather than shrugging at it.
 *
 * Handing the creation response back is scoped to the create-time LIMIT codes
 * alone. Every other creation failure keeps the 1.3.0 contract exactly --
 * `*out_response` stays NULL and the creation response is freed internally --
 * because a caller written against 1.3.0 learned that and does not free on
 * that path. Widening it would leak one TamgaResponse per failed activation
 * in code that did not change, on a patch upgrade.
 *
 * 409 FINGERPRINT_TAKEN is the case that matters in practice: it is what a
 * second launch on an already-activated machine looks like, so it is the
 * creation failure a real integration hits most.
 */
TT_TEST(a_non_limit_creation_failure_hands_back_no_response) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 409,
               "{\"errors\":[{\"status\":\"409\",\"code\":\"FINGERPRINT_TAKEN\","
               "\"title\":\"Conflict\",\"detail\":\"fingerprint is already taken\"}]}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(
        tamga_client_activate_machine(client, LICENSE_ID, "fp-1", NULL, NULL, true, &response),
        TAMGA_ERR_FINGERPRINT_TAKEN);

    /* Still only the create -- no validate, no DELETE. */
    TT_ASSERT_EQ_SIZE(mock.call_count, 1u);
    /* And nothing handed back, so a 1.3.0 caller that does not free here
     * still does not leak. ASan's LeakSanitizer proves the response was
     * actually freed internally rather than dropped. */
    TT_ASSERT_NULL(response);

    tamga_response_free(response);
    tamga_client_free(client);
}

/*
 * The same licence state under ALLOW_ACCESS / ALLOW_1_25X_OVERAGE: the
 * server's create-time limit check runs through the policy's overage strategy
 * and lets the creation through, so the limit only appears at validation --
 * and the rollback path is the only thing that stops an orphaned machine row
 * being left behind. This is why the create-time branch above is an addition
 * to this path rather than a replacement for it.
 */
TT_TEST(activate_machine_still_rolls_back_when_the_overage_strategy_allows_the_create) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    /* 201, not 422: the overage strategy allowed it. */
    mock_reply(&mock, 201,
               "{\"data\":{\"type\":\"machines\",\"id\":\"01926b3e-0000-7000-8000-000000000002\","
               "\"attributes\":{\"fingerprint\":\"fp-1\",\"cores\":4,\"memory\":16384,"
               "\"disk\":512000}}}");
    mock_reply(&mock, 200,
               "{\"data\":{\"type\":\"licenses\",\"id\":\"01926b3e-0000-7000-8000-000000000001\"},"
               "\"meta\":{\"ts\":\"2026-08-21T00:00:00Z\",\"valid\":false,"
               "\"detail\":\"too many machines\",\"code\":\"TOO_MANY_MACHINES\"}}");
    mock_reply(&mock, 204, "");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(
        tamga_client_activate_machine(client, LICENSE_ID, "fp-1", NULL, NULL, true, &response),
        TAMGA_OK);

    TT_ASSERT_EQ_SIZE(mock.call_count, 3u);
    TT_ASSERT_EQ_STR(mock.calls[1].method, "POST");
    TT_ASSERT_NOT_NULL(strstr(mock.calls[1].url, "/actions/validate"));
    TT_ASSERT_EQ_STR(mock.calls[2].method, "DELETE");
    TT_ASSERT_NOT_NULL(strstr(mock.calls[2].url, "/machines/01926b3e-0000-7000-8000-000000000002"));

    TT_ASSERT_FALSE(tamga_response_validation_is_valid(response));
    TT_ASSERT_EQ_INT(tamga_response_validation_code_enum(response),
                     TAMGA_VALIDATION_TOO_MANY_MACHINES);

    tamga_response_free(response);
    tamga_client_free(client);
}

/* An over-limit activation is undone, so a rejected activation does not leave
 * an orphaned machine row behind. */
TT_TEST(activate_machine_undoes_an_over_limit_activation) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 201, "{\"data\":{\"id\":\"01926b3e-0000-7000-8000-000000000002\"}}");
    mock_reply(&mock, 200,
               "{\"data\":{},\"meta\":{\"valid\":false,\"code\":\"TOO_MANY_MACHINES\"}}");
    mock_reply(&mock, 204, "");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(
        tamga_client_activate_machine(client, LICENSE_ID, "fp-1", NULL, NULL, true, &response),
        TAMGA_OK);
    TT_ASSERT_EQ_SIZE(mock.call_count, 3u);
    TT_ASSERT_EQ_STR(mock.calls[2].method, "DELETE");
    TT_ASSERT_NOT_NULL(strstr(mock.calls[2].url, "/machines/01926b3e-0000-7000-8000-000000000002"));
    /* The validation result is what the caller gets back, not the deletion. */
    TT_ASSERT_FALSE(tamga_response_validation_is_valid(response));
    TT_ASSERT_EQ_STR(tamga_response_validation_code(response), "TOO_MANY_MACHINES");

    tamga_response_free(response);
    tamga_client_free(client);
}

/* A non-overage failure means the licence itself is unusable; deleting the
 * machine would hide that rather than help. */
TT_TEST(activate_machine_keeps_the_machine_on_a_non_overage_failure) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 201, "{\"data\":{\"id\":\"01926b3e-0000-7000-8000-000000000002\"}}");
    mock_reply(&mock, 200, "{\"data\":{},\"meta\":{\"valid\":false,\"code\":\"EXPIRED\"}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(
        tamga_client_activate_machine(client, LICENSE_ID, "fp-1", NULL, NULL, true, &response),
        TAMGA_OK);
    TT_ASSERT_EQ_SIZE(mock.call_count, 2u);

    tamga_response_free(response);
    tamga_client_free(client);
}

TT_TEST(validation_codes_round_trip) {
    TT_ASSERT_EQ_INT(tamga_validation_code_parse("VALID"), TAMGA_VALIDATION_VALID);
    TT_ASSERT_EQ_INT(tamga_validation_code_parse("TOO_MANY_MACHINES"),
                     TAMGA_VALIDATION_TOO_MANY_MACHINES);
    TT_ASSERT_EQ_INT(tamga_validation_code_parse("SOMETHING_NEW"), TAMGA_VALIDATION_UNKNOWN);
    TT_ASSERT_EQ_INT(tamga_validation_code_parse(NULL), TAMGA_VALIDATION_UNKNOWN);
    TT_ASSERT_EQ_STR(tamga_validation_code_name(TAMGA_VALIDATION_EXPIRED), "EXPIRED");
    TT_ASSERT_EQ_STR(tamga_validation_code_name(TAMGA_VALIDATION_UNKNOWN), "UNKNOWN");

    TT_ASSERT(tamga_validation_code_is_overage(TAMGA_VALIDATION_TOO_MANY_MACHINES));
    TT_ASSERT(tamga_validation_code_is_overage(TAMGA_VALIDATION_TOO_MANY_CORES));
    TT_ASSERT(tamga_validation_code_is_overage(TAMGA_VALIDATION_TOO_MUCH_MEMORY));
    TT_ASSERT(tamga_validation_code_is_overage(TAMGA_VALIDATION_TOO_MUCH_DISK));
    TT_ASSERT(tamga_validation_code_is_overage(TAMGA_VALIDATION_TOO_MANY_PROCESSES));
    /* Expiry and suspension are not overage: the licence is unusable, not
     * merely over its limit. */
    TT_ASSERT_FALSE(tamga_validation_code_is_overage(TAMGA_VALIDATION_EXPIRED));
    TT_ASSERT_FALSE(tamga_validation_code_is_overage(TAMGA_VALIDATION_SUSPENDED));
    TT_ASSERT_FALSE(tamga_validation_code_is_overage(TAMGA_VALIDATION_VALID));
}

/* The server reports the same over-limit condition in two vocabularies
 * depending on the policy's overage strategy; the fold has to line them up
 * exactly, or a caller handling one shape silently mishandles the other. */
TT_TEST(creation_time_limits_fold_onto_their_validation_codes) {
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error(TAMGA_ERR_MACHINE_LIMIT_EXCEEDED),
                     TAMGA_VALIDATION_TOO_MANY_MACHINES);
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error(TAMGA_ERR_CORE_LIMIT_EXCEEDED),
                     TAMGA_VALIDATION_TOO_MANY_CORES);
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error(TAMGA_ERR_MEMORY_LIMIT_EXCEEDED),
                     TAMGA_VALIDATION_TOO_MUCH_MEMORY);
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error(TAMGA_ERR_DISK_LIMIT_EXCEEDED),
                     TAMGA_VALIDATION_TOO_MUCH_DISK);
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error(TAMGA_ERR_TOO_MANY_PROCESSES),
                     TAMGA_VALIDATION_TOO_MANY_PROCESSES);

    /* Anything else is UNKNOWN -- never VALID. A caller reading "not a limit"
     * as "fine" would pass every other failure straight through. */
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error(TAMGA_OK), TAMGA_VALIDATION_UNKNOWN);
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error(TAMGA_ERR_LICENSE_NOT_ALLOWED),
                     TAMGA_VALIDATION_UNKNOWN);
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error(TAMGA_ERR_TRANSPORT),
                     TAMGA_VALIDATION_UNKNOWN);
    TT_ASSERT_EQ_INT(tamga_validation_code_from_error((TamgaErrorCode)9999),
                     TAMGA_VALIDATION_UNKNOWN);
}

/* Every appended code has a name. A missing case falls through to
 * "TAMGA_ERR_UNKNOWN", which turns a precise server rejection into an
 * unreadable log line at exactly the moment somebody is reading logs. */
TT_TEST(the_appended_error_codes_all_have_names) {
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_MACHINE_LIMIT_EXCEEDED),
                     "TAMGA_ERR_MACHINE_LIMIT_EXCEEDED");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_CORE_LIMIT_EXCEEDED),
                     "TAMGA_ERR_CORE_LIMIT_EXCEEDED");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_MEMORY_LIMIT_EXCEEDED),
                     "TAMGA_ERR_MEMORY_LIMIT_EXCEEDED");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_DISK_LIMIT_EXCEEDED),
                     "TAMGA_ERR_DISK_LIMIT_EXCEEDED");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_TOO_MANY_PROCESSES),
                     "TAMGA_ERR_TOO_MANY_PROCESSES");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_LICENSE_SUSPENDED), "TAMGA_ERR_LICENSE_SUSPENDED");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_LICENSE_EXPIRED), "TAMGA_ERR_LICENSE_EXPIRED");
    TT_ASSERT_EQ_STR(tamga_error_name(TAMGA_ERR_LICENSE_NOT_ALLOWED),
                     "TAMGA_ERR_LICENSE_NOT_ALLOWED");
}

/* An identifier that is not a UUID never reaches the URL builder -- otherwise
 * one containing a slash would silently address a different endpoint. */
TT_TEST(identifiers_must_be_uuids) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_check_in(client, "../../admin", &response),
                         TAMGA_ERR_NULL_ARGUMENT);
        TT_ASSERT_EQ_INT(tamga_client_check_in(client, NULL, &response), TAMGA_ERR_NULL_ARGUMENT);
        TT_ASSERT_EQ_INT(tamga_client_ping_heartbeat(client, "not-a-uuid", &response),
                         TAMGA_ERR_NULL_ARGUMENT);
        TT_ASSERT_EQ_SIZE(mock.call_count, 0u);
    });
}

/* A caller's spelling of a UUID must not change the URL: the server's own
 * form is lowercase and hyphenated. */
TT_TEST(identifiers_are_normalised_into_the_path) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_check_in(client, "{01926B3E-0000-7000-8000-000000000001}", &response),
            TAMGA_OK);
        expect_call(&mock, "POST",
                    "/licenses/01926b3e-0000-7000-8000-000000000001/actions/check-in");
    });
}

/* --- the reads and writes added in 1.3.x --------------------------------- */

TT_TEST(the_licence_and_policy_reads_hit_their_routes) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_get_license(client, LICENSE_ID, &response), TAMGA_OK);
        expect_call(&mock, "GET", "/licenses/01926b3e-0000-7000-8000-000000000001");
    });
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_get_license_policy(client, LICENSE_ID, &response), TAMGA_OK);
        expect_call(&mock, "GET", "/licenses/01926b3e-0000-7000-8000-000000000001/policy");
    });
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_get_policy(client, POLICY_ID, &response), TAMGA_OK);
        expect_call(&mock, "GET", "/policies/01926b3e-0000-7000-8000-000000000005");
    });
}

/*
 * The heartbeat window comes from the policy, and an absent one means the
 * server's 600-second fallback rather than "no heartbeat".
 *
 * An SDK that hardcoded 600 would ping far too slowly for a policy asking for
 * a shorter window, and its machines would fall outside that window. The
 * third case is the one that keeps this honest: a response that is not a
 * policy must be refused rather than answered with the default, or a caller
 * that passed the wrong response would silently ping on the wrong schedule.
 */
TT_TEST(the_policy_response_carries_the_heartbeat_window) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;
    int64_t window = 0;

    mock_reset(&mock);
    mock_reply(&mock, 200,
               "{\"data\":{\"type\":\"policies\",\"id\":\"p\","
               "\"attributes\":{\"heartbeat_duration\":120,\"require_heartbeat\":true}}}");
    mock_reply(&mock, 200,
               "{\"data\":{\"type\":\"policies\",\"id\":\"p\","
               "\"attributes\":{\"heartbeat_duration\":null,\"require_heartbeat\":false}}}");
    mock_reply(&mock, 200, "{\"data\":{\"type\":\"machines\",\"id\":\"m\",\"attributes\":{}}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_get_license_policy(client, LICENSE_ID, &response), TAMGA_OK);
    TT_ASSERT(tamga_response_heartbeat_window_secs(response, &window));
    TT_ASSERT_EQ_INT((int)window, 120);
    tamga_response_free(response);
    response = NULL;

    /* `heartbeat_duration: null` is the 600-second fallback, not an error --
     * the field is always present on the wire because the server declares no
     * skip_serializing_if for it. */
    TT_ASSERT_EQ_INT(tamga_client_get_license_policy(client, LICENSE_ID, &response), TAMGA_OK);
    TT_ASSERT(tamga_response_heartbeat_window_secs(response, &window));
    TT_ASSERT_EQ_INT((int)window, TAMGA_DEFAULT_HEARTBEAT_WINDOW_SECONDS);
    tamga_response_free(response);
    response = NULL;

    window = -1;
    TT_ASSERT_EQ_INT(tamga_client_get_machine(client, MACHINE_ID, &response), TAMGA_OK);
    TT_ASSERT_FALSE(tamga_response_heartbeat_window_secs(response, &window));
    /* Refused, and nothing written -- a caller that ignored the return value
     * must not find a plausible-looking 600 in its variable. */
    TT_ASSERT_EQ_INT((int)window, -1);
    tamga_response_free(response);
    tamga_client_free(client);
}

/*
 * A stored window of zero or less is refused, and `*out_seconds` is left
 * exactly as the caller had it.
 *
 * Not a defensive formality: `policies.heartbeat_duration` is a bare nullable
 * INTEGER with no CHECK constraint, and neither create_policy nor
 * update_policy range-checks the attribute before binding it -- each
 * validates only its enum-typed string fields. So `0` and negatives are
 * storable, and `effective_heartbeat_duration_secs()` hands them straight
 * back, because its fallback to 600 keys off NULL alone.
 *
 * Both halves of the promise are pinned here. Answering true with a zero
 * would turn a heartbeat loop into a busy loop against the server, and a
 * negative window is already in the past on every comparison that uses it.
 * Writing to `*out_seconds` on the way out would be just as bad: the refusal
 * only helps if a caller that ignored the return value cannot find a
 * plausible-looking number waiting in its variable. The sibling test above
 * covers the readable cases, and every one of its assertions stays green if
 * the `<= 0` guard is deleted -- which is what makes this test the one
 * holding the documented contract up.
 */
TT_TEST(a_non_positive_heartbeat_window_is_refused_without_writing) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;
    int64_t window;

    mock_reset(&mock);
    mock_reply(&mock, 200,
               "{\"data\":{\"type\":\"policies\",\"id\":\"p\","
               "\"attributes\":{\"heartbeat_duration\":0,\"require_heartbeat\":true}}}");
    mock_reply(&mock, 200,
               "{\"data\":{\"type\":\"policies\",\"id\":\"p\","
               "\"attributes\":{\"heartbeat_duration\":-1,\"require_heartbeat\":true}}}");
    mock_reply(&mock, 200,
               "{\"data\":{\"type\":\"policies\",\"id\":\"p\","
               "\"attributes\":{\"heartbeat_duration\":\"600\",\"require_heartbeat\":true}}}");
    mock_reply(&mock, 200,
               "{\"data\":{\"type\":\"policies\",\"id\":\"p\","
               "\"attributes\":{\"heartbeat_duration\":120,\"require_heartbeat\":true}}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    /* Zero -- storable upstream, and a schedule computed from it never
     * sleeps. */
    window = -7;
    TT_ASSERT_EQ_INT(tamga_client_get_policy(client, POLICY_ID, &response), TAMGA_OK);
    TT_ASSERT_FALSE(tamga_response_heartbeat_window_secs(response, &window));
    TT_ASSERT_EQ_INT((int)window, -7);
    tamga_response_free(response);
    response = NULL;

    /* Negative -- equally storable, and every deadline built from it has
     * already passed. */
    window = -7;
    TT_ASSERT_EQ_INT(tamga_client_get_policy(client, POLICY_ID, &response), TAMGA_OK);
    TT_ASSERT_FALSE(tamga_response_heartbeat_window_secs(response, &window));
    TT_ASSERT_EQ_INT((int)window, -7);
    tamga_response_free(response);
    response = NULL;

    /* Present, non-null, and not a number. The value even looks right, which
     * is exactly why it is worth pinning: the guard is a type check as well
     * as a range check. */
    window = -7;
    TT_ASSERT_EQ_INT(tamga_client_get_policy(client, POLICY_ID, &response), TAMGA_OK);
    TT_ASSERT_FALSE(tamga_response_heartbeat_window_secs(response, &window));
    TT_ASSERT_EQ_INT((int)window, -7);
    tamga_response_free(response);
    response = NULL;

    /* `out_seconds` is NOT optional here: a perfectly readable window is
     * still a refusal when there is nowhere to put it. Pinned because
     * tamga_response_page(), two declarations up in the header, says every
     * one of ITS out-parameters may be NULL -- so this is the asymmetry a
     * reader is most likely to carry the wrong way. */
    TT_ASSERT_EQ_INT(tamga_client_get_policy(client, POLICY_ID, &response), TAMGA_OK);
    TT_ASSERT_FALSE(tamga_response_heartbeat_window_secs(response, NULL));
    tamga_response_free(response);
    tamga_client_free(client);
}

/*
 * `false` from tamga_response_validation_is_valid() is not by itself proof
 * that the server rejected the licence.
 *
 * tamga_json_bool_or() returns its fallback for an absent key and a
 * wrong-typed one alike, so a response carrying no readable `valid` flag --
 * the wrong response passed, or an error document -- reads exactly like a
 * licence the server refused. Failing closed is the right default and this
 * test does not argue with it; what it pins is the remedy the header now
 * points at, because a conflation is only safe while the documented way out
 * of it keeps working. tamga_response_validation_code() answers NULL where
 * there is no verdict to report and a code string where there is, so the two
 * cases that look identical through `is_valid` stay distinguishable.
 */
TT_TEST(an_unreadable_validation_flag_reads_as_invalid) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 200, "{\"data\":{\"type\":\"machines\",\"id\":\"m\",\"attributes\":{}}}");
    mock_reply(&mock, 200,
               "{\"ts\":\"2026-08-20T00:00:00Z\",\"valid\":false,"
               "\"detail\":\"has expired\",\"code\":\"EXPIRED\"}");
    mock_reply(&mock, 200,
               "{\"ts\":\"2026-08-20T00:00:00Z\",\"valid\":\"true\",\"code\":\"VALID\"}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    /* No verdict anywhere in the document: false, and the code is NULL. That
     * NULL is the whole remedy -- it is what separates this from the refusal
     * immediately below. */
    TT_ASSERT_EQ_INT(tamga_client_get_machine(client, MACHINE_ID, &response), TAMGA_OK);
    TT_ASSERT_FALSE(tamga_response_validation_is_valid(response));
    TT_ASSERT_NULL(tamga_response_validation_code(response));
    TT_ASSERT_EQ_INT(tamga_response_validation_code_enum(response), TAMGA_VALIDATION_UNKNOWN);
    tamga_response_free(response);
    response = NULL;

    /* A licence the server really did reject: identical `is_valid`, but a
     * code that says so. */
    TT_ASSERT_EQ_INT(tamga_client_quick_validate(client, LICENSE_ID, NULL, &response), TAMGA_OK);
    TT_ASSERT_FALSE(tamga_response_validation_is_valid(response));
    TT_ASSERT_EQ_STR(tamga_response_validation_code(response), "EXPIRED");
    tamga_response_free(response);
    response = NULL;

    /* `valid` present but a string. It spells "true", and it still reads
     * false -- tamga_json_bool_or() takes the fallback on a type mismatch
     * rather than coercing, so a server that ever quoted the field would fail
     * closed instead of waving every licence through. */
    TT_ASSERT_EQ_INT(tamga_client_quick_validate(client, LICENSE_ID, NULL, &response), TAMGA_OK);
    TT_ASSERT_FALSE(tamga_response_validation_is_valid(response));
    tamga_response_free(response);
    tamga_client_free(client);
}

/*
 * Nothing on the server deletes a process row -- its reaper is dead code --
 * so a client that never disposes of one leaks a seat against
 * TOO_MANY_PROCESSES until a later, innocent run fails.
 */
TT_TEST(deleting_a_process_is_a_bare_delete) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_delete_process(client, PROCESS_ID, &response), TAMGA_OK);
        expect_call(&mock, "DELETE", "/processes/01926b3e-0000-7000-8000-000000000003");
        expect_body(&mock, "");
    });
}

TT_TEST(listing_machine_processes_is_keyset_paginated) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(
            tamga_client_list_machine_processes(client, MACHINE_ID, 50u, ENTITLEMENT_ID, &response),
            TAMGA_OK);
        expect_call(&mock, "GET",
                    "/machines/01926b3e-0000-7000-8000-000000000002/processes"
                    "?limit=50&page%5Bafter%5D=01926b3e-0000-7000-8000-000000000004");
    });
}

TT_TEST(machine_reads_and_updates_hit_their_routes) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_get_machine(client, MACHINE_ID, &response), TAMGA_OK);
        expect_call(&mock, "GET", "/machines/01926b3e-0000-7000-8000-000000000002");
    });

    /* Enveloped, and `type` is mandatory: the server declares it as a
     * non-optional String, so a body without it is a 422 at deserialization
     * before the handler ever runs. Only the recognised attributes are
     * forwarded -- and never `fingerprint`, which has no field here. */
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_update_machine(
                             client, MACHINE_ID,
                             "{\"hostname\":\"build-02\",\"cores\":8,"
                             "\"fingerprint\":\"cannot-move\",\"unexpected\":\"dropped\"}",
                             &response),
                         TAMGA_OK);
        expect_call(&mock, "PATCH", "/machines/01926b3e-0000-7000-8000-000000000002");
        expect_body(&mock, "{\"data\":{\"type\":\"machines\","
                           "\"attributes\":{\"hostname\":\"build-02\",\"cores\":8}}}");
    });
}

/*
 * GET /machines is the one listing in this domain that is OFFSET-paginated,
 * not keyset. Sending it a cursor would address the first page forever; the
 * page metadata is what a caller loops on instead.
 */
TT_TEST(the_machine_collection_is_offset_paginated) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;
    int64_t number = 0;
    int64_t size = 0;
    int64_t total = 0;
    int64_t total_pages = 0;

    mock_reset(&mock);
    mock_reply(&mock, 200,
               "{\"data\":[],\"meta\":{\"page\":{\"number\":2,\"size\":25,"
               "\"total\":51,\"totalPages\":3}}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_list_machines(client, LICENSE_ID, "build-01", 2u, 25u, &response),
                     TAMGA_OK);
    expect_call(&mock, "GET",
                "/machines?page%5Bnumber%5D=2&page%5Bsize%5D=25"
                "&filter%5Blicense%5D=01926b3e-0000-7000-8000-000000000001"
                "&filter%5Bq%5D=build-01");

    TT_ASSERT(tamga_response_page(response, &number, &size, &total, &total_pages));
    TT_ASSERT_EQ_INT((int)number, 2);
    TT_ASSERT_EQ_INT((int)size, 25);
    TT_ASSERT_EQ_INT((int)total, 51);
    TT_ASSERT_EQ_INT((int)total_pages, 3);
    /* The keyset accessor answers nothing here, which is the correct failure:
     * this listing carries no cursor and never will. */
    TT_ASSERT_NULL(tamga_response_next_cursor(response, 25u));

    tamga_response_free(response);
    tamga_client_free(client);
}

/* Every parameter is optional on this call and each one omitted must vanish
 * from the query rather than being sent empty. */
TT_TEST(the_machine_collection_omits_what_it_was_not_given) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_list_machines(client, NULL, NULL, 0u, 0u, &response),
                         TAMGA_OK);
        expect_call(&mock, "GET", "/machines");
    });
}

/* A page with no `meta.page` -- an unexpected body shape -- must not yield a
 * half-filled set of numbers a caller would act on. */
TT_TEST(a_page_without_metadata_is_refused_whole) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;
    int64_t number = -1;
    int64_t total_pages = -1;

    mock_reset(&mock);
    /* `totalPages` missing: three of the four fields are readable, and a zero
     * in the fourth would read as "there is nothing here" and stop a paging
     * loop on its first iteration. */
    mock_reply(&mock, 200,
               "{\"data\":[],\"meta\":{\"page\":{\"number\":1,\"size\":25,"
               "\"total\":51}}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_list_machines(client, NULL, NULL, 1u, 25u, &response), TAMGA_OK);
    TT_ASSERT_FALSE(tamga_response_page(response, &number, NULL, NULL, &total_pages));
    TT_ASSERT_EQ_INT((int)number, -1);
    TT_ASSERT_EQ_INT((int)total_pages, -1);

    tamga_response_free(response);
    tamga_client_free(client);
}

/*
 * `filter[q]` is a SUBSTRING search, not an equality filter -- there is no
 * filter[fingerprint] on the server at all. A machine whose fingerprint
 * merely contains the one asked for comes back from the same query, and
 * returning it would hand the caller somebody else's seat.
 */
TT_TEST(finding_a_machine_by_fingerprint_demands_an_exact_match) {
    MockTransport mock;
    TamgaClient *client;
    char *machine_id = (char *)0x1;

    mock_reset(&mock);
    mock_reply(&mock, 200,
               "{\"data\":[{\"id\":\"01926b3e-0000-7000-8000-00000000000f\","
               "\"attributes\":{\"fingerprint\":\"fp-1-but-longer\"}}],"
               "\"meta\":{\"page\":{\"number\":1,\"size\":100,\"total\":1,\"totalPages\":1}}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(
        tamga_client_find_machine_by_fingerprint(client, LICENSE_ID, "fp-1", &machine_id),
        TAMGA_OK);
    /* Not found is TAMGA_OK with NULL, and the out-param is cleared first so
     * a caller cannot read the value it passed in. */
    TT_ASSERT_NULL(machine_id);
    TT_ASSERT_EQ_SIZE(mock.call_count, 1u);

    tamga_client_free(client);
}

TT_TEST(finding_a_machine_walks_past_a_page_that_does_not_hold_it) {
    MockTransport mock;
    TamgaClient *client;
    char *machine_id = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 200,
               "{\"data\":[{\"id\":\"01926b3e-0000-7000-8000-00000000000f\","
               "\"attributes\":{\"fingerprint\":\"fp-1-but-longer\"}}],"
               "\"meta\":{\"page\":{\"number\":1,\"size\":100,\"total\":2,\"totalPages\":2}}}");
    mock_reply(&mock, 200,
               "{\"data\":[{\"id\":\"01926b3e-0000-7000-8000-000000000002\","
               "\"attributes\":{\"fingerprint\":\"fp-1\"}}],"
               "\"meta\":{\"page\":{\"number\":2,\"size\":100,\"total\":2,\"totalPages\":2}}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(
        tamga_client_find_machine_by_fingerprint(client, LICENSE_ID, "fp-1", &machine_id),
        TAMGA_OK);
    TT_ASSERT_NOT_NULL(machine_id);
    TT_ASSERT_EQ_STR(machine_id, "01926b3e-0000-7000-8000-000000000002");
    TT_ASSERT_EQ_SIZE(mock.call_count, 2u);
    TT_ASSERT_NOT_NULL(strstr(mock.calls[1].url, "page%5Bnumber%5D=2"));

    tamga_string_free(machine_id);
    tamga_client_free(client);
}

/*
 * Re-activating an already-activated machine is the normal case -- it happens
 * on every restart -- and the plain activate call reports it as a bare
 * conflict with no way forward. The server checks fingerprint uniqueness
 * BEFORE the seat limits precisely so this is not reported as "buy more
 * seats"; carrying on is the intended reading.
 */
TT_TEST(an_already_activated_machine_is_not_an_error) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 409,
               "{\"errors\":[{\"status\":\"409\",\"code\":\"FINGERPRINT_TAKEN\","
               "\"title\":\"Conflict\",\"detail\":\"already activated\"}]}");
    mock_reply(&mock, 200,
               "{\"data\":[{\"id\":\"01926b3e-0000-7000-8000-000000000002\","
               "\"attributes\":{\"fingerprint\":\"fp-1\"}}],"
               "\"meta\":{\"page\":{\"number\":1,\"size\":100,\"total\":1,\"totalPages\":1}}}");
    mock_reply(&mock, 200, "{\"data\":{},\"meta\":{\"valid\":true,\"code\":\"VALID\"}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_activate_machine_idempotent(client, LICENSE_ID, "fp-1", NULL,
                                                              NULL, true, &response),
                     TAMGA_OK);
    TT_ASSERT_EQ_SIZE(mock.call_count, 3u);
    TT_ASSERT_EQ_STR(mock.calls[0].method, "POST");
    TT_ASSERT_EQ_STR(mock.calls[1].method, "GET");
    TT_ASSERT_NOT_NULL(strstr(mock.calls[1].url, "filter%5Bq%5D=fp-1"));
    /* The existing machine is NOT deleted: this call created nothing, and
     * auto_delete_on_overage governs only the create path. */
    TT_ASSERT_EQ_STR(mock.calls[2].method, "POST");
    TT_ASSERT_NOT_NULL(strstr(mock.calls[2].url, "/actions/validate"));
    TT_ASSERT(tamga_response_validation_is_valid(response));

    tamga_response_free(response);
    tamga_client_free(client);
}

/*
 * The conflict is real when the fingerprint belongs to a DIFFERENT licence,
 * which UNIQUE_PER_POLICY and UNIQUE_PER_ACCOUNT both allow. Those two
 * strategies exist to stop one fingerprint holding seats on several licences,
 * so handing the other licence's machine back as "yours" would defeat them --
 * and the machine resource carries no licence id, so scoping the lookup
 * server-side is the only way to tell.
 */
TT_TEST(an_idempotent_activation_still_refuses_another_licences_fingerprint) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = (TamgaResponse *)0x1;

    mock_reset(&mock);
    mock_reply(&mock, 409,
               "{\"errors\":[{\"status\":\"409\",\"code\":\"FINGERPRINT_TAKEN\","
               "\"title\":\"Conflict\",\"detail\":\"already activated\"}]}");
    mock_reply(&mock, 200,
               "{\"data\":[],\"meta\":{\"page\":{\"number\":1,\"size\":100,"
               "\"total\":0,\"totalPages\":0}}}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_activate_machine_idempotent(client, LICENSE_ID, "fp-1", NULL,
                                                              NULL, true, &response),
                     TAMGA_ERR_FINGERPRINT_TAKEN);
    TT_ASSERT_EQ_SIZE(mock.call_count, 2u);
    /* No validation was attempted, and nothing was handed back to free --
     * the same contract tamga_client_activate_machine() has on this path. */
    TT_ASSERT_NULL(response);
    TT_ASSERT_NOT_NULL(tamga_last_error_message());

    tamga_client_free(client);
}

/*
 * A credential that cannot read machines cannot recover from the conflict
 * either -- but the two failures are different things and must not share a
 * message. Both keep TAMGA_ERR_FINGERPRINT_TAKEN, because in both cases the
 * activation genuinely did not happen.
 */
TT_TEST(an_idempotent_activation_says_when_the_lookup_itself_failed) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = (TamgaResponse *)0x1;

    mock_reset(&mock);
    mock_reply(&mock, 409,
               "{\"errors\":[{\"status\":\"409\",\"code\":\"FINGERPRINT_TAKEN\","
               "\"title\":\"Conflict\",\"detail\":\"already activated\"}]}");
    mock_reply(&mock, 403,
               "{\"errors\":[{\"status\":\"403\",\"code\":\"FORBIDDEN\","
               "\"title\":\"Forbidden\",\"detail\":\"cannot read machines\"}]}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_activate_machine_idempotent(client, LICENSE_ID, "fp-1", NULL,
                                                              NULL, true, &response),
                     TAMGA_ERR_FINGERPRINT_TAKEN);
    TT_ASSERT_EQ_SIZE(mock.call_count, 2u);
    TT_ASSERT_NULL(response);
    /* Named, not folded into "it belongs to another licence" -- the operator
     * fix for a missing permission is not the fix for a shared fingerprint. */
    TT_ASSERT_NOT_NULL(strstr(tamga_last_error_message(), "could not be looked up"));

    tamga_client_free(client);
}

/*
 * All four of product/platform/filetype/version are required server-side --
 * they are non-Option query fields, so omitting one is a 400 rather than a
 * defaulted search.
 */
TT_TEST(the_upgrade_check_sends_every_required_parameter) {
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_check_upgrade(client, PRODUCT_ID, "darwin-aarch64", "dmg",
                                                    "1.2.0", NULL, NULL, &response),
                         TAMGA_OK);
        expect_call(&mock, "GET",
                    "/releases/actions/upgrade"
                    "?product=01926b3e-0000-7000-8000-000000000006"
                    "&platform=darwin-aarch64&filetype=dmg&version=1.2.0");
    });

    /* The optional two are appended only when given, and every value is
     * percent-encoded -- a constraint like ">=1.2, <2" carries characters
     * that would otherwise add parameters of their own. */
    WITH_CLIENT({
        TT_ASSERT_EQ_INT(tamga_client_check_upgrade(client, PRODUCT_ID, "linux-x86_64", "AppImage",
                                                    "1.2.0", "beta", ">=1.2, <2", &response),
                         TAMGA_OK);
        expect_call(&mock, "GET",
                    "/releases/actions/upgrade"
                    "?product=01926b3e-0000-7000-8000-000000000006"
                    "&platform=linux-x86_64&filetype=AppImage&version=1.2.0"
                    "&channel=beta&constraint=%3E%3D1.2%2C%20%3C2");
    });
}

/*
 * `204` means BOTH "there is no newer release" and "there is one and this
 * licence is not entitled to it", and the server answers the same way on
 * purpose so a refusal cannot leak the second. The SDK's job is to surface
 * the status honestly rather than to invent a third state -- there is no
 * client-side way to tell them apart, and reporting "you are up to date"
 * would be a claim the response does not support.
 */
TT_TEST(the_upgrade_check_reports_204_without_claiming_currency) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 204, "");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_check_upgrade(client, PRODUCT_ID, "windows-x86_64", "exe",
                                                "1.2.0", NULL, NULL, &response),
                     TAMGA_OK);
    TT_ASSERT_NOT_NULL(response);
    TT_ASSERT_EQ_INT(tamga_response_status(response), 204);

    tamga_response_free(response);
    tamga_client_free(client);
}

/*
 * The one route that is not account-scoped. Every URL builder in this SDK
 * family unconditionally prepended /v1/accounts/{account_id}, which is why no
 * SDK could reach a route the server deliberately publishes outside the
 * account tree -- the restriction was ours, not the server's.
 */
TT_TEST(health_is_not_account_scoped) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 200, "{\"status\":\"ok\",\"version\":\"0.1.0\",\"uptime_secs\":42}");
    client = make_client(&mock);
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_health(client, &response), TAMGA_OK);
    TT_ASSERT_EQ_SIZE(mock.call_count, 1u);
    TT_ASSERT_EQ_STR(mock.calls[0].method, "GET");
    TT_ASSERT_EQ_STR(mock.calls[0].url, "https://api.tamga.sh/v1/health");
    TT_ASSERT_NULL(strstr(mock.calls[0].url, "/accounts/"));
    /* A flat body, not a JSON:API document -- nothing that expects a `data`
     * envelope applies to it. */
    TT_ASSERT_NOT_NULL(strstr(tamga_response_json(response, NULL), "\"uptime_secs\":42"));
    /* The credential still goes out: this client has no anonymous mode. */
    TT_ASSERT_NOT_NULL(mock_last_header(&mock, "Authorization"));

    tamga_response_free(response);
    tamga_client_free(client);
}

int main(void) {
    TT_RUN(validate_by_key);
    TT_RUN(validate_by_id_with_and_without_scope);
    TT_RUN(quick_validate);
    TT_RUN(quick_validate_decodes_a_flat_body);
    TT_RUN(check_in);
    TT_RUN(licence_checkout_both_forms);
    TT_RUN(machine_checkout_both_forms);
    TT_RUN(an_out_of_range_ttl_never_reaches_the_server);
    TT_RUN(create_machine_uses_the_json_api_envelope);
    TT_RUN(create_machine_forwards_only_known_options);
    TT_RUN(machine_actions);
    TT_RUN(generate_offline_proof_defaults_the_dataset_to_an_object);
    TT_RUN(components_and_processes_use_flat_bodies);
    TT_RUN(listings_are_keyset_paginated);
    TT_RUN(the_next_page_cursor_is_derived_from_a_full_page_only);
    TT_RUN(has_entitlement_matches_on_code_not_name);
    TT_RUN(activate_machine_creates_then_validates);
    TT_RUN(activate_machine_reports_a_creation_time_limit_without_deleting);
    TT_RUN(a_non_limit_creation_failure_hands_back_no_response);
    TT_RUN(activate_machine_still_rolls_back_when_the_overage_strategy_allows_the_create);
    TT_RUN(activate_machine_undoes_an_over_limit_activation);
    TT_RUN(activate_machine_keeps_the_machine_on_a_non_overage_failure);
    TT_RUN(validation_codes_round_trip);
    TT_RUN(creation_time_limits_fold_onto_their_validation_codes);
    TT_RUN(the_appended_error_codes_all_have_names);
    TT_RUN(identifiers_must_be_uuids);
    TT_RUN(identifiers_are_normalised_into_the_path);
    TT_RUN(the_licence_and_policy_reads_hit_their_routes);
    TT_RUN(the_policy_response_carries_the_heartbeat_window);
    TT_RUN(a_non_positive_heartbeat_window_is_refused_without_writing);
    TT_RUN(an_unreadable_validation_flag_reads_as_invalid);
    TT_RUN(deleting_a_process_is_a_bare_delete);
    TT_RUN(listing_machine_processes_is_keyset_paginated);
    TT_RUN(machine_reads_and_updates_hit_their_routes);
    TT_RUN(the_machine_collection_is_offset_paginated);
    TT_RUN(the_machine_collection_omits_what_it_was_not_given);
    TT_RUN(a_page_without_metadata_is_refused_whole);
    TT_RUN(finding_a_machine_by_fingerprint_demands_an_exact_match);
    TT_RUN(finding_a_machine_walks_past_a_page_that_does_not_hold_it);
    TT_RUN(an_already_activated_machine_is_not_an_error);
    TT_RUN(an_idempotent_activation_still_refuses_another_licences_fingerprint);
    TT_RUN(an_idempotent_activation_says_when_the_lookup_itself_failed);
    TT_RUN(the_upgrade_check_sends_every_required_parameter);
    TT_RUN(the_upgrade_check_reports_204_without_claiming_currency);
    TT_RUN(health_is_not_account_scoped);
    return TT_SUMMARY();
}
