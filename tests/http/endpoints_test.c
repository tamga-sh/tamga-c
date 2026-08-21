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
    return TT_SUMMARY();
}
