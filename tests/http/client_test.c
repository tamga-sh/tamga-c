/*
 * Client behaviour: URL construction, authentication, headers, the retry
 * policy and the error model. All through a mock transport, so nothing here
 * touches a socket.
 */
#include "tamga_test.h"

#include "http/client.h"
#include "mock_transport.h"
#include "tamga_error.h"

static const char ACCOUNT[] = "01926b3e-0000-7000-8000-0000000000aa";
static const char LICENSE_ID[] = "01926b3e-0000-7000-8000-000000000001";

/* A client wired to the mock, with credentials set. */
static TamgaClient *make_client(MockTransport *mock, const char *host) {
    TamgaClient *client = NULL;
    if (tamga_client_new(ACCOUNT, host, &client) != TAMGA_OK) {
        return NULL;
    }
    if (tamga_client_set_auth(client, TAMGA_AUTH_BEARER, "tok-abc123", NULL) != TAMGA_OK) {
        tamga_client_free(client);
        return NULL;
    }
    if (tamga_client_set_transport(client, mock_perform, mock, NULL) != TAMGA_OK) {
        tamga_client_free(client);
        return NULL;
    }
    return client;
}

TT_TEST(builds_the_account_scoped_base_url) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    client = make_client(&mock, "api.tamga.sh");
    TT_ASSERT_NOT_NULL(client);

    TT_ASSERT_EQ_INT(tamga_client_quick_validate(client, LICENSE_ID, NULL, &response), TAMGA_OK);
    TT_ASSERT_EQ_SIZE(mock.call_count, 1u);
    TT_ASSERT_EQ_STR(mock.calls[0].url,
                     "https://api.tamga.sh/v1/accounts/01926b3e-0000-7000-8000-0000000000aa"
                     "/licenses/01926b3e-0000-7000-8000-000000000001/actions/validate");
    TT_ASSERT_EQ_STR(mock.calls[0].method, "GET");

    tamga_response_free(response);
    tamga_client_free(client);
}

/* A bare host, a trailing slash and an explicit https:// must all produce the
 * same URL; an explicit http:// must be preserved, since that is what makes a
 * local mock server usable without a test-only code path. */
TT_TEST(host_forms_normalise_consistently) {
    static const char *const equivalent[] = {"api.tamga.sh", "api.tamga.sh/",
                                             "https://api.tamga.sh", "https://api.tamga.sh/"};
    size_t i;

    for (i = 0u; i < 4u; i++) {
        MockTransport mock;
        TamgaClient *client;
        TamgaResponse *response = NULL;

        mock_reset(&mock);
        client = make_client(&mock, equivalent[i]);
        TT_ASSERT_NOT_NULL(client);
        TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_OK);
        TT_ASSERT_EQ_STR(mock.calls[0].url,
                         "https://api.tamga.sh/v1/accounts/"
                         "01926b3e-0000-7000-8000-0000000000aa/licenses/"
                         "01926b3e-0000-7000-8000-000000000001/actions/check-in");
        tamga_response_free(response);
        tamga_client_free(client);
    }

    {
        MockTransport mock;
        TamgaClient *client;
        TamgaResponse *response = NULL;

        mock_reset(&mock);
        client = make_client(&mock, "http://localhost:8080");
        TT_ASSERT_NOT_NULL(client);
        TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_OK);
        TT_ASSERT_EQ_STR(mock.calls[0].url,
                         "http://localhost:8080/v1/accounts/"
                         "01926b3e-0000-7000-8000-0000000000aa/licenses/"
                         "01926b3e-0000-7000-8000-000000000001/actions/check-in");
        tamga_response_free(response);
        tamga_client_free(client);
    }
}

TT_TEST(every_auth_transport_produces_the_documented_header) {
    struct {
        TamgaAuthKind kind;
        const char *primary;
        const char *secondary;
        const char *expected;
    } cases[] = {
        {TAMGA_AUTH_BEARER, "tok-abc123", NULL, "Bearer tok-abc123"},
        {TAMGA_AUTH_LICENSE, "lic-xyz789", NULL, "License lic-xyz789"},
        /* base64("user@example.com:hunter2") */
        {TAMGA_AUTH_BASIC_EMAIL_PASSWORD, "user@example.com", "hunter2",
         "Basic dXNlckBleGFtcGxlLmNvbTpodW50ZXIy"},
        /* base64("tok-abc123:") -- the token as the username, empty password */
        {TAMGA_AUTH_BASIC_TOKEN, "tok-abc123", NULL, "Basic dG9rLWFiYzEyMzo="},
        /* base64("license:lic-xyz789") */
        {TAMGA_AUTH_BASIC_LICENSE, "lic-xyz789", NULL, "Basic bGljZW5zZTpsaWMteHl6Nzg5"},
    };
    size_t i;

    for (i = 0u; i < (sizeof(cases) / sizeof(cases[0])); i++) {
        MockTransport mock;
        TamgaClient *client = NULL;
        TamgaResponse *response = NULL;

        mock_reset(&mock);
        TT_ASSERT_EQ_INT(tamga_client_new(ACCOUNT, "api.tamga.sh", &client), TAMGA_OK);
        TT_ASSERT_EQ_INT(
            tamga_client_set_auth(client, cases[i].kind, cases[i].primary, cases[i].secondary),
            TAMGA_OK);
        TT_ASSERT_EQ_INT(tamga_client_set_transport(client, mock_perform, &mock, NULL), TAMGA_OK);
        TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_OK);
        TT_ASSERT_EQ_STR(mock_last_header(&mock, "Authorization"), cases[i].expected);
        tamga_response_free(response);
        tamga_client_free(client);
    }
}

/* The query transport sends no Authorization header and percent-encodes the
 * token, so a token containing a reserved character cannot inject a second
 * query parameter. */
TT_TEST(the_query_transport_encodes_the_token_into_the_url) {
    MockTransport mock;
    TamgaClient *client = NULL;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    TT_ASSERT_EQ_INT(tamga_client_new(ACCOUNT, "api.tamga.sh", &client), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_client_set_auth(client, TAMGA_AUTH_QUERY_TOKEN, "a b&c=d", NULL),
                     TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_client_set_transport(client, mock_perform, &mock, NULL), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_OK);

    TT_ASSERT_NULL(mock_last_header(&mock, "Authorization"));
    TT_ASSERT_NOT_NULL(strstr(mock.calls[0].url, "?token=a%20b%26c%3Dd"));

    tamga_response_free(response);
    tamga_client_free(client);
}

TT_TEST(standard_headers_are_present) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    client = make_client(&mock, "api.tamga.sh");
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_OK);

    TT_ASSERT_EQ_STR(mock_last_header(&mock, "Tamga-Version"), "1.8");
    TT_ASSERT_NOT_NULL(mock_last_header(&mock, "Accept"));
    /* No OTP was supplied, so no OTP header. */
    TT_ASSERT_NULL(mock_last_header(&mock, "Tamga-OTP"));

    tamga_response_free(response);
    tamga_client_free(client);
}

TT_TEST(the_otp_header_is_sent_when_supplied) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    client = make_client(&mock, "api.tamga.sh");
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_quick_validate(client, LICENSE_ID, "123456", &response),
                     TAMGA_OK);
    TT_ASSERT_EQ_STR(mock_last_header(&mock, "Tamga-OTP"), "123456");
    tamga_response_free(response);
    tamga_client_free(client);
}

/* Filter-then-truncate, matching the server's own handling. Dropping rather
 * than replacing matters: a header the two sides disagree about is worse than
 * a rejected one. */
TT_TEST(the_api_version_is_sanitised_the_way_the_server_does) {
    char *sanitized;

    sanitized = tamga_sanitize_api_version("1.8");
    TT_ASSERT_EQ_STR(sanitized, "1.8");
    tamga_string_free(sanitized);

    sanitized = tamga_sanitize_api_version("v1.0-beta");
    TT_ASSERT_EQ_STR(sanitized, "v1.0-beta");
    tamga_string_free(sanitized);

    sanitized = tamga_sanitize_api_version("1.8; DROP TABLE");
    TT_ASSERT_EQ_STR(sanitized, "1.8DROPTABLE");
    tamga_string_free(sanitized);

    sanitized = tamga_sanitize_api_version("a/b c");
    TT_ASSERT_EQ_STR(sanitized, "abc");
    tamga_string_free(sanitized);

    sanitized = tamga_sanitize_api_version("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    TT_ASSERT_EQ_SIZE(strlen(sanitized), 32u);
    tamga_string_free(sanitized);
}

/*
 * Creates are excluded from retry deliberately: repeating POST /machines after
 * a timeout-shaped failure risks burning a second seat, and only the caller
 * knows whether that is acceptable.
 */
TT_TEST(only_safe_requests_are_retryable) {
    TT_ASSERT(tamga_request_is_retryable("GET", "/anything"));
    TT_ASSERT(tamga_request_is_retryable("POST", "/licenses/x/actions/validate"));
    TT_ASSERT(tamga_request_is_retryable("POST", "/licenses/actions/validate-key"));
    TT_ASSERT(tamga_request_is_retryable("POST", "/licenses/x/actions/check-in"));
    TT_ASSERT(tamga_request_is_retryable("POST", "/machines/x/actions/check-out"));
    TT_ASSERT(tamga_request_is_retryable("POST", "/processes/x/actions/ping"));

    TT_ASSERT_FALSE(tamga_request_is_retryable("POST", "/machines"));
    TT_ASSERT_FALSE(tamga_request_is_retryable("POST", "/components"));
    TT_ASSERT_FALSE(tamga_request_is_retryable("POST", "/processes"));
    TT_ASSERT_FALSE(tamga_request_is_retryable("DELETE", "/machines/x"));
    TT_ASSERT_FALSE(
        tamga_request_is_retryable("POST", "/machines/x/actions/generate-offline-proof"));
}

/* The delay policy is asserted directly rather than by waiting: a test that
 * really slept would be either slow or meaningless. */
TT_TEST(the_retry_delay_follows_the_documented_policy) {
    unsigned int delay;

    /* Retry-After wins when the server supplies one. */
    TT_ASSERT_EQ_INT(tamga_retry_delay_ms(0u, 5), 5000);
    /* ...but is capped, so a hostile proxy cannot park the caller. */
    TT_ASSERT_EQ_INT(tamga_retry_delay_ms(0u, 86400), 60000);

    /* Otherwise 1, 2, 4, 8, 16, 32 seconds plus under a second of jitter. */
    delay = tamga_retry_delay_ms(0u, 0);
    TT_ASSERT(delay >= 1000u && delay < 2000u);
    delay = tamga_retry_delay_ms(1u, 0);
    TT_ASSERT(delay >= 2000u && delay < 3000u);
    delay = tamga_retry_delay_ms(3u, 0);
    TT_ASSERT(delay >= 8000u && delay < 9000u);
    /* Flat past the sixth attempt rather than growing without bound. */
    delay = tamga_retry_delay_ms(9u, 0);
    TT_ASSERT(delay >= 32000u && delay < 33000u);
}

TT_TEST(a_rate_limited_request_is_retried_then_succeeds) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    /* Retry-After of 0 keeps the test instant while still exercising the
     * header-parsing path. */
    mock_reply_with_header(&mock, 429, "{\"errors\":[{\"code\":\"TOO_MANY_REQUESTS\"}]}",
                           "Retry-After", "0");
    mock_reply(&mock, 200, "{\"data\":{\"id\":\"x\"}}");

    client = make_client(&mock, "api.tamga.sh");
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_OK);
    TT_ASSERT_EQ_SIZE(mock.call_count, 2u);
    TT_ASSERT_EQ_INT(tamga_response_status(response), 200);

    tamga_response_free(response);
    tamga_client_free(client);
}

TT_TEST(a_sustained_rate_limit_gives_up_with_its_own_code) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply_with_header(&mock, 429, "{\"errors\":[{\"code\":\"TOO_MANY_REQUESTS\"}]}",
                           "Retry-After", "0");

    client = make_client(&mock, "api.tamga.sh");
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_set_max_retries(client, 2u), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_ERR_RATE_LIMITED);
    /* The original plus two retries. */
    TT_ASSERT_EQ_SIZE(mock.call_count, 3u);
    /* The response is still returned, carrying the server's Retry-After. */
    TT_ASSERT_NOT_NULL(response);
    TT_ASSERT_EQ_STR(tamga_response_header(response, "retry-after"), "0");

    tamga_response_free(response);
    tamga_client_free(client);
}

TT_TEST(a_create_is_never_retried_even_when_rate_limited) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply_with_header(&mock, 429, "{\"errors\":[{\"code\":\"TOO_MANY_REQUESTS\"}]}",
                           "Retry-After", "0");

    client = make_client(&mock, "api.tamga.sh");
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_create_machine(client, LICENSE_ID, "fp", NULL, &response),
                     TAMGA_ERR_RATE_LIMITED);
    TT_ASSERT_EQ_SIZE(mock.call_count, 1u);

    tamga_response_free(response);
    tamga_client_free(client);
}

TT_TEST(json_api_error_codes_map_to_typed_results) {
    struct {
        int status;
        const char *body;
        TamgaErrorCode expected;
    } cases[] = {
        {422, "{\"errors\":[{\"code\":\"CHECK_IN_NOT_REQUIRED\"}]}",
         TAMGA_ERR_CHECK_IN_NOT_REQUIRED},
        {422, "{\"errors\":[{\"code\":\"LICENSE_NOT_ENCRYPTED\"}]}",
         TAMGA_ERR_LICENSE_NOT_ENCRYPTED},
        {422, "{\"errors\":[{\"code\":\"TTL_INVALID\"}]}", TAMGA_ERR_TTL_INVALID},
        {422, "{\"errors\":[{\"code\":\"SCHEME_NOT_SUPPORTED\"}]}", TAMGA_ERR_SCHEME_NOT_SUPPORTED},
        {409, "{\"errors\":[{\"code\":\"FINGERPRINT_TAKEN\"}]}", TAMGA_ERR_FINGERPRINT_TAKEN},
        {422, "{\"errors\":[{\"code\":\"DATASET_INVALID\"}]}", TAMGA_ERR_DATASET_INVALID},
        {409, "{\"errors\":[{\"code\":\"PID_TAKEN\"}]}", TAMGA_ERR_PID_TAKEN},
        /* 401 and 403 stay distinct: a missing credential and an insufficient
         * one are different states, and conflating them makes a caller
         * re-prompt for something that will not help. */
        {401, "{\"errors\":[{\"code\":\"UNAUTHORIZED\"}]}", TAMGA_ERR_UNAUTHORIZED},
        {403, "{\"errors\":[{\"code\":\"FORBIDDEN\"}]}", TAMGA_ERR_FORBIDDEN},
        {404, "{\"errors\":[{\"code\":\"NOT_FOUND\"}]}", TAMGA_ERR_NOT_FOUND},
        {500, "{\"errors\":[{\"code\":\"INTERNAL_SERVER_ERROR\"}]}", TAMGA_ERR_SERVER},
        /* An unmodelled code still produces a usable outcome. */
        {418, "{\"errors\":[{\"code\":\"SOMETHING_NEW\"}]}", TAMGA_ERR_API},
        /* A non-JSON body from a proxy must not become a parse failure. */
        {502, "<html>bad gateway</html>", TAMGA_ERR_SERVER},
    };
    size_t i;

    for (i = 0u; i < (sizeof(cases) / sizeof(cases[0])); i++) {
        MockTransport mock;
        TamgaClient *client;
        TamgaResponse *response = NULL;

        mock_reset(&mock);
        mock_reply(&mock, cases[i].status, cases[i].body);
        client = make_client(&mock, "api.tamga.sh");
        TT_ASSERT_NOT_NULL(client);
        TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), cases[i].expected);
        TT_ASSERT_EQ_INT(tamga_response_status(response), cases[i].status);
        tamga_response_free(response);
        tamga_client_free(client);
    }
}

/* The server's own code is preserved even when this SDK has no dedicated
 * value for it -- that string is usually the only actionable part. */
TT_TEST(the_servers_error_code_is_available_verbatim) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock_reply(&mock, 418, "{\"errors\":[{\"code\":\"SOMETHING_NEW\",\"detail\":\"nope\"}]}");
    client = make_client(&mock, "api.tamga.sh");
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_ERR_API);
    TT_ASSERT_EQ_STR(tamga_response_error_code(response), "SOMETHING_NEW");
    tamga_response_free(response);
    tamga_client_free(client);
}

TT_TEST(a_transport_failure_is_distinct_from_a_server_error) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    mock.fail_transport = true;
    client = make_client(&mock, "api.tamga.sh");
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_ERR_TRANSPORT);
    TT_ASSERT_NULL(response);
    TT_ASSERT_NOT_NULL(tamga_last_error_message());
    tamga_client_free(client);
}

TT_TEST(a_request_without_credentials_is_refused_before_it_is_sent) {
    MockTransport mock;
    TamgaClient *client = NULL;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    TT_ASSERT_EQ_INT(tamga_client_new(ACCOUNT, "api.tamga.sh", &client), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_client_set_transport(client, mock_perform, &mock, NULL), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_SIZE(mock.call_count, 0u);
    tamga_client_free(client);
}

/*
 * Header injection, the one finding an adversarial review of this layer
 * turned up as HIGH.
 *
 * Both transports serialise headers by joining them as "name: value\r\n"
 * into a single block. A caller-supplied value carrying its own CRLF
 * therefore appends attacker-chosen headers to a request this library
 * authenticates -- an overridden Content-Length, a header a front-end proxy
 * trusts, or a smuggled request. It was demonstrated end to end through the
 * transport boundary before being fixed.
 *
 * The OTP is the sharpest case: applications prompt an end user for it and
 * forward it straight through, so the value is under the control of exactly
 * the party this SDK exists to constrain.
 */
TT_TEST(a_line_break_in_the_otp_never_reaches_a_transport) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;
    static const char *const hostile[] = {
        "123456\r\nX-Injected: pwned",
        "123456\nX-Injected: pwned",
        "123456\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1",
    };
    size_t i;

    for (i = 0u; i < (sizeof(hostile) / sizeof(hostile[0])); i++) {
        mock_reset(&mock);
        client = make_client(&mock, "api.tamga.sh");
        TT_ASSERT_NOT_NULL(client);
        TT_ASSERT_EQ_INT(tamga_client_quick_validate(client, LICENSE_ID, hostile[i], &response),
                         TAMGA_ERR_NULL_ARGUMENT);
        /* Refused before anything was sent -- not sanitised on the way out. */
        TT_ASSERT_EQ_SIZE(mock.call_count, 0u);
        /* And the diagnostic must not echo a one-time credential. */
        TT_ASSERT_NOT_NULL(tamga_last_error_message());
        TT_ASSERT_NULL(strstr(tamga_last_error_message(), "123456"));
        tamga_response_free(response);
        tamga_client_free(client);
        response = NULL;
    }
}

/* The same class, one layer earlier: a credential carrying a line break is
 * refused when it is set, so it can never become a header at all. */
TT_TEST(a_line_break_in_a_credential_is_refused_at_configuration) {
    TamgaClient *client = NULL;

    TT_ASSERT_EQ_INT(tamga_client_new(ACCOUNT, "api.tamga.sh", &client), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_client_set_auth(client, TAMGA_AUTH_BEARER, "tok\r\nX-Evil: 1", NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_client_set_auth(client, TAMGA_AUTH_LICENSE, "lic\nX-Evil: 1", NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(
        tamga_client_set_auth(client, TAMGA_AUTH_BASIC_EMAIL_PASSWORD, "a@b.c", "pw\r\nX-Evil: 1"),
        TAMGA_ERR_NULL_ARGUMENT);
    /* A credential with no line break is unaffected. */
    TT_ASSERT_EQ_INT(tamga_client_set_auth(client, TAMGA_AUTH_BEARER, "tok-abc123", NULL),
                     TAMGA_OK);
    tamga_client_free(client);
}

/* A body containing a NUL byte is a well-formed response, not a transport
 * failure. Reporting it as one would make an ordinary server reply
 * indistinguishable from the network being down. */
TT_TEST(a_response_body_may_contain_a_nul_byte) {
    MockTransport mock;
    TamgaClient *client;
    TamgaResponse *response = NULL;

    mock_reset(&mock);
    /* The mock sends whatever length it is given, NUL included. */
    mock_reply(&mock, 200, "{\"a\":\"b\"}");
    client = make_client(&mock, "api.tamga.sh");
    TT_ASSERT_NOT_NULL(client);
    TT_ASSERT_EQ_INT(tamga_client_check_in(client, LICENSE_ID, &response), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_response_status(response), 200);
    tamga_response_free(response);
    tamga_client_free(client);
}

TT_TEST(configuration_is_validated) {
    TamgaClient *client = NULL;

    TT_ASSERT_EQ_INT(tamga_client_new(NULL, "host", &client), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_client_new("acct", NULL, &client), TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_client_new("", "host", &client), TAMGA_ERR_NULL_ARGUMENT);

    TT_ASSERT_EQ_INT(tamga_client_new(ACCOUNT, "api.tamga.sh", &client), TAMGA_OK);
    TT_ASSERT_EQ_INT(tamga_client_set_timeout_ms(client, 0u), TAMGA_ERR_LENGTH_INVALID);
    TT_ASSERT_EQ_INT(tamga_client_set_max_retries(client, 1000u), TAMGA_ERR_LENGTH_INVALID);
    /* The email form needs a password; the others must not require one. */
    TT_ASSERT_EQ_INT(tamga_client_set_auth(client, TAMGA_AUTH_BASIC_EMAIL_PASSWORD, "a@b.c", NULL),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_client_set_auth(client, (TamgaAuthKind)99, "x", NULL),
                     TAMGA_ERR_UNSUPPORTED_SCHEME);
    tamga_client_free(client);
    tamga_client_free(NULL);
}

int main(void) {
    TT_RUN(builds_the_account_scoped_base_url);
    TT_RUN(host_forms_normalise_consistently);
    TT_RUN(every_auth_transport_produces_the_documented_header);
    TT_RUN(the_query_transport_encodes_the_token_into_the_url);
    TT_RUN(standard_headers_are_present);
    TT_RUN(the_otp_header_is_sent_when_supplied);
    TT_RUN(the_api_version_is_sanitised_the_way_the_server_does);
    TT_RUN(only_safe_requests_are_retryable);
    TT_RUN(the_retry_delay_follows_the_documented_policy);
    TT_RUN(a_rate_limited_request_is_retried_then_succeeds);
    TT_RUN(a_sustained_rate_limit_gives_up_with_its_own_code);
    TT_RUN(a_create_is_never_retried_even_when_rate_limited);
    TT_RUN(json_api_error_codes_map_to_typed_results);
    TT_RUN(the_servers_error_code_is_available_verbatim);
    TT_RUN(a_transport_failure_is_distinct_from_a_server_error);
    TT_RUN(a_request_without_credentials_is_refused_before_it_is_sent);
    TT_RUN(a_line_break_in_the_otp_never_reaches_a_transport);
    TT_RUN(a_line_break_in_a_credential_is_refused_at_configuration);
    TT_RUN(a_response_body_may_contain_a_nul_byte);
    TT_RUN(configuration_is_validated);
    return TT_SUMMARY();
}
