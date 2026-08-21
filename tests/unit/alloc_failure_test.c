/*
 * Every allocation on the offline path, failed one at a time.
 *
 * The suite could not previously reach a single TAMGA_ERR_OUT_OF_MEMORY
 * branch -- roughly thirty-five of them across proof.c, tamga_api.c,
 * checkout/ and util/ -- because nothing could make an allocation fail. They
 * were, as far as any test could prove, dead code.
 *
 * The method here is exhaustive rather than sampled: run the operation once
 * to count how many allocations it makes, then run it again N times, failing
 * allocation 1, then 2, and so on to N. Each run must either succeed or
 * fail cleanly with TAMGA_ERR_OUT_OF_MEMORY -- never crash, never return
 * TAMGA_OK with a half-built handle, and never leak, which is what makes
 * running this file under ASan/LSan the point rather than an extra.
 *
 * The HTTP sources are deliberately not linked in: this is the offline
 * surface, the one that must link against libc alone.
 */
#include "tamga_test.h"

#include "checkout/machine_file.h"
#include "http/client.h"
#include "support/failing_alloc.h"
#include "tamga.h"
#include "tamga_mem.h"
#include "util/base64.h"
#include "util/json.h"

#include <string.h>

#define FILE_CAP 8192

/*
 * The Ed25519 key for server-machine-files/ed25519_encrypted_valid.machine,
 * copied from that directory's manifest.json, and a clock reading before any
 * possible expiry so this walk's expected status stays TAMGA_OK for good --
 * the fixture itself was issued with a one-hour ttl.
 */
#define MACHINE_FIXTURE_PUBKEY_B64 "AQAg/HkMCKUVnpDfZAVDWheJo2UmA6fiBHTUDgCFC0g="
#define MACHINE_FIXTURE_BEFORE_ANY_EXPIRY 0

/* An operation to walk. Returns the library's status; out-params are freed
 * by the operation itself so a leak here is the library's, not the test's. */
typedef TamgaErrorCode (*AllocOp)(void);

static char g_pem[FILE_CAP];
static size_t g_pem_len;
static unsigned char g_ed25519_pubkey[32];
static unsigned char g_rsa_pubkey[512];
static size_t g_rsa_pubkey_len;
static char g_proof[FILE_CAP];
static char g_dataset[FILE_CAP];

static TamgaErrorCode verify_licence_file(void) {
    TamgaLicenseFile *handle = NULL;
    TamgaErrorCode status =
        tamga_license_file_verify(g_pem, (uintptr_t)g_pem_len, g_ed25519_pubkey, NULL, &handle);
    if (status == TAMGA_OK) {
        char *json = NULL;
        uintptr_t json_len = 0u;
        if (tamga_license_file_get_json(handle, &json, &json_len) == TAMGA_OK) {
            tamga_string_free(json);
        }
    }
    tamga_license_file_free(handle);
    return status;
}

/*
 * The encrypted machine-file path, which is the longer of the two: PEM,
 * certificate, signature, the "<nonce>.<ciphertext>" split, two base64
 * decodes, HKDF, AES-GCM, the JSON payload and the signed claims.
 *
 * It goes through tamga_machine_file_verify_at() rather than the public
 * wrapper because the fixture was issued with a one-hour ttl: against the
 * wall clock the public entry point starts answering TAMGA_ERR_EXPIRED an
 * hour after the fixture was generated, and this walk needs a stable expected
 * status. The wrapper's only additional allocation is the handle itself, and
 * the licence-file walk above covers that identical shape.
 */
static TamgaErrorCode verify_machine_file(void) {
    TamgaJson *resource = NULL;
    TamgaErrorCode status = tamga_machine_file_verify_at(
        g_pem, g_pem_len, (uint32_t)TAMGA_SCHEME_ED25519_SIGN, g_ed25519_pubkey, 32u,
        "TAMGA-FIXTURE-LICENSE-KEY-0001", "fixture-fingerprint-a1b2c3",
        MACHINE_FIXTURE_BEFORE_ANY_EXPIRY, &resource, NULL);
    tamga_json_free(resource);
    return status;
}

static TamgaErrorCode verify_offline_proof(void) {
    static const char ACCOUNT_ID[] = "01926b3e-0000-7000-8000-0000000000aa";
    static const char MACHINE_ID[] = "01926b3e-0000-7000-8000-000000000002";
    static const char FINGERPRINT[] = "9f8e7d6c5b4a39281706";
    bool valid = false;
    TamgaErrorCode status =
        tamga_offline_proof_verify(g_proof, g_rsa_pubkey, (uintptr_t)g_rsa_pubkey_len, ACCOUNT_ID,
                                   MACHINE_ID, FINGERPRINT, g_dataset, &valid);
    /* A verification that reports OK must also report a valid proof; an OK
     * with valid == false would mean an allocation failure had been turned
     * into "this proof is forged", which is the worst possible answer. */
    if (status == TAMGA_OK && !valid) {
        return TAMGA_ERR_SIGNATURE_INVALID;
    }
    return status;
}

/*
 * Runs `op` once to learn its allocation count, then once more per
 * allocation with that one failing.
 *
 * `label` names the operation in a failure message; `expect_ok` is what the
 * unperturbed run must return, so a fixture that stops loading is caught
 * here rather than silently turning the whole walk into a no-op.
 */
static void walk_allocations(const char *label, AllocOp op, TamgaErrorCode expect_ok) {
    unsigned long total;
    unsigned long n;

    tamga_test_alloc_reset();
    if (op() != expect_ok) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: %s did not succeed before any injection\n", tt_current_,
                      label);
        return;
    }
    total = tamga_test_alloc_calls;
    if (tamga_test_alloc_live != 0uL) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: %s leaked %lu block(s) on the success path\n", tt_current_,
                      label, tamga_test_alloc_live);
        tamga_test_alloc_reset();
        return;
    }
    if (total == 0uL) {
        tt_failures_++;
        (void)fprintf(stderr, "FAIL %s: %s allocated nothing -- the walk would prove nothing\n",
                      tt_current_, label);
        return;
    }

    for (n = 1uL; n <= total; n++) {
        TamgaErrorCode status;

        tamga_test_alloc_reset();
        tamga_test_alloc_fail_at = n;
        status = op();

        /* Either the library coped and produced the real answer, or it gave
         * up and said so. Any other code means a failed allocation was
         * mistaken for a different kind of problem -- a corrupt file, say --
         * which is how an out-of-memory turns into a support ticket about a
         * licence that "stopped working". */
        if (status != expect_ok && status != TAMGA_ERR_OUT_OF_MEMORY) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s returned %s when allocation %lu of %lu failed\n",
                          tt_current_, label, tamga_error_name(status), n, total);
            tamga_test_alloc_reset();
            return;
        }
        /* And it cleaned up after itself. Giving up part-way is fine; giving
         * up part-way while holding onto everything allocated so far is the
         * defect this whole file exists to find, and it is invisible to a
         * test that only checks the return code. */
        if (tamga_test_alloc_live != 0uL) {
            tt_failures_++;
            (void)fprintf(stderr,
                          "FAIL %s: %s leaked %lu block(s) when allocation %lu of %lu failed\n",
                          tt_current_, label, tamga_test_alloc_live, n, total);
            tamga_test_alloc_reset();
            return;
        }
        /* A reported success must be a real one: the handle was fully built
         * and the caller can use it. verify_* above already exercises the
         * handle, so reaching here with TAMGA_OK means it did. */
    }
    tamga_test_alloc_reset();
}

TT_TEST(licence_file_verification_survives_every_allocation_failure) {
    g_pem_len = tt_read_fixture("offline/license_plain.lic", (unsigned char *)g_pem, sizeof(g_pem));
    TT_ASSERT(g_pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", g_ed25519_pubkey, 32u), 32u);

    walk_allocations("tamga_license_file_verify", verify_licence_file, TAMGA_OK);
}

TT_TEST(machine_file_verification_survives_every_allocation_failure) {
    unsigned char *decoded;
    size_t decoded_len = 0u;

    g_pem_len = tt_read_fixture("server-machine-files/ed25519_encrypted_valid.machine",
                                (unsigned char *)g_pem, sizeof(g_pem));
    TT_ASSERT(g_pem_len != (size_t)-1);

    /* The key lives in the fixture manifest rather than in a .bin beside the
     * file; pulling the one line out is cheaper here than parsing JSON. */
    decoded = tamga_base64_decode_alloc(MACHINE_FIXTURE_PUBKEY_B64,
                                        strlen(MACHINE_FIXTURE_PUBKEY_B64), &decoded_len);
    TT_ASSERT_NOT_NULL(decoded);
    TT_ASSERT_EQ_SIZE(decoded_len, 32u);
    memcpy(g_ed25519_pubkey, decoded, 32u);
    tamga_free(decoded);

    walk_allocations("tamga_machine_file_verify_at", verify_machine_file, TAMGA_OK);
}

TT_TEST(offline_proof_verification_survives_every_allocation_failure) {
    size_t proof_len;
    size_t dataset_len;

    proof_len =
        tt_read_fixture("offline/proof.txt", (unsigned char *)g_proof, sizeof(g_proof) - 1u);
    TT_ASSERT(proof_len != (size_t)-1);
    g_proof[proof_len] = '\0';
    while (proof_len > 0u && (g_proof[proof_len - 1u] == '\n' || g_proof[proof_len - 1u] == '\r')) {
        proof_len--;
        g_proof[proof_len] = '\0';
    }

    dataset_len = tt_read_fixture("offline/proof_dataset.json", (unsigned char *)g_dataset,
                                  sizeof(g_dataset) - 1u);
    TT_ASSERT(dataset_len != (size_t)-1);
    g_dataset[dataset_len] = '\0';

    g_rsa_pubkey_len = tt_read_fixture("offline/rsa_spki.der", g_rsa_pubkey, sizeof(g_rsa_pubkey));
    TT_ASSERT(g_rsa_pubkey_len != (size_t)-1);

    walk_allocations("tamga_offline_proof_verify", verify_offline_proof, TAMGA_OK);
}

/* --- the HTTP request builders --------------------------------------------
 *
 * These build a JSON:API body out of several separately allocated objects
 * before handing any of them to a parent, which is exactly the shape that
 * leaked in tamga_proof_build_payload -- and the shape is repeated in eight
 * more endpoints. The transport below always succeeds, so the only thing
 * that can fail during these walks is an allocation.
 */
/* The scripted reply. A non-2xx one matters as much as a 2xx: the error path
 * reads response->json to pull the JSON:API `code` out, so an allocation
 * failure there would fall back to a generic TAMGA_ERR_API and lose the
 * specific error the server actually sent. */
static int g_reply_status = 200;
static const char *g_reply_body = "{\"data\":{\"id\":\"01926b3e-0000-7000-8000-000000000002\"}}";

/*
 * A scripted reply sequence, for the operations that make more than one
 * request. The composites are exactly where an allocation failure part-way
 * through can strand the response from an earlier leg, so they have to be
 * walkable -- and that needs each leg to get its own answer.
 *
 * Empty means "answer every call with g_reply_status/g_reply_body"; the last
 * scripted entry repeats, so a script only has to cover the interesting
 * prefix.
 */
#define SCRIPT_MAX 4
static struct {
    int status;
    const char *body;
} g_script[SCRIPT_MAX];
static size_t g_script_len;
static size_t g_script_pos;

static bool always_ok_perform(void *user_data, const char *method, const char *url,
                              const char *const *header_names, const char *const *header_values,
                              uintptr_t header_count, const char *body, uintptr_t body_len,
                              unsigned int timeout_ms, TamgaHttpResult *result) {
    int status = g_reply_status;
    const char *reply = g_reply_body;

    (void)user_data;
    (void)method;
    (void)url;
    (void)header_names;
    (void)header_values;
    (void)header_count;
    (void)body;
    (void)body_len;
    (void)timeout_ms;

    if (g_script_len > 0u) {
        size_t index = (g_script_pos < g_script_len) ? g_script_pos : (g_script_len - 1u);
        status = g_script[index].status;
        reply = g_script[index].body;
        g_script_pos++;
    }
    tamga_http_result_set_status(result, status);
    return tamga_http_result_set_body(result, reply, (uintptr_t)strlen(reply));
}

static void script_reset(void) {
    g_script_len = 0u;
    g_script_pos = 0u;
}

static void script_add(int status, const char *body) {
    if (g_script_len < SCRIPT_MAX) {
        g_script[g_script_len].status = status;
        g_script[g_script_len].body = body;
        g_script_len++;
    }
}

static TamgaClient *g_client;

/* Builds a client without counting its allocations against the walk, so a
 * walk measures only the operation under test. */
static bool open_client(void) {
    tamga_client_free(g_client);
    g_client = NULL;
    /* Each run of an op replays the same script from the top. */
    g_script_pos = 0u;
    if (tamga_client_new("01926b3e-0000-7000-8000-0000000000aa", "api.tamga.sh", &g_client) !=
        TAMGA_OK) {
        return false;
    }
    if (tamga_client_set_auth(g_client, TAMGA_AUTH_BEARER, "tok-abc123", NULL) != TAMGA_OK) {
        return false;
    }
    return tamga_client_set_transport(g_client, always_ok_perform, NULL, NULL) == TAMGA_OK;
}

/*
 * A TAMGA_OK from any of these must come with a usable response.
 *
 * The mock always replies with the same well-formed JSON, so if the call
 * succeeded, response->json parsed. A NULL tree behind a TAMGA_OK is the
 * failure mode this guards: every accessor built on it reads NULL as "the
 * field was absent" and answers false, so the caller is told a valid licence
 * is invalid, with the server's real answer still unread in the body. The
 * walk exercised that path from the day it was written and could not see it,
 * because it only checked the return code.
 */
static TamgaErrorCode response_must_be_usable(TamgaErrorCode status, TamgaResponse *response) {
    /* The parsed tree, not tamga_response_json() -- that returns the raw body
     * text, which is present either way and would prove nothing. */
    if (status == TAMGA_OK && (response == NULL || response->json == NULL)) {
        return TAMGA_ERR_INVALID_JSON; /* neither expected code: the walk fails */
    }
    return status;
}

static TamgaErrorCode create_machine(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status = tamga_client_create_machine(
        g_client, "01926b3e-0000-7000-8000-0000000000bb", "fingerprint-1",
        "{\"name\":\"a-name\",\"cores\":4,\"metadata\":{\"seat\":1}}", &response);
    status = response_must_be_usable(status, response);
    tamga_response_free(response);
    return status;
}

static TamgaErrorCode check_out_license(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status = tamga_client_check_out_license_json(
        g_client, "01926b3e-0000-7000-8000-0000000000bb", true, 3600, &response);
    status = response_must_be_usable(status, response);
    tamga_response_free(response);
    return status;
}

static TamgaErrorCode validate_by_id(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status =
        tamga_client_validate_by_id(g_client, "01926b3e-0000-7000-8000-0000000000bb",
                                    "{\"product\":\"x\"}", false, NULL, &response);
    status = response_must_be_usable(status, response);
    tamga_response_free(response);
    return status;
}

/*
 * Models a caller written against 1.3.0: it does NOT free `*out_response` on
 * a failed activation, because in 1.3.0 that pointer was always NULL there.
 *
 * That contract is preserved for every creation failure except the five
 * create-time limit codes, so this must strand nothing. If
 * tamga_client_activate_machine() were widened to hand its creation response
 * back on any failure, this op would leak one response per call and the walk
 * below would report it -- which is the whole point of writing it this way.
 * LeakSanitizer would catch it too, but it is unsupported on macOS, so this
 * counter is the check that actually runs everywhere.
 */
static TamgaErrorCode activate_machine_conflict_without_freeing(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status =
        tamga_client_activate_machine(g_client, "01926b3e-0000-7000-8000-0000000000bb",
                                      "fingerprint-1", NULL, NULL, true, &response);

    if (status != TAMGA_ERR_OUT_OF_MEMORY && response != NULL) {
        /* Deliberately not freed -- see above. Returning a code the walk does
         * not expect is how the assertion fails loudly rather than by
         * stranding a block a later reset would forget about. */
        return TAMGA_ERR_UNKNOWN;
    }
    return status;
}

/*
 * The other half: on a create-time limit the response IS handed back, so
 * ownership genuinely transfers and a single free has to balance it exactly
 * -- no leak, and no double free when an allocation failed part-way through
 * building it.
 */
static TamgaErrorCode activate_machine_limit_and_free(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status =
        tamga_client_activate_machine(g_client, "01926b3e-0000-7000-8000-0000000000bb",
                                      "fingerprint-1", NULL, NULL, true, &response);

    tamga_response_free(response);
    return status;
}

#define ALLOC_LICENSE_ID "01926b3e-0000-7000-8000-0000000000bb"
#define ALLOC_MACHINE_ID "01926b3e-0000-7000-8000-000000000002"
#define ALLOC_PRODUCT_ID "01926b3e-0000-7000-8000-000000000006"
#define ALLOC_PROCESS_ID "01926b3e-0000-7000-8000-000000000003"

/* One page holding the machine the lookups below are asked for. */
#define ALLOC_MACHINE_PAGE                                                                         \
    "{\"data\":[{\"id\":\"" ALLOC_MACHINE_ID "\","                                                 \
    "\"attributes\":{\"fingerprint\":\"fingerprint-1\"}}],"                                        \
    "\"meta\":{\"page\":{\"number\":1,\"size\":100,\"total\":1,\"totalPages\":1}}}"

#define ALLOC_CONFLICT                                                                             \
    "{\"errors\":[{\"status\":\"409\",\"code\":\"FINGERPRINT_TAKEN\","                             \
    "\"title\":\"Conflict\",\"detail\":\"already activated\"}]}"

#define ALLOC_VALIDATION "{\"data\":{},\"meta\":{\"valid\":true,\"code\":\"VALID\"}}"

static TamgaErrorCode update_machine(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status = tamga_client_update_machine(
        g_client, ALLOC_MACHINE_ID,
        "{\"hostname\":\"build-02\",\"cores\":8,\"metadata\":{\"a\":1}}", &response);
    status = response_must_be_usable(status, response);
    tamga_response_free(response);
    return status;
}

static TamgaErrorCode list_machines(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status = tamga_client_list_machines(g_client, ALLOC_LICENSE_ID, "fingerprint-1",
                                                       1u, 100u, &response);
    status = response_must_be_usable(status, response);
    tamga_response_free(response);
    return status;
}

static TamgaErrorCode check_upgrade(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status =
        tamga_client_check_upgrade(g_client, ALLOC_PRODUCT_ID, "darwin-aarch64", "dmg", "1.2.0",
                                   "beta", ">=1.2, <2", &response);
    status = response_must_be_usable(status, response);
    tamga_response_free(response);
    return status;
}

static TamgaErrorCode health(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status = tamga_client_health(g_client, &response);
    status = response_must_be_usable(status, response);
    tamga_response_free(response);
    return status;
}

static TamgaErrorCode delete_process(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status = tamga_client_delete_process(g_client, ALLOC_PROCESS_ID, &response);
    status = response_must_be_usable(status, response);
    tamga_response_free(response);
    return status;
}

/*
 * The lookup behind the idempotent activation, walked on its own.
 *
 * A TAMGA_OK carrying no id would mean an allocation failure had been turned
 * into "this machine is not activated" -- and the caller above reads that as
 * "the fingerprint belongs to another licence", which is a wrong and
 * unactionable answer to an out-of-memory. Returning a code the walk does not
 * expect is how that fails loudly.
 */
static TamgaErrorCode find_machine_by_fingerprint(void) {
    char *machine_id = NULL;
    TamgaErrorCode status = tamga_client_find_machine_by_fingerprint(g_client, ALLOC_LICENSE_ID,
                                                                     "fingerprint-1", &machine_id);
    if (status == TAMGA_OK && machine_id == NULL) {
        return TAMGA_ERR_NOT_FOUND;
    }
    tamga_string_free(machine_id);
    return status;
}

/*
 * Three requests in one call -- create (409), lookup, validate -- so an
 * allocation failure can land between any two of them with an earlier leg's
 * response still outstanding. That is the shape the counter below exists to
 * catch.
 */
static TamgaErrorCode activate_machine_idempotent(void) {
    TamgaResponse *response = NULL;
    TamgaErrorCode status = tamga_client_activate_machine_idempotent(
        g_client, ALLOC_LICENSE_ID, "fingerprint-1", NULL, NULL, true, &response);

    tamga_response_free(response);
    return status;
}

TT_TEST(the_added_endpoints_survive_every_allocation_failure) {
    static const struct {
        const char *label;
        AllocOp op;
        int reply_status;
        const char *reply_body;
        TamgaErrorCode expected;
        const char *script[3];
        int script_status[3];
    } CASES[] = {
        {"tamga_client_update_machine",
         update_machine,
         200,
         "{\"data\":{\"id\":\"" ALLOC_MACHINE_ID "\"}}",
         TAMGA_OK,
         {NULL, NULL, NULL},
         {0, 0, 0}},
        {"tamga_client_list_machines",
         list_machines,
         200,
         ALLOC_MACHINE_PAGE,
         TAMGA_OK,
         {NULL, NULL, NULL},
         {0, 0, 0}},
        {"tamga_client_check_upgrade",
         check_upgrade,
         200,
         "{\"data\":{\"id\":\"" ALLOC_MACHINE_ID "\"}}",
         TAMGA_OK,
         {NULL, NULL, NULL},
         {0, 0, 0}},
        {"tamga_client_health",
         health,
         200,
         "{\"status\":\"ok\",\"version\":\"0.1.0\",\"uptime_secs\":42}",
         TAMGA_OK,
         {NULL, NULL, NULL},
         {0, 0, 0}},
        {"tamga_client_delete_process",
         delete_process,
         200,
         "{\"data\":{\"id\":\"" ALLOC_PROCESS_ID "\"}}",
         TAMGA_OK,
         {NULL, NULL, NULL},
         {0, 0, 0}},
        {"tamga_client_find_machine_by_fingerprint",
         find_machine_by_fingerprint,
         200,
         ALLOC_MACHINE_PAGE,
         TAMGA_OK,
         {NULL, NULL, NULL},
         {0, 0, 0}},
        {"tamga_client_activate_machine_idempotent",
         activate_machine_idempotent,
         0,
         NULL,
         TAMGA_OK,
         {ALLOC_CONFLICT, ALLOC_MACHINE_PAGE, ALLOC_VALIDATION},
         {409, 200, 200}},
    };
    size_t i;

    for (i = 0u; i < (sizeof(CASES) / sizeof(CASES[0])); i++) {
        unsigned long total;
        unsigned long n;
        size_t leg;

        script_reset();
        for (leg = 0u; leg < 3u; leg++) {
            if (CASES[i].script[leg] != NULL) {
                script_add(CASES[i].script_status[leg], CASES[i].script[leg]);
            }
        }
        g_reply_status = CASES[i].reply_status;
        g_reply_body = CASES[i].reply_body;

        TT_ASSERT(open_client());
        tamga_test_alloc_reset();
        if (CASES[i].op() != CASES[i].expected) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s did not succeed before any injection\n", tt_current_,
                          CASES[i].label);
            continue;
        }
        total = tamga_test_alloc_calls;
        TT_ASSERT(total > 0uL);

        for (n = 1uL; n <= total; n++) {
            TamgaErrorCode status;
            unsigned long live_before;

            TT_ASSERT(open_client());
            tamga_test_alloc_reset();
            live_before = tamga_test_alloc_live;
            tamga_test_alloc_fail_at = n;
            status = CASES[i].op();

            if (status != CASES[i].expected && status != TAMGA_ERR_OUT_OF_MEMORY) {
                tt_failures_++;
                (void)fprintf(stderr, "FAIL %s: %s returned %s when allocation %lu of %lu failed\n",
                              tt_current_, CASES[i].label, tamga_error_name(status), n, total);
                break;
            }
            if (tamga_test_alloc_live != live_before) {
                tt_failures_++;
                (void)fprintf(
                    stderr, "FAIL %s: %s leaked %lu block(s) when allocation %lu of %lu failed\n",
                    tt_current_, CASES[i].label, tamga_test_alloc_live - live_before, n, total);
                break;
            }
        }
        tamga_test_alloc_reset();
    }
    script_reset();
    tamga_client_free(g_client);
    g_client = NULL;
}

TT_TEST(request_builders_survive_every_allocation_failure) {
    /* The last case is a non-2xx reply, and its expected outcome is the
     * specific error the server sent, not TAMGA_OK. Falling back to the
     * generic TAMGA_ERR_API would mean an allocation failure had swallowed
     * the JSON:API `code` -- the same defect as the 2xx case, one branch
     * over, and previously untested on this side. */
    static const struct {
        const char *label;
        AllocOp op;
        int reply_status;
        const char *reply_body;
        TamgaErrorCode expected;
    } CASES[] = {
        {"tamga_client_create_machine", create_machine, 200,
         "{\"data\":{\"id\":\"01926b3e-0000-7000-8000-000000000002\"}}", TAMGA_OK},
        {"tamga_client_check_out_license_json", check_out_license, 200,
         "{\"data\":{\"id\":\"01926b3e-0000-7000-8000-000000000002\"}}", TAMGA_OK},
        {"tamga_client_validate_by_id", validate_by_id, 200,
         "{\"data\":{\"id\":\"01926b3e-0000-7000-8000-000000000002\"}}", TAMGA_OK},
        {"tamga_client_validate_by_id (422)", validate_by_id, 422,
         "{\"errors\":[{\"status\":\"422\",\"code\":\"DATASET_INVALID\","
         "\"title\":\"Unprocessable\",\"detail\":\"dataset must be an object\"}]}",
         TAMGA_ERR_DATASET_INVALID},
        /* The two activate_machine creation-failure shapes. They differ only
         * in whether the response comes back, which is exactly the contract
         * these two ops assert from opposite sides. */
        {"tamga_client_activate_machine (409, caller frees nothing)",
         activate_machine_conflict_without_freeing, 409,
         "{\"errors\":[{\"status\":\"409\",\"code\":\"FINGERPRINT_TAKEN\","
         "\"title\":\"Conflict\",\"detail\":\"fingerprint is already taken\"}]}",
         TAMGA_ERR_FINGERPRINT_TAKEN},
        {"tamga_client_activate_machine (422 limit, caller frees)", activate_machine_limit_and_free,
         422,
         "{\"errors\":[{\"status\":\"422\",\"code\":\"MACHINE_LIMIT_EXCEEDED\","
         "\"title\":\"Unprocessable\",\"detail\":\"machine limit exceeded\"}]}",
         TAMGA_ERR_MACHINE_LIMIT_EXCEEDED},
    };
    size_t i;

    for (i = 0u; i < (sizeof(CASES) / sizeof(CASES[0])); i++) {
        unsigned long total;
        unsigned long n;

        g_reply_status = CASES[i].reply_status;
        g_reply_body = CASES[i].reply_body;

        TT_ASSERT(open_client());
        tamga_test_alloc_reset();
        if (CASES[i].op() != CASES[i].expected) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: %s did not succeed before any injection\n", tt_current_,
                          CASES[i].label);
            continue;
        }
        total = tamga_test_alloc_calls;
        TT_ASSERT(total > 0uL);

        for (n = 1uL; n <= total; n++) {
            TamgaErrorCode status;
            unsigned long live_before;

            /* The client is rebuilt outside the counted region, so its own
             * allocations neither shift the injection index nor show up as
             * outstanding blocks belonging to the operation. */
            TT_ASSERT(open_client());
            tamga_test_alloc_reset();
            live_before = tamga_test_alloc_live;
            tamga_test_alloc_fail_at = n;
            status = CASES[i].op();

            if (status != CASES[i].expected && status != TAMGA_ERR_OUT_OF_MEMORY) {
                tt_failures_++;
                (void)fprintf(stderr, "FAIL %s: %s returned %s when allocation %lu of %lu failed\n",
                              tt_current_, CASES[i].label, tamga_error_name(status), n, total);
                break;
            }
            if (tamga_test_alloc_live != live_before) {
                tt_failures_++;
                (void)fprintf(
                    stderr, "FAIL %s: %s leaked %lu block(s) when allocation %lu of %lu failed\n",
                    tt_current_, CASES[i].label, tamga_test_alloc_live - live_before, n, total);
                break;
            }
        }
        tamga_test_alloc_reset();
    }
    tamga_client_free(g_client);
    g_client = NULL;
}

int main(void) {
    TT_RUN(licence_file_verification_survives_every_allocation_failure);
    TT_RUN(machine_file_verification_survives_every_allocation_failure);
    TT_RUN(offline_proof_verification_survives_every_allocation_failure);
    TT_RUN(request_builders_survive_every_allocation_failure);
    TT_RUN(the_added_endpoints_survive_every_allocation_failure);
    return TT_SUMMARY();
}
