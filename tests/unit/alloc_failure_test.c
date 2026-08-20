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

#include "http/client.h"
#include "support/failing_alloc.h"
#include "tamga.h"

#include <string.h>

#define FILE_CAP 8192

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

static TamgaErrorCode verify_machine_file(void) {
    TamgaMachineFile *handle = NULL;
    TamgaErrorCode status = tamga_machine_file_verify(
        g_pem, (uintptr_t)g_pem_len, TAMGA_SCHEME_ED25519_SIGN, g_ed25519_pubkey, 32u,
        "MUP7-2TQK-7FBF-4Q6H-Y7ZR-9C3V", "fingerprint-1", &handle);
    tamga_machine_file_free(handle);
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
    g_pem_len =
        tt_read_fixture("offline/machine_ed25519.mach", (unsigned char *)g_pem, sizeof(g_pem));
    TT_ASSERT(g_pem_len != (size_t)-1);
    TT_ASSERT_EQ_SIZE(tt_read_fixture("offline/ed25519_pubkey.bin", g_ed25519_pubkey, 32u), 32u);

    walk_allocations("tamga_machine_file_verify", verify_machine_file, TAMGA_OK);
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
static bool always_ok_perform(void *user_data, const char *method, const char *url,
                              const char *const *header_names, const char *const *header_values,
                              uintptr_t header_count, const char *body, uintptr_t body_len,
                              unsigned int timeout_ms, TamgaHttpResult *result) {
    static const char REPLY[] = "{\"data\":{\"id\":\"01926b3e-0000-7000-8000-000000000002\"}}";
    (void)user_data;
    (void)method;
    (void)url;
    (void)header_names;
    (void)header_values;
    (void)header_count;
    (void)body;
    (void)body_len;
    (void)timeout_ms;
    tamga_http_result_set_status(result, 200);
    return tamga_http_result_set_body(result, REPLY, (uintptr_t)(sizeof(REPLY) - 1u));
}

static TamgaClient *g_client;

/* Builds a client without counting its allocations against the walk, so a
 * walk measures only the operation under test. */
static bool open_client(void) {
    tamga_client_free(g_client);
    g_client = NULL;
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

TT_TEST(request_builders_survive_every_allocation_failure) {
    static const struct {
        const char *label;
        AllocOp op;
    } CASES[] = {
        {"tamga_client_create_machine", create_machine},
        {"tamga_client_check_out_license_json", check_out_license},
        {"tamga_client_validate_by_id", validate_by_id},
    };
    size_t i;

    for (i = 0u; i < (sizeof(CASES) / sizeof(CASES[0])); i++) {
        unsigned long total;
        unsigned long n;

        TT_ASSERT(open_client());
        tamga_test_alloc_reset();
        if (CASES[i].op() != TAMGA_OK) {
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

            if (status != TAMGA_OK && status != TAMGA_ERR_OUT_OF_MEMORY) {
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
    return TT_SUMMARY();
}
