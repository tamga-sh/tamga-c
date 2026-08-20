/*
 * Machine offline proof verification.
 *
 * The fixture proof was signed over the exact canonical payload the server
 * produces and confirmed against tamga-rust's verifier before being written
 * out, so these tests exercise byte-for-byte agreement on the serialization,
 * not just on the signature maths.
 */
#include "tamga_test.h"

#include "proof.h"
#include "tamga_error.h"
#include "tamga_mem.h"

#define CAP 4096

static const char ACCOUNT_ID[] = "01926b3e-0000-7000-8000-0000000000aa";
static const char MACHINE_ID[] = "01926b3e-0000-7000-8000-000000000002";
static const char FINGERPRINT[] = "9f8e7d6c5b4a39281706";

typedef struct ProofFixture {
    char proof[CAP];
    unsigned char spki[CAP];
    size_t spki_len;
    char dataset[CAP];
} ProofFixture;

static bool load(ProofFixture *f) {
    size_t proof_len =
        tt_read_fixture("offline/proof.txt", (unsigned char *)f->proof, sizeof(f->proof) - 1u);
    size_t dataset_len = tt_read_fixture("offline/proof_dataset.json", (unsigned char *)f->dataset,
                                         sizeof(f->dataset) - 1u);
    f->spki_len = tt_read_fixture("offline/rsa_spki.der", f->spki, sizeof(f->spki));
    if (proof_len == (size_t)-1 || dataset_len == (size_t)-1 || f->spki_len == (size_t)-1) {
        return false;
    }
    f->proof[proof_len] = '\0';
    f->dataset[dataset_len] = '\0';
    return true;
}

TT_TEST(verifies_a_real_proof) {
    ProofFixture f;
    bool valid = false;

    TT_ASSERT(load(&f));
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT, f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT(valid);
    TT_ASSERT_NULL(tamga_last_error_message());
}

/*
 * The signed payload sorts its keys, so a dataset written in a different
 * order is the same value and must still verify. This is the property that
 * makes the canonical serializer necessary: reproducing the caller's literal
 * text instead would fail here.
 */
TT_TEST(a_reordered_dataset_is_the_same_value) {
    ProofFixture f;
    bool valid = false;
    static const char reordered[] = "{\"nested\":{\"z\":true,\"y\":null},\"b\":1,\"a\":\"two\"}";

    TT_ASSERT(load(&f));
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT, reordered, &valid),
                     TAMGA_OK);
    TT_ASSERT(valid);
}

/* Whitespace is not part of the value either. */
TT_TEST(dataset_whitespace_is_irrelevant) {
    ProofFixture f;
    bool valid = false;
    static const char spaced[] =
        "{ \"a\" : \"two\" , \"b\" : 1 , \"nested\" : { \"y\" : null , \"z\" : true } }";

    TT_ASSERT(load(&f));
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT, spaced, &valid),
                     TAMGA_OK);
    TT_ASSERT(valid);
}

/* A UUID spelled differently is the same identifier: the server serializes
 * through a UUID type that always renders lowercase and hyphenated, so this
 * SDK normalizes rather than passing the caller's spelling through. */
TT_TEST(uuid_spelling_is_normalised_before_signing) {
    ProofFixture f;
    bool valid = false;
    static const char uppercase_account[] = "01926B3E-0000-7000-8000-0000000000AA";
    static const char braced_machine[] = "{01926b3e-0000-7000-8000-000000000002}";

    TT_ASSERT(load(&f));
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, uppercase_account,
                                        braced_machine, FINGERPRINT, f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT(valid);
}

TT_TEST(rejects_a_changed_tuple) {
    ProofFixture f;
    bool valid = true;

    TT_ASSERT(load(&f));

    /* different account */
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len,
                                        "01926b3e-0000-7000-8000-0000000000ab", MACHINE_ID,
                                        FINGERPRINT, f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);

    /* different machine */
    valid = true;
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, ACCOUNT_ID,
                                        "01926b3e-0000-7000-8000-000000000003", FINGERPRINT,
                                        f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);

    /* different fingerprint */
    valid = true;
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        "0000000000000000000", f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);

    /* different dataset value */
    valid = true;
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT,
                                        "{\"a\":\"two\",\"b\":2,\"nested\":{\"y\":null,"
                                        "\"z\":true}}",
                                        &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);

    /* an extra dataset key */
    valid = true;
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT,
                                        "{\"a\":\"two\",\"b\":1,\"c\":0,\"nested\":"
                                        "{\"y\":null,\"z\":true}}",
                                        &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);
}

/*
 * A malformed proof string is reported through out_valid rather than as a
 * call failure: the caller asked whether the proof holds, and it does not.
 * Returning an error code here would make "this is not a valid proof"
 * indistinguishable from "the SDK could not run the check".
 */
TT_TEST(a_malformed_proof_is_invalid_not_an_error) {
    ProofFixture f;
    bool valid = true;

    TT_ASSERT(load(&f));

    TT_ASSERT_EQ_INT(tamga_proof_verify("no-prefix-here", f.spki, f.spki_len, ACCOUNT_ID,
                                        MACHINE_ID, FINGERPRINT, f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);

    valid = true;
    TT_ASSERT_EQ_INT(tamga_proof_verify("v2x0.AAAA", f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT, f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);

    valid = true;
    TT_ASSERT_EQ_INT(tamga_proof_verify("v1x0.", f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT, f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);

    valid = true;
    TT_ASSERT_EQ_INT(tamga_proof_verify("v1x0.!!!not-base64!!!", f.spki, f.spki_len, ACCOUNT_ID,
                                        MACHINE_ID, FINGERPRINT, f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);

    valid = true;
    TT_ASSERT_EQ_INT(tamga_proof_verify("v1x0.AAAA", f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT, f.dataset, &valid),
                     TAMGA_OK);
    TT_ASSERT_FALSE(valid);
}

/* Genuine call failures -- as opposed to an invalid proof -- do return an
 * error, because there is nothing the caller can conclude about the proof. */
TT_TEST(bad_arguments_are_call_failures) {
    ProofFixture f;
    bool valid = true;

    TT_ASSERT(load(&f));

    TT_ASSERT_EQ_INT(tamga_proof_verify(NULL, f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT, f.dataset, &valid),
                     TAMGA_ERR_NULL_ARGUMENT);
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, "not-a-uuid", MACHINE_ID,
                                        FINGERPRINT, f.dataset, &valid),
                     TAMGA_ERR_INVALID_JSON);
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT, "{not json", &valid),
                     TAMGA_ERR_INVALID_JSON);
    /* The server refuses a non-object dataset with 422, so no proof could
     * ever have been issued for one. */
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, f.spki_len, ACCOUNT_ID, MACHINE_ID,
                                        FINGERPRINT, "[1,2,3]", &valid),
                     TAMGA_ERR_INVALID_JSON);
    TT_ASSERT_EQ_INT(tamga_proof_verify(f.proof, f.spki, 0u, ACCOUNT_ID, MACHINE_ID, FINGERPRINT,
                                        f.dataset, &valid),
                     TAMGA_ERR_LENGTH_INVALID);
}

int main(void) {
    TT_RUN(verifies_a_real_proof);
    TT_RUN(a_reordered_dataset_is_the_same_value);
    TT_RUN(dataset_whitespace_is_irrelevant);
    TT_RUN(uuid_spelling_is_normalised_before_signing);
    TT_RUN(rejects_a_changed_tuple);
    TT_RUN(a_malformed_proof_is_invalid_not_an_error);
    TT_RUN(bad_arguments_are_call_failures);
    return TT_SUMMARY();
}
