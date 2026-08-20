#include "proof.h"

#include <string.h>

#include "crypto/rsa.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/base64.h"
#include "util/json.h"
#include "util/uuid.h"

static const char TAMGA_PROOF_PREFIX[] = "v1x0.";

/*
 * Builds the payload as a value tree and lets the canonical serialiser order
 * it, exactly as the server's serde_json does. Writing the fields in source
 * order and trusting that order would be wrong -- see proof.h.
 */
static TamgaErrorCode tamga_proof_build_payload(const char *account_id, const char *machine_id,
                                                const char *fingerprint, const char *dataset_json,
                                                char **out_payload, size_t *out_payload_len) {
    char account_canonical[TAMGA_UUID_STRING_SIZE];
    char machine_canonical[TAMGA_UUID_STRING_SIZE];
    TamgaJson *root = NULL;
    TamgaJson *account = NULL;
    TamgaJson *machine = NULL;
    TamgaJson *dataset = NULL;
    const char *parse_error = NULL;
    char *payload;

    /* The server serialises these as uuid::Uuid, which always renders
     * lowercase and hyphenated. A caller who passes the same UUID in a
     * different spelling must still produce the same signed bytes, so both
     * are normalised rather than copied through. */
    if (!tamga_uuid_normalize(account_id, account_canonical)) {
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "the account id is not a valid UUID");
    }
    if (!tamga_uuid_normalize(machine_id, machine_canonical)) {
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "the machine id is not a valid UUID");
    }

    dataset = tamga_json_parse(dataset_json, strlen(dataset_json), &parse_error);
    if (dataset == NULL) {
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "the dataset is not valid JSON: %s",
                               (parse_error != NULL) ? parse_error : "unknown");
    }
    /* The server rejects a non-object dataset with 422 DATASET_INVALID, so a
     * proof could never have been issued for one. */
    if (tamga_json_type(dataset) != TAMGA_JSON_OBJECT) {
        tamga_json_free(dataset);
        return tamga_error_set(TAMGA_ERR_INVALID_JSON, "the dataset must be a JSON object");
    }

    root = tamga_json_new_object();
    account = tamga_json_new_object();
    machine = tamga_json_new_object();
    if (root == NULL || account == NULL || machine == NULL) {
        tamga_json_free(root);
        tamga_json_free(account);
        tamga_json_free(machine);
        tamga_json_free(dataset);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the proof payload");
    }

    if (!tamga_json_object_set(
            account, "id", tamga_json_new_string(account_canonical, strlen(account_canonical))) ||
        !tamga_json_object_set(
            machine, "id", tamga_json_new_string(machine_canonical, strlen(machine_canonical))) ||
        !tamga_json_object_set(machine, "fingerprint",
                               tamga_json_new_string(fingerprint, strlen(fingerprint))) ||
        !tamga_json_object_set(root, "account", account) ||
        !tamga_json_object_set(root, "machine", machine) ||
        !tamga_json_object_set(root, "dataset", dataset)) {
        /* Every setter takes ownership even when it fails, so the children
         * are already released; only the root can still be outstanding. */
        tamga_json_free(root);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not build the proof payload");
    }

    payload = tamga_json_write_canonical(root, out_payload_len);
    tamga_json_free(root);
    if (payload == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not serialise the proof payload");
    }
    *out_payload = payload;
    return TAMGA_OK;
}

TamgaErrorCode tamga_proof_verify(const char *proof, const unsigned char *rsa_pubkey,
                                  size_t rsa_pubkey_len, const char *account_id,
                                  const char *machine_id, const char *fingerprint,
                                  const char *dataset_json, bool *out_valid) {
    TamgaErrorCode status;
    char *payload = NULL;
    size_t payload_len = 0u;
    unsigned char *signature = NULL;
    size_t signature_len = 0u;
    size_t prefix_len = sizeof(TAMGA_PROOF_PREFIX) - 1u;
    size_t proof_len;

    if (proof == NULL || rsa_pubkey == NULL || account_id == NULL || machine_id == NULL ||
        fingerprint == NULL || dataset_json == NULL || out_valid == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "a required argument was null");
    }
    *out_valid = false;

    if (rsa_pubkey_len == 0u || rsa_pubkey_len > TAMGA_MAX_REASONABLE_LEN) {
        return tamga_error_set(TAMGA_ERR_LENGTH_INVALID,
                               "public key length is zero or exceeds the accepted maximum");
    }

    status = tamga_proof_build_payload(account_id, machine_id, fingerprint, dataset_json, &payload,
                                       &payload_len);
    if (status != TAMGA_OK) {
        return status;
    }

    /* From here on, anything wrong with the proof string itself is reported
     * as "not valid" rather than as a call failure: the caller asked whether
     * the proof holds, and it does not. */
    proof_len = strlen(proof);
    if (proof_len <= prefix_len || memcmp(proof, TAMGA_PROOF_PREFIX, prefix_len) != 0) {
        tamga_string_free(payload);
        return TAMGA_OK;
    }

    signature =
        tamga_base64_decode_alloc(&proof[prefix_len], proof_len - prefix_len, &signature_len);
    if (signature == NULL) {
        tamga_string_free(payload);
        return TAMGA_OK;
    }

    *out_valid =
        tamga_rsa_verify_pkcs1_sha256(rsa_pubkey, rsa_pubkey_len, (const unsigned char *)payload,
                                      payload_len, signature, signature_len);

    tamga_free(signature);
    tamga_string_free(payload);
    return TAMGA_OK;
}
