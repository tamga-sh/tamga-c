/*
 * tamga_api.c -- the public C entry points.
 *
 * A thin marshalling layer over the internal modules. Its job is the part
 * that is specific to being a C library rather than to licensing: validating
 * caller-supplied pointers and lengths before anything dereferences them,
 * owning the opaque handles, and keeping the per-thread error contract.
 *
 * Every signature here is byte-for-byte what v1.2.2 exported, including the
 * uintptr_t length parameters -- which are the wrong type for a length, and
 * are kept anyway. cbindgen chose them when it translated Rust's usize, they
 * are identical in width to size_t on every supported target, and the
 * repository's ABI-freeze commitment is worth more than the tidier
 * declaration.
 *
 * Contract, unchanged: every function clears the thread's last error on
 * entry, so a TAMGA_OK return always means tamga_last_error_message() is
 * NULL. The three free functions are the exception -- they cannot fail, and
 * clearing there would erase a message the caller is about to print.
 */
#include "tamga.h"

#include <string.h>

#include "checkout/license_file.h"
#include "checkout/machine_file.h"
#include "crypto/hkdf.h"
#include "proof.h"
#include "tamga_error.h"
#include "tamga_mem.h"
#include "util/json.h"
#include "util/rfc3339.h"

struct TamgaLicenseFile {
    TamgaJson *resource;
};

struct TamgaMachineFile {
    TamgaJson *resource;
};

/* Shared bounds check for every (pointer, length) pair crossing the boundary.
 * Zero and absurd lengths get their own code so a caller can tell a bad
 * length from a null pointer -- they are different bugs. */
static TamgaErrorCode tamga_check_span(const void *pointer, size_t len, const char *what) {
    if (pointer == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "%s must not be null", what);
    }
    if (len == 0u || len > TAMGA_MAX_REASONABLE_LEN) {
        return tamga_error_set(TAMGA_ERR_LENGTH_INVALID,
                               "%s length is zero or exceeds the accepted maximum", what);
    }
    return TAMGA_OK;
}

/* --- key derivation ----------------------------------------------------- */

TamgaErrorCode tamga_hkdf_derive_machine_file_key(const char *license_key, const char *fingerprint,
                                                  uint8_t *out_32_bytes) {
    tamga_error_clear();

    if (license_key == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "license_key must not be null");
    }
    if (fingerprint == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "fingerprint must not be null");
    }
    if (out_32_bytes == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "out_32_bytes must not be null");
    }
    if (!tamga_derive_machine_file_key(license_key, fingerprint, out_32_bytes)) {
        return tamga_error_set(TAMGA_ERR_UNKNOWN, "key derivation failed");
    }
    return TAMGA_OK;
}

TamgaErrorCode tamga_hkdf_derive_license_file_key(const char *license_key, uint8_t *out_32_bytes) {
    tamga_error_clear();

    if (license_key == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "license_key must not be null");
    }
    if (out_32_bytes == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "out_32_bytes must not be null");
    }
    if (!tamga_derive_license_file_key(license_key, out_32_bytes)) {
        return tamga_error_set(TAMGA_ERR_UNKNOWN, "key derivation failed");
    }
    return TAMGA_OK;
}

/* --- shared handle plumbing --------------------------------------------- */

/* Serialises a handle's resource as an owned JSON string. Both get_json
 * entry points are the same function with a different handle type. */
static TamgaErrorCode tamga_resource_to_json(const TamgaJson *resource, char **out_ptr,
                                             uintptr_t *out_len) {
    size_t len = 0u;
    char *json;

    if (resource == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "handle must not be null");
    }
    if (out_ptr == NULL || out_len == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "out_ptr and out_len must not be null");
    }
    json = tamga_json_write(resource, &len);
    if (json == NULL) {
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not serialise the resource");
    }
    *out_ptr = json;
    *out_len = (uintptr_t)len;
    return TAMGA_OK;
}

/* --- licence file ------------------------------------------------------- */

TamgaErrorCode tamga_license_file_verify(const char *pem, uintptr_t pem_len,
                                         const uint8_t *ed25519_pubkey, const char *license_key,
                                         struct TamgaLicenseFile **out_handle) {
    TamgaErrorCode status;
    TamgaJson *resource = NULL;
    struct TamgaLicenseFile *handle;
    int64_t now_unix = 0;

    tamga_error_clear();

    status = tamga_check_span(pem, (size_t)pem_len, "pem");
    if (status != TAMGA_OK) {
        return status;
    }
    if (ed25519_pubkey == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "ed25519_pubkey must not be null");
    }
    if (out_handle == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "out_handle must not be null");
    }
    *out_handle = NULL;

    if (!tamga_time_now_unix(&now_unix)) {
        /* Refusing beats guessing: the only thing `now` is used for is the
         * expiry check, and any substituted value silently decides it. */
        return tamga_error_set(TAMGA_ERR_UNKNOWN,
                               "the system clock could not be read, so the file's expiry "
                               "could not be checked");
    }

    status = tamga_license_file_verify_at(pem, (size_t)pem_len, ed25519_pubkey, license_key,
                                          now_unix, &resource, NULL);
    if (status != TAMGA_OK) {
        return status;
    }

    handle = (struct TamgaLicenseFile *)tamga_calloc(1u, sizeof(*handle));
    if (handle == NULL) {
        tamga_json_free(resource);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the handle");
    }
    handle->resource = resource;
    *out_handle = handle;
    return TAMGA_OK;
}

TamgaErrorCode tamga_license_file_get_json(const struct TamgaLicenseFile *handle, char **out_ptr,
                                           uintptr_t *out_len) {
    tamga_error_clear();
    if (handle == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "handle must not be null");
    }
    return tamga_resource_to_json(handle->resource, out_ptr, out_len);
}

void tamga_license_file_free(struct TamgaLicenseFile *handle) {
    /* Null is a documented no-op. Double-free is documented undefined
     * behaviour and intentionally unguarded: a guard would hide the caller
     * bug rather than fix it, and cannot be made reliable anyway. */
    if (handle == NULL) {
        return;
    }
    tamga_json_free(handle->resource);
    tamga_secure_free(handle, sizeof(*handle));
}

/* --- machine file ------------------------------------------------------- */

TamgaErrorCode tamga_machine_file_verify(const char *pem, uintptr_t pem_len, uint32_t scheme,
                                         const uint8_t *pubkey, uintptr_t pubkey_len,
                                         const char *license_key, const char *fingerprint,
                                         struct TamgaMachineFile **out_handle) {
    TamgaErrorCode status;
    TamgaJson *resource = NULL;
    struct TamgaMachineFile *handle;

    tamga_error_clear();

    status = tamga_check_span(pem, (size_t)pem_len, "pem");
    if (status != TAMGA_OK) {
        return status;
    }
    status = tamga_check_span(pubkey, (size_t)pubkey_len, "pubkey");
    if (status != TAMGA_OK) {
        return status;
    }
    if (out_handle == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "out_handle must not be null");
    }
    *out_handle = NULL;

    /* `scheme` arrives as a raw uint32_t rather than the enum type on
     * purpose: a C enum has no validity range at the ABI level, so a stale
     * header or a buggy binding can pass anything. It is validated inside. */
    status =
        tamga_machine_file_verify_into(pem, (size_t)pem_len, scheme, pubkey, (size_t)pubkey_len,
                                       license_key, fingerprint, &resource);
    if (status != TAMGA_OK) {
        return status;
    }

    handle = (struct TamgaMachineFile *)tamga_calloc(1u, sizeof(*handle));
    if (handle == NULL) {
        tamga_json_free(resource);
        return tamga_error_set(TAMGA_ERR_OUT_OF_MEMORY, "could not allocate the handle");
    }
    handle->resource = resource;
    *out_handle = handle;
    return TAMGA_OK;
}

TamgaErrorCode tamga_machine_file_get_json(const struct TamgaMachineFile *handle, char **out_ptr,
                                           uintptr_t *out_len) {
    tamga_error_clear();
    if (handle == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "handle must not be null");
    }
    return tamga_resource_to_json(handle->resource, out_ptr, out_len);
}

void tamga_machine_file_free(struct TamgaMachineFile *handle) {
    if (handle == NULL) {
        return;
    }
    tamga_json_free(handle->resource);
    tamga_secure_free(handle, sizeof(*handle));
}

/* --- offline proof ------------------------------------------------------ */

TamgaErrorCode tamga_offline_proof_verify(const char *proof_str, const uint8_t *rsa_pubkey,
                                          uintptr_t rsa_pubkey_len, const char *account_id,
                                          const char *machine_id, const char *fingerprint,
                                          const char *dataset_json, bool *out_valid) {
    TamgaErrorCode status;

    tamga_error_clear();

    status = tamga_check_span(rsa_pubkey, (size_t)rsa_pubkey_len, "rsa_pubkey");
    if (status != TAMGA_OK) {
        return status;
    }
    if (out_valid == NULL) {
        return tamga_error_set(TAMGA_ERR_NULL_ARGUMENT, "out_valid must not be null");
    }
    *out_valid = false;

    /*
     * An invalid proof is not a call failure, so this returns TAMGA_OK with
     * *out_valid false and leaves the error slot clear. Populating an error
     * message here would break the "TAMGA_OK implies no message" contract --
     * a regression this SDK's Rust predecessor shipped and had corrected in
     * review.
     */
    return tamga_proof_verify(proof_str, rsa_pubkey, (size_t)rsa_pubkey_len, account_id, machine_id,
                              fingerprint, dataset_json, out_valid);
}

TamgaErrorCode tamga_offline_proof_generate(const char *rsa_privkey, const char *account_id,
                                            const char *machine_id, const char *fingerprint,
                                            const char *dataset_json, char **out_proof_str) {
    (void)rsa_privkey;
    (void)account_id;
    (void)machine_id;
    (void)fingerprint;
    (void)dataset_json;

    tamga_error_clear();
    if (out_proof_str != NULL) {
        *out_proof_str = NULL;
    }

    /*
     * Deliberately not implemented, and kept only so the v1.x ABI stays
     * intact.
     *
     * Proof generation is a server-side operation. This SDK is a client that
     * verifies server-issued material and holds no signing keys; adding a
     * local RSA private-key operation would introduce the highest-risk
     * primitive in the library for no protocol benefit. Use
     * tamga_client_generate_offline_proof(), which performs the real call.
     */
    return tamga_error_set(TAMGA_ERR_UNKNOWN,
                           "local proof generation is not supported: proofs are issued by "
                           "the server, and this SDK holds no signing keys. Use "
                           "tamga_client_generate_offline_proof() instead.");
}
