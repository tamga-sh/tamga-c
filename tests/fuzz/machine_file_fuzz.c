/* The machine-file path across every scheme, so the alg dispatch and each
 * verifier's key handling all see arbitrary input. */
#include <stdint.h>

#include "checkout/machine_file.h"
#include "tamga.h"
#include "util/json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const unsigned char pubkey[65] = {0x04};
    static const uint32_t schemes[] = {
        (uint32_t)TAMGA_SCHEME_ED25519_SIGN,
        (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_SIGN,
        (uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN,
        (uint32_t)TAMGA_SCHEME_ECDSA_P256_SIGN,
    };
    size_t i;

    for (i = 0u; i < (sizeof(schemes) / sizeof(schemes[0])); i++) {
        TamgaJson *resource = NULL;
        if (tamga_machine_file_verify_into((const char *)data, size, schemes[i], pubkey,
                                           sizeof(pubkey), "licence-key", "fingerprint",
                                           &resource) == TAMGA_OK) {
            tamga_json_free(resource);
        }
    }
    return 0;
}
