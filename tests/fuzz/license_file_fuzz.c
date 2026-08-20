/* The whole licence-file path: envelope, certificate JSON, signature check,
 * decryption and claim parsing, on arbitrary bytes. */
#include <stdint.h>

#include "checkout/license_file.h"
#include "util/json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const unsigned char pubkey[32] = {0};
    TamgaJson *resource = NULL;

    if (tamga_license_file_verify_at((const char *)data, size, pubkey, "licence-key",
                                     1750000000, &resource, NULL) == TAMGA_OK) {
        tamga_json_free(resource);
    }
    return 0;
}
