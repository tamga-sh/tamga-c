/* Base64 decoding runs on the PEM body, the enc field and every signature. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tamga_mem.h"
#include "util/base64.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t decoded_len = 0u;
    unsigned char *decoded = tamga_base64_decode_alloc((const char *)data, size, &decoded_len);

    if (decoded != NULL) {
        /* Whatever decoded must re-encode to something that decodes again --
         * the strict decoder and the encoder have to agree on canonical
         * form. */
        char *encoded = tamga_base64_encode_alloc(decoded, decoded_len);
        if (encoded != NULL) {
            size_t round_len = 0u;
            unsigned char *round = tamga_base64_decode_alloc(encoded, strlen(encoded), &round_len);
            if (round == NULL || round_len != decoded_len) {
                abort();
            }
            tamga_free(round);
            tamga_free(encoded);
        }
        tamga_free(decoded);
    }
    return 0;
}
