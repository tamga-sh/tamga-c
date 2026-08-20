/*
 * DER parsing runs on attacker-supplied key material and signatures. Both
 * verifiers are driven, since the interesting failures are in the parser they
 * share rather than in the arithmetic behind it.
 */
#include <stdint.h>

#include "crypto/ecdsa.h"
#include "crypto/rsa.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const unsigned char message[] = "message";
    static const unsigned char signature[64] = {0};

    /* The input is treated as a public key with a fixed signature, then as a
     * signature with a fixed key, so both parsers see it. */
    (void)tamga_rsa_verify_pkcs1_sha256(data, size, message, sizeof(message) - 1u, signature,
                                        sizeof(signature));
    (void)tamga_rsa_verify_pss_sha256(data, size, message, sizeof(message) - 1u, signature,
                                      sizeof(signature));
    (void)tamga_ecdsa_p256_verify(data, size, message, sizeof(message) - 1u, signature,
                                  sizeof(signature));
    (void)tamga_ecdsa_p256_verify(signature, sizeof(signature), message, sizeof(message) - 1u,
                                  data, size);
    return 0;
}
