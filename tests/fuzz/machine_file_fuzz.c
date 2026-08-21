/* The machine-file path across every scheme, so the alg dispatch and each
 * verifier's key handling all see arbitrary input.
 *
 * Each scheme gets a key of the length its verifier requires. A single shared
 * buffer does not work: tamga_machine_check_signature rejects an Ed25519 key
 * that is not exactly 32 bytes before it ever calls the verifier, so a 65-byte
 * P-256-shaped buffer would silently give Ed25519 point decompression and
 * signature parsing zero fuzzing time while still looking covered. */
#include <stdint.h>

#include "checkout/machine_file.h"
#include "tamga.h"
#include "util/json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* A valid RFC 8032 public key, so decompression succeeds and the fuzzer
     * reaches the signature equation rather than stopping at the point. */
    static const unsigned char ed25519_pubkey[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
        0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
        0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
    static const unsigned char p256_pubkey[65] = {0x04};
    /* A DER RSAPublicKey is parsed from bytes, so a stub is enough to exercise
     * the parser's rejection path; the RSA verifiers are fuzzed directly by
     * their own targets. */
    static const unsigned char rsa_pubkey[8] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03};
    static const struct {
        uint32_t scheme;
        const unsigned char *pubkey;
        size_t pubkey_len;
    } cases[] = {
        {(uint32_t)TAMGA_SCHEME_ED25519_SIGN, ed25519_pubkey, sizeof(ed25519_pubkey)},
        {(uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_SIGN, rsa_pubkey, sizeof(rsa_pubkey)},
        {(uint32_t)TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN, rsa_pubkey, sizeof(rsa_pubkey)},
        {(uint32_t)TAMGA_SCHEME_ECDSA_P256_SIGN, p256_pubkey, sizeof(p256_pubkey)},
    };
    size_t i;

    for (i = 0u; i < (sizeof(cases) / sizeof(cases[0])); i++) {
        TamgaJson *resource = NULL;
        /* A fixed clock, as the licence-file harness uses: an input that
         * verifies must do so on every run, and the wall clock would make the
         * expiry check -- and therefore the corpus -- time-dependent. */
        if (tamga_machine_file_verify_at((const char *)data, size, cases[i].scheme, cases[i].pubkey,
                                         cases[i].pubkey_len, "licence-key", "fingerprint",
                                         1750000000, &resource, NULL) == TAMGA_OK) {
            tamga_json_free(resource);
        }
    }
    return 0;
}
