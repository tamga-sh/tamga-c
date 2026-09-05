/* The verify-first key-set path for machine files. Ed25519 only --
 * tamga_machine_file_verify_at_with_key_set() refuses every other scheme by
 * name before touching a byte of `data` (a machine file's kid names the
 * account's Ed25519 key whatever scheme actually signed it, so selecting an
 * RSA or ECDSA key by kid would be algorithm confusion; see key_set.h) -- so,
 * unlike machine_file_fuzz.c, there is only one case here rather than one per
 * scheme. */
#include <stdbool.h>
#include <stdint.h>

#include "checkout/machine_file.h"
#include "tamga.h"
#include "util/json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* The key that actually signs every seed under corpus/machine_file_keyset/
 * (tests/fixtures/server-machine-files/manifest.json's "ed25519_*" entries),
 * so at least one seed verifies through the set on the first run and the
 * fuzzer reaches the payload parse on the success path too, not only the
 * failure-labelling one. */
static const char ED25519_FIXTURE_KEY_B64[] = "AQAg/HkMCKUVnpDfZAVDWheJo2UmA6fiBHTUDgCFC0g=";

/* An unrelated second key -- what an account would be signing with AFTER a
 * rotation -- so the set genuinely holds more than one entry and the loop in
 * tamga_key_set_find_verifier() runs more than a single iteration. */
static const char ROTATED_KEY_B64[] = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/*
 * Built once and kept for the life of the process: a fresh key set on every
 * call would spend each iteration on setup rather than on the input. It stays
 * reachable through this static pointer for the whole run, so it is never
 * reported as a leak.
 */
static TamgaSigningKeySet *fuzz_key_set(void) {
    static TamgaSigningKeySet *set;
    static bool attempted;

    if (!attempted) {
        attempted = true;
        if (tamga_signing_key_set_new(&set) == TAMGA_OK) {
            if (tamga_signing_key_set_add_public_key(set, ED25519_FIXTURE_KEY_B64) != TAMGA_OK ||
                tamga_signing_key_set_add_public_key(set, ROTATED_KEY_B64) != TAMGA_OK) {
                tamga_signing_key_set_free(set);
                set = NULL;
            }
        }
    }
    return set;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TamgaSigningKeySet *keys = fuzz_key_set();
    TamgaJson *resource = NULL;

    if (keys == NULL) {
        return 0;
    }
    /* A fixed clock, as the single-key harness uses: an input that verifies
     * must do so on every run. */
    if (tamga_machine_file_verify_at_with_key_set(
            (const char *)data, size, (uint32_t)TAMGA_SCHEME_ED25519_SIGN, keys, "licence-key",
            "fingerprint", 1750000000, &resource, NULL) == TAMGA_OK) {
        tamga_json_free(resource);
    }
    return 0;
}
