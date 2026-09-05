/* The verify-first key-set path: tamga_key_set_find_verifier() tries every
 * held key against the signature over `enc`'s base64 STRING before a byte of
 * `enc` is decoded (see checkout/key_set.h), which is a different code path
 * from the single-pubkey one license_file_fuzz.c drives -- and, until now,
 * one this harness family gave zero fuzz iterations. */
#include <stdbool.h>
#include <stdint.h>

#include "checkout/license_file.h"
#include "tamga.h"
#include "util/json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* The key that actually signs every seed under corpus/license_file_keyset/
 * (the same key tests/fixtures/offline/license_plain.lic carries), so at
 * least one seed verifies through the set on the first run and the fuzzer
 * reaches the payload parse on the success path too, not only the
 * failure-labelling one. */
static const char LICENSE_FIXTURE_KEY_B64[] = "GX9rI+FshTLGq8g4+s1ep4m+DHaykgM0A5v6iz02jWE=";

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
            if (tamga_signing_key_set_add_public_key(set, LICENSE_FIXTURE_KEY_B64) != TAMGA_OK ||
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
    if (tamga_license_file_verify_at_with_key_set((const char *)data, size, keys, "licence-key",
                                                  1750000000, &resource, NULL) == TAMGA_OK) {
        tamga_json_free(resource);
    }
    return 0;
}
