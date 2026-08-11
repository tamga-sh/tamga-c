# tamga-c

[![CI](https://github.com/tamga-sh/tamga-c/actions/workflows/ci.yml/badge.svg)](https://github.com/tamga-sh/tamga-c/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

C/C++ core library for Tamga. Exposes license activation and offline verification through a stable C ABI, built from the Rust reference implementation ([`tamga-rust`](https://github.com/tamga-sh/tamga-rust)) and used as the shared foundation for the Java ([`tamga-java`](https://github.com/tamga-sh/tamga-java)) and Swift ([`tamga-swift`](https://github.com/tamga-sh/tamga-swift)) SDKs.

> **This is NOT an HTTP client.** There is no auth-transport, `validate`, `check-in`, or machine-management surface in this repo — no `Authorization` headers, no JSON:API request/response handling, no policy/entitlement logic. `tamga-c`'s entire surface is four offline, deterministic crypto operations: verify a `.lic` license file, verify a machine file (across 4 signing schemes), verify/generate a machine offline proof, and derive the two AES keys those file formats depend on. For everything else — license validation over HTTP, machine registration, heartbeats, entitlements — use one of the full hand-written SDKs (`tamga-rust`, `tamga-python`, `tamga-go`, `tamga-dotnet`, `tamga-js`).

> **Status: actively developed.** License-file verify, machine-file verify (all 4 signing schemes), machine offline-proof verify, and both key-derivation primitives are implemented and tested against a CMake+corrosion build (including an AddressSanitizer run). `tamga_offline_proof_generate` is a deliberate non-implementation — see `CLAUDE.md`. The cross-platform build matrix (beyond macOS x86_64) is still in progress.

## Install

`tamga-c` ships as a prebuilt static/shared library + header via **GitHub Releases** (`.so`/`.dylib`/`.dll` + `tamga.h`) — there is no crates.io/npm-style package registry for this repo. An optional `vcpkg`/Conan port is backlog (see `vcpkg.json`, present but without a portfile yet).

**Static link via CMake (recommended once a real release exists):**

```cmake
include(FetchContent)
FetchContent_Declare(
    tamga_c
    GIT_REPOSITORY https://github.com/tamga-sh/tamga-c.git
    GIT_TAG v0.1.0
)
FetchContent_MakeAvailable(tamga_c)

target_link_libraries(your_target PRIVATE tamga_c::tamga_c)
```

**Manual link:** download the archive matching your platform from the [Releases page](https://github.com/tamga-sh/tamga-c/releases), extract `include/tamga.h` and the built library, and link against `libtamga.a`/`libtamga.so`/`libtamga.dylib`/`tamga.dll` (package name **`libtamga`**) directly.

## Quickstart

> Illustrative only — the exact function signatures below match the current scaffold in `src/license_file.rs`, but every one of them is still a stub that returns `TAMGA_ERR_UNKNOWN`. This snippet shows the intended shape of the API, not something you can run today.

```c
#include <stdio.h>
#include <stdlib.h>

#include "tamga.h"

int main(void) {
    /* Load a .lic file's raw bytes (PEM markers included) however you like. */
    const char *pem = "-----BEGIN LICENSE FILE-----\n...\n-----END LICENSE FILE-----\n";
    size_t pem_len = strlen(pem);

    /* The account's Ed25519 public key, 32 raw bytes. */
    unsigned char ed25519_pubkey[32] = { /* ... */ };

    TamgaLicenseFile *license = NULL;
    TamgaErrorCode err = tamga_license_file_verify(pem, pem_len, ed25519_pubkey, &license);
    if (err != TAMGA_OK) {
        fprintf(stderr, "verify failed: %s\n", tamga_last_error_message());
        return 1;
    }

    char *json = NULL;
    size_t json_len = 0;
    if (tamga_license_file_get_json(license, &json, &json_len) == TAMGA_OK) {
        printf("%s\n", json);
        tamga_string_free(json);
    }

    tamga_license_file_free(license);
    return 0;
}
```

See `examples/verify_license.c`, `examples/verify_machine.c`, and `examples/verify_offline_proof.c` for the other two operations (currently stubs with the same caveat).

## Documentation

- [`tamga-api`'s `docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md) — the protocol reference this repo implements against: license/machine checkout file formats (§4, §6), offline proof (§7), and the `LicenseScheme` enum (§10). Read it before touching any verification logic here — every field name and byte layout in this crate is meant to trace back to that document, not to assumption.

## License

MIT — see [`LICENSE`](LICENSE).
