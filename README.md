# tamga-c

[![CI](https://github.com/tamga-sh/tamga-c/actions/workflows/ci.yml/badge.svg)](https://github.com/tamga-sh/tamga-c/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Official C/C++ SDK for Tamga. Integrate license activation, offline verification, and machine
management into your C/C++ applications.

> **Scope of this package.** `tamga-c` is the fleet's shared offline-verification core, not an
> HTTP client. It has no auth transport, no `validate`/`check-in`, and no machine-management
> surface — no `Authorization` headers, no JSON:API request handling, no policy or entitlement
> logic. Its entire surface is four offline, deterministic crypto operations: verify a `.lic`
> license file, verify a machine file across four signing schemes, verify a machine offline
> proof, and derive the two AES keys those file formats depend on. It is built from the Rust
> reference implementation ([`tamga-rust`](https://github.com/tamga-sh/tamga-rust)) and is the
> foundation the [Java](https://github.com/tamga-sh/tamga-java) (JNI) and
> [Swift](https://github.com/tamga-sh/tamga-swift) (Swift/ObjC bridge) SDKs link against
> instead of re-implementing signature verification per language.
>
> For activation over HTTP, machine registration, heartbeats, and entitlements, use one of the
> full SDKs: `tamga-rust`, `tamga-python`, `tamga-go`, `tamga-dotnet`, or `tamga-js`.

## Install

`tamga-c` ships as a prebuilt static/shared library plus a header via
[GitHub Releases](https://github.com/tamga-sh/tamga-c/releases) (`.a`/`.so`/`.dylib`/`.dll` +
`tamga.h`, one archive per platform). Every release is cross-compiled for eight platform/arch
targets: Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64, iOS device arm64, and both
iOS Simulator architectures (see [`.github/workflows/build-native.yml`](.github/workflows/build-native.yml)).

**CMake (FetchContent):**

```cmake
include(FetchContent)
FetchContent_Declare(
    tamga_c
    GIT_REPOSITORY https://github.com/tamga-sh/tamga-c.git
    GIT_TAG v1.2.0  # see the Releases page for the latest
)
FetchContent_MakeAvailable(tamga_c)

target_link_libraries(your_target PRIVATE tamga_c::tamga_c)
```

Building from source requires a Rust toolchain on `PATH` — the CMake build drives Cargo through
[corrosion](https://github.com/corrosion-rs/corrosion), vendored via `FetchContent` in
[`cmake/FetchCorrosion.cmake`](cmake/FetchCorrosion.cmake).

**Manual link:** download the archive matching your platform, extract `include/tamga.h` and the
library, and link against `libtamga.a`/`libtamga.so`/`libtamga.dylib`/`tamga.dll` directly. The
library name is `libtamga`, not `libtamga_c` — `[lib] name` in `Cargo.toml` is `tamga` so the
built artifact matches the C-facing product name.

**vcpkg: not consumable yet.** A prepared port lives in [`vcpkg-port/`](vcpkg-port/), but it is
not usable as-is — its `SHA512` is still a placeholder, and its `REF` points at `v1.2.0`, whose
`CMakeLists.txt` installs only `include/tamga.h` and not the compiled library. The `install()`
rules that fix that are on `main` (`cmake --install` now produces the header plus both the
static and shared library) and will ship in the next tagged release; the portfile's `REF`/`SHA512`
need updating to that tag before it will build a usable package. Submission to the central vcpkg
registry is separately blocked: the
[Maintainer Guide](https://learn.microsoft.com/en-us/vcpkg/contributing/maintainer-guide) requires
a release at least 6 months old or 6 months of active public development, and the first public
release here was 2026-08-11.

## Quickstart

Verify a `.lic` file offline and print the decoded license resource. Every function returns a
`TamgaErrorCode`; `TAMGA_OK` (0) is success, and any other value has a thread-local detail
message behind `tamga_last_error_message()`.

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tamga.h"

int main(void) {
    /* The raw bytes of a .lic file, PEM markers included. Read this from disk
       in a real application -- see examples/verify_license.c. */
    const char *pem = "-----BEGIN LICENSE FILE-----\n"
                      "<base64 body>\n"
                      "-----END LICENSE FILE-----\n";

    /* Your account's Ed25519 public key: 32 raw bytes, embedded at build time. */
    static const uint8_t ed25519_pubkey[32] = {
        /* 32 bytes of public key go here */
        0};

    /* Required only for an encrypted file (alg "aes-256-gcm+ed25519+v2").
       Pass NULL for a plain "base64+ed25519+v2" file. */
    const char *license_key = NULL;

    TamgaLicenseFile *license = NULL;
    TamgaErrorCode err =
        tamga_license_file_verify(pem, strlen(pem), ed25519_pubkey, license_key, &license);
    if (err != TAMGA_OK) {
        const char *detail = tamga_last_error_message();
        fprintf(stderr, "verify failed (code=%d): %s\n", (int)err, detail ? detail : "(no detail)");
        return 1;
    }

    char *json = NULL;
    uintptr_t json_len = 0;
    if (tamga_license_file_get_json(license, &json, &json_len) == TAMGA_OK) {
        printf("%.*s\n", (int)json_len, json);
        tamga_string_free(json); /* never libc free() on a string this library returned */
    }

    tamga_license_file_free(license);
    return 0;
}
```

Runnable versions of all three verification flows live in
[`examples/`](examples/) — `verify_license.c`, `verify_machine.c`, and `verify_offline_proof.c`
are real CLIs, not stubs. Build them with `-DTAMGA_C_BUILD_EXAMPLES=ON`.

## Offline verification

### License files

`tamga_license_file_verify(pem, pem_len, ed25519_pubkey, license_key, &handle)` strips the PEM
markers, Ed25519-verifies the signature over `enc`'s base64 **string**, decrypts if the file is
encrypted, and enforces the signed expiry — all without network access. The decoded resource is
read back as JSON with `tamga_license_file_get_json` and released with
`tamga_license_file_free`.

License-file checkout signatures are always Ed25519, independent of the license's own `scheme`.

> ⚠️ **Compatibility warning: offline license files must be format v2.** The file's `alg` must
> end in `+v2` (`base64+ed25519+v2` or `aes-256-gcm+ed25519+v2`), and its signed `meta` claims
> (`iat`, `exp`, `jti`, `kid`) are covered by the signature. **v1 files are rejected outright
> with no fallback path** — `TAMGA_ERR_UNSUPPORTED_SCHEME`. If you hold `.lic` files issued
> before v2, they will stop verifying and must be checked out again. This is a real behavioral
> break, not a deprecation.
>
> `exp` is enforced with a 60-second clock-skew tolerance and reported as its own
> `TAMGA_ERR_EXPIRED` code, so an authentic-but-expired file is distinguishable from a forged
> one.

### Machine files

`tamga_machine_file_verify(pem, pem_len, scheme, pubkey, pubkey_len, license_key, fingerprint, &handle)`
dispatches on the **license's** `scheme`, not on the file's self-declared `alg`:

| `scheme` (pass as `uint32_t`) | Public key format |
| --- | --- |
| `TAMGA_SCHEME_ED25519_SIGN` | 32 raw bytes |
| `TAMGA_SCHEME_RSA_2048_PKCS1_SIGN` | `SubjectPublicKeyInfo` DER |
| `TAMGA_SCHEME_RSA_2048_PKCS1_PSS_SIGN` | `SubjectPublicKeyInfo` DER |
| `TAMGA_SCHEME_ECDSA_P256_SIGN` | 65-byte uncompressed point |

`TAMGA_SCHEME_RSA_2048_JWT_RS256` and `TAMGA_SCHEME_NONE` are rejected with
`TAMGA_ERR_UNSUPPORTED_SCHEME`. The `scheme` parameter is declared `uint32_t` rather than
`enum TamgaScheme` on purpose — see "Security notes".

An encrypted machine file needs **both** the license key and the target machine's fingerprint to
decrypt; a license file needs only the license key.

### Offline proofs

`tamga_offline_proof_verify(proof_str, rsa_pubkey, rsa_pubkey_len, account_id, machine_id, fingerprint, dataset_json, &out_valid)`
checks a `"v1x0.<base64 signature>"` proof. Proofs are always signed RSA-2048 PKCS#1 v1.5 /
SHA-256, regardless of the license's `scheme`.

Check both results: a non-`TAMGA_OK` return means the *call* failed (bad UUID, malformed JSON,
null pointer), while `TAMGA_OK` with `out_valid == false` means the call succeeded and the proof
did not verify.

### Key derivation

`tamga_hkdf_derive_license_file_key(license_key, out_32_bytes)` and
`tamga_hkdf_derive_machine_file_key(license_key, fingerprint, out_32_bytes)` expose the two
AES-256-GCM key derivations directly, for callers that need the raw key without a full
verify round-trip. Both are HKDF-SHA256 — see "Security notes" for the parameters.

## Security notes

Every claim below names the function that implements it. Cryptographic work is delegated to
`tamga-rust`; this crate is a marshalling layer, not a second implementation.

- **Both offline file formats derive their AES key with HKDF-SHA256** (RFC 5869).
  License file: `salt = "tamga:license-file-key-v1"`, `ikm = <license key>`,
  `info = "license-file"` (`src/kdf.rs::tamga_hkdf_derive_license_file_key` →
  `tamga-rust`'s `src/crypto/hkdf.rs::derive_license_file_key`). Machine file:
  `salt = "tamga:machine-file-key-v1"`, `ikm = <license key>`, `info = <machine fingerprint>`
  (`src/kdf.rs::tamga_hkdf_derive_machine_file_key` →
  `tamga-rust`'s `src/crypto/hkdf.rs::derive_machine_file_key`).
  The pre-v2 license-file transform — the licence key's raw bytes zero-padded or truncated to 32
  — was **removed, not deprecated**: its source module and the exported
  `tamga_naive_derive_license_file_key` symbol are both gone, so no caller can silently fall back
  to a key whose real strength was the licence key's own entropy.
- **Format v2 is required and `exp` is enforced** with a 60-second skew tolerance
  (`tamga-rust`'s `src/checkout/license_file.rs::verify_license_file_at`, tolerance constant
  `CLOCK_SKEW_TOLERANCE_SECS`), surfaced as `TAMGA_ERR_EXPIRED` by
  `src/license_file.rs::map_checkout_error`.
- **Signatures are verified over `enc`'s base64 string, before decoding it**
  (`tamga-rust`'s `src/checkout/license_file.rs::verify_license_file_at`). Verifying over the
  decoded bytes is the most common way to get this format wrong.
- **Machine-file algorithm selection comes from the license's `scheme`, cross-checked against the
  file's `alg` suffix** (`tamga-rust`'s `src/checkout/machine_file.rs::scheme_alg_suffix`); a
  self-declared string never selects the verifying primitive.
  `src/machine_file.rs::map_scheme` rejects `TAMGA_SCHEME_NONE`.
- **No Rust panic can unwind into C.** Every exported function runs through
  `src/lib.rs::ffi_guard` or `src/lib.rs::ffi_guard_void`, which convert a caught panic into
  `TAMGA_ERR_PANIC`.
- **`#[repr(C)]` enums are never parameters by value.** A C `enum` has no validity range, so an
  out-of-range value would be undefined behavior the moment it reached a typed Rust parameter.
  Scheme arguments arrive as `uint32_t` and go through `src/lib.rs::TamgaScheme::from_raw`.
- **Length arguments are range-checked** against a 16 MiB bound before any
  `slice::from_raw_parts`, returning `TAMGA_ERR_LENGTH_INVALID`
  (`src/lib.rs::MAX_REASONABLE_LEN`).
- **Derived keys are zeroized on drop.** `tamga-rust`'s derivations return
  `Zeroizing<[u8; 32]>`; note that a key you copy out through `out_32_bytes` is yours to wipe.
- **The `rsa` crate is banned** (RUSTSEC-2023-0071, the unpatched Marvin timing attack).
  [`deny.toml`](deny.toml) enforces this and CI runs `cargo deny check`; RSA work uses
  `aws-lc-rs`.

Memory ownership: every `tamga_*_verify` handle is freed exactly once with its matching
`tamga_*_free`, and every owned `char *` this library returns goes through `tamga_string_free` —
never libc `free()`. `tamga_last_error_message()` returns a **borrowed** pointer valid only until
the next `tamga_*` call on the same thread; copy it out if you need it longer. Double-free is
documented undefined behavior and intentionally unguarded.

Full policy and reporting instructions: [`SECURITY.md`](SECURITY.md).

## Known gaps

- **`tamga_offline_proof_generate` is not implemented** and always returns
  `TAMGA_ERR_UNKNOWN` (`src/offline_proof.rs::tamga_offline_proof_generate`). This is deliberate:
  `tamga-rust`'s RSA module is verify-only, and re-deriving the byte-exact canonical JSON payload
  a second time in this crate would reintroduce exactly the field-order risk the shared
  implementation exists to avoid. Proof generation is a server-side operation, reachable through
  the HTTP-capable SDKs.
- **No HTTP surface at all.** Activation, validation, check-in/check-out, heartbeats, machine
  registration and entitlements are not in this package. Rate limiting is likewise out of scope
  here — the server does return HTTP `429`, and the transport SDKs handle it (parsed and capped
  `Retry-After`, jittered exponential backoff, auto-retry on `GET` plus the five safe `POST`
  actions `validate`, `validate-key`, `check-in`, `check-out`, `ping`, with creates deliberately
  excluded — `tamga-rust`'s `src/client.rs::is_retryable`).
- **Expiry is checked against the host clock**, which the end user controls. `tamga-rust` exposes
  `verify_license_file_at` for applications that keep a server-supplied timestamp; the C ABI does
  not surface that parameter yet.
- **No central package registry.** GitHub Releases is the artifact store; crates.io publishing is
  disabled (`publish = false`), and the vcpkg port is overlay-only for now (see "Install").
- **`examples/verify_machine.c` only parses Ed25519 public keys.** RSA and ECDSA keys are
  variable-length and would need a length argument; the FFI entry point supports them, the
  example does not.
- **C-side test coverage is not measured.** `cargo llvm-cov` gates the Rust layer at 70% lines;
  the `tests/c/` CTest suite is pass/fail only.

## Documentation

- [tamga.sh](https://tamga.sh) — product documentation, including the protocol reference for the
  license-file, machine-file, and offline-proof formats this package implements.
- [`include/tamga.h`](include/tamga.h) — the generated C ABI reference. Every function, error
  code, and ownership contract is documented inline.
- [`examples/`](examples/) — runnable programs for all three verification flows.
- [`SECURITY.md`](SECURITY.md) — security properties, supported versions, and reporting.
- [`CHANGELOG.md`](CHANGELOG.md) — release history.

## License

MIT — see [`LICENSE`](LICENSE).
