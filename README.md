# tamga-c

The official C/C++ SDK for [Tamga](https://tamga.sh) — licence activation,
offline verification, and machine management.

**No dependencies.** The offline-verification half of this library links
against the C standard library and nothing else: no OpenSSL, no libsodium, no
JSON library, no build-time toolchain beyond a C11 compiler and CMake. The
HTTP half needs a transport, which is either an operating-system component
(WinHTTP on Windows, libcurl elsewhere) or one you supply.

---

## What it does

**Offline, with no network access at all:**

- verify and decode a `.lic` licence file (Ed25519, optionally AES-256-GCM encrypted)
- verify and decode a machine file across all four signing schemes
- verify a machine offline proof
- derive the two AES keys those formats use

**Over HTTP:**

- validate a licence by key or by id, with or without a scope
- check in, and check out `.lic` and machine files
- register, activate, heartbeat and delete machines
- generate an offline proof
- register components and processes
- list and query entitlements

Everything the [Rust reference SDK](https://github.com/tamga-sh/tamga-rust)
exposes is here.

---

## Install

### CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(tamga
    GIT_REPOSITORY https://github.com/tamga-sh/tamga-c
    GIT_TAG        v1.3.0)
FetchContent_MakeAvailable(tamga)

target_link_libraries(your_app PRIVATE tamga::tamga)
```

### find_package

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /usr/local
```

```cmake
find_package(tamga 1.3 REQUIRED)
target_link_libraries(your_app PRIVATE tamga::tamga)
```

### Release archives

Each release attaches a per-platform archive containing the built library, the
header, and the CMake package files. Linux x86_64 and aarch64, macOS
universal, Windows x86_64.

### vcpkg

`vcpkg-port/` holds a portfile for registry submission.

---

## Quick start

Validate a licence at startup:

```c
#include <tamga.h>

TamgaClient *client = NULL;
TamgaResponse *response = NULL;

tamga_client_new("<account-id>", "api.tamga.sh", &client);
/* Licence-key auth needs the policy's authentication_strategy set to LICENSE
   or MIXED -- the default TOKEN answers 401 LICENSE_NOT_ALLOWED. */
tamga_client_set_auth(client, TAMGA_AUTH_LICENSE, "<licence-key>", NULL);

if (tamga_client_validate_by_key(client, "<licence-key>", NULL, &response) == TAMGA_OK) {
    if (tamga_response_validation_is_valid(response)) {
        /* good to go */
    } else {
        printf("not valid: %s\n", tamga_response_validation_code(response));
    }
} else {
    /* The check could not be made -- a network failure, not a verdict.
       Treating this as "invalid" is how a licensing system locks out a
       paying customer on an aeroplane. */
}

tamga_response_free(response);
tamga_client_free(client);
```

Verify a licence file with no network access:

```c
TamgaLicenseFile *file = NULL;

/* pubkey is your account's 32-byte Ed25519 public key, embedded in your
   binary. licence_key is needed only for an encrypted file. */
TamgaErrorCode code = tamga_license_file_verify(pem, pem_len, pubkey, licence_key, &file);

if (code == TAMGA_OK) {
    char *json = NULL;
    uintptr_t len = 0;
    tamga_license_file_get_json(file, &json, &len);
    puts(json);
    tamga_string_free(json);
} else if (code == TAMGA_ERR_EXPIRED) {
    /* Authentic, but out of time. Distinct from a forgery on purpose. */
}

tamga_license_file_free(file);
```

More in [`examples/`](examples/), including the full activation flow.

---

## Build options

| Option | Default | What it does |
|---|---|---|
| `TAMGA_HTTP` | `auto` | Transport backend: `auto`, `winhttp`, `curl`, `none` |
| `TAMGA_BUILD_SHARED` | `ON` | Build the shared library alongside the static one |
| `TAMGA_C_BUILD_TESTS` | `ON` | Build the test suites |
| `TAMGA_C_BUILD_EXAMPLES` | `OFF` | Build `examples/` |
| `TAMGA_WARNINGS_AS_ERRORS` | `OFF` | Promote compiler warnings to errors |
| `TAMGA_C_ENABLE_ASAN` | `OFF` | AddressSanitizer + UndefinedBehaviorSanitizer |
| `TAMGA_C_ENABLE_COVERAGE` | `OFF` | Source-based coverage instrumentation |
| `TAMGA_C_ENABLE_FUZZ` | `OFF` | Build the libFuzzer targets (clang) |

`auto` picks WinHTTP on Windows and libcurl elsewhere when it is found, and
falls back to no backend with a message rather than failing the build.

None of these options add a dependency to the library. The one thing a
*contributor* needs beyond a C compiler and CMake is the pinned style and
static-analysis tooling, which CI uses at exactly these versions:

```sh
python3 -m pip install -r requirements-dev.txt
```

clang-format's output changes between major versions, so a system-installed
one will disagree with the gate.

### Opening a pull request

```sh
sh scripts/mr.sh              # target: main
sh scripts/mr.sh some-branch  # another target
```

This runs the checks CI runs — formatting, build, the full suite, and the
`TAMGA_HTTP=none` build whenever the library itself changed — and only then
pushes and opens the pull request. Use it rather than `gh pr create` directly:
the push is its last step, not its purpose.

It also **derives the pull-request title** from the branch's commits, taking
the highest semver-relevant conventional type actually present. That is not
cosmetic. This repository squashes, and GitHub writes the PR title as the
squashed commit message — so a branch full of `feat:` work opened under a
`chore:` title lands on `main` as a `chore:` commit, and release-please skips
the release. `MR_TITLE=...` overrides the wording but is refused if its type
would weaken the release; `MR_BODY_FILE=...` supplies a written description.

### An offline-only build

```sh
cmake -S . -B build -DTAMGA_HTTP=none
```

The whole offline surface works; the client entry points return
`TAMGA_ERR_NO_TRANSPORT` until you register a transport. The resulting library
links against libc alone — CI asserts it.

### Your own transport

For an application that already has an HTTP stack, or one that must route
requests through its own proxy or audit layer:

```c
static bool perform(void *user_data, const char *method, const char *url,
                    const char *const *names, const char *const *values,
                    uintptr_t header_count, const char *body, uintptr_t body_len,
                    unsigned int timeout_ms, TamgaHttpResult *result) {
    /* Make the request however you like, then: */
    tamga_http_result_set_status(result, status);
    tamga_http_result_set_body(result, response_body, response_len);
    tamga_http_result_add_header(result, "Retry-After", "5");
    return true;   /* false only if the request could not be made at all */
}

tamga_client_set_transport(client, perform, my_state, NULL);
```

Whatever you build on must verify TLS certificates and hostnames. This library
offers no way to disable that in its own backends and assumes the same of
yours.

---

## Things worth knowing

**Ownership.** Every function returning an owned `char *` pairs with
`tamga_string_free`; every handle pairs with its own `_free`. Never call
`free()` on something this library returned. `tamga_last_error_message()`
returns a *borrowed* pointer valid until the next `tamga_*` call on that
thread — copy it if you need it longer.

**Errors.** `TAMGA_OK` always means `tamga_last_error_message()` returns
`NULL` on that thread. A failing call always sets one. No error message ever
contains a licence key, token or password.

**Offline files expire.** Both a `.lic` file and a machine file carry a signed
expiry, enforced with sixty seconds of clock skew and reported as
`TAMGA_ERR_EXPIRED` rather than as a signature failure — a caller that cannot
tell "expired" from "forged" either accuses the user of tampering when their
trial ends, or treats a forgery as a renewal prompt. A file checked out with
no `ttl` never expires; the server omits the claim entirely, and its absence
is not an error.

**Offline files are format v2 only.** Both formats' `alg` must end in `+v2`,
and a v1 file is rejected with `TAMGA_ERR_UNSUPPORTED_SCHEME` and no fallback.
In v1 the expiry lived outside the signature, and the encryption key came from
zero-padding the licence key rather than from HKDF.

**The client's clock is the user's clock.** For a stricter offline grace
period, keep a server-supplied timestamp and check the file's expiry against
that instead of the system clock.

**Machine files need the fingerprint.** An encrypted machine file's key is
derived from the licence key *and* the machine's fingerprint, so a file issued
for one machine cannot be decrypted on another even by someone holding the
licence key. Its payload is framed differently from a licence file's, too:
`"<nonce_b64>.<ciphertext_b64>"`, two halves encoded separately, where the
licence file uses a single `base64(nonce||ciphertext||tag)` blob. Both are
handled internally; the distinction only matters if you are reading the bytes
yourself.

**Licence-key authentication is off by default.** `TAMGA_AUTH_LICENSE` only
works when the licence's policy sets `authentication_strategy` to `LICENSE` or
`MIXED`. The column defaults to `TOKEN`, and `NONE` refuses licence keys too —
either one answers `401 LICENSE_NOT_ALLOWED`
(`TAMGA_ERR_LICENSE_NOT_ALLOWED`) on *every* call. That is a provisioning
precondition, not a transient failure and not a bad key, so retrying or
re-prompting for the key never helps. Two calls stay closed to a licence key
whatever the strategy: `tamga_client_reset_heartbeat()` and
`tamga_client_generate_offline_proof()` are role-gated to admin, developer,
product and environment tokens and always answer `403`.

**An over-limit activation is reported two different ways.** Registering a
machine *does* check the licence's limits, and what happens next is the
policy's overage strategy. Under a strict strategy the creation itself is
rejected with `422` and one of the `TAMGA_ERR_*_LIMIT_EXCEEDED` codes. Under
`ALLOW_ACCESS` or `ALLOW_1_25X_OVERAGE` it succeeds and the same limit only
appears on the next validation. Use `tamga_client_activate_machine()`, which
handles both: it returns the limit code directly on a rejected creation, and
undoes an accepted-then-over-limit one. `tamga_validation_code_from_error()`
folds the first vocabulary onto the second so one branch covers both.

**`memory` and `disk` are megabytes.** Not bytes. The server sums them into
the licence's running memory and disk totals, which the limits are checked
against — reporting 16 GiB as `17179869184` instead of `16384` inflates that
total by a factor of a million and trips `MEMORY_LIMIT_EXCEEDED` on somebody
else's activation.

**Entitlements cannot be paginated.** `GET /licenses/{id}/entitlements` accepts
`page[after]` and ignores it: the listing is a union of direct and
policy-inherited rows, which no single cursor describes. `limit` bounds it
instead, defaulting to 25 and capped at 100 — so a licence with more than 100
effective entitlements cannot be read out in full, and a `false` from
`tamga_client_has_entitlement()` is only authoritative below that ceiling.
Never loop on `tamga_response_next_cursor()` for this route; it would return
the same first page forever. It works correctly for
`tamga_client_list_components()`, where the server really does apply the
cursor.

**`scope.version` and `scope.checksum` fail the whole call.** They are not
ignored: the server rejects either with `422 SCOPE_NOT_SUPPORTED` before any
validation runs, so no verdict comes back at all. The other six scope
members — `product`, `policy`, `user`, `environment`, `entitlements` and
`fingerprint` — are enforced, and a mismatch is a normal validation outcome
rather than an error.

**Quick-validate silently skips its write when the request carries `Origin`.**
`tamga_client_quick_validate()` normally stamps `last_validated_at`, but the
server skips that whenever an `Origin` header is present — and the two
responses are identical, so there is no way to tell. This SDK's own transports
never send `Origin`; one registered through `tamga_client_set_transport()`, or
a proxy in front of it, can. When the write matters, use
`tamga_client_validate_by_id()`.

**Threading.** Every function is safe to call concurrently on distinct
handles, and the last-error slot is per-thread. A single `TamgaClient` or
handle must not be used from two threads at once without your own
synchronisation.

---

## Compatibility

Version 1.3 replaced the implementation entirely — through 1.2 this was a Rust
crate exposed through a generated C header — while keeping the ABI. **A binary
built against 1.2.x links and runs against 1.3 unchanged.** All twelve entry
points keep byte-identical signatures and no enum value was renumbered; the
v1.2.2 test harness runs against the new library untouched, which is how that
is verified rather than asserted.

What changed for you: building no longer needs a Rust toolchain, corrosion or
cbindgen, and there is now an HTTP client.

`tamga_offline_proof_generate()` remains a deliberate non-implementation.
Proofs are issued by the server; this SDK holds no signing keys. Use
`tamga_client_generate_offline_proof()`.

---

## Security

Every cryptographic primitive is implemented in this repository and pinned to
the published test vectors for its specification. The reasoning behind that,
the threat model, and how to report a vulnerability are in
[SECURITY.md](SECURITY.md).

---

## Licence

MIT. See [LICENSE](LICENSE).
