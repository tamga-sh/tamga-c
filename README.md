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
- survive a signing-key rotation: verify a file against the key its own `kid`
  claim names, from a set of keys you already trust

**Over HTTP:**

- validate a licence by key or by id, with or without a scope
- check in, and check out `.lic` and machine files
- register, activate, heartbeat, read, update and delete machines
- re-activate a machine that already holds a seat, without an error
- read a licence, and the policy behind it
- generate an offline proof
- register, list and dispose of components and processes
- list and query entitlements
- ask whether a newer release is available
- read the account's signing keys, retired ones included
- probe the server's health, for when nothing else works

Everything the [Rust reference SDK](https://github.com/tamga-sh/tamga-rust)
exposes is here.

---

## Install

### CMake FetchContent

<!-- x-release-please-start-version -->
```cmake
include(FetchContent)
FetchContent_Declare(tamga
    GIT_REPOSITORY https://github.com/tamga-sh/tamga-c
    GIT_TAG        v1.3.2)
FetchContent_MakeAvailable(tamga)

target_link_libraries(your_app PRIVATE tamga::tamga)
```
<!-- x-release-please-end -->

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
sh Scripts/mr.sh              # target: main, or the pull request's own base
sh Scripts/mr.sh some-branch  # another target
```

The directory is capitalised. It is the only top-level one that is, and a
lowercase `scripts/` works on macOS only because the filesystem is
case-insensitive — on Linux it fails outright.

This runs the checks CI runs — formatting, build, the full suite, and the
`TAMGA_HTTP=none` build whenever the library itself changed — and only then
pushes. Use it rather than `gh pr create` or `git push` directly: the push is
its last step, not its purpose.

It handles a branch that **already has an open pull request**, which is most
of a branch's life: it runs the same checks and pushes to that pull request
instead of trying to open a second one. It also takes the base branch from the
pull request itself, so a stacked branch does not need the target spelled out
— pass one only to override, and it will refuse if it disagrees with the pull
request rather than guess.

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

**A rotated signing key does not have to lock anyone out.** When an account
rotates its Ed25519 key, a file checked out *before* the rotation is still
authentic — but against the one key an application has embedded it fails with
exactly the error a forged file produces. Verify through a key set instead and
the two become different answers:

```c
TamgaSigningKeySet *keys = NULL;
tamga_signing_key_set_new(&keys);

/* Keys you pin in your own binary. Their kid is computed locally, so this
   needs no network -- which matters, because a licence-key credential is
   refused GET /signing-keys outright. */
tamga_signing_key_set_add_public_key(keys, current_key_b64);
tamga_signing_key_set_add_public_key(keys, previous_key_b64);

TamgaLicenseFile *file = NULL;
switch (tamga_license_file_verify_with_key_set(pem, pem_len, keys, NULL, &file)) {
case TAMGA_OK:
    break;
case TAMGA_ERR_UNKNOWN_SIGNING_KEY:
    /* Not a forgery. The key set has not caught up with a rotation --
       refresh it, or ship an update. */
    break;
case TAMGA_ERR_SIGNING_KEY_NOT_PUBLISHED:
    /* This account never published an Ed25519 public key, so no key set can
       ever match. Refetching will not help. */
    break;
case TAMGA_ERR_SIGNATURE_INVALID:
    /* The kid resolved and the signature still failed. Refuse the file. */
    break;
default:
    break;
}
```

A `kid` is `SHA-256` of the public key's **base64 string** — not of the 32
bytes it decodes to — truncated to eight bytes and hex-encoded.
`tamga_signing_key_id()` computes it, but you rarely need to: a key set fetched
with `tamga_client_list_signing_keys()` is already indexed by `kid`, because on
that route the resource `id` *is* the `kid`.

⚠️ Two limits, both the server's. `GET /signing-keys` needs `account.read`,
which a licence key does not carry, and there is no second route to the same
resource — so an embedded client must be *given* the key set rather than fetch
it. And a machine file signed under an RSA or ECDSA scheme cannot be matched by
`kid` at all: the server computes that claim from the account's Ed25519 key
whatever scheme signed the file. Those get
`TAMGA_ERR_KEY_ID_NOT_APPLICABLE`; verify them with
`tamga_machine_file_verify()`. Nothing is lost, because only the Ed25519 key is
ever rotated.

**An empty key set is a healthy account.** `GET /signing-keys` answers
`{"data": []}` for an account that has never rotated — the table is written
only by the rotation handler. Read that as "nothing has rotated yet", not as a
fault.

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

**Re-activating an already-activated machine is normal, and there are two
calls for it.** `tamga_client_activate_machine()` reports the server's `409
FINGERPRINT_TAKEN` as an error, which is right for a first activation and
wrong for the restart of an installed application.
`tamga_client_activate_machine_idempotent()` treats it the way the server
intends: it looks the existing machine up on the same licence and validates
it. The server checks fingerprint uniqueness *before* the seat limits
precisely so that a re-activation is reported as a conflict rather than as
"buy more seats" — its own comment on that branch says the conflict means
"already activated, carry on".

The conflict still stands when it is real. A policy set to
`UNIQUE_PER_POLICY` or `UNIQUE_PER_ACCOUNT` refuses a fingerprint already
registered anywhere in that scope, so the machine holding it can belong to a
*different* licence. The lookup is therefore scoped to the licence being
activated, server-side — a machine resource carries no licence id, so there is
no way to check it locally — and that scope is the point rather than a
limitation: returning the other licence's machine would leave you holding a
machine id whose seat belongs to that licence, with this one's machine count
never incremented, which is the arrangement those strategies exist to forbid.

To find out *which* licence holds a fingerprint, search account-wide with
`tamga_client_list_machines(client, NULL, fingerprint, ...)`. That is a
diagnostic, and deliberately a separate call.

**No machine route is scoped to your licence.** The server applies its
`require_license_scope` check to the licence validate and check-out routes and
to no machine route at all, while a licence-key credential carries
`machine.read`, `machine.update` and `machine.delete` by default. So a licence
key can read, update and delete *any* machine in the account by id. Reported
upstream; noted here so nothing in this SDK reads as a scoped surface.

**The machine collection is the one listing that is not keyset-paginated.**
`tamga_client_list_machines()` goes through the server's offset paginator:
`page[number]`, `page[size]`, and `meta.page{number,size,total,totalPages}`,
read with `tamga_response_page()`. Every other listing here is keyset-based
and uses `tamga_response_next_cursor()`. Using the wrong one does not fail
loudly — a cursor derived from a machine listing addresses the first page
forever.

There is also no exact-fingerprint filter: `filter[q]` is a case-insensitive
*substring* match across `name`, `hostname` and `fingerprint`, so anything
looking for one exact value has to re-check what comes back.
`tamga_client_find_machine_by_fingerprint()` is that check, written once.

**The heartbeat window comes from the policy, not from
`next_heartbeat_at`.** Read it with `tamga_client_get_license_policy()` and
`tamga_response_heartbeat_window_secs()`; it is the policy's
`heartbeat_duration`, or 600 seconds when the policy sets none. Ping at about
a third of it.

Do not derive it from a machine's `next_heartbeat_at`. That field is computed
against the 600-second fallback on the create, ping-heartbeat and
reset-heartbeat responses, and against the real `policy.heartbeat_duration` on
check-out, generate-offline-proof and the machine reads — only the read
queries join `policies`. Two responses for the same machine, seconds apart,
can disagree about when the next heartbeat is due, and the endpoint a
heartbeat loop naturally calls is the one that is wrong. Reported upstream.

A window is not the same thing as culling: `policies.require_heartbeat`
defaults to false and the cull job early-returns when it is, so on a default
policy no machine is ever removed for missing a heartbeat.

**A licence key cannot read `/policies/{id}`, and can read every other
licence.** Two separate asymmetries, both server-side:

`tamga_client_get_policy()` gates on the `policy.read` permission, which a
licence-key credential does not carry — it answers `403` whatever the
policy's authentication strategy says. `tamga_client_get_license_policy()`
reaches the identical resource through `license.read`, which a licence key
does carry, and is the call to use.

Neither `tamga_client_get_license()` nor `tamga_client_get_license_policy()`
is confined to the credential's own licence. The server applies its
`require_license_scope` check to validate, quick-validate, validate-key and
check-out, and not to these two — so one licence key can read every other
licence in the same account by id, including `attributes.key`, the plaintext
licence key. That is the server's behaviour, it has been reported upstream,
and an SDK cannot fix it. Do not treat these two calls as a scoped surface.

**Processes have to be disposed of; nothing else removes them.** The server
has a process reaper, but nothing calls it, so no process row is ever deleted
automatically. Every row keeps counting towards the licence's process total,
and that total is what `TOO_MANY_PROCESSES` is checked against — so an
application that registers a process per run and never deletes one works
until it does not, and the failure lands on a later, innocent run. Pair every
`tamga_client_create_process()` with `tamga_client_delete_process()` on the
way out, including on the error paths. It answers `204` whether or not the row
was there.

**`204` from the update check means two things.**
`tamga_client_check_upgrade()` gets `204 No Content` both when there is no
newer release *and* when there is one this licence is not entitled to,
because refusing the second explicitly would leak "a newer version exists but
you cannot have it". There is no client-side way to tell them apart and there
is not meant to be — so do not report a `204` as "you are up to date". The
accurate wording is *there is no update available to you*.

**Canonicalise the fingerprint before you send it.** The server stores
`fingerprint TEXT NOT NULL` with no length limit, no `CHECK` and no
normalisation, unique per `(license_id, fingerprint)` — so `"ABC-123"`,
`"abc-123"` and `" ABC-123 "` are three machines on three seats.
`tamga_fingerprint_compute()` takes labelled components you choose and returns
one stable 64-character string: order-independent, whitespace-trimmed,
case-preserving, and rejecting rather than repairing anything it cannot
canonicalise.

```c
const char *labels[] = {"machine-id", "disk"};
const char *values[] = {"abc123", "SN-9"};
char *fp = NULL;
if (tamga_fingerprint_compute(labels, values, 2, &fp) == TAMGA_OK) {
    tamga_client_activate_machine(client, license_id, fp, NULL, NULL, true, &response);
    tamga_string_free(fp);
}
```

It deliberately does **not** read hardware identifiers, and will not grow the
ability to. What identifies a machine is a product decision — a cloned VM
template shares them, a container has none, a replaced motherboard changes them
— and no default is right for both a desktop application and a Kubernetes
sidecar. Values are also **not** Unicode-normalised: NFC would mean a
dependency, and a rule the eight SDKs cannot implement identically would give
one machine two fingerprints depending on which SDK the app was written in.
Normalise before calling if your values can arrive in more than one form. And
note that changing the component set changes the fingerprint, which the server
reads as a new machine against the seat limit — choose it once, at the point
you ship.

**Never let an artifact download follow its redirect.**
`GET /artifacts/{id}/actions/download` answers `303 See Other` with a
short-lived presigned URL on the object store. An HTTP client that follows
that redirect while still attaching the request's `Authorization` header hands
your licence key to the storage host. `tamga_client_get_artifact_download_url()`
therefore always asks for `?redirect=false` and offers no way to ask otherwise:
the URL comes back in the body, in `redirectUrl`, and you fetch it yourself
**with no credentials attached** — it carries its own signature and needs none.

Measured against libcurl 8.7.1 with following forced on, per credential: a
**same-origin** redirect carries `Authorization` intact for the licence-key,
bearer and basic forms, while a **cross-origin** one arrives with it stripped,
and `TAMGA_AUTH_QUERY_TOKEN` is carried by neither. Same-origin is exactly what
the server's `s3_endpoint` + `s3_force_path_style` settings produce when
storage is served from the API's own origin.

But the header worth watching is not that one: `Tamga-OTP`, which carries a
one-time password, was forwarded **to a different host** on the same build that
stripped `Authorization` there. Do not read a rule into that — across this SDK
family five runtimes produced five distinct behaviours, and every attempt to
generalise them has failed. The only claim that has held is the negative one:
you cannot know what a redirect forwards without watching it, which is why this
SDK does not follow one. Both built-in
transports refuse to follow at all (`CURLOPT_FOLLOWLOCATION` is left at `0`;
WinHTTP follows by default and is set to
`WINHTTP_OPTION_REDIRECT_POLICY_NEVER`), so the question does not arise for
them — but a transport you register through `tamga_client_set_transport()` is
your own HTTP stack, and most follow redirects out of the box.

A second reason holds regardless of headers: following the redirect streams the
artifact's **bytes** into the response buffer, which is capped, before anything
can reject them. A real artifact routinely exceeds any sane cap.

**An artifact's timestamps are `created` and `updated`, not `createdAt`.**
`ArtifactAttributes` is `rename_all = "camelCase"` — which is why the
neighbouring field really is `redirectUrl` — but carries explicit
`#[serde(rename)]` attributes overriding it for exactly those two. Applying one
rule to the whole resource compiles, runs, and reads nothing.

**A `403` on an artifact download is not necessarily an auth problem.** The
download runs the owning release through the same four gates `GET /releases/{id}`
applies — distribution strategy, suspension, expiry, entitlement — on top of
the `artifact.download` permission. So a caller holding the permission is still
refused the binary of a release its licence is not entitled to. That gate is on
the download action *alone*: `tamga_client_get_artifact()` and
`tamga_client_list_release_artifacts()` check the permission only, so an
artifact whose metadata reads perfectly well can still refuse to hand over its
bytes. Publishing is out of reach in any case — `Role::LicenseToken` carries
`artifact.read` and `artifact.download` and none of create, update or delete.

**`tamga_client_health()` is the only call that skips the account prefix.**
`/v1/health` is public, sits outside the account router, and bypasses the
host-header middleware. If every ordinary call is failing with `403` and "The
Host header does not match any configured host" while this one succeeds, the
fault is the deployment's `TAMGA_ALLOWED_HOSTS`, not your credential. Its body
is a flat `{status, version, uptime_secs}`, not a JSON:API document.

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
