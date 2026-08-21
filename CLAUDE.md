# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project

`tamga-c` is the official C/C++ SDK for Tamga — licence activation, offline
verification, and machine management. It is a **native C11 library with no
package dependencies**: every cryptographic primitive, the JSON parser, and
the protocol layer are implemented here, and the offline half links against
libc alone.

Protocol source of truth: the Tamga API protocol specification. Where any
other description of the wire format disagrees with it, the specification
wins. `tamga-rust` is the reference implementation, and this repository is
checked against it directly — see "Interoperability is verified, not assumed"
below.

**History that matters for reading the code:** through v1.2 this repository
was a Rust crate that wrapped `tamga-rust` and exposed it through a
cbindgen-generated header. v1.3 replaced the implementation entirely while
keeping the ABI. If you find a reference to Cargo, corrosion or cbindgen
anywhere, it is stale.

## Architecture

```
tamga-c/
├── CMakeLists.txt          # pure C project; src/sources.cmake holds the explicit source list
├── cmake/                  # warnings, sanitisers, HTTP backend selection, package config
├── include/tamga.h         # THE public ABI, hand-maintained (not generated)
├── src/
│   ├── tamga_api.c         # the public entry points: marshalling and handle ownership
│   ├── tamga_error.c       # the per-thread last-error slot
│   ├── tamga_mem.c         # overflow-checked allocation, DSE-resistant erase
│   ├── util/               # buf, base64, hex, uuid, rfc3339, fingerprint,
│   │                       #   json (parse + two writers)
│   ├── crypto/             # sha256/512, hmac, hkdf, aes, gcm, ed25519+fe25519,
│   │                       #   bn, rsa, p256, ecdsa, der, ct
│   ├── checkout/           # pem, cert, claims, license_file, machine_file
│   ├── proof.c             # machine offline proof
│   ├── models/validation.c # the 24 validation codes
│   └── http/               # transport seam, curl and winhttp backends, client, endpoints
├── tests/
│   ├── tamga_test.h        # the entire test framework, ~200 lines
│   ├── unit/               # per-module, incl. RFC/NIST known-answer vectors
│   ├── integration/        # offline formats against real fixtures
│   ├── http/               # endpoints via a mock transport, no sockets
│   ├── fuzz/               # libFuzzer targets for every untrusted-input parser
│   ├── fixtures/           # committed key material and offline files (see its README);
│   │                       #   server-machine-files/ is the only set this repo did not produce
│   └── c/                  # THE v1.2.2 ABI harness (see its CMakeLists for the one edit)
├── tools/fixture-generator/ # dev-only; cross-verifies fixtures against tamga-rust
└── examples/
```

## Dev commands

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DTAMGA_WARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build --output-on-failure

# ASan + UBSan -- run this before claiming anything about memory safety
cmake -S . -B build-asan -DTAMGA_C_ENABLE_ASAN=ON && cmake --build build-asan
ctest --test-dir build-asan --output-on-failure

# The zero-dependency claim
cmake -S . -B build-none -DTAMGA_HTTP=none && cmake --build build-none
ldd build-none/libtamga.so       # or otool -L on macOS

# Coverage (gate: 80% lines)
cmake -S . -B build-cov -DTAMGA_C_ENABLE_COVERAGE=ON && cmake --build build-cov
(cd build-cov && LLVM_PROFILE_FILE="$PWD/%p.profraw" ctest)
sh Scripts/check-coverage.sh 80 build-cov

# Fuzzing -- needs a full LLVM clang; Apple's does not ship libFuzzer
cmake -S . -B build-fuzz -DTAMGA_C_ENABLE_FUZZ=ON -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang
cmake --build build-fuzz
# Start from the committed seeds; copy them aside, libFuzzer writes into the
# directory it is given. Cold-starting a target wastes the run rediscovering
# the file format.
for d in tests/fuzz/corpus/*/; do
    name=$(basename "$d")
    mkdir -p "/tmp/corpus/$name" && cp "$d"* "/tmp/corpus/$name/"
done
for f in build-fuzz/tests/fuzz/fuzz_*; do
    "$f" "/tmp/corpus/$(basename "$f" | sed 's/^fuzz_//')" -max_total_time=60
done

# Style and static analysis. Install the pinned versions first -- CI uses
# exactly these, and clang-format's output differs between major versions, so
# a system clang-format will disagree with the gate.
python3 -m pip install -r requirements-dev.txt

clang-format --dry-run --Werror $(find src include tests examples -name '*.c' -o -name '*.h')
cmake -S . -B build-tidy -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
clang-tidy -p build-tidy $(find src -name '*.c')
```

## GOTCHAS

These are the mistakes that have actually cost this SDK family time. Each has
a negative test; do not remove one to "simplify" a test file.

### The signature covers the base64 STRING, not the decoded bytes

A `.lic` or machine file's signature is computed over the ASCII bytes of the
`enc` field's base64 *text*, never over what that text decodes to. Verify
before decoding. Getting this backwards produces a verifier that rejects every
real server-issued file while looking like a key problem.

Pinned by `tests/fixtures/offline/license_signed_over_decoded_bytes.lic`,
which is signed the wrong way round on purpose and must fail.

### ECDSA must pin the curve, not read it

An attacker-supplied SubjectPublicKeyInfo can declare secp256k1 while carrying
a point of exactly the right length, and several widely used parsers accept
it. A cross-repo audit found that gap live in three of this family's
from-scratch implementations. `src/crypto/ecdsa.c` compares both the algorithm
OID and the curve OID explicitly and hardwires the arithmetic to P-256.

`tests/unit/ecdsa_test.c::rejects_a_key_declaring_the_wrong_curve` builds the
actual attack and first proves the spliced point verifies when presented
honestly — so the rejection can only be the OID check.

### Canonical JSON sorts keys by UTF-8 bytes

The offline proof's signature covers a canonical serialisation whose object
keys are sorted at every nesting level. Sorting by UTF-16 code units, locale
collation or Unicode canonical equivalence diverges for astral-plane
characters — `tamga-js` shipped that once. The adversarial pair (U+E000 versus
U+10000) is a regression test.

The writer is verified against `serde_json` itself, not against reasoning
about it. Three things that check turned up and that the tests now pin:
exponential form keeps its explicit `+` (`1e+16`, not `1e16`); the
decimal/exponential threshold is ryu's, not printf's `%g`; and `serde_json`'s
*parser* is one ULP off on at least one input, while its writer agrees with
this one given identical bits.

### A `kid` hashes the base64 STRING, and a machine file's names the wrong key

`key_id()` (`tamga-api/src/shared/crypto/license_file.rs`) takes a `&str` and
digests `.as_bytes()`, so a `kid` is
`lowercase_hex(SHA-256(<the base64 text>)[0..8])` — sixteen characters from
**eight** bytes. Hashing the 32 decoded bytes instead is the natural assumption
and it is wrong silently: it yields an equally well-formed sixteen-character id
that matches nothing the server ever issued, so every genuine file reports an
unknown signing key and the bug reads as a rotation problem rather than a
hashing one.

Pinned twice, from two unrelated sources.
`tests/fixtures/signing-keys/signing-key-ids.json` carries a **negative**
vector — the same key yields `905f28def18eaac0` correctly and
`630dcd2966c43366` decoded-first — and it was produced outside this SDK
family. `tests/fixtures/server-machine-files/manifest.json` was produced by the
server's own encoder and agrees, which
`signing_key_test.c::the_servers_own_machine_file_manifest_agrees_with_the_hash_rule`
asserts.

⚠️ But that manifest may be used for the hash rule and **nothing else**. Its
generator derived each `kid` from the file's *own* signing key, so its RSA and
ECDSA entries carry four distinct kids where the live server emits one. Both
live checkout handlers compute the claim from
`account.ed25519_public_key.unwrap_or_default()` **whatever scheme signed the
bytes** (`check_out_license.rs:92-94`, `check_out_machine.rs:125-127`), while
the machine file's signing key is chosen by the licence's scheme
(`check_out_machine.rs:83-96`).

Three consequences, and each one silently breaks the obvious implementation:

- **A `kid` can only select a key for a licence file or an Ed25519 machine
  file.** For RSA and ECDSA the claim names a key that had no part in the
  signature, so a scheme-agnostic `kid`-to-key lookup would report an authentic
  file as forged — reintroducing the very defect in a new place.
  `tamga_machine_file_verify_with_key_set()` refuses them by name with
  `TAMGA_ERR_KEY_ID_NOT_APPLICABLE`. Nothing is lost: `rotate_ed25519` is the
  only rotation there is, so no other scheme has one to survive.
- **`unwrap_or_default()` means the empty string is a real input.** An account
  whose key column was never populated stamps `e3b0c44298fc1c14` —
  `SHA-256("")` — into every file it signs. `TAMGA_ERR_SIGNING_KEY_NOT_PUBLISHED`
  exists so that this is not reported as a stale key set: refetching the keys
  will never produce a match, however many times it is tried.
  `tamga_signing_key_id()` therefore validates nothing about its input, or that
  value would be out of reach.
- **A licence key cannot fetch the key set.** `GET /signing-keys` needs
  `account.read`, which `Role::LicenseToken` lacks, and unlike `policy.read`
  there is no second route to the same resource. So the key set is built from
  bytes (`tamga_signing_key_set_add_json`) or from pinned keys
  (`tamga_signing_key_set_add_public_key`), never from a client — otherwise
  offline verification would stop being offline.

The resource `id` on that route **is** the `kid`, not a UUID, so a fetched set
is indexed by the served id and the local computation is only a cross-check;
`tamga_signing_key_set_add_json` counts a disagreement in `*out_mismatched`
and still adds the key under the served id, because that is what a file names.
Retired keys are kept for the same reason — filtering them out reinstates the
whole defect.

Lookup matches the **served id alone**, never the computed one as a fallback.
`tamga-swift` documents the lenient rule (either id matches); `tamga-rust` and
`tamga-dotnet` match the served id, and so does this one. It is not a security
difference — the signature still has to verify against that key's bytes, so a
wrong selection fails closed — but a fallback would swallow the very signal
`*out_mismatched` exists to raise, and would invent a matching rule the wire
does not have. `a_fetched_key_set_indexes_by_the_served_id_not_the_computed_one`
pins the absence of the second path.

⚠️ Choosing a key by `kid` inverts this format's usual order: the `kid` lives
inside `enc`, so `enc` is decoded (and decrypted) **before** the signature is
checked. That is sound only because the `kid` can select from keys the caller
already trusts and can never introduce one, and because there is deliberately
no "try every key" fallback — which would accept the same files while
destroying the distinction the whole feature exists to draw. The single-key
entry points keep the old order and are unchanged.

### The two key derivations are not interchangeable

Both are HKDF-SHA256 over the licence key, with different parameters:

- licence file: `salt = "tamga:license-file-key-v1"`, `info = "license-file"`
- machine file: `salt = "tamga:machine-file-key-v1"`, `info = <fingerprint>`

Swapping them produces code that compiles, looks right and silently decrypts
nothing. `tests/unit/hash_test.c` asserts directly that they never coincide
and that `("ab","c")` does not collide with `("a","bc")`.

`tamga-rust/CLAUDE.md` still describes the licence-file key as "intentionally
not a KDF" over a `naive_key.rs` that no longer exists — that text predates
format v2. The code, `tamga-rust/src/checkout/license_file.rs`, calls
`crypto::hkdf::derive_license_file_key`.

### Both offline formats are v2 only, and the marker is the LAST `+` segment

`alg` must end in `+v2`; a v1 file is rejected with no fallback. In v1 the ttl
lived in the JSON envelope *outside* the signature, so a 24-hour trial file
was cryptographically valid forever — the client holds the file and can edit
anything the signature does not cover. Accepting both formats hands that back.

The licence file's `alg` is one of two fixed strings, matched whole. The
machine file's is not: it is `<encoding>+<signing suffix>+v2`, where the
encoding is `base64` or `aes-256-gcm` and the suffix is one of four. Both
outer parts contain hyphens of their own, so the only correct delimiters are
the **first** `+` and the **last** `+` — `src/checkout/machine_file.c`'s
`tamga_machine_alg_split`. Two wrong readings have shipped across this SDK
family: splitting once and comparing the whole remainder (which rejects every
real file, because the remainder still carries `+v2`), and a substring
`contains("+v2")` test (which accepts `base64+ed25519+v2junk` and
`xbase64+ed25519+v2`). Pinned per-fixture in
`tests/integration/server_machine_files_test.c`, which rewrites each real
file's marker to `""`, `+v1`, `+v3`, `+v2junk` and `+v2+v2` in turn.

### An encrypted machine file's payload is dot-separated; a licence file's is not

Same AES-256-GCM primitive, different framing, and assuming one framing for
both breaks the other:

- licence file: `enc = base64(nonce(12) || ciphertext || tag(16))`, one blob
- machine file: `enc = base64(nonce) "." base64(ciphertext || tag)`, two
  halves encoded **separately**

The server's own doc comment at `tamga-api`
`src/shared/crypto/machine_file.rs:59` still describes the machine file as the
single blob, contradicting the code twenty lines below it that calls
`FieldEncryption::encrypt`. That stale comment is why all eight SDKs
implemented the same wrong thing. The licence file really is the single blob
(`license_file.rs`'s own private `aes256gcm_encrypt`), so `license_file.c` is
correct as written — do not "fix" it to match.

This repository's base64 decoder is strict (`TAMGA_B64_REVERSE['.']` is
`0xFF`), so the old single-blob reading failed outright here rather than
working by accident the way it does under CPython's and Node's lenient
decoders, which silently drop the `.` and happen to reconstruct
`nonce||ciphertext` because both halves are multiples of four characters.

Verify, THEN split, THEN decode, THEN decrypt. Nothing parses `enc` before the
signature over the whole `enc` string has verified.

### The machine file's `exp` is signed, and it is enforced

`check_out_machine.rs` builds the signed payload as
`{ "data": <machine>, "meta": <LicenseFileClaims> }` — the same claims struct
the licence file uses, carrying `iat`, `exp`, `jti` and `kid`. Until this was
enforced, a machine file verified forever.

`exp` is optional by design: `ttl` is an `Option`, `exp` is
`#[serde(skip_serializing_if = "Option::is_none")]`, and a checkout with no
ttl produces a file with no `exp` that genuinely never expires. Absence is not
an error. Both formats run the check through `tamga_claims_are_expired()` in
`src/checkout/claims.c` so the 60-second tolerance cannot drift between them.

### The machine file's scheme comes from the caller, never from the file

`RSA_2048_PKCS1_SIGN` and `RSA_2048_JWT_RS256` share the `rsa-sha256` alg
suffix server-side, so the file cannot disambiguate its own scheme — and
letting untrusted input select a cryptographic primitive is algorithm
confusion regardless. The caller passes the licence's `scheme`; the file's
declared suffix must match it. `RSA_2048_JWT_RS256` and `NONE` are rejected
outright.

### The RSA public key is PKCS#1 RSAPublicKey, not SPKI

`aws-lc-rs`'s RSA verification API takes `SEQUENCE { INTEGER n, INTEGER e }`,
so that is what `tamga-rust` exchanges — despite its doc comment calling it
SPKI, and despite `tests/fixtures/offline/rsa_spki.der` keeping that name.
This library accepts both encodings; they are unambiguous to tell apart.

### PEM marker checks need a combined-length guard

Matching a prefix and matching a suffix are independent facts: a short enough
input satisfies both while the markers overlap, and the body span computed
from them then has a negative length — which, as a `size_t`, is an enormous
one. The same bug was found and fixed during the security review of this
family's .NET, Java and Swift implementations, where it produced an unexpected
exception type; here it would be an out-of-bounds read.

### tamga-rust rejects a line-wrapped PEM body

Its parser trims only the ends of the body and hands the rest to a strict
base64 decoder. `tamga-swift` and `tamga-java` strip embedded whitespace and
accept either form. This SDK follows the lenient majority, pinned by
`license_plain_wrapped.lic`.

### A JSON child belongs to its parent only once it has been set into it

`tamga_json_object_set` takes ownership of its `item` whether it succeeds or
fails -- but only of that item. Building `meta`, filling it, and setting it
into `root` last means a failure part-way leaves `meta` owned by nobody, and
the single `tamga_json_free(root)` that every one of these builders ends with
silently leaks it.

Three real leaks of exactly this shape were found in `proof.c` and
`endpoints.c`. The fix is to attach the child to its parent first and fill it
afterwards -- except where insertion order is the wire order, which
`tests/http/endpoints_test.c` pins byte-for-byte; there the child is freed
explicitly on the failure path instead. Do not reorder those keys to make the
ownership tidier.

### An allocation failure is not a malformed file

`tamga_base64_decode_alloc` and `tamga_json_parse` both return NULL for two
unrelated reasons, and reporting the wrong one turns "this machine is out of
memory" into "your licence file is corrupt" -- or, in `proof.c`, into "this
proof is forged". Use `tamga_base64_decode_alloc_why` and
`tamga_json_error_is_out_of_memory` at any boundary that maps to a
`TamgaErrorCode`.

`tests/unit/alloc_failure_test.c` walks every allocation on the offline path
and in three request builders, failing them one at a time -- 943 injections
across five offline operations, plus the request builders -- and asserts each
run either succeeds or returns `TAMGA_ERR_OUT_OF_MEMORY`, with no blocks left
outstanding. Every misreport above was found by it.

The key-set walk is there for a reason of its own: on that path a failed
`strdup` of a key id would leave the set short of the key a genuine file names,
and the caller would read the resulting `TAMGA_ERR_UNKNOWN_SIGNING_KEY` as
"this file belongs to another licence". The walk asserts that no allocation
failure can produce a verdict -- only `TAMGA_OK` or `TAMGA_ERR_OUT_OF_MEMORY`.

### The same over-limit activation is reported two different ways

Creation *does* enforce the licence's limits, and the server's create-time
check runs through the policy's overage strategy. Under a strict strategy
`POST /machines` is rejected with `422 MACHINE_LIMIT_EXCEEDED` (or the core,
memory, disk variant). Under `ALLOW_ACCESS` or `ALLOW_1_25X_OVERAGE` the same
request succeeds and the limit only appears in the following validation as
`TOO_MANY_MACHINES`. Both are live for the same code path, so
`tamga_client_activate_machine()` carries both branches: the create-time one
returns the limit error and issues **no** rollback DELETE (there is no row to
delete), while the overage one still creates, validates and rolls back.
`tamga_validation_code_from_error()` exists so a caller writes one branch
instead of two.

Pinned by `activate_machine_reports_a_creation_time_limit_without_deleting`
and `activate_machine_still_rolls_back_when_the_overage_strategy_allows_the_create`.
Do not delete either — the pair is the point.

### One listing in the machine domain is offset-paginated, and only one

`GET /machines` goes through the server's shared offset paginator
(`tamga-api/src/shared/list_query.rs`): `page[number]`, `page[size]`, and a
`meta.page{number,size,total,totalPages}` object. Every other listing this SDK
calls — components, entitlements, a machine's processes — keeps its own
hand-written keyset query and returns no `meta` at all.

Neither shape fails loudly when confused for the other, which is why both
accessors exist and why each names its own: `tamga_response_next_cursor()`
against a machine listing derives a cursor the route ignores and re-fetches
page one forever; `tamga_response_page()` against a keyset listing returns
false. `the_machine_collection_is_offset_paginated` asserts both directions on
the same response.

M6 found `page[after]` inert on entitlements. This is the same mistake
available in the opposite direction — do not assume a domain paginates one
way because most of it does.

### `FINGERPRINT_TAKEN` means "already activated", and only sometimes "not yours"

`machines/service.rs` checks fingerprint uniqueness *before* the seat limits,
and its comment says why: checked the other way round, a licence at its limit
answered a routine re-activation with `MACHINE_LIMIT_EXCEEDED`, so an SDK told
the customer to buy seats for a machine they had already licensed. The
conflict is the accurate answer and it means "carry on".

`tamga_client_activate_machine_idempotent()` is that carrying on, and the part
that is easy to get wrong is when it must NOT. The conflict is raised under the
policy's `machine_uniqueness_strategy`, which has three scopes:
`UNIQUE_PER_LICENSE` (the default), `UNIQUE_PER_POLICY` and
`UNIQUE_PER_ACCOUNT`. Under the wider two the machine holding the fingerprint
can belong to a **different licence**, and returning it as "yours" shares one
seat across licences — the exact thing those strategies exist to prevent. So
the lookup is scoped to the licence server-side with `filter[license]`, and a
miss re-raises `FINGERPRINT_TAKEN` unchanged.

Server-side scoping is not a stylistic choice here: `MachineResource` carries
no `relationships` and no licence id, so a machine handed back by the listing
cannot be checked against a licence locally.

Widening the lookup to the account was proposed and is wrong, and the reason
is that all three uniqueness scopes are supersets of "a machine on this
licence with this fingerprint". Every `EXISTS` check in `service.rs` includes
the caller's own licence rows: `UNIQUE_PER_LICENSE` matches `license_id = $2`
directly, `UNIQUE_PER_POLICY` joins licences on the policy this licence
already has, `UNIQUE_PER_ACCOUNT` covers the whole account. So a genuine
re-activation raises the conflict under all three *and* a licence-scoped
lookup finds it under all three.

What an account-wide lookup adds is precisely the cross-licence case — the one
the server refuses on purpose. Returning that machine leaves the caller
heartbeating and checking out a machine its licence does not own, with its own
`machines_count` still zero and no way to notice, because the resource carries
no licence id. An account-wide search is still available as an explicit
diagnostic, `tamga_client_list_machines(client, NULL, fingerprint, ...)`, and
it is deliberately a separate call.

And there is no exact-fingerprint filter to scope with. `filter[q]` is
`ILIKE '%term%'` across `name`, `hostname` and `fingerprint`
(`shared/list_filter.rs`), truncated at 200 characters — a substring search,
not an equality filter. Every candidate it returns is compared in full by
`tamga_machine_page_exact_match`, which reports a failed copy as
`TAMGA_ERR_OUT_OF_MEMORY` rather than as "no match": the caller reads "no
match" as "the fingerprint belongs to another licence", which is a wrong and
unactionable answer to an out-of-memory.

### The heartbeat window is a policy read, never a machine field

`Policy::effective_heartbeat_duration_secs()` is the policy's
`heartbeat_duration` or 600. `tamga_response_heartbeat_window_secs()` mirrors
it, and `heartbeat_duration: null` is the fallback rather than an error — the
field has no `skip_serializing_if`, so it is always on the wire.

`next_heartbeat_at` is not a substitute. It is derived from
`Machine::effective_window_secs()`, which reads a column populated only when
the query joined `policies` — so create, ping-heartbeat and reset-heartbeat
compute it against 600 while check-out, generate-offline-proof and the machine
reads compute it against the policy. Two responses for one machine, seconds
apart, disagree, and a scheduler naturally calls the wrong one. Reported
upstream.

Two further things that are not the window: `require_heartbeat` defaults to
false and the cull job early-returns when it is, so a default policy culls
nothing; and a licence key cannot read `/policies/{id}` at all
(`Role::LicenseToken` has no `policy.read` — see below), so the window comes
from `GET /licenses/{id}/policy`.

### `PATCH /machines/{id}` is a write whose response can still say `DEAD`

The contract's write-vs-read rule — a response the server builds off a write
it just performed can never report `DEAD`, because the status is derived from
the timestamp that write set — has a counterexample, and it is the update
route. `queries::update`'s `UPDATE … RETURNING` never touches
`last_heartbeat_at`, so the status is judged against a timestamp this write
did not set and `DEAD` is reachable; and the statement does not join
`policies`, so `next_heartbeat_at` falls back to 600 seconds the way the ping
routes do.

The durable form of the rule is narrower than "write": a response is only
guaranteed not to say `DEAD` when the write it was built from set
`last_heartbeat_at` itself. Ping, reset and create qualify. PATCH does not.

### An artifact download must never be allowed to follow its redirect

`GET /artifacts/{id}/actions/download` answers `303 See Other` to a short-lived
presigned URL on the object store. A client that follows that redirect with the
request's `Authorization` header still attached hands the licence key to the
storage host.

⚠️ **Measured, not assumed**, and measured per auth kind -- a rule about one
credential is not a rule about another. Driving this repo's own curl transport
at a local 303 server with `CURLOPT_FOLLOWLOCATION` forced to `1`
(libcurl 8.7.1):

| auth kind | same-origin hop | cross-origin hop |
|---|---|---|
| `TAMGA_AUTH_LICENSE` | **sent intact** | stripped |
| `TAMGA_AUTH_BEARER` | **sent intact** | stripped |
| `TAMGA_AUTH_BASIC_*` | **sent intact** | stripped |
| `TAMGA_AUTH_QUERY_TOKEN` | not sent | not sent |

So all three `Authorization` forms leak same-origin and none leaks
cross-origin; the query-token form leaks by neither route, because the
`Location` replaces the URL and the `?token=` goes with it. There is no cookie
credential here, so the cookie-forwarding hazard a sibling SDK measured has no
analogue. The leak needs a same-origin redirect -- exactly what `s3_endpoint` +
`s3_force_path_style` produce when storage is served from the API's own origin.

Do not generalise any of it: `CURLOPT_UNRESTRICTED_AUTH`'s default has varied
across libcurl versions, and sibling SDKs measured three different behaviours
across three runtimes. Re-measure before relying on it.

At the shipped `FOLLOWLOCATION` of `0` no redirect is followed at all, so the
question does not arise; `transport_winhttp.c` sets
`WINHTTP_OPTION_REDIRECT_POLICY_NEVER` for the same reason (WinHTTP follows by
default, so that one is a correction). But a transport registered through
`tamga_client_set_transport()` is the caller's own stack and most follow out of
the box, so `tamga_client_get_artifact_download_url()` sends `?redirect=false`
unconditionally and exposes no parameter for asking otherwise. Pinned by
`the_artifact_download_never_asks_for_the_redirect`.

A second reason holds whatever a transport does about headers: following
streams the artifact's **bytes** into the capped response buffer
(`TAMGA_TRANSPORT_FAIL_OVERSIZED`) before anything can reject them, and a real
artifact routinely exceeds any sane cap.

Three more things about that surface:

- **`created`/`updated`, not `createdAt`/`updatedAt`.** `ArtifactAttributes` is
  `rename_all = "camelCase"` -- which really does make the neighbouring field
  `redirectUrl` -- but carries explicit `#[serde(rename)]` attributes overriding
  the container rule for exactly those two (`artifacts/serializer.rs:20,34-37`).
  Applying one rule to the whole resource compiles, runs and reads nothing.
- **A `403` on the download is not necessarily an auth problem.** The handler
  runs the owning release through `releases::service::enforce_release_access`
  on top of the permission, so a caller holding `artifact.download` is still
  refused a release its licence is not entitled to. That gate is on the
  download action **alone** -- `list_artifacts` and `get_artifact` check the
  permission only, so metadata that reads perfectly well can still refuse its
  bytes.
- **Read and download are the whole surface.** `Role::LicenseToken`
  (`shared/authz/mod.rs:241-268`) carries `artifact.read` and
  `artifact.download` and none of create, update or delete. An SDK offering
  publication would only be offering a 403. Note that only `artifact.download`
  (`:265`) was granted by `e6d317b` -- `artifact.read` (`:264`) predates it, so
  the listing and metadata read were always reachable and merely had no SDK
  method. Only the bytes were ever a 403.

### The curl handle is confined to http and https

`tamga_curl_restrict_protocols()` sets `CURLOPT_PROTOCOLS_STR` to `http,https`
(falling back to `CURLOPT_PROTOCOLS` below libcurl 7.85), checked rather than
discarded like the TLS-verification options beside it.

⚠️ **This was measured to matter.** With the option removed, driving the
transport at `file:///tmp/<a file>` on libcurl 8.7.1 **succeeded** and returned
the file's contents as `response->body`; with it set the same call fails, while
an `http://` control still succeeds. libcurl speaks `file:`, `scp:`, `ftp:` and
`gopher:` and will attempt whatever scheme the URL names.

Nothing builds a curl URL from a server-supplied value today --
`tamga_client_compose_origin()` prepends `https://` to anything not already
beginning `http://` or `https://`, and `CURLOPT_FOLLOWLOCATION` is `0` so no
`Location` can introduce one. Both are one edit away from being untrue, and the
failure is a local-file read driven by a remote value, handed back as a
response body. A sibling SDK found its own "is this an absolute URI" check
accepting `/relative/path` and `C:\x\y` as `file:` URIs.

There is deliberately **no unit test** for this: `transport_curl.c` needs a live
handle, and this repo's rule is that a fake test for it would measure nothing.
It was verified with a throwaway probe instead, both directions.

### A fingerprint is canonicalised, never generated

`tamga_fingerprint_compute()` takes caller-chosen labelled components and
returns `lowercase_hex(SHA-256(canonical))`. It deliberately does **not** read
hardware identifiers, and must not grow the ability to: what identifies a
machine is a product decision -- a cloned VM template shares them, a container
has none, a replaced motherboard changes them -- and no default is right for
both a desktop application and a Kubernetes sidecar.

What it does fix is measured: all eight SDKs sent the caller's string byte for
byte, and the server stores `fingerprint TEXT NOT NULL` with no length limit,
no `CHECK` and no normalisation, unique per `(license_id, fingerprint)`. So
`"ABC-123"`, `"abc-123"` and `" ABC-123 "` were three seats.

⚠️ **Values are NOT Unicode-normalised, and that is a constraint rather than an
oversight.** NFC here would mean ICU or hand-rolled Unicode tables inside a
library whose defining property is having none, and a rule the eight ports
cannot implement identically is worse than no rule: one machine would get two
fingerprints depending on which SDK the application used. Every rule is
ASCII-only for that reason. Do not "improve" it with a normalisation step.

⚠️ **The sort is over unsigned bytes.** `memcmp`, `strcmp` and `strncmp` are
all specified to compare as `unsigned char` (C11 7.24.4p1), so the library
functions are safe -- the trap is a hand-rolled `a[i] - b[i]` over plain
`char`, which on a signed-char target orders every byte above `0x7F` before
every ASCII one and fingerprints the same machine differently on ARM than on
x86. `src/util/fingerprint.c` uses `memcmp`, and
`the_sort_compares_bytes_as_unsigned` pins the ordering that the published
single-component `non_ascii_value` vector cannot reach.

⚠️ **Rejections are never repairs.** Stripping a control character or
deduplicating a repeated label maps two different inputs onto one canonical
string -- two machines, one seat, the mirror image of the defect above. All
eight `rejected` cases in `tests/fixtures/fingerprint/fingerprint.json` return
`TAMGA_ERR_INVALID_FINGERPRINT_COMPONENT`.

The vectors were produced outside this SDK family. In the file the separator is
written as the literal text `<US>` for diffability; the byte hashed is `0x1f`.

### The permission a licence key has decides which read route works

`Role::LicenseToken::default_permissions()` (`shared/authz/mod.rs`) is the
whole list a licence-key credential gets. It carries `license.read`,
`machine.read`, `machine.update`, `process.read`, `process.delete` and
`component.*` — so the reads and the disposal added in 1.3.x work — and it
does **not** carry `policy.read`. `GET /policies/{id}` is therefore a `403`
for every licence key, and `GET /licenses/{id}/policy` returns the identical
resource through a permission it does have.

Separately, `require_license_scope` — the check that confines a licence key to
its own licence — is applied to validate, quick-validate, validate-key and
check-out, and **not** to `get_license` or `get_license_policy`. One licence
key can read every licence in the account by id, and `attributes.key` is the
plaintext key. Reported upstream; the SDK's obligation is to not describe that
surface as scoped. Do not "simplify" the warnings on those two entry points.

The same is true of every machine route: `require_license_scope` is applied to
none of them, and a licence key carries `machine.read`, `machine.update` and
`machine.delete`. So a licence key can read, PATCH and DELETE any machine in
the account by id. Also reported upstream, and also not something the docs may
imply is scoped.

### Licence-key authentication is off unless the policy opts in

`authentication_strategy` defaults to `TOKEN`, and `NONE` refuses licence keys
too, so `TAMGA_AUTH_LICENSE` answers `401 LICENSE_NOT_ALLOWED` on a default
policy. It is a provisioning precondition, not a bad key and not a transient
error, which is why it has its own code rather than collapsing into
`TAMGA_ERR_UNAUTHORIZED` and inviting a re-prompt. `LICENSE_SUSPENDED` and
`LICENSE_EXPIRED` arrive the same way, also as 401.

Separately, `reset-heartbeat` and `generate-offline-proof` are role-gated
above a licence key and always answer `403` to one, whatever its permissions.

### The error enum grows, and error-code JSON `status` is a string

New `TamgaErrorCode` values are appended as the server widens its error
vocabulary. Consumers must carry a `default:` case; `tests/c/
abi_surface_test.c` pins the first and last value of each appended block so an
insertion into the middle fails the build rather than silently renumbering.

When writing a test fixture for a JSON:API error document, `status` is the
**string** `"422"`, not the number. The mapping reads `code` and never
`status`, which is exactly why the real shape has to be in the test — nothing
would fail if it drifted.

### The clock is a security input

`tamga_time_now_unix` returns `bool`. The licence-file expiry check is
`now - skew > exp`, so any substituted value on a clock-read failure -- 0
especially -- makes every expiry check pass and returns `TAMGA_OK`. An earlier
version returned 0 while its own comment claimed to fail closed.

## Conventions

**The ABI is frozen.** Every signature in `include/tamga.h` that shipped in a
release stays byte-identical, including the `uintptr_t` length parameters that
are the wrong type for a length. Enum values are appended, never renumbered.
`tests/c/` holds the v1.2.2 harness as the proof; `tests/c/
abi_surface_test.c` asserts every frozen number at compile time.

The one edit ever made to that harness is in `test_machine_file.c`, and it did
not touch the ABI: the machine file it shipped with is offline format v1,
which is now refused, so the assertion changed from "this verifies" to "this
is refused". The original bytes are still in the file as the negative case.
Internal headers under `src/` are not part of this promise --
`tamga_machine_file_verify_at()` gained a `now_unix` and a claims out-param
when machine-file expiry started being enforced.

**Errors.** Every public entry point clears the thread's error slot on entry,
so `TAMGA_OK` always means `tamga_last_error_message()` returns `NULL`. The
free functions are the exception — they cannot fail, and clearing there would
erase a message the caller is about to print. No message ever contains a
licence key, token or password.

**Ownership.** One `_free` per handle; one `tamga_string_free` for every owned
`char *`. Double-free is documented undefined behaviour and intentionally
unguarded — a guard hides the caller's bug rather than fixing it.

**No `strcpy`, `strcat`, `sprintf` or `atoi` in `src/`.** Every growable byte
sequence goes through `util/buf.c`; every length computation goes through the
checked arithmetic in `tamga_mem.h`.

**Sticky-failure buffers are safe because detaching checks.** `TamgaBuf`
absorbs an allocation failure into a flag rather than returning at every
append, and both detach functions refuse a failed buffer. A caller cannot
receive truncated output without having ignored a NULL.

## Testing

**Coverage gate: 80% lines**, enforced in CI. `src/http/transport_curl.c` sits
far below that on purpose — it needs a live server, and a fake test for it
would measure nothing. Do not write one.

**Every crypto primitive is pinned to published vectors**, and every gotcha
above has a *negative* test. A positive test proves the happy path works; only
the negative one proves the check is there.

**Fuzzing needs three things to mean anything**: the harnesses must be built
against an instrumented library (`tests/fuzz/CMakeLists.txt` records what
happened when they were not -- 43M executions at a coverage counter of 3),
each harness must actually reach the code it names (`machine_file_fuzz.c`
passed one key length for four schemes and never reached Ed25519), and the
seed corpus in `tests/fuzz/corpus/` must be used (measured: `cov: 455` cold
versus `cov: 1221` seeded, same 30 seconds).

**Whitebox tests compile the module under test instead of linking it**, via
`tamga_add_whitebox_test`. That is how `p256_test.c` reaches static Montgomery
arithmetic and how `alloc_failure_test.c` substitutes an allocator, without
either putting a test-only symbol in the library.

**Interoperability is verified, not assumed.** The offline fixtures were
produced by `tools/fixture-generator/` and run through `tamga-rust`'s verifier
before being committed. That tool needs Rust and a sibling `tamga-rust`
checkout, and is deliberately outside the CMake build — the library itself
must never grow a dependency, and a fixture generated and checked by the same
implementation proves only self-consistency.

**And self-consistency is not enough — it hid a two-year bug.** Every machine
file under `tests/fixtures/offline/` and `tests/fixtures/cross-sdk/` is
offline format **v1**, because the generator was written from the same
misreading of the format the verifier had. CI was green the whole time and no
build of this SDK could open a file the server actually emitted.
`tests/fixtures/server-machine-files/` is the answer: twelve files from the
server's own `encode_machine_file`, driven from a `manifest.json` so a new
fixture needs no test edit. **Do not generate a machine-file fixture here.**
Ask for one from the server's encoder. The v1 sets are kept as the negative
corpus and are asserted to be refused.

Note that those server fixtures were issued with a one-hour ttl, so a test
that verifies one against the wall clock starts failing an hour later. Use
`tamga_machine_file_verify_at()` and the file's own signed `iat`/`exp`.

**`src/crypto/`, `src/checkout/`, `src/proof.c` and `src/http/` require a
`security-reviewer` pass before merge**, one area per review.

## Branch and commit convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`
Commits: [Conventional Commits](https://www.conventionalcommits.org/).
release-please reads this history to compute the next version and to rewrite
the four places the version appears (`CMakeLists.txt`, `include/tamga.h`, and
both `vcpkg.json` files) — an inaccurate commit type skips a release entirely,
and a `!` where none belongs forces a major.
