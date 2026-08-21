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
│   ├── util/               # buf, base64, hex, uuid, rfc3339, json (parse + two writers)
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
and in three request builders, failing them one at a time -- 586 injections --
and asserts each run either succeeds or returns `TAMGA_ERR_OUT_OF_MEMORY`,
with no blocks left outstanding. Every misreport above was found by it.

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

Widening the lookup to the account was proposed and is wrong. It would hit in
the cross-licence case too, and returning that machine leaves the caller
holding a machine id whose seat belongs to another licence while this one's
`machines_count` was never incremented — the exact arrangement
`UNIQUE_PER_ACCOUNT` exists to forbid, arranged by the SDK. The scoped lookup
hits in exactly the cases where carrying on is legitimate. An account-wide
search is still available as an explicit diagnostic —
`tamga_client_list_machines(client, NULL, fingerprint, ...)` — and it is
deliberately a separate call.

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
