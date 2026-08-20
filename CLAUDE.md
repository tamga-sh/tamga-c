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
│   ├── checkout/           # pem, cert, license_file, machine_file
│   ├── proof.c             # machine offline proof
│   ├── models/validation.c # the 24 validation codes
│   └── http/               # transport seam, curl and winhttp backends, client, endpoints
├── tests/
│   ├── tamga_test.h        # the entire test framework, ~200 lines
│   ├── unit/               # per-module, incl. RFC/NIST known-answer vectors
│   ├── integration/        # offline formats against real fixtures
│   ├── http/               # endpoints via a mock transport, no sockets
│   ├── fuzz/               # libFuzzer targets for every untrusted-input parser
│   ├── fixtures/           # committed key material and offline files (see its README)
│   └── c/                  # THE v1.2.2 ABI harness, byte-for-byte unmodified
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

### Licence files are format v2 only

`alg` must end in `+v2`; a v1 file is rejected with no fallback. In v1 the ttl
lived in the JSON envelope *outside* the signature, so a 24-hour trial file
was cryptographically valid forever — the client holds the file and can edit
anything the signature does not cover. Accepting both formats hands that back.

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

### The clock is a security input

`tamga_time_now_unix` returns `bool`. The licence-file expiry check is
`now - skew > exp`, so any substituted value on a clock-read failure -- 0
especially -- makes every expiry check pass and returns `TAMGA_OK`. An earlier
version returned 0 while its own comment claimed to fail closed.

## Conventions

**The ABI is frozen.** Every signature in `include/tamga.h` that shipped in a
release stays byte-identical, including the `uintptr_t` length parameters that
are the wrong type for a length. Enum values are appended, never renumbered.
`tests/c/` holds the v1.2.2 harness unmodified as the proof; `tests/c/
abi_surface_test.c` asserts every frozen number at compile time.

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

**`src/crypto/`, `src/checkout/`, `src/proof.c` and `src/http/` require a
`security-reviewer` pass before merge**, one area per review.

## Branch and commit convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`
Commits: [Conventional Commits](https://www.conventionalcommits.org/).
release-please reads this history to compute the next version and to rewrite
the four places the version appears (`CMakeLists.txt`, `include/tamga.h`, and
both `vcpkg.json` files) — an inaccurate commit type skips a release entirely,
and a `!` where none belongs forces a major.
