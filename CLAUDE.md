# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`tamga-c` is a pure crypto/FFI wrapper crate over `tamga-rust`'s offline-verification API, exposed through a stable C ABI (`cdylib` + `staticlib` + a committed `include/tamga.h`). It has **no HTTP transport surface** — no auth headers, no `validate`/`check-in`/machine-management/entitlements endpoints. Its entire surface is four offline, deterministic crypto operations: license-file verify, machine-file verify, machine offline-proof verify + generate, and the two key-derivation primitives those file formats depend on. `tamga-java` (JNI) and `tamga-swift` (Swift/ObjC bridge) both wrap this crate rather than re-implementing signature verification in each language.

Full task breakdown and status: [`docs/plans/tamga-c.plan.md`](docs/plans/tamga-c.plan.md). Protocol/field-name source of truth for everything this repo touches: [`tamga-api`'s `docs/sdk.md`](/Users/neco/Projects/tamga-api/docs/sdk.md) (Sections 4, 6, 7, 10 specifically — checkout file formats, offline proof, and the `LicenseScheme` enum).

> **BLOCKED**: this repo is blocked on `tamga-rust` v0.1 (public API frozen/documented, 80% coverage green, published to crates.io with an explicit semver commitment). As of this scaffold, `../tamga-rust` is an empty sibling checkout, not a real crate — `Cargo.toml`'s path dependency does not resolve, and nothing in this repo builds yet. Every `extern "C" fn` currently returns `TAMGA_ERR_UNKNOWN` from a `todo!()`-adjacent stub body. See the plan file's top-of-file banner.

## Architecture

```
tamga-c/
├── Cargo.toml                    # crate-type = ["cdylib", "staticlib"]; [lib] name = "tamga"; path dep on ../tamga-rust
├── build.rs                      # runs cbindgen against src/lib.rs to (re)generate include/tamga.h
├── cbindgen.toml                 # cbindgen config: C header style, export filters, include guard, cpp_compat
├── rust-toolchain.toml           # pinned toolchain, intended to match tamga-rust
├── src/
│   ├── lib.rs                    # extern "C" fns, opaque handles, thread-local last-error, catch_unwind pattern
│   ├── license_file.rs           # tamga_license_file_verify / _get_json / _free — the ONE function with catch_unwind wired
│   ├── machine_file.rs           # tamga_machine_file_verify / _get_json / _free — multi-scheme + HKDF decrypt (all TODO)
│   ├── offline_proof.rs          # tamga_offline_proof_verify / _generate — byte-exact JSON signing (all TODO)
│   └── kdf.rs                    # tamga_hkdf_derive_machine_file_key / tamga_naive_derive_license_file_key (all TODO)
├── include/
│   └── tamga.h                   # COMMITTED, cbindgen-generated. CI diffs this for freshness. Placeholder until src/lib.rs has real exports.
├── cmake/
│   └── FetchCorrosion.cmake      # FetchContent for corrosion-rs/corrosion, vendored via CMake
├── CMakeLists.txt                # corrosion_import_crate(...), exposes IMPORTED target tamga_c::tamga_c
├── tests/
│   ├── license_file_verify.rs    # Rust-side integration tests (Section C) — STUB, currently unlinkable, see GOTCHAS
│   ├── machine_file_verify.rs    # (Section D)
│   ├── offline_proof.rs          # (Section E)
│   ├── key_derivation.rs         # (Sections C/D)
│   ├── panic_safety.rs           # catch_unwind regression tests (Section F)
│   ├── memory.rs                 # alloc/free contract tests (Section F)
│   └── c/
│       ├── CMakeLists.txt        # CTest registration, ASAN build option
│       ├── test_license_file.c   # stub CTest file
│       ├── test_machine_file.c   # stub CTest file
│       └── test_offline_proof.c  # stub CTest file
├── examples/
│   ├── CMakeLists.txt
│   ├── verify_license.c
│   ├── verify_machine.c
│   └── verify_offline_proof.c
├── vcpkg.json                    # present, BACKLOG — no portfile yet
├── CLAUDE.md                     # this file
├── README.md
├── CHANGELOG.md                  # maintained by release-please going forward
└── .github/
    ├── dependabot.yml
    └── workflows/
        ├── ci.yml                # clippy, clang-format, header-freshness gate, llvm-cov@70%, ctest, OS matrix
        ├── build-native.yml      # reusable workflow_call: cross-compile matrix (tamga-swift will reuse this later)
        └── release.yml           # release-please + cross-compile + package + gh-release attach
```

## Dev Commands

```bash
cargo build --lib          # runs build.rs -> cbindgen -> regenerates include/tamga.h
cargo test                 # BLOCKED until crate-type includes an rlib target — see GOTCHAS
cargo clippy --all-targets -- -D warnings
cargo fmt / cargo fmt --check
cargo deny check           # enforces the `rsa` crate ban, see below

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release

# AddressSanitizer build of the C harness (catches use-after-free/double-free/leaks):
cmake -S . -B build-asan -DTAMGA_C_ENABLE_ASAN=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure

clang-format --dry-run --Werror $(find tests/c examples -name '*.c' -o -name '*.h')
```

None of the above will fully succeed today — see the BLOCKED banner. `cargo build`/`cargo clippy`/`cmake` all need `../tamga-rust` to resolve as a real crate first. You *can* however syntax-check `src/*.rs` standalone (no dependency resolution needed, since `lib.rs` currently imports nothing beyond `std`):

```bash
rustc --edition 2024 --crate-type lib --emit=metadata -o /dev/null src/lib.rs
```

## GOTCHAS

### docs/sdk.md's "Known Server-Side Gaps" — none apply directly

`tamga-api`'s `docs/sdk.md` lists 10 numbered "Known Server-Side Gaps" (broken `/releases/actions/upgrade`, auth not enforced on license/machine endpoints, only 14/24 `ValidationCode` values reachable, no rate limiting, dead RFC 9421 signing code, etc.). **All 10 are about the HTTP transport surface** — endpoints, auth headers, validation codes, policy objects read over the wire. `tamga-c` has zero HTTP surface: it never makes a request, never sees a `ValidationCode`, never reads a `Policy` resource. None of those 10 items apply to this repo, and nothing here should be built to work around any of them. If you find yourself reasoning about `ValidationCode`, rate limiting, or auth headers while working in this repo, you've drifted out of scope — that logic belongs in the hand-written SDKs (`tamga-rust`, `tamga-python`, `tamga-go`, `tamga-dotnet`, `tamga-js`), not here.

### The gotchas that actually matter here (from docs/sdk.md §4, §6, §7)

- **Base64 string, not decoded bytes.** The license-file and machine-file signature is computed over `enc`'s base64 **string** — its ASCII/UTF-8 bytes as text — never the bytes you get from base64-decoding it. This is *the* single most common implementation mistake in this format. Every verify path must check the signature **before** base64-decoding `enc`, not after. `tests/license_file_verify.rs` has a dedicated regression test placeholder for this exact bug (currently `#[ignore]`d — see below).
- **Two different key derivations — do not swap them.** License-file AES keys use a **naive, non-KDF** transform: the license key's raw UTF-8 bytes, zero-padded/truncated to exactly 32 bytes (`tamga_naive_derive_license_file_key`). Machine-file AES keys use **real HKDF-SHA256** (`salt="tamga:machine-file-key-v1"`, `ikm=<license key>`, `info=<machine fingerprint>` — `tamga_hkdf_derive_machine_file_key`). Implementing the naive transform where HKDF belongs (or vice versa) produces a function that looks plausible, compiles, and silently decrypts nothing correctly.
- **`RSA_2048_JWT_RS256` is a legal `TamgaScheme` enum value, but never a legal machine-file input.** The server itself rejects this scheme for machine-file checkout (`422 SCHEME_NOT_SUPPORTED`); `tamga_machine_file_verify` must reject it outright with `TAMGA_ERR_UNSUPPORTED_SCHEME`, never attempt JWT verification.
- **Offline proof JSON field order is not negotiable.** The signed payload is `{"account":{"id":...},"machine":{"id":...,"fingerprint":...},"dataset":<dataset>}` in exactly that key order. A semantically-equal but differently-ordered re-serialization fails every check. `tamga_offline_proof_verify` and `_generate` MUST share one canonical-serialization helper so the two paths can never drift from each other.
- **Offline proof is always RSA-2048 PKCS#1 v1.5/SHA-256**, regardless of the license's own `scheme` field. Machine-file verification, by contrast, dispatches on the license's `scheme` — don't conflate the two "which algorithm do I use" decisions.

### `crate-type` has no `rlib` — `cargo test` on `tests/*.rs` won't link yet

`Cargo.toml`'s `[lib] crate-type = ["cdylib", "staticlib"]` deliberately omits `rlib`/`lib`, matching the plan's Section A checklist exactly. Consequence: none of `cdylib`/`staticlib` produce the rustc metadata Cargo needs to link a `tests/*.rs` integration-test binary against this crate via `--extern`. Every file under `tests/*.rs` is currently `#[ignore]`d for this reason — they will not compile as real tests until this is resolved, most likely by adding `rlib` to `crate-type` (ideally scoped so it doesn't ship in release build artifacts) or by driving those tests entirely through the C ABI instead of `use tamga_c::...`. Don't silently "fix" this by editing `crate-type` without reading this note and updating the plan/Cargo.toml comments together.

### Every `extern "C" fn` MUST wrap its body in `catch_unwind`

Unwinding a Rust panic across an `extern "C"` boundary is undefined behavior. `tamga_license_file_verify` in `src/license_file.rs` is the canonical reference implementation (via the `ffi_guard` helper in `src/lib.rs`) — every other exported function is `TODO`-marked to copy the exact same shape. **`security-reviewer` is mandatory** on any change to Section F (memory/lifecycle) before merge — use-after-free, double-free, panic-across-FFI UB, and string-ownership confusion are the #1 FFI bug class, and a defect here is a memory-safety vulnerability in every downstream consumer (`tamga-java`, `tamga-swift`, any direct C/C++ integrator), not a localized bug.

### Alloc/free pairing

Every function returning an owned pointer (`tamga_*_verify`, `tamga_*_generate`) has exactly one matching `tamga_*_free`. Every owned `char*` (JSON payloads, error messages, generated proof strings) goes through `tamga_string_free` — never libc `free()`. Double-free is documented UB and intentionally unguarded; guarding it would hide caller bugs. `tamga_last_error_message()` returns a **borrowed** pointer valid only until the next `tamga_*` call on the same thread — do not free it, do not hold it across calls.

## Coverage gate: 70%, not 80%

CI gates `cargo llvm-cov` at **70% lines**, lower than this org's usual 80% norm. Most of the underlying crypto/parsing correctness is (or will be) already covered by `tamga-rust`'s own test suite — this crate is marshalling/lifecycle glue *over* that logic (pointer/string marshalling, panic containment, handle lifecycle), not a second implementation of it. Don't chase 80% here by writing tests that duplicate what `tamga-rust`'s suite already proves; do chase 100% on the FFI-boundary-specific paths (null checks, `catch_unwind`, alloc/free) that have no equivalent on the Rust-native side. The C-side `ctest` suite (`tests/c/`) is pass/fail only in CI — no coverage is counted there, since C-side coverage tooling isn't part of this stack.

## Critical Dependency Notes

- **ABI-freeze commitment**: once a version of `include/tamga.h` ships in a GitHub Release, struct layout and function signature changes require a version bump — no silent breaking changes. `tamga-java` and `tamga-swift` both link against built artifacts of this exact header; a mismatch between the documented C ABI and what the `cdylib` actually exports is a memory-safety bug in every downstream consumer, not just a compile error.
- **`rsa` crate is banned**, inherited from `tamga-rust`'s house policy (RUSTSEC-2023-0071, the Marvin timing attack, unpatched). `cargo deny check` enforces this in CI. If RSA-2048 PKCS#1/PSS support (needed for machine-file verification and offline proofs) needs a crate, use `aws-lc-rs` — do not reach for `rsa` because it has the friendliest API.
- **No registry publish for v0.1.** GitHub Releases is the artifact store (`.tar.gz`/`.zip` bundling the built library + `tamga.h`), matching `docs/sdk.md`'s SDK Index. `crates.io` publish is explicitly disabled (`publish = false` in `Cargo.toml`); vcpkg/Conan portfile work is backlog (`vcpkg.json` exists with no portfile).
- **`tamga-swift`'s `Package.swift` already has a reuse-point comment** referencing `build-native.yml`'s cross-compile matrix, written before this repo had one. Keep the two comments in sync if either side's target list changes.

## Branch & Commit Convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`
Commits: [Conventional Commits](https://www.conventionalcommits.org/) format (`feat: …`, `fix: …`, etc.) — required for `release-please` to compute the next version correctly.
