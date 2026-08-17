# Security Policy

## Scope

`tamga-c` is a pure crypto/FFI wrapper over `tamga-rust`'s offline-verification
API, exposed through a stable C ABI. It has no HTTP transport surface. The
highest-risk code lives in:

- [`src/license_file.rs`](src/license_file.rs) — `.lic` file FFI verify/decrypt.
- [`src/machine_file.rs`](src/machine_file.rs) — machine-file FFI verify/decrypt, multi-scheme.
- [`src/offline_proof.rs`](src/offline_proof.rs) — offline proof FFI verify.
- [`src/kdf.rs`](src/kdf.rs) — the two key-derivation FFI entry points.
- `src/lib.rs`'s `catch_unwind` wrappers — a panic crossing the FFI boundary is undefined behavior.

## Supported Versions

A 1.x series exists (latest release `v1.2.0`), so the two most recent minor
versions receive security patches.

## Security Properties

Each claim below names the function that implements it. Cryptographic work is
delegated to `tamga-rust`; this crate marshals arguments across the C ABI.

- **Both offline file formats derive their AES-256-GCM key with HKDF-SHA256**
  (RFC 5869), never from raw key bytes.
  - License file: `salt = "tamga:license-file-key-v1"`, `ikm = <license key>`,
    `info = "license-file"` — `src/kdf.rs::tamga_hkdf_derive_license_file_key`,
    delegating to `tamga-rust`'s `src/crypto/hkdf.rs::derive_license_file_key`.
  - Machine file: `salt = "tamga:machine-file-key-v1"`, `ikm = <license key>`,
    `info = <machine fingerprint>` —
    `src/kdf.rs::tamga_hkdf_derive_machine_file_key`, delegating to
    `tamga-rust`'s `src/crypto/hkdf.rs::derive_machine_file_key`.

  The pre-v2 license-file transform (the licence key's raw bytes zero-padded or
  truncated to 32) has been **removed, not deprecated** — its source module and
  its exported `tamga_naive_derive_license_file_key` symbol are both gone, so a
  caller cannot silently opt back into a key whose real strength was the licence
  key's own entropy.

- **License files must be offline format v2.** `alg` must end in `+v2`
  (`base64+ed25519+v2` or `aes-256-gcm+ed25519+v2`), and the signed `meta` claims
  (`iat`, `exp`, `jti`, `kid`) are covered by the signature rather than sitting in
  an editable envelope. A file that does not declare `+v2` is rejected with
  `TAMGA_ERR_UNSUPPORTED_SCHEME`; there is no v1 fallback path. Enforced by
  `tamga-rust`'s `src/checkout/license_file.rs::verify_license_file`, surfaced
  through `src/license_file.rs::tamga_license_file_verify`.

- **`exp` is enforced, with a 60-second clock-skew tolerance**, and reported as a
  dedicated `TAMGA_ERR_EXPIRED` code so callers can tell an expired file from a
  forged one (`src/license_file.rs::map_checkout_error`). The tolerance constant
  is `tamga-rust`'s `src/checkout/license_file.rs::CLOCK_SKEW_TOLERANCE_SECS`.

- **Signatures are verified over `enc`'s base64 *string*, before decoding**, which
  is the single most common implementation mistake in this file format
  (`tamga-rust`'s `src/checkout/license_file.rs::verify_license_file_at`).

- **Machine-file algorithm selection comes from the license's `scheme`, not from
  the file's self-declared `alg`**, and the two are cross-checked — a self-declared
  string cannot be allowed to pick the verifying primitive
  (`tamga-rust`'s `src/checkout/machine_file.rs::scheme_alg_suffix`).
  `RSA_2048_JWT_RS256` and `TAMGA_SCHEME_NONE` are rejected outright
  (`src/machine_file.rs::map_scheme`).

- **No panic crosses the FFI boundary.** Every exported function runs its body
  through `src/lib.rs::ffi_guard` or `src/lib.rs::ffi_guard_void`, converting a
  caught panic into `TAMGA_ERR_PANIC` instead of unwinding into C (which is
  undefined behavior).

- **`#[repr(C)]` enums are never accepted as parameters by value.** A C `enum` has
  no validity range, so an out-of-range value would be undefined behavior the
  instant it landed in a typed Rust parameter. Scheme arguments arrive as `uint32_t`
  and are validated by `src/lib.rs::TamgaScheme::from_raw` first.

- **The `rsa` crate is banned** (RUSTSEC-2023-0071, the unpatched Marvin timing
  attack). `deny.toml` enforces this and CI runs `cargo deny check`; RSA work uses
  `aws-lc-rs`.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a suspected security vulnerability.**

Report it privately via GitHub's [private vulnerability reporting](https://github.com/tamga-sh/tamga-c/security/advisories/new)
feature on this repository. Include:

- The affected file(s)/function(s) and, if possible, a minimal reproduction.
- Whether the issue is a verification bypass (a forged `.lic`/machine file
  or offline proof that this SDK would incorrectly accept as valid), an
  information leak, a denial-of-service via malformed/adversarial input, or
  something else.
- The version (git commit or tagged release) you tested against.

You should receive an initial response within 5 business days. Confirmed
vulnerabilities will be fixed in a private branch and disclosed via a GitHub
Security Advisory alongside the patched release; we will credit reporters
who wish to be credited.

## What Counts as a Vulnerability Here

Given this SDK's actual attack surface (an offline file/proof verifier, not
a server), the highest-severity class of bug is **a verifier that accepts
something it should reject** — for example, a signature check computed over
the wrong bytes, a scheme dispatch that picks the wrong algorithm, an
acceptance of a non-`+v2` license file, or an offline proof that verifies
against a differently-serialized (but semantically equivalent) payload.

Memory-safety defects at the ABI boundary are the second class:
`tamga-java` and `tamga-swift` both link against built artifacts of
`include/tamga.h`, so a use-after-free, double-free, or panic-across-FFI
here is a vulnerability in every downstream consumer, not a localized bug.

## Known, Deliberate Non-Vulnerabilities

The following are intentional design decisions, not bugs, and reports about
them will be closed without action (though corrections/clarifications are
welcome):

- **Expiry is checked against whatever clock the host provides.** The end user
  controls that clock, so winding it back can revive an expired file. The 60-second
  skew tolerance is deliberately small for exactly this reason, but it is not a
  defence. `tamga-rust` exposes `verify_license_file_at` for callers that keep a
  server-supplied timestamp; this crate's C ABI does not surface that parameter
  today (see the README's "Known gaps").
- **Double-free and use-after-free on handles are documented undefined behavior
  and intentionally unguarded** (`src/lib.rs::tamga_string_free`,
  `src/license_file.rs::tamga_license_file_free`,
  `src/machine_file.rs::tamga_machine_file_free`). Guarding them would hide caller
  bugs rather than fix them.
- **`tamga_offline_proof_verify` returns `TAMGA_OK` for a proof that fails to
  verify.** The call itself succeeded; `*out_valid` is the verification result and
  callers must check both (`src/offline_proof.rs::tamga_offline_proof_verify`).
- **`tamga_offline_proof_generate` always returns `TAMGA_ERR_UNKNOWN`.** It is a
  deliberate non-implementation, not an oversight — see the README's "Known gaps".

### Not applicable to this package

`tamga-c` makes no HTTP requests, so nothing about the wire transport is in scope
here. In particular, the server **does** return HTTP `429`, and the transport SDKs
**do** handle it — parsed and capped `Retry-After`, jittered exponential backoff,
auto-retry scoped to `GET` plus five safe `POST` actions (`validate`,
`validate-key`, `check-in`, `check-out`, `ping`), with creates deliberately
excluded (`tamga-rust`'s `src/client.rs::is_retryable` and
`src/client.rs::send_with_retry`, `src/transport.rs::jitter_millis`). Report
transport-layer issues against the SDK that owns the transport, not against this
package.
