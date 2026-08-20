# Security

## Reporting a vulnerability

Report privately through [GitHub Security
Advisories](https://github.com/tamga-sh/tamga-c/security/advisories/new).
Please do not open a public issue for a suspected vulnerability.

Include what you have: the affected version, what an attacker gains, and a
reproduction if you have one. If you are unsure whether something qualifies,
report it anyway — a false positive costs a few minutes, and the alternative
costs more.

---

## The threat model this library is built for

In licence enforcement **the client is the adversary**. The software runs on a
machine the attacker controls, holding data they can read, with a clock they
can set. That shapes several decisions that would be wrong in another context:

- **The system clock is not trusted for expiry.** A licence file's expiry is
  checked with sixty seconds of skew tolerance and no more, because a generous
  allowance is simply a free extension on every expired file. Callers that can
  keep a server-supplied timestamp should verify against that instead.
- **AES-GCM's S-box lookup is not a meaningful side channel here.** The key is
  derived from the licence key, which the caller already holds and is entitled
  to. An adversary who has the key learns nothing by timing its use. This
  reasoning is written into `src/crypto/aes.h`, and it would not hold if that
  key were ever a server-side secret.
- **GHASH is a different case, and is treated differently.** It is
  implemented bit by bit rather than through a precomputed table, because a
  table-driven GHASH indexes memory with data derived from the ciphertext and
  the hash subkey.
- **Signature verification has no secrets at all.** Every input — signature,
  message, public key — is public, so the Ed25519, RSA and P-256 code carries
  no constant-time obligation and says so in its own headers. A signing
  primitive could not reuse any of it, which is one reason there is no signing
  primitive.

## Why the cryptography is implemented here

Every primitive this library uses is implemented in this repository. That is a
deliberate choice with a real cost, made for a specific reason: **Ed25519
exists in neither Windows CNG nor Apple's Security framework.** Any build
would need an in-repo implementation regardless, and a platform-backed build
would then have three code paths — one per operating system — instead of one,
each with its own behaviour and its own bugs.

The mitigation for reimplementation risk is the discipline this SDK family
adopted after a cross-repo audit found the *same* ECDSA curve-confusion
vulnerability independently present in three of its from-scratch
implementations:

- **Every primitive is pinned to the published vectors for its
  specification** — FIPS 180-4, RFC 2104, RFC 4231, RFC 5869, RFC 8032, NIST
  SP 800-38D, NIST CAVP — including the boundary cases short vectors miss.
- **Every protocol gotcha has a negative test**, not just a positive one. A
  signature over the decoded bytes instead of the base64 string must *fail*; a
  key declaring the wrong curve must be *rejected*; a non-canonical scalar must
  be *refused*.
- **Interoperability is verified against another implementation.** The offline
  fixtures in `tests/fixtures/offline/` were produced independently and run
  through `tamga-rust`'s verifier before being committed. A test that passes
  only against material this code also generated proves self-consistency, not
  interoperability.
- **Every parser that reads untrusted bytes is fuzzed** under ASan and UBSan:
  PEM, base64, JSON, DER, and both offline file formats end to end.

## Guarantees the code keeps

- **TLS verification cannot be disabled.** Neither built-in transport exposes
  an option to relax certificate or hostname checking, and neither follows
  redirects — every request address is built by this library from a configured
  host, so a redirect could only come from someone already controlling the
  response, and following one would replay the `Authorization` header wherever
  they pointed.
- **No secret appears in a diagnostic.** No error message contains a licence
  key, token or password. Callers log these.
- **Key material is erased, not just released.** Derived keys, decrypted
  payloads and response bodies go through an erase that the optimiser is not
  permitted to remove.
- **Authenticated decryption verifies before it returns.** AES-GCM's tag is
  checked in constant time, and the decrypted buffer is erased on failure —
  CTR mode necessarily writes plaintext before the tag can be checked, so
  erasing is what makes the contract true from outside.
- **Every caller-supplied length is bounds- and overflow-checked** before use,
  with a 16 MiB cap on any single input. The banned C string functions
  (`strcpy`, `strcat`, `sprintf`, `atoi`) appear nowhere in `src/`.

## Review policy

Changes to `src/crypto/`, `src/checkout/`, `src/proof.c` or `src/http/`
require an adversarial security review before merge, one area at a time. Do
not batch several crypto areas into one review — each covers materially
different primitives, and a reviewer's attention does not divide.

## What this library does not do

- **It does not sign anything.** There is no signing primitive and no private
  key handling. `tamga_offline_proof_generate()` is a documented
  non-implementation; proofs are issued by the server.
- **It cannot stop a determined attacker from patching your binary.** No
  client-side licensing library can. What it can do is make forging a
  server-issued artefact require the server's private key, and that property
  is what the tests above defend.

## Supported versions

The latest minor release receives security fixes. Given the ABI compatibility
between 1.2.x and 1.3, upgrading is a rebuild rather than a port.
