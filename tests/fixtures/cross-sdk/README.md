# Cross-SDK conformance fixtures

Offline files and key material produced by **`tamga-go`** — a third
implementation, written independently of both this SDK and `tamga-rust`, from
the same protocol specification. Nothing in this repository generated any of
it; the files were copied verbatim from `tamga-go/testdata/`, with the
base64-wrapped keys unwrapped into raw bytes so the C tests can read them
without a JSON parser.

`tests/integration/cross_sdk_test.c` verifies them.

## Why a second source of fixtures

`tests/fixtures/offline/` proves agreement with `tamga-rust`, the reference
implementation. These prove that three implementations which never shared code
agree on the same bytes. A format detail all three got wrong the same way
would still slip through — but a detail any one of them got wrong differently
shows up here, which is exactly what happened with RSA-PSS below.

## Parameters

Licence key `lic-abc123`, fingerprint `fp-abc123`. The offline proof's tuple is
in `proof_params.txt` (account id, machine id, fingerprint, one per line).

| File | What it is |
|---|---|
| `license_file_plain.lic` | `base64+ed25519+v2` |
| `license_file_encrypted.lic` | `aes-256-gcm+ed25519+v2` |
| `machine_file_ed25519.machine` | `base64+ed25519` |
| `machine_file_rsa_pkcs1.machine` | `base64+rsa-sha256` |
| `machine_file_rsa_pss.machine` | `base64+rsa-pss-sha256` — see the divergence below |
| `machine_file_ecdsa.machine` | `aes-256-gcm+ecdsa-p256` (the encrypted variant) |
| `ed25519_pubkey.bin` | 32 raw bytes |
| `rsa_pkcs1_pubkey.der`, `rsa_pss_pubkey.der` | SubjectPublicKeyInfo |
| `ecdsa_point.bin` | 65-byte uncompressed point |
| `proof.txt`, `proof_dataset.json`, `proof_rsa_pubkey.der`, `proof_params.txt` | An offline proof and everything needed to check it |
| `proof_payload.json` | The exact canonical bytes `tamga-go` signed |

`proof_payload.json` earns its place: comparing our rebuilt payload against it
character by character localises a canonical-JSON divergence to the
serializer, instead of leaving it as "the signature did not verify" — which
could equally be the hash or the RSA arithmetic.

## The RSA-PSS divergence

`machine_file_rsa_pss.machine` is signed with a **222-byte salt**. Go's
`rsa.SignPSS` with `nil` options means `PSSSaltLengthAuto`, which on the
signing side makes the salt as large as the modulus allows; Go verifies with
`PSSSaltLengthAuto` too, so it accepts its own fixture.

The reference implementation does not. Checked directly: `tamga-rust`, through
`aws-lc-rs`'s `RSA_PSS_2048_8192_SHA256`, **rejects** this exact file, and
accepts a 32-byte-salt signature over the same message. Salt length equal to
the digest length is therefore the fleet's convention, and this SDK matching
the reference is correct while being stricter than `tamga-go`'s verifier.

The test asserts the rejection rather than skipping the file. "We skipped that
one" loses the finding; and if a future change made this file verify, this SDK
would be accepting signatures the reference rejects — a divergence worth
failing a test over, whichever direction it runs in.

## Regenerating

Don't. These are a snapshot of another repository's committed test data, and
their value is that this repository did not produce them. If `tamga-go`'s
fixtures change, copy the new ones across deliberately and re-check what the
reference implementation makes of them.
