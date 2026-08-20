# Key material and signature fixtures

Public keys and signatures used by the crypto unit tests
(`tests/unit/rsa_test.c`, `tests/unit/ecdsa_test.c`).

Regenerate with `sh generate.sh`. It needs only the `openssl` command line
tool, which is a developer convenience here rather than a dependency of
anything: the library never links OpenSSL, and these files are inputs to
tests, not to the build.

| File | What it is |
|---|---|
| `message.txt` | The message every signature covers — a base64 string, the shape the `.lic` format actually signs |
| `rsa2048.spki.der` | An RSA-2048 public key, SubjectPublicKeyInfo |
| `sig_pkcs1.bin` | RSASSA-PKCS1-v1_5 over `message.txt` |
| `sig_pss.bin` | RSASSA-PSS (MGF1-SHA256, 32-byte salt) over the same |
| `p256.spki.der` | A P-256 public key |
| `sig_ecdsa.bin` | ECDSA P-256 / SHA-256 over the same, ASN.1 DER |
| `secp256k1.spki.der` | A secp256k1 public key, used to build the curve-confusion regression fixture |

`secp256k1.spki.der` exists for one test. `ecdsa_test.c` splices the real
P-256 point into it, producing a structurally valid SubjectPublicKeyInfo that
names the wrong curve while carrying a point that genuinely verifies. A
verifier that reads the point and ignores the curve OID accepts it — which is
the vulnerability class a cross-repo audit found live in three of this SDK
family's implementations.

**No private keys are committed.** `generate.sh` mints fresh key material into
a temporary directory on every run and keeps it only for the few seconds it
takes to sign. A repository that ships a private key, even a throwaway one,
trains both scanners and readers to ignore the thing they should never ignore.
Regenerating produces different keys, which is fine: nothing hardcodes these
bytes, and the tests read whatever is committed.

## `vectors/`

A set rather than a single signature per scheme, because one key and one
message is the weakness NIST's CAVP SigVer files exist to remove: a verifier
can be wrong for a whole class of operand and still verify one signature.

CAVP's own files are not vendored — they are large and their provenance would
need tracking — so `generate.sh` produces the same coverage locally. For ECDSA
it does something CAVP does by curation and this does by construction: it
**bins the signatures by encoded r/s length** and keeps them until every bin
is filled, so the awkward DER encodings are present on purpose rather than by
luck.

| encoded length | what it means |
|---|---|
| 33 bytes | the scalar's top bit is set, so DER carries a leading `0x00` |
| 31 bytes | the scalar is short, so DER stripped a leading zero |
| 32 bytes | the ordinary case |

`manifest.txt` records which vector is which, and `count=` bounds the test
loop.

This is not decoration. A verifier written on the assumption that r and s are
always exactly 32 bytes — a common and entirely reasonable-looking mistake —
verifies every other fixture in this repository, both integration suites, and
the cross-SDK files, and is caught only by the first short-integer vector.
