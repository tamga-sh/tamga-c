# Signing-key id vectors

`(public key, kid)` pairs for `tamga_signing_key_id()`, used by
`tests/unit/signing_key_test.c`.

## What a `kid` is

```
kid = lowercase_hex( SHA-256( utf8 bytes of the public-key STRING )[0..8] )
```

Sixteen hex characters, from the first **eight** bytes of the digest. The
server's own `key_id()` (`tamga-api src/shared/crypto/license_file.rs`) takes a
`&str` and digests `.as_bytes()`.

## The trap these exist to pin

**It hashes the base64 STRING, never the 32 bytes that string decodes to.** The
natural assumption is the wrong one, and it is wrong silently: decoding first
produces an equally well-formed sixteen-character id that matches nothing the
server ever issued, so every genuine file reports an unknown signing key and
the bug reads as a rotation problem rather than a hashing one.

`negative` in the JSON is the pair that catches it — the same key yields
`905f28def18eaac0` correctly and `630dcd2966c43366` if decoded first. A test
asserting only the positive does not catch it, because a decode-first
implementation still produces *a* well-formed id for every input.

`unbackfilled_account` is the other one worth knowing: the empty key hashes to
`e3b0c44298fc1c14`, which is what both server checkout handlers stamp into
every file signed by an account whose `ed25519_public_key` column was never
populated (they pass `.unwrap_or_default()`). This SDK reports it as
`TAMGA_ERR_SIGNING_KEY_NOT_PUBLISHED` rather than as a stale key set, because
refetching the key set will never fix it.

## Provenance

**Not generated here.** Produced by an independent SHA-256 implementation and
confirmed against `tamga-rust`'s committed vector `51643eac9777b63a`, then
re-derived once more with a third SHA-256 before being committed. A fixture the
SDK under test produced can only prove that SDK agrees with itself — the same
mistake that hid a two-year machine-file bug in this repository (see
`../server-machine-files/README.md`). Do not regenerate these with this
library.

An earlier revision of the upstream file carried shell command-substitution
output in `_provenance.servedAs` where the word `id` belongs — an unquoted
`$(id)` in the generator, which substituted the generating account's uid, gid
and group list into a string bound for a public repository. That was repaired
upstream; this copy was taken after the repair and re-checked for it. Every
`publicKey` and every `kid` here is byte-identical to upstream, verified by
diff rather than by assertion.

## A second, independent confirmation already in this tree

`tests/fixtures/server-machine-files/manifest.json` was produced by the
**server's** own encoder, and every one of its four `kid` values is
`SHA-256(public_key_b64 string)[0..8]` — none of them matches the decode-first
reading. `signing_key_test.c` asserts that too, so the rule is pinned against
material from two unrelated sources.

⚠️ Those fixture kids are each derived from **their own scheme's** key, which
the live server does not do: both live checkout handlers compute the claim from
the account's Ed25519 key whatever scheme signed the bytes. The fixtures prove
the hash rule; they do not prove which key gets hashed.
