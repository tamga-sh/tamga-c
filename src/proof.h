/*
 * proof.h -- machine offline proof verification.
 *
 * A lighter alternative to a full checkout for periodic "this machine is
 * still valid" checks in air-gapped environments. The server returns
 * meta.proof = "v1x0.<base64 signature>", always signed with RSA-2048 PKCS#1
 * v1.5 / SHA-256 regardless of the licence's own scheme.
 *
 * ⚠️ The signed payload's field order is not negotiable, and it is not the
 * order the server's source code writes. The server builds the payload as
 * {account, machine, dataset} through serde_json, whose map is BTreeMap-backed
 * and therefore serialises alphabetically at every nesting level. The bytes on
 * the wire are:
 *
 *     {"account":{"id":...},"dataset":...,"machine":{"fingerprint":...,"id":...}}
 *
 * -- dataset before machine, fingerprint before id. Reproducing the literal
 * source order instead produces a payload that never verifies. This module
 * builds the payload as a value tree and serialises it canonically, so the
 * ordering follows from the same rule the server's serialiser applies rather
 * than from anyone hardcoding a guess.
 */
#ifndef TAMGA_PROOF_H
#define TAMGA_PROOF_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga.h"
#include "tamga_compat.h"

/**
 * Verifies a proof string against the exact tuple it should have been issued
 * for.
 *
 * `rsa_pubkey` is the account's RSA public key as DER, in either accepted
 * encoding (see crypto/rsa.h). `dataset_json` is the
 * client dataset as JSON text; it is re-serialised canonically.
 *
 * A malformed proof string is reported through `*out_valid`, not as a call
 * failure: "this proof does not verify" is the answer the caller asked for,
 * whatever the reason. Only genuine call errors -- a null argument, an
 * unparseable dataset, a broken key -- return a non-OK code.
 */
TAMGA_NODISCARD TamgaErrorCode tamga_proof_verify(const char *proof,
                                                  const unsigned char *rsa_pubkey,
                                                  size_t rsa_pubkey_len, const char *account_id,
                                                  const char *machine_id, const char *fingerprint,
                                                  const char *dataset_json, bool *out_valid);

#endif /* TAMGA_PROOF_H */
