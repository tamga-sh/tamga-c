/*
 * key_set.h -- the trusted Ed25519 signing keys an offline file is allowed to
 * have been signed by, indexed by the `kid` its claims name.
 *
 * # What this closes
 *
 * Verifying against one embedded public key collapses two unrelated outcomes
 * into one error. A file checked out last month, before the account rotated
 * its signing key, is authentic and its licence may well still be valid -- but
 * against the current key it fails with precisely the error a forgery
 * produces, and the caller cannot tell "my key set is stale" from "this file
 * was tampered with". The first calls for refetching the key set or shipping
 * an update; the second calls for refusing the customer. Getting them the
 * wrong way round locks a paying customer out and sends support to the wrong
 * place.
 *
 * # Why reading the `kid` before verifying is sound
 *
 * The `kid` lives INSIDE the signed payload and is read BEFORE the signature
 * is checked, which is only safe under one rule: it SELECTS from keys the
 * caller already trusts, and can never SUPPLY one. A file naming a `kid` the
 * set does not hold is refused; a file naming one it does hold is verified
 * against exactly that key and nothing else. There is deliberately no
 * "try every key" fallback -- trying them all would accept the same set of
 * files while destroying the distinction this module exists to draw.
 *
 * # Ed25519 only
 *
 * Every key the server publishes is Ed25519: rotation is `rotate_ed25519`,
 * which inserts a literal `'ed25519'` and is the only writer. Licence files
 * are Ed25519-signed regardless of the licence's own `scheme`, so they are
 * always in scope. A machine file signed under an RSA or ECDSA scheme is not,
 * and the reason is subtle enough to be worth stating: a machine file's
 * signing key is chosen by the licence's scheme, but its `kid` is computed
 * from `account.ed25519_public_key` WHATEVER the scheme, so the claim names a
 * key that had no part in the signature. Those files are refused here with
 * TAMGA_ERR_KEY_ID_NOT_APPLICABLE and must go through
 * tamga_machine_file_verify() with the account's own key for that algorithm.
 * Nothing is lost by it -- only the Ed25519 key is ever rotated, so no other
 * scheme has a rotation to survive.
 */
#ifndef TAMGA_CHECKOUT_KEY_SET_H
#define TAMGA_CHECKOUT_KEY_SET_H

#include <stdbool.h>
#include <stddef.h>

#include "crypto/ed25519.h"
#include "tamga.h"
#include "tamga_compat.h"
#include "util/json.h"

/**
 * Computes the `kid` a file signed under `public_key` claims: the first eight
 * bytes of SHA-256 over the key, as TAMGA_KEY_ID_LENGTH lowercase hex
 * characters plus a NUL.
 *
 * ⚠️ The digest covers the base64 STRING's own bytes, never the 32 bytes it
 * decodes to. The server's `key_id()` takes a `&str` and calls `.as_bytes()`
 * on it, and getting this backwards is silent: decoding first yields an
 * equally well-formed sixteen-character id that matches nothing the server
 * ever issued, so every genuine file reports an unknown signing key.
 *
 * Nothing about `public_key` is validated -- it is hashed as given. An empty
 * key is a meaningful input (TAMGA_UNPUBLISHED_KEY_ID), so rejecting it would
 * put the one value a caller most needs to recognise out of reach.
 */
void tamga_signing_key_id_compute(const char *public_key, size_t public_key_len, char *out_key_id);

/** Allocates an empty set. */
TAMGA_NODISCARD TamgaErrorCode tamga_key_set_create(TamgaSigningKeySet **out_set);

/** Releases a set and every key id in it. NULL-safe. */
void tamga_key_set_destroy(TamgaSigningKeySet *set);

/**
 * Adds one key the caller holds itself, standard base64 of the raw 32 bytes,
 * indexed by the `kid` computed from it.
 *
 * Strict on purpose: a key that is not base64 of exactly 32 bytes is an error
 * rather than a skipped entry. A typo in a key pinned in an application binary
 * has to fail loudly at startup, not quietly produce a set that reports every
 * genuine file in the field as signed by an unknown key.
 */
TAMGA_NODISCARD TamgaErrorCode tamga_key_set_add_public_key(TamgaSigningKeySet *set,
                                                            const char *public_key);

/**
 * Adds every usable key in a `GET /signing-keys` document.
 *
 * Lenient where tamga_key_set_add_public_key() is strict, and for the opposite
 * reason: this input is the server's whole key history, and one unusable row
 * -- a future non-Ed25519 algorithm, a legacy key that does not decode -- must
 * not strand every file the account has already signed. Such rows are counted
 * in `*out_skipped` rather than failing the call.
 *
 * The `kid` is taken from the resource `id`, which IS the `kid`: the server
 * sets it from the same value it writes into the file's claim, so nothing is
 * hashed to index this path. The local computation still runs, purely as a
 * cross-check, and a row whose two disagree is counted in `*out_mismatched`
 * -- and is still added under the served id, because the served id is what an
 * offline file actually names. Dropping it would strand exactly the files it
 * is needed for.
 *
 * Atomic: on any non-TAMGA_OK return the set is exactly as it was, and none
 * of the three counters is written. A half-merged key set is worse than an
 * unmerged one -- it verifies some files and reports the rest as forged.
 *
 * Every counter is optional.
 */
TAMGA_NODISCARD TamgaErrorCode tamga_key_set_add_json(TamgaSigningKeySet *set, const char *json,
                                                      size_t json_len, size_t *out_added,
                                                      size_t *out_skipped, size_t *out_mismatched);

/**
 * The raw 32-byte key held under `key_id`, if any. `out_public_key` is
 * optional and is written only on a hit.
 *
 * Matching is exact and case-sensitive, and the id's shape is deliberately not
 * validated: it is an opaque server-issued label that indexes a set of keys
 * the caller already trusts, so imposing a format here would buy nothing and
 * would refuse a server that ever widened it.
 */
TAMGA_NODISCARD bool tamga_key_set_lookup(const TamgaSigningKeySet *set, const char *key_id,
                                          unsigned char *out_public_key);

/** How many usable keys the set holds. */
size_t tamga_key_set_count(const TamgaSigningKeySet *set);

/**
 * Selects the key a file's `kid` names, mapping every way that can fail onto
 * the code that describes it: TAMGA_ERR_UNKNOWN_SIGNING_KEY for a stale set,
 * TAMGA_ERR_SIGNING_KEY_NOT_PUBLISHED for the one id no set can ever hold, and
 * TAMGA_ERR_INVALID_JSON for a payload carrying no `kid` at all.
 *
 * `out_public_key` receives 32 bytes, and only on TAMGA_OK.
 */
TAMGA_NODISCARD TamgaErrorCode tamga_key_set_select(const TamgaSigningKeySet *set,
                                                    const char *key_id,
                                                    unsigned char *out_public_key);

/**
 * The `kid` a signed payload's `meta` names, borrowed from the tree and valid
 * only while it lives, or NULL when there is none.
 *
 * Borrowed rather than copied into TamgaFileClaims on purpose: the claims
 * struct is a plain value a caller receives by copy and never frees, and an
 * owned pointer in it would be an ownership rule nobody could see.
 */
const char *tamga_claims_key_id(const TamgaJson *meta);

#endif /* TAMGA_CHECKOUT_KEY_SET_H */
