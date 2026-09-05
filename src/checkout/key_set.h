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
 * # Why trying every key is sound, and what the `kid` is for now
 *
 * Every key the set holds is tried against the signature over `enc`'s base64
 * STRING before a byte of `enc` is decoded, so the only bytes that reach a
 * decoder, a cipher or the JSON parser on the success path are bytes a
 * trusted key has already vouched for. The `kid` is read only afterwards, and
 * only when no key verified, to LABEL the failure: a `kid` the set holds means
 * a forgery (TAMGA_ERR_SIGNATURE_INVALID); one it does not hold means a set
 * that has not caught up with a rotation (TAMGA_ERR_UNKNOWN_SIGNING_KEY). The
 * distinction this module exists for survives because the `kid` still decides
 * the label; what changed in 1.3.4 is that a file no longer chooses which key
 * its signature meets. Trying them all is sound because a set can only be
 * built from keys the caller supplies, never from anything the file carries.
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
 * Tries every key the set holds against `signature` over `message`, the
 * base64 STRING bytes of `enc`. True on the first that verifies; the key is
 * copied to `out_public_key` when that is non-NULL. False when none does, or
 * when `signature_len` is not the 64 bytes Ed25519 requires.
 *
 * Runs BEFORE a byte of `enc` is decoded, so on the success path nothing
 * attacker-chosen reaches a decoder, a cipher or the JSON parser.
 */
TAMGA_NODISCARD bool tamga_key_set_find_verifier(const TamgaSigningKeySet *set,
                                                 const unsigned char *message, size_t message_len,
                                                 const unsigned char *signature,
                                                 size_t signature_len,
                                                 unsigned char *out_public_key);

/**
 * Labels a signature no held key verified, from the `kid` the still-unverified
 * `payload` names.
 *
 * `probe_status` is what decoding -- and, for an encrypted file, decrypting --
 * `enc` solely to read the kid returned, and `payload` the parse when that
 * succeeded (NULL otherwise). TAMGA_ERR_OUT_OF_MEMORY and
 * TAMGA_ERR_NULL_ARGUMENT (a missing licence key or fingerprint) propagate
 * untouched: neither is a verdict, and the second is the caller's to fix. Any
 * other failure to read the payload leaves TAMGA_ERR_SIGNATURE_INVALID
 * standing. A readable kid maps through tamga_key_set_select(): held ->
 * TAMGA_ERR_SIGNATURE_INVALID (a forgery), absent -> TAMGA_ERR_SIGNATURE_INVALID
 * (nothing to label it by), otherwise TAMGA_ERR_UNKNOWN_SIGNING_KEY or
 * TAMGA_ERR_SIGNING_KEY_NOT_PUBLISHED. Always leaves the error slot set for
 * the code it returns.
 */
TamgaErrorCode tamga_key_set_label_failure(const TamgaSigningKeySet *set,
                                           TamgaErrorCode probe_status, const TamgaJson *payload);

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
