/*
 * license_file.h -- `.lic` parsing and verification.
 *
 * Format:
 *
 *     -----BEGIN LICENSE FILE-----
 *     <base64 of {"enc": "<base64>", "sig": "<base64>", "alg": "<algorithm>"}>
 *     -----END LICENSE FILE-----
 *
 * `alg` is exactly "base64+ed25519+v2" (plain) or "aes-256-gcm+ed25519+v2"
 * (encrypted). Licence-file checkout is Ed25519-only, independent of the
 * licence's own scheme field.
 *
 * ⚠️ Format v2 only, and there is no v1 fallback. In v1 the ttl and expiry a
 * caller asked for lived in the JSON envelope *around* the certificate,
 * outside the signature -- so a 24-hour trial file was cryptographically
 * valid forever, since the client holds the file and can edit anything the
 * signature does not cover. v2 moves the claims inside the signed bytes.
 * Accepting both formats would hand that back, so a file whose alg does not
 * end in "+v2" is refused.
 *
 * ⚠️ The signature covers `enc`'s base64 STRING -- the ASCII bytes of the
 * encoded text itself -- and NOT the bytes that string decodes to. This is
 * the single most common way to get the format wrong, and a verifier that
 * decodes first produces a false negative against every real file.
 */
#ifndef TAMGA_CHECKOUT_LICENSE_FILE_H
#define TAMGA_CHECKOUT_LICENSE_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "checkout/claims.h"
#include "tamga.h"
#include "tamga_compat.h"
#include "util/json.h"

/**
 * Verifies a `.lic` file and yields the embedded licence resource.
 *
 * `license_key` is required only for the encrypted variant. `now_unix` is the
 * current time to check the signed `exp` claim against; a caller holding a
 * server-supplied timestamp should pass that instead of the local clock,
 * which the user controls.
 *
 * On success `*out_resource` owns the decoded licence resource and is
 * released with tamga_json_free().
 */
TAMGA_NODISCARD TamgaErrorCode tamga_license_file_verify_at(const char *pem, size_t pem_len,
                                                            const unsigned char ed25519_pubkey[32],
                                                            const char *license_key,
                                                            int64_t now_unix,
                                                            TamgaJson **out_resource,
                                                            TamgaFileClaims *out_claims);

#endif /* TAMGA_CHECKOUT_LICENSE_FILE_H */
