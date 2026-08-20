/*
 * bn.h -- fixed-width modular exponentiation, sized for RSA.
 *
 * Exactly one operation is needed anywhere in this library: s^e mod n, the
 * public-key side of an RSA signature verification. There is no signing, no
 * key generation, no CRT, no inversion -- so this is not a general bignum
 * library and should not grow into one.
 *
 * Nothing here is secret: the signature, the exponent and the modulus are all
 * public values. The implementation is therefore free of constant-time
 * requirements, and says so, because a future signing primitive could not
 * reuse it.
 *
 * Reduction is Montgomery, which avoids implementing general long division
 * entirely -- the Montgomery constant R^2 mod n is built by repeated doubling
 * rather than by dividing.
 */
#ifndef TAMGA_CRYPTO_BN_H
#define TAMGA_CRYPTO_BN_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

/* 8192 bits, matching the widest modulus the reference implementation
 * accepts (aws-lc-rs's RSA_PKCS1_2048_8192_SHA256). */
#define TAMGA_BN_MAX_BYTES 1024u

/**
 * out = base^exponent mod modulus.
 *
 * All three inputs and the output are unsigned big-endian byte strings of
 * exactly `mod_len` bytes (the output is left-padded to that width, as RSA
 * requires). `exponent` is its own big-endian byte string, of any length up
 * to `mod_len`.
 *
 * Returns false if `mod_len` is out of range, the modulus is even or does not
 * have its top bit set (both true of any real RSA modulus and required by the
 * Montgomery setup), or `base` is not less than `modulus`.
 */
TAMGA_NODISCARD bool tamga_bn_modexp(const unsigned char *base,
                                     const unsigned char *modulus, size_t mod_len,
                                     const unsigned char *exponent, size_t exp_len,
                                     unsigned char *out);

#endif /* TAMGA_CRYPTO_BN_H */
