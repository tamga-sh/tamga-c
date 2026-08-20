/*
 * fe25519.h -- arithmetic in the field GF(2^255 - 19), for Ed25519.
 *
 * Representation: eight 32-bit little-endian limbs, kept fully reduced into
 * [0, p) after every operation. That is slower than the packed 2^51 or
 * 2^25.5 radix representations used by performance-oriented libraries, and
 * it is chosen deliberately:
 *
 *   - it needs nothing wider than uint64_t, so it compiles identically under
 *     MSVC, which has no __int128;
 *   - each operation is a plain schoolbook algorithm whose correctness can be
 *     read off the code, rather than a carry-chain argument that has to be
 *     re-derived to review;
 *   - nothing here is secret. This field is used only for signature
 *     *verification*, whose inputs -- signature, message, public key -- are
 *     all public, so the constant-time discipline that motivates the packed
 *     representations does not apply. Verification takes a few hundred
 *     microseconds either way.
 *
 * If a signing primitive is ever added, this file is not suitable for it
 * without a constant-time review: several routines below branch on their
 * operands.
 */
#ifndef TAMGA_CRYPTO_FE25519_H
#define TAMGA_CRYPTO_FE25519_H

#include <stdbool.h>
#include <stdint.h>

typedef struct TamgaFe {
    uint32_t v[8];
} TamgaFe;

void tamga_fe_zero(TamgaFe *r);
void tamga_fe_one(TamgaFe *r);
void tamga_fe_copy(TamgaFe *r, const TamgaFe *a);

void tamga_fe_add(TamgaFe *r, const TamgaFe *a, const TamgaFe *b);
void tamga_fe_sub(TamgaFe *r, const TamgaFe *a, const TamgaFe *b);
void tamga_fe_neg(TamgaFe *r, const TamgaFe *a);
void tamga_fe_mul(TamgaFe *r, const TamgaFe *a, const TamgaFe *b);
void tamga_fe_sq(TamgaFe *r, const TamgaFe *a);

/** r = a^(p-2) = a^-1. Zero maps to zero, matching the usual convention. */
void tamga_fe_invert(TamgaFe *r, const TamgaFe *a);
/** r = a^((p-5)/8), the exponent Ed25519's square-root recovery needs. */
void tamga_fe_pow_p58(TamgaFe *r, const TamgaFe *a);

bool tamga_fe_is_zero(const TamgaFe *a);
bool tamga_fe_equal(const TamgaFe *a, const TamgaFe *b);
/** The canonical encoding's sign bit: the least significant bit of the
 *  fully-reduced value. */
bool tamga_fe_is_negative(const TamgaFe *a);

/** Little-endian 32-byte canonical encoding. */
void tamga_fe_to_bytes(const TamgaFe *a, unsigned char out[32]);
/** Little-endian 32-byte decode. The top bit is ignored (callers that care
 *  about it, such as point decompression, extract it first), and the value is
 *  reduced, so a non-canonical encoding is accepted and normalised. */
void tamga_fe_from_bytes(TamgaFe *r, const unsigned char in[32]);

/** The curve constant d = -121665/121666. */
void tamga_fe_d(TamgaFe *r);
/** sqrt(-1) = 2^((p-1)/4), used when the first square-root candidate is
 *  wrong by a factor of i. */
void tamga_fe_sqrtm1(TamgaFe *r);

#endif /* TAMGA_CRYPTO_FE25519_H */
