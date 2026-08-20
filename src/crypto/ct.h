/*
 * ct.h -- constant-time helpers.
 *
 * Comparing a computed MAC or signature against an expected one with memcmp
 * leaks, through timing, how many leading bytes matched. That turns a
 * forgery from "guess 2^128 values" into "guess 16 bytes one at a time". Any
 * comparison whose operands are derived from a secret or from a value an
 * attacker is trying to forge goes through tamga_ct_memeq.
 */
#ifndef TAMGA_CRYPTO_CT_H
#define TAMGA_CRYPTO_CT_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Compares `len` bytes without branching on their contents, so execution time
 * depends only on `len`. Returns true when they are equal.
 */
bool tamga_ct_memeq(const void *a, const void *b, size_t len);

#endif /* TAMGA_CRYPTO_CT_H */
