/*
 * der.h -- the minimal strict DER reader this library needs.
 *
 * Enough to walk a SubjectPublicKeyInfo and an ECDSA signature, and no more.
 * Strict in the sense that matters for a parser reading attacker-supplied
 * key material: definite lengths only, minimal length encodings only, no
 * indefinite form, no trailing content, and every length checked against the
 * remaining buffer before it is used.
 *
 * The OID helpers exist for one specific reason. A public key's declared
 * algorithm and curve are data, and a parser that reads the key material
 * while ignoring the identifiers around it will happily verify an ECDSA
 * signature using whatever curve an attacker names -- a curve-confusion
 * vulnerability that an audit of this SDK family found live in three
 * independent implementations. Callers here compare OIDs explicitly.
 */
#ifndef TAMGA_CRYPTO_DER_H
#define TAMGA_CRYPTO_DER_H

#include <stdbool.h>
#include <stddef.h>

#include "tamga_compat.h"

#define TAMGA_DER_INTEGER 0x02u
#define TAMGA_DER_BIT_STRING 0x03u
#define TAMGA_DER_OCTET_STRING 0x04u
#define TAMGA_DER_NULL 0x05u
#define TAMGA_DER_OID 0x06u
#define TAMGA_DER_SEQUENCE 0x30u

typedef struct TamgaDer {
    const unsigned char *data;
    size_t len;
    size_t pos;
} TamgaDer;

void tamga_der_init(TamgaDer *reader, const unsigned char *data, size_t len);

/** True when every byte of this reader's span has been consumed. */
bool tamga_der_at_end(const TamgaDer *reader);

/**
 * Reads the next TLV. On success `content`/`content_len` describe the value
 * bytes and the reader advances past them.
 */
TAMGA_NODISCARD bool tamga_der_read(TamgaDer *reader, unsigned int *tag,
                                    const unsigned char **content, size_t *content_len);

/** Reads the next TLV and fails unless its tag matches. */
TAMGA_NODISCARD bool tamga_der_expect(TamgaDer *reader, unsigned int tag,
                                      const unsigned char **content, size_t *content_len);

/**
 * Reads an INTEGER and yields its unsigned magnitude, rejecting negative and
 * non-minimally-encoded values. A single leading zero byte -- DER's way of
 * keeping a high-bit-set value positive -- is stripped.
 */
TAMGA_NODISCARD bool tamga_der_read_unsigned(TamgaDer *reader, const unsigned char **value,
                                             size_t *value_len);

/**
 * Reads a BIT STRING and yields its payload, requiring the unused-bits count
 * to be zero (the only form used by the structures this library reads).
 */
TAMGA_NODISCARD bool tamga_der_read_bit_string(TamgaDer *reader, const unsigned char **value,
                                               size_t *value_len);

/** Reads an OID and compares it against an expected encoded value. */
TAMGA_NODISCARD bool tamga_der_expect_oid(TamgaDer *reader, const unsigned char *expected,
                                          size_t expected_len);

#endif /* TAMGA_CRYPTO_DER_H */
