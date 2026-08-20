#include "crypto/ecdsa.h"

#include <string.h>

#include "crypto/der.h"
#include "crypto/p256.h"
#include "crypto/sha256.h"

/* 1.2.840.10045.2.1 id-ecPublicKey */
static const unsigned char TAMGA_OID_EC_PUBLIC_KEY[] = {0x2au, 0x86u, 0x48u, 0xceu,
                                                        0x3du, 0x02u, 0x01u};

/* 1.2.840.10045.3.1.7 prime256v1 (a.k.a. P-256, secp256r1) */
static const unsigned char TAMGA_OID_PRIME256V1[] = {0x2au, 0x86u, 0x48u, 0xceu,
                                                     0x3du, 0x03u, 0x01u, 0x07u};

#define TAMGA_P256_POINT_LEN 65u

/*
 * Extracts the affine coordinates from either accepted key encoding.
 *
 * For the DER form both OIDs are compared: skipping the curve OID is the
 * curve-confusion gap this module's header describes, and it is not enough to
 * check that the point is the right *length* -- a secp256k1 point is also 65
 * bytes.
 */
static bool tamga_ecdsa_extract_point(const unsigned char *public_key, size_t public_key_len,
                                      const unsigned char **x, const unsigned char **y) {
    TamgaDer outer;
    TamgaDer inner;
    TamgaDer algorithm;
    const unsigned char *sequence = NULL;
    size_t sequence_len = 0u;
    const unsigned char *algorithm_content = NULL;
    size_t algorithm_len = 0u;
    const unsigned char *point = NULL;
    size_t point_len = 0u;

    if (public_key == NULL) {
        return false;
    }

    /* Raw uncompressed point. Compressed points (0x02/0x03) are deliberately
     * unsupported: nothing in this protocol emits them, and decompression is
     * code that would never run in production. */
    if (public_key_len == TAMGA_P256_POINT_LEN && public_key[0] == 0x04u) {
        *x = &public_key[1];
        *y = &public_key[33];
        return true;
    }

    tamga_der_init(&outer, public_key, public_key_len);
    if (!tamga_der_expect(&outer, TAMGA_DER_SEQUENCE, &sequence, &sequence_len)) {
        return false;
    }
    if (!tamga_der_at_end(&outer)) {
        return false;
    }

    tamga_der_init(&inner, sequence, sequence_len);
    if (!tamga_der_expect(&inner, TAMGA_DER_SEQUENCE, &algorithm_content, &algorithm_len)) {
        return false;
    }
    tamga_der_init(&algorithm, algorithm_content, algorithm_len);
    if (!tamga_der_expect_oid(&algorithm, TAMGA_OID_EC_PUBLIC_KEY,
                              sizeof(TAMGA_OID_EC_PUBLIC_KEY))) {
        return false;
    }
    if (!tamga_der_expect_oid(&algorithm, TAMGA_OID_PRIME256V1, sizeof(TAMGA_OID_PRIME256V1))) {
        return false;
    }
    if (!tamga_der_at_end(&algorithm)) {
        return false;
    }

    if (!tamga_der_read_bit_string(&inner, &point, &point_len)) {
        return false;
    }
    if (!tamga_der_at_end(&inner)) {
        return false;
    }
    if (point_len != TAMGA_P256_POINT_LEN || point[0] != 0x04u) {
        return false;
    }

    *x = &point[1];
    *y = &point[33];
    return true;
}

/* Copies a DER INTEGER magnitude into a fixed 32-byte big-endian buffer,
 * left-padding with zeros. Rejects anything wider than the curve order. */
static bool tamga_ecdsa_pad_scalar(const unsigned char *value, size_t value_len,
                                   unsigned char out[32]) {
    if (value_len == 0u || value_len > 32u) {
        return false;
    }
    memset(out, 0, 32u);
    memcpy(&out[32u - value_len], value, value_len);
    return true;
}

static bool tamga_ecdsa_parse_signature(const unsigned char *signature, size_t signature_len,
                                        unsigned char r[32], unsigned char s[32]) {
    TamgaDer outer;
    TamgaDer inner;
    const unsigned char *sequence = NULL;
    size_t sequence_len = 0u;
    const unsigned char *r_value = NULL;
    size_t r_len = 0u;
    const unsigned char *s_value = NULL;
    size_t s_len = 0u;

    if (signature == NULL) {
        return false;
    }
    tamga_der_init(&outer, signature, signature_len);
    if (!tamga_der_expect(&outer, TAMGA_DER_SEQUENCE, &sequence, &sequence_len)) {
        return false;
    }
    if (!tamga_der_at_end(&outer)) {
        return false; /* trailing bytes after the signature */
    }

    tamga_der_init(&inner, sequence, sequence_len);
    if (!tamga_der_read_unsigned(&inner, &r_value, &r_len)) {
        return false;
    }
    if (!tamga_der_read_unsigned(&inner, &s_value, &s_len)) {
        return false;
    }
    if (!tamga_der_at_end(&inner)) {
        return false;
    }

    return tamga_ecdsa_pad_scalar(r_value, r_len, r) && tamga_ecdsa_pad_scalar(s_value, s_len, s);
}

bool tamga_ecdsa_p256_verify(const unsigned char *public_key, size_t public_key_len,
                             const unsigned char *message, size_t message_len,
                             const unsigned char *signature, size_t signature_len) {
    const unsigned char *x = NULL;
    const unsigned char *y = NULL;
    unsigned char r[32];
    unsigned char s[32];
    unsigned char digest[TAMGA_SHA256_DIGEST_LEN];

    if (message == NULL && message_len > 0u) {
        return false;
    }
    if (!tamga_ecdsa_extract_point(public_key, public_key_len, &x, &y)) {
        return false;
    }
    if (!tamga_ecdsa_parse_signature(signature, signature_len, r, s)) {
        return false;
    }

    tamga_sha256(message, message_len, digest);
    return tamga_p256_verify(x, y, digest, r, s);
}
