#include "crypto/rsa.h"

#include <string.h>

#include "crypto/bn.h"
#include "crypto/ct.h"
#include "crypto/der.h"
#include "crypto/sha256.h"
#include "tamga_mem.h"

/* 1.2.840.113549.1.1.1 rsaEncryption */
static const unsigned char TAMGA_OID_RSA_ENCRYPTION[] = {0x2au, 0x86u, 0x48u, 0x86u, 0xf7u,
                                                         0x0du, 0x01u, 0x01u, 0x01u};

/* The fixed DigestInfo prefix for SHA-256: SEQUENCE { SEQUENCE { OID
 * 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING (32) }. Kept as literal bytes
 * because it is a constant, and because building it dynamically would mean
 * writing a DER *encoder* for one value. */
static const unsigned char TAMGA_SHA256_DIGEST_INFO_PREFIX[] = {
    0x30u, 0x31u, 0x30u, 0x0du, 0x06u, 0x09u, 0x60u, 0x86u, 0x48u, 0x01u,
    0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0x04u, 0x20u};

#define TAMGA_RSA_MIN_MODULUS_BYTES 256u  /* 2048 bits */
#define TAMGA_RSA_MAX_MODULUS_BYTES 1024u /* 8192 bits */

typedef struct TamgaRsaPublicKey {
    const unsigned char *modulus;
    size_t modulus_len;
    const unsigned char *exponent;
    size_t exponent_len;
} TamgaRsaPublicKey;

/* Reads SEQUENCE { INTEGER n, INTEGER e } and validates the key parameters. */
static bool tamga_rsa_read_rsa_public_key(const unsigned char *der, size_t der_len,
                                          TamgaRsaPublicKey *key) {
    TamgaDer reader;
    const unsigned char *sequence = NULL;
    size_t sequence_len = 0u;

    tamga_der_init(&reader, der, der_len);
    if (!tamga_der_expect(&reader, TAMGA_DER_SEQUENCE, &sequence, &sequence_len)) {
        return false;
    }
    if (!tamga_der_at_end(&reader)) {
        return false;
    }

    tamga_der_init(&reader, sequence, sequence_len);
    if (!tamga_der_read_unsigned(&reader, &key->modulus, &key->modulus_len)) {
        return false;
    }
    if (!tamga_der_read_unsigned(&reader, &key->exponent, &key->exponent_len)) {
        return false;
    }
    if (!tamga_der_at_end(&reader)) {
        return false;
    }

    if (key->modulus_len < TAMGA_RSA_MIN_MODULUS_BYTES ||
        key->modulus_len > TAMGA_RSA_MAX_MODULUS_BYTES) {
        return false;
    }
    /* The top bit of a normalised RSA modulus is set; tamga_bn_modexp
     * requires it, and a modulus without it is not the size it claims. */
    if ((key->modulus[0] & 0x80u) == 0u) {
        return false;
    }
    /* e = 1 would make the signature equal to the padded block, so anyone
     * could "sign". e must also be odd to be a usable RSA exponent. */
    if (key->exponent_len == 0u || key->exponent_len > 8u) {
        return false;
    }
    if ((key->exponent[key->exponent_len - 1u] & 1u) == 0u) {
        return false;
    }
    if (key->exponent_len == 1u && key->exponent[0] <= 1u) {
        return false;
    }
    return true;
}

/*
 * Extracts (n, e) from either DER encoding an RSA public key comes in.
 *
 * Both are accepted because the fleet uses both. The Tamga server and
 * tamga-rust exchange PKCS#1 RSAPublicKey -- SEQUENCE { INTEGER n,
 * INTEGER e } -- which is what aws-lc-rs's RSA verification API takes,
 * notwithstanding tamga-rust's doc comment describing it as SPKI. Tooling
 * built around OpenSSL hands out SubjectPublicKeyInfo instead. An integrator
 * should not have to know which one they have.
 *
 * The two are unambiguous to tell apart -- SPKI's first inner element is a
 * SEQUENCE (the algorithm identifier), RSAPublicKey's is an INTEGER -- so
 * accepting both adds no leniency about what a given blob means. When it is
 * SPKI, the algorithm OID is checked rather than skipped, so an EC key cannot
 * be fed to the RSA verifier just because its bit string parses.
 */
static bool tamga_rsa_parse_public_key(const unsigned char *der, size_t der_len,
                                       TamgaRsaPublicKey *key) {
    TamgaDer outer;
    TamgaDer inner;
    TamgaDer algorithm;
    const unsigned char *sequence = NULL;
    size_t sequence_len = 0u;
    const unsigned char *algorithm_content = NULL;
    size_t algorithm_len = 0u;
    const unsigned char *bit_string = NULL;
    size_t bit_string_len = 0u;

    if (der == NULL || key == NULL) {
        return false;
    }

    tamga_der_init(&outer, der, der_len);
    if (!tamga_der_expect(&outer, TAMGA_DER_SEQUENCE, &sequence, &sequence_len)) {
        return false;
    }
    if (!tamga_der_at_end(&outer)) {
        return false; /* trailing bytes after the key */
    }

    /* Peek at the first inner element to decide which encoding this is. */
    tamga_der_init(&inner, sequence, sequence_len);
    if (sequence_len > 0u && sequence[0] == (unsigned char)TAMGA_DER_INTEGER) {
        return tamga_rsa_read_rsa_public_key(der, der_len, key);
    }

    if (!tamga_der_expect(&inner, TAMGA_DER_SEQUENCE, &algorithm_content, &algorithm_len)) {
        return false;
    }
    tamga_der_init(&algorithm, algorithm_content, algorithm_len);
    if (!tamga_der_expect_oid(&algorithm, TAMGA_OID_RSA_ENCRYPTION,
                              sizeof(TAMGA_OID_RSA_ENCRYPTION))) {
        return false;
    }
    /* rsaEncryption's parameters field is an explicit NULL. Some encoders
     * omit it; both are accepted here, but nothing else is. */
    if (!tamga_der_at_end(&algorithm)) {
        const unsigned char *params = NULL;
        size_t params_len = 0u;
        if (!tamga_der_expect(&algorithm, TAMGA_DER_NULL, &params, &params_len)) {
            return false;
        }
        if (params_len != 0u || !tamga_der_at_end(&algorithm)) {
            return false;
        }
    }

    if (!tamga_der_read_bit_string(&inner, &bit_string, &bit_string_len)) {
        return false;
    }
    if (!tamga_der_at_end(&inner)) {
        return false;
    }

    return tamga_rsa_read_rsa_public_key(bit_string, bit_string_len, key);
}

/* s^e mod n, with the result left-padded to the modulus width. */
static bool tamga_rsa_public_op(const TamgaRsaPublicKey *key, const unsigned char *signature,
                                size_t signature_len, unsigned char *out) {
    /* RFC 8017: the signature must be exactly the modulus width. A shorter
     * one is not "the same number with leading zeros" as far as this check is
     * concerned -- it is a malformed signature. */
    if (signature_len != key->modulus_len) {
        return false;
    }
    return tamga_bn_modexp(signature, key->modulus, key->modulus_len, key->exponent,
                           key->exponent_len, out);
}

bool tamga_rsa_verify_pkcs1_sha256(const unsigned char *spki, size_t spki_len,
                                   const unsigned char *message, size_t message_len,
                                   const unsigned char *signature, size_t signature_len) {
    TamgaRsaPublicKey key;
    unsigned char recovered[TAMGA_RSA_MAX_MODULUS_BYTES];
    unsigned char expected[TAMGA_RSA_MAX_MODULUS_BYTES];
    unsigned char digest[TAMGA_SHA256_DIGEST_LEN];
    size_t suffix_len;
    size_t padding_len;
    size_t i;
    bool matches;

    if (message == NULL && message_len > 0u) {
        return false;
    }
    if (signature == NULL || !tamga_rsa_parse_public_key(spki, spki_len, &key)) {
        return false;
    }
    if (!tamga_rsa_public_op(&key, signature, signature_len, recovered)) {
        return false;
    }

    tamga_sha256(message, message_len, digest);

    /*
     * Build the block the private key must have signed, then compare the
     * whole thing. RFC 8017 explicitly recommends this over parsing the
     * recovered value: a parser that hunts for the DigestInfo and ignores
     * what surrounds it accepts forgeries that a whole-block comparison
     * rejects.
     */
    suffix_len = sizeof(TAMGA_SHA256_DIGEST_INFO_PREFIX) + sizeof(digest);
    /* 0x00 0x01 <PS> 0x00 <DigestInfo>, with PS at least 8 bytes of 0xFF. */
    if (key.modulus_len < (suffix_len + 11u)) {
        return false;
    }
    padding_len = key.modulus_len - suffix_len - 3u;

    expected[0] = 0x00u;
    expected[1] = 0x01u;
    for (i = 0u; i < padding_len; i++) {
        expected[2u + i] = 0xffu;
    }
    expected[2u + padding_len] = 0x00u;
    memcpy(&expected[3u + padding_len], TAMGA_SHA256_DIGEST_INFO_PREFIX,
           sizeof(TAMGA_SHA256_DIGEST_INFO_PREFIX));
    memcpy(&expected[3u + padding_len + sizeof(TAMGA_SHA256_DIGEST_INFO_PREFIX)], digest,
           sizeof(digest));

    matches = tamga_ct_memeq(recovered, expected, key.modulus_len);

    tamga_secure_zero(recovered, sizeof(recovered));
    tamga_secure_zero(expected, sizeof(expected));
    tamga_secure_zero(digest, sizeof(digest));
    return matches;
}

/* MGF1 with SHA-256, per RFC 8017 appendix B.2.1. */
static void tamga_mgf1_sha256(const unsigned char *seed, size_t seed_len, unsigned char *mask,
                              size_t mask_len) {
    unsigned char counter[4];
    unsigned char block[TAMGA_SHA256_DIGEST_LEN];
    size_t produced = 0u;
    uint32_t index = 0u;

    while (produced < mask_len) {
        TamgaSha256 ctx;
        size_t take = mask_len - produced;

        counter[0] = (unsigned char)(index >> 24);
        counter[1] = (unsigned char)(index >> 16);
        counter[2] = (unsigned char)(index >> 8);
        counter[3] = (unsigned char)index;

        tamga_sha256_init(&ctx);
        tamga_sha256_update(&ctx, seed, seed_len);
        tamga_sha256_update(&ctx, counter, sizeof(counter));
        tamga_sha256_final(&ctx, block);

        if (take > sizeof(block)) {
            take = sizeof(block);
        }
        memcpy(&mask[produced], block, take);
        produced += take;
        index++;
    }
    tamga_secure_zero(block, sizeof(block));
}

bool tamga_rsa_verify_pss_sha256(const unsigned char *spki, size_t spki_len,
                                 const unsigned char *message, size_t message_len,
                                 const unsigned char *signature, size_t signature_len) {
    TamgaRsaPublicKey key;
    unsigned char encoded[TAMGA_RSA_MAX_MODULUS_BYTES];
    unsigned char db_mask[TAMGA_RSA_MAX_MODULUS_BYTES];
    unsigned char digest[TAMGA_SHA256_DIGEST_LEN];
    unsigned char recomputed[TAMGA_SHA256_DIGEST_LEN];
    TamgaSha256 ctx;
    const size_t hash_len = TAMGA_SHA256_DIGEST_LEN;
    const size_t salt_len = TAMGA_SHA256_DIGEST_LEN;
    size_t em_len;
    size_t db_len;
    size_t modulus_bits;
    unsigned int leading_zero_bits;
    const unsigned char *h;
    unsigned char *db;
    size_t i;
    bool matches;
    static const unsigned char zero_prefix[8] = {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u};

    if (message == NULL && message_len > 0u) {
        return false;
    }
    if (signature == NULL || !tamga_rsa_parse_public_key(spki, spki_len, &key)) {
        return false;
    }
    if (!tamga_rsa_public_op(&key, signature, signature_len, encoded)) {
        return false;
    }

    /*
     * emBits = modBits - 1, so when the modulus is a whole number of bytes
     * (every RSA key here) the encoded message is the full modulus width and
     * its top bit must be zero.
     */
    modulus_bits = key.modulus_len * 8u; /* top bit is set, checked at parse time */
    em_len = (modulus_bits - 1u + 7u) / 8u;
    if (em_len != key.modulus_len) {
        return false;
    }
    leading_zero_bits = (unsigned int)((8u * em_len) - (modulus_bits - 1u));

    if (em_len < (hash_len + salt_len + 2u)) {
        return false;
    }
    if (encoded[em_len - 1u] != 0xbcu) {
        return false;
    }
    if ((encoded[0] & (unsigned char)(0xffu << (8u - leading_zero_bits))) != 0u) {
        return false;
    }

    db_len = em_len - hash_len - 1u;
    h = &encoded[db_len];

    tamga_mgf1_sha256(h, hash_len, db_mask, db_len);
    db = encoded; /* unmask in place */
    for (i = 0u; i < db_len; i++) {
        db[i] = (unsigned char)(db[i] ^ db_mask[i]);
    }
    db[0] = (unsigned char)(db[0] & (unsigned char)(0xffu >> leading_zero_bits));

    /* DB must be PS || 0x01 || salt, with PS all zero. */
    for (i = 0u; i < (db_len - salt_len - 1u); i++) {
        if (db[i] != 0u) {
            return false;
        }
    }
    if (db[db_len - salt_len - 1u] != 0x01u) {
        return false;
    }

    tamga_sha256(message, message_len, digest);

    /* H' = SHA-256(0x00 * 8 || mHash || salt) */
    tamga_sha256_init(&ctx);
    tamga_sha256_update(&ctx, zero_prefix, sizeof(zero_prefix));
    tamga_sha256_update(&ctx, digest, hash_len);
    tamga_sha256_update(&ctx, &db[db_len - salt_len], salt_len);
    tamga_sha256_final(&ctx, recomputed);

    matches = tamga_ct_memeq(recomputed, h, hash_len);

    tamga_secure_zero(encoded, sizeof(encoded));
    tamga_secure_zero(db_mask, sizeof(db_mask));
    tamga_secure_zero(digest, sizeof(digest));
    tamga_secure_zero(recomputed, sizeof(recomputed));
    return matches;
}
