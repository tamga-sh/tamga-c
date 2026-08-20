/*
 * ECDSA P-256 verification tests.
 *
 * The fixtures are OpenSSL-produced (tests/fixtures/keys/generate.sh), so
 * every positive case verifies material this implementation did not create.
 *
 * The case that matters most is the last one: an attacker-supplied key that
 * declares the wrong curve while carrying a point of exactly the right shape.
 * A cross-repo audit of this SDK family found that gap live in three
 * independent implementations, so it gets an explicit regression test rather
 * than trust in the parser.
 */
#include "tamga_test.h"

#include "crypto/ecdsa.h"

#define BUF_CAP 256

typedef struct EcFixtures {
    unsigned char p256_spki[BUF_CAP];
    size_t p256_spki_len;
    unsigned char k256_spki[BUF_CAP];
    size_t k256_spki_len;
    unsigned char message[BUF_CAP];
    size_t message_len;
    unsigned char signature[BUF_CAP];
    size_t signature_len;
} EcFixtures;

static bool load(EcFixtures *f)
{
    f->p256_spki_len = tt_read_fixture("keys/p256.spki.der", f->p256_spki,
                                       sizeof(f->p256_spki));
    f->k256_spki_len = tt_read_fixture("keys/secp256k1.spki.der", f->k256_spki,
                                       sizeof(f->k256_spki));
    f->message_len = tt_read_fixture("keys/message.txt", f->message, sizeof(f->message));
    f->signature_len = tt_read_fixture("keys/sig_ecdsa.bin", f->signature,
                                       sizeof(f->signature));
    return f->p256_spki_len != (size_t)-1 && f->k256_spki_len != (size_t)-1 &&
           f->message_len != (size_t)-1 && f->signature_len != (size_t)-1;
}

/* Both EC SubjectPublicKeyInfo encodings end with the 65-byte uncompressed
 * point, so this is where the key material lives in either fixture. */
static const unsigned char *point_of(const unsigned char *spki, size_t len)
{
    return &spki[len - 65u];
}

TT_TEST(accepts_a_real_signature_via_spki)
{
    EcFixtures f;
    TT_ASSERT(load(&f));
    TT_ASSERT(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message, f.message_len,
                                      f.signature, f.signature_len));
}

/* The machine-file format supplies the key as a bare uncompressed point, not
 * as SPKI, so that path needs its own coverage. */
TT_TEST(accepts_a_real_signature_via_a_raw_point)
{
    EcFixtures f;
    TT_ASSERT(load(&f));
    TT_ASSERT(tamga_ecdsa_p256_verify(point_of(f.p256_spki, f.p256_spki_len), 65u,
                                      f.message, f.message_len,
                                      f.signature, f.signature_len));
}

TT_TEST(rejects_a_tampered_message)
{
    EcFixtures f;
    TT_ASSERT(load(&f));
    f.message[0] ^= 0x01u;
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, f.signature, f.signature_len));
}

TT_TEST(rejects_a_tampered_signature)
{
    EcFixtures f;
    TT_ASSERT(load(&f));
    /* The last byte is inside s. */
    f.signature[f.signature_len - 1u] ^= 0x01u;
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, f.signature, f.signature_len));
}

TT_TEST(rejects_a_wrong_public_key)
{
    EcFixtures f;
    unsigned char altered[BUF_CAP];

    TT_ASSERT(load(&f));
    memcpy(altered, f.p256_spki, f.p256_spki_len);
    /* Perturbing the point almost certainly moves it off the curve, which is
     * itself a rejection path worth exercising. */
    altered[f.p256_spki_len - 1u] ^= 0x01u;
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(altered, f.p256_spki_len, f.message,
                                            f.message_len, f.signature, f.signature_len));
}

/* The signature is ASN.1 DER, not a fixed-width r||s pair. Accepting the raw
 * form would mean accepting two encodings for one signature. */
TT_TEST(rejects_a_raw_concatenated_signature)
{
    EcFixtures f;
    unsigned char raw[64];

    TT_ASSERT(load(&f));
    memset(raw, 0x11, sizeof(raw));
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, raw, sizeof(raw)));
}

TT_TEST(rejects_malformed_signature_encodings)
{
    EcFixtures f;
    unsigned char altered[BUF_CAP];

    TT_ASSERT(load(&f));

    /* trailing byte after a complete SEQUENCE */
    memcpy(altered, f.signature, f.signature_len);
    altered[f.signature_len] = 0x00u;
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, altered, f.signature_len + 1u));

    /* truncated */
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, f.signature,
                                            f.signature_len - 1u));

    /* wrong outer tag */
    memcpy(altered, f.signature, f.signature_len);
    altered[0] = 0x31u;
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, altered, f.signature_len));

    /* empty */
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, f.signature, 0u));
}

/* r and s must lie in [1, n-1]. A verifier that skips the range check accepts
 * signatures nobody's private key produced. */
TT_TEST(rejects_out_of_range_scalars)
{
    EcFixtures f;
    /* SEQUENCE { INTEGER 0, INTEGER 1 } */
    static const unsigned char zero_r[] = {0x30u, 0x06u, 0x02u, 0x01u, 0x00u,
                                           0x02u, 0x01u, 0x01u};
    /* SEQUENCE { INTEGER 1, INTEGER 0 } */
    static const unsigned char zero_s[] = {0x30u, 0x06u, 0x02u, 0x01u, 0x01u,
                                           0x02u, 0x01u, 0x00u};
    /* SEQUENCE { INTEGER n, INTEGER 1 } -- exactly the group order */
    static const unsigned char r_equals_n[] = {
        0x30u, 0x28u,
        0x02u, 0x21u, 0x00u,
        0xffu, 0xffu, 0xffu, 0xffu, 0x00u, 0x00u, 0x00u, 0x00u,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0xbcu, 0xe6u, 0xfau, 0xadu, 0xa7u, 0x17u, 0x9eu, 0x84u,
        0xf3u, 0xb9u, 0xcau, 0xc2u, 0xfcu, 0x63u, 0x25u, 0x51u,
        0x02u, 0x01u, 0x01u
    };

    TT_ASSERT(load(&f));
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, zero_r, sizeof(zero_r)));
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, zero_s, sizeof(zero_s)));
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message,
                                            f.message_len, r_equals_n, sizeof(r_equals_n)));
}

/*
 * THE curve-confusion regression test.
 *
 * The fixture is a structurally valid secp256k1 SubjectPublicKeyInfo -- right
 * shape, right tags, secp256k1 curve OID -- with its 65-byte uncompressed
 * point replaced by the real P-256 public key. A secp256k1 point is also 65
 * bytes, so nothing about the encoding looks wrong.
 *
 * A verifier that reads the point and ignores the OID accepts this and
 * verifies successfully, because the point and the signature genuinely match.
 * That is exactly the vulnerability: the key's declared curve is
 * attacker-controlled, so an implementation that honours the declaration
 * instead of pinning the curve can be steered onto a weaker one. It must be
 * rejected even though the underlying arithmetic would have succeeded.
 */
TT_TEST(rejects_a_key_declaring_the_wrong_curve)
{
    EcFixtures f;
    unsigned char confused[BUF_CAP];

    TT_ASSERT(load(&f));

    memcpy(confused, f.k256_spki, f.k256_spki_len);
    memcpy(&confused[f.k256_spki_len - 65u], point_of(f.p256_spki, f.p256_spki_len), 65u);

    /* The same point, presented honestly, verifies. */
    TT_ASSERT(tamga_ecdsa_p256_verify(f.p256_spki, f.p256_spki_len, f.message, f.message_len,
                                      f.signature, f.signature_len));

    /* And the point inside the forged blob is genuinely a working P-256 key:
     * fed in directly, with no curve claim attached, it verifies. This is
     * what makes the assertion below meaningful -- the rejection has to come
     * from the OID check, not from the point being malformed or the DER
     * failing to parse. Without this line the test would still pass if the
     * splice had simply produced garbage. */
    TT_ASSERT(tamga_ecdsa_p256_verify(&confused[f.k256_spki_len - 65u], 65u, f.message,
                                      f.message_len, f.signature, f.signature_len));

    /* Presented under a false curve OID, it must not. */
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(confused, f.k256_spki_len, f.message,
                                            f.message_len, f.signature, f.signature_len));
}

TT_TEST(rejects_malformed_key_encodings)
{
    EcFixtures f;
    unsigned char raw[65];

    TT_ASSERT(load(&f));

    /* A compressed point is a legal EC encoding but is deliberately
     * unsupported here -- nothing in this protocol emits one. */
    memcpy(raw, point_of(f.p256_spki, f.p256_spki_len), sizeof(raw));
    raw[0] = 0x02u;
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(raw, sizeof(raw), f.message, f.message_len,
                                            f.signature, f.signature_len));

    /* Right length, wrong leading byte. */
    memcpy(raw, point_of(f.p256_spki, f.p256_spki_len), sizeof(raw));
    raw[0] = 0x00u;
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(raw, sizeof(raw), f.message, f.message_len,
                                            f.signature, f.signature_len));

    /* Truncated point. */
    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(point_of(f.p256_spki, f.p256_spki_len), 64u,
                                            f.message, f.message_len,
                                            f.signature, f.signature_len));

    TT_ASSERT_FALSE(tamga_ecdsa_p256_verify(NULL, 65u, f.message, f.message_len,
                                            f.signature, f.signature_len));
}

int main(void)
{
    TT_RUN(accepts_a_real_signature_via_spki);
    TT_RUN(accepts_a_real_signature_via_a_raw_point);
    TT_RUN(rejects_a_tampered_message);
    TT_RUN(rejects_a_tampered_signature);
    TT_RUN(rejects_a_wrong_public_key);
    TT_RUN(rejects_a_raw_concatenated_signature);
    TT_RUN(rejects_malformed_signature_encodings);
    TT_RUN(rejects_out_of_range_scalars);
    TT_RUN(rejects_a_key_declaring_the_wrong_curve);
    TT_RUN(rejects_malformed_key_encodings);
    return TT_SUMMARY();
}
