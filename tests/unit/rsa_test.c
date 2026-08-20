/*
 * RSA verification tests, against committed fixtures.
 *
 * tests/fixtures/keys/ holds a real RSA-2048 key and two signatures over the
 * same message, produced by OpenSSL and independently confirmed to verify
 * under aws-lc-rs -- the verifier tamga-rust uses. Testing against material
 * this implementation did not itself produce is the point: a round-trip
 * against our own signer would pass even if both halves shared a mistake.
 *
 * Regenerate with tests/fixtures/keys/generate.sh.
 */
#include "tamga_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/der.h"
#include "crypto/rsa.h"

#define SPKI_CAP 512
#define SIG_CAP 512
#define MSG_CAP 128

typedef struct Fixtures {
    unsigned char spki[SPKI_CAP];
    size_t spki_len;
    unsigned char message[MSG_CAP];
    size_t message_len;
    unsigned char pkcs1[SIG_CAP];
    size_t pkcs1_len;
    unsigned char pss[SIG_CAP];
    size_t pss_len;
} Fixtures;

static bool load(Fixtures *f) {
    f->spki_len = tt_read_fixture("keys/rsa2048.spki.der", f->spki, sizeof(f->spki));
    f->message_len = tt_read_fixture("keys/message.txt", f->message, sizeof(f->message));
    f->pkcs1_len = tt_read_fixture("keys/sig_pkcs1.bin", f->pkcs1, sizeof(f->pkcs1));
    f->pss_len = tt_read_fixture("keys/sig_pss.bin", f->pss, sizeof(f->pss));
    return f->spki_len != (size_t)-1 && f->message_len != (size_t)-1 &&
           f->pkcs1_len != (size_t)-1 && f->pss_len != (size_t)-1;
}

TT_TEST(accepts_a_real_pkcs1_signature) {
    Fixtures f;
    TT_ASSERT(load(&f));
    TT_ASSERT_EQ_SIZE(f.pkcs1_len, 256u);
    TT_ASSERT(tamga_rsa_verify_pkcs1_sha256(f.spki, f.spki_len, f.message, f.message_len, f.pkcs1,
                                            f.pkcs1_len));
}

TT_TEST(accepts_a_real_pss_signature) {
    Fixtures f;
    TT_ASSERT(load(&f));
    TT_ASSERT_EQ_SIZE(f.pss_len, 256u);
    TT_ASSERT(tamga_rsa_verify_pss_sha256(f.spki, f.spki_len, f.message, f.message_len, f.pss,
                                          f.pss_len));
}

/* The two padding schemes are not interchangeable, and a verifier that
 * accepts either for the same key would let an attacker pick whichever is
 * easier to forge against. */
TT_TEST(the_two_padding_schemes_do_not_cross_verify) {
    Fixtures f;
    TT_ASSERT(load(&f));
    TT_ASSERT_FALSE(tamga_rsa_verify_pss_sha256(f.spki, f.spki_len, f.message, f.message_len,
                                                f.pkcs1, f.pkcs1_len));
    TT_ASSERT_FALSE(tamga_rsa_verify_pkcs1_sha256(f.spki, f.spki_len, f.message, f.message_len,
                                                  f.pss, f.pss_len));
}

TT_TEST(rejects_a_tampered_message) {
    Fixtures f;
    TT_ASSERT(load(&f));
    f.message[0] ^= 0x01u;
    TT_ASSERT_FALSE(tamga_rsa_verify_pkcs1_sha256(f.spki, f.spki_len, f.message, f.message_len,
                                                  f.pkcs1, f.pkcs1_len));
    TT_ASSERT_FALSE(tamga_rsa_verify_pss_sha256(f.spki, f.spki_len, f.message, f.message_len, f.pss,
                                                f.pss_len));
}

TT_TEST(rejects_a_tampered_signature) {
    Fixtures f;
    size_t positions[3];
    size_t i;

    TT_ASSERT(load(&f));
    positions[0] = 0u;
    positions[1] = 128u;
    positions[2] = 255u;

    for (i = 0u; i < 3u; i++) {
        Fixtures local;
        TT_ASSERT(load(&local));
        local.pkcs1[positions[i]] ^= 0x01u;
        TT_ASSERT_FALSE(tamga_rsa_verify_pkcs1_sha256(local.spki, local.spki_len, local.message,
                                                      local.message_len, local.pkcs1,
                                                      local.pkcs1_len));
        local.pss[positions[i]] ^= 0x01u;
        TT_ASSERT_FALSE(tamga_rsa_verify_pss_sha256(local.spki, local.spki_len, local.message,
                                                    local.message_len, local.pss, local.pss_len));
    }
}

/* RFC 8017 requires the signature to be exactly the modulus width. Accepting
 * a shorter one -- "the same number with the leading zeros trimmed" -- would
 * make the encoding ambiguous. */
TT_TEST(rejects_a_signature_of_the_wrong_length) {
    Fixtures f;
    TT_ASSERT(load(&f));
    TT_ASSERT_FALSE(tamga_rsa_verify_pkcs1_sha256(f.spki, f.spki_len, f.message, f.message_len,
                                                  f.pkcs1, f.pkcs1_len - 1u));
    TT_ASSERT_FALSE(
        tamga_rsa_verify_pkcs1_sha256(f.spki, f.spki_len, f.message, f.message_len, f.pkcs1, 0u));
}

TT_TEST(rejects_a_malformed_or_truncated_key) {
    Fixtures f;
    unsigned char corrupted[SPKI_CAP];

    TT_ASSERT(load(&f));

    /* truncated */
    TT_ASSERT_FALSE(tamga_rsa_verify_pkcs1_sha256(f.spki, f.spki_len - 1u, f.message, f.message_len,
                                                  f.pkcs1, f.pkcs1_len));
    /* trailing garbage after a complete SPKI */
    memcpy(corrupted, f.spki, f.spki_len);
    corrupted[f.spki_len] = 0x00u;
    TT_ASSERT_FALSE(tamga_rsa_verify_pkcs1_sha256(corrupted, f.spki_len + 1u, f.message,
                                                  f.message_len, f.pkcs1, f.pkcs1_len));
    /* wrong outer tag */
    memcpy(corrupted, f.spki, f.spki_len);
    corrupted[0] = 0x31u;
    TT_ASSERT_FALSE(tamga_rsa_verify_pkcs1_sha256(corrupted, f.spki_len, f.message, f.message_len,
                                                  f.pkcs1, f.pkcs1_len));
    /* empty */
    TT_ASSERT_FALSE(
        tamga_rsa_verify_pkcs1_sha256(f.spki, 0u, f.message, f.message_len, f.pkcs1, f.pkcs1_len));
    TT_ASSERT_FALSE(
        tamga_rsa_verify_pkcs1_sha256(NULL, 10u, f.message, f.message_len, f.pkcs1, f.pkcs1_len));
}

/*
 * An EC public key must not be accepted by the RSA verifier just because its
 * bit string happens to contain parseable bytes. Checking the algorithm OID
 * rather than skipping it is what prevents that.
 */
TT_TEST(rejects_a_key_that_declares_a_different_algorithm) {
    Fixtures f;
    unsigned char corrupted[SPKI_CAP];

    TT_ASSERT(load(&f));
    memcpy(corrupted, f.spki, f.spki_len);
    /* The rsaEncryption OID body starts at a fixed offset in this fixture;
     * flipping its last byte names a different algorithm without changing
     * any length, so only the OID comparison can catch it. */
    {
        size_t i;
        for (i = 0u; i + 9u < f.spki_len; i++) {
            if (corrupted[i] == 0x2au && corrupted[i + 1u] == 0x86u && corrupted[i + 2u] == 0x48u &&
                corrupted[i + 3u] == 0x86u) {
                corrupted[i + 8u] ^= 0x01u;
                break;
            }
        }
    }
    TT_ASSERT_FALSE(tamga_rsa_verify_pkcs1_sha256(corrupted, f.spki_len, f.message, f.message_len,
                                                  f.pkcs1, f.pkcs1_len));
}

/* --- DER reader --------------------------------------------------------- */

TT_TEST(der_rejects_non_minimal_lengths) {
    /* SEQUENCE with a long-form length that would fit in the short form. */
    static const unsigned char padded[] = {0x30u, 0x81u, 0x01u, 0x05u};
    /* Long-form length with a leading zero byte. */
    static const unsigned char leading_zero[] = {0x30u, 0x82u, 0x00u, 0x01u, 0x05u};
    /* Indefinite length. */
    static const unsigned char indefinite[] = {0x30u, 0x80u, 0x05u, 0x00u, 0x00u, 0x00u};
    TamgaDer reader;
    const unsigned char *content = NULL;
    size_t content_len = 0u;
    unsigned int tag = 0u;

    tamga_der_init(&reader, padded, sizeof(padded));
    TT_ASSERT_FALSE(tamga_der_read(&reader, &tag, &content, &content_len));

    tamga_der_init(&reader, leading_zero, sizeof(leading_zero));
    TT_ASSERT_FALSE(tamga_der_read(&reader, &tag, &content, &content_len));

    tamga_der_init(&reader, indefinite, sizeof(indefinite));
    TT_ASSERT_FALSE(tamga_der_read(&reader, &tag, &content, &content_len));
}

TT_TEST(der_rejects_a_length_past_the_buffer) {
    static const unsigned char overlong[] = {0x30u, 0x7fu, 0x01u, 0x02u};
    TamgaDer reader;
    const unsigned char *content = NULL;
    size_t content_len = 0u;
    unsigned int tag = 0u;

    tamga_der_init(&reader, overlong, sizeof(overlong));
    TT_ASSERT_FALSE(tamga_der_read(&reader, &tag, &content, &content_len));
}

TT_TEST(der_reads_unsigned_integers_strictly) {
    static const unsigned char positive[] = {0x02u, 0x01u, 0x7fu};
    static const unsigned char high_bit[] = {0x02u, 0x02u, 0x00u, 0x80u};
    static const unsigned char negative[] = {0x02u, 0x01u, 0x80u};
    static const unsigned char padded[] = {0x02u, 0x02u, 0x00u, 0x01u};
    static const unsigned char zero[] = {0x02u, 0x01u, 0x00u};
    static const unsigned char empty[] = {0x02u, 0x00u};
    TamgaDer reader;
    const unsigned char *value = NULL;
    size_t value_len = 0u;

    tamga_der_init(&reader, positive, sizeof(positive));
    TT_ASSERT(tamga_der_read_unsigned(&reader, &value, &value_len));
    TT_ASSERT_EQ_SIZE(value_len, 1u);
    TT_ASSERT_EQ_INT(value[0], 0x7f);

    tamga_der_init(&reader, high_bit, sizeof(high_bit));
    TT_ASSERT(tamga_der_read_unsigned(&reader, &value, &value_len));
    TT_ASSERT_EQ_SIZE(value_len, 1u);
    TT_ASSERT_EQ_INT(value[0], 0x80);

    tamga_der_init(&reader, negative, sizeof(negative));
    TT_ASSERT_FALSE(tamga_der_read_unsigned(&reader, &value, &value_len));

    tamga_der_init(&reader, padded, sizeof(padded));
    TT_ASSERT_FALSE(tamga_der_read_unsigned(&reader, &value, &value_len));

    tamga_der_init(&reader, zero, sizeof(zero));
    TT_ASSERT(tamga_der_read_unsigned(&reader, &value, &value_len));

    tamga_der_init(&reader, empty, sizeof(empty));
    TT_ASSERT_FALSE(tamga_der_read_unsigned(&reader, &value, &value_len));
}

/* The generator records how many vectors it kept; reading that beats probing
 * for a missing file, which the fixture reader (rightly) reports as an
 * error. */
static unsigned int vector_count(void) {
    char manifest[4096];
    size_t len = tt_read_fixture("keys/vectors/manifest.txt", (unsigned char *)manifest,
                                 sizeof(manifest) - 1u);
    const char *marker;
    if (len == (size_t)-1) {
        return 0u;
    }
    manifest[len] = '\0';
    marker = strstr(manifest, "count=");
    return (marker != NULL) ? (unsigned int)strtoul(marker + 6, NULL, 10) : 0u;
}

/*
 * The vector set, not the single signature above.
 *
 * One key and one message per scheme is exactly the weakness NIST's CAVP
 * SigVer sets exist to remove: a verifier can be wrong for a whole class of
 * operand and still verify one signature. CAVP's own files are not vendored
 * here -- they are large, and their provenance would need tracking -- so
 * tests/fixtures/keys/generate.sh produces the same coverage locally,.
 *
 * For RSA the variation that matters is the digest: every vector signs a
 * different message, so the padded block differs in every byte position,
 * which a modexp or a padding comparison that is wrong only for some inputs
 * will not survive. Both schemes are checked over the same messages, and
 * each is checked NOT to verify under the other's padding.
 */
TT_TEST(verifies_every_committed_vector) {
    unsigned char spki[SPKI_CAP];
    size_t spki_len;
    unsigned int n;
    unsigned int checked = 0u;
    unsigned int total = vector_count();

    /* A silently empty or unregenerated fixture directory would make this
     * test vacuous, so the floor is asserted before anything is read. */
    TT_ASSERT(total >= 12u);

    spki_len = tt_read_fixture("keys/vectors/rsa2048.spki.der", spki, sizeof(spki));
    TT_ASSERT(spki_len != (size_t)-1);

    for (n = 1u; n <= total; n++) {
        char msg_path[64];
        char p1_path[64];
        char ps_path[64];
        unsigned char msg[MSG_CAP];
        unsigned char pkcs1[SIG_CAP];
        unsigned char pss[SIG_CAP];
        size_t msg_len;
        size_t pkcs1_len;
        size_t pss_len;

        (void)snprintf(msg_path, sizeof(msg_path), "keys/vectors/msg_%u.bin", n);
        (void)snprintf(p1_path, sizeof(p1_path), "keys/vectors/pkcs1_%u.bin", n);
        (void)snprintf(ps_path, sizeof(ps_path), "keys/vectors/pss_%u.bin", n);
        msg_len = tt_read_fixture(msg_path, msg, sizeof(msg));
        TT_ASSERT(msg_len != (size_t)-1);
        pkcs1_len = tt_read_fixture(p1_path, pkcs1, sizeof(pkcs1));
        pss_len = tt_read_fixture(ps_path, pss, sizeof(pss));
        TT_ASSERT(pkcs1_len != (size_t)-1);
        TT_ASSERT(pss_len != (size_t)-1);

        if (!tamga_rsa_verify_pkcs1_sha256(spki, spki_len, msg, msg_len, pkcs1, pkcs1_len) ||
            !tamga_rsa_verify_pss_sha256(spki, spki_len, msg, msg_len, pss, pss_len)) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: vector %u did not verify\n", tt_current_, n);
            return;
        }
        /* And neither padding accepts the other's signature, for every
         * vector rather than for the single pair above. */
        if (tamga_rsa_verify_pkcs1_sha256(spki, spki_len, msg, msg_len, pss, pss_len) ||
            tamga_rsa_verify_pss_sha256(spki, spki_len, msg, msg_len, pkcs1, pkcs1_len)) {
            tt_failures_++;
            (void)fprintf(stderr, "FAIL %s: vector %u cross-verified\n", tt_current_, n);
            return;
        }
        checked++;
    }
    TT_ASSERT_EQ_SIZE((size_t)checked, (size_t)total);
}

int main(void) {
    TT_RUN(accepts_a_real_pkcs1_signature);
    TT_RUN(accepts_a_real_pss_signature);
    TT_RUN(the_two_padding_schemes_do_not_cross_verify);
    TT_RUN(rejects_a_tampered_message);
    TT_RUN(rejects_a_tampered_signature);
    TT_RUN(rejects_a_signature_of_the_wrong_length);
    TT_RUN(rejects_a_malformed_or_truncated_key);
    TT_RUN(rejects_a_key_that_declares_a_different_algorithm);
    TT_RUN(der_rejects_non_minimal_lengths);
    TT_RUN(der_rejects_a_length_past_the_buffer);
    TT_RUN(der_reads_unsigned_integers_strictly);
    TT_RUN(verifies_every_committed_vector);
    return TT_SUMMARY();
}
