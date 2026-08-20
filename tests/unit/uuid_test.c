#include "tamga_test.h"

#include "util/uuid.h"

static const char CANONICAL[] = "01926b3e-0000-7000-8000-000000000000";

TT_TEST(parses_the_canonical_hyphenated_form)
{
    TamgaUuid uuid;
    char out[TAMGA_UUID_STRING_SIZE];
    TT_ASSERT(tamga_uuid_parse(CANONICAL, &uuid));
    tamga_uuid_format(&uuid, out);
    TT_ASSERT_EQ_STR(out, CANONICAL);
}

/*
 * Every accepted spelling must normalise to the same 36 lowercase characters:
 * that string goes verbatim into the offline proof's signed payload, so an
 * uppercase input that round-tripped as uppercase would produce different
 * signed bytes than the server's and fail every verification.
 */
TT_TEST(all_accepted_spellings_normalise_identically)
{
    char out[TAMGA_UUID_STRING_SIZE];

    TT_ASSERT(tamga_uuid_normalize("01926B3E-0000-7000-8000-000000000000", out));
    TT_ASSERT_EQ_STR(out, CANONICAL);

    TT_ASSERT(tamga_uuid_normalize("01926b3e000070008000000000000000", out));
    TT_ASSERT_EQ_STR(out, CANONICAL);

    TT_ASSERT(tamga_uuid_normalize("{01926b3e-0000-7000-8000-000000000000}", out));
    TT_ASSERT_EQ_STR(out, CANONICAL);

    TT_ASSERT(tamga_uuid_normalize("urn:uuid:01926b3e-0000-7000-8000-000000000000", out));
    TT_ASSERT_EQ_STR(out, CANONICAL);

    TT_ASSERT(tamga_uuid_normalize("URN:UUID:01926b3e-0000-7000-8000-000000000000", out));
    TT_ASSERT_EQ_STR(out, CANONICAL);
}

TT_TEST(rejects_malformed_input)
{
    TamgaUuid uuid;
    TT_ASSERT_FALSE(tamga_uuid_parse(NULL, &uuid));
    TT_ASSERT_FALSE(tamga_uuid_parse("", &uuid));
    TT_ASSERT_FALSE(tamga_uuid_parse("not-a-uuid", &uuid));
    /* right length, hyphens in the wrong places */
    TT_ASSERT_FALSE(tamga_uuid_parse("01926b3e-0000-7000-8000-0000-0000000", &uuid));
    /* right shape, non-hex character */
    TT_ASSERT_FALSE(tamga_uuid_parse("01926b3g-0000-7000-8000-000000000000", &uuid));
    /* braced but unbalanced */
    TT_ASSERT_FALSE(tamga_uuid_parse("{01926b3e-0000-7000-8000-000000000000", &uuid));
}

TT_TEST(round_trips_every_byte_position)
{
    TamgaUuid uuid;
    char out[TAMGA_UUID_STRING_SIZE];
    TT_ASSERT(tamga_uuid_parse("00112233-4455-6677-8899-aabbccddeeff", &uuid));
    TT_ASSERT_EQ_INT(uuid.bytes[0], 0x00);
    TT_ASSERT_EQ_INT(uuid.bytes[4], 0x44);
    TT_ASSERT_EQ_INT(uuid.bytes[6], 0x66);
    TT_ASSERT_EQ_INT(uuid.bytes[8], 0x88);
    TT_ASSERT_EQ_INT(uuid.bytes[15], 0xff);
    tamga_uuid_format(&uuid, out);
    TT_ASSERT_EQ_STR(out, "00112233-4455-6677-8899-aabbccddeeff");
}

int main(void)
{
    TT_RUN(parses_the_canonical_hyphenated_form);
    TT_RUN(all_accepted_spellings_normalise_identically);
    TT_RUN(rejects_malformed_input);
    TT_RUN(round_trips_every_byte_position);
    return TT_SUMMARY();
}
