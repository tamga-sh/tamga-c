#include "tamga_test.h"

#include "util/hex.h"

TT_TEST(encodes_lowercase)
{
    const unsigned char raw[4] = {0x00u, 0x0Fu, 0xA5u, 0xFFu};
    char out[9];
    tamga_hex_encode(raw, sizeof(raw), out);
    TT_ASSERT_EQ_STR(out, "000fa5ff");
}

TT_TEST(decodes_either_case)
{
    unsigned char out[4];
    const unsigned char expected[4] = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    TT_ASSERT(tamga_hex_decode("DeAdBeEf", 8u, out));
    TT_ASSERT_EQ_MEM(out, expected, sizeof(expected));
}

TT_TEST(rejects_odd_length_and_non_hex)
{
    unsigned char out[4];
    TT_ASSERT_FALSE(tamga_hex_decode("abc", 3u, out));
    TT_ASSERT_FALSE(tamga_hex_decode("zz", 2u, out));
    TT_ASSERT_FALSE(tamga_hex_decode("0x", 2u, out));
    TT_ASSERT_FALSE(tamga_hex_decode("a ", 2u, out));
}

TT_TEST(empty_input_round_trips)
{
    unsigned char out[1];
    char text[1];
    TT_ASSERT(tamga_hex_decode("", 0u, out));
    tamga_hex_encode(out, 0u, text);
    TT_ASSERT_EQ_STR(text, "");
}

int main(void)
{
    TT_RUN(encodes_lowercase);
    TT_RUN(decodes_either_case);
    TT_RUN(rejects_odd_length_and_non_hex);
    TT_RUN(empty_input_round_trips);
    return TT_SUMMARY();
}
