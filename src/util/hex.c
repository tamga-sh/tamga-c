#include "util/hex.h"

static const char TAMGA_HEX_DIGITS[] = "0123456789abcdef";

/* Returns 0-15, or -1 when `c` is not a hex digit. */
static int tamga_hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return (c - 'a') + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return (c - 'A') + 10;
    }
    return -1;
}

bool tamga_hex_decode(const char *in, size_t in_len, unsigned char *out)
{
    size_t i;

    if (in == NULL || out == NULL) {
        return false;
    }
    if ((in_len % 2u) != 0u) {
        return false;
    }
    for (i = 0u; i < in_len; i += 2u) {
        int hi = tamga_hex_value(in[i]);
        int lo = tamga_hex_value(in[i + 1u]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i / 2u] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

void tamga_hex_encode(const unsigned char *in, size_t in_len, char *out)
{
    size_t i;

    if (out == NULL) {
        return;
    }
    if (in == NULL) {
        out[0] = '\0';
        return;
    }
    for (i = 0u; i < in_len; i++) {
        out[i * 2u] = TAMGA_HEX_DIGITS[(in[i] >> 4) & 0x0Fu];
        out[(i * 2u) + 1u] = TAMGA_HEX_DIGITS[in[i] & 0x0Fu];
    }
    out[in_len * 2u] = '\0';
}
