#include "util/base64.h"

#include <stdint.h>
#include <string.h>

#include "tamga_mem.h"

static const char TAMGA_B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * 0-63 decode to their sextet, 0xFF means "not in the alphabet". Padding
 * ('=') is deliberately 0xFF too -- it is handled by the length/position
 * logic in the decoder, never by table lookup, so a '=' in the middle of the
 * input can never be silently absorbed as a value.
 */
static const unsigned char TAMGA_B64_REVERSE[256] = {
    /* 0x00 */ 0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    /* 0x08 */ 0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    /* 0x10 */ 0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    /* 0x18 */ 0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    /* 0x20 */ 0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    /* 0x28 */ 0xFF,
    0xFF,
    0xFF,
    62u,
    0xFF,
    0xFF,
    0xFF,
    63u,
    /* 0x30 */ 52u,
    53u,
    54u,
    55u,
    56u,
    57u,
    58u,
    59u,
    /* 0x38 */ 60u,
    61u,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    /* 0x40 */ 0xFF,
    0u,
    1u,
    2u,
    3u,
    4u,
    5u,
    6u,
    /* 0x48 */ 7u,
    8u,
    9u,
    10u,
    11u,
    12u,
    13u,
    14u,
    /* 0x50 */ 15u,
    16u,
    17u,
    18u,
    19u,
    20u,
    21u,
    22u,
    /* 0x58 */ 23u,
    24u,
    25u,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    /* 0x60 */ 0xFF,
    26u,
    27u,
    28u,
    29u,
    30u,
    31u,
    32u,
    /* 0x68 */ 33u,
    34u,
    35u,
    36u,
    37u,
    38u,
    39u,
    40u,
    /* 0x70 */ 41u,
    42u,
    43u,
    44u,
    45u,
    46u,
    47u,
    48u,
    /* 0x78 */ 49u,
    50u,
    51u,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF};

bool tamga_base64_decoded_cap(size_t encoded_len, size_t *out) {
    size_t groups;
    if (out == NULL) {
        return false;
    }
    if (!tamga_checked_add(encoded_len, 3u, &groups)) {
        return false;
    }
    groups /= 4u;
    return tamga_checked_mul(groups, 3u, out);
}

bool tamga_base64_decode(const char *in, size_t in_len, unsigned char *out, size_t *out_len) {
    size_t i;
    size_t written = 0u;
    size_t body_len = in_len;
    size_t pad = 0u;
    uint_fast32_t accum = 0u;
    unsigned int accum_bits = 0u;

    if (in == NULL || out_len == NULL) {
        return false;
    }
    if (in_len == 0u) {
        *out_len = 0u;
        return true;
    }
    if (out == NULL) {
        return false;
    }

    /* Padding is only ever legal as the last one or two characters. Measuring
     * it here rather than inside the main loop means a '=' anywhere else
     * falls through to the alphabet check and is rejected. */
    while (pad < 2u && body_len > 0u && in[body_len - 1u] == '=') {
        pad++;
        body_len--;
    }
    if (body_len > 0u && in[body_len - 1u] == '=') {
        return false; /* three or more '=' */
    }
    if (pad > 0u && (((body_len + pad) % 4u) != 0u)) {
        return false; /* padded input must be a whole number of quartets */
    }
    /* 4n+1 can never be a valid encoding: one leftover character carries 6
     * bits, which is neither a byte nor nothing. */
    if ((body_len % 4u) == 1u) {
        return false;
    }
    if (pad == 1u && ((body_len % 4u) != 3u)) {
        return false;
    }
    if (pad == 2u && ((body_len % 4u) != 2u)) {
        return false;
    }

    for (i = 0u; i < body_len; i++) {
        unsigned char sextet = TAMGA_B64_REVERSE[(unsigned char)in[i]];
        if (sextet == 0xFFu) {
            return false;
        }
        accum = (accum << 6) | (uint_fast32_t)sextet;
        accum_bits += 6u;
        if (accum_bits >= 8u) {
            accum_bits -= 8u;
            out[written] = (unsigned char)((accum >> accum_bits) & 0xFFu);
            written++;
        }
    }

    /* Canonical form: the bits left over after the final whole byte must all
     * be zero. Accepting non-zero remainders would let several distinct
     * strings decode to identical bytes. */
    if (accum_bits > 0u) {
        uint_fast32_t mask = ((uint_fast32_t)1u << accum_bits) - 1u;
        if ((accum & mask) != 0u) {
            return false;
        }
    }

    *out_len = written;
    return true;
}

unsigned char *tamga_base64_decode_alloc_why(const char *in, size_t in_len, size_t *out_len,
                                             TamgaBase64Failure *out_failure) {
    size_t cap;
    size_t decoded_len = 0u;
    unsigned char *buf;
    TamgaBase64Failure ignored;

    if (out_failure == NULL) {
        out_failure = &ignored;
    }
    *out_failure = TAMGA_BASE64_FAILURE_MALFORMED;

    if (in == NULL || out_len == NULL) {
        return NULL;
    }
    /* An input so long its decoded size overflows is refused as malformed
     * rather than as an allocation failure -- nothing was attempted. */
    if (!tamga_base64_decoded_cap(in_len, &cap)) {
        return NULL;
    }
    buf = (unsigned char *)tamga_malloc(cap);
    if (buf == NULL) {
        *out_failure = TAMGA_BASE64_FAILURE_OUT_OF_MEMORY;
        return NULL;
    }
    if (!tamga_base64_decode(in, in_len, buf, &decoded_len)) {
        tamga_secure_free(buf, cap);
        return NULL;
    }
    *out_len = decoded_len;
    return buf;
}

unsigned char *tamga_base64_decode_alloc(const char *in, size_t in_len, size_t *out_len) {
    return tamga_base64_decode_alloc_why(in, in_len, out_len, NULL);
}

bool tamga_base64_encoded_len(size_t decoded_len, size_t *out) {
    size_t groups;
    if (out == NULL) {
        return false;
    }
    if (!tamga_checked_add(decoded_len, 2u, &groups)) {
        return false;
    }
    groups /= 3u;
    return tamga_checked_mul(groups, 4u, out);
}

void tamga_base64_encode(const unsigned char *in, size_t in_len, char *out) {
    size_t i = 0u;
    size_t o = 0u;

    if (out == NULL) {
        return;
    }
    if (in == NULL || in_len == 0u) {
        out[0] = '\0';
        return;
    }

    while ((in_len - i) >= 3u) {
        uint_fast32_t triple = ((uint_fast32_t)in[i] << 16) | ((uint_fast32_t)in[i + 1u] << 8) |
                               (uint_fast32_t)in[i + 2u];
        out[o++] = TAMGA_B64_ALPHABET[(triple >> 18) & 0x3Fu];
        out[o++] = TAMGA_B64_ALPHABET[(triple >> 12) & 0x3Fu];
        out[o++] = TAMGA_B64_ALPHABET[(triple >> 6) & 0x3Fu];
        out[o++] = TAMGA_B64_ALPHABET[triple & 0x3Fu];
        i += 3u;
    }

    if ((in_len - i) == 1u) {
        uint_fast32_t triple = (uint_fast32_t)in[i] << 16;
        out[o++] = TAMGA_B64_ALPHABET[(triple >> 18) & 0x3Fu];
        out[o++] = TAMGA_B64_ALPHABET[(triple >> 12) & 0x3Fu];
        out[o++] = '=';
        out[o++] = '=';
    } else if ((in_len - i) == 2u) {
        uint_fast32_t triple = ((uint_fast32_t)in[i] << 16) | ((uint_fast32_t)in[i + 1u] << 8);
        out[o++] = TAMGA_B64_ALPHABET[(triple >> 18) & 0x3Fu];
        out[o++] = TAMGA_B64_ALPHABET[(triple >> 12) & 0x3Fu];
        out[o++] = TAMGA_B64_ALPHABET[(triple >> 6) & 0x3Fu];
        out[o++] = '=';
    }

    out[o] = '\0';
}

char *tamga_base64_encode_alloc(const unsigned char *in, size_t in_len) {
    size_t enc_len;
    size_t total;
    char *out;

    if (!tamga_base64_encoded_len(in_len, &enc_len)) {
        return NULL;
    }
    if (!tamga_checked_add(enc_len, 1u, &total)) {
        return NULL;
    }
    out = (char *)tamga_malloc(total);
    if (out == NULL) {
        return NULL;
    }
    tamga_base64_encode(in, in_len, out);
    return out;
}
