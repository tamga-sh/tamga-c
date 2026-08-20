#include "crypto/aes.h"

#include <string.h>

#include "tamga_mem.h"

static const uint8_t TAMGA_AES_SBOX[256] = {
    0x63u, 0x7cu, 0x77u, 0x7bu, 0xf2u, 0x6bu, 0x6fu, 0xc5u, 0x30u, 0x01u, 0x67u, 0x2bu,
    0xfeu, 0xd7u, 0xabu, 0x76u, 0xcau, 0x82u, 0xc9u, 0x7du, 0xfau, 0x59u, 0x47u, 0xf0u,
    0xadu, 0xd4u, 0xa2u, 0xafu, 0x9cu, 0xa4u, 0x72u, 0xc0u, 0xb7u, 0xfdu, 0x93u, 0x26u,
    0x36u, 0x3fu, 0xf7u, 0xccu, 0x34u, 0xa5u, 0xe5u, 0xf1u, 0x71u, 0xd8u, 0x31u, 0x15u,
    0x04u, 0xc7u, 0x23u, 0xc3u, 0x18u, 0x96u, 0x05u, 0x9au, 0x07u, 0x12u, 0x80u, 0xe2u,
    0xebu, 0x27u, 0xb2u, 0x75u, 0x09u, 0x83u, 0x2cu, 0x1au, 0x1bu, 0x6eu, 0x5au, 0xa0u,
    0x52u, 0x3bu, 0xd6u, 0xb3u, 0x29u, 0xe3u, 0x2fu, 0x84u, 0x53u, 0xd1u, 0x00u, 0xedu,
    0x20u, 0xfcu, 0xb1u, 0x5bu, 0x6au, 0xcbu, 0xbeu, 0x39u, 0x4au, 0x4cu, 0x58u, 0xcfu,
    0xd0u, 0xefu, 0xaau, 0xfbu, 0x43u, 0x4du, 0x33u, 0x85u, 0x45u, 0xf9u, 0x02u, 0x7fu,
    0x50u, 0x3cu, 0x9fu, 0xa8u, 0x51u, 0xa3u, 0x40u, 0x8fu, 0x92u, 0x9du, 0x38u, 0xf5u,
    0xbcu, 0xb6u, 0xdau, 0x21u, 0x10u, 0xffu, 0xf3u, 0xd2u, 0xcdu, 0x0cu, 0x13u, 0xecu,
    0x5fu, 0x97u, 0x44u, 0x17u, 0xc4u, 0xa7u, 0x7eu, 0x3du, 0x64u, 0x5du, 0x19u, 0x73u,
    0x60u, 0x81u, 0x4fu, 0xdcu, 0x22u, 0x2au, 0x90u, 0x88u, 0x46u, 0xeeu, 0xb8u, 0x14u,
    0xdeu, 0x5eu, 0x0bu, 0xdbu, 0xe0u, 0x32u, 0x3au, 0x0au, 0x49u, 0x06u, 0x24u, 0x5cu,
    0xc2u, 0xd3u, 0xacu, 0x62u, 0x91u, 0x95u, 0xe4u, 0x79u, 0xe7u, 0xc8u, 0x37u, 0x6du,
    0x8du, 0xd5u, 0x4eu, 0xa9u, 0x6cu, 0x56u, 0xf4u, 0xeau, 0x65u, 0x7au, 0xaeu, 0x08u,
    0xbau, 0x78u, 0x25u, 0x2eu, 0x1cu, 0xa6u, 0xb4u, 0xc6u, 0xe8u, 0xddu, 0x74u, 0x1fu,
    0x4bu, 0xbdu, 0x8bu, 0x8au, 0x70u, 0x3eu, 0xb5u, 0x66u, 0x48u, 0x03u, 0xf6u, 0x0eu,
    0x61u, 0x35u, 0x57u, 0xb9u, 0x86u, 0xc1u, 0x1du, 0x9eu, 0xe1u, 0xf8u, 0x98u, 0x11u,
    0x69u, 0xd9u, 0x8eu, 0x94u, 0x9bu, 0x1eu, 0x87u, 0xe9u, 0xceu, 0x55u, 0x28u, 0xdfu,
    0x8cu, 0xa1u, 0x89u, 0x0du, 0xbfu, 0xe6u, 0x42u, 0x68u, 0x41u, 0x99u, 0x2du, 0x0fu,
    0xb0u, 0x54u, 0xbbu, 0x16u
};

/* Round constants for the key schedule, x^(i-1) in GF(2^8). AES-256 needs
 * seven of them. */
static const uint8_t TAMGA_AES_RCON[7] = {0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u};

/* Multiply by x in GF(2^8) modulo the AES polynomial. The mask is built from
 * the high bit rather than branching on it. */
static uint8_t tamga_xtime(uint8_t value)
{
    uint8_t high = (uint8_t)(0u - (uint8_t)(value >> 7)); /* 0xFF when set, else 0 */
    return (uint8_t)(((uint8_t)(value << 1)) ^ (uint8_t)(0x1bu & high));
}

void tamga_aes256_init(TamgaAes256 *ctx, const unsigned char key[TAMGA_AES256_KEY_LEN])
{
    uint8_t words[TAMGA_AES256_ROUND_KEYS * TAMGA_AES_BLOCK_LEN];
    unsigned int i;

    if (ctx == NULL || key == NULL) {
        return;
    }
    memcpy(words, key, TAMGA_AES256_KEY_LEN);

    /* AES-256: Nk = 8 words of key, Nr = 14 rounds, so 4*(Nr+1) = 60 words.
     * The schedule applies RotWord+SubWord+Rcon every 8 words and a bare
     * SubWord at the 4-word midpoint -- the latter is specific to 256-bit
     * keys and is the step most often omitted by mistake. */
    for (i = TAMGA_AES256_KEY_LEN; i < sizeof(words); i += 4u) {
        uint8_t temp[4];
        temp[0] = words[i - 4u];
        temp[1] = words[i - 3u];
        temp[2] = words[i - 2u];
        temp[3] = words[i - 1u];

        if ((i % TAMGA_AES256_KEY_LEN) == 0u) {
            uint8_t rotated = temp[0];
            temp[0] = TAMGA_AES_SBOX[temp[1]];
            temp[1] = TAMGA_AES_SBOX[temp[2]];
            temp[2] = TAMGA_AES_SBOX[temp[3]];
            temp[3] = TAMGA_AES_SBOX[rotated];
            temp[0] = (uint8_t)(temp[0] ^ TAMGA_AES_RCON[(i / TAMGA_AES256_KEY_LEN) - 1u]);
        } else if ((i % TAMGA_AES256_KEY_LEN) == 16u) {
            temp[0] = TAMGA_AES_SBOX[temp[0]];
            temp[1] = TAMGA_AES_SBOX[temp[1]];
            temp[2] = TAMGA_AES_SBOX[temp[2]];
            temp[3] = TAMGA_AES_SBOX[temp[3]];
        }

        words[i] = (uint8_t)(words[i - TAMGA_AES256_KEY_LEN] ^ temp[0]);
        words[i + 1u] = (uint8_t)(words[(i + 1u) - TAMGA_AES256_KEY_LEN] ^ temp[1]);
        words[i + 2u] = (uint8_t)(words[(i + 2u) - TAMGA_AES256_KEY_LEN] ^ temp[2]);
        words[i + 3u] = (uint8_t)(words[(i + 3u) - TAMGA_AES256_KEY_LEN] ^ temp[3]);
    }

    memcpy(ctx->round_key, words, sizeof(words));
    tamga_secure_zero(words, sizeof(words));
}

void tamga_aes256_encrypt_block(const TamgaAes256 *ctx,
                                const unsigned char in[TAMGA_AES_BLOCK_LEN],
                                unsigned char out[TAMGA_AES_BLOCK_LEN])
{
    uint8_t state[TAMGA_AES_BLOCK_LEN];
    unsigned int round;
    unsigned int i;

    if (ctx == NULL || in == NULL || out == NULL) {
        return;
    }
    memcpy(state, in, sizeof(state));

    for (i = 0u; i < TAMGA_AES_BLOCK_LEN; i++) {
        state[i] = (uint8_t)(state[i] ^ ctx->round_key[0][i]);
    }

    for (round = 1u; round <= 14u; round++) {
        uint8_t tmp;

        /* SubBytes */
        for (i = 0u; i < TAMGA_AES_BLOCK_LEN; i++) {
            state[i] = TAMGA_AES_SBOX[state[i]];
        }

        /* ShiftRows -- the state is column-major, so row r lives at indices
         * r, r+4, r+8, r+12 and is rotated left by r. */
        tmp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = tmp;

        tmp = state[2];
        state[2] = state[10];
        state[10] = tmp;
        tmp = state[6];
        state[6] = state[14];
        state[14] = tmp;

        tmp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = tmp;

        /* MixColumns -- skipped in the final round, per FIPS 197. */
        if (round != 14u) {
            for (i = 0u; i < TAMGA_AES_BLOCK_LEN; i += 4u) {
                uint8_t a0 = state[i];
                uint8_t a1 = state[i + 1u];
                uint8_t a2 = state[i + 2u];
                uint8_t a3 = state[i + 3u];
                uint8_t all = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);

                state[i] = (uint8_t)(a0 ^ all ^ tamga_xtime((uint8_t)(a0 ^ a1)));
                state[i + 1u] = (uint8_t)(a1 ^ all ^ tamga_xtime((uint8_t)(a1 ^ a2)));
                state[i + 2u] = (uint8_t)(a2 ^ all ^ tamga_xtime((uint8_t)(a2 ^ a3)));
                state[i + 3u] = (uint8_t)(a3 ^ all ^ tamga_xtime((uint8_t)(a3 ^ a0)));
            }
        }

        /* AddRoundKey */
        for (i = 0u; i < TAMGA_AES_BLOCK_LEN; i++) {
            state[i] = (uint8_t)(state[i] ^ ctx->round_key[round][i]);
        }
    }

    memcpy(out, state, sizeof(state));
    tamga_secure_zero(state, sizeof(state));
}

void tamga_aes256_clear(TamgaAes256 *ctx)
{
    if (ctx != NULL) {
        tamga_secure_zero(ctx, sizeof(*ctx));
    }
}
