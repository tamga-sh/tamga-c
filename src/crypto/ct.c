#include "crypto/ct.h"

bool tamga_ct_memeq(const void *a, const void *b, size_t len)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0u;
    size_t i;

    if (a == NULL || b == NULL) {
        return false;
    }
    /* Accumulate every byte difference instead of returning early, so the
     * loop runs the same number of iterations regardless of where -- or
     * whether -- the inputs diverge. */
    for (i = 0u; i < len; i++) {
        diff |= (unsigned char)(pa[i] ^ pb[i]);
    }
    return diff == 0u;
}
