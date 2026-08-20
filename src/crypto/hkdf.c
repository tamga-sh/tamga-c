#include "crypto/hkdf.h"

#include <string.h>

#include "crypto/hmac_sha256.h"
#include "tamga_mem.h"

/* Fixed salts, byte-for-byte as the server uses them. Changing either string
 * -- including its trailing version suffix -- makes every existing file
 * undecryptable, which is the point of versioning them. */
static const char TAMGA_LICENSE_FILE_SALT[] = "tamga:license-file-key-v1";
static const char TAMGA_LICENSE_FILE_INFO[] = "license-file";
static const char TAMGA_MACHINE_FILE_SALT[] = "tamga:machine-file-key-v1";

bool tamga_hkdf_sha256(const unsigned char *salt, size_t salt_len, const unsigned char *ikm,
                       size_t ikm_len, const unsigned char *info, size_t info_len,
                       unsigned char *out, size_t out_len) {
    unsigned char prk[TAMGA_SHA256_DIGEST_LEN];
    unsigned char block[TAMGA_SHA256_DIGEST_LEN];
    unsigned char zero_salt[TAMGA_SHA256_DIGEST_LEN];
    size_t produced = 0u;
    unsigned int counter = 1u;

    if (out == NULL || out_len == 0u) {
        return false;
    }
    /* RFC 5869: at most 255 blocks of HashLen. */
    if (out_len > (255u * TAMGA_SHA256_DIGEST_LEN)) {
        return false;
    }

    /* Extract. An absent salt is defined as HashLen zero bytes. */
    if (salt == NULL || salt_len == 0u) {
        memset(zero_salt, 0, sizeof(zero_salt));
        tamga_hmac_sha256(zero_salt, sizeof(zero_salt), ikm, ikm_len, prk);
    } else {
        tamga_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }

    /* Expand. T(n) = HMAC(PRK, T(n-1) || info || n), with T(0) empty. */
    while (produced < out_len) {
        TamgaHmacSha256 hmac;
        size_t take;
        unsigned char counter_byte = (unsigned char)counter;

        tamga_hmac_sha256_init(&hmac, prk, sizeof(prk));
        if (counter > 1u) {
            tamga_hmac_sha256_update(&hmac, block, sizeof(block));
        }
        if (info != NULL && info_len > 0u) {
            tamga_hmac_sha256_update(&hmac, info, info_len);
        }
        tamga_hmac_sha256_update(&hmac, &counter_byte, 1u);
        tamga_hmac_sha256_final(&hmac, block);

        take = out_len - produced;
        if (take > sizeof(block)) {
            take = sizeof(block);
        }
        memcpy(&out[produced], block, take);
        produced += take;
        counter++;
    }

    tamga_secure_zero(prk, sizeof(prk));
    tamga_secure_zero(block, sizeof(block));
    return true;
}

bool tamga_derive_license_file_key(const char *license_key, unsigned char out[TAMGA_FILE_KEY_LEN]) {
    if (license_key == NULL || out == NULL) {
        return false;
    }
    return tamga_hkdf_sha256((const unsigned char *)TAMGA_LICENSE_FILE_SALT,
                             sizeof(TAMGA_LICENSE_FILE_SALT) - 1u,
                             (const unsigned char *)license_key, strlen(license_key),
                             (const unsigned char *)TAMGA_LICENSE_FILE_INFO,
                             sizeof(TAMGA_LICENSE_FILE_INFO) - 1u, out, TAMGA_FILE_KEY_LEN);
}

bool tamga_derive_machine_file_key(const char *license_key, const char *fingerprint,
                                   unsigned char out[TAMGA_FILE_KEY_LEN]) {
    if (license_key == NULL || fingerprint == NULL || out == NULL) {
        return false;
    }
    return tamga_hkdf_sha256(
        (const unsigned char *)TAMGA_MACHINE_FILE_SALT, sizeof(TAMGA_MACHINE_FILE_SALT) - 1u,
        (const unsigned char *)license_key, strlen(license_key), (const unsigned char *)fingerprint,
        strlen(fingerprint), out, TAMGA_FILE_KEY_LEN);
}
