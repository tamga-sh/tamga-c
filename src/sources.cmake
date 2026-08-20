# Explicit source list for the tamga library.
#
# Deliberately not a file(GLOB): a glob makes the build depend on directory
# contents rather than on this file, so a newly added source silently does or
# does not get compiled depending on whether the generator happened to re-run.
# Every source is listed here on purpose.

set(TAMGA_SOURCES
    # --- core ---------------------------------------------------------
    src/tamga_error.c
    src/tamga_mem.c

    # --- utilities ----------------------------------------------------
    src/util/buf.c
    src/util/base64.c
    src/util/hex.c
    src/util/uuid.c
    src/util/rfc3339.c
    src/util/json.c
    src/util/json_parse.c
    src/util/json_write.c

    # --- crypto: hashes, MAC, KDF ------------------------------------
    src/crypto/ct.c
    src/crypto/sha256.c
    src/crypto/sha512.c
    src/crypto/hmac_sha256.c
    src/crypto/hkdf.c

    # --- crypto: authenticated encryption -----------------------------
    src/crypto/aes.c
    src/crypto/gcm.c

    # --- crypto: Ed25519 ----------------------------------------------
    src/crypto/fe25519.c
    src/crypto/ed25519.c
)

list(TRANSFORM TAMGA_SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
