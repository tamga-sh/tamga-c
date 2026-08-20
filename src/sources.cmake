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
)

list(TRANSFORM TAMGA_SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
