# Compiler warning configuration shared by the library, tests, and examples.
#
# The warning set is deliberately aggressive: this library hand-rolls every
# parser and every cryptographic primitive it uses, so the bug classes the
# compiler can catch for free (implicit conversions that silently truncate a
# length, shadowed locals in a loop over a buffer, missing prototypes hiding a
# typo'd symbol) are exactly the ones that turn into memory-safety defects
# here. CI additionally promotes all of these to errors -- see
# TAMGA_WARNINGS_AS_ERRORS.

option(TAMGA_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

function(tamga_set_warnings TARGET)
    if(MSVC)
        target_compile_options(${TARGET} PRIVATE
            /W4
            /permissive-
            # C4996: MSVC deprecates the standard C library's string/IO
            # functions in favour of its own _s variants. This codebase does
            # not use the deprecated ones at all (see CLAUDE.md's banned-API
            # rule), so the warning only ever fires on third-party headers.
            /wd4996
        )
        if(TAMGA_WARNINGS_AS_ERRORS)
            target_compile_options(${TARGET} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${TARGET} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wshadow
            -Wconversion
            -Wsign-conversion
            -Wcast-qual
            -Wcast-align
            -Wpointer-arith
            -Wwrite-strings
            -Wstrict-prototypes
            -Wmissing-prototypes
            -Wredundant-decls
            -Wundef
            -Wvla
            -Wformat=2
            -Wswitch-enum
            -Wdouble-promotion
        )
        if(TAMGA_WARNINGS_AS_ERRORS)
            target_compile_options(${TARGET} PRIVATE -Werror)
        endif()
    endif()
endfunction()
