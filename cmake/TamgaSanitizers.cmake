# Sanitizer and coverage build options.
#
# TAMGA_C_ENABLE_ASAN keeps the exact option name the pre-1.3 build used, so
# existing CI invocations and developer muscle memory keep working. It now
# applies to the library itself as well as the test harness -- under the old
# Rust-backed build only the C-side executables could be instrumented.

option(TAMGA_C_ENABLE_ASAN     "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(TAMGA_C_ENABLE_MSAN     "Build with MemorySanitizer (clang only; mutually exclusive with ASan)" OFF)
option(TAMGA_C_ENABLE_COVERAGE "Build with source-based coverage instrumentation" OFF)
option(TAMGA_C_ENABLE_FUZZ     "Build the libFuzzer targets in tests/fuzz (clang only)" OFF)

if(TAMGA_C_ENABLE_ASAN AND TAMGA_C_ENABLE_MSAN)
    message(FATAL_ERROR "TAMGA_C_ENABLE_ASAN and TAMGA_C_ENABLE_MSAN cannot both be ON -- "
                        "ASan and MSan are mutually exclusive at link time.")
endif()

# Applies whichever sanitizer/coverage flags are enabled to one target.
# Every flag here must be applied to BOTH compile and link steps; a target
# compiled with -fsanitize=address but linked without it fails at runtime
# with an unresolved __asan_* symbol rather than a useful message.
function(tamga_apply_sanitizers TARGET)
    if(MSVC)
        if(TAMGA_C_ENABLE_ASAN)
            target_compile_options(${TARGET} PRIVATE /fsanitize=address)
        endif()
        if(TAMGA_C_ENABLE_MSAN OR TAMGA_C_ENABLE_COVERAGE OR TAMGA_C_ENABLE_FUZZ)
            message(WARNING "MSan/coverage/fuzz options are not supported under MSVC; ignoring.")
        endif()
        return()
    endif()

    if(TAMGA_C_ENABLE_ASAN)
        target_compile_options(${TARGET} PRIVATE
            -fsanitize=address,undefined
            -fno-sanitize-recover=all
            -fno-omit-frame-pointer
            -g)
        target_link_options(${TARGET} PRIVATE -fsanitize=address,undefined)
    endif()

    if(TAMGA_C_ENABLE_MSAN)
        target_compile_options(${TARGET} PRIVATE
            -fsanitize=memory
            -fsanitize-memory-track-origins=2
            -fno-omit-frame-pointer
            -g)
        target_link_options(${TARGET} PRIVATE -fsanitize=memory)
    endif()

    if(TAMGA_C_ENABLE_COVERAGE)
        target_compile_options(${TARGET} PRIVATE -fprofile-instr-generate -fcoverage-mapping -g -O0)
        target_link_options(${TARGET} PRIVATE -fprofile-instr-generate)
    endif()
endfunction()
