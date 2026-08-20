# libFuzzer targets for every parser that reads untrusted bytes.
#
# These are the code paths an attacker reaches directly: a .lic file, a
# machine file, a public key, an API response. Unit tests cover the inputs
# someone thought of; fuzzing covers the ones nobody did.
#
# clang only, and off by default -- enable with -DTAMGA_C_ENABLE_FUZZ=ON.

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "TAMGA_C_ENABLE_FUZZ requires clang (libFuzzer).")
endif()

# Apple's clang does not ship libFuzzer's runtime, so -fsanitize=fuzzer links
# against a library that is not there. Say so at configure time rather than
# letting it surface as an unresolved library at the end of a full build.
if(APPLE AND CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
    message(FATAL_ERROR
        "Apple's clang does not ship libFuzzer. Build the fuzzers with a full LLVM "
        "toolchain instead, e.g.:\n"
        "  cmake -S . -B build-fuzz -DTAMGA_C_ENABLE_FUZZ=ON "
        "-DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang")
endif()

function(tamga_add_fuzzer NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    target_link_libraries(${NAME} PRIVATE tamga_static)
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src)
    # Fuzzing without a sanitizer finds crashes but not the reads and writes
    # that merely happen to land somewhere harmless, which is most of them.
    target_compile_options(${NAME} PRIVATE -fsanitize=fuzzer,address,undefined
                                           -fno-omit-frame-pointer -g)
    target_link_options(${NAME} PRIVATE -fsanitize=fuzzer,address,undefined)
endfunction()

tamga_add_fuzzer(fuzz_json         json_fuzz.c)
tamga_add_fuzzer(fuzz_base64       base64_fuzz.c)
tamga_add_fuzzer(fuzz_pem          pem_fuzz.c)
tamga_add_fuzzer(fuzz_der          der_fuzz.c)
tamga_add_fuzzer(fuzz_license_file license_file_fuzz.c)
tamga_add_fuzzer(fuzz_machine_file machine_file_fuzz.c)
