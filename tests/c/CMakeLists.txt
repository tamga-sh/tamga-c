# CTest harness for tamga-c's C ABI. Pass/fail only -- no coverage counted
# on the C side (C-side coverage tooling isn't part of this stack; see
# CLAUDE.md and docs/plans/tamga-c.plan.md Section I).

enable_testing()

option(TAMGA_C_ENABLE_ASAN "Build the C test harness with AddressSanitizer + UBSan" OFF)

function(tamga_c_add_test NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    target_link_libraries(${NAME} PRIVATE tamga_c::tamga_c)
    target_include_directories(${NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

    if(WIN32)
        # Rust's std/getrandom (and friends, transitively via tamga-rust)
        # link against these Windows system libraries at final-binary-link
        # time when built as a normal `cargo build` binary — Cargo handles
        # that automatically. Here the Rust code is a staticlib linked
        # into a plain CMake/MSVC executable, which bypasses Cargo's own
        # linking step entirely, so these must be listed explicitly or the
        # link fails with "unresolved external symbol __imp_BCryptGenRandom"
        # (and similar, for the others) on windows-latest.
        target_link_libraries(${NAME} PRIVATE bcrypt ntdll userenv ws2_32)
    endif()

    if(TAMGA_C_ENABLE_ASAN)
        # Catches use-after-free/double-free/leaks at the FFI boundary --
        # the #1 bug class for this kind of library (Section F of
        # docs/plans/tamga-c.plan.md). Every handle-returning function
        # needs a matching successful free with zero ASAN leak reports.
        target_compile_options(${NAME} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer -g)
        target_link_options(${NAME} PRIVATE -fsanitize=address,undefined)
    endif()

    add_test(NAME ${NAME} COMMAND ${NAME})
endfunction()

tamga_c_add_test(test_license_file  test_license_file.c)
tamga_c_add_test(test_machine_file  test_machine_file.c)
tamga_c_add_test(test_offline_proof test_offline_proof.c)
