# The pre-1.3 C ABI harness, kept as the compatibility gate.
#
# The three test_*.c sources here are byte-for-byte unchanged across the
# native rewrite, fixtures included: they were written against v1.x's public
# header and nothing else. If they still compile and pass, the ABI genuinely
# did not break -- which is a stronger statement than any assertion this
# rewrite could make about itself.
#
# They link the SHARED library on purpose. It is built with hidden visibility,
# so only the exported entry points are reachable through it; a test that
# accidentally reached an internal symbol would not be testing the ABI.

function(tamga_add_abi_test NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    if(TARGET tamga_shared)
        target_link_libraries(${NAME} PRIVATE tamga_shared)
    else()
        target_link_libraries(${NAME} PRIVATE tamga_static)
    endif()
    target_include_directories(${NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    tamga_apply_sanitizers(${NAME})
    add_test(NAME ${NAME} COMMAND ${NAME})
endfunction()

# Deliberately not run through tamga_set_warnings: these sources are frozen
# artefacts of the previous release, and holding them to warning settings
# written after they were would mean editing them, which defeats the point.
tamga_add_abi_test(test_license_file_abi  test_license_file.c)
tamga_add_abi_test(test_machine_file_abi  test_machine_file.c)
tamga_add_abi_test(test_offline_proof_abi test_offline_proof.c)

# Written for 1.3: asserts the frozen numeric values and the presence of every
# exported symbol, so a future edit to the header cannot quietly renumber an
# error code the way an appended one may not.
add_executable(test_abi_surface abi_surface_test.c)
if(TARGET tamga_shared)
    target_link_libraries(test_abi_surface PRIVATE tamga_shared)
else()
    target_link_libraries(test_abi_surface PRIVATE tamga_static)
endif()
target_include_directories(test_abi_surface PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/tests)
tamga_set_warnings(test_abi_surface)
tamga_apply_sanitizers(test_abi_surface)
add_test(NAME test_abi_surface COMMAND test_abi_surface)
