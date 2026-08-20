# Example programs, built against the public target.
#
# Off by default -- see TAMGA_C_BUILD_EXAMPLES in the parent CMakeLists.
#
# verify_*.c are offline only and link a TAMGA_HTTP=none build unchanged; the
# rest use the HTTP client and need a transport.

function(tamga_add_example NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    target_link_libraries(${NAME} PRIVATE tamga::tamga)
    target_include_directories(${NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
endfunction()

# Offline verification.
tamga_add_example(verify_license       verify_license.c)
tamga_add_example(verify_machine       verify_machine.c)
tamga_add_example(verify_offline_proof verify_offline_proof.c)

# The HTTP client.
tamga_add_example(validate_license     validate_license.c)
tamga_add_example(activate_machine     activate_machine.c)
tamga_add_example(checkout_and_verify  checkout_and_verify.c)
