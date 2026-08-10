# Builds the example programs against the tamga_c::tamga_c CMake target.
# Off by default (see the parent CMakeLists.txt's TAMGA_C_BUILD_EXAMPLES
# option) -- each is a real, working CLI wrapping one FFI entry point; see
# each example source file's header comment for its usage string.

function(tamga_c_add_example NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    target_link_libraries(${NAME} PRIVATE tamga_c::tamga_c)
    target_include_directories(${NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
endfunction()

tamga_c_add_example(verify_license        verify_license.c)
tamga_c_add_example(verify_machine        verify_machine.c)
tamga_c_add_example(verify_offline_proof  verify_offline_proof.c)
