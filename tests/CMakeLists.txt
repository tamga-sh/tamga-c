# Test suites.
#
# Everything links the STATIC library. The shared library is built with
# hidden visibility, so only the 12 public `tamga_*` entry points are
# reachable through it -- which is exactly what tests/c/ wants (it is the ABI
# gate) but useless for tests/unit/, which exercises internal modules like
# base64 and the JSON parser directly. Static archives keep every symbol
# regardless of the visibility attribute, so one link mode covers both.

# Adds one test executable from one source file. NAME must be unique across
# every suite -- CTest test names are global.
function(tamga_add_test NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    target_link_libraries(${NAME} PRIVATE tamga_static)
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/tests
    )
    target_compile_definitions(${NAME} PRIVATE
        TAMGA_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures"
    )
    tamga_set_warnings(${NAME})
    tamga_apply_sanitizers(${NAME})
    add_test(NAME ${NAME} COMMAND ${NAME})
endfunction()

add_subdirectory(unit)

# tests/c/ is the pre-1.3 C ABI harness. Its source files are kept
# byte-for-byte unmodified across the native rewrite on purpose: if they still
# compile and pass, the ABI genuinely did not break. It is wired in once the
# public entry points exist.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/c/CMakeLists.txt" AND TAMGA_PUBLIC_API_READY)
    add_subdirectory(c)
endif()

if(TAMGA_C_ENABLE_FUZZ)
    add_subdirectory(fuzz)
endif()
