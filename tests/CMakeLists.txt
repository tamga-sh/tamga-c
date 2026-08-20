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
# A whitebox test compiles the module under test directly instead of linking
# the library, so it can reach static internals without the production code
# having to export a test-only symbol. It gets the library's own sources for
# whatever that module depends on -- never libtamga itself, which would define
# the same non-static symbols twice.
function(tamga_add_whitebox_test NAME SOURCE)
    cmake_parse_arguments(ARG "" "" "DEPS" ${ARGN})
    add_executable(${NAME} ${SOURCE} ${ARG_DEPS})
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
add_subdirectory(integration)
add_subdirectory(http)

# tests/c/ is the pre-1.3 C ABI harness. Its source files are kept
# byte-for-byte unmodified across the native rewrite on purpose: if they still
# compile and pass, the ABI genuinely did not break.
add_subdirectory(c)

if(TAMGA_C_ENABLE_FUZZ)
    # TAMGA_SOURCES is set by src/sources.cmake in the top-level scope; the
    # fuzz targets rebuild the library from it with coverage instrumentation.
    add_subdirectory(fuzz)
endif()
