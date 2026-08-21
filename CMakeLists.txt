cmake_minimum_required(VERSION 3.22)

project(tamga
    VERSION 1.3.2 # x-release-please-version
    # CMake's DESCRIPTION is a single line; this is the fleet-wide SDK
    # description, matching vcpkg.json.
    DESCRIPTION "Official C/C++ SDK for Tamga. Integrate license activation, offline verification, and machine management into your C/C++ applications."
    HOMEPAGE_URL "https://github.com/tamga-sh/tamga-c"
    LANGUAGES C
)

# C11 for _Thread_local, _Static_assert, and stdint/stdbool without dialect
# extensions. No compiler extensions: the library must build identically
# under gcc, clang and MSVC.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(GNUInstallDirs)
include(TamgaWarnings)
include(TamgaSanitizers)
include(TamgaHttpBackend)
include(${CMAKE_CURRENT_SOURCE_DIR}/src/sources.cmake)

option(TAMGA_BUILD_SHARED   "Build the shared library in addition to the static one" ON)
option(TAMGA_C_BUILD_TESTS  "Build the test suites"  ON)
option(TAMGA_C_BUILD_EXAMPLES "Build examples/"      OFF)

# --- library targets -------------------------------------------------------
#
# Static and shared are compiled separately rather than sharing an OBJECT
# library: the shared build needs TAMGA_BUILD_SHARED_LIB defined (it drives
# __declspec(dllexport) on Windows and default-visibility elsewhere) while the
# static build must not have it, and sanitizer/coverage instrumentation
# differs between the two on some toolchains. For a project this size the
# duplicate compile is cheaper than the edge cases an OBJECT library
# introduces.
function(tamga_configure_library TARGET)
    target_sources(${TARGET} PRIVATE ${TAMGA_SOURCES})
    target_include_directories(${TARGET}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    set_target_properties(${TARGET} PROPERTIES
        OUTPUT_NAME tamga
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
    tamga_set_warnings(${TARGET})
    tamga_apply_sanitizers(${TARGET})
    tamga_configure_http(${TARGET})
endfunction()

add_library(tamga_static STATIC)
tamga_configure_library(tamga_static)
target_compile_definitions(tamga_static PUBLIC TAMGA_STATIC_LIB=1)

# On Windows a DLL's IMPORT library is also a .lib, and both targets are named
# `tamga` -- so the static library overwrote the shared one's import library,
# and everything linking the DLL then linked the static archive instead and
# failed on unresolved __imp_ symbols. Elsewhere libtamga.a and libtamga.so
# have different extensions and never collide, so the name stays `tamga`
# there.
if(WIN32)
    set_target_properties(tamga_static PROPERTIES OUTPUT_NAME tamga_static)
endif()

if(TAMGA_BUILD_SHARED)
    add_library(tamga_shared SHARED)
    tamga_configure_library(tamga_shared)
    target_compile_definitions(tamga_shared PRIVATE TAMGA_BUILD_SHARED_LIB=1)
    set_target_properties(tamga_shared PROPERTIES
        VERSION   ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

# Consumers link `tamga::tamga`. `tamga_c::tamga_c` is the pre-1.3 alias and
# is kept permanently -- tests/c/ and examples/ still use it, and so may any
# downstream CMake project written against 1.0-1.2.
if(TAMGA_BUILD_SHARED)
    add_library(tamga::tamga     ALIAS tamga_shared)
    add_library(tamga_c::tamga_c ALIAS tamga_shared)
else()
    add_library(tamga::tamga     ALIAS tamga_static)
    add_library(tamga_c::tamga_c ALIAS tamga_static)
endif()
add_library(tamga::tamga_static ALIAS tamga_static)

# --- installation ----------------------------------------------------------
set(TAMGA_INSTALL_TARGETS tamga_static)
if(TAMGA_BUILD_SHARED)
    list(APPEND TAMGA_INSTALL_TARGETS tamga_shared)
endif()

install(TARGETS ${TAMGA_INSTALL_TARGETS}
    EXPORT tamga-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/tamga.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/tamga-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/tamga-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/tamga-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tamga
)
install(EXPORT tamga-targets
    FILE tamga-targets.cmake
    NAMESPACE tamga::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tamga
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/tamga-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/tamga-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tamga
)

# --- subprojects -----------------------------------------------------------
if(TAMGA_C_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(TAMGA_C_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
