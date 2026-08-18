cmake_minimum_required(VERSION 3.22)

project(tamga_c
    VERSION 0.1.0
    # CMake's DESCRIPTION is a single line; this is the fleet-wide SDK
    # description, matching Cargo.toml and vcpkg.json.
    DESCRIPTION "Official C/C++ SDK for Tamga. Integrate license activation, offline verification, and machine management into your C/C++ applications."
    LANGUAGES C CXX
)

# --- corrosion (Rust <-> CMake bridge) ------------------------------------
# Vendored via FetchContent rather than requiring a system-wide corrosion
# install; see cmake/FetchCorrosion.cmake for the pinned version.
include(cmake/FetchCorrosion.cmake)

# --- Rust crate ------------------------------------------------------------
# Builds this repo's Cargo.toml ([lib] name = "tamga", crate-type =
# ["cdylib", "staticlib", "rlib"]). corrosion registers a CMake target per
# Cargo lib target, named after `[lib].name` -- i.e. plain `tamga`, NOT this
# crate's `[package].name` (`tamga-c`).
corrosion_import_crate(MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml)

# Namespaced ALIAS so downstream consumers always link via
# `tamga_c::tamga_c`, regardless of the underlying Cargo target name --
# matches the CMake package::target convention (e.g. `fmt::fmt`,
# `nlohmann_json::nlohmann_json`) and insulates consumers from a rename of
# [lib].name.
if(TARGET tamga)
    add_library(tamga_c::tamga_c ALIAS tamga)
endif()

# --- Installation ------------------------------------------------------
include(GNUInstallDirs)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/tamga.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Plain `install(TARGETS tamga_c::tamga_c ...)` does NOT work here -- the
# targets corrosion_import_crate() exports are an INTERFACE library wrapping
# internal IMPORTED SHARED/STATIC targets, and CMake's own install(TARGETS)
# does not know how to install an IMPORTED target's artifacts.
#
# corrosion's own corrosion_install() looks like the documented answer (see
# https://corrosion-rs.github.io/corrosion/usage.html) but is genuinely
# broken for library crates in the pinned version -- read its actual
# implementation (cmake/FetchCorrosion.cmake pins the version; see
# Corrosion.cmake's corrosion_install() body) and it only ever installs
# targets where `get_property(... PROPERTY TYPE)` equals EXECUTABLE; there
# is no branch for STATIC_LIBRARY/SHARED_LIBRARY at all, so
# corrosion_install(TARGETS tamga) silently installs nothing for a
# cdylib/staticlib crate -- confirmed empirically (built libtamga.a and
# libtamga.dylib existed in the build dir, cmake --install copied neither)
# before reading the source and finding why. EXPORT is separately listed as
# "not yet implemented" and hard-errors if used.
#
# Installing the real underlying IMPORTED targets directly instead --
# corrosion names these <crate>-static / <crate>-shared internally (see
# Corrosion.cmake's add_library(${target_name}-static STATIC IMPORTED ...)
# and the -shared equivalent), which DO support $<TARGET_FILE:...> like any
# normal IMPORTED library target.
if(TARGET tamga-static)
    install(FILES $<TARGET_FILE:tamga-static> DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
if(TARGET tamga-shared)
    install(FILES $<TARGET_FILE:tamga-shared> DESTINATION ${CMAKE_INSTALL_LIBDIR})
    if(WIN32)
        install(FILES $<TARGET_LINKER_FILE:tamga-shared> DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()
endif()

# --- Subprojects -------------------------------------------------------
option(TAMGA_C_BUILD_TESTS "Build the tests/c/ CTest harness" ON)
option(TAMGA_C_BUILD_EXAMPLES "Build examples/" OFF)

if(TAMGA_C_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests/c)
endif()

if(TAMGA_C_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
