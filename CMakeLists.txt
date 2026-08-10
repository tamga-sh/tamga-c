cmake_minimum_required(VERSION 3.22)

project(tamga_c
    VERSION 0.1.0
    DESCRIPTION "C ABI bindings for the Tamga licensing SDK"
    LANGUAGES C CXX
)

# --- corrosion (Rust <-> CMake bridge) ------------------------------------
# Vendored via FetchContent rather than requiring a system-wide corrosion
# install; see cmake/FetchCorrosion.cmake for the pinned version.
include(cmake/FetchCorrosion.cmake)

# --- Rust crate ------------------------------------------------------------
# Builds this repo's Cargo.toml ([lib] name = "tamga", crate-type =
# ["cdylib", "staticlib"]). corrosion registers a CMake target per Cargo lib
# target, named after `[lib].name` -- i.e. plain `tamga`, NOT this crate's
# `[package].name` (`tamga-c`).
#
# NOTE: this crate's Cargo.toml has a path dependency on ../tamga-rust,
# which does not exist as a real crate yet (see the plan's BLOCKED banner
# and Cargo.toml's comments) -- this corrosion_import_crate() call will fail
# until that's resolved. Scaffolded now so the CMake shape is reviewable
# ahead of that unblock landing.
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

# TODO(Section G): install() the corrosion-built cdylib/staticlib artifacts
# themselves once real cross-platform builds exist to test against --
# likely `install(IMPORTED_RUNTIME_ARTIFACTS tamga_c::tamga_c ...)` (CMake
# 3.21+) alongside an archive/library destination for the staticlib. Left
# as a TODO rather than guessed at, since corrosion's exact artifact target
# properties should be confirmed against the pinned corrosion version
# before writing install() rules that silently install nothing.

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
