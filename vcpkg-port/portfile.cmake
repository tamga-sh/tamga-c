# NOTE: REF/SHA512 below point at v1.2.0 -- the latest tag as of writing, but
# v1.2.0's CMakeLists.txt only install()s include/tamga.h, not the compiled
# library (fixed in PR #18, "fix: actually install the compiled library, not
# just the header" -- merged after this file was written, not yet part of a
# tagged release). Update REF/SHA512 to the next release once it's out;
# until then this portfile would configure and build correctly but produce a
# package with no library in it, same failure PR #18 fixes upstream.
#
# This crate has zero HTTP surface and depends on a working Rust toolchain
# via corrosion (see cmake/FetchCorrosion.cmake) -- vcpkg has no reliable
# built-in way to provision one, so this port assumes `cargo`/`rustc` are
# already on PATH (matching rustup's normal install), the same precondition
# tamga-c's own CI documents. Document this in the triplet/consumer's own
# setup, don't try to vendor a Rust toolchain download into the port itself.

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO tamga-sh/tamga-c
    REF v1.2.0
    SHA512 0 # TODO: fill in via `vcpkg hash <downloaded-tarball>` once REF points at a release that includes PR #18's install() fix.
    HEAD_REF main
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DTAMGA_C_BUILD_TESTS=OFF
        -DTAMGA_C_BUILD_EXAMPLES=OFF
)

vcpkg_cmake_install()

# corrosion's build always produces both cdylib and staticlib artifacts
# (Cargo.toml's crate-type list, shared across every consumer of this repo --
# see tamga-c/CLAUDE.md's rlib-vs-cdylib gotcha) -- vcpkg's usage-conflict
# checker will otherwise complain about both a static and shared library
# being present for the same port. Default this port to the static
# library only, matching how the other Tamga SDKs consume tamga-c (linked
# in, not loaded as a shared object) -- remove the .dylib/.so instead of
# trying to support a `tamga-c[shared]` feature until a real consumer
# actually needs dynamic linking.
if(EXISTS "${CURRENT_PACKAGES_DIR}/lib/libtamga.dylib")
    file(REMOVE "${CURRENT_PACKAGES_DIR}/lib/libtamga.dylib")
endif()
if(EXISTS "${CURRENT_PACKAGES_DIR}/lib/libtamga.so")
    file(REMOVE "${CURRENT_PACKAGES_DIR}/lib/libtamga.so")
endif()

# vcpkg convention: debug builds don't need a second copy of public headers.
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
