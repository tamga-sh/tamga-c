# NOTE: REF/SHA512 below point at v1.2.1, the first tag whose CMakeLists.txt
# install()s the compiled library alongside include/tamga.h. Keep REF, SHA512
# and vcpkg.json's "version" in lockstep when bumping to a later release --
# regenerate the hash with `vcpkg hash <downloaded-tarball>`.
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
    REF v1.2.1
    SHA512 cc9b1ce06a70ee7e33e0d28bb90a6a0a38e2f056b278357bb2885ff0a97d90dcc5f3f11fd8932e9ed76da6383dd9c0a5e7959be92233463a3c72dfe250ce237d
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
