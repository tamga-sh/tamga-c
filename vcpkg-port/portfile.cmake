# tamga-c vcpkg portfile.
#
# Nothing here fetches a toolchain or a runtime dependency: as of v1.3 the
# library is plain C with no package dependencies. The optional `http` feature
# pulls in libcurl on non-Windows platforms, and nothing at all on Windows,
# where the transport is WinHTTP -- an operating-system component.
#
# Building without the feature still produces a complete offline-verification
# library.

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO tamga-sh/tamga-c
    REF "v${VERSION}"
    SHA512 0
    HEAD_REF main
)

if("http" IN_LIST FEATURES)
    if(VCPKG_TARGET_IS_WINDOWS)
        set(TAMGA_HTTP_BACKEND winhttp)
    else()
        set(TAMGA_HTTP_BACKEND curl)
    endif()
else()
    set(TAMGA_HTTP_BACKEND none)
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DTAMGA_HTTP=${TAMGA_HTTP_BACKEND}
        -DTAMGA_C_BUILD_TESTS=OFF
        -DTAMGA_C_BUILD_EXAMPLES=OFF
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME tamga CONFIG_PATH lib/cmake/tamga)
vcpkg_copy_pdbs()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
