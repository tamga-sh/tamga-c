#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "tamga::tamga_static" for configuration "Release"
set_property(TARGET tamga::tamga_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(tamga::tamga_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libtamga.a"
  )

list(APPEND _cmake_import_check_targets tamga::tamga_static )
list(APPEND _cmake_import_check_files_for_tamga::tamga_static "${_IMPORT_PREFIX}/lib/libtamga.a" )

# Import target "tamga::tamga_shared" for configuration "Release"
set_property(TARGET tamga::tamga_shared APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(tamga::tamga_shared PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libtamga.1.3.0.dylib"
  IMPORTED_SONAME_RELEASE "@rpath/libtamga.1.dylib"
  )

list(APPEND _cmake_import_check_targets tamga::tamga_shared )
list(APPEND _cmake_import_check_files_for_tamga::tamga_shared "${_IMPORT_PREFIX}/lib/libtamga.1.3.0.dylib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
