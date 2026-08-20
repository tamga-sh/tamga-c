
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was tamga-config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

include(CMakeFindDependencyMacro)

# Only the curl backend leaves a link-time dependency for a consumer to
# resolve; WinHTTP is a Windows system library and the `none` backend has none.
if("curl" STREQUAL "curl")
    find_dependency(CURL)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/tamga-targets.cmake")

# The export contains tamga::tamga_shared and/or tamga::tamga_static, named
# after the real targets. `tamga::tamga` is the name consumers are told to
# link, and it has to be created here: an ALIAS in the build tree does not
# travel through install(EXPORT), so a find_package consumer would otherwise
# get "target not found" from a package that installed cleanly.
#
# tamga_c::tamga_c is the pre-1.3 spelling, kept so a project written against
# 1.0-1.2 still configures.
foreach(_tamga_alias tamga::tamga tamga_c::tamga_c)
    if(NOT TARGET ${_tamga_alias})
        add_library(${_tamga_alias} INTERFACE IMPORTED)
        if(TARGET tamga::tamga_shared)
            set_target_properties(${_tamga_alias} PROPERTIES
                INTERFACE_LINK_LIBRARIES tamga::tamga_shared)
        elseif(TARGET tamga::tamga_static)
            set_target_properties(${_tamga_alias} PROPERTIES
                INTERFACE_LINK_LIBRARIES tamga::tamga_static)
        else()
            message(FATAL_ERROR "tamga: the installed package exports no library target")
        endif()
    endif()
endforeach()
unset(_tamga_alias)

check_required_components(tamga)
