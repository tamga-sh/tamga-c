# HTTP transport backend selection.
#
# The library's offline-verification core has no dependencies at all -- not
# even a TLS stack. HTTP is the only part that needs one, and TLS is the one
# thing this project will not hand-roll, so the backend comes from whatever
# the operating system already ships:
#
#   winhttp  Windows. winhttp.dll is an OS component; winhttp.lib ships with
#            the Windows SDK. Nothing to install.
#   curl     macOS and Linux. macOS ships libcurl in the base system; on Linux
#            it is present on essentially every non-minimal image. Found via
#            CMake's own FindCURL.
#   none     No built-in backend at all. src/http/ is still compiled (the
#            client, the models, the retry policy and the JSON:API error model
#            are all transport-agnostic), but no transport is registered, and
#            the caller must supply one via tamga_client_set_transport().
#            The resulting library links against libc and nothing else --
#            this is the configuration CI asserts the zero-dependency claim
#            against.
#
# TAMGA_HTTP=auto (the default) picks winhttp on Windows, curl elsewhere when
# it is found, and falls back to none with a status message rather than a hard
# error -- a machine without libcurl can still build and use the entire
# offline surface.

set(TAMGA_HTTP "auto" CACHE STRING "HTTP transport backend: auto|winhttp|curl|none")
set_property(CACHE TAMGA_HTTP PROPERTY STRINGS auto winhttp curl none)

set(TAMGA_HTTP_BACKEND "none" CACHE INTERNAL "Resolved HTTP backend")

if(TAMGA_HTTP STREQUAL "auto")
    if(WIN32)
        set(TAMGA_HTTP_BACKEND "winhttp" CACHE INTERNAL "Resolved HTTP backend")
    else()
        find_package(CURL QUIET)
        if(CURL_FOUND)
            set(TAMGA_HTTP_BACKEND "curl" CACHE INTERNAL "Resolved HTTP backend")
        else()
            message(STATUS
                "tamga: libcurl not found -- building with no built-in HTTP backend. "
                "The offline surface is fully available; supply a transport via "
                "tamga_client_set_transport() to use the HTTP client.")
            set(TAMGA_HTTP_BACKEND "none" CACHE INTERNAL "Resolved HTTP backend")
        endif()
    endif()
elseif(TAMGA_HTTP STREQUAL "winhttp")
    if(NOT WIN32)
        message(FATAL_ERROR "TAMGA_HTTP=winhttp is only available on Windows.")
    endif()
    set(TAMGA_HTTP_BACKEND "winhttp" CACHE INTERNAL "Resolved HTTP backend")
elseif(TAMGA_HTTP STREQUAL "curl")
    find_package(CURL REQUIRED)
    set(TAMGA_HTTP_BACKEND "curl" CACHE INTERNAL "Resolved HTTP backend")
elseif(TAMGA_HTTP STREQUAL "none")
    set(TAMGA_HTTP_BACKEND "none" CACHE INTERNAL "Resolved HTTP backend")
else()
    message(FATAL_ERROR "Unknown TAMGA_HTTP value '${TAMGA_HTTP}'. Expected auto|winhttp|curl|none.")
endif()

message(STATUS "tamga: HTTP backend = ${TAMGA_HTTP_BACKEND}")

# Captured while this module is being included, which happens from the top
# level. CMAKE_CURRENT_SOURCE_DIR inside the function below would be the
# CALLER's directory instead, so a call from tests/ pointed target_sources at
# a path that does not exist -- and because a static archive does not resolve
# its symbols, that produced a library with an undefined
# tamga_http_transport_create_curl rather than an error.
set(TAMGA_PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}" CACHE INTERNAL "tamga source root")

# Adds the backend's sources, compile definitions and link libraries to one
# library target.
function(tamga_configure_http TARGET)
    if(TAMGA_HTTP_BACKEND STREQUAL "winhttp")
        target_sources(${TARGET} PRIVATE ${TAMGA_PROJECT_ROOT}/src/http/transport_winhttp.c)
        target_compile_definitions(${TARGET} PRIVATE TAMGA_HTTP_WINHTTP=1)
        target_link_libraries(${TARGET} PRIVATE winhttp)
    elseif(TAMGA_HTTP_BACKEND STREQUAL "curl")
        target_sources(${TARGET} PRIVATE ${TAMGA_PROJECT_ROOT}/src/http/transport_curl.c)
        target_compile_definitions(${TARGET} PRIVATE TAMGA_HTTP_CURL=1)
        target_link_libraries(${TARGET} PRIVATE CURL::libcurl)
    else()
        target_compile_definitions(${TARGET} PRIVATE TAMGA_HTTP_NONE=1)
    endif()
endfunction()
