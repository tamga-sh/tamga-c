/*
 * tamga_compat.h -- the complete set of platform differences this library
 * cares about.
 *
 * Kept to one small header on purpose. Every #ifdef in the codebase that is
 * about "which compiler/OS is this" belongs here; the rest of src/ is written
 * as if there were only one platform. The exceptions are the HTTP transport
 * backends (src/http/transport_*.c), which are whole-file platform
 * implementations selected by CMake rather than conditional code.
 */
#ifndef TAMGA_COMPAT_H
#define TAMGA_COMPAT_H

#include <stddef.h>

/* --- thread-local storage ------------------------------------------------
 *
 * Backs the per-thread last-error slot. C11 spells this `_Thread_local`;
 * MSVC only accepted it from VS2019 16.8 with /std:c11, and older toolchains
 * in the wild still need __declspec(thread), so both spellings stay.
 */
#if defined(_MSC_VER)
#define TAMGA_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define TAMGA_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define TAMGA_THREAD_LOCAL __thread
#else
#error "tamga requires thread-local storage support"
#endif

/* --- symbol visibility ---------------------------------------------------
 *
 * The library is built with hidden visibility; TAMGA_API is what re-exports
 * the 12 public entry points. On Windows the shared build needs dllexport and
 * a consumer of the DLL needs dllimport, which is why TAMGA_STATIC_LIB (set
 * as a PUBLIC define on the static target) and TAMGA_BUILD_SHARED_LIB (set
 * PRIVATE while compiling the DLL) are distinct.
 */
#if defined(_WIN32) && !defined(TAMGA_STATIC_LIB)
#if defined(TAMGA_BUILD_SHARED_LIB)
#define TAMGA_API __declspec(dllexport)
#else
#define TAMGA_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define TAMGA_API __attribute__((visibility("default")))
#else
#define TAMGA_API
#endif

/* --- attributes ---------------------------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
#define TAMGA_PRINTF(fmt_index, first_arg) __attribute__((format(printf, fmt_index, first_arg)))
#define TAMGA_NODISCARD __attribute__((warn_unused_result))
#else
#define TAMGA_PRINTF(fmt_index, first_arg)
#define TAMGA_NODISCARD
#endif

#define TAMGA_UNUSED(x) ((void)(x))

/* Number of elements in a true array. Deliberately not usable on a pointer:
 * the division would silently produce a wrong answer, and this idiom is used
 * in the crypto known-answer tables where that would be a real bug. */
#define TAMGA_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#endif /* TAMGA_COMPAT_H */
