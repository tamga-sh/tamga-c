# Vendors corrosion-rs/corrosion via CMake FetchContent instead of requiring
# consumers to have it pre-installed system-wide (Section A of
# docs/plans/tamga-c.plan.md).
#
# Pin a tagged release, not a floating branch, so builds stay reproducible.
# Bump TAMGA_C_CORROSION_VERSION deliberately, not as a side effect of an
# unrelated change, and update the tested-version note in README.md (see
# docs/plans/tamga-c.plan.md Section G) when you do.

include(FetchContent)

set(TAMGA_C_CORROSION_VERSION "v0.5.1" CACHE STRING
    "corrosion-rs/corrosion git tag to vendor.")

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG ${TAMGA_C_CORROSION_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(Corrosion)
