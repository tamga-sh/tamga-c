#!/bin/sh
# Line-coverage gate.
#
# Hand-rolled for the same reason everything else here is: a coverage tool
# would be a dependency, and this needs llvm-profdata and llvm-cov, which ship
# with the compiler that produced the instrumented build.
#
# Usage: sh Scripts/check-coverage.sh [threshold] [build-dir]
#
# The build must have been configured with -DTAMGA_C_ENABLE_COVERAGE=ON and
# the tests run, so the .profraw files exist.
set -e

THRESHOLD=${1:-80}
BUILD=${2:-build-cov}

if [ ! -d "$BUILD" ]; then
    echo "no such build directory: $BUILD" >&2
    echo "configure with: cmake -S . -B $BUILD -DTAMGA_C_ENABLE_COVERAGE=ON" >&2
    exit 2
fi

# Written as explicit branches rather than as `command -v X || command -v xcrun
# && echo ...`. That chain parses as ((A || B) && C): on a machine where the
# tool IS on PATH, A prints the path AND C then appends "xcrun llvm-profdata",
# so the variable holds two lines and the command below runs as
# `llvm-profdata xcrun llvm-profdata merge`. It only appeared to work on macOS,
# where A fails and the fallback is what runs.
if command -v llvm-profdata >/dev/null 2>&1; then
    PROFDATA="llvm-profdata"
elif command -v xcrun >/dev/null 2>&1; then
    PROFDATA="xcrun llvm-profdata"
else
    echo "llvm-profdata is required" >&2
    exit 2
fi

if command -v llvm-cov >/dev/null 2>&1; then
    COV="llvm-cov"
elif command -v xcrun >/dev/null 2>&1; then
    COV="xcrun llvm-cov"
else
    echo "llvm-cov is required" >&2
    exit 2
fi

RAW=$(find "$BUILD" -name '*.profraw' 2>/dev/null | tr '\n' ' ')
if [ -z "$RAW" ]; then
    echo "no .profraw files found -- run the tests first:" >&2
    echo "  LLVM_PROFILE_FILE=$BUILD/%p.profraw ctest --test-dir $BUILD" >&2
    exit 2
fi

# shellcheck disable=SC2086
$PROFDATA merge -sparse $RAW -o "$BUILD/coverage.profdata"

# One object is enough for the library's own coverage: every test links the
# same library, and the merged profile covers all of them.
#
# The SHARED library is preferred because llvm-cov cannot read a static
# archive on Linux -- it fails with "coverage mapping header section is larger
# than buffer size". That worked on macOS, where Mach-O archives are handled,
# which is exactly how this gate came to be macOS-only without anyone
# noticing. The static archive stays as the fallback for a
# -DTAMGA_BUILD_SHARED=OFF build, where it is the only thing there is.
OBJECT=""
for candidate in "$BUILD/libtamga.so" "$BUILD/libtamga.dylib" "$BUILD/libtamga.a"; do
    if [ -f "$candidate" ]; then
        OBJECT="$candidate"
        break
    fi
done
if [ -z "$OBJECT" ]; then
    echo "no built library found in $BUILD" >&2
    exit 2
fi

REPORT=$($COV report "$OBJECT" -instr-profile="$BUILD/coverage.profdata" \
    -ignore-filename-regex='(tests|examples)/' 2>/dev/null | tail -1)
echo "$REPORT"

# llvm-cov's summary row carries four percentages, in order: regions,
# functions, LINES, branches. The third is the one this gate is about --
# taking the last would silently measure branch coverage instead.
PERCENT=$(echo "$REPORT" | awk '{
    n = 0
    for (i = 1; i <= NF; i++) {
        if ($i ~ /%$/) {
            n++
            if (n == 3) { sub(/%$/, "", $i); print $i; exit }
        }
    }
}')
if [ -z "$PERCENT" ]; then
    echo "could not read a coverage percentage from llvm-cov" >&2
    exit 2
fi

echo "line coverage: ${PERCENT}% (threshold ${THRESHOLD}%)"
awk -v p="$PERCENT" -v t="$THRESHOLD" 'BEGIN { exit !(p + 0 >= t + 0) }' || {
    echo "coverage below the threshold" >&2
    exit 1
}
echo "coverage gate passed"
