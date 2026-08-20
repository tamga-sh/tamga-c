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

PROFDATA=$(command -v llvm-profdata || command -v xcrun >/dev/null 2>&1 && echo "xcrun llvm-profdata" || true)
COV=$(command -v llvm-cov || command -v xcrun >/dev/null 2>&1 && echo "xcrun llvm-cov" || true)
if [ -z "$PROFDATA" ] || [ -z "$COV" ]; then
    echo "llvm-profdata and llvm-cov are required" >&2
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
# same static archive, and the merged profile covers all of them.
OBJECT="$BUILD/libtamga.a"
if [ ! -f "$OBJECT" ]; then
    echo "static library not found at $OBJECT" >&2
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
