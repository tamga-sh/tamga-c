#!/bin/sh
# Opens a pull request through the checks CI will run, so CI never fails on
# something that was auto-fixable locally.
#
#   sh scripts/mr.sh [target-branch]      (default: main)
#
# There is no package manager in this repository, so this is the entry point —
# see README.md. Never call `gh pr create` or `git push` directly: the push is
# only this script's last step, and calling it directly skips the gate.
set -e
TARGET=${1:-main}
BRANCH=$(git rev-parse --abbrev-ref HEAD)

if [ "$BRANCH" = "$TARGET" ]; then
    echo "Refusing to open a pull request from $TARGET into itself."
    exit 1
fi

# --- 1. Formatting: the auto-fixable check, so it runs first ---------------
echo "Checking formatting..."
FILES=$(find src include tests examples -name '*.c' -o -name '*.h')
if ! clang-format --dry-run --Werror $FILES 2>/dev/null; then
    echo
    echo "Formatting differs from the pinned clang-format."
    echo "  1. python3 -m pip install -r requirements-dev.txt   (exact version CI uses)"
    echo "  2. clang-format -i \$(find src include tests examples -name '*.c' -o -name '*.h')"
    echo "  3. Commit the result and retry."
    echo
    echo "Not fixed automatically on purpose: a formatting change belongs in its"
    echo "own commit, made by you, not folded silently into a push."
    exit 1
fi

# --- 2. Build and test -----------------------------------------------------
echo "Building and testing..."
if ! cmake -S . -B build-mr -DCMAKE_BUILD_TYPE=Debug -DTAMGA_WARNINGS_AS_ERRORS=ON >/dev/null; then
    echo "Configure failed. Fix, commit and retry."
    exit 1
fi
if ! cmake --build build-mr -j8 >/dev/null; then
    echo "Build failed. Fix, commit and retry."
    exit 1
fi
if ! ctest --test-dir build-mr --output-on-failure >/dev/null; then
    ctest --test-dir build-mr --output-on-failure || true
    echo "Tests failed. Fix, commit and retry."
    exit 1
fi

# --- 3. The zero-dependency claim, when the library itself changed ---------
BASE=$(git merge-base HEAD "origin/$TARGET" 2>/dev/null || echo "")
if [ -n "$BASE" ] && git diff --name-only "$BASE"...HEAD 2>/dev/null | grep -qE '^(src|include|cmake|CMakeLists.txt)'; then
    echo "Library sources changed, checking the offline build links libc alone..."
    if ! cmake -S . -B build-mr-none -DTAMGA_HTTP=none >/dev/null || \
       ! cmake --build build-mr-none -j8 >/dev/null; then
        echo "The TAMGA_HTTP=none build failed. That build is the zero-dependency claim."
        exit 1
    fi
    ctest --test-dir build-mr-none >/dev/null || { echo "Offline-build tests failed."; exit 1; }
fi

# --- 4. The pull-request title ---------------------------------------------
#
# This repository squashes, and its squash_merge_commit_title is
# COMMIT_OR_PR_TITLE — so for a multi-commit branch GitHub writes the PR TITLE
# as the squashed commit message, and that single line is the whole of what
# release-please sees. A branch full of feat: work behind a chore: title
# squashes into a chore: commit on main and skips the release entirely.
#
# So the title is derived, not typed: the highest semver-relevant conventional
# type actually present in the branch wins, and that commit's own subject
# becomes the title. Same rule as the GitLab-side `git mr`.
echo "Deriving the pull-request title..."
SUBJECT=""
for TYPE in breaking feat fix perf refactor docs style test chore ci build revert; do
    if [ "$TYPE" = "breaking" ]; then
        SUBJECT=$(git log --format='%s' "$TARGET"..HEAD | grep -E '^[a-z]+(\([^)]*\))?!:' | tail -1 || true)
    else
        SUBJECT=$(git log --format='%s' "$TARGET"..HEAD | grep -E "^$TYPE(\([^)]*\))?: " | tail -1 || true)
    fi
    [ -n "$SUBJECT" ] && break
done
if [ -z "$SUBJECT" ]; then
    echo "No conventional-commit subject found on this branch; refusing to guess a title."
    exit 1
fi
DERIVED_TYPE=$TYPE

# MR_TITLE overrides the derived subject -- a branch's first feat: is often a
# worse summary than one written by hand. It may not weaken the release,
# though: the override has to be conventional-commit shaped and carry a type
# at least as semver-significant as the one the branch actually contains, so
# it can improve the wording and never silently downgrade feat: to chore:.
if [ -n "$MR_TITLE" ]; then
    if ! printf '%s' "$MR_TITLE" | grep -qE '^[a-z]+(\([^)]*\))?!?: .+'; then
        echo "MR_TITLE is not a conventional commit subject: $MR_TITLE"
        exit 1
    fi
    OVERRIDE_TYPE=$(printf '%s' "$MR_TITLE" | sed -nE 's/^([a-z]+).*/\1/p')
    printf '%s' "$MR_TITLE" | grep -qE '^[a-z]+(\([^)]*\))?!:' && OVERRIDE_TYPE=breaking
    RANK() {
        case $1 in
            breaking) echo 0 ;; feat) echo 1 ;; fix) echo 2 ;; perf) echo 3 ;;
            refactor) echo 4 ;; docs) echo 5 ;; style) echo 6 ;; test) echo 7 ;;
            chore) echo 8 ;; ci) echo 9 ;; build) echo 10 ;; revert) echo 11 ;;
            *) echo 99 ;;
        esac
    }
    if [ "$(RANK "$OVERRIDE_TYPE")" -gt "$(RANK "$DERIVED_TYPE")" ]; then
        echo "MR_TITLE's type '$OVERRIDE_TYPE' is weaker than the '$DERIVED_TYPE' this branch"
        echo "actually contains. Squashing under it would drop the release."
        exit 1
    fi
    SUBJECT=$MR_TITLE
fi
echo "  title: $SUBJECT"

echo "All checks passed."
git push -u origin "$BRANCH"

# MR_BODY_FILE=path to supply a written description; without it the body is
# filled from the branch's commit messages rather than left empty.
if [ -n "$MR_BODY_FILE" ] && [ -f "$MR_BODY_FILE" ]; then
    gh pr create --base "$TARGET" --head "$BRANCH" --title "$SUBJECT" --body-file "$MR_BODY_FILE"
else
    gh pr create --base "$TARGET" --head "$BRANCH" --title "$SUBJECT" --fill-verbose
fi
