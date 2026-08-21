#!/bin/sh
# Puts a branch through the checks CI will run, so CI never fails on something
# that was auto-fixable locally, then opens a pull request for it -- or pushes
# to the one it already has.
#
#   sh Scripts/mr.sh [target-branch]
#
# Target defaults to the pull request's own base when one is open, and to
# main otherwise. Note the capital S: it is the only capitalised top-level
# directory here, and a lowercase scripts/ resolves on macOS but not Linux.
#
# There is no package manager in this repository, so this is the entry point --
# see README.md. Never call `gh pr create` or `git push` directly: the push is
# only this script's last step, and calling it directly skips the gate.
#
# Two paths, because a branch spends most of its life in the second one:
#
#   no open PR -- run the checks, push, create the pull request.
#   open PR    -- run the SAME checks, push to it, and leave it alone.
#
# The update path exists because without it the gate quietly stopped applying
# exactly when a branch was being revised. `gh pr create` fails against a
# branch that already has an open pull request, so the only way to update one
# was the raw `git push` this script tells you never to use -- which is to say
# the gate only ever covered a branch's first push. It now covers every push.
set -e

# Whether a target branch was actually typed, as opposed to defaulted. On the
# update path an explicit argument is a claim to be checked against the pull
# request rather than a value to be used.
TARGET_GIVEN=0
[ $# -ge 1 ] && TARGET_GIVEN=1
TARGET=${1:-main}
BRANCH=$(git rev-parse --abbrev-ref HEAD)

if [ "$BRANCH" = "$TARGET" ]; then
    echo "Refusing to open a pull request from $TARGET into itself."
    exit 1
fi

# Conventional-commit types, ordered by how much of a release each one causes.
# Used to derive a title and, on the update path, to refuse a title that would
# release less than the branch's commits deserve.
RANK() {
    case $1 in
        breaking) echo 0 ;; feat) echo 1 ;; fix) echo 2 ;; perf) echo 3 ;;
        refactor) echo 4 ;; docs) echo 5 ;; style) echo 6 ;; test) echo 7 ;;
        chore) echo 8 ;; ci) echo 9 ;; build) echo 10 ;; revert) echo 11 ;;
        *) echo 99 ;;
    esac
}

# --- 0. The pull request this branch already has, if any -------------------
#
# Looked up before the checks run so that the target branch is settled before
# anything depends on it. A stacked branch's base is the commonest thing for
# the default to get wrong, and both the zero-dependency check and the title
# derivation below are computed against it.
PR_NUMBER=""
PR_BASE=""
PR_TITLE=""
EXISTING=$(gh pr list --head "$BRANCH" --state open \
           --json number,baseRefName,title \
           --jq '.[0] | select(. != null) | "\(.number)\t\(.baseRefName)\t\(.title)"' \
           2>/dev/null || true)
if [ -n "$EXISTING" ]; then
    PR_NUMBER=$(printf '%s' "$EXISTING" | cut -f1)
    PR_BASE=$(printf '%s' "$EXISTING" | cut -f2)
    PR_TITLE=$(printf '%s' "$EXISTING" | cut -f3)

    if [ "$TARGET_GIVEN" = "1" ] && [ "$TARGET" != "$PR_BASE" ]; then
        echo "Pull request #$PR_NUMBER targets $PR_BASE, but $TARGET was given."
        echo
        echo "Refusing to guess which one you meant. Either drop the argument to"
        echo "use the pull request's own base, or retarget it first:"
        echo "  gh pr edit $PR_NUMBER --base $TARGET"
        exit 1
    fi
    # The pull request is the authority on its own base -- more so than this
    # script's `main` default, which is wrong for every stacked branch.
    TARGET=$PR_BASE
    echo "Updating pull request #$PR_NUMBER ($BRANCH -> $TARGET)."
else
    echo "No open pull request for $BRANCH; one will be created against $TARGET."
fi

# The commit range every step below is computed over. A stacked base often
# exists only as a remote ref, and `git log missing-branch..HEAD` would abort
# the script under `set -e` with nothing explaining why.
if git rev-parse --verify --quiet "$TARGET" >/dev/null 2>&1; then
    RANGE_BASE=$TARGET
elif git rev-parse --verify --quiet "origin/$TARGET" >/dev/null 2>&1; then
    RANGE_BASE=origin/$TARGET
else
    echo "Cannot resolve '$TARGET' locally or as origin/$TARGET."
    echo "Fetch it first:  git fetch origin $TARGET"
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
BASE=$(git merge-base HEAD "$RANGE_BASE" 2>/dev/null || echo "")
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
        SUBJECT=$(git log --format='%s' "$RANGE_BASE"..HEAD | grep -E '^[a-z]+(\([^)]*\))?!:' | tail -1 || true)
    else
        SUBJECT=$(git log --format='%s' "$RANGE_BASE"..HEAD | grep -E "^$TYPE(\([^)]*\))?: " | tail -1 || true)
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
    if [ "$(RANK "$OVERRIDE_TYPE")" -gt "$(RANK "$DERIVED_TYPE")" ]; then
        echo "MR_TITLE's type '$OVERRIDE_TYPE' is weaker than the '$DERIVED_TYPE' this branch"
        echo "actually contains. Squashing under it would drop the release."
        exit 1
    fi
    SUBJECT=$MR_TITLE
fi
if [ -n "$PR_NUMBER" ]; then
    # Printed, not applied: on the update path this is only the yardstick the
    # drift check below measures the existing title against.
    echo "  branch contains: $SUBJECT"
    echo "  title (unchanged): $PR_TITLE"
else
    echo "  title: $SUBJECT"
fi

# On the update path the title is already set and is not ours to rewrite -- it
# may well have been written by hand, and this script auto-fixes nothing. But
# a title cannot be allowed to UNDER-release: a branch that has since gained a
# feat: commit behind a title that still says fix: squashes onto main as a
# fix:, and release-please cuts a patch for a minor change. Same rule the
# MR_TITLE override obeys above, applied to a title that drifted rather than
# one that was typed.
if [ -n "$PR_NUMBER" ]; then
    PR_TYPE=$(printf '%s' "$PR_TITLE" | sed -nE 's/^([a-z]+).*/\1/p')
    printf '%s' "$PR_TITLE" | grep -qE '^[a-z]+(\([^)]*\))?!:' && PR_TYPE=breaking
    if [ "$(RANK "$PR_TYPE")" -gt "$(RANK "$DERIVED_TYPE")" ]; then
        echo
        echo "Pull request #$PR_NUMBER is titled:"
        echo "  $PR_TITLE"
        echo "but this branch now contains '$DERIVED_TYPE' work:"
        echo "  $SUBJECT"
        echo
        echo "This repository squashes and takes the commit message from the pull"
        echo "request title, so pushing under the current one would release less"
        echo "than the branch actually contains. Retitle it, then retry:"
        echo "  gh pr edit $PR_NUMBER --title \"$SUBJECT\""
        exit 1
    fi
fi

echo "All checks passed."
git push -u origin "$BRANCH"

if [ -n "$PR_NUMBER" ]; then
    # Already open: the push above IS the update. Creating a second pull
    # request for the same branch is what `gh pr create` would attempt, and it
    # fails -- which is how this path came to be skipped entirely.
    echo "Pushed to pull request #$PR_NUMBER."
    gh pr view "$PR_NUMBER" --json url --jq .url
    exit 0
fi

# MR_BODY_FILE=path to supply a written description; without it the body is
# filled from the branch's commit messages rather than left empty.
if [ -n "$MR_BODY_FILE" ] && [ -f "$MR_BODY_FILE" ]; then
    gh pr create --base "$TARGET" --head "$BRANCH" --title "$SUBJECT" --body-file "$MR_BODY_FILE"
else
    gh pr create --base "$TARGET" --head "$BRANCH" --title "$SUBJECT" --fill-verbose
fi
