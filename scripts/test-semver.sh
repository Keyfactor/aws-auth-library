#!/usr/bin/env bash
# Tests the semver logic used in pr-prerelease.yml and release.yml.
# No git repo or network access needed — pass mock tag lists directly.
#
# HOW IT WORKS
# ------------
# The two workflow scripts extract X.Y from the branch name (release-X.Y),
# then query git for existing tags to compute the next version. These functions
# mirror that logic exactly, accepting a newline-separated tag list in place of
# a live git repo so scenarios can be tested without commits or network calls.
#
# ASSUMPTIONS UNDER TEST
# ----------------------
# - Z (patch) = highest non-RC patch for this X.Y + 1. Zero if no releases exist yet.
# - RC int    = count of existing vX.Y.Z-rc.* tags for the computed Z. Zero-based.
# - Tags from other major/minor versions are completely ignored — the grep pattern
#   anchors on the exact X.Y extracted from the branch name.
# - RC tags are invisible to release Z computation (grep -v strips them before sort).
# - sort -V handles double-digit patch numbers correctly (9 < 10, not lexicographic).

PASS=0
FAIL=0

# Mirrors the version logic in pr-prerelease.yml.
# Args: <base-branch e.g. release-1.0> <newline-separated tag list>
compute_rc() {
  local base_branch="$1"
  local tags="$2"

  local XY="${base_branch#release-}"
  local X="${XY%%.*}"
  local Y="${XY##*.}"

  # Find the highest released (non-RC) patch for this X.Y only.
  local LATEST_RELEASE
  LATEST_RELEASE=$(echo "$tags" | grep -E "^v${X}\.${Y}\.[0-9]+" | grep -v -- '-rc\.' | sort -V | tail -1)

  local NEXT_Z
  if [ -z "$LATEST_RELEASE" ]; then
    NEXT_Z=0
  else
    local CURRENT_Z
    CURRENT_Z=$(echo "$LATEST_RELEASE" | sed "s/v${X}\.${Y}\.\([0-9]*\)/\1/")
    NEXT_Z=$((CURRENT_Z + 1))
  fi

  # RC int = how many RC tags already exist for this exact X.Y.Z (0-based).
  local RC_INT
  RC_INT=$(echo "$tags" | grep -E "^v${X}\.${Y}\.${NEXT_Z}-rc\.[0-9]+$" | wc -l | tr -d ' ')

  echo "v${X}.${Y}.${NEXT_Z}-rc.${RC_INT}"
}

# Mirrors the version logic in release.yml.
# Args: <branch e.g. release-1.0> <newline-separated tag list>
compute_release() {
  local branch="$1"
  local tags="$2"

  local XY="${branch#release-}"
  local X="${XY%%.*}"
  local Y="${XY##*.}"

  # RC tags are intentionally excluded — only shipped releases determine next Z.
  local LATEST_RELEASE
  LATEST_RELEASE=$(echo "$tags" | grep -E "^v${X}\.${Y}\.[0-9]+" | grep -v -- '-rc\.' | sort -V | tail -1)

  local NEXT_Z
  if [ -z "$LATEST_RELEASE" ]; then
    NEXT_Z=0
  else
    local CURRENT_Z
    CURRENT_Z=$(echo "$LATEST_RELEASE" | sed "s/v${X}\.${Y}\.\([0-9]*\)/\1/")
    NEXT_Z=$((CURRENT_Z + 1))
  fi

  echo "v${X}.${Y}.${NEXT_Z}"
}

assert() {
  local description="$1"
  local expected="$2"
  local actual="$3"

  if [ "$expected" = "$actual" ]; then
    echo "  PASS  $description"
    ((PASS++))
  else
    echo "  FAIL  $description"
    echo "        expected: $expected"
    echo "        actual:   $actual"
    ((FAIL++))
  fi
}

# ---------------------------------------------------------------------------

echo ""
echo "RC versioning (pr-prerelease.yml logic)"
echo "---------------------------------------"

# Brand-new branch with no prior tags — Z starts at 0, RC int starts at 0.
assert "no existing tags → first RC is rc.0" \
  "v1.0.0-rc.0" \
  "$(compute_rc "release-1.0" "")"

# One released patch exists; next Z must increment past it.
assert "v1.0.0 exists → next RC is v1.0.1-rc.0" \
  "v1.0.1-rc.0" \
  "$(compute_rc "release-1.0" "v1.0.0")"

# One RC already created for the in-progress Z; RC int increments by counting it.
assert "v1.0.0 + v1.0.1-rc.0 exist → next RC is v1.0.1-rc.1" \
  "v1.0.1-rc.1" \
  "$(compute_rc "release-1.0" "$(printf 'v1.0.0\nv1.0.1-rc.0')")"

# Two RCs already exist; confirms count-based increment keeps working past rc.1.
assert "v1.0.0 + rc.0 + rc.1 exist → next RC is v1.0.1-rc.2" \
  "v1.0.1-rc.2" \
  "$(compute_rc "release-1.0" "$(printf 'v1.0.0\nv1.0.1-rc.0\nv1.0.1-rc.1')")"

# Two releases shipped; Z must jump to 2 and RC int resets to 0 for the new Z.
assert "v1.0.0 + v1.0.1 exist → patch increments to v1.0.2-rc.0" \
  "v1.0.2-rc.0" \
  "$(compute_rc "release-1.0" "$(printf 'v1.0.0\nv1.0.1')")"

# Tags from a different minor on the same major must not bleed into this branch.
# v1.1.0 should be invisible when computing versions for release-1.0.
assert "tags from other minor (v1.1.0) don't affect release-1.0" \
  "v1.0.1-rc.0" \
  "$(compute_rc "release-1.0" "$(printf 'v1.0.0\nv1.1.0')")"

# Reverse: v1.0.x tags must not affect release-1.1.
assert "tags from other minor (v1.0.x) don't affect release-1.1" \
  "v1.1.1-rc.0" \
  "$(compute_rc "release-1.1" "$(printf 'v1.0.5\nv1.1.0')")"

# Tags from a completely different major must not affect version computation.
assert "tags from other major (v2.0.5) don't affect release-1.0" \
  "v1.0.0-rc.0" \
  "$(compute_rc "release-1.0" "v2.0.5")"

# Real-world regression scenario: release-2.0 has been shipped alongside release-1.2.
# The v2.x tags must be fully invisible when a PR targets release-1.2.
# The dot in git tag -l "v1.2.*" is literal, so v2.x never matches v1.2.*.
assert "release-1.2 with release-2.0 already shipped → targets v1.2.x only" \
  "v1.2.1-rc.0" \
  "$(compute_rc "release-1.2" "$(printf 'v1.2.0\nv2.0.0\nv2.0.1-rc.0\nv2.0.1')")"

# sort -V must order numerically, not lexicographically (9 < 10, not 9 > 10).
assert "double-digit patch (v1.0.9) → next is v1.0.10-rc.0" \
  "v1.0.10-rc.0" \
  "$(compute_rc "release-1.0" "v1.0.9")"

# Branch name with a non-zero minor to confirm X.Y parsing handles both digits.
assert "release-2.3 branch parses correctly" \
  "v2.3.1-rc.0" \
  "$(compute_rc "release-2.3" "v2.3.0")"

# ---------------------------------------------------------------------------

echo ""
echo "Release versioning (release.yml logic)"
echo "---------------------------------------"

# No prior tags; first release of this branch is Z=0.
assert "no existing tags → first release is v1.0.0" \
  "v1.0.0" \
  "$(compute_release "release-1.0" "")"

# One released patch; next release increments Z.
assert "v1.0.0 exists → next release is v1.0.1" \
  "v1.0.1" \
  "$(compute_release "release-1.0" "v1.0.0")"

# RC tags for the in-progress Z must be ignored; release Z is still based on the
# last non-RC only. Two rc tags present but release should still be v1.0.1.
assert "v1.0.0 + v1.0.1-rc.0 exist → release is v1.0.1 (RC tags ignored)" \
  "v1.0.1" \
  "$(compute_release "release-1.0" "$(printf 'v1.0.0\nv1.0.1-rc.0\nv1.0.1-rc.1')")"

# Two shipped patches; next is Z=2.
assert "v1.0.0 + v1.0.1 exist → next release is v1.0.2" \
  "v1.0.2" \
  "$(compute_release "release-1.0" "$(printf 'v1.0.0\nv1.0.1')")"

# Tags from a different minor must not affect release Z computation.
assert "tags from other minor don't affect release version" \
  "v1.0.1" \
  "$(compute_release "release-1.0" "$(printf 'v1.0.0\nv1.1.5')")"

# Numeric sort: patch 9 → 10, not lexicographic ordering.
assert "double-digit patch (v1.0.9) → next release is v1.0.10" \
  "v1.0.10" \
  "$(compute_release "release-1.0" "v1.0.9")"

# Non-zero minor in branch name parses correctly.
assert "release-2.3 branch parses correctly" \
  "v2.3.1" \
  "$(compute_release "release-2.3" "v2.3.0")"

# ---------------------------------------------------------------------------

echo ""
echo "End-to-end scenario: PR lifecycle"
echo "----------------------------------"
# Simulates a full PR from open to merge, accumulating tags as each workflow
# run would, then verifies the next PR starts from the right RC.

TAGS=""

# PR opened against a branch with no history.
RC1=$(compute_rc "release-1.0" "$TAGS")
assert "PR opened, no prior tags → v1.0.0-rc.0" "v1.0.0-rc.0" "$RC1"
TAGS="$RC1"

# Developer pushes a fix to the open PR; rc int increments.
RC2=$(compute_rc "release-1.0" "$TAGS")
assert "push to open PR → v1.0.0-rc.1" "v1.0.0-rc.1" "$RC2"
TAGS="$(printf '%s\n%s' "$TAGS" "$RC2")"

# Another push; keeps incrementing.
RC3=$(compute_rc "release-1.0" "$TAGS")
assert "second push to open PR → v1.0.0-rc.2" "v1.0.0-rc.2" "$RC3"
TAGS="$(printf '%s\n%s' "$TAGS" "$RC3")"

# PR is merged; release workflow runs with all three RC tags in place.
# RC tags must be ignored — release is v1.0.0, not v1.0.3.
REL=$(compute_release "release-1.0" "$TAGS")
assert "PR merged → v1.0.0" "v1.0.0" "$REL"
TAGS="$(printf '%s\n%s' "$TAGS" "$REL")"

# A subsequent PR opens after the release; Z increments to 1, RC resets to 0.
RC_NEXT=$(compute_rc "release-1.0" "$TAGS")
assert "next PR after release → v1.0.1-rc.0" "v1.0.1-rc.0" "$RC_NEXT"

# ---------------------------------------------------------------------------

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "All $PASS tests passed."
else
  echo "$PASS passed, $FAIL failed."
  exit 1
fi
echo ""
