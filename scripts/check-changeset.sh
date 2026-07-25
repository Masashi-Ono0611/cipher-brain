#!/usr/bin/env bash
# Issue #227 part 1: a PR that changes SHIPPED code (src/) must carry a changeset,
# so `changeset version` can generate the CHANGELOG entry and the version bump
# rather than someone hand-writing both at release time and, in practice,
# forgetting (CHANGELOG.md has been touched exactly once since it was created).
#
# Scoped to src/ deliberately: CI, docs, scripts and test-only changes reach no
# user, and demanding a changeset for them would train people to write empty ones.
# `bun run changeset --empty` is the documented escape hatch for a src/ change that
# genuinely ships nothing user-visible (a comment, a pure internal refactor).
#
# Usage: bash scripts/check-changeset.sh <base-ref>   (e.g. origin/main)
# Exits 0 when no changeset is needed or one is present, 1 when one is missing.
# Follows rules/shell-ops discipline: explicit FAIL + exit 1, no `cond && echo PASS`.
set -u

BASE="${1:-origin/main}"

if ! git rev-parse --verify "$BASE" >/dev/null 2>&1; then
  echo "[FAIL] base ref '$BASE' not found — this check needs the merge base (fetch-depth: 0)"
  exit 1
fi

# ...HEAD (three dots) = changed since the MERGE BASE, so commits that landed on the
# base branch after this one forked are not counted as this PR's changes.
CHANGED="$(git diff --name-only "$BASE...HEAD")"

if ! printf '%s\n' "$CHANGED" | grep -q '^src/'; then
  echo "[PASS] no src/ changes in this diff — no changeset required"
  exit 0
fi

# .changeset/README.md and config.json are the tool's own files, not changesets.
if printf '%s\n' "$CHANGED" | grep -Eq '^\.changeset/[^/]+\.md$' &&
  printf '%s\n' "$CHANGED" | grep -E '^\.changeset/[^/]+\.md$' | grep -qvx '.changeset/README.md'; then
  FOUND="$(printf '%s\n' "$CHANGED" | grep -E '^\.changeset/[^/]+\.md$' | grep -vx '.changeset/README.md' | tr '\n' ' ')"
  echo "[PASS] src/ changed and this PR adds a changeset: $FOUND"
  exit 0
fi

echo "[FAIL] this PR changes src/ but adds no changeset."
echo
echo "  Run one of these, commit the generated .changeset/*.md, and push:"
echo "    bun run changeset           # describe the user-visible change (patch/minor/major)"
echo "    bun run changeset --empty   # the change ships nothing user-visible"
echo
echo "  src/ files changed in this PR:"
printf '%s\n' "$CHANGED" | grep '^src/' | sed 's/^/    /'
exit 1
