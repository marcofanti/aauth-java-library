#!/usr/bin/env bash
# Release this library to Maven Central.
#
# Usage:
#   ./release.sh [--dry-run] <release-version> [next-snapshot-version]
#
# Examples:
#   ./release.sh 0.1.1                  # releases 0.1.1, bumps back to 0.2.0-SNAPSHOT
#   ./release.sh 0.2.0 0.3.0-SNAPSHOT   # explicit next development version
#   ./release.sh --dry-run 0.1.1        # preflight checks only, no changes
#
# One-time setup (Central Portal token, GPG key) is described in RELEASING.md.
set -euo pipefail

usage() {
  grep '^#' "$0" | grep -v '^#!' | sed 's/^# \{0,1\}//' | head -10
  exit 1
}

DRY_RUN=0
if [[ ${1:-} == "--dry-run" ]]; then
  DRY_RUN=1
  shift
fi

VERSION=${1:-}
[[ -n $VERSION ]] || usage
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "ERROR: release version must be X.Y.Z (got: $VERSION)" >&2
  exit 1
}

if [[ $# -ge 2 ]]; then
  NEXT=$2
else
  IFS=. read -r major minor _ <<<"$VERSION"
  NEXT="$major.$((minor + 1)).0-SNAPSHOT"
fi
[[ $NEXT == *-SNAPSHOT ]] || {
  echo "ERROR: next development version must end in -SNAPSHOT (got: $NEXT)" >&2
  exit 1
}

say() { printf '\n==> %s\n' "$*"; }

# --- Preflight checks --------------------------------------------------------

say "Preflight: git state"
[[ $(git branch --show-current) == main ]] || {
  echo "ERROR: releases must run from main (currently on $(git branch --show-current))" >&2
  exit 1
}
git diff-index --quiet HEAD || {
  echo "ERROR: working tree is not clean" >&2
  exit 1
}
git fetch -q origin
[[ $(git rev-parse HEAD) == $(git rev-parse origin/main) ]] || {
  echo "ERROR: local main is not in sync with origin/main" >&2
  exit 1
}
if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then
  echo "ERROR: tag v$VERSION already exists" >&2
  exit 1
fi

say "Preflight: Central Portal credentials"
grep -q '<id>central</id>' ~/.m2/settings.xml || {
  echo "ERROR: no <server><id>central</id> entry in ~/.m2/settings.xml (see RELEASING.md)" >&2
  exit 1
}
if grep -q 'PASTE_TOKEN' ~/.m2/settings.xml; then
  echo "ERROR: ~/.m2/settings.xml still has placeholder token values" >&2
  exit 1
fi

say "Preflight: GPG signing"
if [[ -z ${GPG_TTY:-} ]] && tty -s; then
  GPG_TTY=$(tty)
  export GPG_TTY
fi
echo release-test | gpg --clearsign >/dev/null || {
  echo "ERROR: gpg cannot sign (check pinentry-mac or GPG_TTY; see RELEASING.md)" >&2
  exit 1
}

say "Preflight: build is green (mvn verify)"
mvn -q clean verify

if [[ $DRY_RUN -eq 1 ]]; then
  say "Dry run OK. Would release $VERSION, tag v$VERSION, then bump to $NEXT."
  exit 0
fi

# --- Release -----------------------------------------------------------------

rollback_hint() {
  cat >&2 <<EOF

Release FAILED before completion. To roll back local state:
  git tag -d v$VERSION 2>/dev/null || true
  git reset --hard origin/main
Nothing has been pushed; re-run after fixing the problem.
EOF
}
trap rollback_hint ERR

say "Setting version $VERSION"
mvn -q versions:set -DnewVersion="$VERSION" && mvn -q versions:commit
git commit -aqm "release: $VERSION"
git tag "v$VERSION"

say "Building, signing and uploading to the Central Portal"
mvn clean deploy -Prelease

say "Bumping to $NEXT"
mvn -q versions:set -DnewVersion="$NEXT" && mvn -q versions:commit
git commit -aqm "chore: bump to $NEXT"

say "Pushing main and tags"
git push origin main
git push origin "v$VERSION"

trap - ERR
say "Done. Now press 'Publish' on the validated deployment:"
echo "    https://central.sonatype.com/publishing"
echo "Artifacts sync to Maven Central within about an hour of publishing."
