#!/usr/bin/env bash
set -euo pipefail

version="$(jq -er '."."' .release-please-manifest.json)"
if [[ ! "$version" =~ ^([0-9]+\.[0-9]+)\.[0-9]+$ ]]; then
  echo "pin-release-minor.sh: .release-please-manifest.json holds '$version', not MAJOR.MINOR.PATCH" >&2
  exit 1
fi
export RELEASE_MINOR="${BASH_REMATCH[1]}"

find README.md examples templates docs -type f \( -name '*.md' -o -name '*.tf' -o -name '*.tmpl' \) -print0 |
  xargs -0 perl -pi -e 's/(version\s*=\s*"~>\s*)\d+\.\d+(?:\.\d+)?"/$1$ENV{RELEASE_MINOR}"/g'
