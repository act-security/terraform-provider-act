#!/usr/bin/env bash
set -euo pipefail

version="$(jq -er '."."' .release-please-manifest.json)"
export RELEASE_MINOR="${version%.*}"

find README.md examples templates docs -type f \( -name '*.md' -o -name '*.tf' -o -name '*.tmpl' \) -print0 |
  xargs -0 perl -pi -e 's/(version\s*=\s*"~>\s*)\d+\.\d+(?:\.\d+)?"/$1$ENV{RELEASE_MINOR}"/g'
