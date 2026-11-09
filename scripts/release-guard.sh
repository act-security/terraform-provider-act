#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 0 ]; then
  echo "usage: release-guard.sh <provider binary>..." >&2
  exit 2
fi
forbidden=()
if [ -n "${RELEASE_GUARD_FORBIDDEN:-}" ]; then
  read -r -a forbidden <<<"$RELEASE_GUARD_FORBIDDEN"
fi
status=0
for bin in "$@"; do
  info="$(go version -m "$bin")"
  if grep -Eq $'^\tbuild\t-tags=.*actinternal' <<<"$info"; then
    echo "$bin was built with the actinternal tag" >&2
    status=1
  fi
  if ! grep -q $'^\tbuild\tCGO_ENABLED=0$' <<<"$info"; then
    echo "$bin was not built with CGO_ENABLED=0" >&2
    status=1
  fi
  if ! grep -q $'^\tbuild\t-trimpath=true$' <<<"$info"; then
    echo "$bin was not built with -trimpath" >&2
    status=1
  fi
  if grep -aqF ACT_ALLOW_UNSAFE_ENDPOINT "$bin"; then
    echo "$bin reads ACT_ALLOW_UNSAFE_ENDPOINT" >&2
    status=1
  fi
  for needle in ${forbidden[@]+"${forbidden[@]}"}; do
    if grep -aqiF -- "$needle" "$bin"; then
      echo "$bin contains a forbidden string" >&2
      status=1
    fi
  done
done
exit "$status"
