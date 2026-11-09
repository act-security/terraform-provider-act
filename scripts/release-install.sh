#!/usr/bin/env bash
set -euo pipefail
: "${VERSION:?VERSION is required}"
: "${TOOL:?TOOL is required}"
: "${KEY_ID:?KEY_ID is required}"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION $VERSION is not a release version" >&2
  exit 1
fi
case "$TOOL" in
  opentofu*) bin=tofu; minutes=60 ;;
  terraform*) bin=terraform; minutes=30 ;;
  *) echo "unknown TOOL $TOOL" >&2; exit 1 ;;
esac
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
cat >"$root/main.tf" <<HCL
terraform {
  required_providers {
    act = {
      source  = "act-security/act"
      version = "= $VERSION"
    }
  }
}
HCL
deadline=$(( $(date +%s) + minutes * 60 ))
while :; do
  if out="$(cd "$root" && mise exec "$TOOL" -- "$bin" init -input=false -no-color 2>&1)"; then
    echo "$out"
    if grep -q "key ID $KEY_ID" <<<"$out"; then
      exit 0
    fi
    echo "the provider installed, but not with signing key $KEY_ID" >&2
    exit 1
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "$out" >&2
    echo "act-security/act $VERSION did not install within $minutes minutes" >&2
    exit 1
  fi
  sleep 60
done
