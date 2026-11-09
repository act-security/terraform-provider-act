#!/usr/bin/env bash
set -euo pipefail
run="${1:?usage: rc-install.sh <CI run id>}"
repo="${RC_REPO:-act-security/terraform-provider-act}"
dest="$(pwd)/.rc"
providers=(registry.terraform.io/act-security/act)

rm -rf "$dest"
mkdir -p "$dest/download"
gh run download "$run" -R "$repo" -n release-candidate -D "$dest/download"

version="$(jq -r .version "$dest/download/metadata.json")"
zip="terraform-provider-act_${version}_$(go env GOOS)_$(go env GOARCH).zip"
(cd "$dest/download" && grep " ${zip}\$" ./*_SHA256SUMS | shasum -a 256 -c -)

for provider in "${providers[@]}"; do
  mkdir -p "$dest/mirror/$provider"
  cp "$dest/download/$zip" "$dest/mirror/$provider/"
done

cat >"$dest/terraformrc" <<RC
provider_installation {
  filesystem_mirror {
    path    = "$dest/mirror"
    include = ["${providers[0]}"]
  }
  direct {
    exclude = ["${providers[0]}"]
  }
}
RC

echo "Installed release candidate $version for $(go env GOOS)/$(go env GOARCH)."
echo "export TF_CLI_CONFIG_FILE=$dest/terraformrc"
echo "Then pin version = \"$version\" for act-security/act and run terraform init."
