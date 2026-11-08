#!/usr/bin/env bash
set -euo pipefail
state=$1
pool=$2
bundle=$3
target=$4
key=$5
key_home=$6
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
arch=$(jq -r .arch "$state/expected.json")
app=$(jq -r .app "$state/expected.json")
ref=$(jq -r .ref "$state/expected.json")
commit=$(jq -r .commit "$state/expected.json")
sha256sum --check --status "$state/entry.sha256"
[[ $(sha256sum "$bundle" | cut -d ' ' -f 1) == "$(jq -r .bundle_sha256 "$state/expected.json")" ]]
ostree --repo="$target" init --mode=archive-z2
cp "$state/config" "$target/config"
cp "$pool/summary" "$pool/summary.sig" "$pool/summary.idx" "$pool/summary.idx.sig" "$target/"
cp -a "$pool/summaries" "$target/"
ostree --repo="$target" remote add --gpg-import="$state/public.gpg" frozen "file://$pool"
mapfile -t heads < <(cut -f 1 "$state/heads.tsv")
ostree --repo="$target" pull --mirror --depth=0 --disable-static-deltas frozen "${heads[@]}"
while IFS=$'\t' read -r head expected; do
    [[ $(ostree --repo="$target" rev-parse "$head") == "$expected" ]]
done <"$state/heads.tsv"
python3 "$here/fixture.py" inventory "$target" >"$target.restore.json"
printf 'RESTORE current HEADs include application/runtime payload; historical replay=none\n'
jq '{files:length, bytes:([.[].bytes]|add), objects:([keys[]|select(startswith("objects/"))]|length), payload_bytes:([to_entries[]|select(.key|endswith(".filez"))|.value.bytes]|add)}' "$target.restore.json"
ostree --repo="$target" checkout --user-mode "appstream/$arch" "$target.catalogue-before"
python3 "$here/fixture.py" catalogue "$target.catalogue-before" "$app" 1
flatpak build-import-bundle --no-update-summary --gpg-sign="$key" --gpg-homedir="$key_home" "$target" "$bundle"
[[ $(ostree --repo="$target" rev-parse "$ref") == "$commit" ]]
[[ $(sha256sum "$bundle" | cut -d ' ' -f 1) == "$(jq -r .bundle_sha256 "$state/expected.json")" ]]
flatpak build-update-repo --gpg-sign="$key" --gpg-homedir="$key_home" "$target"
ostree --repo="$target" checkout --user-mode "appstream/$arch" "$target.catalogue-after"
python3 "$here/fixture.py" catalogue "$target.catalogue-after" "$app" 2
printf 'PASS: Fresh publisher process restored declared current heads and imported only revision two\n'
