#!/usr/bin/env bash
set -euo pipefail

case "${1:-all}" in
    all) formats=(apt rpm arch apk flatpak brew scoop) ;;
    apt | rpm | arch | apk | flatpak | brew | scoop) formats=("$1") ;;
    *)
        printf 'Error: unknown proof format: %s\n' "$1" >&2
        exit 1
        ;;
esac
case "${HABERDASHER_TOOL_SYSTEM:-}" in
    x86_64-linux) ;;
    aarch64-linux)
        printf 'Error: Python native acceptance is not qualified on aarch64-linux.\n' >&2
        exit 1
        ;;
    *)
        printf 'Error: local proofs require a Linux Nix development shell.\n' >&2
        exit 1
        ;;
esac
if [[ -z ${HABERDASHER_TOOL_PATH:-} ]]; then
    printf 'Error: enter the project Nix development shell first.\n' >&2
    exit 1
fi
export PATH="$HABERDASHER_TOOL_PATH"

native=()
for format in "${formats[@]}"; do
    native+=("tests/native/test_$format.py")
done
if [[ ${1:-all} == all ]]; then
    native+=(tests/native/test_signing.py tests/native/test_http.py
        tests/native/test_storage_clients.py tests/native/test_pipeline.py)
fi
workspace=$(mktemp -d "${TMPDIR:-/tmp}/haberdasher-native.XXXXXXXX")
trap 'rm -rf "$workspace"' EXIT
chmod 700 "$workspace"
env -i PATH="$PATH" HABERDASHER_TOOL_PATH="$PATH" TMPDIR="$workspace" HOME="$workspace" \
    .venv/bin/python -m pytest -p no:cacheprovider "${native[@]}"
