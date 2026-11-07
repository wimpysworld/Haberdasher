#!/usr/bin/env bash
set -euo pipefail

case "${1:-all}" in
    all) formats=(apt rpm arch apk flatpak) ;;
    apt | rpm | arch | apk | flatpak) formats=("$1") ;;
    *)
        printf 'Error: unknown proof format: %s\n' "$1" >&2
        exit 1
        ;;
esac
case "${HABERDASHER_TOOL_SYSTEM:-}" in
    x86_64-linux | aarch64-linux) ;;
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

for format in "${formats[@]}"; do
    script="tests/proofs/$format.sh"
    if [[ ! -f $script ]]; then
        printf 'Error: proof script is not available: %s\n' "$script" >&2
        exit 1
    fi
    env -i PATH="$PATH" HABERDASHER_TOOL_PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" \
        bash --noprofile --norc "$script"
done
