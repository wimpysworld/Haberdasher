#!/usr/bin/env bash
set -euo pipefail

scripts=(just/project/*.sh tests/proofs/*.sh)
shellcheck "${scripts[@]}"
case "${1:-check}" in
    check)
        shfmt -d -i 4 -ci "${scripts[@]}"
        nixfmt --check flake.nix nix/tools.nix
        ;;
    correct)
        shfmt -w -i 4 -ci "${scripts[@]}"
        nixfmt flake.nix nix/tools.nix
        ;;
    *)
        printf 'Error: lint mode must be check or correct.\n' >&2
        exit 1
        ;;
esac
