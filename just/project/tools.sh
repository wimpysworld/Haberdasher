#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${HABERDASHER_TOOL_PATH:-} ]]; then
    printf 'Error: enter the project Nix development shell first.\n' >&2
    exit 1
fi
export PATH="$HABERDASHER_TOOL_PATH"

tools=(
    bash env cat cp mv rm mkdir mktemp chmod sha256sum sort timeout id
    find xargs grep sed tar gzip xz zstd bsdtar
    jq curl openssl gpg gpgv gpgsm gpgconf cosign shellcheck shfmt nixfmt rclone
    gh just actionlint python3 tailor-python uv ruff basedpyright aws miniserve git
)
case "${HABERDASHER_TOOL_SYSTEM:-}" in
    x86_64-linux | aarch64-linux)
        tools+=(
            apt-ftparchive apt-get apt-config dpkg dpkg-deb dpkg-query createrepo_c modifyrepo_c
            rpm rpmsign rpmbuild rpmkeys dnf5 fakechroot fakeroot
            apk abuild abuild-sign abuild-tar abuild-gzsplit getopt pacman makepkg repo-add repo-remove vercmp
            flatpak ostree update-mime-database appstreamcli ruby nix haberdasher-nixpkgs
        )
        ;;
    aarch64-darwin)
        printf 'Darwin: common development tools only. Publishing requires Linux.\n'
        ;;
    *)
        printf 'Error: unsupported or unset Nix tool system.\n' >&2
        exit 1
        ;;
esac

missing=0
for tool in "${tools[@]}"; do
    if executable=$(type -P "$tool"); then
        printf '%s: %s\n' "$tool" "$executable"
    else
        printf 'Missing tool: %s\n' "$tool" >&2
        missing=1
    fi
done
exit "$missing"
