#!/usr/bin/env bash
set -euo pipefail

bash_path=$(type -P bash)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir "$fixture/bin"
printf '#!/bin/sh\nexit 99\n' >"$fixture/tool"
chmod +x "$fixture/tool"
for tool in bash cat cp mv rm mkdir mktemp sha256sum sort \
    find xargs grep sed tar gzip xz zstd bsdtar \
    jq curl openssl gpg gpgv gpgsm shellcheck shfmt nixfmt rclone gh just actionlint; do
    ln -s "$fixture/tool" "$fixture/bin/$tool"
done

check() {
    env -i PATH="$PATH" HABERDASHER_TOOL_SYSTEM="$1" \
        HABERDASHER_TOOL_PATH="$fixture/bin" \
        "$bash_path" just/project/tools.sh >"$fixture/output" 2>&1
}

check aarch64-darwin
printf 'PASS: Darwin needs only common tools.\n'
for system in x86_64-linux aarch64-linux; do
    if check "$system"; then
        printf 'FAIL: Linux accepted missing repository tools.\n' >&2
        exit 1
    fi
    grep -q 'Missing tool: apt-ftparchive' "$fixture/output"
done
printf 'PASS: both Linux systems require repository tools.\n'

for tool in apt-ftparchive dpkg dpkg-deb createrepo_c modifyrepo_c \
    rpm rpmsign apk abuild abuild-sign getopt pacman repo-add repo-remove flatpak ostree; do
    ln -s "$fixture/tool" "$fixture/bin/$tool"
done
for system in x86_64-linux aarch64-linux; do
    check "$system"
done
printf 'PASS: both Linux systems accept all tools without executing them.\n'

for tool in bash openssl gpgsm getopt; do
    rm "$fixture/bin/$tool"
    if check x86_64-linux; then
        printf 'FAIL: inherited PATH hid missing %s.\n' "$tool" >&2
        exit 1
    fi
    grep -q "Missing tool: $tool" "$fixture/output"
    ln -s "$fixture/tool" "$fixture/bin/$tool"
done
printf 'PASS: inherited PATH cannot hide missing shell or signing tools.\n'

if check unsupported; then
    printf 'FAIL: unsupported system accepted.\n' >&2
    exit 1
fi
grep -q 'unsupported or unset Nix tool system' "$fixture/output"
printf 'PASS: unsupported systems fail.\n'

if env -i "$bash_path" just/project/tools.sh >"$fixture/output" 2>&1; then
    printf 'FAIL: missing Nix environment accepted.\n' >&2
    exit 1
fi
grep -q 'enter the project Nix development shell' "$fixture/output"
printf 'PASS: missing Nix environment fails.\n'
