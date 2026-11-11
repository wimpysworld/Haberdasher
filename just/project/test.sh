#!/usr/bin/env bash
set -euo pipefail

bash_path=$(type -P bash)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir "$fixture/bin"
printf '#!/bin/sh\nexit 99\n' >"$fixture/tool"
chmod +x "$fixture/tool"
for tool in bash env cat cp mv rm mkdir mktemp chmod sha256sum sort timeout id \
    find xargs grep sed tar gzip xz zstd bsdtar \
    jq curl openssl gpg gpgv gpgsm gpgconf cosign shellcheck shfmt nixfmt rclone gh just actionlint \
    python3 tailor-python uv ruff basedpyright aws miniserve git; do
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

for tool in apt-ftparchive apt-get apt-config dpkg dpkg-deb dpkg-query createrepo_c modifyrepo_c \
    rpm rpmsign rpmbuild rpmkeys dnf5 fakechroot fakeroot \
    apk abuild abuild-sign abuild-tar abuild-gzsplit getopt pacman makepkg repo-add repo-remove vercmp flatpak ostree update-mime-database appstreamcli ruby; do
    ln -s "$fixture/tool" "$fixture/bin/$tool"
done
for system in x86_64-linux aarch64-linux; do
    check "$system"
done
printf 'PASS: both Linux systems accept all tools without executing them.\n'

for tool in bash openssl gpgsm gpgconf cosign getopt dnf5 fakechroot fakeroot python3 tailor-python uv ruff basedpyright aws miniserve appstreamcli apt-get rpmkeys vercmp update-mime-database; do
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

mkdir -p "$fixture/project/just/project"
cp just/project/proof.sh "$fixture/project/just/project/"

router() {
    (
        cd "$fixture/project"
        env -i PATH="$fixture/bin" HABERDASHER_TOOL_SYSTEM="$1" \
            HABERDASHER_TOOL_PATH="$PATH" HD_SIGNING_KEY_FILE=unused-test-only \
            HD_CLOUDFLARE_ACCESS_KEY_ID=unused-test-only HOME=/unused-test-only \
            GNUPGHOME=/unused-test-only UNRELATED_SENTINEL=unused-test-only \
            "$bash_path" just/project/proof.sh "$2"
    ) >"$fixture/output" 2>&1
}
mkdir -p "$fixture/project/.venv/bin"
cat >"$fixture/project/.venv/bin/python" <<'EOF'
#!/bin/sh
[ -z "${HD_SIGNING_KEY_FILE+x}${HD_CLOUDFLARE_ACCESS_KEY_ID+x}${UNRELATED_SENTINEL+x}" ] || exit 1
[ "$HOME" = "$TMPDIR" ] && [ -d "$HOME" ] || exit 1
printf '%s\n' "$*" >native.log
EOF
chmod +x "$fixture/project/.venv/bin/python"
router x86_64-linux all
[[ $(cat "$fixture/project/native.log") == '-m pytest -p no:cacheprovider tests/native/test_apt.py tests/native/test_rpm.py tests/native/test_arch.py tests/native/test_apk.py tests/native/test_flatpak.py tests/native/test_brew.py tests/native/test_signing.py tests/native/test_http.py tests/native/test_storage_clients.py tests/native/test_pipeline.py' ]]
rm "$fixture/project/native.log"
if router aarch64-linux all; then
    printf 'FAIL: unqualified native architecture accepted.\n' >&2
    exit 1
fi
grep -q 'not qualified on aarch64-linux' "$fixture/output"
router x86_64-linux apt
[[ $(cat "$fixture/project/native.log") == '-m pytest -p no:cacheprovider tests/native/test_apt.py' ]]
rm "$fixture/project/native.log"
if router x86_64-linux unknown; then
    printf 'FAIL: unknown proof format accepted.\n' >&2
    exit 1
fi
grep -q 'unknown proof format' "$fixture/output"
for system in aarch64-darwin unsupported; do
    if router "$system" all; then
        printf 'FAIL: proof dispatched outside Linux.\n' >&2
        exit 1
    fi
    grep -q 'require a Linux' "$fixture/output"
done
[[ ! -e $fixture/project/native.log ]]
printf 'PASS: proof routing checks formats, Linux, and isolation.\n'

cp just/project.just "$fixture/project/justfile"
cat >"$fixture/project/.venv/bin/python" <<'EOF'
#!/bin/sh
printf '<%s>\n' "$@" >publish.log
EOF
(
    cd "$fixture/project"
    for recipe in plan publish unlock; do
        env -i PATH="$PATH" just "$recipe"
        [[ $(cat publish.log) == $'<-m>\n<haberdasher>\n'"<$recipe>" ]]
        if env -i PATH="$PATH" just "$recipe" --local-root /tmp/unused 2>/dev/null; then
            printf 'FAIL: %s accepted an argument.\n' "$recipe" >&2
            exit 1
        fi
    done
)
printf 'PASS: plan, publish, and unlock run their subcommands and take no arguments.\n'
