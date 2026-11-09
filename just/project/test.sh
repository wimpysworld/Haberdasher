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
    python3 tailor-python uv ruff basedpyright aws miniserve; do
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
    apk abuild abuild-sign abuild-tar abuild-gzsplit getopt pacman makepkg repo-add repo-remove vercmp flatpak ostree update-mime-database appstreamcli; do
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

mkdir -p "$fixture/project/just/project" "$fixture/project/tests/proofs" "$fixture/helpers"
cp just/project/proof.sh "$fixture/project/just/project/"
cp tests/proofs/common.sh "$fixture/project/tests/proofs/"
for format in apt rpm arch apk flatpak; do
    cat >"$fixture/project/tests/proofs/$format.sh" <<'EOF'
set -euo pipefail
[[ -z ${HD_SIGNING_KEY_FILE+x} && -z ${HD_CLOUDFLARE_ACCESS_KEY_ID+x} ]]
[[ -z ${HOME+x} && -z ${GNUPGHOME+x} && -z ${UNRELATED_SENTINEL+x} ]]
[[ $PATH == "$HABERDASHER_TOOL_PATH" ]]
printf '%s\n' "${0##*/}" >>dispatch.log
EOF
done

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
[[ $(cat "$fixture/project/dispatch.log") == $'apt.sh\nrpm.sh\narch.sh\napk.sh\nflatpak.sh' ]]
[[ $(cat "$fixture/project/native.log") == '-m pytest -p no:cacheprovider tests/native/test_apt.py tests/native/test_rpm.py tests/native/test_arch.py tests/native/test_apk.py tests/native/test_flatpak.py tests/native/test_signing.py tests/native/test_http.py tests/native/test_storage_clients.py tests/native/test_pipeline.py' ]]
rm "$fixture/project/dispatch.log"
if router aarch64-linux all; then
    printf 'FAIL: unqualified native architecture accepted.\n' >&2
    exit 1
fi
grep -q 'not qualified on aarch64-linux' "$fixture/output"
router x86_64-linux apt
[[ $(cat "$fixture/project/dispatch.log") == apt.sh ]]
[[ $(cat "$fixture/project/native.log") == '-m pytest -p no:cacheprovider tests/native/test_apt.py' ]]
rm "$fixture/project/dispatch.log"
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
[[ ! -e $fixture/project/dispatch.log ]]
rm "$fixture/project/tests/proofs/apt.sh"
if router x86_64-linux apt; then
    printf 'FAIL: missing proof script accepted.\n' >&2
    exit 1
fi
grep -q 'proof script is not available' "$fixture/output"
printf 'PASS: proof routing checks formats, Linux, isolation, and missing scripts.\n'

cp just/project.just "$fixture/project/justfile"
cat >"$fixture/project/.venv/bin/python" <<'EOF'
#!/bin/sh
printf '<%s>\n' "$@" >publish.log
EOF
(
    cd "$fixture/project"
    env -i PATH="$PATH" just publish
    [[ $(cat publish.log) == $'<-m>\n<haberdasher>' ]]
    literal="path with spaces;\$(touch unexpected)"
    env -i PATH="$PATH" just publish --config "$literal" --plan
    [[ $(cat publish.log) == $'<-m>\n<haberdasher>\n<--config>\n'"<$literal>"$'\n<--plan>' ]]
    [[ ! -e unexpected ]]
)
printf 'PASS: publish defaults to no arguments and preserves literal argument boundaries.\n'

cat >"$fixture/helpers/gpgconf" <<'EOF'
#!/bin/sh
[ "$1" = --homedir ] && [ "$2" = "$GNUPGHOME" ] && [ "$3" = --kill ] && [ "$4" = all ] || exit 1
printf '%s\n' "$2" >>"$PWD/agent-cleanup.log"
EOF
cat >"$fixture/helpers/gpg" <<'EOF'
#!/bin/sh
socket="$GNUPGHOME/S.gpg-agent.browser"
[ "${#socket}" -lt 107 ] || exit 1
case "$*" in
    '--batch --pinentry-mode loopback --passphrase  --quick-generate-key Haberdasher local proof <proof@invalid> rsa4096 sign,cert 1d') ;;
    '--batch --with-colons --list-keys')
        if [ ! -f "$PROOF_WORK/invalid-key" ]; then
            printf 'fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n'
        fi
        ;;
    '--batch --armor --export AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') printf 'test public armour\n' ;;
    '--batch --export AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') printf 'test public binary\n' ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$fixture/helpers/gpgconf" "$fixture/helpers/gpg"
cat >"$fixture/project/common-test.sh" <<'EOF'
set -euo pipefail
[[ ! -e $1 ]] || exit 97
source tests/proofs/common.sh
proof_init apt
[[ $# == 2 ]]
[[ -z ${HD_SIGNING_KEY_FILE+x} && -z ${HD_CLOUDFLARE_ACCESS_KEY_ID+x} ]]
[[ -z ${UNRELATED_SENTINEL+x} ]]
for directory in "$PROOF_WORK" "$GNUPGHOME" "$HOME" "$XDG_CONFIG_HOME" \
    "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$TMPDIR"; do
    [[ -d $directory && $(stat -c %a "$directory") == 700 ]]
    [[ $directory == "$PROOF_WORK" || $directory == "$PROOF_WORK/"* ]]
done
[[ $(stat -c %a "$GNUPGHOME/gpg.conf") == 600 ]]
grep -q '^digest-algo SHA256$' "$GNUPGHOME/gpg.conf"
printf '%s\n' "$PROOF_WORK" >"$1"
case "$2" in
    success) proof_pass 'Private workspace ready.' ;;
    fail) proof_fail 'Expected test failure.' ;;
    int) kill -INT "$$" ;;
    term) kill -TERM "$$" ;;
    repeat-init) proof_init apt ;;
    key | long-tmp | socket-106 | socket-107)
        proof_key
        [[ $PROOF_FPR == AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ]]
        [[ $(cat "$PROOF_WORK/public.asc") == 'test public armour' ]]
        [[ $(cat "$PROOF_WORK/public.gpg") == 'test public binary' ]]
        [[ $(stat -c %a "$PROOF_WORK/public.asc") == 600 ]]
        [[ $(stat -c %a "$PROOF_WORK/public.gpg") == 600 ]]
        ;;
    invalid-key)
        touch "$PROOF_WORK/invalid-key"
        proof_key
        ;;
    finish)
        proof_finish
        proof_finish
        [[ ! -e $PROOF_WORK ]]
        ;;
esac
EOF
boundary_fixture=$(mktemp -d /tmp/hd-test.XXXXXXXX)
trap 'rm -rf "$fixture" "$boundary_fixture"' EXIT
for mode in success fail int term finish key invalid-key repeat-init long-tmp socket-106 socket-107; do
    temporary_base=$fixture
    if [[ $mode == long-tmp ]]; then
        temporary_base="$fixture/$(printf '%090d' 0)"
        mkdir "$temporary_base"
    elif [[ $mode == socket-* ]]; then
        socket="$boundary_fixture//haberdasher-proof-apt.XXXXXXXX/gnupg/S.gpg-agent.browser"
        temporary_base="$boundary_fixture/$(printf '%0*d' "$((${mode#socket-} - ${#socket}))" 0)"
        mkdir "$temporary_base"
        socket="$temporary_base/haberdasher-proof-apt.XXXXXXXX/gnupg/S.gpg-agent.browser"
        [[ ${#socket} == "${mode#socket-}" ]]
    fi
    rm -f "$fixture/work-path"
    status=0
    (
        cd "$fixture/project"
        env -i PATH="$PATH" HABERDASHER_TOOL_PATH="$fixture/helpers:$PATH" TMPDIR="$temporary_base" \
            HD_SIGNING_KEY_FILE=unused-test-only HD_CLOUDFLARE_ACCESS_KEY_ID=unused-test-only \
            UNRELATED_SENTINEL=unused-test-only HOME=/unused-test-only GNUPGHOME=/unused-test-only PROOF_CLEAN=1 \
            "$bash_path" common-test.sh "$fixture/work-path" "$mode"
    ) >"$fixture/output" 2>&1 || status=$?
    case "$mode" in
        success | finish | key | long-tmp | socket-106 | socket-107) [[ $status == 0 ]] ;;
        fail | invalid-key | repeat-init) [[ $status == 1 ]] ;;
        int) [[ $status == 130 ]] ;;
        term) [[ $status == 143 ]] ;;
    esac
    work=$(cat "$fixture/work-path")
    [[ ! -e $work ]]
    grep -Fxq "$work/gnupg" "$fixture/project/agent-cleanup.log"
    socket="$(cd "$temporary_base" && pwd -P)/haberdasher-proof-apt.XXXXXXXX/gnupg/S.gpg-agent.browser"
    if ((${#socket} >= 107)); then
        [[ $work == /tmp/haberdasher-proof-apt.* ]]
        grep -Fxq 'WARNING: Temporary path is too long for GPG sockets. Use a private workspace in /tmp.' "$fixture/output"
        [[ -z $(find "$temporary_base" -mindepth 1 -maxdepth 1 -name 'haberdasher-proof-*' -print) ]]
    else
        [[ ${work%/*} == "$(cd "$temporary_base" && pwd -P)" ]]
    fi
    if [[ $mode == repeat-init ]]; then
        grep -Fxq 'FAIL: The proof workspace is already initialised.' "$fixture/output"
    fi
done
printf 'PASS: repeated initialisation fails without a restart and cleans up the original workspace and agent.\n'
printf 'PASS: long temporary paths use a private /tmp workspace for key generation and cleanup.\n'
printf 'PASS: 106-byte socket paths stay in place and 107-byte paths use the fallback.\n'
printf 'PASS: common setup isolates configuration and cleans up on success, failure, INT, TERM, and repeated finish.\n'
printf 'PASS: disposable key setup requests RSA4096 sign+cert, validates the fingerprint, and exports only public keys.\n'
