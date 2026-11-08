#!/usr/bin/env bash

_proof_args=("$@")

proof_fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

proof_pass() {
    printf 'PASS: %s\n' "$*"
}

proof_finish() {
    if [[ -n ${_proof_work:-} ]]; then
        gpgconf --homedir "$_proof_work/gnupg" --kill all >/dev/null 2>&1 || true
        rm -rf -- "$_proof_work"
        _proof_work=
    fi
}

proof_init() {
    [[ -z ${_proof_work:-} ]] || proof_fail 'The proof workspace is already initialised.'
    [[ -n ${HABERDASHER_TOOL_PATH:-} ]] || proof_fail 'Enter the project Nix development shell first.'
    export PATH="$HABERDASHER_TOOL_PATH"
    local name
    for name in $(compgen -e); do
        case "$name" in
            PATH | HABERDASHER_TOOL_PATH | TMPDIR | PROOF_CLEAN | PWD | SHLVL | _) ;;
            *)
                unset PROOF_CLEAN
                break
                ;;
        esac
    done
    if [[ ${PROOF_CLEAN:-} != 1 ]]; then
        exec env -i PATH="$PATH" HABERDASHER_TOOL_PATH="$PATH" \
            TMPDIR="${TMPDIR:-/tmp}" PROOF_CLEAN=1 \
            bash --noprofile --norc "$0" "${_proof_args[@]}"
    fi
    set -euo pipefail
    case "$1" in
        apt | rpm | arch | apk | flatpak) ;;
        *) proof_fail 'Unknown proof format.' ;;
    esac
    umask 077
    local LC_ALL=C base template socket
    base=$(cd -- "${TMPDIR:-/tmp}" && pwd -P)
    template="$base/haberdasher-proof-$1.XXXXXXXX"
    socket="$template/gnupg/S.gpg-agent.browser"
    # GnuPG rejects socket paths of 107 bytes or more.
    if ((${#socket} >= 107)); then
        printf 'WARNING: Temporary path is too long for GPG sockets. Use a private workspace in /tmp.\n' >&2
        template="/tmp/haberdasher-proof-$1.XXXXXXXX"
    fi
    _proof_work=$(mktemp -d "$template")
    trap proof_finish EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    export PROOF_WORK="$_proof_work"
    export GNUPGHOME="$PROOF_WORK/gnupg" HOME="$PROOF_WORK/home"
    export XDG_CONFIG_HOME="$HOME/.config" XDG_DATA_HOME="$HOME/.local/share"
    export XDG_CACHE_HOME="$HOME/.cache" XDG_STATE_HOME="$HOME/.local/state"
    export XDG_RUNTIME_DIR="$PROOF_WORK/run" TMPDIR="$PROOF_WORK/tmp"
    mkdir -p "$GNUPGHOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" \
        "$XDG_CACHE_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$TMPDIR"
    printf 'digest-algo SHA256\ncert-digest-algo SHA256\npersonal-digest-preferences SHA256\n' >"$GNUPGHOME/gpg.conf"
}

proof_key() {
    [[ -n ${_proof_work:-} ]] || proof_fail 'Initialise the proof workspace before key generation.'
    gpg --batch --pinentry-mode loopback --passphrase '' \
        --quick-generate-key 'Haberdasher local proof <proof@invalid>' rsa4096 sign,cert 1d
    PROOF_FPR=$(gpg --batch --with-colons --list-keys | sed -n 's/^fpr:::::::::\([^:]*\):$/\1/p')
    [[ $PROOF_FPR =~ ^[A-F0-9]{40}$ ]] || proof_fail 'Expected one disposable primary key.'
    export PROOF_FPR
    gpg --batch --armor --export "$PROOF_FPR" >"$PROOF_WORK/public.asc"
    gpg --batch --export "$PROOF_FPR" >"$PROOF_WORK/public.gpg"
}
