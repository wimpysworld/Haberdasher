#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/proofs/common.sh
source "$HERE/common.sh"
proof_init flatpak
XDG_DATA_DIRS=$(realpath "$(dirname "$(realpath "$(type -P update-mime-database)")")/../share")
[[ -f $XDG_DATA_DIRS/mime/mime.cache ]] || proof_fail 'The pinned MIME database is missing.'
export XDG_DATA_DIRS
proof_key
gpg --batch --with-colons --list-keys "$PROOF_FPR" >"$PROOF_WORK/key-policy"
grep -E '^pub:[^:]*:4096:1:' "$PROOF_WORK/key-policy" >/dev/null
if grep -q '^sub:' "$PROOF_WORK/key-policy"; then proof_fail 'Unexpected signing subkey'; fi
export LC_ALL=C
export FLATPAK_USER_DIR="$PROOF_WORK/client/flatpak"
APP=world.wimpress.HaberdasherProof
RUNTIME=world.wimpress.HaberdasherRuntime
ARCH=$(flatpak --default-arch)
REF="app/$APP/$ARCH/stable"
RREF="runtime/$RUNTIME/$ARCH/stable"
W=$PROOF_WORK
SIGN=(--gpg-sign="$PROOF_FPR" --gpg-homedir="$GNUPGHOME")
flatpak --version
ostree --version

same() { [[ $1 == "$2" ]] || proof_fail "$3: expected $2, got $1"; }
sha() { sha256sum "$1" | cut -d ' ' -f 1; }
repo() { ostree --repo="$1" init --mode=archive-z2; }
update() { flatpak build-update-repo "${SIGN[@]}" "$1"; }

check_catalogue() {
    local target=$W/catalogue-$2-$RANDOM
    ostree --repo="$1" checkout --user-mode "appstream/$ARCH" "$target"
    python3 "$HERE/flatpak/fixture.py" catalogue "$target" "$APP" "$2"
}

inspect() {
    local repository=$1 commit=$2 version=$3 binding metadata payload
    binding=$(ostree --repo="$repository" show --print-metadata-key=ostree.ref-binding "$commit") || return 1
    same "$binding" "['$REF']" 'Full ref binding'
    binding=$(ostree --repo="$repository" show --print-metadata-key=ostree.collection-binding "$commit") || return 1
    [[ $binding == "''" ]] || {
        echo 'REJECT collection binding'
        return 1
    }
    metadata=$(ostree --repo="$repository" cat "$commit" /metadata) || return 1
    grep -Fx "name=$APP" <<<"$metadata" >/dev/null || {
        echo 'REJECT metadata name'
        return 1
    }
    grep -Fx "runtime=$RUNTIME/$ARCH/stable" <<<"$metadata" >/dev/null || {
        echo 'REJECT metadata runtime'
        return 1
    }
    grep -Fx "version=$version" <<<"$metadata" >/dev/null || {
        echo 'REJECT metadata version'
        return 1
    }
    payload=$(ostree --repo="$repository" cat "$commit" /files/version) || return 1
    same "$payload" "$version" 'Version payload'
}

admit() {
    local bundle=$1 expected=$2 owner=$3 asset=$4 version=$5 actual quarantine commit
    actual=$(sha "$bundle")
    [[ $actual == "$expected" ]] || {
        echo 'REJECT checksum'
        return 1
    }
    [[ $owner == wimpysworld/fixture ]] || {
        echo 'REJECT source ownership'
        return 1
    }
    if [[ -f $W/accepted/$asset ]]; then
        [[ $(cat "$W/accepted/$asset") == "$actual" ]] || {
            echo 'REJECT asset identity'
            return 1
        }
        echo 'Accepted replay leaves bytes unchanged'
        return
    fi
    quarantine=$W/quarantine-$asset-$RANDOM
    repo "$quarantine"
    flatpak build-import-bundle --no-update-summary "$quarantine" "$bundle" >/dev/null
    commit=$(ostree --repo="$quarantine" rev-parse "$REF")
    inspect "$quarantine" "$commit" "$version" || return 1
    mkdir -p "$W/accepted"
    printf '%s\n' "$actual" >"$W/accepted/$asset"
    printf 'ADMIT asset=%s source=%s commit=%s ref=%s runtime=%s version=%s collection=none\n' \
        "$asset" "$actual" "$commit" "$REF" "$RREF" "$version"
}

reject_admission() {
    local reason=$1
    shift
    if (admit "$@") >"$W/admission-negative" 2>&1; then proof_fail "$reason accepted"; fi
    grep -F "REJECT $reason" "$W/admission-negative"
}

import_signed() {
    local target=$1 bundle=$2 commit=$3 before
    before=$(sha "$bundle")
    flatpak build-import-bundle --no-update-summary "${SIGN[@]}" "$target" "$bundle"
    same "$(ostree --repo="$target" rev-parse "$REF")" "$commit" 'Import preserves source commit'
    same "$(sha "$bundle")" "$before" 'Import preserves source bundle'
}

freeze() {
    cp -a "$1" "$2"
    python3 "$HERE/flatpak/fixture.py" inventory "$2" >"$2.inventory.json"
}

publish_dependencies() {
    local snapshot=$1 pool=$2 file rel
    mkdir -p "$pool"
    while IFS= read -r -d '' file; do
        rel=${file#"$snapshot/"}
        case "$rel" in summary | summary.sig | summary.idx | summary.idx.sig | refs/* | config) continue ;; esac
        mkdir -p "$pool/$(dirname "$rel")"
        if [[ -f $pool/$rel && $rel != *.commitmeta ]]; then
            same "$(sha "$file")" "$(sha "$pool/$rel")" "Immutable object: $rel"
        else
            cp "$file" "$pool/$rel"
        fi
    done < <(find "$snapshot" -type f -print0)
}

publish_entries() {
    local snapshot=$1 pool=$2
    cp "$snapshot/config" "$pool/config"
    cp -a "$snapshot/refs" "$pool/"
    cp "$snapshot/summary" "$snapshot/summary.sig" "$snapshot/summary.idx" "$snapshot/summary.idx.sig" "$pool/"
}

client() (
    local name=$1
    shift
    export HOME="$W/clients/$name/home"
    export XDG_CONFIG_HOME="$HOME/.config" XDG_DATA_HOME="$HOME/.local/share"
    export XDG_CACHE_HOME="$HOME/.cache" XDG_STATE_HOME="$HOME/.local/state"
    export XDG_RUNTIME_DIR="$W/clients/$name/run" FLATPAK_USER_DIR="$W/clients/$name/flatpak"
    mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"
    flatpak --user "$@"
)

add_remote() {
    client "$1" remote-add --gpg-import="$W/public.gpg" proof "file://$2"
}

installed() {
    local name=$1 commit=$2 version=$3 location
    same "$(client "$name" info --show-ref "$APP")" "$REF" 'Installed ref'
    same "$(client "$name" info --show-commit "$APP")" "$commit" 'Installed commit'
    same "$(client "$name" info --show-runtime "$APP")" "$RUNTIME/$ARCH/stable" 'Installed runtime'
    same "$(client "$name" info --show-origin "$APP")" proof 'Installed origin'
    same "$(client "$name" info --show-commit "$RUNTIME")" "$RCOMMIT" 'Approved runtime commit'
    location=$(client "$name" info --show-location "$APP")
    same "$(cat "$location/files/version")" "$version" 'Installed application data'
    location=$(client "$name" info --show-location "$RUNTIME")
    same "$(cat "$location/files/runtime-version")" 1 'Installed runtime data'
    proof_pass "Actual deployment app=$version runtime=1 commit=$commit runtime_commit=$RCOMMIT ref=$REF origin=proof"
}

negative_client() {
    local name=$1 path=$2 pattern=$3
    if { add_remote "$name" "$path" && client "$name" install --noninteractive proof "$REF"; } >"$W/$name.log" 2>&1; then
        proof_fail "$name accepted"
    fi
    cat "$W/$name.log"
    grep -Ei "$pattern" "$W/$name.log" >/dev/null || proof_fail "$name failed for an unrelated reason"
    if client "$name" info "$APP" >/dev/null 2>&1; then proof_fail "$name deployed an app"; fi
    proof_pass "$name rejected by native trust checks"
}

mkdir -p "$W/runtime/usr" "$W/runtime/files"
printf '[Runtime]\nname=%s\nruntime=%s/%s/stable\nsdk=%s/%s/stable\n' "$RUNTIME" "$RUNTIME" "$ARCH" "$RUNTIME" "$ARCH" >"$W/runtime/metadata"
printf '1\n' >"$W/runtime/usr/runtime-version"
flatpak build-export --runtime --no-update-summary "$W/source" "$W/runtime" stable
RCOMMIT=$(ostree --repo="$W/source" rev-parse "$RREF")
flatpak build-bundle --runtime --arch="$ARCH" "$W/source" "$W/runtime.flatpak" "$RUNTIME" stable
for version in 1 2; do
    python3 "$HERE/flatpak/fixture.py" fixture "$W/app-$version" "$APP" "$RUNTIME" "$ARCH" "$version"
    flatpak build-finish "$W/app-$version"
    flatpak build-export --no-update-summary "$W/source" "$W/app-$version" stable
    flatpak build-bundle --arch="$ARCH" "$W/source" "$W/app-$version.flatpak" "$APP" stable
    ostree --repo="$W/source" rev-parse "$REF" >"$W/commit-$version"
done
C1=$(cat "$W/commit-1")
C2=$(cat "$W/commit-2")
S1=$(sha "$W/app-1.flatpak")
S2=$(sha "$W/app-2.flatpak")
admit "$W/app-1.flatpak" "$S1" wimpysworld/fixture release-1 1
same "$(cat "$W/accepted/release-1")" "$S1" 'Valid metadata admission'
proof_pass 'Valid native bundle passes metadata admission'
admit "$W/app-1.flatpak" "$S1" wimpysworld/fixture release-1 1
python3 "$HERE/flatpak/fixture.py" inventory "$W/accepted" >"$W/accepted-before.json"
repo "$W/malformed-source"
ostree --repo="$W/malformed-source" pull-local "$W/source" "$C1"
ostree --repo="$W/malformed-source" checkout --user-mode "$C1" "$W/malformed-tree"
for field in name runtime version; do
    case "$field" in
        name) wrong=world.wimpress.Unexpected ;;
        runtime) wrong="world.wimpress.Unexpected/$ARCH/stable" ;;
        version) wrong=999 ;;
    esac
    sed "s|^$field=.*|$field=$wrong|" "$W/app-1/metadata" >"$W/malformed-tree/metadata"
    malformed=$(ostree --repo="$W/malformed-source" commit --branch="$REF" \
        --tree="dir=$W/malformed-tree" --add-metadata-string=ostree.collection-binding= \
        --add-metadata-string="xa.metadata=$(cat "$W/malformed-tree/metadata")")
    same "$(ostree --repo="$W/malformed-source" show --print-metadata-key=ostree.ref-binding "$malformed")" "['$REF']" 'Negative fixture ref'
    same "$(ostree --repo="$W/malformed-source" show --print-metadata-key=ostree.collection-binding "$malformed")" "''" 'Negative fixture collection'
    same "$(ostree --repo="$W/malformed-source" cat "$malformed" /files/version)" 1 'Negative fixture payload'
    flatpak build-bundle --arch="$ARCH" "$W/malformed-source" "$W/wrong-$field.flatpak" "$APP" stable
    reject_admission "metadata $field" "$W/wrong-$field.flatpak" "$(sha "$W/wrong-$field.flatpak")" wimpysworld/fixture "wrong-$field" 1
    python3 "$HERE/flatpak/fixture.py" inventory "$W/accepted" >"$W/accepted-after.json"
    same "$(sha "$W/accepted-after.json")" "$(sha "$W/accepted-before.json")" 'Admission completion unchanged'
    [[ ! -e $W/publisher && ! -e $W/public && ! -e $W/state ]]
    if compgen -G "$W/*.complete" >/dev/null; then proof_fail 'Metadata rejection advanced completion'; fi
    proof_pass "Wrong metadata $field rejected before admission/publication; completion unchanged"
    rm -- "$W/wrong-$field.flatpak"
done
rm -rf -- "$W/malformed-source" "$W/malformed-tree"
reject_admission checksum "$W/app-1.flatpak" "$S2" wimpysworld/fixture bad 1
reject_admission 'source ownership' "$W/app-1.flatpak" "$S1" other/fixture bad 1
reject_admission 'asset identity' "$W/app-2.flatpak" "$S2" wimpysworld/fixture release-1 2
admit "$W/app-2.flatpak" "$S2" wimpysworld/fixture release-2 2
flatpak build-export --collection-id=world.wimpress.Unexpected --no-update-summary "$W/bound-source" "$W/app-2" stable
flatpak build-bundle --arch="$ARCH" "$W/bound-source" "$W/bound.flatpak" "$APP" stable
reject_admission 'collection binding' "$W/bound.flatpak" "$(sha "$W/bound.flatpak")" wimpysworld/fixture bound 2
repo "$W/publisher"
flatpak build-import-bundle --no-update-summary "${SIGN[@]}" "$W/publisher" "$W/runtime.flatpak"
import_signed "$W/publisher" "$W/app-1.flatpak" "$C1"
update "$W/publisher"
check_catalogue "$W/publisher" 1
ostree --repo="$W/publisher" show --print-detached-metadata-key=ostree.gpgsigs "$C1" >"$W/commit-signature.variant"
ostree --repo="$W/publisher" show --print-variant-type='a{sv}' "$W/publisher/summary.sig" >"$W/summary-signature.variant"
ostree --repo="$W/publisher" show --print-variant-type='a{sv}' "$W/publisher/summary.idx.sig" >"$W/index-signature.variant"
for kind in commit summary index; do
    python3 "$HERE/flatpak/fixture.py" signature "$W/$kind-signature.variant" "$W/$kind-signature.gpg"
    gpg --batch --list-packets "$W/$kind-signature.gpg" >"$W/$kind-packets"
    grep -F 'digest algo 8,' "$W/$kind-packets"
    proof_pass "$kind uses SHA256 OpenPGP signatures"
done
freeze "$W/publisher" "$W/generation-1"
publish_dependencies "$W/generation-1" "$W/public"
publish_entries "$W/generation-1" "$W/public"
add_remote real "$W/public"
client real update --appstream --noninteractive --verbose proof
find "$W/clients/real" -name '*xml*' -print
DEFER=0
client real search --columns=application,version Haberdasher | tee "$W/search"
if ! grep -F "$APP" "$W/search"; then
    printf 'DEFER: native search did not discover the generated application\n'
    DEFER=1
fi
client real install --noninteractive proof "$REF"
installed real "$C1" 1

repo "$W/metadata-only"
ostree --repo="$W/metadata-only" remote add --gpg-import="$W/public.gpg" frozen "file://$W/public"
mapfile -t HEADS < <(ostree --repo="$W/generation-1" refs | sort)
ostree --repo="$W/metadata-only" pull --mirror --depth=0 --commit-metadata-only --disable-static-deltas frozen "${HEADS[@]}"
if ostree --repo="$W/metadata-only" checkout --user-mode "$REF" "$W/sparse-check" >"$W/sparse.log" 2>&1; then
    proof_fail 'Commit-only control unexpectedly contains application payload'
fi
cat "$W/sparse.log"
proof_pass 'Commit-only restore lacks required trees and payload'

mkdir -p "$W/state"
cp "$W/public.gpg" "$W/state/"
cp -a "$W/accepted" "$W/state/"
cp "$W/public/config" "$W/state/config"
sha256sum "$W/public/summary.idx" "$W/public/summary" "$W/public/summary.sig" >"$W/state/entry.sha256"
for head in "${HEADS[@]}"; do
    printf '%s\t%s\n' "$head" "$(ostree --repo="$W/public" rev-parse "$head")"
done >"$W/state/heads.tsv"
jq -n --arg arch "$ARCH" --arg app "$APP" --arg ref "$REF" --arg commit "$C2" --arg bundle_sha256 "$S2" \
    '{arch:$arch,app:$app,ref:$ref,commit:$commit,bundle_sha256:$bundle_sha256}' >"$W/state/expected.json"
python3 "$HERE/flatpak/fixture.py" inventory "$W/state" >"$W/state.inventory.json"
printf 'STATE retained admission history, expected refs/digests, public trust and native configuration\n'
jq '{files:length, bytes:([.[].bytes]|add)}' "$W/state.inventory.json"
rm -rf -- "$W/source" "$W/publisher" "$W/app-1" "$W/app-2" "$W/runtime" "$W"/quarantine-* "$W/bound-source"
rm -- "$W/app-1.flatpak" "$W/runtime.flatpak" "$W/bound.flatpak"
bash --noprofile --norc "$HERE/flatpak/cold.sh" "$W/state" "$W/public" "$W/app-2.flatpak" "$W/restored" "$PROOF_FPR" "$GNUPGHOME"
freeze "$W/restored" "$W/generation-2"
publish_dependencies "$W/generation-2" "$W/public"
publish_entries "$W/generation-2" "$W/public"
client real update --noninteractive
installed real "$C2" 2
add_remote fresh "$W/public"
client fresh install --noninteractive proof "$REF"
installed fresh "$C2" 2

cp -a "$W/generation-2" "$W/missing-commit-signature"
rm -- "$W/missing-commit-signature/objects/${C2:0:2}/${C2:2}.commitmeta"
negative_client missing-commit-signature "$W/missing-commit-signature" 'GPG|signature'
cp -a "$W/generation-2" "$W/altered-commit"
printf 'altered' >"$W/altered-commit/objects/${C2:0:2}/${C2:2}.commit"
negative_client altered-commit "$W/altered-commit" 'checksum|corrupt|invalid|signature|GPG'
cp -a "$W/generation-2" "$W/altered-index"
printf 'altered' >"$W/altered-index/summary.idx"
negative_client altered-index "$W/altered-index" 'signature|GPG|invalid|summary'
cp -a "$W/generation-2" "$W/missing-entry-signature"
find "$W/missing-entry-signature/summaries" -name '*.idx.sig' -delete
rm -- "$W/missing-entry-signature/summary.sig" "$W/missing-entry-signature/summary.idx.sig"
negative_client missing-entry-signature "$W/missing-entry-signature" 'signature|GPG|summary'
if { client missing-key remote-add proof "file://$W/public" && client missing-key install --noninteractive proof "$REF"; } >"$W/missing-key.log" 2>&1; then
    proof_fail 'Missing key accepted'
fi
cat "$W/missing-key.log"
grep -Ei 'GPG|signature|public key' "$W/missing-key.log" >/dev/null
if client missing-key info "$APP" >/dev/null 2>&1; then proof_fail 'Missing key deployed'; fi
proof_pass 'Missing key rejected'
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'Wrong proof key <wrong@invalid>' rsa4096 sign,cert 1d
gpg --batch --export wrong@invalid >"$W/wrong.gpg"
if { client wrong-key remote-add --gpg-import="$W/wrong.gpg" proof "file://$W/public" && client wrong-key install --noninteractive proof "$REF"; } >"$W/wrong-key.log" 2>&1; then
    proof_fail 'Wrong key accepted'
fi
cat "$W/wrong-key.log"
grep -F "public key not found" "$W/wrong-key.log"
if client wrong-key info "$APP" >/dev/null 2>&1; then proof_fail 'Wrong key deployed'; fi
proof_pass 'Wrong scoped key rejected'

flatpak build-update-repo "${SIGN[@]}" --title='Metadata refresh three' "$W/restored"
freeze "$W/restored" "$W/generation-3"
publish_dependencies "$W/generation-3" "$W/public"
publish_entries "$W/generation-3" "$W/public"
for generation in 1 2 3; do
    while IFS= read -r -d '' signature; do
        same "$(sha "$signature")" "$(sha "$W/public/summaries/${signature##*/}")" 'Retained index signature'
    done < <(find "$W/generation-$generation/summaries" -type f -print0)
    index=$(sha "$W/generation-$generation/summary.idx")
    [[ -s $W/public/summaries/$index.idx.sig ]]
    printf 'RETAIN generation=%s index=%s signature_bytes=%s\n' "$generation" "$index" "$(stat -c %s "$W/public/summaries/$index.idx.sig")"
done
old_index=$(sha "$W/generation-1/summary.idx")
[[ ! -e $W/restored/summaries/$old_index.idx.sig ]] || proof_fail 'Expected native cleanup of the first index signature'
proof_pass 'Published union retains signatures that native working-repository cleanup removed'
for generation in 1 2; do
    cp -a "$W/public" "$W/delayed-$generation"
    publish_entries "$W/generation-$generation" "$W/delayed-$generation"
    rm -- "$W/delayed-$generation/summary.idx.sig"
    add_remote "delayed-$generation" "$W/delayed-$generation"
    client "delayed-$generation" remote-ls --app proof | grep -F "$APP"
done

for order in summary-first signature-first; do
    cp -a "$W/generation-1" "$W/$order"
    rm -- "$W/$order/summary.idx"
    if [[ $order == summary-first ]]; then
        cp "$W/generation-2/summary" "$W/$order/summary"
    else
        cp "$W/generation-2/summary.sig" "$W/$order/summary.sig"
    fi
    negative_client "$order" "$W/$order" 'signature|GPG'
    publish_dependencies "$W/generation-2" "$W/$order"
    cp "$W/generation-2/summary" "$W/generation-2/summary.sig" "$W/$order/"
    add_remote "$order-recovered" "$W/$order"
    client "$order-recovered" install --noninteractive proof "$REF"
    installed "$order-recovered" "$C2" 2
done

payload=$(ostree --repo="$W/generation-2" ls --checksum "$C2" /files/version | grep -oE '[a-f0-9]{64}')
[[ $payload =~ ^[a-f0-9]{64}$ ]]
for stage in dependency entry inventory; do
    mkdir -p "$W/replay-$stage"
    case "$stage" in
        dependency)
            publish_dependencies "$W/generation-2" "$W/replay-$stage"
            rm -- "$W/replay-$stage/objects/${payload:0:2}/${payload:2}.filez"
            [[ ! -e $W/replay-$stage/summary ]]
            ;;
        entry)
            publish_dependencies "$W/generation-2" "$W/replay-$stage"
            cp "$W/generation-2/summary" "$W/replay-$stage/"
            ;;
        inventory)
            publish_dependencies "$W/generation-2" "$W/replay-$stage"
            publish_entries "$W/generation-2" "$W/replay-$stage"
            ;;
    esac
    [[ ! -e $W/replay-$stage.complete ]]
    publish_dependencies "$W/generation-2" "$W/replay-$stage"
    publish_entries "$W/generation-2" "$W/replay-$stage"
    python3 "$HERE/flatpak/fixture.py" inventory "$W/replay-$stage" >"$W/replay-$stage.inventory.json"
    same "$(sha "$W/generation-2.inventory.json")" "$(sha "$W/replay-$stage.inventory.json")" 'Frozen inventory'
    cp "$W/replay-$stage.inventory.json" "$W/replay-$stage.complete"
    proof_pass "Frozen retry after $stage interruption, completion recorded last"
done
python3 "$HERE/flatpak/fixture.py" inventory "$W/public" >"$W/public.inventory.json"
jq '{files:length, bytes:([.[].bytes]|add), objects:([keys[]|select(startswith("objects/"))]|length)}' "$W/public.inventory.json"
if [[ -n ${1:-} ]]; then
    [[ $1 == /* && -d $1 ]] || proof_fail 'Evidence destination must be an existing absolute directory'
    cp "$W/public.gpg" "$W/public.inventory.json" "$W/state.inventory.json" "$W/restored.restore.json" "$W/state/expected.json" "$W/state/heads.tsv" "$1/"
    for generation in 1 2 3; do
        mkdir "$1/generation-$generation"
        cp "$W/generation-$generation/summary" "$W/generation-$generation/summary.sig" "$W/generation-$generation/summary.idx" "$W/generation-$generation/summary.idx.sig" "$1/generation-$generation/"
        cp -a "$W/generation-$generation/summaries" "$1/generation-$generation/"
        cp "$W/generation-$generation.inventory.json" "$1/"
    done
    cp "$W/commit-signature.gpg" "$W/summary-signature.gpg" "$W/index-signature.gpg" "$1/"
fi
printf 'BOUNDARY: collection=none; minimum tested client=Flatpak 1.18.4 with OSTree 2026.2 on x86_64; legacy mismatch temporarily unavailable; local file transport only; no multi-object atomicity; production=defer\n'
if ((DEFER)); then proof_fail 'DEFER: required native client cases remain blocked'; fi
proof_pass 'Flatpak local core proof'
