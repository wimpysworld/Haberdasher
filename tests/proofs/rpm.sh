#!/usr/bin/env bash
# shellcheck source=tests/proofs/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
proof_init rpm
[[ $(id -u) != 0 ]] || proof_fail 'Run this proof as a normal user, not root.'

helper="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rpm/metadata.py"
work=$PROOF_WORK
mkdir -p "$work"/{source,build,db,stage1,stage2,published,state,logs}
operations="$work/operations"
: >"$operations"
# libdnf also reads the private HOME macros, without the command-line rpmrc.
rpm_lib="$(dirname "$(type -P rpm)")/../lib/rpm"
cat >"$HOME/.rpmmacros" <<EOF
%_dbpath $work/db
%_tmppath $TMPDIR
%_topdir $work/build
%_buildhost proof.invalid
%_signature gpg
%_gpg_path $GNUPGHOME
%__gpg $(type -P gpg)
%_gpg_digest_algo sha256
%_binary_filedigest_algorithm 8
%_source_filedigest_algorithm 8
%__os_install_post %{nil}
%_build_id_links none
EOF
printf 'include: %s/rpmrc\nmacrofiles: %s/macros:%s/macros.d/macros.*:%s/.rpmmacros\n' \
    "$rpm_lib" "$rpm_lib" "$rpm_lib" "$HOME" >"$work/rpmrc"
rpm_args=(--rcfile "$work/rpmrc")
rpm "${rpm_args[@]}" --eval '%{_dbpath} %{_tmppath} %{_topdir}' >"$work/paths"
[[ $(cat "$work/paths") == "$work/db $TMPDIR $work/build" ]] || proof_fail 'RPM paths are not private.'
proof_key
printf '%%_gpg_name %s\n' "$PROOF_FPR" >>"$HOME/.rpmmacros"
rpm "${rpm_args[@]}" --initdb
rpmkeys "${rpm_args[@]}" --import "$work/public.asc"
printf 'VERSION: %s\n' "$(rpm "${rpm_args[@]}" --version)" "$(createrepo_c --version)" "$(dnf5 --version | head -1)"
dnf5 --help >"$work/dnf-help"
for flag in --no-plugins --installroot --releasever --refresh --repo=; do
    grep -q -- "$flag" "$work/dnf-help" || proof_fail "DNF5 lacks $flag"
done

hash() { sha256sum "$1" | cut -d ' ' -f 1; }
same_bytes() { [[ $(hash "$1") == "$(hash "$2")" ]]; }
tree_hash() {
    (cd "$1" && find . -type f -print0 | sort -z | xargs -0 sha256sum) | sha256sum | cut -d ' ' -f 1
}
identity() {
    printf 'extract\n' >>"$operations"
    rpm "${rpm_args[@]}" -qp --qf '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}' "$1"
}
metadata() { python3 "$helper" "$@"; }
expect_reject() {
    local label=$1
    shift
    if "$@" >"$work/logs/rejection" 2>&1; then
        proof_fail "$label was accepted"
    fi
    proof_pass "$label rejected"
}
build_package() {
    local name=$1 version=$2 payload=$3 epoch=${4:-}
    local requires='' path="/opt/hd-proof/$name"
    if [[ $name == hd-proof-app ]]; then
        requires=$'Requires: hd-proof-data = 1-1\nRequires: /opt/hd-proof/hd-proof-data'
    fi
    cat >"$work/build/fixture.spec" <<EOF
Name: $name
Version: $version
Release: 1
${epoch:+Epoch: $epoch}
Summary: Disposable RPM proof fixture
License: MIT
BuildArch: noarch
AutoReqProv: no
$requires
%description
Disposable unsigned input. No upstream package or maintainer script.
%install
mkdir -p %{buildroot}/opt/hd-proof
printf '%s\n' '$payload' > %{buildroot}$path
%files
$path
%changelog
* Wed Jun 17 2026 Proof <proof@invalid> - $version-1
- Fixture payload $payload.
EOF
    rpmbuild "${rpm_args[@]}" -bb "$work/build/fixture.spec" >"$work/logs/build-$name-$version" 2>&1
    mv "$work/build/RPMS/noarch/$name-$version-1.noarch.rpm" "$work/source/$name-$version-1.noarch.rpm"
}
admit() {
    local source=$1 expected=$2 stage=$3 inventory=$4
    local actual key prior target published
    actual=$(hash "$source")
    [[ $actual == "$expected" ]] || return 1
    key=$(identity "$source") || return 1
    prior=$(grep -F "$key"$'\t' "$inventory" | cut -f 2) || prior=''
    if [[ -n $prior ]]; then
        [[ $actual == "$prior" ]]
        return
    fi
    target="$stage/$(basename "$source")"
    cp "$source" "$target"
    printf 'package-sign\n' >>"$operations"
    rpmsign "${rpm_args[@]}" --addsign "$target" >"$work/logs/sign" 2>&1 || return 1
    [[ $(identity "$target") == "$key" ]] || return 1
    published=$(hash "$target")
    [[ $published != "$actual" ]] || return 1
    rpmkeys "${rpm_args[@]}" --checksig --verbose "$target" >"$work/logs/checksig" 2>&1 || return 1
    grep -Eq 'RSA/SHA256 Signature.*: OK' "$work/logs/checksig" || return 1
    printf '%s\t%s\t%s\t%s\n' "$key" "$actual" "$published" "$(basename "$target")" >>"$inventory"
}
sign_metadata() {
    printf 'metadata-sign\n' >>"$operations"
    gpg --batch --yes --armor --digest-algo SHA256 --local-user "$PROOF_FPR" \
        --detach-sign --output "$1/repodata/repomd.xml.asc" "$1/repodata/repomd.xml"
}
validate_cache() {
    gpgv --keyring "$work/public.gpg" "$1/repodata/repomd.xml.asc" "$1/repodata/repomd.xml" || return 1
    metadata snapshot "$1" "$2"
}
index() {
    printf 'index\n' >>"$operations"
    createrepo_c --general-compress-type gz --checksum sha256 --no-database "$@"
}
immutable_copy() {
    local source=$1 target=$2
    if [[ -f $target ]]; then
        same_bytes "$source" "$target"
    else
        cp "$source" "$target"
    fi
}
publish() {
    local frozen=$1 inventory=$2 destination=$3 completed=$4 stop=${5:-none} item
    mkdir -p "$destination/repodata"
    for item in "$frozen"/*.rpm "$frozen"/repodata/*.gz; do
        [[ -f $item ]] || continue
        if [[ $item == *.rpm ]]; then
            immutable_copy "$item" "$destination/$(basename "$item")" || return 1
        else
            immutable_copy "$item" "$destination/repodata/$(basename "$item")" || return 1
        fi
    done
    [[ $stop != packages ]] || return 75
    cp "$frozen/repodata/repomd.xml" "$destination/repodata/repomd.xml"
    [[ $stop != entry ]] || return 75
    cp "$frozen/repodata/repomd.xml.asc" "$destination/repodata/repomd.xml.asc"
    [[ $stop != inventory ]] || return 75
    cp "$inventory" "$completed"
}
refresh_generation() {
    local stage=$1 retained=$2 inventory=$3 manifest=$4
    same_bytes "$manifest" "$work/state/manifest" && return 0
    validate_cache "$retained" "$inventory" >"$work/snapshot-gate" || return 1
    index --update --recycle-pkglist --skip-stat --pkglist "$work/new.list" \
        --read-pkgs-list "$work/read.list" "$stage"
}

build_package hd-proof-data 1 'dependency-v1'
build_package hd-proof-app 1 'application-v1'
build_package hd-proof-app 2 'application-v2' 0
: >"$work/inventory1"
source_app="$work/source/hd-proof-app-1-1.noarch.rpm"
expect_reject 'source SHA256 mismatch' admit "$source_app" "$(printf '%064d' 0)" "$work/stage1" "$work/inventory1"
[[ ! -s $work/inventory1 && ! -s $operations ]] || proof_fail 'Checksum rejection did package work.'
admit "$work/source/hd-proof-data-1-1.noarch.rpm" "$(hash "$work/source/hd-proof-data-1-1.noarch.rpm")" "$work/stage1" "$work/inventory1"
admit "$source_app" "$(hash "$source_app")" "$work/stage1" "$work/inventory1"
[[ $(identity "$source_app") == 'hd-proof-app|0|1|1|noarch' ]] || proof_fail 'Absent epoch did not normalise to zero.'
build_package hd-proof-app 1 'conflicting-payload' 0
[[ $(identity "$source_app") == 'hd-proof-app|0|1|1|noarch' ]] || proof_fail 'Explicit zero epoch changed identity.'
expect_reject 'changed bytes with equivalent zero epoch identity' admit "$source_app" "$(hash "$source_app")" "$work/stage1" "$work/inventory1"
index "$work/stage1"
sign_metadata "$work/stage1"
validate_cache "$work/stage1" "$work/inventory1" >"$work/snapshot1"
publish "$work/stage1" "$work/inventory1" "$work/published" "$work/state/inventory"
cp -r "$work/stage1/repodata" "$work/stage2/repodata"
# Historical package bytes remain only in published storage, not publisher inputs.
rm "$work/stage1"/*.rpm "$work/source/hd-proof-data-1-1.noarch.rpm" "$source_app"
[[ -z $(find "$work/stage1" "$work/stage2" -name '*.rpm' -print) ]] || proof_fail 'Historical RPM remains in staging.'
cp "$work/inventory1" "$work/inventory2"
admit "$work/source/hd-proof-app-2-1.noarch.rpm" "$(hash "$work/source/hd-proof-app-2-1.noarch.rpm")" "$work/stage2" "$work/inventory2"
printf 'hd-proof-app-2-1.noarch.rpm\n' >"$work/new.list"
printf 'generation-one\n' >"$work/state/manifest"
printf 'generation-two\n' >"$work/manifest2"
refresh_generation "$work/stage2" "$work/stage1" "$work/inventory1" "$work/manifest2"
sed "s|^$work/stage2/||" "$work/read.list" | sort >"$work/read.normalised"
same_bytes "$work/new.list" "$work/read.normalised"
sign_metadata "$work/stage2"
validate_cache "$work/stage2" "$work/inventory2" >"$work/snapshot2"
metadata compare "$work/snapshot1" "$work/snapshot2"
[[ $(wc -l <"$work/inventory2") == 3 ]] || proof_fail 'Generation two inventory is not exact.'
proof_pass 'Only the new RPM was parsed; all historical primary, filelists and changelogs remain exact.'
proof_pass 'Source and signed SHA256 differ; native identities remain unchanged; each new RPM is signed once.'
printf 'INVENTORY: identity, source SHA256, published SHA256, location\n'
cat "$work/inventory2"
frozen_hash=$(tree_hash "$work/stage2")

failures=0
run_case() {
    local name=$1 status
    shift
    set +e
    (
        set -e
        "$@"
    ) >"$work/logs/$name" 2>&1
    status=$?
    set -e
    if [[ $status == 0 ]]; then
        proof_pass "$name"
        grep '^CLIENT ' "$work/logs/$name" || true
    else
        cat "$work/logs/$name"
        printf 'FAIL: %s (exit %s)\n' "$name" "$status" >&2
        failures=$((failures + 1))
    fi
}
cache_case() {
    local kind=$1 mode=$2 damaged="$work/damaged-$1-$2" before published_before
    mkdir "$damaged"
    cp -r "$work/stage1/repodata" "$damaged/repodata"
    metadata damage "$damaged" "$kind" "$mode"
    if [[ $mode == incomplete || $mode == malformed ]]; then
        sign_metadata "$damaged"
    fi
    before=$(hash "$operations")
    published_before=$(tree_hash "$work/published")
    expect_reject "$kind $mode cache" refresh_generation "$work/stage2" "$damaged" "$work/inventory1" "$work/manifest2"
    [[ $(hash "$operations") == "$before" ]]
    same_bytes "$work/state/inventory" "$work/inventory1"
    [[ $(tree_hash "$work/published") == "$published_before" ]]
}
for kind in primary filelists other; do
    for mode in missing corrupt incomplete malformed; do
        run_case "cache-$kind-$mode" cache_case "$kind" "$mode"
    done
done
noop_case() {
    local before entry
    before=$(hash "$operations")
    entry=$(tree_hash "$work/published")
    refresh_generation "$work/stage2" "$work/stage1" "$work/inventory1" "$work/state/manifest"
    [[ $(hash "$operations") == "$before" && $(tree_hash "$work/published") == "$entry" ]]
    same_bytes "$work/state/inventory" "$work/inventory1"
}
run_case no-op-zero-extraction-signing-indexing noop_case
retry_case() {
    local stop=$1 destination="$work/retry-$1" completed="$work/completed-$1" before
    cp -r "$work/published" "$destination"
    cp "$work/inventory1" "$completed"
    before=$(hash "$operations")
    if publish "$work/stage2" "$work/inventory2" "$destination" "$completed" "$stop"; then
        proof_fail "No interruption after $stop"
    else
        [[ $? == 75 ]] || proof_fail "Unexpected publication error before $stop"
    fi
    same_bytes "$completed" "$work/inventory1"
    case "$stop" in
        packages) same_bytes "$destination/repodata/repomd.xml" "$work/stage1/repodata/repomd.xml" ;;
        entry)
            expect_reject 'split entry/signature pair' gpgv --keyring "$work/public.gpg" \
                "$destination/repodata/repomd.xml.asc" "$destination/repodata/repomd.xml"
            ;;
        inventory) validate_cache "$destination" "$work/inventory2" >"$work/retry-snapshot" ;;
    esac
    publish "$work/stage2" "$work/inventory2" "$destination" "$completed"
    [[ $(hash "$operations") == "$before" && $(tree_hash "$work/stage2") == "$frozen_hash" ]]
    same_bytes "$completed" "$work/inventory2"
    for item in "$work/stage2"/*.rpm "$work/stage2"/repodata/*; do
        if [[ $item == *.rpm ]]; then
            same_bytes "$item" "$destination/$(basename "$item")"
        else
            same_bytes "$item" "$destination/repodata/$(basename "$item")"
        fi
    done
    for item in "$work/published"/*.rpm "$work/published"/repodata/*.gz; do
        if [[ $item == *.rpm ]]; then
            same_bytes "$item" "$destination/$(basename "$item")"
        else
            same_bytes "$item" "$destination/repodata/$(basename "$item")"
        fi
    done
}
for boundary in packages entry inventory; do
    run_case "frozen-retry-$boundary" retry_case "$boundary"
done

native_crypto_case() {
    local mode=$1
    case "$mode" in
        unsigned-package)
            rpmkeys "${rpm_args[@]}" --define '_pkgverify_level signature' --checksig --verbose \
                "$work/stage2/hd-proof-app-2-1.noarch.rpm"
            expect_reject 'unsigned RPM with mandatory signature verification' \
                rpmkeys "${rpm_args[@]}" --define '_pkgverify_level signature' --checksig --verbose \
                "$work/source/hd-proof-app-2-1.noarch.rpm"
            ;;
        unsigned-metadata)
            expect_reject 'missing detached metadata signature' gpgv --keyring "$work/public.gpg" \
                "$work/absent.asc" "$work/stage2/repodata/repomd.xml"
            ;;
        old-entry-new-signature)
            expect_reject 'old entry and new signature' gpgv --keyring "$work/public.gpg" \
                "$work/stage2/repodata/repomd.xml.asc" "$work/stage1/repodata/repomd.xml"
            ;;
        new-entry-old-signature)
            expect_reject 'new entry and old signature' gpgv --keyring "$work/public.gpg" \
                "$work/stage1/repodata/repomd.xml.asc" "$work/stage2/repodata/repomd.xml"
            ;;
    esac
    validate_cache "$work/stage2" "$work/inventory2" >"$work/crypto-snapshot"
}
for mode in unsigned-package unsigned-metadata old-entry-new-signature new-entry-old-signature; do
    run_case "native-crypto-$mode" native_crypto_case "$mode"
done

client_setup() {
    local client=$1 c=${1#"$work"} r=${2#"$work"} keyring
    mkdir -p "$client"/{root,repos,vars,cache,log,persist,home,gnupg} "$work"/{dev,etc,run/user/0}
    # GPGME needs /dev/null during process setup. Keep the stand-in inside the disposable root.
    : >"$work/dev/null"
    printf '%%_dbpath /var/lib/rpm\n%%_tmppath /tmp\n' >"$client/home/.rpmmacros"
    cat >"$client/dnf.conf" <<EOF
[main]
reposdir=$c/repos
varsdir=$c/vars
cachedir=$c/cache
system_cachedir=$c/cache
logdir=$c/log
persistdir=$c/persist
gpgcheck=1
repo_gpgcheck=1
install_weak_deps=0
optional_metadata_types=filelists
keepcache=0
plugins=0
[proof]
name=Disposable local RPM proof
baseurl=file://$r
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///public.asc
skip_if_unavailable=0
metadata_expire=0
EOF
    # DNF5 uses the first eight SHA256 bytes of the URL for its repository cache.
    # Seed scoped public trust because librepo 1.20 cannot identify a missing key for DNF5's import retry.
    keyring="$client/cache/proof-$(printf 'file://%s' "$r" | sha256sum | cut -c 1-16)/pubring"
    mkdir -p "$keyring"
    cp "$work/public.gpg" "$keyring/pubring.gpg"
    printf 'no-autostart\n' >"$keyring/gpg.conf"
}
dnf_client() {
    local c=${1#"$work"}
    shift
    FAKECHROOT_EXCLUDE_PATH=/nix/store timeout 45 fakechroot -e none fakeroot chroot "$work" \
        "$(type -P env)" HOME="$c/home" GNUPGHOME="$c/gnupg" TMPDIR=/tmp \
        XDG_CONFIG_HOME="$c/home/.config" XDG_DATA_HOME="$c/home/.local/share" \
        XDG_CACHE_HOME="$c/home/.cache" XDG_STATE_HOME="$c/home/.local/state" XDG_RUNTIME_DIR=/run \
        "$(type -P dnf5)" --config "$c/dnf.conf" --installroot "$c/root" \
        --setopt="reposdir=$c/repos" --setopt="varsdir=$c/vars" \
        --setopt="cachedir=$c/cache" --setopt="system_cachedir=$c/cache" \
        --setopt="logdir=$c/log" --setopt="persistdir=$c/persist" \
        --releasever 1 --no-plugins --repo proof --assumeyes --refresh "$@"
}
client_state() {
    local client=$1 version=$2
    rpm "${rpm_args[@]}" --define '_dbpath /var/lib/rpm' --root "$client/root" -q --qf '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\n' \
        hd-proof-app hd-proof-data | sort >"$client/installed"
    printf 'hd-proof-app|0|%s|1|noarch\nhd-proof-data|0|1|1|noarch\n' "$version" >"$client/expected"
    same_bytes "$client/installed" "$client/expected"
    [[ $(cat "$client/root/opt/hd-proof/hd-proof-app") == "application-v$version" ]]
    [[ $(cat "$client/root/opt/hd-proof/hd-proof-data") == dependency-v1 ]]
    printf 'CLIENT STATE: app=%s-1.noarch; data=1-1.noarch; both payloads verified\n' "$version"
}
client_positive() {
    local client="$work/client-positive"
    client_setup "$client" "$work/published"
    dnf_client "$client" install hd-proof-app
    client_state "$client" 1
    publish "$work/stage2" "$work/inventory2" "$work/published" "$work/state/inventory"
    dnf_client "$client" upgrade hd-proof-app
    client_state "$client" 2
}
# Each negative starts from an installed version one and keeps its own client cache.
client_negative() {
    local mode=$1 client="$work/client-$1" repo="$work/repo-$1"
    cp -r "$work/published" "$repo"
    cp "$work/stage1/repodata/repomd.xml" "$repo/repodata/repomd.xml"
    cp "$work/stage1/repodata/repomd.xml.asc" "$repo/repodata/repomd.xml.asc"
    client_setup "$client" "$repo"
    dnf_client "$client" install hd-proof-app
    client_state "$client" 1
    publish "$work/stage2" "$work/inventory2" "$repo" "$client/completed"
    case "$mode" in
        unsigned-package)
            cp "$work/source/hd-proof-app-2-1.noarch.rpm" "$repo/hd-proof-app-2-1.noarch.rpm"
            index "$repo"
            sign_metadata "$repo"
            ;;
        unsigned-metadata) rm "$repo/repodata/repomd.xml.asc" ;;
        old-entry-new-signature) cp "$work/stage1/repodata/repomd.xml" "$repo/repodata/repomd.xml" ;;
        new-entry-old-signature) cp "$work/stage1/repodata/repomd.xml.asc" "$repo/repodata/repomd.xml.asc" ;;
    esac
    if dnf_client "$client" upgrade hd-proof-app >"$client/rejected.log" 2>&1; then
        cat "$client/rejected.log"
        proof_fail "$mode allowed a transaction"
    fi
    cat "$client/rejected.log"
    case "$mode" in
        unsigned-package) grep -Eiq 'not signed|signature.*(missing|failed|not found)|OpenPGP check.*failed' "$client/rejected.log" ;;
        unsigned-metadata) grep -Eiq 'repomd.xml.asc|signature.*(missing|failed|not found)' "$client/rejected.log" ;;
        *) grep -Eiq 'bad.*signature|signature.*(bad|invalid|verification|verify)|repomd.xml.*signature' "$client/rejected.log" ;;
    esac
    client_state "$client" 1
    printf 'CLIENT REJECTION: %s; signature failure and unchanged installed state verified\n' "$mode"
    cp "$work/stage2/hd-proof-app-2-1.noarch.rpm" "$repo/hd-proof-app-2-1.noarch.rpm"
    cp "$work/stage2/repodata/"* "$repo/repodata/"
    dnf_client "$client" upgrade hd-proof-app
    client_state "$client" 2
}
run_case native-dnf5-install-upgrade client_positive
for mode in unsigned-package unsigned-metadata old-entry-new-signature new-entry-old-signature; do
    run_case "native-$mode-and-refresh-recovery" client_negative "$mode"
done
[[ $(grep -c '^package-sign$' "$operations") == 3 ]] || proof_fail 'A package was signed more than once.'
printf 'ISOLATION: normal-user fakechroot/fakeroot UID 0 and chroot emulation, not a security boundary.\n'
printf 'POLICY: synthetic unsigned inputs only; preservation of upstream signatures remains a deferred production policy.\n'
if ((failures)); then
    proof_fail "$failures independent cases failed; native installation is deferred unless its case passed."
fi
proof_pass 'RPM proof complete: real DNF5 install, upgrade, trust rejection and normal refresh recovery.'
