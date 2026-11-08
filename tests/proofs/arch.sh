#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/proofs/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
proof_init arch
export LC_ALL=C

[[ $(uname -m) == x86_64 ]] || proof_fail 'This proof requires x86_64.'
[[ $(id -u) != 0 ]] || proof_fail 'Run this proof as a normal user.'
for tool in pacman makepkg repo-add vercmp fakeroot gpg bsdtar zstd; do
    command -v "$tool" >/dev/null || proof_fail "Missing tool: $tool"
done
printf 'CLIENT: %s\n' "$(readlink -f "$(command -v pacman)")"
pacman --version
repo-add --version
proof_key

hash() { sha256sum "$1" | cut -d ' ' -f 1; }
bytes_equal() { [[ $(hash "$1") == "$(hash "$2")" ]]; }
expect_reject() {
    local label=$1
    shift
    if "$@" >"$PROOF_WORK/rejection.log" 2>&1; then
        proof_fail "Unexpected acceptance: $label"
    fi
    proof_pass "Reject: $label"
}
sign() {
    gpg --batch --yes --local-user "$PROOF_FPR" --digest-algo SHA256 --detach-sign "$1"
}
verify() {
    local status
    [[ -s $1 && -s $2 ]] || return 1
    status=$(gpg --batch --status-fd 1 --verify "$2" "$1" 2>/dev/null) || return 1
    grep -Eq "^\[GNUPG:\] VALIDSIG $PROOF_FPR [^ ]+ [^ ]+ [^ ]+ [^ ]+ [^ ]+ 1 8 " <<<"$status"
}

mkdir -p "$PROOF_WORK/source" "$PROOF_WORK/publisher1" "$PROOF_WORK/publisher2" \
    "$PROOF_WORK/frozen1" "$PROOF_WORK/frozen2" "$PROOF_WORK/live"
pacman_prefix=$(dirname "$(dirname "$(command -v makepkg)")")
cat "$pacman_prefix/etc/makepkg.conf" >"$PROOF_WORK/makepkg.conf"
cat >>"$PROOF_WORK/makepkg.conf" <<'CONF'
BUILDENV=(!distcc !color !ccache !check !sign)
OPTIONS=(!strip docs libtool staticlibs emptydirs !zipman !purge !debug !lto !autodeps)
PKGEXT='.pkg.tar.zst'
CONF

fixture() {
    local name=$1 version=$2 content=$3 dir="$PROOF_WORK/build-$1-$2-$3"
    mkdir -p "$dir"
    cat >"$dir/PKGBUILD" <<PKG
pkgname=$name
pkgver=$version
pkgrel=${4:-1}
pkgdesc='Disposable data-only Arch proof'
arch=('x86_64')
license=('MIT')
package() {
    install -Dm644 /dev/null "\$pkgdir/usr/share/arch-proof/$name.txt"
    printf '%s\\n' '$content' >"\$pkgdir/usr/share/arch-proof/$name.txt"
}
PKG
    if [[ $name == keeper ]]; then
        printf "depends=('updateable>=1')\n" >>"$dir/PKGBUILD"
    fi
    (cd "$dir" && makepkg --nodeps --config "$PROOF_WORK/makepkg.conf") >"$dir/build.log" 2>&1 || {
        cat "$dir/build.log"
        proof_fail "makepkg failed: $name $version"
    }
    cp "$dir/$name-$version-${4:-1}-x86_64.pkg.tar.zst" "$PROOF_WORK/source/$name-$version-$content.pkg.tar.zst"
}
fixture keeper 1 keeper-1
fixture updateable 1 updateable-1
fixture updateable 2 updateable-2
fixture keeper 1 changed
fixture checksum-probe 1 original
checksum_source="$PROOF_WORK/source/checksum-probe-1-original.pkg.tar.zst"
hash "$checksum_source" >"$PROOF_WORK/release.sha256"
fixture checksum-probe 1 changed

mkdir -p "$PROOF_WORK/identity-root" "$PROOF_WORK/identity-db"
identity() {
    local file=$1 name version architecture
    read -r name version < <(pacman --config /dev/null --root "$PROOF_WORK/identity-root" --dbpath "$PROOF_WORK/identity-db" -Qp "$file")
    architecture=$(pacman --config /dev/null --root "$PROOF_WORK/identity-root" --dbpath "$PROOF_WORK/identity-db" -Qip "$file" | sed -n 's/^Architecture *: //p')
    [[ -n $name && -n $version && $architecture == x86_64 ]] || return 1
    printf '%s\t%s\t%s\n' "$name" "$version" "$architecture"
}
: >"$PROOF_WORK/history"
import_package() {
    local file=$1 expected=$2 target=$3 name version architecture oldname oldversion oldarch digest actual metadata
    actual=$(hash "$file")
    if [[ $actual != "$expected" ]]; then
        printf '%s\n' 'Source checksum mismatch.' >&2
        return 1
    fi
    metadata=$(identity "$file") || return 1
    read -r name version architecture <<<"$metadata"
    while read -r oldname oldversion oldarch digest; do
        if [[ $name == "$oldname" && $architecture == "$oldarch" && $(vercmp "$version" "$oldversion") == 0 ]]; then
            [[ $actual == "$digest" ]] || return 1
            return 0
        fi
    done <"$PROOF_WORK/history"
    cp "$file" "$target/$name-$version-$architecture.pkg.tar.zst"
    printf '%s\t%s\t%s\t%s\n' "$name" "$version" "$architecture" "$actual" >>"$PROOF_WORK/history"
}
keeper='keeper-1-1-x86_64.pkg.tar.zst'
old=updateable-1-1-x86_64.pkg.tar.zst
new=updateable-2-1-x86_64.pkg.tar.zst
for name in keeper updateable; do
    src="$PROOF_WORK/source/$name-1-$name-1.pkg.tar.zst"
    import_package "$src" "$(hash "$src")" "$PROOF_WORK/publisher1"
done
history_before=$(hash "$PROOF_WORK/history")
import_package "$PROOF_WORK/source/keeper-1-keeper-1.pkg.tar.zst" "$(hash "$PROOF_WORK/source/keeper-1-keeper-1.pkg.tar.zst")" "$PROOF_WORK/publisher2"
[[ $(hash "$PROOF_WORK/history") == "$history_before" && ! -e $PROOF_WORK/publisher2/$keeper ]] || proof_fail 'Unchanged import was not a no-op.'
proof_pass 'Unchanged native identity is a no-op'
read -r release_checksum <"$PROOF_WORK/release.sha256"
[[ $release_checksum =~ ^[a-f0-9]{64}$ ]] || proof_fail 'Expected a recorded release SHA256.'
checksum_identity=$(identity "$checksum_source")
[[ $checksum_identity == $'checksum-probe\t1-1\tx86_64' ]] || proof_fail 'Unexpected checksum fixture identity.'
! grep -q '^checksum-probe[[:space:]]' "$PROOF_WORK/history" || proof_fail 'Checksum fixture identity is not fresh.'
cp "$PROOF_WORK/source/checksum-probe-1-changed.pkg.tar.zst" "$checksum_source"
[[ $(identity "$checksum_source") == "$checksum_identity" ]] || proof_fail 'Changed checksum fixture is not a valid matching native identity.'
[[ $(hash "$checksum_source") != "$release_checksum" ]] || proof_fail 'Checksum fixture bytes did not change.'
outputs_before=$(find "$PROOF_WORK"/{publisher1,publisher2,frozen1,frozen2,live} -type f -exec sha256sum {} + | sort)
expect_reject 'fresh native identity with changed bytes against recorded release checksum' import_package "$checksum_source" "$release_checksum" "$PROOF_WORK/publisher2"
grep -qx 'Source checksum mismatch.' "$PROOF_WORK/rejection.log" || proof_fail 'Source rejection did not identify the checksum mismatch.'
[[ $(hash "$PROOF_WORK/history") == "$history_before" ]] || proof_fail 'Checksum failure advanced identity history.'
[[ -z $(find "$PROOF_WORK/publisher2" -mindepth 1 -print -quit) ]] || proof_fail 'Checksum failure imported or indexed a package.'
[[ $(find "$PROOF_WORK"/{publisher1,publisher2,frozen1,frozen2,live} -type f -exec sha256sum {} + | sort) == "$outputs_before" ]] || proof_fail 'Checksum failure changed signing, index or publication state.'
proof_pass 'Release checksum rejection precedes import, signing, indexing and state advancement'
expect_reject 'changed bytes for existing identity' import_package "$PROOF_WORK/source/keeper-1-changed.pkg.tar.zst" "$(hash "$PROOF_WORK/source/keeper-1-changed.pkg.tar.zst")" "$PROOF_WORK/publisher2"
[[ $(vercmp 1-1 1-01) == 0 ]] || proof_fail 'Expected native equivalent release versions.'
fixture keeper 1 equivalent-release 01
expect_reject 'native equivalent-version conflict' import_package "$PROOF_WORK/source/keeper-1-equivalent-release.pkg.tar.zst" "$(hash "$PROOF_WORK/source/keeper-1-equivalent-release.pkg.tar.zst")" "$PROOF_WORK/publisher2"
[[ $(vercmp 2-1 1-1) == 1 ]] || proof_fail 'Native update order failed.'

for pkg in "$PROOF_WORK/publisher1/"*.pkg.tar.zst; do
    before=$(hash "$pkg")
    ! bsdtar -tf "$pkg" | grep -qx '.INSTALL' || proof_fail 'Fixture contains an install script.'
    sign "$pkg"
    [[ $(hash "$pkg") == "$before" ]] || proof_fail 'Detached signing changed package bytes.'
    verify "$pkg" "$pkg.sig" || proof_fail 'Package signature failed.'
done
(cd "$PROOF_WORK/publisher1" && repo-add --include-sigs --sign --key "$PROOF_FPR" proof.db.tar.gz "$keeper" "$old")

state_gate() {
    local dir=$1 kind
    for kind in db files; do
        verify "$dir/proof.$kind.tar.gz" "$dir/proof.$kind.tar.gz.sig" || return 1
    done
}
output_gate() {
    local dir=$1 kind record filename checksum embedded count
    state_gate "$dir" || return 1
    for kind in db files; do
        [[ $(readlink "$dir/proof.$kind") == "proof.$kind.tar.gz" ]] || return 1
        [[ $(readlink "$dir/proof.$kind.sig") == "proof.$kind.tar.gz.sig" ]] || return 1
        count=0
        while read -r record; do
            [[ $record == */desc ]] || continue
            count=$((count + 1))
            filename=$(bsdtar -xOf "$dir/proof.$kind.tar.gz" "$record" | sed -n '/^%FILENAME%$/{n;p;}')
            [[ $filename != */* && -n $filename ]] || return 1
            verify "$dir/$filename" "$dir/$filename.sig" || return 1
            checksum=$(bsdtar -xOf "$dir/proof.$kind.tar.gz" "$record" | sed -n '/^%SHA256SUM%$/{n;p;}') || return 1
            [[ $checksum == "$(hash "$dir/$filename")" ]] || return 1
            embedded=$(bsdtar -xOf "$dir/proof.$kind.tar.gz" "$record" | sed -n '/^%PGPSIG%$/{n;p;}')
            [[ -n $embedded ]] || return 1
            printf '%s' "$embedded" | base64 -d >"$PROOF_WORK/embedded.sig" || return 1
            bytes_equal "$dir/$filename.sig" "$PROOF_WORK/embedded.sig" || return 1
            verify "$dir/$filename" "$PROOF_WORK/embedded.sig" || return 1
        done < <(bsdtar -tf "$dir/proof.$kind.tar.gz")
        [[ $count == 2 ]] || return 1
    done
}
output_gate "$PROOF_WORK/publisher1" || proof_fail 'Generation 1 output gate failed.'
cp -a "$PROOF_WORK/publisher1/." "$PROOF_WORK/frozen1/"
cp "$PROOF_WORK/history" "$PROOF_WORK/frozen1/history"
state_gate "$PROOF_WORK/frozen1" || proof_fail 'Retained state failed verification.'
for kind in db files; do
    cp "$PROOF_WORK/frozen1/proof.$kind.tar.gz" "$PROOF_WORK/frozen1/proof.$kind.tar.gz.sig" "$PROOF_WORK/publisher2/"
done
src="$PROOF_WORK/source/updateable-2-updateable-2.pkg.tar.zst"
import_package "$src" "$(hash "$src")" "$PROOF_WORK/publisher2"
before=$(hash "$PROOF_WORK/publisher2/$new")
sign "$PROOF_WORK/publisher2/$new"
[[ $(hash "$PROOF_WORK/publisher2/$new") == "$before" ]] || proof_fail 'Update signing changed package bytes.'
[[ ! -e $PROOF_WORK/publisher2/$keeper && ! -e $PROOF_WORK/publisher2/$old ]] || proof_fail 'Historical packages reached the generation 2 publisher.'
(cd "$PROOF_WORK/publisher2" && repo-add --include-sigs --sign --key "$PROOF_FPR" proof.db.tar.gz "$new")
cp -a "$PROOF_WORK/publisher2/." "$PROOF_WORK/frozen2/"
cp "$PROOF_WORK/history" "$PROOF_WORK/frozen2/history"
cp "$PROOF_WORK/frozen1/"*.pkg.tar.zst* "$PROOF_WORK/frozen2/"
output_gate "$PROOF_WORK/frozen2" || proof_fail 'Generation 2 output gate failed.'
for kind in db files; do
    for generation in 1 2; do
        dependency=$(bsdtar -xOf "$PROOF_WORK/frozen$generation/proof.$kind.tar.gz" keeper-1-1/desc | sed -n '/^%DEPENDS%$/{n;p;}')
        [[ $dependency == 'updateable>=1' ]] || proof_fail "Missing keeper dependency in generation $generation $kind."
    done
    proof_pass "$kind retains the non-empty keeper dependency across generations"
    bytes_equal <(bsdtar -xOf "$PROOF_WORK/frozen1/proof.$kind.tar.gz" keeper-1-1/desc) <(bsdtar -xOf "$PROOF_WORK/frozen2/proof.$kind.tar.gz" keeper-1-1/desc) || proof_fail 'Keeper metadata changed.'
    entries=$(bsdtar -tf "$PROOF_WORK/frozen2/proof.$kind.tar.gz")
    grep -qx 'updateable-2-1/desc' <<<"$entries" || proof_fail 'Missing active update.'
    ! grep -q '^updateable-1-1/' <<<"$entries" || proof_fail 'Old version remains active.'
done
bytes_equal <(bsdtar -xOf "$PROOF_WORK/frozen1/proof.files.tar.gz" keeper-1-1/files) <(bsdtar -xOf "$PROOF_WORK/frozen2/proof.files.tar.gz" keeper-1-1/files) || proof_fail 'Keeper file records changed.'
proof_pass 'Both signed native archives retain keeper records with only the new package available'

for kind in db files; do
    fault_dir="$PROOF_WORK/fault-checksum-$kind"
    mkdir -p "$fault_dir/records"
    cp -a "$PROOF_WORK/frozen2/." "$fault_dir/"
    bsdtar -xf "$fault_dir/proof.$kind.tar.gz" -C "$fault_dir/records"
    correct=$(hash "$fault_dir/$keeper")
    wrong=$(hash "$fault_dir/$new")
    [[ $correct != "$wrong" ]] || proof_fail 'Checksum fixtures have identical bytes.'
    for checksum in "$wrong" "$correct"; do
        sed -i "/^%SHA256SUM%$/{n;s|.*|$checksum|;}" "$fault_dir/records/keeper-1-1/desc"
        bsdtar -czf "$fault_dir/proof.$kind.tar.gz" -C "$fault_dir/records" keeper-1-1 updateable-2-1
        sign "$fault_dir/proof.$kind.tar.gz"
        state_gate "$fault_dir" || proof_fail 'Checksum test metadata is not validly signed.'
        if [[ $checksum == "$wrong" ]]; then
            expect_reject "$kind keeper checksum belongs to another signed package" output_gate "$fault_dir"
            [[ ! -e $fault_dir/inventory ]] || proof_fail 'Checksum failure advanced inventory.'
        else
            output_gate "$fault_dir" || proof_fail 'Checksum-only repair failed the output gate.'
            proof_pass "$kind checksum-only repair passes with unchanged packages and package signatures"
        fi
    done
done

for absent in proof.files.tar.gz proof.db.tar.gz.sig proof.files.tar.gz.sig "$new.sig"; do
    mkdir "$PROOF_WORK/fault-$absent"
    cp -a "$PROOF_WORK/frozen2/." "$PROOF_WORK/fault-$absent/"
    rm "$PROOF_WORK/fault-$absent/$absent"
    expect_reject "missing $absent before inventory" output_gate "$PROOF_WORK/fault-$absent"
    [[ ! -e $PROOF_WORK/fault-$absent/inventory ]] || proof_fail 'Failed gate advanced inventory.'
done
mkdir "$PROOF_WORK/fault-bin"
real_gpg=$(command -v gpg)
cat >"$PROOF_WORK/fault-bin/gpg" <<'FAULT'
#!/usr/bin/env bash
for arg in "$@"; do
    if [[ $arg == --detach-sign ]]; then
        printf '%s\n' "$FAULT_MODE" >>"$PROOF_WORK/fault-sign-calls"
        [[ $FAULT_MODE != zero-output ]] || exit 0
        exec "$REAL_GPG" --batch --local-user 0000000000000000000000000000000000000000 --detach-sign "${!#}"
    fi
done
exec "$REAL_GPG" "$@"
FAULT
chmod 700 "$PROOF_WORK/fault-bin/gpg"
for fault in sign-control sign-failure zero-output; do
    mkdir "$PROOF_WORK/$fault"
    for pkg in "$keeper" "$new"; do
        cp "$PROOF_WORK/frozen2/$pkg" "$PROOF_WORK/frozen2/$pkg.sig" "$PROOF_WORK/$fault/"
    done
    if [[ $fault == sign-control ]]; then
        (cd "$PROOF_WORK/$fault" && repo-add --include-sigs --sign --key "$PROOF_FPR" proof.db.tar.gz "$keeper" "$new")
        output_gate "$PROOF_WORK/$fault" || proof_fail 'Two-record signing control failed.'
        proof_pass 'Actual signer passes the two-record output gate for both archives'
        continue
    fi
    status=0
    (cd "$PROOF_WORK/$fault" && PATH="$PROOF_WORK/fault-bin:$PATH" REAL_GPG="$real_gpg" FAULT_MODE="$fault" repo-add --include-sigs --sign --key "$PROOF_FPR" proof.db.tar.gz "$keeper" "$new") >"$PROOF_WORK/$fault.log" 2>&1 || status=$?
    grep -qx "$fault" "$PROOF_WORK/fault-sign-calls" || proof_fail 'Signing fault did not run.'
    [[ $status == 0 ]] || proof_fail "Expected native zero exit for $fault."
    for kind in db files; do
        # Keep aliases present so missing signature bytes alone cause rejection.
        ln -s "proof.$kind.tar.gz.sig" "$PROOF_WORK/$fault/proof.$kind.sig"
        expect_reject "$fault $kind signature" verify "$PROOF_WORK/$fault/proof.$kind.tar.gz" "$PROOF_WORK/$fault/proof.$kind.tar.gz.sig"
    done
    expect_reject "$fault before inventory (repo-add exit $status)" output_gate "$PROOF_WORK/$fault"
    [[ ! -e $PROOF_WORK/$fault/inventory ]] || proof_fail 'Signing fault advanced inventory.'
    for kind in db files; do
        sign "$PROOF_WORK/$fault/proof.$kind.tar.gz"
    done
    output_gate "$PROOF_WORK/$fault" || proof_fail 'Signature-only repair did not pass the output gate.'
    proof_pass "$fault signature-only repair passes both archives, record counts and package signatures"
done

for generation in 1 2; do
    (
        cd "$PROOF_WORK/frozen$generation"
        sha256sum ./*.pkg.tar.zst* proof.db proof.db.sig proof.files proof.files.sig >inventory
        sha256sum history inventory ./*.pkg.tar.zst* proof.db.tar.gz proof.db.tar.gz.sig proof.files.tar.gz proof.files.tar.gz.sig >generation.sha256
    )
done
publish() {
    local generation=$1 stop=${2:-complete} kind
    local frozen="$PROOF_WORK/frozen$generation" live="$PROOF_WORK/live"
    (cd "$frozen" && sha256sum --status -c generation.sha256) || return 1
    cp "$frozen/"*.pkg.tar.zst* "$live/"
    [[ $stop != packages ]] || return 1
    for kind in db files; do
        cp "$frozen/proof.$kind.tar.gz" "$live/proof.$kind"
        [[ $stop != "$kind" ]] || return 1
        cp "$frozen/proof.$kind.tar.gz.sig" "$live/proof.$kind.sig"
    done
    [[ $stop != inventory ]] || return 1
    cp "$frozen/inventory" "$live/inventory"
}
publish 1

client="$PROOF_WORK/client"
mkdir -p "$client"/{root,db,cache,gpg,hooks}
gpg --homedir "$client/gpg" --batch --no-autostart --no-default-keyring --keyring "$client/gpg/pubring.gpg" --import "$PROOF_WORK/public.gpg"
printf '%s:6:\n' "$PROOF_FPR" | gpg --homedir "$client/gpg" --batch --no-autostart --import-ownertrust
[[ -z $(gpg --homedir "$client/gpg" --batch --no-autostart --with-colons --list-secret-keys) ]] || proof_fail 'Client keyring contains a secret key.'
cat >"$client/pacman.conf" <<CONF
[options]
RootDir = $client/root
DBPath = $client/db
CacheDir = $client/cache
LogFile = $client/pacman.log
GPGDir = $client/gpg
HookDir = $client/hooks
Architecture = x86_64
SigLevel = Required TrustedOnly
LocalFileSigLevel = Required TrustedOnly
RemoteFileSigLevel = Required TrustedOnly
[proof]
Server = file://$PROOF_WORK/live
CONF
native() {
    local field path
    for field in RootDir DBPath CacheDir LogFile GPGDir HookDir; do
        path=$(sed -n "s/^$field = //p" "$client/pacman.conf")
        [[ $path == "$PROOF_WORK/client/"* && $(realpath -m "$path") == "$path" ]] || proof_fail "Unsafe client $field"
    done
    fakeroot pacman --config "$client/pacman.conf" --noconfirm "$@"
}
file_search() {
    local name=$1 version=$2 result
    result=$(native -F "usr/share/arch-proof/$name.txt") || return 1
    printf '%s\n' "$result"
    grep -Fq "is owned by proof/$name $version" <<<"$result"
}
native -Syy
native -S keeper
[[ $(native -Q keeper) == 'keeper 1-1' && $(native -Q updateable) == 'updateable 1-1' ]] || proof_fail 'Generation 1 install failed.'
[[ $(cat "$client/root/usr/share/arch-proof/keeper.txt") == keeper-1 && $(cat "$client/root/usr/share/arch-proof/updateable.txt") == updateable-1 ]] || proof_fail 'Generation 1 payload mismatch.'
native -Fyy
file_search keeper 1-1
proof_pass 'Strict native refresh, dependency-resolved install, query, payload and file search'

for boundary in packages db files inventory; do
    publish 1
    completed=$(hash "$PROOF_WORK/live/inventory")
    expect_reject "interruption after $boundary" publish 2 "$boundary"
    [[ $(hash "$PROOF_WORK/live/inventory") == "$completed" ]] || proof_fail 'Interruption advanced inventory.'
    publish 2
    for kind in db files; do
        bytes_equal "$PROOF_WORK/live/proof.$kind" "$PROOF_WORK/frozen2/proof.$kind.tar.gz"
        bytes_equal "$PROOF_WORK/live/proof.$kind.sig" "$PROOF_WORK/frozen2/proof.$kind.tar.gz.sig"
    done
    for pkg in "$keeper" "$old" "$new"; do
        bytes_equal "$PROOF_WORK/live/$pkg" "$PROOF_WORK/frozen2/$pkg"
        bytes_equal "$PROOF_WORK/live/$pkg.sig" "$PROOF_WORK/frozen2/$pkg.sig"
    done
    bytes_equal "$PROOF_WORK/live/inventory" "$PROOF_WORK/frozen2/inventory"
    native -Syy
    native -Fyy
    proof_pass "Exact frozen recovery after $boundary, without signing or deletion"
done
native -Su
[[ $(native -Q keeper) == 'keeper 1-1' && $(native -Q updateable) == 'updateable 2-1' ]] || proof_fail 'Generation 2 update failed.'
[[ $(cat "$client/root/usr/share/arch-proof/updateable.txt") == updateable-2 ]] || proof_fail 'Generation 2 payload mismatch.'
file_search keeper 1-1
file_search updateable 2-1
proof_pass 'Strict native generation 2 update and retained file search'

for kind in db files; do
    operation=-Syy
    [[ $kind != files ]] || operation=-Fyy
    for pair in '1 2' '2 1'; do
        read -r data_generation signature_generation <<<"$pair"
        publish 2
        cp "$PROOF_WORK/frozen$data_generation/proof.$kind.tar.gz" "$PROOF_WORK/live/proof.$kind"
        cp "$PROOF_WORK/frozen$signature_generation/proof.$kind.tar.gz.sig" "$PROOF_WORK/live/proof.$kind.sig"
        expect_reject "$kind generation $data_generation with signature $signature_generation" native "$operation"
        publish 2
        native "${operation%y}"
        bytes_equal "$client/db/sync/proof.$kind" "$PROOF_WORK/frozen2/proof.$kind.tar.gz" || proof_fail 'Recovered client metadata differs from frozen bytes.'
        proof_pass "$kind matching frozen generation restores normal strict refresh"
    done
    cp "$PROOF_WORK/live/$keeper.sig" "$PROOF_WORK/live/proof.$kind.sig"
    expect_reject "invalid $kind signature" native "$operation"
    publish 2
    rm "$PROOF_WORK/live/proof.$kind.sig"
    expect_reject "missing $kind signature" native "$operation"
    publish 2
    native "$operation"
done

# Valid metadata signatures and unchanged package digests isolate package verification.
mkdir "$PROOF_WORK/bad-package" "$PROOF_WORK/bad-extract"
native -R keeper updateable
for fault in invalid missing; do
    publish 2
    bsdtar -xf "$PROOF_WORK/frozen2/proof.db.tar.gz" -C "$PROOF_WORK/bad-extract"
    if [[ $fault == invalid ]]; then
        wrong=$(base64 -w0 "$PROOF_WORK/frozen2/$keeper.sig")
        sed -i "/^%PGPSIG%$/{n;s|.*|$wrong|;}" "$PROOF_WORK/bad-extract/updateable-2-1/desc"
        cp "$PROOF_WORK/frozen2/$keeper.sig" "$PROOF_WORK/live/$new.sig"
    else
        sed -i '/^%PGPSIG%$/{N;d;}' "$PROOF_WORK/bad-extract/updateable-2-1/desc"
        rm "$PROOF_WORK/live/$new.sig"
    fi
    bsdtar -czf "$PROOF_WORK/bad-package/proof.db.tar.gz" -C "$PROOF_WORK/bad-extract" keeper-1-1 updateable-2-1
    sign "$PROOF_WORK/bad-package/proof.db.tar.gz"
    verify "$PROOF_WORK/bad-package/proof.db.tar.gz" "$PROOF_WORK/bad-package/proof.db.tar.gz.sig" || proof_fail 'Negative metadata is not validly signed.'
    cp "$PROOF_WORK/bad-package/proof.db.tar.gz" "$PROOF_WORK/live/proof.db"
    cp "$PROOF_WORK/bad-package/proof.db.tar.gz.sig" "$PROOF_WORK/live/proof.db.sig"
    [[ $(hash "$PROOF_WORK/live/$new") == "$(bsdtar -xOf "$PROOF_WORK/live/proof.db" updateable-2-1/desc | sed -n '/^%SHA256SUM%$/{n;p;}')" ]] || proof_fail 'Negative package checksum changed.'
    native -Syy
    rm -f "$client/cache/"*.pkg.tar.zst*
    expect_reject "$fault package signature with valid signed metadata and correct checksum" native -S updateable
    if [[ $fault == invalid ]]; then
        grep -Ei 'signature.*invalid|invalid.*signature' "$PROOF_WORK/rejection.log" || proof_fail 'Package rejection did not identify an invalid signature.'
    else
        grep -F "failed retrieving file '$new.sig'" "$PROOF_WORK/rejection.log" || proof_fail 'Package rejection did not identify a missing signature.'
    fi
    expect_reject "$fault signature leaves package uninstalled" native -Q updateable
    [[ ! -e $client/root/usr/share/arch-proof/updateable.txt ]] || proof_fail 'Unverified payload was installed.'
done
publish 2
native -Syy
native -S keeper
[[ $(cat "$client/root/usr/share/arch-proof/updateable.txt") == updateable-2 ]] || proof_fail 'Recovered payload mismatch.'
proof_pass 'Matching frozen package and metadata recover strict installation'

mv "$client/gpg" "$client/trusted-gpg"
mkdir "$client/gpg"
gpg --homedir "$client/gpg" --batch --no-autostart --no-default-keyring --keyring "$client/gpg/pubring.gpg" --import "$PROOF_WORK/public.gpg"
expect_reject 'untrusted repository signing key' native -Syy
mv "$client/gpg" "$client/untrusted-gpg"
mv "$client/trusted-gpg" "$client/gpg"
native -Syy
native -Fyy
file_search keeper 1-1
[[ -f $PROOF_WORK/live/$old ]] || proof_fail 'Historical object was deleted.'
printf '%s\n' 'DEFER: official Arch distribution coverage. This run tests only the printed Nix pacman build.' \
    'DECISION: split metadata fails closed and exact-byte retry recovers locally; production availability policy remains deferred.'
proof_pass 'Arch local two-generation proof complete'
proof_finish
