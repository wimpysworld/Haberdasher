#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/proofs/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
proof_init apk
W=$PROOF_WORK
export LC_ALL=C SOURCE_DATE_EPOCH=1794000000
export ABUILD_CONF="$W/abuild.conf" ABUILD_USERCONF="$W/abuild-user.conf"
export ABUILD_DEFCONF="$W/abuild-default.conf" ABUILD_USERDIR="$W/abuild"
: >"$ABUILD_CONF"
: >"$ABUILD_USERCONF"
: >"$ABUILD_DEFCONF"
trap 'cat "$W"/logs/*; proof_fail "Alpine proof stopped at line $LINENO"' ERR
mkdir -p "$W/keys" "$W/empty" "$W/logs" "$W/admitted" "$W/source" "$W/pending" "$W/repo/x86_64"
: >"$W/ledger"
: >"$W/signatures"
sha() { sha256sum "$1" | cut -d' ' -f1; }
same() { [[ $(sha "$1") == "$(sha "$2")" ]]; }
reject() {
    if "$@"; then proof_fail "Unexpected acceptance: $*"; fi
}
gp() { gpg --batch --yes --pinentry-mode loopback "$@"; }
sm() { gpgsm --no-options --no-common-certs-import --disable-dirmngr --batch --pinentry-mode loopback "$@"; }
archive() {
    local dir=$1
    shift
    tar --format=ustar --owner=0 --group=0 --numeric-owner -cf "$W/archive.tar" -C "$dir" "$@"
    abuild-tar --cut <"$W/archive.tar" | gzip -n -9
}
split_signature() {
    python3 - "$@" <<'PY'
import sys, zlib
raw = open(sys.argv[1], 'rb').read()
z = zlib.decompressobj(31)
z.decompress(raw)
n = len(raw) - len(z.unused_data)
open(sys.argv[2], 'wb').write(raw[:n])
open(sys.argv[3], 'wb').write(raw[n:])
PY
}
convert_key() {
    proof_key
    gp --with-colons --with-keygrip --list-secret-keys >"$W/key.list"
    [[ $(grep -c '^sec:' "$W/key.list") == 1 ]]
    reject grep -q '^ssb:' "$W/key.list"
    grep -Eq '^sec:[^:]*:4096:1:' "$W/key.list"
    usage=$(grep '^sec:' "$W/key.list" | cut -d: -f12)
    [[ $usage == *s* && $usage == *c* && $usage != *e* ]]
    grip=$(grep '^grp:' "$W/key.list" | cut -d: -f10)
    gp --export-secret-keys "$PROOF_FPR" >"$W/canonical-secret.gpg"
    gp --import "$W/canonical-secret.gpg"
    cat >"$W/cert.batch" <<EOF
Key-Type: RSA
Key-Grip: $grip
Key-Usage: sign
Name-DN: CN=Haberdasher Disposable Alpine Proof
Serial: 01
Hash-Algo: sha256
%commit
EOF
    sm --output "$W/cert.der" --generate-key "$W/cert.batch"
    sm --import "$W/cert.der"
    sm --with-colons --with-keygrip --list-secret-keys >"$W/cert.list"
    [[ $grip == "$(grep '^grp:' "$W/cert.list" | cut -d: -f10)" ]]
    sm --armor --export-secret-key-p8 "$(grep '^fpr:' "$W/cert.list" | cut -d: -f10)" >"$W/alpine.rsa"
    openssl pkey -in "$W/alpine.rsa" -check -noout
    gp --with-colons --with-key-data --list-keys "$PROOF_FPR" >"$W/mpi"
    cat >"$W/asn1" <<EOF
asn1=SEQUENCE:rsakey
[rsakey]
n=INTEGER:0x$(grep '^pkd:0:' "$W/mpi" | cut -d: -f4)
e=INTEGER:0x$(grep '^pkd:1:' "$W/mpi" | cut -d: -f4)
EOF
    openssl asn1parse -genconf "$W/asn1" -out "$W/rsa.der" -noout
    openssl rsa -RSAPublicKey_in -inform DER -in "$W/rsa.der" -pubout -outform DER >"$W/gpg.der"
    openssl x509 -inform DER -in "$W/cert.der" -pubkey -noout | openssl pkey -pubin -outform DER >"$W/x509.der"
    openssl pkey -in "$W/alpine.rsa" -pubout -outform DER >"$W/pem.der"
    same "$W/gpg.der" "$W/x509.der"
    same "$W/gpg.der" "$W/pem.der"
    [[ $(find "$GNUPGHOME/private-keys-v1.d" -name '*.key' | wc -l) == 1 ]]
    openssl pkey -in "$W/alpine.rsa" -pubout >"$W/keys/alpine.rsa.pub"
    proof_pass 'One disposable RSA4096 primary: OpenPGP, X.509 and PKCS#8 public DER and keygrips agree.'
}
new_client() {
    local name=$1 repo=$2 trust=${3:-yes} d="$W/client-$1"
    mkdir -p "$d/root/etc/apk/keys" "$d/cache" "$d/downloads"
    : >"$d/repositories"
    client "$name" add --initdb --usermode --no-scripts --no-commit-hooks >/dev/null
    printf '%s\n' "$repo" >"$d/repositories"
    if [[ $trust == yes ]]; then cp "$W/keys/alpine.rsa.pub" "$d/root/etc/apk/keys/"; fi
    if [[ $trust == wrong ]]; then
        # A different public modulus needs no second private key.
        sed 's/n=INTEGER:0x/n=INTEGER:0x1/' "$W/asn1" >"$d/asn1"
        openssl asn1parse -genconf "$d/asn1" -out "$d/wrong.der" -noout
        openssl rsa -RSAPublicKey_in -inform DER -in "$d/wrong.der" -pubout >"$d/root/etc/apk/keys/alpine.rsa.pub"
        reject same "$W/keys/alpine.rsa.pub" "$d/root/etc/apk/keys/alpine.rsa.pub"
    fi
}
client() {
    local d="$W/client-$1"
    shift
    apk --root "$d/root" --arch x86_64 --keys-dir "$d/root/etc/apk/keys" \
        --repositories-file "$d/repositories" --cache-dir "$d/cache" \
        --no-network --no-logfile --no-progress --no-interactive "$@"
}
capture() {
    local name=$1 op=$2
    shift 2
    if client "$name" "$@" >"$W/logs/$name-$op" 2>&1; then RC=0; else RC=$?; fi
    cat "$W/logs/$name-$op"
    printf 'NATIVE: %s %s exit=%s\n' "$name" "$op" "$RC"
}
fixture() {
    local name=$1 ver=$2 trust=$3 text=$4 d="$W/source/$1-$2"
    mkdir -p "$d/tree/usr/share/$name" "$d/control"
    printf '%s\n' "$text" >"$d/tree/usr/share/$name/payload"
    tar --format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,atime:=0,ctime:=0 \
        --owner=0 --group=0 --numeric-owner -cf "$d/data.tar" -C "$d/tree" usr
    abuild-tar --hash --cut <"$d/data.tar" >"$d/hash.tar"
    {
        cat "$d/hash.tar"
        tail -c 1024 "$d/data.tar"
    } | gzip -n -9 >"$d/data.gz"
    cat >"$d/control/.PKGINFO" <<EOF
pkgname = $name
pkgver = $ver
pkgdesc = Disposable Alpine proof
url = https://example.invalid
builddate = $SOURCE_DATE_EPOCH
packager = Disposable Proof
size = $(stat -c %s "$d/tree/usr/share/$name/payload")
arch = x86_64
origin = $name
license = MIT
datahash = $(sha "$d/data.gz")
EOF
    [[ $(find "$d/control" -type f | wc -l) == 1 ]]
    reject grep -Eq '^(depend|install_if|triggers) = ' "$d/control/.PKGINFO"
    archive "$d/control" .PKGINFO >"$d/control.gz"
    if [[ $trust == signed ]]; then abuild-sign -t RSA256 -k "$W/alpine.rsa" -p "$W/keys/alpine.rsa.pub" "$d/control.gz"; fi
    cat "$d/control.gz" "$d/data.gz" >"$d/$name-$ver.apk"
    sha "$d/$name-$ver.apk" >"$d/source.sha256"
    chmod 400 "$d/$name-$ver.apk"
}
records() {
    local line p='' v='' a='' deps='' checksum='' count=0
    while IFS= read -r line || [[ -n $line ]]; do
        case "$line" in
            P:*) p=${line#P:} ;;
            V:*) v=${line#V:} ;;
            A:*) a=${line#A:} ;;
            D:*) deps=${line#D:} ;;
            C:*) checksum=${line#C:} ;;
            '')
                if [[ -n $p ]]; then
                    [[ -n $v && $a == x86_64 && $checksum == Q1* && -z $deps ]] || return 1
                    printf '%s|%s|%s|%s\n' "$p" "$v" "$a" "$deps"
                    count=$((count + 1))
                    p=
                    v=
                    a=
                    deps=
                    checksum=
                fi
                ;;
        esac
    done <"$1"
    [[ -z $p && $count -gt 0 ]]
}
index_records() {
    tar -xOf "$1" APKINDEX >"$W/records.raw" || return 1
    records "$W/records.raw" | sort
}
admit() {
    local file=$1 expected=$2 dest=$3 mode=${4:-signed} id digest prior
    [[ -r $file && -s $file ]] || return 1
    [[ $(head -c 3 "$file" | base64 -w0) != QURC ]] || return 1
    gzip -t "$file" 2>/dev/null || return 1
    digest=$(sha "$file")
    [[ $digest == "$expected" ]] || return 1
    case "$mode" in
        signed)
            client build verify "$file" >"$W/logs/admission" 2>&1 || return 1
            client build index --output "$W/admission.tar.gz" "$file" >>"$W/logs/admission" 2>&1 || return 1
            ;;
        unsigned)
            # Only the publisher parser permits unsigned input after the whole-file SHA256 check.
            apk --arch x86_64 --no-network --keys-dir "$W/empty" --repositories-file /dev/null \
                index --allow-untrusted --output "$W/admission.tar.gz" "$file" >"$W/logs/admission" 2>&1 || return 1
            ;;
        *) return 1 ;;
    esac
    id=$(index_records "$W/admission.tar.gz") || return 1
    [[ $id != *$'\n'* && -n $id ]] || return 1
    prior=$(grep -F "$id " "$W/ledger" || true)
    [[ -z $prior || $prior == "$id $digest" ]] || return 1
    mkdir -p "$dest"
    cp "$file" "$dest/$(basename "$file")" || return 1
    if [[ -z $prior ]]; then printf '%s %s\n' "$id" "$digest" >>"$W/ledger"; fi
}
sign_index() {
    abuild-sign -t RSA256 -k "${SIGNING_KEY:-$W/alpine.rsa}" -p "$W/keys/alpine.rsa.pub" "$1" || return 1
    printf '%s\n' "$(sha "$1")" >>"$W/signatures"
    client build verify "$1" || return 1
    gzip -dc "$1" | tar -tf - >"$W/members" || return 1
    grep -Fxq '.SIGN.RSA256.alpine.rsa.pub' "$W/members"
}
stage() {
    local gen=$1 old=$2 expected=$3
    shift 3
    local d="$W/pending/$gen" file
    [[ ! -e $d/inventory ]] || return 1
    if [[ $old != none ]]; then
        [[ -s $old && -r $old ]] || return 1
        client build verify "$old" >/dev/null 2>&1 || return 1
        index_records "$old" >/dev/null || return 1
    fi
    for file in "$@"; do [[ -s $file && -r $file ]] || return 1; done
    mkdir -p "$d"
    if [[ $old == none ]]; then
        client build index --output "$d/APKINDEX.tar.gz" "$@" || return 1
    else
        client build index --merge --index "$old" --output "$d/APKINDEX.tar.gz" "$@" || return 1
    fi
    [[ $(index_records "$d/APKINDEX.tar.gz") == "$expected" ]] || return 1
    sign_index "$d/APKINDEX.tar.gz" || return 1
    [[ $(index_records "$d/APKINDEX.tar.gz") == "$expected" ]] || return 1
    for file in "$@"; do cp "$file" "$d/" || return 1; done
    (cd "$d" && sha256sum ./*.apk APKINDEX.tar.gz >inventory) || return 1
    (cd "$d" && sha256sum inventory >inventory.sha256) || return 1
    chmod 400 "$d"/*
}
publish() {
    local target=$2 stop=${3:-none} d="$W/pending/$1" file base
    (cd "$d" && sha256sum -c inventory && sha256sum -c inventory.sha256) >/dev/null || return 1
    mkdir -p "$target/x86_64" || return 1
    for file in "$d"/*.apk; do
        base=${file##*/}
        head -c 8 "$file" >"$target/x86_64/$base.partial" || return 1
        [[ $stop != package ]] || return 75
        cp "$file" "$target/x86_64/$base.partial" || return 1
        mv "$target/x86_64/$base.partial" "$target/x86_64/$base" || return 1
    done
    head -c 8 "$d/APKINDEX.tar.gz" >"$target/x86_64/APKINDEX.tar.gz.partial" || return 1
    [[ $stop != index ]] || return 75
    cp "$d/APKINDEX.tar.gz" "$target/x86_64/APKINDEX.tar.gz.partial" || return 1
    mv "$target/x86_64/APKINDEX.tar.gz.partial" "$target/x86_64/APKINDEX.tar.gz" || return 1
    head -c 8 "$d/inventory" >"$target/inventory.partial" || return 1
    [[ $stop != inventory ]] || return 75
    cp "$d/inventory" "$target/inventory.partial" || return 1
    mv "$target/inventory.partial" "$target/inventory" || return 1
}
installed() {
    local name=$1 version=$2 payload=$3
    client "$name" info --installed "hd-main=$version"
    [[ $(cat "$W/client-$name/root/usr/share/hd-main/payload") == "$payload" ]]
    client "$name" list --installed >"$W/logs/$name-installed"
    grep -F "hd-main-$version" "$W/logs/$name-installed"
}
negative() {
    local name=$1 repo=$2 trust=$3 package=${4:-hd-main} version=${5:-1.0-r0}
    new_client "$name" "$repo" "$trust"
    capture "$name" verify verify "$repo/x86_64/APKINDEX.tar.gz"
    case "$name" in
        missing | wrong | index-tamper) [[ $RC != 0 ]] ;;
        *) [[ $RC == 0 ]] ;;
    esac
    capture "$name" update update
    capture "$name" policy policy "$package"
    capture "$name" add add --initdb --usermode --no-scripts --no-commit-hooks "$package=$version"
    [[ $RC != 0 ]] || proof_fail "$name installed an unauthenticated candidate"
    reject test -e "$W/client-$name/root/usr/share/$package/payload"
    reject client "$name" info --installed "$package"
    capture "$name" fetch fetch --recursive --output "$W/client-$name/downloads" "$package=$version"
    [[ -z $(find "$W/client-$name/downloads" -type f -print -quit) ]] || proof_fail "$name fetched unauthenticated bytes"
    proof_pass "$name rejects installation and yields no fetched package, independent of update/fetch exit status."
}

apk --version
getopt --version
convert_key
new_client build "$W/repo"
fixture hd-unsigned 1.0-r0 unsigned unsigned-primary-candidate
unsigned_apk="$W/source/hd-unsigned-1.0-r0/hd-unsigned-1.0-r0.apk"
capture build unsigned-index index --output "$W/unsigned-index.tar.gz" "$unsigned_apk"
[[ $RC != 0 ]]
new_client unsigned "$W/repo"
capture unsigned verify verify "$unsigned_apk"
[[ $RC != 0 ]]
capture unsigned add add --initdb --usermode --no-scripts --no-commit-hooks "$unsigned_apk"
[[ $RC != 0 ]]
reject test -e "$W/client-unsigned/root/usr/share/hd-unsigned/payload"
reject client unsigned info --installed hd-unsigned
reject admit "$unsigned_apk" bad "$W/reject-unsigned-checksum" unsigned
reject test -e "$W/admission.tar.gz"
admit "$unsigned_apk" "$(cat "$W/source/hd-unsigned-1.0-r0/source.sha256")" "$W/unsigned-repo/x86_64" unsigned
cat "$W/logs/admission"
[[ $(index_records "$W/admission.tar.gz") == 'hd-unsigned|1.0-r0|x86_64|' ]]
cp "$W/admission.tar.gz" "$W/unsigned-repo/x86_64/APKINDEX.tar.gz"
sign_index "$W/unsigned-repo/x86_64/APKINDEX.tar.gz"
same "$unsigned_apk" "$W/unsigned-repo/x86_64/hd-unsigned-1.0-r0.apk"
proof_pass 'Unsigned v2 publisher parsing succeeds with index --allow-untrusted only after whole-file SHA256 admission. Client trust checks remain enabled.'
new_client unsigned-repo "$W/unsigned-repo"
capture unsigned-repo verify verify "$W/unsigned-repo/x86_64/APKINDEX.tar.gz"
[[ $RC == 0 ]]
capture unsigned-repo add add --initdb --usermode --no-scripts --no-commit-hooks hd-unsigned=1.0-r0
if [[ $RC == 0 ]]; then
    client unsigned-repo info --installed hd-unsigned=1.0-r0
    [[ $(cat "$W/client-unsigned-repo/root/usr/share/hd-unsigned/payload") == unsigned-primary-candidate ]]
    client unsigned-repo list --installed >"$W/logs/unsigned-repo-installed"
    grep -F 'hd-unsigned-1.0-r0' "$W/logs/unsigned-repo-installed"
    capture unsigned-repo fetch fetch --recursive --output "$W/client-unsigned-repo/downloads" hd-unsigned=1.0-r0
    [[ $RC == 0 ]]
    same "$unsigned_apk" "$W/client-unsigned-repo/downloads/hd-unsigned-1.0-r0.apk"
    unsigned_policy='Unsigned v2 installation from the RSA256-trusted index passes on this client with unchanged source and fetched SHA256 bytes. Standalone verification and installation still reject.'
else
    reject test -e "$W/client-unsigned-repo/root/usr/share/hd-unsigned/payload"
    reject client unsigned-repo info --installed hd-unsigned
    unsigned_policy='Unsigned v2 publisher parsing passes, but strict repository installation rejects as recorded above. Reject/defer unsigned input support. Standalone verification and installation also reject.'
fi
[[ $(sha "$unsigned_apk") == "$(cat "$W/source/hd-unsigned-1.0-r0/source.sha256")" ]]
same "$unsigned_apk" "$W/unsigned-repo/x86_64/hd-unsigned-1.0-r0.apk"
proof_pass "BOUNDARY: $unsigned_policy Never sign admitted upstream APK bytes."
fixture hd-main 1.0-r0 signed version-one
fixture hd-keeper 1.0-r0 signed keeper
fixture hd-main 2.0-r0 signed version-two
fixture hd-added 1.0-r0 signed added
fixture hd-signed 1.0-r0 signed signed-comparison
for pair in hd-main-1.0-r0 hd-keeper-1.0-r0 hd-main-2.0-r0 hd-added-1.0-r0 hd-signed-1.0-r0; do
    admit "$W/source/$pair/$pair.apk" "$(cat "$W/source/$pair/source.sha256")" "$W/admitted/$pair"
done
ledger=$(sha "$W/ledger")
admit "$W/source/hd-main-1.0-r0/hd-main-1.0-r0.apk" "$(cat "$W/source/hd-main-1.0-r0/source.sha256")" "$W/replay-admission"
[[ $(sha "$W/ledger") == "$ledger" ]]
proof_pass 'Unchanged admission replay leaves the identity ledger unchanged.'
client build verify "$W/source/hd-main-1.0-r0/hd-main-1.0-r0.apk"
client build verify "$W/source/hd-signed-1.0-r0/hd-signed-1.0-r0.apk"
proof_pass 'Unsigned standalone verification rejects. Independently signed upstream comparison verifies before admission.'
expected1=$(printf '%s\n' 'hd-main|1.0-r0|x86_64|' 'hd-keeper|1.0-r0|x86_64|' | sort)
expected2=$(printf '%s\n' "$expected1" 'hd-main|2.0-r0|x86_64|' 'hd-added|1.0-r0|x86_64|' | sort)
stage gen1 none "$expected1" "$W/admitted/hd-main-1.0-r0/"*.apk "$W/admitted/hd-keeper-1.0-r0/"*.apk
publish gen1 "$W/repo"
new_client trusted "$W/repo"
capture trusted add add --initdb --usermode --no-scripts --no-commit-hooks hd-main=1.0-r0
[[ $RC == 0 ]]
installed trusted 1.0-r0 version-one
proof_pass 'Signed-upstream comparison: actual native usermode installation of version one succeeds.'
# The second publisher input directory contains no historical package.
mkdir -p "$W/input2"
cp "$W/admitted/hd-main-2.0-r0/"*.apk "$W/admitted/hd-added-1.0-r0/"*.apk "$W/input2/"
[[ $(find "$W/input2" -name '*.apk' | wc -l) == 2 ]]
reject test -e "$W/input2/hd-main-1.0-r0.apk"
reject test -e "$W/input2/hd-keeper-1.0-r0.apk"
stage gen2 "$W/pending/gen1/APKINDEX.tar.gz" "$expected2" "$W/input2/"*.apk
client build index --index "$W/pending/gen1/APKINDEX.tar.gz" --output "$W/plain.tar.gz" "$W/input2/"*.apk
[[ $(index_records "$W/plain.tar.gz") == "$(printf '%s\n' 'hd-main|2.0-r0|x86_64|' 'hd-added|1.0-r0|x86_64|' | sort)" ]]
proof_pass 'Merge retains all four exact records and empty dependency fields. Plain --index loses both old records.'
publish gen2 "$W/repo"
for pair in hd-main-1.0-r0 hd-keeper-1.0-r0 hd-main-2.0-r0 hd-added-1.0-r0; do
    [[ $(sha "$W/repo/x86_64/$pair.apk") == "$(cat "$W/source/$pair/source.sha256")" ]]
done
client trusted update
client trusted add --usermode --no-scripts --no-commit-hooks hd-main=2.0-r0 hd-added=1.0-r0
installed trusted 2.0-r0 version-two
[[ $(cat "$W/client-trusted/root/usr/share/hd-added/payload") == added ]]
client trusted fetch --recursive --output "$W/client-trusted/downloads" hd-main=2.0-r0 hd-keeper hd-added
for pair in hd-main-2.0-r0 hd-keeper-1.0-r0 hd-added-1.0-r0; do
    same "$W/source/$pair/$pair.apk" "$W/repo/x86_64/$pair.apk"
    same "$W/source/$pair/$pair.apk" "$W/client-trusted/downloads/$pair.apk"
    client trusted verify "$W/client-trusted/downloads/$pair.apk"
done
proof_pass 'Actual same-client upgrade to version two, added-asset installation and retained-keeper fetch preserve source SHA256 bytes.'

stage comparison none 'hd-signed|1.0-r0|x86_64|' "$W/admitted/hd-signed-1.0-r0/"*.apk
publish comparison "$W/comparison"
new_client comparison "$W/comparison"
client comparison add --initdb --usermode --no-scripts --no-commit-hooks hd-signed
[[ $(cat "$W/client-comparison/root/usr/share/hd-signed/payload") == signed-comparison ]]
proof_pass 'Separate signed-upstream comparison installs without any post-admission package signing.'
negative missing "$W/repo" no
negative wrong "$W/repo" wrong

mkdir -p "$W/tamper-index/x86_64" "$W/index-content"
cp "$W/repo/x86_64/"*.apk "$W/tamper-index/x86_64/"
# Keep the original signature bytes while changing the signed content.
split_signature "$W/pending/gen1/APKINDEX.tar.gz" "$W/signature.gz" "$W/content.gz"
tar -xf "$W/content.gz" -C "$W/index-content"
printf 'changed description\n' >"$W/index-content/DESCRIPTION"
archive "$W/index-content" DESCRIPTION APKINDEX >"$W/changed.gz"
cat "$W/signature.gz" "$W/changed.gz" >"$W/tamper-index/x86_64/APKINDEX.tar.gz"
reject client build verify "$W/tamper-index/x86_64/APKINDEX.tar.gz"
negative index-tamper "$W/tamper-index" yes
for kind in control payload; do
    repo="$W/tamper-$kind"
    mkdir -p "$repo/x86_64" "$W/change-$kind"
    cp "$W/pending/gen1/"*.apk "$W/pending/gen1/APKINDEX.tar.gz" "$repo/x86_64/"
    chmod 600 "$repo/x86_64/hd-main-1.0-r0.apk"
    d="$W/source/hd-main-1.0-r0"
    if [[ $kind == control ]]; then
        sed 's/Disposable Alpine proof/Alteredxxx Alpine proof/' "$d/control/.PKGINFO" >"$W/change-$kind/.PKGINFO"
        split_signature "$d/control.gz" "$W/change-$kind/signature.gz" "$W/change-$kind/original.gz"
        archive "$W/change-$kind" .PKGINFO >"$W/change-$kind/control.gz"
        cat "$W/change-$kind/signature.gz" "$W/change-$kind/control.gz" "$d/data.gz" >"$repo/x86_64/hd-main-1.0-r0.apk"
    else
        gzip -dc "$d/data.gz" | sed 's/version-one/version-bad/g' | gzip -n -9 >"$W/change-$kind/data.gz"
        cat "$d/control.gz" "$W/change-$kind/data.gz" >"$repo/x86_64/hd-main-1.0-r0.apk"
    fi
    reject client build verify "$repo/x86_64/hd-main-1.0-r0.apk"
    negative "$kind-tamper" "$repo" yes
done

completion=$(sha "$W/repo/inventory")
client build index --merge --index "$W/absent" --output "$W/native-missing-state.tar.gz" "$W/input2/"*.apk
[[ $(index_records "$W/native-missing-state.tar.gz") == "$(index_records "$W/plain.tar.gz")" ]]
client build index --merge --index "$W/pending/gen1/APKINDEX.tar.gz" --output "$W/native-missing-input.tar.gz" "$W/missing.apk"
[[ $(index_records "$W/native-missing-input.tar.gz") == "$expected1" ]]
proof_pass 'Native index silently accepts absent retained state and missing new input. Guards and exact records prevent false completion.'
reject stage absent "$W/absent" "$expected2" "$W/input2/"*.apk
printf 'corrupt\n' >"$W/corrupt"
reject stage corrupt "$W/corrupt" "$expected2" "$W/input2/"*.apk
reject stage missing-input "$W/pending/gen1/APKINDEX.tar.gz" "$expected2" "$W/missing.apk"
for gen in absent corrupt missing-input; do reject test -e "$W/pending/$gen/inventory"; done
# A failed native signer must not create completion state.
SIGNING_KEY="$W/missing-key" reject stage failed-sign "$W/pending/gen1/APKINDEX.tar.gz" "$expected2" "$W/input2/"*.apk
reject test -e "$W/pending/failed-sign/inventory"
[[ $(sha "$W/repo/inventory") == "$completion" ]]
reject admit "$W/source/hd-main-1.0-r0/hd-main-1.0-r0.apk" bad "$W/reject-checksum"
cp "$W/source/hd-main-1.0-r0/hd-main-1.0-r0.apk" "$W/replacement.apk"
chmod 600 "$W/replacement.apk"
# The gzip mtime is outside the control identity, and changing it keeps the size.
printf '\001' | dd of="$W/replacement.apk" bs=1 seek=4 conv=notrunc status=none
touch -t 200001010000 "$W/replacement.apk"
[[ $(stat -c %s "$W/replacement.apk") == "$(stat -c %s "$W/source/hd-main-1.0-r0/hd-main-1.0-r0.apk")" ]]
client build index --output "$W/replacement-index.tar.gz" "$W/replacement.apk"
[[ $(index_records "$W/replacement-index.tar.gz") == 'hd-main|1.0-r0|x86_64|' ]]
reject admit "$W/replacement.apk" "$(sha "$W/replacement.apk")" "$W/reject-identity"
client build mkpkg --info name:hd-v3 --info version:1.0-r0 --info arch:x86_64 --files "$W/empty" --output "$W/v3.apk"
[[ $(head -c 3 "$W/v3.apk" | base64 -w0) == QURC ]]
reject admit "$W/v3.apk" "$(sha "$W/v3.apk")" "$W/reject-v3"
reject admit "$W/corrupt" "$(sha "$W/corrupt")" "$W/reject-malformed"
proof_pass 'Admission rejects checksum mismatch, equal-size backdated identity replacement, v3 and malformed input. Retained-state and input guards reject before inventory.'

signatures=$(sha "$W/signatures")
for interruption in package index inventory; do
    target="$W/recovery-$interruption"
    publish gen1 "$target"
    old=$(sha "$target/inventory")
    reject publish gen2 "$target" "$interruption"
    [[ $(sha "$target/inventory") == "$old" ]]
    [[ -f $W/pending/gen2/inventory && -f $target/x86_64/hd-keeper-1.0-r0.apk ]]
    publish gen2 "$target"
    same "$W/pending/gen2/inventory" "$target/inventory"
    (cd "$target/x86_64" && sha256sum -c ../inventory)
    same "$W/source/hd-keeper-1.0-r0/hd-keeper-1.0-r0.apk" "$target/x86_64/hd-keeper-1.0-r0.apk"
    same "$W/source/hd-main-1.0-r0/hd-main-1.0-r0.apk" "$target/x86_64/hd-main-1.0-r0.apk"
    publish gen2 "$target"
    same "$W/pending/gen2/inventory" "$target/inventory"
    [[ $(sha "$W/signatures") == "$signatures" ]]
    proof_pass "$interruption interruption: no premature completion, exact frozen replay, retained old objects, no retry signing."
done
proof_pass "DECISION: signed-upstream v2 comparison passes on this client. $unsigned_policy v2 Q1 control identity remains SHA1, datahash is compressed-payload SHA256, admission uses whole-file SHA256. Defer production policy for SHA1 identity, remote publication and other clients, including older Alpine clients."
printf 'DIGEST: whole APK SHA256 %s\n' "$(cat "$W/source/hd-main-1.0-r0/source.sha256")"
grep '^datahash = ' "$W/source/hd-main-1.0-r0/control/.PKGINFO"
client build index --output "$W/digest-index.tar.gz" "$W/source/hd-main-1.0-r0/hd-main-1.0-r0.apk"
tar -xOf "$W/digest-index.tar.gz" APKINDEX | grep '^C:'
proof_finish
