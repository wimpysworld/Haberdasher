#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/proofs/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
proof_init apt
helper=$(cd "$(dirname "${BASH_SOURCE[0]}")/apt" && pwd)
server_pid=
cleanup() {
    if [[ -n $server_pid ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if [[ -d $PROOF_WORK/wrong ]]; then
        gpgconf --homedir "$PROOF_WORK/wrong" --kill all >/dev/null 2>&1 || true
    fi
    chmod -R u+rwX "$PROOF_WORK" 2>/dev/null || true
    proof_finish
}
trap cleanup EXIT
[[ $(id -u) != 0 ]] || proof_fail 'Run this proof as an ordinary user.'
w=$PROOF_WORK
mkdir -p "$w/input" "$w/state/records" "$w/http/live" "$w/build" "$w/signer-bin"
: >"$w/state/assets"
: >"$w/state/history"
: >"$w/extractions"
: >"$w/signatures"
cat >"$w/signer-bin/gpg" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "\$*" >>"\$PROOF_WORK/signatures"
[[ ! -e \$PROOF_WORK/signer-frozen ]] || exit 98
exec "$(command -v gpg)" "\$@"
EOF
chmod +x "$w/signer-bin/gpg"
export PATH="$w/signer-bin:$PATH"
proof_key

start_server() {
    # The pipe waits for server readiness without a timer or network probe.
    coproc APT_SERVER { exec python3 "$helper/server.py" "$w/http" "$w/port" "$w/requests"; }
    server_pid=$APT_SERVER_PID
    read -r ready <&"${APT_SERVER[0]}"
    [[ $ready == ready ]] || proof_fail 'Loopback server did not start.'
    port=$(cat "$w/port")
}

sha() { sha256sum "$1" | cut -d ' ' -f 1; }
same_bytes() { [[ $(sha "$1") == "$(sha "$2")" ]] || proof_fail "Different bytes: $1 and $2"; }
reject() {
    local message=$1
    shift
    if "$@" >"$w/rejection.log" 2>&1; then
        proof_fail "$message was accepted"
    fi
    proof_pass "$message rejected"
    grep '^E:' "$w/rejection.log" || true
}
fixture() {
    local version=$1 payload=$2 output=$3
    local root="$w/build/$version-$payload"
    mkdir -p "$root/DEBIAN" "$root/usr/share/haberdasher-proof"
    printf 'Package: haberdasher-proof\nVersion: %s\nArchitecture: amd64\nMaintainer: Local proof <proof@invalid>\nDescription: Disposable local APT fixture\n' "$version" >"$root/DEBIAN/control"
    printf '%s\n' "$payload" >"$root/usr/share/haberdasher-proof/value"
    chmod 755 "$root" "$root/DEBIAN" "$root/usr" "$root/usr/share" "$root/usr/share/haberdasher-proof"
    chmod 644 "$root/DEBIAN/control" "$root/usr/share/haberdasher-proof/value"
    dpkg-deb --root-owner-group --build "$root" "$output" >/dev/null
}

import_asset() {
    local source=$1 expected=$2 digest package version arch size filename p v a
    [[ -n $expected && -f $source ]] || return 1
    digest=$(sha "$source")
    [[ $digest == "$expected" ]] || return 1
    if grep -q " $digest " "$w/state/assets"; then
        return 0
    fi
    printf '%s\n' "$digest" >>"$w/extractions"
    package=$(dpkg-deb -f "$source" Package) || return 1
    version=$(dpkg-deb -f "$source" Version) || return 1
    arch=$(dpkg-deb -f "$source" Architecture) || return 1
    while read -r p v a _ _ _; do
        if [[ $p == "$package" && $a == "$arch" ]] && dpkg --compare-versions "$v" eq "$version"; then
            return 1
        fi
    done <"$w/state/assets"
    size=$(stat -c %s "$source")
    filename="pool/${digest}.deb"
    mkdir -p "$w/publisher/pool"
    cp "$source" "$w/publisher/$filename"
    (cd "$w/publisher" && apt-ftparchive packages "$filename") >"$w/state/records/$digest"
    grep -qx "SHA256: $digest" "$w/state/records/$digest"
    grep -qx "Filename: $filename" "$w/state/records/$digest"
    printf '%s %s %s %s %s %s\n' "$package" "$version" "$arch" "$digest" "$size" "$filename" >>"$w/state/assets"
}

freeze() {
    local expiry=$2 frozen="$w/frozen-$1" index digest file
    mkdir -p "$frozen/dists/proof/main/binary-amd64" "$frozen/pool"
    index="$frozen/dists/proof/main/binary-amd64"
    while read -r _ _ _ digest _ _; do
        cat "$w/state/records/$digest"
    done <"$w/state/assets" >"$index/Packages"
    gzip -n -c "$index/Packages" >"$index/Packages.gz"
    for file in "$index/Packages" "$index/Packages.gz"; do
        digest=$(sha "$file")
        mkdir -p "$index/by-hash/SHA256"
        cp "$file" "$index/by-hash/SHA256/$digest"
    done
    (cd "$frozen/dists/proof" && apt-ftparchive \
        -o APT::FTPArchive::Release::MD5=false \
        -o APT::FTPArchive::Release::SHA1=false \
        -o APT::FTPArchive::Release::SHA512=false \
        -o APT::FTPArchive::Release::Suite=proof \
        -o APT::FTPArchive::Release::Codename=proof \
        -o APT::FTPArchive::Release::Architectures=amd64 \
        -o APT::FTPArchive::Release::Components=main \
        -o APT::FTPArchive::Release::Acquire-By-Hash=yes release .) >"$frozen/dists/proof/Release"
    printf 'Valid-Until: %s\n' "$expiry" >>"$frozen/dists/proof/Release"
    for file in InRelease Release.gpg; do
        if [[ $file == InRelease ]]; then
            gpg --batch --yes --digest-algo SHA256 --local-user "$PROOF_FPR" --clearsign \
                --output "$frozen/dists/proof/$file" "$frozen/dists/proof/Release"
        else
            gpg --batch --yes --digest-algo SHA256 --local-user "$PROOF_FPR" --armor --detach-sign \
                --output "$frozen/dists/proof/$file" "$frozen/dists/proof/Release"
        fi
    done
    cp "$w/publisher/pool/"*.deb "$frozen/pool/"
    (
        cd "$frozen"
        find pool -type f | sort
        find dists -path '*/by-hash/*' -type f | sort
        printf '%s\n' dists/proof/main/binary-amd64/Packages dists/proof/main/binary-amd64/Packages.gz \
            dists/proof/Release dists/proof/Release.gpg dists/proof/InRelease
    ) >"$frozen/order"
    cp "$w/state/assets" "$frozen/assets"
    (cd "$frozen" && while read -r file; do sha256sum "$file"; done <order) >"$frozen/objects"
    cat "$frozen/objects" "$w/state/history" | sort -s -k 2,2 -u >"$frozen/inventory"
    (cd "$frozen" && sha256sum order assets objects inventory) >"$frozen/control.sha256"
}

publish() {
    local frozen=$1 target=$2 interrupt=${3:-none} file phase
    (cd "$frozen" && sha256sum -c control.sha256 && sha256sum -c objects) >/dev/null || return 1
    gpgv --keyring "$w/public.gpg" "$frozen/dists/proof/InRelease" >/dev/null 2>&1 || return 1
    gpgv --keyring "$w/public.gpg" "$frozen/dists/proof/Release.gpg" "$frozen/dists/proof/Release" >/dev/null 2>&1 || return 1
    mkdir -p "$target"
    while read -r file; do
        case "$file" in
            pool/*) phase=package ;;
            */by-hash/*) phase=index ;;
            */InRelease) phase=entry ;;
            *) phase=other ;;
        esac
        mkdir -p "$target/$(dirname "$file")"
        if [[ $phase == "$interrupt" ]]; then
            head -c 17 "$frozen/$file" >"$target/$file"
            return 75
        fi
        cp "$frozen/$file" "$target/$file"
    done <"$frozen/order"
    (cd "$target" && sha256sum -c "$frozen/inventory") >/dev/null || return 1
    if [[ $interrupt == inventory ]]; then
        head -c 17 "$frozen/inventory" >"$target/inventory.pending"
        return 75
    fi
    cp "$frozen/inventory" "$target/inventory.pending"
    mv "$target/inventory.pending" "$target/inventory"
}

client() {
    local name=$1 view=$2 trust=${3:-$w/public.gpg}
    c="$w/client-$name"
    mkdir -p "$c/etc/empty" "$c/lists/partial" "$c/cache/archives/partial" "$c/log" "$c/root/var/lib/dpkg" "$c/root/var/log"
    : >"$c/root/var/lib/dpkg/status"
    printf 'deb [arch=amd64 signed-by=%s] http://127.0.0.1:%s/%s proof main\n' "$trust" "$port" "$view" >"$c/etc/sources.list"
    cat >"$c/apt.conf" <<EOF
Dir "$c";
Dir::Etc "$c/etc";
Dir::Etc::main "-";
Dir::Etc::parts "$c/etc/empty";
Dir::Etc::sourcelist "$c/etc/sources.list";
Dir::Etc::sourceparts "$c/etc/empty";
Dir::Etc::trusted "$c/etc/absent.gpg";
Dir::Etc::trustedparts "$c/etc/empty";
Dir::State "$c";
Dir::State::status "$c/root/var/lib/dpkg/status";
Dir::State::lists "$c/lists";
Dir::State::extended_states "$c/extended_states";
Dir::Cache "$c/cache";
Dir::Cache::archives "$c/cache/archives";
Dir::Log "$c/log";
Dir::Bin::dpkg "$(command -v dpkg)";
APT::Architecture "amd64";
APT::Architectures { "amd64"; };
APT::Sandbox::User "$(id -un)";
APT::Update::Error-Mode "any";
Acquire::Languages "none";
Acquire::Retries "0";
Acquire::http::Proxy "DIRECT";
Acquire::Check-Date "true";
Acquire::Check-Valid-Until "true";
DPkg::Options { "--root=$c/root"; "--admindir=$c/root/var/lib/dpkg"; "--log=$c/root/var/log/dpkg.log"; };
DPkg::Use-Pty "false";
EOF
}
apt_run() {
    [[ $c == "$w/"client-* && -f $c/apt.conf ]] || proof_fail 'Unsafe APT client path.'
    [[ $(APT_CONFIG="$c/apt.conf" apt-config shell status Dir::State::status) == "status='$c/root/var/lib/dpkg/status'" ]] || proof_fail 'Unsafe dpkg status path.'
    APT_CONFIG="$c/apt.conf" fakeroot apt-get "$@" >"$c/last.log" 2>&1 || {
        cat "$c/last.log" >&2
        return 1
    }
}
installed() {
    [[ $(dpkg-query --admindir="$c/root/var/lib/dpkg" -W -f='${Status} ${Version}' haberdasher-proof) == "install ok installed $1" ]] || proof_fail "Installed version is not $1"
    [[ $(cat "$c/root/usr/share/haberdasher-proof/value") == "$2" ]] || proof_fail 'Installed payload mismatch.'
}

not_installed() {
    local status
    status=$(dpkg-query --admindir="$c/root/var/lib/dpkg" -W -f='${Status}' haberdasher-proof 2>/dev/null || true)
    [[ -z $status || $status == 'unknown ok not-installed' ]] || proof_fail "Rejected client has dpkg state: $status"
    [[ ! -e $c/root/usr/share/haberdasher-proof/value ]] || proof_fail 'Rejected client has an installed payload.'
    proof_pass "${c##*/}: no installed dpkg state or payload"
}
reject_install() {
    reject 'Installation after rejected metadata' apt_run install -y haberdasher-proof
    not_installed
}

if [[ ${1:-} == __apt_cleanup_probe ]]; then
    start_server
    mkdir "$w/wrong"
    gpgconf --homedir "$w/wrong" --launch gpg-agent
    agent_pid=$(gpg-connect-agent 'GETINFO pid' /bye | sed -n 's/^D //p')
    wrong_pid=$(gpg-connect-agent --homedir "$w/wrong" 'GETINFO pid' /bye | sed -n 's/^D //p')
    kill -0 "$server_pid" "$agent_pid" "$wrong_pid"
    printf '%s %s %s %s\n' "$w" "$server_pid" "$agent_pid" "$wrong_pid"
    case "$2" in
        failure) false ;;
        INT | TERM) kill -s "$2" "$$" ;;
        *) proof_fail 'Unknown private cleanup probe.' ;;
    esac
    proof_fail 'Cleanup probe did not exit.'
fi

python3 - "$helper/../apt.sh" <<'PY'
import os
import pathlib
import select
import signal
import subprocess
import sys

for mode, expected in (("failure", 1), ("INT", 130), ("TERM", 143)):
    result = subprocess.run(
        ["bash", sys.argv[1], "__apt_cleanup_probe", mode],
        stdout=subprocess.PIPE, text=True, timeout=90,
    )
    fields = result.stdout.split()
    if len(fields) != 4:
        raise SystemExit(f"FAIL: {mode} cleanup probe did not record owned processes: {result.stdout}")
    work, *pids = fields
    survivors = []
    for pid in map(int, pids):
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            continue
        try:
            if not select.select([fd], [], [], 5)[0]:
                survivors.append(pid)
                signal.pidfd_send_signal(fd, signal.SIGKILL)
        finally:
            os.close(fd)
    if result.returncode != expected or survivors or pathlib.Path(work).exists():
        raise SystemExit(
            f"FAIL: {mode} cleanup: exit={result.returncode}, surviving PIDs={survivors}, "
            f"workspace_exists={pathlib.Path(work).exists()}, workspace={work}"
        )
    print(f"PASS: native {mode} cleanup exit={expected}, workspace removed={work}, "
          f"server/agents stopped={','.join(pids)}", flush=True)
PY

fixture 1.0 first "$w/input/v1.deb"
fixture 2.0 second "$w/input/v2.deb"
fixture 1.0 changed "$w/input/conflict.deb"
fixture 1.0-0 equivalent "$w/input/equivalent.deb"
v1=$(sha "$w/input/v1.deb")
v2=$(sha "$w/input/v2.deb")
reject 'Missing source checksum' import_asset "$w/input/v1.deb" ''
reject 'Wrong source checksum' import_asset "$w/input/v1.deb" "$v2"
[[ ! -s $w/state/assets ]] || proof_fail 'Rejected source changed accepted state.'
import_asset "$w/input/v1.deb" "$v1"
cp "$w/state/assets" "$w/accepted-assets"
reject 'Changed bytes at the same identity' import_asset "$w/input/conflict.deb" "$(sha "$w/input/conflict.deb")"
reject 'Native-equivalent 1.0-0 identity' import_asset "$w/input/equivalent.deb" "$(sha "$w/input/equivalent.deb")"
same_bytes "$w/accepted-assets" "$w/state/assets"
expiry=$(date -u -d '+1 day' -R)
freeze 1 "$expiry"
publish "$w/frozen-1" "$w/http/live"
cp "$w/frozen-1/inventory" "$w/state/history"
cp -a "$w/http/live" "$w/base"
cp "$w/extractions" "$w/extractions-before"
cp "$w/signatures" "$w/signatures-before"
import_asset "$w/input/v1.deb" "$v1"
same_bytes "$w/extractions-before" "$w/extractions"
same_bytes "$w/signatures-before" "$w/signatures"
same_bytes "$w/accepted-assets" "$w/state/assets"
proof_pass 'Repeated identical input needs no extraction, signing, or duplicate record'

start_server
client normal live
apt_run update
apt_run install -y haberdasher-proof=1.0
installed 1.0 first
proof_pass 'Native apt-get installed 1.0 into the disposable dpkg root'

cp "$w/state/records/$v1" "$w/old-record"
rm "$w/input/v1.deb" "$w/publisher/pool/$v1.deb"
chmod 000 "$w/http/live/pool" "$w/base/pool" "$w/frozen-1/pool" "$c/cache/archives"
if cat "$w/http/live/pool/$v1.deb" >/dev/null 2>&1; then
    proof_fail 'Publisher can still open the old public DEB.'
fi
import_asset "$w/input/v2.deb" "$v2"
freeze 2 "$expiry"
same_bytes "$w/old-record" "$w/state/records/$v1"
cat "$w/state/records/$v1" "$w/state/records/$v2" >"$w/expected-packages"
same_bytes "$w/expected-packages" "$w/frozen-2/dists/proof/main/binary-amd64/Packages"
[[ $(find "$w/publisher/pool" -type f | wc -l) == 1 ]] || proof_fail 'Historical publisher input remains.'
chmod 700 "$w/http/live/pool" "$w/base/pool" "$w/frozen-1/pool" "$c/cache/archives"
proof_pass 'Generation two reused the exact full record with historical DEBs inaccessible'
publish "$w/frozen-2" "$w/http/live"
cp "$w/frozen-2/inventory" "$w/state/history"
apt_run update
apt_run upgrade -y
installed 2.0 second
proof_pass 'Native apt-get upgraded to 2.0 and changed the installed payload'

mkdir -p "$w/http/delayed/dists/proof/main"
ln -s "$w/http/live/dists/proof/main/binary-amd64" "$w/http/delayed/dists/proof/main/binary-amd64"
ln -s "$w/http/live/pool" "$w/http/delayed/pool"
cp "$w/frozen-1/dists/proof/InRelease" "$w/http/delayed/dists/proof/InRelease"
client delayed delayed
apt_run update
old_index=$(sha "$w/frozen-1/dists/proof/main/binary-amd64/Packages.gz")
grep -Fxq "/delayed/dists/proof/main/binary-amd64/by-hash/SHA256/$old_index" "$w/requests"
apt_run install -y haberdasher-proof
installed 1.0 first
proof_pass 'Delayed client fetched the old SHA256 by-hash index after generation two and installed 1.0'

cp -a "$w/http/live" "$w/http/detached"
rm "$w/http/detached/dists/proof/InRelease"
client detached detached
apt_run update
grep -Fxq '/detached/dists/proof/Release.gpg' "$w/requests"
proof_pass 'Native APT verified the detached Release.gpg fallback'

cp "$w/http/live/inventory" "$w/accepted-inventory"
client missing live "$w/missing.gpg"
reject 'Missing scoped trust' apt_run update
grep -q 'is not signed' "$w/rejection.log"
reject_install
mkdir "$w/wrong"
gpg --homedir "$w/wrong" --batch --cert-digest-algo SHA256 --pinentry-mode loopback --passphrase '' --quick-generate-key 'Wrong disposable proof <wrong@invalid>' rsa4096 sign,cert 1d
gpg --homedir "$w/wrong" --export >"$w/wrong.gpg"
gpgconf --homedir "$w/wrong" --kill all
client wrong live "$w/wrong.gpg"
reject 'Wrong scoped trust' apt_run update
grep -q 'is not signed' "$w/rejection.log"
reject_install
cp -a "$w/http/live" "$w/http/tamper-signature"
sed -i 's/Suite: proof/Suite: wrong/' "$w/http/tamper-signature/dists/proof/InRelease"
client signature tamper-signature
reject 'Tampered InRelease signature' apt_run update
grep -q 'is not signed' "$w/rejection.log"
reject_install
cp -a "$w/http/live" "$w/http/tamper-index"
new_index=$(sha "$w/frozen-2/dists/proof/main/binary-amd64/Packages.gz")
printf X | dd of="$w/http/tamper-index/dists/proof/main/binary-amd64/by-hash/SHA256/$new_index" conv=notrunc status=none
client index tamper-index
reject 'Tampered by-hash index' apt_run update
grep -q 'Hash Sum mismatch' "$w/rejection.log"
reject_install
cp -a "$w/http/live" "$w/http/tamper-package"
printf X | dd of="$w/http/tamper-package/pool/$v2.deb" conv=notrunc status=none
client package tamper-package
apt_run update
reject 'Tampered package bytes' apt_run install -y haberdasher-proof
grep -q 'Hash Sum mismatch' "$w/rejection.log"
not_installed
freeze expired "$(date -u -d '-1 day' -R)"
cp -a "$w/http/live" "$w/http/expired"
publish "$w/frozen-expired" "$w/http/expired"
client expired expired
reject 'Expired signed Release' apt_run update
grep -q 'is expired' "$w/rejection.log"
reject_install
same_bytes "$w/accepted-inventory" "$w/http/live/inventory"
(cd "$w/http/live" && sha256sum -c inventory) >/dev/null
proof_pass 'Client rejection cases left the accepted publication unchanged'

cp -a "$w/frozen-2" "$w/broken-frozen"
printf 'corrupt' >>"$w/broken-frozen/dists/proof/InRelease"
reject 'Corrupt frozen publication' publish "$w/broken-frozen" "$w/http/live"
same_bytes "$w/accepted-inventory" "$w/http/live/inventory"
cp "$w/frozen-2/dists/proof/InRelease" "$w/broken-frozen/dists/proof/InRelease"
sed -i 's/Suite: proof/Suite: wrong/' "$w/broken-frozen/dists/proof/InRelease"
(cd "$w/broken-frozen" && while read -r file; do sha256sum "$file"; done <order) >"$w/broken-frozen/objects"
(cd "$w/broken-frozen" && sha256sum order assets objects inventory) >"$w/broken-frozen/control.sha256"
reject 'Invalid signature despite matching frozen checksums' publish "$w/broken-frozen" "$w/http/live"
(cd "$w/http/live" && sha256sum -c inventory) >/dev/null
same_bytes "$w/accepted-inventory" "$w/http/live/inventory"
chmod 000 "$w/input" "$w/publisher" "$w/build" "$w/state"
prepared_signatures=$(grep -Ec -- '--clearsign|--detach-sign' "$w/signatures")
[[ $prepared_signatures == 6 ]] || proof_fail 'Expected six native signing invocations during preparation.'
: >"$w/signer-frozen"
cp "$w/signatures" "$w/signatures-before"
(cd "$w/frozen-2" && sha256sum control.sha256) >"$w/frozen-before"
proof_pass "PREPARE recorded $prepared_signatures native signing invocations before FREEZE"
for phase in index entry inventory; do
    target="$w/http/retry-$phase"
    cp -a "$w/base" "$target"
    if publish "$w/frozen-2" "$target" "$phase"; then
        proof_fail "$phase publication did not stop"
    else
        [[ $? == 75 ]] || proof_fail "$phase publication failed before the injected interruption"
    fi
    same_bytes "$w/base/inventory" "$target/inventory"
    publish "$w/frozen-2" "$target"
    same_bytes "$w/signatures-before" "$w/signatures"
    (cd "$w/frozen-2" && sha256sum -c "$w/frozen-before" && sha256sum -c control.sha256 && sha256sum -c objects) >/dev/null
    proof_pass "$phase interruption and retry invoked no signer after FREEZE ($prepared_signatures signing calls unchanged)"
    (cd "$target" && sha256sum -c "$w/frozen-2/inventory") >/dev/null
    same_bytes "$w/frozen-2/inventory" "$target/inventory"
    [[ $(sha "$target/pool/$v1.deb") == "$v1" ]] || proof_fail 'Recovery lost the historical package.'
    same_bytes "$w/base/dists/proof/main/binary-amd64/by-hash/SHA256/$old_index" "$target/dists/proof/main/binary-amd64/by-hash/SHA256/$old_index"
    client "retry-$phase" "retry-$phase"
    apt_run update
    apt_run install -y haberdasher-proof
    installed 2.0 second
    proof_pass "$phase recovery reused exact frozen bytes, retained history, and passed native installation"
done
same_bytes "$w/signatures-before" "$w/signatures"
export PATH=${PATH#"$w/signer-bin:"}
printf 'APT: %s\nDPKG: %s\nGPG: %s\n' "$(APT_CONFIG="$c/apt.conf" apt-get --version | head -n 1)" "$(dpkg-query --version | head -n 1)" "$(gpg --version | head -n 1)"
proof_pass 'APT local proof complete'
