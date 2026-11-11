"""Trusted script-free RPM fixtures and guarded DNF5 clients."""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from haberdasher import site
from haberdasher.core import PreparedFormat, SourceAsset, VerifiedAsset, sha256_file
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession
from tests.support.http import HttpFixture
from tests.support.native import NativeClient

NOW = datetime(2026, 11, 8, tzinfo=UTC)


def checked(runtime: Runtime, *argv: str) -> bytes:
    result = runtime.run(argv)
    if result.returncode:
        raise AssertionError(
            f"{argv[0]} failed:\n{result.stdout.decode()}\n{result.stderr.decode()}"
        )
    return result.stdout


def build(
    runtime: Runtime,
    name: str,
    version: str,
    payload: str,
    *,
    epoch: int | None = None,
    number: int = 1,
) -> VerifiedAsset:
    if name not in {"hd-proof-app", "hd-proof-data"}:
        raise ValueError("Only trusted RPM fixture names are allowed")
    if version not in {"1", "2", "1.01", "1.1"} or payload not in {
        "application-v1",
        "application-v2",
        "dependency-v1",
        "conflicting-payload",
    }:
        raise ValueError("Only trusted RPM fixture content is allowed")
    root = runtime.root / f"build-{number}"
    root.mkdir()
    spec = root / "fixture.spec"
    requires = (
        "Requires: hd-proof-data = 1-1\nRequires: /opt/hd-proof/hd-proof-data"
        if name == "hd-proof-app"
        else ""
    )
    spec.write_text(f"""Name: {name}
Version: {version}
Release: 1
{f"Epoch: {epoch}" if epoch is not None else ""}
Summary: Disposable RPM adapter fixture
License: MIT
BuildArch: noarch
AutoReqProv: no
{requires}
%description
Trusted fixture without package scripts.
%install
mkdir -p %{{buildroot}}/opt/hd-proof
printf '%s\\n' '{payload}' > %{{buildroot}}/opt/hd-proof/{name}
%files
/opt/hd-proof/{name}
%changelog
* Wed Jun 17 2026 Proof <proof@invalid> - {version}-1
- Fixture payload {payload}.
""")
    checked(
        runtime,
        "rpmbuild",
        "--define",
        f"_topdir {root}",
        "--define",
        f"_tmppath {runtime.root / 'tmp'}",
        "--define",
        "_buildhost proof.invalid",
        "--define",
        "__os_install_post %{nil}",
        "--define",
        "_build_id_links none",
        "--define",
        "_binary_filedigest_algorithm 8",
        "-bb",
        str(spec),
    )
    path = root / f"RPMS/noarch/{name}-{version}-1.noarch.rpm"
    assert checked(runtime, "rpm", "-qp", "--scripts", str(path)) == b""
    digest, size = sha256_file(path)
    source = SourceAsset(
        "wimpysworld/fixture",
        number,
        number,
        path.name,
        size,
        NOW.isoformat(),
        f"https://example.invalid/{path.name}",
    )
    return VerifiedAsset(source, path, digest, size, number + 100, "a" * 64)


def upstream_sign(runtime: Runtime, asset: VerifiedAsset, signer: SigningSession) -> VerifiedAsset:
    """Sign a fixture RPM with a separate upstream key, as a release asset can be."""
    gpg = shutil.which("gpg", path=runtime.environment["PATH"])
    assert gpg is not None
    checked(
        runtime,
        "env",
        f"GNUPGHOME={signer.gnupghome}",
        "rpmsign",
        "--define",
        f"_gpg_name {signer.fingerprint}!",
        "--define",
        f"_gpg_path {signer.gnupghome}",
        "--define",
        f"__gpg {gpg}",
        "--define",
        "_gpg_digest_algo sha256",
        "--addsign",
        str(asset.local_path),
    )
    digest, size = sha256_file(asset.local_path)
    return replace(asset, sha256=digest, size=size, source=replace(asset.source, size=size))


def publish(prepared: PreparedFormat, root: Path, server: HttpFixture, generation: int) -> None:
    paths: list[Path] = []
    for output in prepared.outputs:
        target = root / output.ref.key
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output.local_path, target)
        assert sha256_file(target) == (output.ref.sha256, output.ref.size)
        paths.append(target)
    server.set_generation_mtime(paths, generation)


class DnfClient:
    def __init__(self, runtime: Runtime, name: str, url: str, keyring: Path) -> None:
        if os.getuid() == 0:
            raise ValueError("DNF fixture requires a normal user")
        self.client = NativeClient(runtime, name)
        self.runtime = runtime
        self.base = self.client.base
        self.root = self.client.root
        for part in ("home", "gnupg", "repos", "vars"):
            self.client.path(part).mkdir(mode=0o700)
        for part in ("dev", "etc", "run/user/0"):
            (runtime.root / part).mkdir(mode=0o700, parents=True, exist_ok=True)
        (runtime.root / "dev/null").touch()
        self.client.path("home/.rpmmacros").write_text("%_dbpath /var/lib/rpm\n%_tmppath /tmp\n")
        local = self.local(self.base)
        self.config = self.client.path("config/dnf.conf")
        self.config.write_text(f"""[main]
reposdir={local}/repos
varsdir={local}/vars
cachedir={local}/cache
system_cachedir={local}/cache
logdir={local}/log
persistdir={local}/state
gpgcheck=1
repo_gpgcheck=1
install_weak_deps=0
optional_metadata_types=filelists
keepcache=1
plugins=0
{site.rpm_repo(url, "file:///public.asc")}metadata_expire=0
""")
        # Librepo 1.20 needs preseeded scoped public trust for its missing-key retry.
        ring = self.client.path(
            f"cache/haberdasher-{hashlib.sha256(url.encode()).hexdigest()[:16]}/pubring"
        )
        ring.mkdir(parents=True, mode=0o700)
        shutil.copyfile(keyring, ring / "pubring.gpg")
        (ring / "gpg.conf").write_text("no-autostart\n")
        public = checked(
            runtime,
            "gpg",
            "--batch",
            "--no-default-keyring",
            "--keyring",
            str(keyring),
            "--armor",
            "--export",
        )
        (runtime.root / "public.asc").write_bytes(public)

    def local(self, path: Path) -> str:
        return "/" + str(path.relative_to(self.runtime.root))

    def run(self, *args: str, success: bool = True) -> bytes:
        self.client.guard_root(self.root)
        binary = shutil.which("dnf5", path=self.runtime.environment["PATH"])
        env = shutil.which("env", path=self.runtime.environment["PATH"])
        if binary is None or env is None:
            raise AssertionError("Pinned DNF5 tools are missing")
        home = self.local(self.client.path("home"))
        local = self.local(self.base)
        argv = [
            "env",
            "FAKECHROOT_EXCLUDE_PATH=/nix/store",
            f"HD_PRIVATE_INSTALL_ROOT={self.root}",
            "fakechroot",
            "-e",
            "none",
            "fakeroot",
            "chroot",
            str(self.runtime.root),
            env,
            f"HOME={home}",
            f"GNUPGHOME={local}/gnupg",
            "TMPDIR=/tmp",
            f"XDG_CONFIG_HOME={home}/.config",
            f"XDG_DATA_HOME={home}/.local/share",
            f"XDG_CACHE_HOME={home}/.cache",
            f"XDG_STATE_HOME={home}/.local/state",
            "XDG_RUNTIME_DIR=/run",
            binary,
            "--config",
            self.local(self.config),
            "--installroot",
            self.local(self.root),
            "--releasever",
            "1",
            "--no-plugins",
            "--repo",
            "haberdasher",
            "--assumeyes",
            "--refresh",
        ]
        argv.extend(
            f"--setopt={key}={local}/{value}"
            for key, value in (
                ("reposdir", "repos"),
                ("varsdir", "vars"),
                ("cachedir", "cache"),
                ("system_cachedir", "cache"),
                ("logdir", "log"),
                ("persistdir", "state"),
            )
        )
        result = self.client.run([*argv, *args], install_root=self.root, timeout=60)
        output = result.stdout + result.stderr
        assert (result.returncode == 0) == success, output.decode(errors="replace")
        return output

    def state(self, version: str) -> None:
        result = self.client.run(
            [
                "rpm",
                "--define",
                "_dbpath /var/lib/rpm",
                "--root",
                str(self.root),
                "-q",
                "--qf",
                "%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\\n",
                "hd-proof-app",
                "hd-proof-data",
            ],
            install_root=self.root,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert sorted(result.stdout.decode().splitlines()) == [
            f"hd-proof-app|0|{version}|1|noarch",
            "hd-proof-data|0|1|1|noarch",
        ]
        assert (self.root / "opt/hd-proof/hd-proof-app").read_text() == f"application-v{version}\n"
        assert (self.root / "opt/hd-proof/hd-proof-data").read_text() == "dependency-v1\n"
