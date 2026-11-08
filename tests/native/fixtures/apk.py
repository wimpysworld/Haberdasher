"""Script-free APK v2 fixtures built with native Alpine archive tools."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

from haberdasher.core import (
    JSONValue,
    PreparedFormat,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
    atomic_write,
    sha256_file,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession
from tests.support.keys import run
from tests.support.native import NativeClient


def verified(path: Path, asset_id: int = 1) -> VerifiedAsset:
    digest, size = sha256_file(path)
    source = SourceAsset(
        "synthetic/apk",
        1,
        asset_id,
        path.name,
        size,
        "2026-01-01T00:00:00Z",
        f"https://example.invalid/{path.name}",
        digest,
    )
    return VerifiedAsset(source, path, digest, size, 999, "a" * 64)


def archive(runtime: Runtime, directory: Path, *members: str) -> bytes:
    tar = run(
        runtime,
        "tar",
        "--format=ustar",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "--mtime=@1700000000",
        "-cf",
        "-",
        "-C",
        str(directory),
        *members,
    )
    cut = run(runtime, "abuild-tar", "--cut", data=tar)
    return run(runtime, "gzip", "-n", "-9", data=cut)


def fixture(
    runtime: Runtime,
    name: str,
    version: str,
    *,
    payload: str,
    dependency: str = "",
    signer: SigningSession | None = None,
    arch: str = "x86_64",
    suffix: str = "",
) -> VerifiedAsset:
    directory = runtime.root / f"source-{name}-{version}{suffix}"
    tree, control = directory / "tree", directory / "control"
    (tree / "usr/share" / name).mkdir(mode=0o700, parents=True)
    control.mkdir(mode=0o700)
    data = (payload + "\n").encode()
    atomic_write(tree / "usr/share" / name / "payload", data)
    tar = run(
        runtime,
        "tar",
        "--format=posix",
        "--pax-option=exthdr.name=%d/PaxHeaders/%f,atime:=0,ctime:=0",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "--mtime=@1700000000",
        "-cf",
        "-",
        "-C",
        str(tree),
        "usr",
    )
    hashed = run(runtime, "abuild-tar", "--hash", "--cut", data=tar)
    payload_file = directory / "data.gz"
    atomic_write(payload_file, run(runtime, "gzip", "-n", "-9", data=hashed + tar[-1024:]))
    info = (
        f"pkgname = {name}\npkgver = {version}\npkgdesc = Disposable APK acceptance\n"
        "url = https://example.invalid\nbuilddate = 1700000000\npackager = Synthetic APK\n"
        f"size = {len(data)}\narch = {arch}\norigin = {name}\nlicense = MIT\n"
        f"datahash = {sha256_file(payload_file)[0]}\n"
        + (f"depend = {dependency}\n" if dependency else "")
    )
    atomic_write(control / ".PKGINFO", info.encode())
    compressed = directory / "control.gz"
    atomic_write(compressed, archive(runtime, control, ".PKGINFO"))
    if signer is not None:
        private, public = signer.alpine_key()
        run(
            runtime,
            "env",
            "ABUILD_CONF=/dev/null",
            "ABUILD_USERCONF=/dev/null",
            "ABUILD_DEFCONF=/dev/null",
            "abuild-sign",
            "-t",
            "RSA256",
            "-k",
            str(private),
            "-p",
            str(public),
            str(compressed),
        )
    path = directory / f"upstream-asset-{name}-{version}.apk"
    atomic_write(path, compressed.read_bytes() + payload_file.read_bytes())
    return verified(path)


def tamper(runtime: Runtime, asset: VerifiedAsset, kind: str, path: Path) -> VerifiedAsset:
    directory = asset.local_path.parent
    control = (directory / "control.gz").read_bytes()
    payload = (directory / "data.gz").read_bytes()
    if kind == "payload":
        raw = run(runtime, "gzip", "-dc", data=payload)
        payload = run(runtime, "gzip", "-n", "-9", data=raw.replace(b"version-one", b"version-bad"))
    elif kind == "control":
        changed = directory / "changed-control"
        changed.mkdir(mode=0o700)
        info = (directory / "control/.PKGINFO").read_bytes().replace(b"Disposable", b"Tamperedxx")
        atomic_write(changed / ".PKGINFO", info)
        control = archive(runtime, changed, ".PKGINFO")
    else:
        raise ValueError("Unknown fixture corruption")
    atomic_write(path, control + payload)
    return verified(path)


def committed(prepared: PreparedFormat, etag: str = '"synthetic-etag"') -> RetainedFormat:
    retained_indexes = cast(dict[str, dict[str, JSONValue]], prepared.retained.metadata["indexes"])
    indexes: dict[str, JSONValue] = {
        arch: {**record, "etag": etag} for arch, record in retained_indexes.items()
    }
    return replace(
        prepared.retained,
        prior_generation="synthetic-generation",
        metadata={
            **prepared.retained.metadata,
            "indexes": indexes,
        },
    )


def wrong_public_key(runtime: Runtime, public: Path, output: Path) -> None:
    modulus = (
        run(runtime, "openssl", "rsa", "-pubin", "-in", str(public), "-modulus", "-noout")
        .decode()
        .strip()
        .removeprefix("Modulus=")
    )
    config, der = output.parent / "wrong.asn1", output.parent / "wrong.der"
    atomic_write(
        config,
        (f"asn1=SEQUENCE:rsakey\n[rsakey]\nn=INTEGER:0x1{modulus}\ne=INTEGER:65537\n").encode(),
    )
    run(runtime, "openssl", "asn1parse", "-genconf", str(config), "-out", str(der), "-noout")
    atomic_write(
        output,
        run(
            runtime,
            "openssl",
            "rsa",
            "-RSAPublicKey_in",
            "-inform",
            "DER",
            "-in",
            str(der),
            "-pubout",
        ),
    )
    assert sha256_file(output)[0] != sha256_file(public)[0]


class Client:
    def __init__(self, runtime: Runtime, name: str, url: str, key: Path | None) -> None:
        self.native = NativeClient(runtime, name)
        self.root = self.native.root
        self.keys = self.native.path("config/keys")
        self.keys.mkdir(mode=0o700)
        if key is not None:
            shutil.copyfile(key, self.keys / "haberdasher.rsa.pub")
        self.repositories = self.native.path("config/repositories")
        atomic_write(self.repositories, b"")
        self.run("add", "--initdb", "--usermode", "--no-scripts", "--no-commit-hooks")
        atomic_write(self.repositories, (url + "\n").encode())

    def run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        argv = [
            "apk",
            "--root",
            str(self.root),
            "--arch",
            "x86_64",
            "--keys-dir",
            str(self.keys),
            "--repositories-file",
            str(self.repositories),
            "--cache-dir",
            str(self.native.path("cache")),
            "--no-logfile",
            "--no-progress",
            "--no-interactive",
            *args,
        ]
        assert "--allow-untrusted" not in argv
        result = self.native.run(argv, install_root=self.root)
        if check:
            assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()
        return result

    def add(self, *packages: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return self.run(
            "add", "--usermode", "--no-scripts", "--no-commit-hooks", *packages, check=check
        )

    def installed(self, name: str, version: str, payload: str) -> None:
        self.run("info", "--installed", f"{name}={version}")
        listing = self.run("list", "--installed").stdout.decode()
        assert f"{name}-{version}" in listing
        assert (self.root / "usr/share" / name / "payload").read_text() == payload + "\n"

    def fetch(self, directory: str, *packages: str, check: bool = True) -> Path:
        target = self.native.path(directory)
        target.mkdir(mode=0o700)
        assert not list(target.iterdir())
        self.run("fetch", "--recursive", "--output", str(target), *packages, check=check)
        return target
