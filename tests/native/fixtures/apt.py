"""Script-free DEBs and guarded private-root APT commands."""

from __future__ import annotations

import os
import pwd
import shutil
from dataclasses import replace
from pathlib import Path

from haberdasher import site
from haberdasher.config import FormatPolicy
from haberdasher.core import (
    JSONValue,
    PreparedFormat,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
    sha256_file,
)
from haberdasher.runtime import Runtime
from tests.support.http import set_generation_mtime
from tests.support.native import NativeClient


def policy() -> FormatPolicy:
    return FormatPolicy("apt", architectures=("amd64", "arm64"))


def build(
    runtime: Runtime,
    name: str,
    version: str,
    payload: str,
    *,
    arch: str = "amd64",
    depends: str = "",
    source: str = "",
    asset_id: int = 1,
) -> VerifiedAsset:
    root = runtime.root / f"build-{asset_id}"
    control = root / "DEBIAN/control"
    control.parent.mkdir(parents=True)
    destination = root / f"usr/share/{name}/value"
    destination.parent.mkdir(parents=True)
    control.write_text(
        f"Package: {name}\nVersion: {version}\nArchitecture: {arch}\n"
        + (f"Source: {source}\n" if source else "")
        + "Maintainer: Synthetic test <test@invalid>\n"
        + (f"Depends: {depends}\n" if depends else "")
        + "Description: Disposable APT fixture\n Complete multiline description.\n"
        "X-Haberdasher-Fixture: preserved-extension\n"
    )
    destination.write_text(payload + "\n")
    for path in (root, *root.rglob("*")):
        path.chmod(0o755 if path.is_dir() else 0o644)
    output = runtime.root / f"asset-{asset_id}.deb"
    result = runtime.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(output)])
    if result.returncode:
        raise RuntimeError(result.stderr.decode())
    sha, size = sha256_file(output)
    source = SourceAsset(
        "synthetic/apt",
        1,
        asset_id,
        output.name,
        size,
        "2026-01-01T00:00:00Z",
        f"https://example.invalid/{output.name}",
    )
    return VerifiedAsset(source, output, sha, size, 999, "0" * 64)


def publish(prepared: PreparedFormat, root: Path, generation: int) -> RetainedFormat:
    etags: dict[str, JSONValue] = dict(prepared.retained.metadata.get("etags", {}))  # type: ignore[arg-type]
    paths: list[Path] = []
    for output in prepared.outputs:
        target = root / output.ref.key
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output.local_path, target)
        assert sha256_file(target) == (output.ref.sha256, output.ref.size)
        etags[output.ref.key] = f"synthetic-{generation}-{output.ordinal}"
        paths.append(target)
    set_generation_mtime(paths, generation)
    return replace(
        prepared.retained,
        metadata={**prepared.retained.metadata, "etags": etags},
    )


class Client:
    def __init__(self, runtime: Runtime, name: str, url: str, keyring: Path) -> None:
        self.native = NativeClient(runtime, name)
        client = self.native
        for relative in (
            "config/empty",
            "state/lists/partial",
            "cache/archives/partial",
            "root/var/lib/dpkg",
            "root/var/log",
        ):
            client.path(relative).mkdir(parents=True, exist_ok=True)
        client.path("root/var/lib/dpkg/status").touch()
        client.path("config/sources.list").touch()
        client.path("config/sources.list.d").mkdir()
        client.path("config/sources.list.d/wimpysworld.sources").write_text(
            site.apt_sources(url, str(keyring), "amd64")
        )
        self.config = client.path("config/apt.conf")
        dpkg = shutil.which("dpkg", path=runtime.environment["PATH"])
        if dpkg is None:
            raise RuntimeError("Native dpkg is required")
        gpgv = shutil.which("gpgv", path=runtime.environment["PATH"])
        if gpgv is None:
            raise RuntimeError("Native gpgv is required")
        self.config.write_text(f'''Dir "{client.base}";
Dir::Etc "{client.path("config")}";
Dir::Etc::main "-";
Dir::Etc::parts "{client.path("config/empty")}";
Dir::Etc::sourcelist "{client.path("config/sources.list")}";
Dir::Etc::sourceparts "{client.path("config/sources.list.d")}";
Dir::Etc::trusted "{client.path("config/absent.gpg")}";
Dir::Etc::trustedparts "{client.path("config/empty")}";
Dir::State "{client.path("state")}";
Dir::State::status "{client.root}/var/lib/dpkg/status";
Dir::State::lists "{client.path("state/lists")}";
Dir::State::extended_states "{client.path("state/extended_states")}";
Dir::Cache "{client.path("cache")}";
Dir::Cache::archives "{client.path("cache/archives")}";
Dir::Log "{client.path("log")}";
Dir::Bin::dpkg "{dpkg}";
Apt::Key::gpgvcommand "{gpgv}";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
APT::Sandbox::User "{pwd.getpwuid(os.getuid()).pw_name}";
APT::Update::Error-Mode "any";
Acquire::Languages "none";
Acquire::Retries "0";
Acquire::http::Proxy "DIRECT";
Acquire::Check-Date "true";
Acquire::Check-Valid-Until "true";
DPkg::Options {{ "--log={client.root}/var/log/dpkg.log"; }};
DPkg::Use-Pty "false";
''')

    def apt(self, *args: str, succeeds: bool = True) -> bytes:
        client = self.native
        result = client.run(
            [
                "env",
                f"APT_CONFIG={self.config}",
                "fakeroot",
                "apt-get",
                "-o",
                f"Dir::State::status={client.root}/var/lib/dpkg/status",
                f"-oDPkg::Options::=--root={client.root}",
                f"-oDPkg::Options::=--admindir={client.root}/var/lib/dpkg",
                *args,
            ],
            install_root=client.root,
        )
        log = result.stdout + result.stderr
        client.path("log/last.log").write_bytes(log)
        if succeeds:
            assert result.returncode == 0, log.decode()
        else:
            assert result.returncode != 0, log.decode()
        return log

    def installed(self, name: str, version: str, payload: str) -> None:
        client = self.native
        result = client.run(
            [
                "dpkg-query",
                f"--admindir={client.root}/var/lib/dpkg",
                "-W",
                "-f=${Status} ${Version}",
                name,
            ],
            install_root=client.root,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout.decode() == f"install ok installed {version}"
        assert client.path(f"root/usr/share/{name}/value").read_text() == payload + "\n"

    def not_installed(self, name: str) -> None:
        client = self.native
        result = client.run(
            ["dpkg-query", f"--admindir={client.root}/var/lib/dpkg", "-W", "-f=${Status}", name],
            install_root=client.root,
        )
        assert result.stdout in (b"", b"unknown ok not-installed")
        assert not client.path(f"root/usr/share/{name}/value").exists()
