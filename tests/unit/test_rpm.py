from __future__ import annotations

import gzip
import hashlib
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from haberdasher import core
from haberdasher.config import FormatPolicy
from haberdasher.core import AdmittedAsset, NativeIdentity, ObjectRef, RetainedFormat
from haberdasher.formats import rpm
from haberdasher.runtime import Runtime, private_workspace

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def object_ref(path: Path, key: str, kind: str = "entry", name: str = "apt") -> ObjectRef:
    sha, size = core.sha256_file(path)
    return ObjectRef(name, key, kind, size, sha, "application/octet-stream", "no-cache")


def test_compare_uses_native_evr(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Sequence[str]] = []

    def run(
        self: Runtime, argv: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"0\n", b"")

    monkeypatch.setattr(Runtime, "run", run)
    with private_workspace() as runtime:
        identity = NativeIdentity("rpm", "app", "noarch", "1.01", release="1")
        assert rpm.compare(identity, replace(identity, version="1.1"), runtime=runtime) == 0
        assert len(calls) == 3
        assert all(call[:2] == ["rpm", "--eval"] for call in calls)
        assert 'rpm.vercmp("1.01","1.1")' in calls[1][2]
        assert rpm.compare(identity, replace(identity, name="other"), runtime=runtime) is None
        assert len(calls) == 3
        with pytest.raises(rpm.RpmFailure, match="Unsafe"):
            rpm.compare(identity, replace(identity, version='%{lua:print("bad")}'), runtime=runtime)


def test_native_failure_is_not_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(
        self: Runtime, argv: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, b"0\n", b"failure")

    monkeypatch.setattr(Runtime, "run", run)
    with private_workspace() as runtime:
        identity = NativeIdentity("rpm", "app", "noarch", "1", release="1")
        with pytest.raises(rpm.RpmFailure, match="command failed"):
            rpm.compare(identity, identity, runtime=runtime)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"<broken>",
        b'<!DOCTYPE x [<!ENTITY e "bad">]><x>&e;</x>',
        b"<x>" * 65 + b"</x>" * 65,
        b"\xff",
        b"\0<root/>",
    ],
)
def test_bounded_xml_rejects(data: bytes) -> None:
    with pytest.raises(rpm.RpmFailure):
        rpm.parse_xml(data)


def metadata(
    root: Path,
    *,
    missing: str = "",
    location: str | None = None,
    history: Sequence[AdmittedAsset] = (),
) -> None:
    (root / "repodata").mkdir(exist_ok=True)
    entries: list[str] = []
    for kind, (namespace, name) in rpm.NAMESPACES.items():
        if kind == missing:
            continue
        packages: list[str] = []
        for asset in history:
            identity = asset.inspected.identity
            version = (
                f'<version epoch="{identity.epoch}" ver="{identity.version}" '
                f'rel="{identity.release}"/>'
            )
            if kind == "primary":
                packages.append(
                    f"<package><name>{identity.name}</name><arch>{identity.architecture}</arch>"
                    f'{version}<checksum type="sha256">{asset.published_sha256}</checksum>'
                    f'<location href="{asset.inspected.metadata["location"]}"/>'
                    f'<size package="{asset.inspected.metadata["published_size"]}"/></package>'
                )
            else:
                packages.append(
                    f'<package name="{identity.name}" arch="{identity.architecture}" '
                    f'pkgid="{asset.published_sha256}">{version}</package>'
                )
        opened = (
            f'<{name} xmlns="{namespace[1:-1]}" packages="{len(history)}">'
            f"{''.join(packages)}</{name}>"
        ).encode()
        compressed = gzip.compress(opened)
        path = f"repodata/{kind}.gz"
        (root / path).write_bytes(compressed)
        entries.append(
            f'<data type="{kind}"><location href="{location or path}"/>'
            f'<checksum type="sha256">{hashlib.sha256(compressed).hexdigest()}</checksum>'
            f'<open-checksum type="sha256">{hashlib.sha256(opened).hexdigest()}</open-checksum>'
            f"<size>{len(compressed)}</size><open-size>{len(opened)}</open-size></data>"
        )
    (root / rpm.ENTRIES[0]).write_text(
        f'<repomd xmlns="{rpm.REPO[1:-1]}">{"".join(entries)}</repomd>'
    )


def test_complete_metadata_is_required(tmp_path: Path) -> None:
    metadata(tmp_path)
    assert set(rpm.metadata_documents(tmp_path)) == set(rpm.NAMESPACES)
    for kind in rpm.NAMESPACES:
        metadata(tmp_path, missing=kind)
        with pytest.raises(rpm.RpmFailure, match="Incomplete"):
            rpm.metadata_documents(tmp_path)


@pytest.mark.parametrize("location", ["../outside.gz", "/outside.gz", "repodata/../outside.gz"])
def test_metadata_path_traversal(tmp_path: Path, location: str) -> None:
    metadata(tmp_path, location=location)
    with pytest.raises(ValueError):
        rpm.metadata_documents(tmp_path)


def test_metadata_compressed_and_open_checksums(tmp_path: Path) -> None:
    metadata(tmp_path)
    path = tmp_path / "repodata/primary.gz"
    path.write_bytes(gzip.compress(b"<broken/>"))
    with pytest.raises(rpm.RpmFailure, match="checksum"):
        rpm.metadata_documents(tmp_path)


def retained_rpm(root: Path, architectures: tuple[str, ...]) -> RetainedFormat:
    root.mkdir(parents=True)
    keyring = root / "public.gpg"
    keyring.write_bytes(b"synthetic trust")
    history: list[AdmittedAsset] = []
    for index, architecture in enumerate(architectures, 1):
        location = f"packages/test.{architecture}.rpm"
        path = root / location
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(f"synthetic signed {architecture}".encode())
        digest, size = core.sha256_file(path)
        source = core.SourceAsset(
            "test/project",
            1,
            index,
            path.name,
            size,
            NOW.isoformat(),
            f"https://example.invalid/{path.name}",
        )
        verified = core.VerifiedAsset(source, path, "a" * 64, size, 100, "b" * 64)
        history.append(
            core.AdmittedAsset(
                core.InspectedAsset(
                    verified,
                    NativeIdentity("rpm", "test", architecture, "1", release="1"),
                    {"location": location, "published_size": size},
                    {},
                    "unsigned",
                ),
                "rpm-sign",
                f"history-{index}",
                digest,
            )
        )
    metadata(root, history=history)
    (root / rpm.ENTRIES[1]).write_bytes(b"synthetic signature")
    records = rpm._records(root, history)  # pyright: ignore[reportPrivateUsage]
    history = [
        replace(
            asset,
            inspected=replace(
                asset.inspected,
                metadata={**asset.inspected.metadata, "rpm_records": records[asset.history_key]},
            ),
        )
        for asset in history
    ]
    refs = tuple(
        object_ref(path, path.relative_to(root).as_posix(), kind, "rpm")
        for kind, paths in (
            ("package", sorted((root / "packages").iterdir())),
            ("dependency", sorted((root / "repodata").glob("*.gz"))),
            ("entry", [root / key for key in rpm.ENTRIES]),
        )
        for path in paths
    )
    return RetainedFormat(
        "rpm",
        None,
        tuple(history),
        tuple(asset.inspected.identity for asset in history),
        {
            "root": str(root),
            "keyring": str(keyring),
            "keyring_sha256": core.sha256_file(keyring)[0],
            "fingerprint": "A" * 40,
        },
        refs,
    )


def mock_rpm_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(
        self: Runtime, argv: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "gpg" and "--show-keys" in argv:
            output = f"fpr:::::::::{'A' * 40}:".encode()
        elif argv[0] == "gpgv":
            output = f"[GNUPG:] VALIDSIG {'A' * 40} 0 0 0 4 0 1 8 00 {'A' * 40}".encode()
        elif argv[0] == "gpg" and "--export" in argv:
            output = b"synthetic public export"
        elif argv[0] == "rpm" and "--initdb" in argv:
            output = b""
        elif argv[0] == "rpmkeys" and "--import" in argv:
            output = b""
        elif argv[0] == "rpmkeys" and "--checksig" in argv:
            output = b"RSA/SHA256 Signature: OK"
        else:
            raise AssertionError(f"Unexpected native command: {argv[0]}")
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(Runtime, "run", run)


@pytest.mark.parametrize("architectures", [("x86_64",), ("noarch", "x86_64")])
def test_retained_architecture_policy_change_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, architectures: tuple[str, ...]
) -> None:
    retained = retained_rpm(tmp_path / "rpm", architectures)
    mock_rpm_commands(monkeypatch)
    runtime = Runtime(tmp_path / "runtime", environ={})
    rpm.validate_retained(retained, policy=FormatPolicy("rpm"), runtime=runtime)
    with pytest.raises(rpm.RpmFailure, match="architecture is not approved"):
        rpm.validate_retained(
            retained, policy=FormatPolicy("rpm", architectures=("aarch64",)), runtime=runtime
        )


@pytest.mark.parametrize("architectures", [("x86_64",), ("noarch",), ("noarch", "aarch64")])
def test_retained_compatible_architectures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, architectures: tuple[str, ...]
) -> None:
    retained = retained_rpm(tmp_path / "rpm", architectures)
    mock_rpm_commands(monkeypatch)
    rpm.validate_retained(
        retained,
        policy=FormatPolicy("rpm", architectures=("x86_64", "aarch64")),
        runtime=Runtime(tmp_path / "runtime", environ={}),
    )


def test_bootstrap_is_not_missing_state() -> None:
    policy = FormatPolicy("rpm")
    empty = RetainedFormat("rpm", None, (), (), {}, ())
    with private_workspace() as runtime:
        rpm.validate_retained(empty, policy=policy, runtime=runtime)
        for state in (
            replace(empty, prior_generation="one"),
            replace(empty, metadata={"root": "/"}),
        ):
            with pytest.raises(rpm.RpmFailure, match="Incomplete"):
                rpm.validate_retained(state, policy=policy, runtime=runtime)
