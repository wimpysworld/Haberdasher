from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from haberdasher.config import FormatPolicy
from haberdasher.core import (
    AdmittedAsset,
    NativeIdentity,
    PreparedFormat,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
    sha256_file,
)
from haberdasher.formats import apt
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession


class Commands(Runtime):
    def __init__(self, root: Path, replies: list[tuple[int, bytes]]) -> None:
        super().__init__(root, environ={"PATH": ""})
        self.replies = list(replies)
        self.commands: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
        env_kind: str = "native",
    ) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(tuple(argv))
        if not self.replies:
            raise AssertionError("Unexpected native call")
        code, data = self.replies.pop(0)
        return subprocess.CompletedProcess(argv, code, data, b"native failure" if code else b"")


def asset(root: Path) -> VerifiedAsset:
    path = root / "fixture.deb"
    path.write_bytes(b"synthetic bytes for mocked inspection")
    sha, size = sha256_file(path)
    source = SourceAsset(
        "synthetic/apt",
        1,
        2,
        path.name,
        size,
        "2026-01-01T00:00:00Z",
        "https://example.invalid/fixture.deb",
    )
    return VerifiedAsset(source, path, sha, size, 3, "0" * 64)


def control(arch: str = "amd64") -> bytes:
    return f"Package: hd-test\nVersion: 1.0\nArchitecture: {arch}\n".encode()


def record(verified: VerifiedAsset, arch: str = "amd64") -> bytes:
    return (
        control(arch)
        + (
            f"Filename: pool/{verified.sha256}.deb\nSize: {verified.size}\nSHA256: {verified.sha256}\n"
            "Depends: hd-one (>= 1),\n hd-two\nDescription: Test\n Full description.\n"
            "X-Custom: retained\n\n"
        ).encode()
    )


@pytest.mark.parametrize("codes,expected", [([0], 0), ([1, 0], -1), ([1, 1, 0], 1)])
def test_native_version_comparison(tmp_path: Path, codes: list[int], expected: int) -> None:
    runtime = Commands(tmp_path, [(code, b"") for code in codes])
    left = NativeIdentity("apt", "hd-test", "amd64", "1.0")
    right = replace(left, version="1.0-0")
    assert apt.compare(left, right, runtime=runtime) == expected
    assert runtime.commands[0] == ("dpkg", "--compare-versions", "1.0", "eq", "1.0-0")


@pytest.mark.parametrize("codes", [[2], [1, 2], [1, 1, 2], [1, 1, 1], [-9]])
def test_native_comparison_errors_fail_closed(tmp_path: Path, codes: list[int]) -> None:
    runtime = Commands(tmp_path, [(code, b"") for code in codes])
    identity = NativeIdentity("apt", "hd-test", "amd64", "1.0")
    with pytest.raises(apt.AptFailure):
        apt.compare(identity, identity, runtime=runtime)


@pytest.mark.parametrize(
    "other",
    [
        NativeIdentity("apt", "hd-other", "amd64", "1.0"),
        NativeIdentity("apt", "hd-test", "arm64", "1.0"),
        NativeIdentity("rpm", "hd-test", "amd64", "1.0"),
    ],
)
def test_different_slots_do_not_call_native_comparison(
    tmp_path: Path, other: NativeIdentity
) -> None:
    runtime = Commands(tmp_path, [])
    assert (
        apt.compare(NativeIdentity("apt", "hd-test", "amd64", "1.0"), other, runtime=runtime)
        is None
    )
    assert not runtime.commands


def test_complete_record_and_multiline_dependencies_are_preserved(tmp_path: Path) -> None:
    verified = asset(tmp_path)
    raw = record(verified)
    runtime = Commands(tmp_path, [(0, control()), (0, raw)])
    inspected = apt.inspect(
        verified,
        policy=FormatPolicy("apt", ("amd64",)),
        runtime=runtime,
        out=tmp_path / "inspection",
    )
    assert inspected.metadata == {"record": raw.decode()}
    assert inspected.evidence == {"dependencies": {"Depends": "hd-one (>= 1),\n hd-two"}}
    assert inspected.verified == verified
    assert sha256_file(tmp_path / f"inspection/pool/{verified.sha256}.deb") == (
        verified.sha256,
        verified.size,
    )
    assert runtime.commands == [
        ("dpkg-deb", "-f", str(verified.local_path)),
        ("apt-ftparchive", "packages", f"pool/{verified.sha256}.deb"),
    ]


@pytest.mark.parametrize("arch", ["amd64", "arm64", "all"])
def test_approved_architectures_and_all(tmp_path: Path, arch: str) -> None:
    verified = asset(tmp_path)
    runtime = Commands(tmp_path, [(0, control(arch)), (0, record(verified, arch))])
    inspected = apt.inspect(
        verified,
        policy=FormatPolicy("apt", ("amd64", "arm64")),
        runtime=runtime,
        out=tmp_path / "inspection",
    )
    assert inspected.identity.architecture == arch


@pytest.mark.parametrize(
    "native_control",
    [
        control("i386"),
        b"",
        control() + b"Package: duplicate\n",
        control() + b"\nPackage: extra\n",
        control().replace(b"hd-test", b"../unsafe"),
        control().replace(b"1.0", b"bad version"),
        control() + b"Broken\n",
        control() + b"X-Test: value\r\n",
    ],
)
def test_invalid_native_control_is_rejected(tmp_path: Path, native_control: bytes) -> None:
    verified = asset(tmp_path)
    runtime = Commands(tmp_path, [(0, native_control)])
    with pytest.raises(apt.AptFailure):
        apt.inspect(
            verified,
            policy=FormatPolicy("apt", ("amd64",)),
            runtime=runtime,
            out=tmp_path / "inspection",
        )


@pytest.mark.parametrize("mode", ["empty", "duplicate", "digest", "size", "filename", "identity"])
def test_index_records_must_bind_the_exact_verified_asset(tmp_path: Path, mode: str) -> None:
    verified = asset(tmp_path)
    raw = record(verified)
    replacements = {
        "empty": b"",
        "duplicate": raw + raw,
        "digest": raw.replace(verified.sha256.encode(), b"a" * 64),
        "size": raw.replace(f"Size: {verified.size}".encode(), b"Size: 0"),
        "filename": raw.replace(b"Filename: pool/", b"Filename: ../"),
        "identity": raw.replace(b"Version: 1.0", b"Version: 2.0"),
    }
    runtime = Commands(tmp_path, [(0, control()), (0, replacements[mode])])
    with pytest.raises(apt.AptFailure):
        apt.inspect(
            verified,
            policy=FormatPolicy("apt", ("amd64",)),
            runtime=runtime,
            out=tmp_path / "inspection",
        )


@pytest.mark.parametrize("command", ["dpkg-deb", "apt-ftparchive"])
def test_inspection_checks_native_exit_status(tmp_path: Path, command: str) -> None:
    verified = asset(tmp_path)
    replies = [(2, control())] if command == "dpkg-deb" else [(0, control()), (2, record(verified))]
    runtime = Commands(tmp_path, replies)
    with pytest.raises(apt.AptFailure, match="native command failed"):
        apt.inspect(
            verified,
            policy=FormatPolicy("apt", ("amd64",)),
            runtime=runtime,
            out=tmp_path / "inspection",
        )


def test_verified_bytes_are_checked_before_any_native_call(tmp_path: Path) -> None:
    verified = asset(tmp_path)
    verified.local_path.write_bytes(b"changed")
    runtime = Commands(tmp_path, [])
    with pytest.raises(apt.AptFailure, match="changed"):
        apt.inspect(
            verified,
            policy=FormatPolicy("apt", ("amd64",)),
            runtime=runtime,
            out=tmp_path / "inspection",
        )
    assert not runtime.commands


def test_empty_bootstrap_needs_no_native_commands_or_signer(tmp_path: Path) -> None:
    runtime = Commands(tmp_path, [])
    config = FormatPolicy("apt", ("amd64",))
    empty = RetainedFormat("apt", None, (), (), {}, ())
    signer = SigningSession(runtime, tmp_path / "gnupg", "A" * 40)
    prepared = apt.prepare(
        [],
        empty,
        policy=config,
        runtime=runtime,
        signer=signer,
        now=datetime.now(UTC),
        out=tmp_path / "output",
    )
    assert prepared == PreparedFormat("apt", empty, (), ())
    apt.validate_prepared(prepared, policy=config, runtime=runtime, now=datetime.now(UTC))
    assert not runtime.commands


@pytest.mark.parametrize(
    "broken",
    [
        RetainedFormat("apt", "prior", (), (), {}, ()),
        RetainedFormat("apt", None, (), (), {"files": {}}, ()),
        RetainedFormat(
            "apt", None, (), (NativeIdentity("apt", "hd-test", "amd64", "1.0"),), {}, ()
        ),
    ],
)
def test_incomplete_retained_state_cannot_bootstrap(tmp_path: Path, broken: RetainedFormat) -> None:
    runtime = Commands(tmp_path, [])
    with pytest.raises(apt.AptFailure, match="Incomplete"):
        apt.validate_retained(broken, policy=FormatPolicy("apt", ("amd64",)), runtime=runtime)


def test_changed_admitted_bytes_do_not_produce_outputs(tmp_path: Path) -> None:
    verified = asset(tmp_path)
    runtime = Commands(tmp_path, [(0, control()), (0, record(verified))])
    config = FormatPolicy("apt", ("amd64",))
    inspected = apt.inspect(verified, policy=config, runtime=runtime, out=tmp_path / "inspection")
    verified.local_path.write_bytes(b"changed")
    signer = SigningSession(runtime, tmp_path / "gnupg", "A" * 40)
    with patch.object(signer, "sign_file", side_effect=AssertionError("Signer must not run")):
        with pytest.raises(apt.AptFailure, match="bytes changed"):
            apt.prepare(
                [AdmittedAsset(inspected, "preserve", "history")],
                RetainedFormat("apt", None, (), (), {}, ()),
                policy=config,
                runtime=runtime,
                signer=signer,
                now=datetime.now(UTC),
                out=tmp_path / "output",
            )


def test_all_is_not_a_concrete_index_architecture(tmp_path: Path) -> None:
    runtime = Commands(tmp_path, [])
    with pytest.raises(apt.AptFailure, match="concrete"):
        apt.validate_retained(
            RetainedFormat("apt", None, (), (), {}, ()),
            policy=FormatPolicy("apt", ("all",)),
            runtime=runtime,
        )
