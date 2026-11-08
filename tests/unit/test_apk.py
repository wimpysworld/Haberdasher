# pyright: reportPrivateUsage=false

import gzip
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from haberdasher.config import FormatPolicy
from haberdasher.core import NativeIdentity, RetainedFormat, SourceAsset, VerifiedAsset, sha256_file
from haberdasher.formats import apk
from haberdasher.runtime import Runtime

STANZA = (
    "C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\nP:hd-main\nV:1.0-r1\nA:x86_64\nS:123\nI:12\n"
    "T:Description\nU:https://example.invalid\nL:MIT\no:hd-main\n"
    "D:hd-dependency>=1.0-r0 so:libc.musl-x86_64.so.1\np:cmd:hd-main=1.0\n\n"
)


class FakeRuntime(Runtime):
    def __init__(self, root: Path, stdout: bytes = b"=\n", code: int = 0) -> None:
        super().__init__(root, environ={"PATH": ""})
        self.stdout = stdout
        self.code = code
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
        env_kind: str = "native",
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(tuple(argv))
        return subprocess.CompletedProcess(argv, self.code, self.stdout, b"failure")


def test_complete_stanza_is_preserved() -> None:
    assert apk._records(STANZA) == {("hd-main", "1.0-r1", "x86_64"): STANZA}


@pytest.mark.parametrize(
    "value",
    [
        "",
        STANZA.rstrip(),
        STANZA + STANZA,
        STANZA.replace("P:hd-main\n", ""),
        STANZA.replace("S:123", "S:-1"),
        STANZA.replace("A:x86_64", "A:../x86_64"),
        STANZA.replace("L:MIT", "L:MIT\nL:Apache"),
        STANZA.replace("C:Q1", "C:Q2"),
        STANZA.replace("P:hd-main", "P:../../escape"),
        STANZA.replace("T:Description", "broken"),
    ],
)
def test_records_reject_missing_duplicate_and_unsafe_fields(value: str) -> None:
    with pytest.raises(apk.ApkFailure):
        apk._records(value)


@pytest.mark.parametrize("output,expected", [(b"<\n", -1), (b"=\n", 0), (b">\n", 1)])
def test_compare_uses_native_version_rules(tmp_path: Path, output: bytes, expected: int) -> None:
    runtime = FakeRuntime(tmp_path, output)
    identity = NativeIdentity("apk", "main", "x86_64", "1.0-r1")
    assert apk.compare(identity, replace(identity, version="1.0-r01"), runtime=runtime) == expected
    assert runtime.calls == [
        ("apk", "version", "--check", "1.0-r1", "1.0-r01"),
        ("apk", "version", "--test", "1.0-r1", "1.0-r01"),
    ]
    assert apk.compare(identity, replace(identity, name="other"), runtime=runtime) is None
    assert len(runtime.calls) == 2


@pytest.mark.parametrize("output,code", [(b"=\n", 1), (b"", 0), (b"?\n", 0)])
def test_compare_checks_native_exit_and_output(tmp_path: Path, output: bytes, code: int) -> None:
    runtime = FakeRuntime(tmp_path, output, code)
    identity = NativeIdentity("apk", "main", "x86_64", "1.0-r1")
    with pytest.raises(apk.ApkFailure):
        apk.compare(identity, identity, runtime=runtime)


def test_split_preserves_exact_compressed_bytes(tmp_path: Path) -> None:
    source = tmp_path / "package.apk"
    streams = [gzip.compress(b"control", mtime=0), gzip.compress(b"payload" * 100000, mtime=0)]
    source.write_bytes(b"".join(streams))
    directory = tmp_path / "parts"
    directory.mkdir()
    parts = apk._parts(source, directory)
    assert [path.read_bytes() for path in parts] == streams


@pytest.mark.parametrize(
    "data",
    [
        b"ADBv3",
        b"invalid",
        gzip.compress(b"control")[:-4],
        gzip.compress(b"control") + b"trailing",
        gzip.compress(b"data") * 4,
    ],
)
def test_split_rejects_v3_truncation_and_extra_members(tmp_path: Path, data: bytes) -> None:
    source = tmp_path / "package.apk"
    source.write_bytes(data)
    directory = tmp_path / "parts"
    directory.mkdir()
    with pytest.raises(apk.ApkFailure):
        apk._parts(source, directory)


def test_sha256_precedes_all_native_parsing(tmp_path: Path) -> None:
    runtime = FakeRuntime(tmp_path)
    path = tmp_path / "package.apk"
    path.write_bytes(b"unverified upstream bytes")
    _, size = sha256_file(path)
    source = SourceAsset(
        "synthetic/apk",
        1,
        1,
        path.name,
        size,
        "2026-01-01T00:00:00Z",
        "https://example.invalid/package.apk",
    )
    asset = VerifiedAsset(source, path, "0" * 64, size, 2, "1" * 64)
    with pytest.raises(apk.ApkFailure, match="changed APK input"):
        apk.inspect(asset, policy=FormatPolicy("apk"), runtime=runtime, out=tmp_path / "output")
    assert runtime.calls == []
    assert not (tmp_path / "output").exists()


def test_empty_state_is_distinct_from_missing_retained_state(tmp_path: Path) -> None:
    runtime = FakeRuntime(tmp_path)
    policy = FormatPolicy("apk")
    empty = RetainedFormat("apk", None, (), (), {}, ())
    apk.validate_retained(empty, policy=policy, runtime=runtime)
    for retained in (
        replace(empty, prior_generation="prior"),
        replace(empty, metadata={"indexes": {}}),
    ):
        with pytest.raises(apk.ApkFailure, match="Incomplete"):
            apk.validate_retained(retained, policy=policy, runtime=runtime)
    assert runtime.calls == []


@pytest.mark.parametrize("architectures", [("noarch",), ("aarch64",), ("x86_64", "noarch")])
def test_unqualified_placements_reject(tmp_path: Path, architectures: tuple[str, ...]) -> None:
    with pytest.raises(apk.ApkFailure, match="qualified"):
        apk.validate_retained(
            RetainedFormat("apk", None, (), (), {}, ()),
            policy=FormatPolicy("apk", architectures=architectures),
            runtime=FakeRuntime(tmp_path),
        )
