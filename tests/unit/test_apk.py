# pyright: reportPrivateUsage=false

import gzip
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
    InspectedAsset,
    NativeIdentity,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
    sha256_file,
)
from haberdasher.formats import apk
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession

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


@pytest.mark.parametrize("symlink", [None, "root", "parent", "validation"])
def test_prepare_normalises_relative_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, symlink: str | None
) -> None:
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "output"
    out = Path("output")
    if symlink is not None:
        outside = tmp_path / "outside"
        outside.mkdir()
        if symlink == "root":
            root.symlink_to(outside, target_is_directory=True)
        elif symlink == "parent":
            (tmp_path / "parent").symlink_to(outside, target_is_directory=True)
            out = Path("parent/output")
        else:
            root.mkdir()
            (root / "validation").symlink_to(outside, target_is_directory=True)
    runtime = FakeRuntime(tmp_path / "runtime")
    private, public = tmp_path / "synthetic-private", tmp_path / apk.PUBLIC_KEY
    private.write_bytes(b"inert private fixture")
    public.write_bytes(b"inert public fixture")
    signer = SigningSession(runtime, tmp_path / "gnupg", "A" * 40)
    path = tmp_path / "input.apk"
    path.write_bytes(b"inert package fixture")
    sha, size = sha256_file(path)
    source = SourceAsset(
        "synthetic/apk",
        1,
        1,
        path.name,
        size,
        "2026-01-01T00:00:00Z",
        "https://example.invalid/input.apk",
    )
    verified = VerifiedAsset(source, path, sha, size, 2, "1" * 64)
    stanza = STANZA.replace("S:123", f"S:{size}")
    inspected = InspectedAsset(
        verified,
        NativeIdentity("apk", "hd-main", "x86_64", "1.0-r1"),
        {
            "stanza": stanza,
            "pkginfo": "pkgname = hd-main\npkgver = 1.0-r1\narch = x86_64\ndatahash = "
            + "0" * 64
            + "\n",
            "datahash": "0" * 64,
        },
        {"dependencies": apk._fields(stanza)["D"], "control_identity": apk._fields(stanza)["C"]},
        "unsigned",
    )
    native_run = runtime.run

    def run(argv: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        result = native_run(argv)
        for flag in ("-czf", "-C", "--keys-dir", "--index", "--output", "-p"):
            if flag in argv:
                argument = Path(argv[argv.index(flag) + 1])
                assert argument.is_absolute()
                assert argument.is_relative_to(root)
        if "-czf" in argv:
            Path(argv[argv.index("-czf") + 1]).write_bytes(b"inert seed")
        if "--output" in argv:
            Path(argv[argv.index("--output") + 1]).write_bytes(b"inert index")
        if "abuild-sign" in argv:
            assert Path(argv[-1]).is_relative_to(root)
        return result

    with (
        patch.object(runtime, "run", side_effect=run),
        patch.object(signer, "alpine_key", return_value=(private, public)) as signing,
        patch.object(apk, "inspect", return_value=inspected) as inspection,
        patch.object(apk, "_extract", return_value=stanza),
        patch.object(apk, "_verify_index", return_value=apk._records(stanza)),
    ):

        def prepare() -> apk.PreparedFormat:
            return apk.prepare(
                [AdmittedAsset(inspected, "preserve", "synthetic")],
                RetainedFormat("apk", None, (), (), {}, ()),
                policy=FormatPolicy("apk"),
                runtime=runtime,
                signer=signer,
                now=datetime(2026, 1, 1, tzinfo=UTC),
                out=out,
            )

        if symlink is not None:
            with pytest.raises(ValueError, match="Symlink"):
                prepare()
            assert not runtime.calls
            inspection.assert_not_called()
            signing.assert_not_called()
            assert not list((tmp_path / "outside").iterdir())
            return
        prepared = prepare()
        assert inspection.call_args.kwargs["out"] == root
    assert {item.local_path for item in prepared.outputs} == {
        root / apk.PUBLIC_KEY,
        root / "x86_64/hd-main-1.0-r1.apk",
        root / "x86_64/APKINDEX.tar.gz",
    }
    assert prepared.retained.metadata["public_key"] == apk._file_record(root / apk.PUBLIC_KEY)
    assert prepared.retained.metadata["indexes"] == {
        "x86_64": apk._file_record(root / "x86_64/APKINDEX.tar.gz")
    }
    assert runtime.calls


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
