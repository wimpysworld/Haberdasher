# pyright: reportPrivateUsage=false

import gzip
import hashlib
import io
import subprocess
import tarfile
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from haberdasher.admission import admit
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
        progress: Callable[[str], None] | None = None,
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


@pytest.mark.parametrize("architectures", [("noarch",), ("armv7",), ("x86_64", "noarch")])
def test_unqualified_placements_reject(tmp_path: Path, architectures: tuple[str, ...]) -> None:
    with pytest.raises(apk.ApkFailure, match="qualified"):
        apk.validate_retained(
            RetainedFormat("apk", None, (), (), {}, ()),
            policy=FormatPolicy("apk", architectures=architectures),
            runtime=FakeRuntime(tmp_path),
        )


@pytest.mark.parametrize("architectures", [("x86_64",), ("aarch64",), ("x86_64", "aarch64")])
def test_qualified_placements_accept(tmp_path: Path, architectures: tuple[str, ...]) -> None:
    apk.validate_retained(
        RetainedFormat("apk", None, (), (), {}, ()),
        policy=FormatPolicy("apk", architectures=architectures),
        runtime=FakeRuntime(tmp_path),
    )


APK_POLICY = FormatPolicy("apk", architectures=("x86_64", "aarch64"))


def _tar(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _read(path: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            stream = archive.extractfile(member)
            if stream is not None:
                members[member.name] = stream.read()
    return members


class NativeApk(FakeRuntime):
    """Emulate tar, apk index, and apk version for unsigned two-stream APK v2 inputs."""

    def asset(self, name: str, version: str, arch: str) -> VerifiedAsset:
        data = gzip.compress(_tar({"usr/bin/" + name: b"inert"}), mtime=0)
        info = (
            f"pkgname = {name}\npkgver = {version}\narch = {arch}\n"
            f"datahash = {hashlib.sha256(data).hexdigest()}\n"
        )
        control = gzip.compress(_tar({".PKGINFO": info.encode()}), mtime=0)
        path = self.root.parent / f"{name}_{version}_{arch}.apk"
        path.write_bytes(control + data)
        sha, size = sha256_file(path)
        source = SourceAsset(
            "wimpysworld/tailor",
            1,
            1,
            path.name,
            size,
            "2026-01-01T00:00:00Z",
            "https://example.invalid/" + path.name,
        )
        return VerifiedAsset(source, path, sha, size, 2, "1" * 64)

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
        env_kind: str = "native",
        progress: Callable[[str], None] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        argv = tuple(argv)
        self.calls.append(argv)
        stdout = b""
        if argv[:2] == ("tar", "-tzf"):
            stdout = "".join(name + "\n" for name in _read(Path(argv[2]))).encode()
        elif argv[:2] == ("tar", "-xOzf"):
            stdout = _read(Path(argv[2]))[argv[3]]
        elif "-czf" in argv:
            content = Path(argv[argv.index("-C") + 1])
            names = argv[argv.index("-C") + 2 :]
            target = Path(argv[argv.index("-czf") + 1])
            target.write_bytes(gzip.compress(_tar({n: (content / n).read_bytes() for n in names})))
        elif "index" in argv and "--merge" in argv:
            seed = Path(argv[argv.index("--index") + 1])
            Path(argv[argv.index("--output") + 1]).write_bytes(seed.read_bytes())
        elif "index" in argv:
            package = Path(argv[-1])
            control = gzip.decompress(package.read_bytes())
            with tarfile.open(fileobj=io.BytesIO(control)) as archive:
                stream = archive.extractfile(".PKGINFO")
                assert stream is not None
                fields = dict(line.split(" = ", 1) for line in stream.read().decode().splitlines())
            stanza = (
                f"C:Q1{'A' * 27}=\nP:{fields['pkgname']}\nV:{fields['pkgver']}\n"
                f"A:{fields['arch']}\nS:{package.stat().st_size}\nI:5\nT:Inert\nL:MIT\n\n"
            )
            Path(argv[argv.index("--output") + 1]).write_bytes(
                gzip.compress(_tar({"APKINDEX": stanza.encode()}))
            )
        elif "version" in argv and "--test" in argv:
            left, right = argv[-2:]
            stdout = b"=" if left == right else (b">" if left > right else b"<")
        return subprocess.CompletedProcess(argv, 0, stdout, b"")


def _verify_synthetic(path: Path, key: Path, runtime: Runtime) -> dict[tuple[str, str, str], str]:
    return apk._records(_read(path)["APKINDEX"].decode())


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_inspect_version_without_release(tmp_path: Path, arch: str) -> None:
    runtime = NativeApk(tmp_path / "runtime")
    asset = runtime.asset("tailor", "0.6.0", arch)
    inspected = apk.inspect(asset, policy=APK_POLICY, runtime=runtime, out=tmp_path / "out")
    assert inspected.identity == NativeIdentity("apk", "tailor", arch, "0.6.0")
    assert apk._filename(inspected.identity) == f"{arch}/tailor-0.6.0.apk"
    assert inspected.upstream_signature == "unsigned"
    assert ("apk", "version", "--check", "0.6.0") in runtime.calls
    assert apk._fields(apk._string(inspected.metadata.get("stanza")))["V"] == "0.6.0"


@pytest.mark.parametrize("arch,architectures", [("aarch64", ("x86_64",)), ("x86_64", ("aarch64",))])
def test_inspect_rejects_unconfigured_architecture(
    tmp_path: Path, arch: str, architectures: tuple[str, ...]
) -> None:
    runtime = NativeApk(tmp_path / "runtime")
    asset = runtime.asset("tailor", "0.6.0", arch)
    with pytest.raises(
        apk.ApkFailure, match=f"^{asset.source.filename}: unsupported APK architecture '{arch}'$"
    ):
        apk.inspect(
            asset,
            policy=FormatPolicy("apk", architectures=architectures),
            runtime=runtime,
            out=tmp_path / "out",
        )


def test_mixed_architecture_publication(tmp_path: Path) -> None:
    runtime = NativeApk(tmp_path / "runtime")
    private, public = tmp_path / "synthetic-private", tmp_path / apk.PUBLIC_KEY
    private.write_bytes(b"inert private fixture")
    public.write_bytes(b"inert public fixture")
    signer = SigningSession(runtime, tmp_path / "gnupg", "A" * 40)
    history: list[AdmittedAsset] = []
    for arch in ("x86_64", "aarch64"):
        inspected = apk.inspect(
            runtime.asset("tailor", "0.6.0", arch),
            policy=APK_POLICY,
            runtime=runtime,
            out=tmp_path / "inspect",
        )
        history.append(
            admit(inspected, history, compare=apk.compare, policy=APK_POLICY, runtime=runtime)
        )
    with (
        patch.object(signer, "alpine_key", return_value=(private, public)),
        patch.object(apk, "_verify_index", side_effect=_verify_synthetic),
    ):
        prepared = apk.prepare(
            history,
            RetainedFormat("apk", None, (), (), {}, ()),
            policy=APK_POLICY,
            runtime=runtime,
            signer=signer,
            now=datetime(2026, 1, 1, tzinfo=UTC),
            out=tmp_path / "generation",
        )
        with pytest.raises(apk.ApkFailure, match="Invalid retained APK policy"):
            apk.validate_retained(
                prepared.retained,
                policy=FormatPolicy("apk", architectures=("x86_64",)),
                runtime=runtime,
            )
    assert [output.ref.key for output in prepared.outputs] == [
        "keys/" + apk.PUBLIC_KEY,
        "x86_64/tailor-0.6.0.apk",
        "aarch64/tailor-0.6.0.apk",
        "aarch64/APKINDEX.tar.gz",
        "x86_64/APKINDEX.tar.gz",
    ]
    for item in history:
        output = next(
            output
            for output in prepared.outputs
            if output.ref.key == apk._filename(item.inspected.identity)
        )
        assert output.local_path.read_bytes() == item.inspected.verified.local_path.read_bytes()
    indexes = prepared.retained.metadata["indexes"]
    assert isinstance(indexes, dict) and set(indexes) == {"x86_64", "aarch64"}
    for arch in ("x86_64", "aarch64"):
        records = _verify_synthetic(
            tmp_path / f"generation/{arch}/APKINDEX.tar.gz", public, runtime
        )
        assert list(records) == [("tailor", "0.6.0", arch)]
