"""Fail-closed Arch adapter checks without native client dependencies."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import base64
import io
import tarfile
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from haberdasher.admission import admit
from haberdasher.config import FormatPolicy
from haberdasher.core import (
    AdmittedAsset,
    NativeIdentity,
    RetainedFormat,
    SourceAsset,
    UnsupportedAsset,
    VerifiedAsset,
    sha256_file,
)
from haberdasher.formats import arch
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import SigningSession

NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize("reply,expected", [(b"-1\n", -1), (b"0\n", 0), (b"1\n", 1)])
def test_native_comparison(reply: bytes, expected: int, monkeypatch: pytest.MonkeyPatch) -> None:
    def run(self: Runtime, argv: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        if argv[0] != "gpgconf":
            assert tuple(argv) == ("vercmp", "1-1", "1-01")
        return CompletedProcess(argv, 0, reply, b"")

    monkeypatch.setattr(Runtime, "run", run)
    with private_workspace() as runtime:
        assert (
            arch.compare(
                NativeIdentity("arch", "demo", "x86_64", "1-1"),
                NativeIdentity("arch", "demo", "x86_64", "1-01"),
                runtime=runtime,
            )
            == expected
        )


@pytest.mark.parametrize("code,reply", [(1, b"0"), (0, b""), (0, b"2"), (0, b"0\n1")])
def test_failed_comparison(code: int, reply: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    def run(self: Runtime, argv: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        return CompletedProcess(argv, code, reply, b"")

    monkeypatch.setattr(Runtime, "run", run)
    identity = NativeIdentity("arch", "demo", "x86_64", "1-1")
    with private_workspace() as runtime, pytest.raises(arch.ArchFailure):
        arch.compare(identity, identity, runtime=runtime)


def test_distinct_slots_do_not_compare() -> None:
    with private_workspace() as runtime:
        assert (
            arch.compare(
                NativeIdentity("arch", "one", "x86_64", "1-1"),
                NativeIdentity("arch", "two", "x86_64", "1-1"),
                runtime=runtime,
            )
            is None
        )


@pytest.mark.parametrize("architectures", [("any",), ("x86_64", "any"), ("aarch64", "armv7h")])
def test_unqualified_placement(architectures: tuple[str, ...]) -> None:
    with private_workspace() as runtime, pytest.raises(arch.ArchFailure, match="qualified"):
        arch.validate_retained(
            RetainedFormat("arch", (), (), {}, ()),
            policy=FormatPolicy("arch", architectures),
            runtime=runtime,
        )


@pytest.mark.parametrize("architectures", [("x86_64",), ("aarch64",), ("x86_64", "aarch64")])
def test_qualified_placement(architectures: tuple[str, ...]) -> None:
    with private_workspace() as runtime:
        arch.validate_retained(
            RetainedFormat("arch", (), (), {}, ()),
            policy=FormatPolicy("arch", architectures),
            runtime=runtime,
        )


def test_incomplete_retained() -> None:
    state = RetainedFormat("arch", (), (), {"paths": {}}, ())
    with private_workspace() as runtime, pytest.raises(arch.ArchFailure, match="Incomplete"):
        arch.validate_retained(state, policy=FormatPolicy("arch"), runtime=runtime)


def test_empty_retained() -> None:
    with private_workspace() as runtime:
        arch.validate_retained(
            RetainedFormat("arch", (), (), {}, ()),
            policy=FormatPolicy("arch"),
            runtime=runtime,
        )


FINGERPRINT = "A" * 40
ARCH_POLICY = FormatPolicy("arch", ("x86_64", "aarch64"))
PACKAGES = {
    f"tailor_{version}_linux_{label}.pkg.tar.zst": ("tailor", f"{version}-1", architecture)
    for version in ("0.6.0", "0.6.1")
    for label, architecture in (("amd64", "x86_64"), ("arm64", "aarch64"))
}


class NativeArch:
    """Emulate pacman, repo-add, vercmp, and gpgv record forms without native tools."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[tuple[str, ...]] = []
        self.identities: dict[str, tuple[str, str, str]] = {}

    def asset(self, filename: str) -> VerifiedAsset:
        path = self.root / filename
        path.write_bytes(f"inert {filename}".encode())
        digest, size = sha256_file(path)
        self.identities[digest] = PACKAGES[filename]
        source = SourceAsset(
            "wimpysworld/tailor",
            1,
            1,
            filename,
            size,
            "2026-01-01T00:00:00Z",
            "https://example.invalid/" + filename,
        )
        return VerifiedAsset(source, path, digest, size, 2, "1" * 64)

    def _desc(self, package: Path, signed: bool) -> tuple[str, str]:
        digest = sha256_file(package)[0]
        name, version, architecture = self.identities[digest]
        desc = (
            f"%FILENAME%\n{package.name}\n\n%NAME%\n{name}\n\n%VERSION%\n{version}\n\n"
            f"%ARCH%\n{architecture}\n\n%SHA256SUM%\n{digest}\n\n"
        )
        if signed:
            signature = package.with_name(package.name + ".sig").read_bytes()
            desc += f"%PGPSIG%\n{base64.b64encode(signature).decode()}\n\n"
        return f"{name}-{version}", desc

    def _repo_add(self, argv: Sequence[str]) -> None:
        index = next(i for i, value in enumerate(argv) if value.endswith(".db.tar.gz"))
        database = Path(argv[index])
        records: dict[str, str] = {}
        if database.exists():
            with tarfile.open(database) as archive:
                for member in archive.getmembers():
                    stream = archive.extractfile(member)
                    if stream is not None:
                        records[member.name.split("/")[0]] = stream.read().decode()
        for package in argv[index + 1 :]:
            directory, desc = self._desc(Path(package), "--include-sigs" in argv)
            name = desc.split("%NAME%\n")[1].split("\n")[0]
            records = {
                key: value
                for key, value in records.items()
                if value.split("%NAME%\n")[1].split("\n")[0] != name
            }
            records[directory] = desc
        for kind in ("db", "files"):
            target = database.with_name(f"haberdasher.{kind}.tar.gz")
            with tarfile.open(target, "w:gz") as archive:
                for directory, desc in records.items():
                    members = [("desc", desc)]
                    if kind == "files":
                        members.append(("files", "%FILES%\nusr/\n\n"))
                    for member, text in members:
                        data = text.encode()
                        info = tarfile.TarInfo(f"{directory}/{member}")
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
            if "--sign" in argv:
                target.with_name(target.name + ".sig").write_bytes(b"signature")

    def run(self, argv: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        argv = tuple(argv)
        self.calls.append(argv)
        stdout = b""
        if "repo-add" in argv:
            self._repo_add(argv)
        elif argv[0] == "pacman":
            name, version, architecture = self.identities[sha256_file(Path(argv[-1]))[0]]
            if argv[-2] == "-Qp":
                stdout = f"{name} {version}\n".encode()
            else:
                stdout = f"Name            : {name}\nArchitecture    : {architecture}\n".encode()
        elif argv[0] == "vercmp":
            stdout = str((argv[1] > argv[2]) - (argv[1] < argv[2])).encode()
        elif argv[0] == "gpgv":
            stdout = (
                f"[GNUPG:] VALIDSIG {FINGERPRINT} 2026-01-01 0 0 4 0 1 8 00 {FINGERPRINT}\n"
            ).encode()
        elif argv[0] == "gpg":
            stdout = b"public key"
        return CompletedProcess(argv, 0, stdout, b"")


def native_arch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[NativeArch, Runtime]:
    native = NativeArch(tmp_path)
    runtime = Runtime(tmp_path / "runtime", environ={"PATH": ""})
    monkeypatch.setattr(runtime, "run", native.run)
    return native, runtime


def inspected(native: NativeArch, runtime: Runtime, filename: str) -> AdmittedAsset:
    result = arch.inspect(
        native.asset(filename),
        policy=ARCH_POLICY,
        runtime=runtime,
        out=native.root / filename[:-12],
    )
    return admit(result, [], compare=arch.compare, policy=ARCH_POLICY, runtime=runtime)


def test_inspect_aarch64_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    native, runtime = native_arch(tmp_path, monkeypatch)
    item = inspected(native, runtime, "tailor_0.6.0_linux_arm64.pkg.tar.zst")
    identity = item.inspected.identity
    assert identity == NativeIdentity("arch", "tailor", "aarch64", "0.6.0-1")
    assert arch._keys(item.inspected, ARCH_POLICY) == (
        "aarch64/tailor-0.6.0-1-aarch64.pkg.tar.zst",
    )
    assert item.inspected.upstream_signature == "unsigned"
    assert "%PGPSIG%" not in arch._string(item.inspected.metadata.get("desc"))
    other = replace(identity, architecture="x86_64")
    assert arch.compare(identity, other, runtime=runtime) is None


@pytest.mark.parametrize(
    "filename,architectures",
    [
        ("tailor_0.6.0_linux_arm64.pkg.tar.zst", ("x86_64",)),
        ("tailor_0.6.0_linux_amd64.pkg.tar.zst", ("aarch64",)),
    ],
)
def test_inspect_rejects_unconfigured_architecture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    architectures: tuple[str, ...],
) -> None:
    native, runtime = native_arch(tmp_path, monkeypatch)
    unsupported = "aarch64" if "arm64" in filename else "x86_64"
    with pytest.raises(
        UnsupportedAsset, match=f"^{filename}: unsupported Arch architecture '{unsupported}'$"
    ):
        arch.inspect(
            native.asset(filename),
            policy=FormatPolicy("arch", architectures),
            runtime=runtime,
            out=tmp_path / "out",
        )
    assert not any("repo-add" in call for call in native.calls)


def test_mixed_architecture_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    native, runtime = native_arch(tmp_path, monkeypatch)
    signer = SigningSession(runtime, tmp_path / "gnupg", FINGERPRINT)

    def sign(source: Path, output: Path, *, armour: bool = True) -> None:
        output.write_bytes(b"signature of " + source.name.encode())

    monkeypatch.setattr(signer, "sign_file", sign)
    items = [
        inspected(native, runtime, f"tailor_0.6.0_linux_{label}.pkg.tar.zst")
        for label in ("amd64", "arm64")
    ]
    empty = RetainedFormat("arch", (), (), {}, ())
    first = arch.prepare(
        items,
        empty,
        policy=ARCH_POLICY,
        runtime=runtime,
        signer=signer,
        now=NOW,
        out=tmp_path / "generation1",
    )
    packages = [
        "x86_64/tailor-0.6.0-1-x86_64.pkg.tar.zst",
        "aarch64/tailor-0.6.0-1-aarch64.pkg.tar.zst",
    ]
    assert [output.ref.key for output in first.outputs] == [
        key for package in packages for key in (package, package + ".sig")
    ] + [*arch.entries("aarch64"), *arch.entries("x86_64")]
    for item, package in zip(items, packages, strict=True):
        output = next(output for output in first.outputs if output.ref.key == package)
        assert output.local_path.read_bytes() == item.inspected.verified.local_path.read_bytes()
    assert set(arch._mapping(first.retained.metadata.get("records"))) == {"aarch64", "x86_64"}
    assert {identity.architecture for identity in first.retained.active_identities} == {
        "aarch64",
        "x86_64",
    }
    with pytest.raises(arch.ArchFailure, match="not qualified by policy"):
        arch.validate_retained(
            first.retained, policy=FormatPolicy("arch", ("x86_64",)), runtime=runtime
        )
    state = replace(
        first.retained,
        metadata={
            **first.retained.metadata,
            "etags": {output.ref.key: "opaque" for output in first.outputs},
        },
    )
    update = inspected(native, runtime, "tailor_0.6.1_linux_arm64.pkg.tar.zst")
    second = arch.prepare(
        [update],
        state,
        policy=ARCH_POLICY,
        runtime=runtime,
        signer=signer,
        now=NOW,
        out=tmp_path / "generation2",
    )
    assert [output.ref.key for output in second.outputs] == [
        "aarch64/tailor-0.6.1-1-aarch64.pkg.tar.zst",
        "aarch64/tailor-0.6.1-1-aarch64.pkg.tar.zst.sig",
        *arch.entries("aarch64"),
    ]
    assert not (tmp_path / "generation2/x86_64").exists()
    for field in ("paths", "records"):
        before = arch._mapping(first.retained.metadata.get(field))
        after = arch._mapping(second.retained.metadata.get(field))
        for key in (*arch.entries("x86_64"), "x86_64"):
            assert after.get(key) == before.get(key)
    assert sorted(
        (identity.architecture, identity.version) for identity in second.retained.active_identities
    ) == [("aarch64", "0.6.1-1"), ("x86_64", "0.6.0-1")]
    assert {ref.key for ref in second.referenced_objects} >= set(packages)
    arch.validate_prepared(second, policy=ARCH_POLICY, runtime=runtime)
