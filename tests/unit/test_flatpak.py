"""Fail-closed Flatpak policy, metadata and immutable-object rules."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import importlib.util
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from haberdasher.admission import AdmissionFailure
from haberdasher.config import Config, FormatPolicy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    JSONValue,
    NativeIdentity,
    ObjectRef,
    OutputObject,
    PreparedFormat,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
    json_value,
    sha256_file,
)
from haberdasher.formats import flatpak
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession

REF = "app/world.example.Test/x86_64/stable"
RREF = "runtime/world.example.Runtime/x86_64/stable"
POLICY = Config(("example/test",)).format_policy("flatpak")


@pytest.mark.parametrize("size", [1024 * 1024, 1024 * 1024 + 1])
def test_native_summary_signature_bounded_read(monkeypatch: pytest.MonkeyPatch, size: int) -> None:
    glib = MagicMock()
    variant = glib.Variant.new_from_bytes.return_value
    variant.is_normal_form.return_value = True
    variant.lookup_value.return_value = None
    for name in ("gi", "Flatpak", "Gio", "GLib", "OSTree"):
        module_name = name if name == "gi" else f"gi.repository.{name}"
        monkeypatch.setitem(sys.modules, module_name, glib if name == "GLib" else MagicMock())
    spec = importlib.util.spec_from_file_location(
        "flatpak_native_test", Path(flatpak.__file__).with_name("flatpak_native.py")
    )
    assert spec is not None and spec.loader is not None
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)

    def read(limit: int = -1) -> bytes:
        assert limit == 1024 * 1024 + 1
        return b"x" * min(size, limit)

    stream = MagicMock()
    stream.__enter__.return_value = stream
    stream.read.side_effect = read
    open_stream = MagicMock(return_value=stream)
    monkeypatch.setattr(Path, "open", open_stream)
    if size > 1024 * 1024:
        with pytest.raises(ValueError, match="Signature metadata exceeds 1 MiB"):
            native.inspect_native({"summary_signature": "summary.sig"})
        glib.Bytes.new.assert_not_called()
        glib.Variant.new_from_bytes.assert_not_called()
    else:
        assert native.inspect_native({"summary_signature": "summary.sig"}) == {"signatures": []}
        glib.Bytes.new.assert_called_once_with(b"x" * size)
        glib.Variant.new_from_bytes.assert_called_once()
    open_stream.assert_called_once_with("rb")
    stream.read.assert_called_once_with(1024 * 1024 + 1)
    stream.__exit__.assert_called_once()


@pytest.fixture
def runtime(tmp_path: Path) -> Runtime:
    return Runtime(tmp_path)


@pytest.mark.parametrize(
    ("output", "expected"), [(b"1 << 2\n", -1), (b"1 == 2\n", 0), (b"1 >> 2\n", 1)]
)
def test_compare_native(
    runtime: Runtime, monkeypatch: pytest.MonkeyPatch, output: bytes, expected: int
) -> None:
    calls: list[object] = []

    def run(argv: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess([], 0, output, b"")

    monkeypatch.setattr(runtime, "run", run)
    left = NativeIdentity("flatpak", REF, "x86_64", "1")
    right = replace(left, version="2")
    assert flatpak.compare(left, right, runtime=runtime) == expected
    assert calls == [("appstreamcli", "vercmp", "1", "2")]
    assert (
        flatpak.compare(left, replace(right, name=REF.replace("stable", "beta")), runtime=runtime)
        is None
    )
    assert len(calls) == 1


@pytest.mark.parametrize(("code", "output"), [(1, b"1 << 2\n"), (0, b"unknown")])
def test_compare_failure(
    runtime: Runtime, monkeypatch: pytest.MonkeyPatch, code: int, output: bytes
) -> None:
    def run(argv: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], code, output, b"failed")

    monkeypatch.setattr(runtime, "run", run)
    left = NativeIdentity("flatpak", REF, "x86_64", "1")
    with pytest.raises(flatpak.FlatpakFailure):
        flatpak.compare(left, replace(left, version="2"), runtime=runtime)


@pytest.mark.parametrize("version", ["--help", "1 2", "1;2", "x" * 129])
def test_compare_rejects_unqualified_version(runtime: Runtime, version: str) -> None:
    left = NativeIdentity("flatpak", REF, "x86_64", version)
    with pytest.raises(flatpak.FlatpakFailure, match="version"):
        flatpak.compare(left, left, runtime=runtime)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("extra_data", True),
        ("commit", {"ostree.ref-binding": [REF], "ostree.collection-binding": "unexpected"}),
        (
            "keyfile",
            {"Application": {"name": "world.example.Test", "runtime": "unknown/x86_64/stable"}},
        ),
    ],
)
def test_rejects_unsupported_metadata(field: str, value: JSONValue) -> None:
    data: dict[str, JSONValue] = {
        "commit": {"ostree.ref-binding": [REF], "ostree.collection-binding": ""},
        "keyfile": {
            "Application": {"name": "world.example.Test", "runtime": RREF.removeprefix("runtime/")}
        },
        "extra_data": False,
    }
    assert flatpak._check_metadata(data, REF) == RREF
    data[field] = value
    with pytest.raises(flatpak.FlatpakFailure):
        flatpak._check_metadata(data, REF)


@pytest.mark.parametrize(
    "group", ["Extra Data", "Extension world.example.Extension", "ExtensionOf", "Runtime"]
)
def test_rejects_extra_data_and_extensions(group: str) -> None:
    data: dict[str, JSONValue] = {
        "commit": {"ostree.ref-binding": [REF], "ostree.collection-binding": ""},
        "keyfile": {
            "Application": {"name": "world.example.Test", "runtime": RREF.removeprefix("runtime/")},
            group: {},
        },
        "extra_data": False,
    }
    with pytest.raises(flatpak.FlatpakFailure):
        flatpak._check_metadata(data, REF)


@pytest.mark.parametrize(
    ("suffix", "mutable"),
    [
        ("commit", False),
        ("dirtree", False),
        ("dirmeta", False),
        ("filez", False),
        ("commitmeta", True),
    ],
)
def test_native_object_mutability(suffix: str, mutable: bool) -> None:
    assert flatpak._classify(f"objects/aa/{'b' * 62}.{suffix}") == ("dependency", mutable, 0)


def test_summary_dependencies_are_immutable() -> None:
    for key in (
        f"summaries/{'a' * 64}.gz",
        f"summaries/{'a' * 64}.idx.sig",
        f"summaries/{'a' * 64}-{'b' * 64}.delta",
    ):
        assert flatpak._classify(key) == ("dependency", False, 1)
    for key in (
        "summary",
        "summary.sig",
        "summary.idx",
        "summary.idx.sig",
        "config",
        "refs/heads/" + REF,
        flatpak.FLATPAKREPO,
        "world.example.Test.flatpakref",
    ):
        assert flatpak._classify(key)[1] is True
    assert flatpak._classify("world.example.Test.flatpakref") == ("entry", True, 9)
    for key in ("unexpected-secret", "Test.flatpakref", "keys/world.example.Test.flatpakref"):
        with pytest.raises(flatpak.FlatpakFailure):
            flatpak._classify(key)


def test_empty_state_is_not_missing_state(runtime: Runtime) -> None:
    empty = RetainedFormat("flatpak", (), (), {}, ())
    flatpak.validate_retained(empty, policy=POLICY, runtime=runtime)
    with pytest.raises(flatpak.FlatpakFailure, match="Incomplete"):
        flatpak.validate_retained(
            replace(empty, metadata={"heads": {}}), policy=POLICY, runtime=runtime
        )


@pytest.mark.parametrize(
    "xml",
    [
        b"<components/>",
        b"<!DOCTYPE x [<!ENTITY a 'b'>]><components/>",
        b"x" * (flatpak.MAX_METADATA + 1),
    ],
)
def test_missing_or_unsafe_appstream(runtime: Runtime, tmp_path: Path, xml: bytes) -> None:
    path = tmp_path / "appstream.xml"
    path.write_bytes(xml)
    with pytest.raises(flatpak.FlatpakFailure):
        flatpak._version(path, REF, runtime)


@pytest.fixture
def relocated(runtime: Runtime, monkeypatch: pytest.MonkeyPatch) -> PreparedFormat:
    source = SourceAsset(
        "example/test",
        1,
        1,
        "test.flatpak",
        0,
        "2026-01-01T00:00:00Z",
        "https://example.invalid/test",
    )
    verified = VerifiedAsset(source, runtime.root / "unavailable", "a" * 64, 0, 2, "b" * 64)
    identity = NativeIdentity("flatpak", REF, "x86_64", "1", source_commit="c" * 64)
    admitted = AdmittedAsset(
        InspectedAsset(verified, identity, {}, {}, "unsigned"), "synthetic", "synthetic"
    )
    files: dict[str, JSONValue] = {}
    outputs: list[OutputObject] = []
    for ordinal, key in enumerate(("config", "summary", "world.example.Test.flatpakref")):
        native = runtime.root / "flatpak/native" / key
        output = runtime.root / "flatpak/outputs" / str(ordinal)
        for path in (native, output):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(key.encode())
        sha, size = sha256_file(native)
        ref = ObjectRef("flatpak", key, "entry", size, sha, "application/octet-stream", "no-cache")
        files[key] = str(native)
        outputs.append(OutputObject(ref, output, "create", None, ordinal))
    objects = tuple(output.ref for output in outputs)
    retained = RetainedFormat(
        "flatpak",
        (admitted,),
        (identity,),
        {"files": files},
        objects,
    )

    def run(argv: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, b"1 == 1\n", b"")

    def validate_repo(
        retained: RetainedFormat, policy: FormatPolicy, runtime: Runtime, repo: Path
    ) -> None:
        assert policy == POLICY
        assert repo.is_relative_to(runtime.root)
        for ref in retained.objects:
            assert sha256_file(repo / ref.key) == (ref.sha256, ref.size)

    monkeypatch.setattr(runtime, "run", run)
    monkeypatch.setattr(flatpak, "_validate_repo", validate_repo)
    return PreparedFormat("flatpak", retained, tuple(outputs), objects)


def test_prepared_accepts_verified_relocated_copies(
    relocated: PreparedFormat, runtime: Runtime
) -> None:
    files = flatpak._mapping(relocated.retained.metadata["files"])
    assert all(files[output.ref.key] != str(output.local_path) for output in relocated.outputs)
    flatpak.validate_prepared(relocated, policy=POLICY, runtime=runtime)


@pytest.mark.parametrize(
    "change",
    [
        "native-bytes",
        "output-bytes",
        "native-size",
        "output-size",
        "key",
        "ref",
        "size",
        "order",
        "ordinal",
        "closure",
        "missing-map",
        "missing-key",
        "native-symlink",
        "output-symlink",
        "native-trust",
    ],
)
def test_prepared_relocated_copies_fail_closed(
    relocated: PreparedFormat, runtime: Runtime, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    prepared = relocated
    output = prepared.outputs[0]
    files = flatpak._mapping(prepared.retained.metadata["files"])
    if change in {"native-bytes", "output-bytes", "native-size", "output-size"}:
        path = (
            Path(flatpak._string(files[output.ref.key]))
            if change.startswith("native")
            else output.local_path
        )
        path.write_bytes(b"x" * output.ref.size if change.endswith("bytes") else b"short")
    elif change in {"native-symlink", "output-symlink"}:
        link = runtime.root / "link"
        if change == "native-symlink":
            link.symlink_to(flatpak._string(files[output.ref.key]))
            files[output.ref.key] = str(link)
        else:
            link.symlink_to(output.local_path)
            prepared = replace(
                prepared, outputs=(replace(output, local_path=link), *prepared.outputs[1:])
            )
    elif change in {"key", "ref", "size"}:
        ref = (
            replace(output.ref, key="summary.sig")
            if change == "key"
            else replace(output.ref, content_type="text/plain")
            if change == "ref"
            else replace(output.ref, size=output.ref.size + 1)
        )
        prepared = replace(prepared, outputs=(replace(output, ref=ref), *prepared.outputs[1:]))
    elif change == "order":
        prepared = replace(
            prepared,
            outputs=tuple(
                replace(item, ordinal=index)
                for index, item in enumerate(reversed(prepared.outputs))
            ),
        )
    elif change == "ordinal":
        prepared = replace(
            prepared,
            outputs=tuple(replace(item, ordinal=item.ordinal + 1) for item in prepared.outputs),
        )
    elif change == "closure":
        prepared = replace(prepared, referenced_objects=prepared.referenced_objects[1:])
    elif change == "missing-map":
        prepared.retained.metadata.pop("files")
    elif change == "missing-key":
        files.pop(output.ref.key)
    else:

        def reject_native(
            retained: RetainedFormat, policy: FormatPolicy, runtime: Runtime, repo: Path
        ) -> None:
            raise flatpak.FlatpakFailure("Native trust failed")

        monkeypatch.setattr(flatpak, "_validate_repo", reject_native)
    with pytest.raises(ValueError):
        flatpak.validate_prepared(prepared, policy=POLICY, runtime=runtime)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("evidence", "Admission evidence changed"),
        ("transformation", "Admission record differs"),
        ("history-key", "Admission record differs"),
        ("bytes", "Changed bytes"),
        ("commit", "Conflicting commits"),
        ("backwards", "head cannot move backwards"),
        ("missing-source", "Hash input must be a regular file"),
    ],
)
def test_prepare_does_not_reuse_altered_records(
    relocated: PreparedFormat,
    runtime: Runtime,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    message: str,
) -> None:
    retained = replace(
        relocated.retained, metadata={**relocated.retained.metadata, "fingerprint": "A" * 40}
    )
    accepted = retained.accepted_history[0]
    inspected = accepted.inspected
    candidate = accepted
    if change == "transformation":
        candidate = replace(accepted, transformation_policy="preserve")
    elif change == "history-key":
        candidate = replace(accepted, history_key="altered")
    elif change == "bytes":
        inspected = replace(inspected, verified=replace(inspected.verified, sha256="d" * 64))
    elif change == "commit":
        inspected = replace(inspected, identity=replace(inspected.identity, source_commit="d" * 64))
    elif change == "backwards":
        inspected = replace(inspected, identity=replace(inspected.identity, version="0"))

        def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int:
            return (left.version > right.version) - (left.version < right.version)

        monkeypatch.setattr(flatpak, "compare", compare)
    if change in {"bytes", "commit", "backwards"}:
        candidate = replace(accepted, inspected=inspected)
    elif change in {"evidence", "missing-source"}:
        candidate = replace(accepted, inspected=replace(inspected, evidence={"altered": True}))
    if change != "missing-source":

        def inspect(*args: object, **kwargs: object) -> InspectedAsset:
            return inspected

        monkeypatch.setattr(flatpak, "inspect", inspect)
    before = json_value(retained)
    with pytest.raises((flatpak.FlatpakFailure, AdmissionFailure, ValueError), match=message):
        flatpak.prepare(
            (candidate,),
            retained,
            policy=POLICY,
            runtime=runtime,
            signer=SigningSession(runtime, runtime.root / "gnupg", "A" * 40),
            now=datetime.now(UTC),
            out=runtime.root / "prepare",
        )
    assert json_value(retained) == before


def test_prepare_validates_retained_before_history_reuse(
    relocated: PreparedFormat, runtime: Runtime
) -> None:
    files = flatpak._mapping(relocated.retained.metadata["files"])
    Path(flatpak._string(files["config"])).write_bytes(b"corrupt")
    with pytest.raises(flatpak.FlatpakFailure, match="corrupt"):
        flatpak.prepare(
            relocated.retained.accepted_history,
            relocated.retained,
            policy=POLICY,
            runtime=runtime,
            signer=SigningSession(runtime, runtime.root / "gnupg", "A" * 40),
            now=datetime.now(UTC),
            out=runtime.root / "prepare",
        )
    assert not (runtime.root / "prepare").exists()


@pytest.mark.parametrize(
    "runtime",
    [
        "invalid/x86_64/stable",
        RREF.removeprefix("runtime/").replace("x86_64", "aarch64"),
        "world.example.Runtime/x86_64",
    ],
)
def test_runtime_must_match_the_application_architecture(runtime: str) -> None:
    data: dict[str, JSONValue] = {
        "commit": {"ostree.ref-binding": [REF], "ostree.collection-binding": ""},
        "keyfile": {"Application": {"name": "world.example.Test", "runtime": runtime}},
        "extra_data": False,
    }
    with pytest.raises(flatpak.FlatpakFailure, match="runtime"):
        flatpak._check_metadata(data, REF)


@pytest.mark.parametrize(
    ("extension", "accepted"),
    [
        ({"directory": "lib/debug", "autodelete": "true", "no-autodownload": "true"}, True),
        ({"directory": "extensions/test", "version": "stable", "download-if": "x"}, True),
        ({"directory": "../outside"}, False),
        ({}, False),
    ],
)
def test_application_extensions_need_only_a_safe_directory(
    extension: dict[str, JSONValue], accepted: bool
) -> None:
    data: dict[str, JSONValue] = {
        "commit": {"ostree.ref-binding": [REF], "ostree.collection-binding": ""},
        "keyfile": {
            "Application": {"name": "world.example.Test", "runtime": RREF.removeprefix("runtime/")},
            "Extension world.example.Test.Debug": extension,
        },
        "extra_data": False,
    }
    if accepted:
        assert flatpak._check_metadata(data, REF) == RREF
    else:
        with pytest.raises(ValueError):
            flatpak._check_metadata(data, REF)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, flatpak.FLATHUB),
        (
            "https://repo.example.invalid/x.flatpakrepo",
            "https://repo.example.invalid/x.flatpakrepo",
        ),
        ("http://127.0.0.1:8000/x.flatpakrepo", "http://127.0.0.1:8000/x.flatpakrepo"),
        ("http://repo.example.invalid/x.flatpakrepo", None),
        ("https://user:secret@repo.example.invalid/x", None),
        ("file:///etc/passwd", None),
        ("https://repo.example.invalid/x\nGPGKey=AAAA", None),
        ("https://repo.example.invalid/x\r", None),
        ("https://repo.example.invalid/x\tx", None),
        ("https://repo.example.invalid/x\x7f", None),
        (" https://repo.example.invalid/x", None),
        ("", None),
    ],
)
def test_runtime_repository_defaults_to_flathub(value: str | None, expected: str | None) -> None:
    if expected is None:
        with pytest.raises(flatpak.FlatpakFailure):
            flatpak._runtime_repo(value)
    else:
        assert flatpak._runtime_repo(value) == expected


def test_one_runtime_repository_for_the_published_remote(tmp_path: Path) -> None:
    def admitted(number: int, runtime_repo: str) -> AdmittedAsset:
        source = SourceAsset(
            "example/test",
            number,
            number,
            f"{number}.flatpak",
            0,
            "2026-01-01T00:00:00Z",
            "https://example.invalid/test",
        )
        verified = VerifiedAsset(source, tmp_path / "unavailable", "a" * 64, 0, 2, "b" * 64)
        identity = NativeIdentity("flatpak", REF, "x86_64", str(number), source_commit="c" * 64)
        return AdmittedAsset(
            InspectedAsset(verified, identity, {}, {"runtime_repo": runtime_repo}, "unsigned"),
            "flatpak-sign",
            str(number),
        )

    one = (admitted(1, flatpak.FLATHUB), admitted(2, flatpak.FLATHUB))
    assert flatpak._runtime_repos(one) == flatpak.FLATHUB
    text = flatpak._flatpakrepo(b"key", flatpak.FLATHUB).decode()
    assert text == (
        "[Flatpak Repo]\nTitle=Wimpy's World\nUrl=https://flatpak.wimpys.world/\n"
        f"GPGKey=a2V5\nRuntimeRepo={flatpak.FLATHUB}\n"
    )
    with pytest.raises(flatpak.FlatpakFailure, match="different runtime repositories"):
        flatpak._runtime_repos((*one, admitted(3, "https://other.invalid/r.flatpakrepo")))


def test_flatpakref_installs_one_application_with_its_runtime_source(
    runtime: Runtime, tmp_path: Path
) -> None:
    text = flatpak._flatpakref(
        "world.example.Test", "stable", "Test App", b"key", flatpak.FLATHUB
    ).decode()
    assert text == (
        "[Flatpak Ref]\nName=world.example.Test\nBranch=stable\nTitle=Test App\n"
        "Url=https://flatpak.wimpys.world/\nGPGKey=a2V5\nIsRuntime=false\n"
        f"RuntimeRepo={flatpak.FLATHUB}\nSuggestRemoteName=wimpysworld\n"
    )
    path = tmp_path / "appstream.xml"
    path.write_text(
        '<component><id>world.example.Test</id><name xml:lang="de">Prüfung</name>'
        "<name>\n  Test\n  App </name></component>"
    )
    assert flatpak._title(path, REF) == "Test App"
    path.write_text("<component><id>world.example.Test</id></component>")
    assert flatpak._title(path, REF) == "world.example.Test"
