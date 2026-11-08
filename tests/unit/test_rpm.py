from __future__ import annotations

import gzip
import hashlib
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from haberdasher.config import FormatPolicy
from haberdasher.core import NativeIdentity, RetainedFormat
from haberdasher.formats import rpm
from haberdasher.runtime import Runtime, private_workspace


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


def metadata(root: Path, *, missing: str = "", location: str | None = None) -> None:
    (root / "repodata").mkdir(exist_ok=True)
    entries: list[str] = []
    for kind, (namespace, name) in rpm.NAMESPACES.items():
        if kind == missing:
            continue
        opened = f'<{name} xmlns="{namespace[1:-1]}" packages="0"/>'.encode()
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
