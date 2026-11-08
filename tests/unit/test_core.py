import hashlib
import json
import os
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    NativeIdentity,
    ObjectRef,
    ObjectStat,
    OutputObject,
    Ownership,
    PreparedFormat,
    PreparedGeneration,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
    WriteReceipt,
    atomic_write,
    canonical_json,
    public_inventory,
    safe_key,
    safe_path,
    sha256_file,
    utc_now,
)

HASH = "a" * 64
NOW = "2026-01-01T00:00:00Z"


def source() -> SourceAsset:
    return SourceAsset(
        "owner/repo", 1, 2, "package.deb", 3, NOW, "https://example.invalid/package.deb"
    )


def admitted(path: Path) -> AdmittedAsset:
    verified = VerifiedAsset(source(), path, HASH, 3, 4, "b" * 64)
    inspected = InspectedAsset(
        verified,
        NativeIdentity("apt", "package", "amd64", "1"),
        {"description": "complete native data"},
        {},
        "unsigned",
    )
    return AdmittedAsset(inspected, "preserve", "apt:package:amd64:1")


def ref() -> ObjectRef:
    return ObjectRef(
        "apt",
        "pool/package.deb",
        "package",
        3,
        HASH,
        "application/octet-stream",
        "public, max-age=31536000, immutable",
    )


def test_records(tmp_path: Path) -> None:
    asset = admitted(tmp_path / "package.deb")
    output = OutputObject(ref(), tmp_path / "package.deb", "create", None, 0)
    retained = RetainedFormat("apt", None, (asset,), (asset.inspected.identity,), {}, (ref(),))
    prepared = PreparedFormat("apt", retained, (output,), (ref(),), NOW)
    generation = PreparedGeneration(
        "one", None, None, "owner", HASH, HASH, {}, (prepared,), {}, HASH
    )
    assert json.loads(canonical_json(generation.to_dict()))["schema_version"] == 1
    assert Ownership("nonce", '"opaque"', "runner", NOW).etag == '"opaque"'
    assert ObjectStat('"not-a-hash"', 3).size == 3
    assert WriteReceipt("opaque", HASH, 3).sha256 == HASH
    with pytest.raises(FrozenInstanceError):
        asset.history_key = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError):
        replace(prepared, outputs=(output, output))
    with pytest.raises(ValueError):
        replace(generation, previous_completion_id="previous")
    with pytest.raises(ValueError):
        replace(retained, format="rpm")


@pytest.mark.parametrize(
    "key",
    ["", "/root", ".", "..", "a/../b", "a//b", "a/./b", "a/", "a\\b", "a\n", "a\x00", "a\x7f"],
)
def test_unsafe_keys(key: str) -> None:
    with pytest.raises(ValueError):
        safe_key(key)


def test_symlinks_and_atomic_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    destination = tmp_path / "private"
    events: list[str] = []
    fsync, rename = os.fsync, os.replace

    def sync(fd: int) -> None:
        events.append("sync")
        fsync(fd)

    def move(src: str, dst: Path) -> None:
        events.append("replace")
        rename(src, dst)

    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "replace", move)
    atomic_write(destination, b"first")
    assert events == ["sync", "replace", "sync"]
    assert destination.stat().st_mode & 0o777 == 0o600
    atomic_write(destination, b"second")
    assert sha256_file(destination) == (hashlib.sha256(b"second").hexdigest(), 6)
    link = tmp_path / "link"
    link.symlink_to(destination)
    with pytest.raises(ValueError):
        atomic_write(link, b"overwrite")
    directory_link = tmp_path / "directory-link"
    directory_link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        safe_path(directory_link, "escape")
    with pytest.raises(ValueError):
        safe_path(tmp_path, "directory-link/escape")
    assert destination.read_bytes() == b"second"


def test_failed_atomic_write_preserves_previous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "private"
    atomic_write(destination, b"previous")

    def fail(_fd: int) -> None:
        raise OSError("injected fsync failure")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError):
        atomic_write(destination, b"proposed")
    assert destination.read_bytes() == b"previous"
    assert list(tmp_path.iterdir()) == [destination]


def test_streaming_hash(tmp_path: Path) -> None:
    value = b"x" * (2 * 1024 * 1024 + 1)
    path = tmp_path / "large"
    path.write_bytes(value)
    assert sha256_file(path) == (hashlib.sha256(value).hexdigest(), len(value))


def test_canonical_json_and_clock() -> None:
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    with pytest.raises(ValueError):
        canonical_json(float("nan"))
    with pytest.raises(ValueError):
        canonical_json({1: "bad key"})
    fixed = datetime(2026, 1, 1, tzinfo=UTC)
    assert utc_now(lambda: fixed) == fixed
    with pytest.raises(ValueError):
        utc_now(lambda: datetime(2026, 1, 1))


def test_private_fields_do_not_enter_inventory(tmp_path: Path) -> None:
    asset = admitted(tmp_path / "PRIVATE-PATH")
    inventory = canonical_json(public_inventory([asset], [ref()]))
    for forbidden in (b"PRIVATE-PATH", b"checksum", b"history_key", b"evidence", b"transformation"):
        assert forbidden not in inventory
    assert HASH.encode() in inventory
    private = ObjectRef("private", "journal", "private", 3, HASH, "application/json", "no-store")
    with pytest.raises(ValueError):
        public_inventory([asset], [private])


@pytest.mark.parametrize(
    "changes",
    [
        {"size": True},
        {"release_id": 0},
        {"asset_id": -1},
        {"filename": "../escape"},
        {"repository": "owner/.."},
        {"repository": "owner/repo/extra"},
        {"github_sha256": "A" * 64},
        {"updated_at": "2026-01-01"},
        {"public_url": "https://user:password@example.invalid/asset"},
    ],
)
def test_malformed_sources(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        replace(source(), **changes)


def test_invalid_records(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        VerifiedAsset(source(), tmp_path, HASH, 4, 4, HASH)
    with pytest.raises(ValueError):
        replace(ref(), bucket_role="private")
    with pytest.raises(ValueError):
        OutputObject(ref(), tmp_path, "replace", None, 0)
    with pytest.raises(ValueError):
        OutputObject(ref(), tmp_path, "create", "unexpected", 0)
    with pytest.raises(ValueError):
        NativeIdentity("apt", "name", "amd64", "1", epoch=True)


def test_bootstrap_records_are_explicit_immutable_public_pairs(tmp_path: Path) -> None:
    from tests.unit.test_state import generation

    owner = Ownership("nonce", "etag", "runner", NOW)
    original = generation(tmp_path / "input", owner, bootstrap=True)
    asc, binary = original.bootstrap_objects
    output = original.bootstrap_outputs[0]
    for changes in (
        {"bootstrap_objects": (asc,)},
        {"bootstrap_objects": (asc, asc)},
        {"bootstrap_objects": (replace(asc, key="keys/private.key"), binary)},
        {"bootstrap_objects": (replace(asc, bucket_role="rpm"), binary)},
        {"bootstrap_objects": (replace(asc, object_class="entry"), binary)},
        {"bootstrap_outputs": (replace(output, mode="replace", expected_etag="etag"),)},
        {"bootstrap_outputs": (output, output)},
        {"bootstrap_outputs": (replace(output, ordinal=3),)},
        {"signing_fingerprint": None},
        {"signing_fingerprint": "A" * 16},
    ):
        with pytest.raises(ValueError):
            replace(original, **changes)
    prepared = original.formats[0]
    with pytest.raises(ValueError, match="outside native"):
        replace(
            original,
            formats=(replace(prepared, referenced_objects=(*prepared.referenced_objects, asc)),),
        )
