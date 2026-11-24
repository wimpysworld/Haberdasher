import hashlib
import json
import os
import struct
import zlib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from haberdasher.core import (
    MAX_PROJECT_PNG_BYTES,
    MAX_PROJECT_SVG_BYTES,
    TAILOR_PLACEHOLDER_SVG,
    AdmittedAsset,
    InspectedAsset,
    NativeIdentity,
    ObjectRef,
    ObjectStat,
    OutputObject,
    PreparedFormat,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
    WriteReceipt,
    atomic_write,
    canonical_json,
    homepage_url,
    icon_key,
    public_inventory,
    repository_description,
    safe_key,
    safe_path,
    sha256_file,
    size_text,
    utc_now,
    validate_descriptions,
    validate_homepages,
    validate_icons,
    validate_project_png,
    validate_project_svg,
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
    retained = RetainedFormat("apt", (asset,), (asset.inspected.identity,), {}, (ref(),))
    prepared = PreparedFormat("apt", retained, (output,), (ref(),))
    assert json.loads(canonical_json(prepared.to_dict()))["schema_version"] == 1
    assert ObjectStat('"not-a-hash"', 3).size == 3
    assert WriteReceipt("opaque", HASH, 3).sha256 == HASH
    with pytest.raises(FrozenInstanceError):
        asset.history_key = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError):
        replace(prepared, outputs=(output, output))
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


def test_inventory_allow_list_excludes_local_and_control_fields(tmp_path: Path) -> None:
    asset = admitted(tmp_path / "PRIVATE-PATH")
    inventory = canonical_json(public_inventory([asset], [ref()]))
    for forbidden in (b"PRIVATE-PATH", b"checksum", b"history_key", b"evidence", b"transformation"):
        assert forbidden not in inventory
    assert HASH.encode() in inventory
    lock = ObjectRef("apt", "haberdasher.lock", "lock", 3, HASH, "application/json", "no-store")
    with pytest.raises(ValueError):
        public_inventory([asset], [lock])


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
        replace(ref(), object_class="private")
    with pytest.raises(ValueError):
        OutputObject(ref(), tmp_path, "replace", None, 0)
    with pytest.raises(ValueError):
        OutputObject(ref(), tmp_path, "create", "unexpected", 0)
    with pytest.raises(ValueError):
        NativeIdentity("apt", "name", "amd64", "1", epoch=True)


def test_homepage_validation_and_public_inventory_allow_list(tmp_path: Path) -> None:
    assert (
        homepage_url("  HTTPS://tool.example/docs/ ", "owner/repo") == "https://tool.example/docs/"
    )
    assert homepage_url("https://github.com/OWNER/REPO/", "owner/repo") is None
    assert homepage_url("https://user:pass@tool.example/", "owner/repo") is None
    assert homepage_url("https://tool.example:bad/", "owner/repo") is None
    assert homepage_url("https://tool.example/a b", "owner/repo") is None
    assert validate_homepages({"owner/repo": "https://tool.example/"}) == {
        "owner/repo": "https://tool.example/"
    }
    for bad in (
        ["not-a-mapping"],
        {"bad repo": "https://tool.example/"},
        {"owner/repo": "javascript:alert(1)"},
        {"owner/repo": "https://github.com/owner/repo"},
        {"owner/repo": " https://tool.example/ "},
    ):
        with pytest.raises(ValueError):
            validate_homepages(bad)
    asset = admitted(tmp_path / "pkg.deb")
    without = public_inventory([asset], [ref()])
    assert "homepages" not in without
    with_home = public_inventory([asset], [ref()], {"owner/repo": "https://tool.example/"})
    assert with_home["homepages"] == {"owner/repo": "https://tool.example/"}
    with pytest.raises(ValueError):
        public_inventory([asset], [ref()], {"owner/repo": "ftp://tool.example/"})


def test_description_validation_and_public_inventory_allow_list(tmp_path: Path) -> None:
    zwj = "Build tools \U0001f9d1\u200d\U0001f4bb"
    assert repository_description(f"  {zwj}  ") == zwj
    for ignored in (None, "", "   ", 42, "line1\nline2", "bad\x00text", "bad\x7ftext", "a\u202eb"):
        assert repository_description(ignored) is None
    assert validate_descriptions({"z/repo": "Second", "a/repo": zwj}) == {
        "a/repo": zwj,
        "z/repo": "Second",
    }
    for bad in (
        ["not-a-mapping"],
        {"bad repo": "Valid text"},
        {"owner/repo": 123},
        {"owner/repo": ""},
        {"owner/repo": " padded "},
        {"owner/repo": "line1\nline2"},
        {"owner/repo": "bad\x00text"},
        {"owner/repo": "bad\u200btext"},
        {"owner/repo": "bad\u202etext"},
    ):
        with pytest.raises(ValueError):
            validate_descriptions(bad)
    asset = admitted(tmp_path / "pkg.deb")
    without = public_inventory([asset], [ref()])
    assert "descriptions" not in without
    with_desc = public_inventory([asset], [ref()], descriptions={"owner/repo": zwj})
    assert with_desc["descriptions"] == {"owner/repo": zwj}
    with pytest.raises(ValueError):
        public_inventory([asset], [ref()], descriptions={"owner/repo": "bad\x00text"})


def _png(width: int, height: int, *, bad_crc: bool = False, chunk_type: bytes = b"IHDR") -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    crc = zlib.crc32(chunk_type + ihdr) & 0xFFFFFFFF
    if bad_crc:
        crc ^= 0xFF
    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", len(ihdr))
        + chunk_type
        + ihdr
        + struct.pack(">I", crc)
    )


def test_icon_validation_and_public_inventory_allow_list(tmp_path: Path) -> None:
    assert icon_key("icons/tailor.svg") == "icons/tailor.svg"
    assert icon_key("icons/jive-vocals.png") == "icons/jive-vocals.png"
    assert icon_key("icons/tool_1.0.svg") == "icons/tool_1.0.svg"
    for bad_key in (
        "",
        "icons/UPPER.svg",
        "icons/.hidden.svg",
        "icons/..svg",
        "icons/sub/tool.svg",
        "icons/tool.gif",
        "other/tool.svg",
        "../icons/tool.svg",
        "icons/tool.svg\n",
        123,
    ):
        with pytest.raises(ValueError):
            icon_key(bad_key)
    assert validate_icons({"z/repo": "icons/z.png", "a/repo": "icons/a.svg"}) == {
        "a/repo": "icons/a.svg",
        "z/repo": "icons/z.png",
    }
    for bad_map in (
        ["not-a-mapping"],
        {"bad repo": "icons/a.svg"},
        {"owner/repo": "icons/UPPER.svg"},
        {"owner/repo": "../escape.svg"},
    ):
        with pytest.raises(ValueError):
            validate_icons(bad_map)
    asset = admitted(tmp_path / "pkg.deb")
    without = public_inventory([asset], [ref()])
    assert "icons" not in without
    with_icons = public_inventory([asset], [ref()], icons={"owner/repo": "icons/repo.svg"})
    assert with_icons["icons"] == {"owner/repo": "icons/repo.svg"}
    with pytest.raises(ValueError):
        public_inventory([asset], [ref()], icons={"owner/repo": "bad/repo.svg"})


def test_validate_project_svg() -> None:
    good = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
        b'viewBox="0 0 64 64"><defs><linearGradient id="g"/></defs>'
        b'<rect width="64" height="64" fill="url(#g)"/><use xlink:href="#g"/></svg>'
    )
    assert validate_project_svg(good) == good
    assert validate_project_svg(TAILOR_PLACEHOLDER_SVG.encode()) is None
    assert validate_project_svg(f"  {TAILOR_PLACEHOLDER_SVG}\n".encode()) is None
    for rejected in (
        b"",
        b"\xff\xfe",
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">'
        + b"a" * MAX_PROJECT_SVG_BYTES
        + b"</svg>",
        b'<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>',
        b'<svg viewBox="0 0 1 1"/>',
        b'<svg xmlns="http://www.w3.org/2000/svg"/>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="   "/>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><script>alert(1)</script></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><foreignObject/></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><image href="#a"/></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><animate/></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><set/></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1" onload="alert(1)"/>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">'
        b'<a href="https://example.invalid"><rect width="1" height="1"/></a></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">'
        b'<a href="http://example.invalid"><rect width="1" height="1"/></a></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">'
        b'<a href="javascript:alert(1)"><rect width="1" height="1"/></a></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">'
        b'<a href="file:///etc/passwd"><rect width="1" height="1"/></a></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">'
        b'<a href="data:text/html,hi"><rect width="1" height="1"/></a></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">'
        b"<style>@import url('https://example.invalid/a.css');</style></svg>",
        b"<not-xml",
    ):
        assert validate_project_svg(rejected) is None, rejected


def test_validate_project_png() -> None:
    good = _png(128, 128)
    assert validate_project_png(good) == good
    for rejected in (
        b"",
        good[:32],
        b"not-a-png" + good[9:],
        _png(128, 64),
        _png(0, 0),
        _png(64, 64, bad_crc=True),
        _png(64, 64, chunk_type=b"IDAT"),
        good + b"\x00" * (MAX_PROJECT_PNG_BYTES - len(good) + 1),
    ):
        assert validate_project_png(rejected) is None


def test_size_text_steps_through_decimal_units_to_gigabytes() -> None:
    assert size_text(0) == "0 B"
    assert size_text(999) == "999 B"
    assert size_text(1_000) == "1 KB"
    assert size_text(2_500) == "2 KB"
    assert size_text(1_000_000) == "1 MB"
    assert size_text(999_000_000) == "999 MB"
    assert size_text(1_011_000_000) == "1.0 GB"
    assert size_text(1_334_000_000) == "1.3 GB"
    assert size_text(1_813_000_000) == "1.8 GB"
