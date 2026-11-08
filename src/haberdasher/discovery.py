"""Complete GitHub scans and checksum-verified private inputs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import quote

from haberdasher.config import Config
from haberdasher.core import (
    Record,
    SourceAsset,
    VerifiedAsset,
    canonical_json,
    digest,
    integer,
    repository_name,
    safe_key,
    safe_path,
    sha256_file,
    text,
)
from haberdasher.runtime import Runtime

MAX_PAGE_BYTES = 8 * 1024 * 1024
MAX_PAGES = 10_000
MAX_ITEMS = 100_000
MAX_CHECKSUM_BYTES = 1024 * 1024
MAX_CHECKSUM_ENTRIES = 10_000
MAX_ASSET_BYTES = 5 * 1024 * 1024 * 1024 - 1
PACKAGE_SUFFIXES = (".deb", ".rpm", ".apk", ".pkg.tar.zst", ".flatpak")


class DiscoveryFailure(ValueError):
    pass


def _filename(value: object) -> str:
    name = safe_key(value)
    if "/" in name or name != name.strip():
        raise DiscoveryFailure("Expected an unambiguous asset basename")
    return name


@dataclass(frozen=True)
class ChecksumEntry(Record):
    source: SourceAsset
    filename: str
    sha256: str
    checksum_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, SourceAsset):
            raise ValueError("Invalid checksum source")
        _filename(self.filename)
        digest(self.sha256)
        digest(self.checksum_sha256)
        if self.source.github_sha256 not in (None, self.checksum_sha256):
            raise DiscoveryFailure("Checksum document differs from GitHub digest")


@dataclass(frozen=True)
class DiscoveredAsset(Record):
    source: SourceAsset
    checksum: ChecksumEntry | None
    fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, SourceAsset):
            raise ValueError("Invalid discovered source")
        digest(self.fingerprint)
        if self.checksum is not None:
            _match_checksum(self.source, self.checksum)


@dataclass(frozen=True)
class DiscoveryState(Record):
    """A proposed scan, committed only with the publication that consumes it."""

    records: tuple[DiscoveredAsset, ...] = ()
    assets: tuple[SourceAsset, ...] = ()
    sources: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(set(self.sources)) != len(self.sources):
            raise ValueError("Repeated discovery source")
        for source in self.sources:
            repository_name(source)
        assets: dict[tuple[str, int], SourceAsset] = {}
        for asset in self.assets:
            key = _asset_key(asset)
            if key in assets or asset.repository not in self.sources:
                raise ValueError("Invalid discovery asset set")
            assets[key] = asset
        seen: set[tuple[str, int]] = set()
        for record in self.records:
            key = _asset_key(record.source)
            if key in seen or assets.get(key) != record.source:
                raise ValueError("Invalid discovery record set")
            if (
                record.checksum is not None
                and assets.get(_asset_key(record.checksum.source)) != record.checksum.source
            ):
                raise ValueError("Missing checksum source in discovery state")
            seen.add(key)


@dataclass(frozen=True)
class CompleteScan(Record):
    state: DiscoveryState
    changed: tuple[DiscoveredAsset, ...]
    unchanged: tuple[DiscoveredAsset, ...]
    pending: tuple[DiscoveredAsset, ...]
    disappeared: tuple[SourceAsset, ...]


def _asset_key(source: SourceAsset) -> tuple[str, int]:
    return source.repository, source.asset_id


def _match_checksum(source: SourceAsset, checksum: ChecksumEntry) -> None:
    if (
        source.repository != checksum.source.repository
        or source.release_id != checksum.source.release_id
        or source.filename != checksum.filename
    ):
        raise DiscoveryFailure("Checksum belongs to another asset or release")
    if source.github_sha256 not in (None, checksum.sha256):
        raise DiscoveryFailure("Checksum differs from GitHub digest")


def parse_checksums(data: bytes, source: SourceAsset) -> tuple[ChecksumEntry, ...]:
    """Read GNU SHA256 or BSD SHA256 lines, without path or name normalisation."""
    if len(data) > MAX_CHECKSUM_BYTES or len(data) != source.size:
        raise DiscoveryFailure("Invalid checksum document size")
    checksum_hash = hashlib.sha256(data).hexdigest()
    if source.github_sha256 not in (None, checksum_hash):
        raise DiscoveryFailure("Checksum document differs from GitHub digest")
    try:
        lines = data.decode("utf-8").split("\n")
    except UnicodeError as error:
        raise DiscoveryFailure("Checksum document is not UTF-8") from error
    entries: dict[str, ChecksumEntry] = {}
    for line in lines:
        line = line.removesuffix("\r")
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        if match:
            value, name = match.groups()
        else:
            match = re.fullmatch(r"SHA256 \((.+)\) = ([0-9a-fA-F]{64})", line)
            if match is None:
                raise DiscoveryFailure("Malformed SHA256 checksum entry")
            name, value = match.groups()
        name = _filename(name)
        if name in entries:
            raise DiscoveryFailure("Duplicate checksum filename")
        entries[name] = ChecksumEntry(source, name, value.lower(), checksum_hash)
        if len(entries) > MAX_CHECKSUM_ENTRIES:
            raise DiscoveryFailure("Too many checksum entries")
    if not entries:
        raise DiscoveryFailure("Empty checksum document")
    return tuple(entries.values())


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise DiscoveryFailure("Expected a GitHub object")
    return cast(dict[str, object], value)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DiscoveryFailure("Duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(value: str) -> object:
    raise DiscoveryFailure(f"Invalid JSON constant: {value}")


def _json_request(endpoint: str, runtime: Runtime) -> object:
    result = runtime.run(
        [
            "gh",
            "api",
            "--hostname",
            "github.com",
            "--method",
            "GET",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "X-GitHub-Api-Version: 2022-11-28",
            endpoint,
        ],
        env_kind="github",
    )
    if result.returncode != 0:
        raise DiscoveryFailure("GitHub metadata request failed")
    if len(result.stdout) > MAX_PAGE_BYTES:
        raise DiscoveryFailure("GitHub response exceeds the byte limit")
    try:
        value: object = json.loads(
            result.stdout, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise DiscoveryFailure("Invalid GitHub JSON response") from error
    nodes = 0
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > MAX_ITEMS:
            raise DiscoveryFailure("GitHub JSON exceeds structural limits")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in cast(dict[str, object], item).values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in cast(list[object], item))
    return value


def _pages(endpoint: str, runtime: Runtime) -> Iterator[dict[str, object]]:
    seen: dict[int, bytes] = {}
    for page in range(1, MAX_PAGES + 1):
        value = _json_request(f"{endpoint}?per_page=100&page={page}", runtime)
        if not isinstance(value, list):
            raise DiscoveryFailure("Expected a GitHub page array")
        items = cast(list[object], value)
        if not items:
            return
        if len(items) > 100:
            raise DiscoveryFailure("GitHub page exceeds the requested size")
        added = False
        for item in items:
            row = _mapping(item)
            identifier = integer(row.get("id"), "GitHub ID", 1)
            representation = canonical_json(row)
            if identifier in seen:
                if seen[identifier] != representation:
                    raise DiscoveryFailure("Conflicting duplicate GitHub ID")
                continue
            seen[identifier] = representation
            if len(seen) > MAX_ITEMS:
                raise DiscoveryFailure("Too many GitHub records")
            added = True
            yield row
        if not added:
            raise DiscoveryFailure("GitHub pagination made no progress")
    raise DiscoveryFailure("GitHub pagination exceeds the page limit")


def _eligible(release: dict[str, object]) -> bool:
    if type(release.get("draft")) is not bool or type(release.get("prerelease")) is not bool:
        raise DiscoveryFailure("Missing or invalid release eligibility")
    return release["draft"] is False and release["prerelease"] is False


def _source(row: dict[str, object], repository: str, release_id: int) -> SourceAsset:
    if row.get("state") != "uploaded":
        raise DiscoveryFailure("Asset upload is incomplete")
    github_hash = row.get("digest")
    if github_hash is not None:
        github_hash = text(github_hash, "GitHub digest")
        if not github_hash.startswith("sha256:"):
            raise DiscoveryFailure("Unsupported GitHub digest")
        github_hash = digest(github_hash.removeprefix("sha256:"))
    return SourceAsset(
        repository=repository,
        release_id=release_id,
        asset_id=integer(row.get("id"), "asset ID", 1),
        filename=_filename(row.get("name")),
        size=integer(row.get("size"), "asset size"),
        updated_at=text(row.get("updated_at"), "asset timestamp"),
        public_url=text(row.get("browser_download_url"), "asset URL"),
        github_sha256=github_hash,
    )


def _is_checksum(name: str) -> bool:
    name = name.lower()
    return name in {
        "sha256sums",
        "sha256sums.txt",
        "sha256sum.txt",
        "checksums.txt",
    } or name.endswith((".sha256", ".sha256sum", ".sha256sums", "_checksums.txt", "-checksums.txt"))


def _check_current(source: SourceAsset, runtime: Runtime) -> None:
    row = _mapping(
        _json_request(f"repos/{source.repository}/releases/assets/{source.asset_id}", runtime)
    )
    if _source(row, source.repository, source.release_id) != source:
        raise DiscoveryFailure("Asset changed during download")


@contextmanager
def _download(source: SourceAsset, runtime: Runtime, limit: int) -> Generator[Path]:
    if source.size > limit:
        raise DiscoveryFailure("Asset exceeds the download size limit")
    base = f"repos/{source.repository}/releases"
    release = _mapping(_json_request(f"{base}/{source.release_id}", runtime))
    if integer(release.get("id"), "release ID", 1) != source.release_id or not _eligible(release):
        raise DiscoveryFailure("Release is no longer eligible")
    tag = text(release.get("tag_name"), "release tag")
    _check_current(source, runtime)
    root = safe_path(runtime.root, "downloads")
    root.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="asset-", dir=root) as directory:
        path = Path(directory) / "payload"
        pattern = "".join("\\" + char if char in "*?[]" else char for char in source.filename)
        result = runtime.run(
            [
                "gh",
                "release",
                "download",
                "--repo",
                f"https://github.com/{source.repository}",
                "--pattern",
                pattern,
                "--output",
                str(path),
                "--",
                tag,
            ],
            env_kind="github",
            timeout=600,
        )
        if result.returncode != 0:
            raise DiscoveryFailure("GitHub asset download failed")
        safe_path(path.parent, path.name)
        if not path.is_file() or path.stat().st_size != source.size or path.stat().st_size > limit:
            raise DiscoveryFailure("Downloaded asset has an invalid size")
        path.chmod(0o600)
        _check_current(source, runtime)
        current = _mapping(_json_request(f"{base}/tags/{quote(tag, safe='')}", runtime))
        if integer(current.get("id"), "release ID", 1) != source.release_id or not _eligible(
            current
        ):
            raise DiscoveryFailure("Release tag changed during download")
        yield path


def scan_releases(config: Config, *, runtime: Runtime, previous: DiscoveryState) -> CompleteScan:
    """Return a proposed complete scan. Any failed request raises without changing previous."""
    assets: dict[tuple[str, int], SourceAsset] = {}
    groups: list[tuple[SourceAsset, ...]] = []
    for repository in config.sources:
        for release in _pages(f"repos/{repository}/releases", runtime):
            if not _eligible(release):
                continue
            release_id = integer(release.get("id"), "release ID", 1)
            names: set[str] = set()
            release_assets: list[SourceAsset] = []
            for row in _pages(f"repos/{repository}/releases/{release_id}/assets", runtime):
                source = _source(row, repository, release_id)
                key = _asset_key(source)
                if key in assets or source.filename in names:
                    raise DiscoveryFailure("Ambiguous asset ID or filename")
                names.add(source.filename)
                assets[key] = source
                release_assets.append(source)
                if len(assets) > MAX_ITEMS:
                    raise DiscoveryFailure("Too many discovered assets")
            groups.append(tuple(release_assets))
    old = {_asset_key(record.source): record for record in previous.records}
    records: list[DiscoveredAsset] = []
    changed: list[DiscoveredAsset] = []
    unchanged: list[DiscoveredAsset] = []
    pending: list[DiscoveredAsset] = []
    for group in groups:
        checksums: dict[str, ChecksumEntry] = {}
        for source in sorted(group, key=lambda item: item.asset_id):
            if not _is_checksum(source.filename):
                continue
            with _download(source, runtime, MAX_CHECKSUM_BYTES) as path:
                with path.open("rb") as stream:
                    entries = parse_checksums(stream.read(MAX_CHECKSUM_BYTES + 1), source)
            for entry in entries:
                if entry.filename in checksums:
                    raise DiscoveryFailure("Ambiguous checksum sources for an asset")
                checksums[entry.filename] = entry
        for source in sorted(group, key=lambda item: item.asset_id):
            if not source.filename.endswith(PACKAGE_SUFFIXES):
                continue
            checksum = checksums.get(source.filename)
            fingerprint = hashlib.sha256(
                canonical_json((source, checksum.sha256 if checksum is not None else None))
            ).hexdigest()
            record = DiscoveredAsset(source, checksum, fingerprint)
            records.append(record)
            prior = old.get(_asset_key(source))
            if checksum is None:
                pending.append(record)
            elif (
                prior is not None
                and prior.source == source
                and prior.checksum is not None
                and prior.checksum.sha256 == checksum.sha256
            ):
                unchanged.append(record)
            else:
                changed.append(record)
    state = DiscoveryState(tuple(records), tuple(assets.values()), config.sources)
    disappeared = tuple(asset for asset in previous.assets if _asset_key(asset) not in assets)
    return CompleteScan(state, tuple(changed), tuple(unchanged), tuple(pending), disappeared)


def verify_asset(
    source: SourceAsset, checksum: ChecksumEntry, *, runtime: Runtime, out: Path
) -> VerifiedAsset:
    """Create out as a new private file inside the runtime workspace after verification."""
    _match_checksum(source, checksum)
    relative = out.absolute().relative_to(runtime.root.absolute())
    destination = safe_path(runtime.root, relative.as_posix())
    if destination.exists():
        raise DiscoveryFailure("Verified output already exists")
    with _download(source, runtime, MAX_ASSET_BYTES) as path:
        actual, size = sha256_file(path)
        if actual != checksum.sha256 or source.github_sha256 not in (None, actual):
            raise DiscoveryFailure("Downloaded asset differs from SHA256 checksum")
        verified = VerifiedAsset(
            source, destination, actual, size, checksum.source.asset_id, checksum.checksum_sha256
        )
        os.link(path, destination)
    return verified
