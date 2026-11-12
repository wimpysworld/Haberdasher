"""GitHub "Latest" release scans and checksum-verified inputs."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
import time
from collections.abc import Generator, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import quote

from haberdasher.config import Config, load_yaml
from haberdasher.core import (
    Record,
    Report,
    SourceAsset,
    VerifiedAsset,
    canonical_json,
    digest,
    integer,
    plural,
    quiet,
    repository_name,
    safe_key,
    safe_path,
    sha256_file,
    step,
    text,
)
from haberdasher.runtime import Runtime, transfer_timeout

DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_RETRY_SECONDS = 2
MAX_PAGE_BYTES = 8 * 1024 * 1024
MAX_PAGES = 10_000
MAX_ITEMS = 100_000
MAX_CHECKSUM_BYTES = 1024 * 1024
MAX_CHECKSUM_ENTRIES = 10_000
MAX_BUNDLE_BYTES = 1024 * 1024
MAX_ASSET_BYTES = 5 * 1024 * 1024 * 1024 - 1
PACKAGE_SUFFIXES = (
    (".deb", "apt"),
    (".rpm", "rpm"),
    (".pkg.tar.zst", "arch"),
    (".pkg.tar.xz", "arch"),
    (".apk", "apk"),
    (".flatpak", "flatpak"),
    (".exe", "scoop"),
    (".zip", "brew"),
)
# A bare macOS binary has no file extension and names its operating system after the tool.
MACOS_BINARY = re.compile(r"(.+?)[-_](?:darwin|macos|mac|osx)(?:[-_].*)?", re.IGNORECASE)
# A Windows zip file names its operating system.
WINDOWS = re.compile(r"(?:^|[-_.])(?:windows|win(?:32|64)?)(?:[-_.]|$)", re.IGNORECASE)
TARBALL = re.compile(
    r".+[-_](?:linux|darwin|macos|mac|osx)[-_](?:x86_64|amd64|x64|aarch64|arm64)\.tar\.gz$",
    re.IGNORECASE,
)
DMG = re.compile(r".+\.dmg$", re.IGNORECASE)
MAX_NIX_BLOB_BYTES = 262_144
RELEASE_NIX_FILES = frozenset(
    {"nix/default.nix", "nix/linux.nix", "nix/darwin.nix", "nix/package.nix"}
)
# electron-builder publishes this Windows update feed for apps that update themselves.
UPDATER = "latest.yml"
PER_ASSET_SUFFIXES = (".sha256", ".sha256sum")
COSIGN_BUNDLE_SUFFIX = ".sigstore.json"
COSIGN_ISSUER = "https://token.actions.githubusercontent.com"


class DiscoveryFailure(ValueError):
    pass


def asset_format(filename: str) -> str | None:
    """The format that a release asset name can provide, before its bytes are inspected."""
    if filename.endswith(".zip") and WINDOWS.search(filename):
        return "scoop"
    for suffix, name in PACKAGE_SUFFIXES:
        if filename.endswith(suffix):
            return name
    if re.search(r"\.[A-Za-z][A-Za-z0-9]*$", filename) is None and MACOS_BINARY.fullmatch(filename):
        return "brew"
    return None


def asset_formats(filename: str, siblings: Iterable[str] = ()) -> tuple[str, ...]:
    """Every format that a release asset can feed within its release asset group."""
    primary = asset_format(filename)
    result = [primary] if primary is not None else []
    sibling_set = set(siblings) or {filename}
    lower = filename.lower()
    if any(TARBALL.fullmatch(name) is not None for name in sibling_set):
        if TARBALL.fullmatch(filename) is not None:
            result.append("nix")
    elif (
        filename.endswith(".deb")
        or DMG.fullmatch(filename) is not None
        or (primary == "brew" and lower.endswith(".zip"))
    ):
        result.append("nix")
    return tuple(dict.fromkeys(result))


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

    def __post_init__(self) -> None:
        if not isinstance(self.source, SourceAsset):
            raise ValueError("Invalid discovered source")
        if self.checksum is not None:
            _match_checksum(self.source, self.checksum)


@dataclass(frozen=True)
class DiscoveryState(Record):
    """One scan of the latest release of each configured source."""

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
    checksummed: tuple[DiscoveredAsset, ...]
    pending: tuple[DiscoveredAsset, ...]


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
    """Read GNU SHA256 or BSD SHA256 lines, without path or name normalisation.

    A per-asset document, such as app.deb.sha256, can also hold one bare digest for app.deb.
    """
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
        bare = re.fullmatch(r"[0-9a-fA-F]{64}", line)
        if match:
            value, name = match.groups()
        elif bare and source.filename.lower().endswith(PER_ASSET_SUFFIXES):
            value, name = line, source.filename.rsplit(".", 1)[0]
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


def _json_request(endpoint: str, runtime: Runtime, *, missing: object = None) -> object:
    """Return missing for HTTP 404 when missing is given. Raise on any other failure."""
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
        if missing is not None and b"(HTTP 404)" in result.stderr:
            return missing
        raise DiscoveryFailure(
            "GitHub metadata request failed. Run `gh auth login` or set GH_TOKEN"
        )
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
def _download(source: SourceAsset, runtime: Runtime, limit: int) -> Generator[tuple[Path, str]]:
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
        for attempt in range(DOWNLOAD_ATTEMPTS):
            if attempt:
                path.unlink(missing_ok=True)
                time.sleep(DOWNLOAD_RETRY_SECONDS * attempt)
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
                timeout=transfer_timeout(source.size),
            )
            if result.returncode == 0:
                break
        else:
            raise DiscoveryFailure(
                f"GitHub asset download failed after {DOWNLOAD_ATTEMPTS} attempts"
            )
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
        yield path, tag


def release_details(source: SourceAsset, runtime: Runtime) -> tuple[str, str, str]:
    """The release tag of an asset, and the description and SPDX licence of its repository.

    The licence is `Unknown` when GitHub does not name an SPDX licence.
    """
    release = _mapping(
        _json_request(f"repos/{source.repository}/releases/{source.release_id}", runtime)
    )
    if integer(release.get("id"), "release ID", 1) != source.release_id:
        raise DiscoveryFailure("Release changed during inspection")
    repository = _mapping(_json_request(f"repos/{source.repository}", runtime))
    description = repository.get("description")
    licence = repository.get("license")
    spdx = None if licence is None else _mapping(licence).get("spdx_id")
    return (
        text(release.get("tag_name"), "release tag"),
        " ".join(description.split()) if isinstance(description, str) else "",
        spdx if isinstance(spdx, str) and spdx and spdx != "NOASSERTION" else "Unknown",
    )


def cosign_identity(repository: str, tag: str) -> str:
    """Pin a release workflow certificate to the source repository and the release tag."""
    owner, name = repository_name(repository).split("/")
    return (
        rf"^https://github\.com/{re.escape(owner)}/{re.escape(name)}"
        rf"/\.github/workflows/[^@]+@refs/tags/{re.escape(text(tag, 'release tag'))}$"
    )


def _verify_bundle(
    checksum: SourceAsset, bundle: SourceAsset, tag: str, path: Path, runtime: Runtime
) -> None:
    """Fail closed unless cosign verifies the checksum document against its release bundle."""
    with _download(bundle, runtime, MAX_BUNDLE_BYTES) as (bundle_path, bundle_tag):
        if bundle_tag != tag:
            raise DiscoveryFailure("Release tag changed during download")
        result = runtime.run(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                str(bundle_path),
                "--certificate-identity-regexp",
                cosign_identity(checksum.repository, tag),
                "--certificate-oidc-issuer",
                COSIGN_ISSUER,
                str(path),
            ]
        )
    if result.returncode != 0:
        raise DiscoveryFailure(
            f"Cosign bundle {bundle.filename} does not verify for "
            f"{checksum.repository} at tag {tag}"
        )


def _release_label(release: dict[str, object], release_id: int) -> str:
    tag = release.get("tag_name")
    try:
        return text(tag, "release tag")
    except ValueError:
        return f"release {release_id}"


_MISSING = object()


def tag_nix_files(repository: str, tag: str, runtime: Runtime) -> dict[str, str] | None:
    """Read upstream release Nix package expressions from a tag tree, ignoring devShell helpers."""
    repository_name(repository)
    tag = text(tag, "release tag")
    value = _json_request(
        f"repos/{repository}/git/trees/{quote(tag, safe='')}?recursive=1",
        runtime,
        missing=_MISSING,
    )
    if value is _MISSING:
        return None
    tree_map = _mapping(value)
    if tree_map.get("truncated", False) is not False:
        raise DiscoveryFailure(f"{repository}@{tag}: GitHub git tree response is truncated")
    tree_obj = tree_map.get("tree")
    if not isinstance(tree_obj, list):
        raise DiscoveryFailure("Expected a GitHub Git tree array")
    blobs: dict[str, tuple[str, int]] = {}
    for raw in cast(list[object], tree_obj):
        entry = _mapping(raw)
        path = entry.get("path")
        if (
            not isinstance(path, str)
            or (path != "flake.nix" and path not in RELEASE_NIX_FILES)
            or entry.get("type") != "blob"
            or entry.get("mode") != "100644"
        ):
            continue
        sha = text(entry.get("sha"), "Git blob SHA")
        size = integer(entry.get("size"), "Git blob size")
        if re.fullmatch(r"[0-9a-f]{40}", sha) is None or size > MAX_NIX_BLOB_BYTES:
            raise DiscoveryFailure(f"Invalid or oversized Nix expression {path} in {repository}")
        blobs[path] = (sha, size)
    has_release_nix = "nix/default.nix" in blobs or (
        "flake.nix" in blobs
        and bool(blobs.keys() & {"nix/linux.nix", "nix/darwin.nix", "nix/package.nix"})
    )
    if not has_release_nix:
        return None
    files: dict[str, str] = {}
    for path, (sha, size) in sorted(blobs.items()):
        blob = _mapping(_json_request(f"repos/{repository}/git/blobs/{sha}", runtime))
        if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
            raise DiscoveryFailure(f"Unexpected Git blob encoding for {path}")
        compact = "".join(cast(str, blob["content"]).split())
        try:
            raw_bytes = base64.b64decode(compact, validate=True)
            decoded = raw_bytes.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise DiscoveryFailure(f"Invalid UTF-8 Nix expression {path}") from error
        if len(raw_bytes) != size or len(raw_bytes) > MAX_NIX_BLOB_BYTES:
            raise DiscoveryFailure(f"Git blob size mismatch for {path}")
        files[path] = decoded
    return files


def _installers(
    feed: SourceAsset, checksum: ChecksumEntry | None, runtime: Runtime
) -> set[str] | None:
    """The installer names in an electron-builder update feed, or None without a feed checksum."""
    expected = checksum.sha256 if checksum is not None else feed.github_sha256
    if expected is None:
        return None
    try:
        with _download(feed, runtime, MAX_CHECKSUM_BYTES) as (path, _tag):
            if sha256_file(path)[0] != expected:
                raise DiscoveryFailure("Downloaded asset differs from SHA256 checksum")
            data = load_yaml(path)
    except ValueError as error:
        raise DiscoveryFailure(f"{feed.repository}, {feed.filename}: {error}") from error
    files = data.get("files")
    entries = cast(list[object], files) if isinstance(files, list) else []
    urls = [data.get("path")]
    urls += [
        cast(dict[str, object], entry).get("url") for entry in entries if isinstance(entry, dict)
    ]
    return {url for url in urls if isinstance(url, str)}


def scan_releases(config: Config, *, runtime: Runtime, report: Report = quiet) -> CompleteScan:
    """Scan the GitHub "Latest" release of each source. Any failed request raises."""
    assets: dict[tuple[str, int], SourceAsset] = {}
    groups: dict[str, tuple[str, tuple[SourceAsset, ...]] | None] = {}
    for repository in config.sources:
        value = _json_request(f"repos/{repository}/releases/latest", runtime, missing=_MISSING)
        if value is _MISSING:
            groups[repository] = None
            continue
        release = _mapping(value)
        if not _eligible(release):
            raise DiscoveryFailure(f"{repository}: the latest release is a draft or pre-release")
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
        groups[repository] = (_release_label(release, release_id), tuple(release_assets))
    records: list[DiscoveredAsset] = []
    checksummed: list[DiscoveredAsset] = []
    pending: list[DiscoveredAsset] = []
    for repository in config.sources:
        latest = groups[repository]
        if latest is None:
            report(f"{repository}: no latest release")
            continue
        label, group = latest
        report(f"{repository}: latest release {label}")
        checksums: dict[str, ChecksumEntry] = {}
        documents = signed = 0
        siblings = {source.filename: source for source in group}
        for source in sorted(group, key=lambda item: item.asset_id):
            if not _is_checksum(source.filename):
                continue
            documents += 1
            try:
                with _download(source, runtime, MAX_CHECKSUM_BYTES) as (path, tag):
                    bundle = siblings.get(source.filename + COSIGN_BUNDLE_SUFFIX)
                    if bundle is not None:
                        _verify_bundle(source, bundle, tag, path, runtime)
                        signed += 1
                    with path.open("rb") as stream:
                        entries = parse_checksums(stream.read(MAX_CHECKSUM_BYTES + 1), source)
            except DiscoveryFailure as error:
                raise DiscoveryFailure(
                    f"{source.repository} {label}, {source.filename}: {error}"
                ) from error
            for entry in entries:
                prior = checksums.setdefault(entry.filename, entry)
                if prior.sha256 != entry.sha256:
                    raise DiscoveryFailure(
                        f"Conflicting checksums in {repository} {label}: checksum files "
                        f"disagree about {entry.filename}"
                    )
        packages = 0
        missing = 0
        digests = 0
        feed = siblings.get(UPDATER)
        installers: set[str] | None = set()
        if feed is not None and any("scoop" in asset_formats(name, siblings) for name in siblings):
            installers = _installers(feed, checksums.get(UPDATER), runtime)
            if installers is None:
                step(
                    report,
                    "scoop",
                    f"skipped {repository} {label}: the app updates itself ({UPDATER} "
                    "has no checksum)",
                )
        for source in sorted(group, key=lambda item: item.asset_id):
            formats = asset_formats(source.filename, siblings)
            if not formats:
                continue
            if formats == ("scoop",) and (installers is None or source.filename in installers):
                if installers is not None:
                    step(
                        report,
                        "scoop",
                        f"skipped {repository} {label} {source.filename}: "
                        f"a self-updating installer ({UPDATER})",
                    )
                # Keep the record, so the format stays in the run, but never download the asset.
                records.append(DiscoveredAsset(source, None))
                continue
            packages += 1
            checksum = checksums.get(source.filename)
            if checksum is None and source.github_sha256 is not None:
                checksum = ChecksumEntry(
                    source, source.filename, source.github_sha256, source.github_sha256
                )
                digests += 1
            record = DiscoveredAsset(source, checksum)
            records.append(record)
            if checksum is None:
                missing += 1
                pending.append(record)
            else:
                checksummed.append(record)
        if checksums:
            status = "checksums OK"
        elif digests:
            status = "GitHub digests OK"
        else:
            status = "no checksums"
        line = f"  {label}  {status}"
        line += "  cosign OK" if documents and signed == documents else "  no cosign bundle"
        line += f"  {plural(packages, 'package')}"
        if missing:
            line += f", {missing} without a checksum (skipped)"
        report(line)
    state = DiscoveryState(tuple(records), tuple(assets.values()), config.sources)
    return CompleteScan(state, tuple(checksummed), tuple(pending))


def verify_asset(
    source: SourceAsset, checksum: ChecksumEntry, *, runtime: Runtime, out: Path
) -> VerifiedAsset:
    """Create out as a new private file inside the runtime workspace after verification."""
    _match_checksum(source, checksum)
    relative = out.absolute().relative_to(runtime.root.absolute())
    destination = safe_path(runtime.root, relative.as_posix())
    if destination.exists():
        raise DiscoveryFailure("Verified output already exists")
    with _download(source, runtime, MAX_ASSET_BYTES) as (path, _tag):
        actual, size = sha256_file(path)
        if actual != checksum.sha256 or source.github_sha256 not in (None, actual):
            raise DiscoveryFailure("Downloaded asset differs from SHA256 checksum")
        verified = VerifiedAsset(
            source, destination, actual, size, checksum.source.asset_id, checksum.checksum_sha256
        )
        os.link(path, destination)
    return verified
