"""Validated records and durable file primitives."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, cast
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
FORMATS = frozenset({"apt", "rpm", "arch", "apk", "flatpak", "brew", "scoop"})
OBJECT_CLASSES = frozenset({"package", "dependency", "entry", "inventory", "lock", "page"})
type JSONValue = None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]
type Report = Callable[[str], None]


class UnsupportedAsset(ValueError):
    """A release asset that its format cannot publish, such as an unsupported architecture."""


def quiet(line: str) -> None:
    """A Report that prints nothing."""


def step(report: Report, name: str, text: str) -> None:
    """Report one publication step for a format."""
    report(f"{name:<5} {text}")


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def size_text(size: int) -> str:
    if size >= 1_000_000:
        return f"{size / 1_000_000:.0f} MB"
    return f"{size / 1_000:.0f} KB" if size >= 1_000 else f"{size} B"


def text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value)
    ):
        raise ValueError(f"Invalid {label}")
    return value


def integer(value: object, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"Invalid {label}")
    return value


def digest(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Expected a lowercase SHA256 digest")
    return value


def repository_name(value: object) -> str:
    value = text(value, "repository")
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}", value) is None:
        raise ValueError("Invalid repository name")
    if value.split("/")[1] in {".", ".."}:
        raise ValueError("Invalid repository name")
    return value


def safe_key(value: object) -> str:
    value = text(value, "object key")
    if (
        value.startswith("/")
        or "\\" in value
        or any(p in {"", ".", ".."} for p in value.split("/"))
    ):
        raise ValueError("Unsafe relative object key")
    return value


def safe_path(root: Path, key: str) -> Path:
    safe_key(key)
    root = root.absolute()
    for parent in (root, *root.parents):
        if parent.is_symlink():
            raise ValueError("Symlink in private root")
    result = root
    for part in key.split("/"):
        result /= part
        if result.is_symlink():
            raise ValueError("Symlink in private path")
    return result


def sha256_file(path: Path) -> tuple[str, int]:
    path = safe_path(path.parent, path.name)
    if not path.is_file():
        raise ValueError("Hash input must be a regular file")
    total = 0
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            total += len(block)
            hasher.update(block)
    return hasher.hexdigest(), total


def json_value(value: object) -> JSONValue:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        if any(not isinstance(key, str) for key in mapping):
            raise ValueError("JSON object keys must be strings")
        return {str(key): json_value(item) for key, item in mapping.items()}
    if isinstance(value, (tuple, list)):
        return [json_value(item) for item in cast(Sequence[object], value)]
    raise ValueError("Value is not JSON-compatible")


def canonical_json(value: object) -> bytes:
    return json.dumps(
        json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def atomic_write(path: Path, data: bytes) -> None:
    path = safe_path(path.parent, path.name)
    if path.exists() and not path.is_file():
        raise ValueError("Destination is not a regular file")
    descriptor, temporary = tempfile.mkstemp(prefix=".hd-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def utc_now(clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> datetime:
    value = clock()
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("A timezone-aware clock is required")
    return value.astimezone(UTC)


def timestamp(value: object) -> str:
    value = text(value, "timestamp")
    parsed = datetime.fromisoformat(value)
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("Expected a UTC timestamp")
    return value


def format_name(value: object) -> str:
    value = text(value, "format")
    if value not in FORMATS:
        raise ValueError("Unknown format")
    return value


@dataclass(frozen=True)
class Record:
    schema_version: ClassVar[int] = SCHEMA_VERSION

    def to_dict(self) -> dict[str, JSONValue]:
        result = json_value(self)
        if not isinstance(result, dict):
            raise ValueError("Expected a record")
        return {"schema_version": self.schema_version, **result}


@dataclass(frozen=True)
class SourceAsset(Record):
    repository: str
    release_id: int
    asset_id: int
    filename: str
    size: int
    updated_at: str
    public_url: str
    github_sha256: str | None = None

    def __post_init__(self) -> None:
        repository_name(self.repository)
        integer(self.release_id, "release ID", 1)
        integer(self.asset_id, "asset ID", 1)
        safe_key(self.filename)
        if "/" in self.filename:
            raise ValueError("Asset filename must be a basename")
        integer(self.size, "size")
        timestamp(self.updated_at)
        url = urlsplit(text(self.public_url, "public URL"))
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.fragment
            or url.query
        ):
            raise ValueError("Expected a public HTTPS URL")
        if self.github_sha256 is not None:
            digest(self.github_sha256)


@dataclass(frozen=True)
class VerifiedAsset(Record):
    source: SourceAsset
    local_path: Path
    sha256: str
    size: int
    checksum_asset_id: int
    checksum_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, SourceAsset) or not isinstance(self.local_path, Path):
            raise ValueError("Invalid verified asset")
        digest(self.sha256)
        digest(self.checksum_sha256)
        integer(self.size, "size")
        integer(self.checksum_asset_id, "checksum asset ID", 1)
        if self.size != self.source.size or self.source.github_sha256 not in (None, self.sha256):
            raise ValueError("Verified bytes differ from source metadata")


@dataclass(frozen=True)
class NativeIdentity(Record):
    format: str
    name: str
    architecture: str
    version: str
    epoch: int = 0
    release: str = ""
    source_commit: str | None = None

    def __post_init__(self) -> None:
        format_name(self.format)
        for value in (self.name, self.architecture, self.version):
            text(value, "native identity")
        integer(self.epoch, "epoch")
        if not isinstance(self.release, str):
            raise ValueError("Invalid native release")
        if self.release:
            text(self.release, "native release")
        if self.source_commit is not None:
            digest(self.source_commit)


@dataclass(frozen=True)
class InspectedAsset(Record):
    verified: VerifiedAsset
    identity: NativeIdentity
    metadata: dict[str, JSONValue]
    evidence: dict[str, JSONValue]
    upstream_signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.verified, VerifiedAsset) or not isinstance(
            self.identity, NativeIdentity
        ):
            raise ValueError("Invalid inspected asset")
        if not isinstance(self.metadata, dict) or not isinstance(self.evidence, dict):
            raise ValueError("Expected complete metadata and evidence mappings")
        canonical_json(self.metadata)
        canonical_json(self.evidence)
        if self.upstream_signature not in {"unsigned", "signed"}:
            raise ValueError("Invalid upstream signature status")


@dataclass(frozen=True)
class AdmittedAsset(Record):
    inspected: InspectedAsset
    transformation_policy: str
    history_key: str
    published_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.inspected, InspectedAsset):
            raise ValueError("Invalid admitted asset")
        text(self.transformation_policy, "transformation policy")
        text(self.history_key, "history key")
        if self.published_sha256 is not None:
            digest(self.published_sha256)


@dataclass(frozen=True)
class ObjectRef(Record):
    bucket_role: str
    key: str
    object_class: str
    size: int
    sha256: str
    content_type: str
    cache_control: str

    def __post_init__(self) -> None:
        if self.bucket_role not in FORMATS or self.object_class not in OBJECT_CLASSES:
            raise ValueError("Invalid bucket role or object class")
        safe_key(self.key)
        integer(self.size, "size")
        digest(self.sha256)
        text(self.content_type, "content type")
        text(self.cache_control, "cache policy")


@dataclass(frozen=True)
class OutputObject(Record):
    ref: ObjectRef
    local_path: Path
    mode: str
    expected_etag: str | None
    ordinal: int

    def __post_init__(self) -> None:
        if not isinstance(self.ref, ObjectRef) or not isinstance(self.local_path, Path):
            raise ValueError("Invalid output object")
        integer(self.ordinal, "ordinal")
        if self.mode not in {"create", "replace"} or (self.mode == "create") != (
            self.expected_etag is None
        ):
            raise ValueError("Creation requires absence, replacement requires an ETag")
        if self.expected_etag is not None:
            text(self.expected_etag, "ETag")


@dataclass(frozen=True)
class RetainedFormat(Record):
    format: str
    accepted_history: tuple[AdmittedAsset, ...]
    active_identities: tuple[NativeIdentity, ...]
    metadata: dict[str, JSONValue]
    objects: tuple[ObjectRef, ...]

    def __post_init__(self) -> None:
        format_name(self.format)
        if not isinstance(self.metadata, dict):
            raise ValueError("Invalid retained metadata")
        canonical_json(self.metadata)
        for item in self.accepted_history:
            if not isinstance(item, AdmittedAsset) or item.inspected.identity.format != self.format:
                raise ValueError("Invalid retained history")
        for identity in self.active_identities:
            if not isinstance(identity, NativeIdentity) or identity.format != self.format:
                raise ValueError("Invalid active identity")
        for ref in self.objects:
            if not isinstance(ref, ObjectRef) or ref.bucket_role != self.format:
                raise ValueError("Invalid retained public object")


def stale_entries(retained: RetainedFormat) -> frozenset[str]:
    """Entry keys whose published bytes differ from the inventory, after an interrupted run."""
    value = retained.metadata.get("stale", [])
    if not isinstance(value, list) or not all(isinstance(key, str) for key in value):
        raise ValueError("Invalid stale entry list")
    return frozenset(key for key in value if isinstance(key, str))


@dataclass(frozen=True)
class PreparedFormat(Record):
    format: str
    retained: RetainedFormat
    outputs: tuple[OutputObject, ...]
    referenced_objects: tuple[ObjectRef, ...]

    def __post_init__(self) -> None:
        format_name(self.format)
        if not isinstance(self.retained, RetainedFormat) or self.retained.format != self.format:
            raise ValueError("Invalid resulting retained state")
        ordinals: list[int] = []
        keys: set[str] = set()
        for output in self.outputs:
            if not isinstance(output, OutputObject) or output.ref.bucket_role != self.format:
                raise ValueError("Invalid prepared output")
            if output.ref.key in keys:
                raise ValueError("Duplicate output key")
            keys.add(output.ref.key)
            ordinals.append(output.ordinal)
        if ordinals != sorted(set(ordinals)):
            raise ValueError("Outputs must have unique increasing ordinals")
        for ref in self.referenced_objects:
            if not isinstance(ref, ObjectRef) or ref.bucket_role != self.format:
                raise ValueError("Invalid referenced public object")


@dataclass(frozen=True)
class ObjectStat(Record):
    etag: str
    size: int

    def __post_init__(self) -> None:
        text(self.etag, "ETag")
        integer(self.size, "size")


@dataclass(frozen=True)
class WriteReceipt(Record):
    etag: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        text(self.etag, "ETag")
        digest(self.sha256)
        integer(self.size, "size")


def public_inventory(
    assets: Sequence[AdmittedAsset], objects: Sequence[ObjectRef]
) -> dict[str, JSONValue]:
    entries: list[JSONValue] = []
    for asset in assets:
        inspected = asset.inspected
        source = inspected.verified.source
        entries.append(
            {
                "identity": json_value(inspected.identity),
                "source": {
                    "repository": source.repository,
                    "release_id": source.release_id,
                    "asset_id": source.asset_id,
                    "filename": source.filename,
                    "url": source.public_url,
                },
                "source_sha256": inspected.verified.sha256,
                "published_sha256": asset.published_sha256,
            }
        )
    if any(ref.object_class in {"inventory", "lock", "page"} for ref in objects):
        raise ValueError("Inventory, lock, and page objects cannot appear in a public inventory")
    return {
        "schema_version": SCHEMA_VERSION,
        "assets": entries,
        "objects": [json_value(ref) for ref in objects],
    }
