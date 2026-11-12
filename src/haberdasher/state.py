"""Bucket locks, and publication state read from each bucket's public inventory."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import socket
import tempfile
import types
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Union, cast, get_args, get_origin, get_type_hints

from haberdasher import core
from haberdasher.core import (
    AdmittedAsset,
    JSONValue,
    NativeIdentity,
    ObjectRef,
    PreparedFormat,
    RetainedFormat,
    WriteReceipt,
    atomic_write,
    canonical_json,
    safe_path,
    sha256_file,
    text,
    utc_now,
)
from haberdasher.storage import LocalStore, ObjectChanged, PreconditionFailed, R2Store

type Store = LocalStore | R2Store
LOCK_KEY = "haberdasher.lock"
INVENTORY_KEY = "haberdasher.json"
BOOTSTRAP_KEYS = frozenset({"keys/haberdasher.asc", "keys/haberdasher.gpg"})
MAX_INVENTORY_BYTES = 32 * 1024 * 1024
MAX_LOCK_BYTES = 64 * 1024
RPM_ROOT = "."


class StateError(RuntimeError):
    pass


_RECORDS = (
    core.SourceAsset,
    core.VerifiedAsset,
    core.NativeIdentity,
    core.InspectedAsset,
    core.AdmittedAsset,
    core.ObjectRef,
)


def _decode(kind: object, value: JSONValue) -> object:
    if kind is JSONValue:
        return value
    if isinstance(kind, type) and any(
        kind is primitive for primitive in (str, int, bool, float, type(None))
    ):
        if type(value) is not kind:
            raise ValueError("Inventory field has the wrong type")
        return value
    if kind is Path:
        return Path(text(value, "inventory path"))
    origin = get_origin(kind)
    args = cast(tuple[object, ...], get_args(kind))
    if origin in (Union, types.UnionType):
        for option in args:
            try:
                return _decode(option, value)
            except ValueError, TypeError:
                pass
        raise ValueError("Invalid inventory union")
    if origin is tuple:
        if not isinstance(value, list) or len(args) != 2 or args[1] is not Ellipsis:
            raise ValueError("Invalid inventory sequence")
        return tuple(_decode(args[0], item) for item in value)
    if origin is dict:
        if not isinstance(value, dict) or len(args) != 2 or args[0] is not str:
            raise ValueError("Invalid inventory mapping")
        return {key: _decode(args[1], item) for key, item in value.items()}
    if isinstance(kind, type) and any(kind is record for record in _RECORDS) and is_dataclass(kind):
        data = mapping(value)
        if set(data) != {item.name for item in fields(kind)}:
            raise ValueError("Inventory record fields differ from schema version 1")
        hints = cast(dict[str, object], get_type_hints(kind))
        constructor = cast(Callable[..., object], kind)
        return constructor(**{name: _decode(hints[name], item) for name, item in data.items()})
    raise ValueError("Unsupported inventory record type")


def decode_record[T](kind: type[T], value: JSONValue) -> T:
    return cast(T, _decode(kind, value))


def mapping(value: JSONValue) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON mapping")
    return value


def _items(value: JSONValue) -> list[JSONValue]:
    if not isinstance(value, list):
        raise ValueError("Expected a JSON list")
    return value


def _pairs(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("Non-finite JSON number")


def parse(data: bytes) -> dict[str, JSONValue]:
    try:
        value = cast(
            JSONValue, json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
        )
        result = mapping(value)
        if type(result.get("schema_version")) is not int or result["schema_version"] != 1:
            raise ValueError("Unsupported inventory schema")
        canonical_json(result)
        return result
    except (RecursionError, UnicodeError) as error:
        raise ValueError("Invalid inventory JSON") from error


def write_object(store: Store, ref: ObjectRef, data: bytes, expected: str | None) -> WriteReceipt:
    """Create an absent object, or replace it on the expected ETag."""
    with tempfile.TemporaryDirectory(prefix="hd-state-") as temporary:
        path = Path(temporary) / "object"
        atomic_write(path, data)
        if expected is None:
            return store.create(ref, path)
        return store.replace(ref, path, expected_etag=expected)


def _ref(name: str, key: str, kind: str, data: bytes) -> ObjectRef:
    return ObjectRef(
        name,
        key,
        kind,
        len(data),
        hashlib.sha256(data).hexdigest(),
        "application/json",
        "no-store" if kind == "lock" else "no-cache",
    )


@dataclass(frozen=True)
class Lock:
    run_id: str
    held: tuple[tuple[str, str], ...] = ()


def _lock_body(run_id: str, now: datetime) -> bytes:
    environment = os.environ
    body: dict[str, JSONValue] = {
        "run_id": run_id,
        "started_at": utc_now(lambda: now).isoformat(),
    }
    if environment.get("GITHUB_ACTIONS") == "true":
        body["publisher"] = "github-actions:" + environment.get("RUNNER_NAME", "unknown")
        parts = [environment.get(name) for name in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY")]
        run = environment.get("GITHUB_RUN_ID")
        if all(parts) and run:
            body["run_url"] = f"{parts[0]}/{parts[1]}/actions/runs/{run}"
    else:
        body["publisher"] = socket.gethostname() or "unknown"
    return canonical_json(body)


def _shown(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").encode("ascii", "backslashreplace").decode()


def acquire(store: Store, locations: Mapping[str, str], *, now: datetime) -> Lock:
    """Create each bucket lock in sorted format order, or release the new locks and fail."""
    lock = Lock(uuid.uuid4().hex)
    data = _lock_body(lock.run_id, now)
    try:
        for name in sorted(locations):
            try:
                receipt = write_object(store, _ref(name, LOCK_KEY, "lock", data), data, None)
            except PreconditionFailed:
                current = store.read(name, LOCK_KEY, max_bytes=MAX_LOCK_BYTES)
                shown = _shown(current[0]) if current else "(released during the check)"
                raise StateError(
                    f"Bucket {locations[name]} ({name}) is locked by another run: {shown}. "
                    "Use just unlock only after that run has stopped"
                ) from None
            lock = replace(lock, held=(*lock.held, (name, receipt.etag)))
    except BaseException:
        with contextlib.suppress(Exception):
            release(store, lock)
        raise
    return lock


def release(store: Store, lock: Lock) -> None:
    """Delete only the locks that this run created, conditionally on their ETags."""
    failures: list[Exception] = []
    for name, etag in reversed(lock.held):
        try:
            store.delete(name, LOCK_KEY, expected_etag=etag)
        except Exception as error:
            failures.append(error)
    if failures:
        raise StateError("A bucket lock changed or could not be released") from failures[0]


def _holder(data: bytes) -> str:
    """Describe a lock body by its publisher and start time, with unprintable text replaced."""
    try:
        value = mapping(cast(JSONValue, json.loads(data)))
    except ValueError, UnicodeError, RecursionError:
        value = {}

    def field(key: str, default: str) -> str:
        item = value.get(key)
        shown = item if isinstance(item, str) and item else default
        return "".join(char if char.isprintable() else "?" for char in shown[:200])

    return f"from {field('publisher', 'an unknown host')} started {field('started_at', 'unknown')}"


def break_locks(
    store: Store, names: tuple[str, ...], report: core.Report = core.quiet
) -> dict[str, str]:
    broken: dict[str, str] = {}
    for name in sorted(names):
        current = store.read(name, LOCK_KEY, max_bytes=MAX_LOCK_BYTES)
        if current is None:
            core.step(report, name, "no lock")
            continue
        store.delete(name, LOCK_KEY, expected_etag=current[1].etag)
        broken[name] = _shown(current[0])
        core.step(report, name, f"removed lock {_holder(current[0])}")
    return broken


@dataclass(frozen=True)
class Published:
    """A format's committed state. Metadata paths are object keys until materialised."""

    format: str
    etag: str | None
    sha256: str | None
    objects: tuple[ObjectRef, ...]
    retained: RetainedFormat
    record: dict[str, JSONValue] | None = None

    @property
    def bootstrap(self) -> tuple[ObjectRef, ...]:
        return tuple(ref for ref in self.objects if ref.key in BOOTSTRAP_KEYS)


def _paths(
    name: str, metadata: dict[str, JSONValue], move: Callable[[str, str], str]
) -> dict[str, JSONValue]:
    """Map every native metadata file between a local path and its public object key."""
    result = dict(metadata)
    if not result:
        return result
    for field in {
        "apt": ("files",),
        "arch": ("paths",),
        "flatpak": ("files",),
        "brew": ("files",),
        "scoop": ("files",),
        "nix": ("files",),
    }.get(name, ()):
        result[field] = {
            key: move(text(value, "metadata path"), key)
            for key, value in mapping(result.get(field)).items()
        }
    if name == "apk":
        indexes: dict[str, JSONValue] = {}
        for arch, value in mapping(result.get("indexes")).items():
            record = dict(mapping(value))
            record["local_path"] = move(
                text(record.get("local_path"), "APK index path"), f"{arch}/APKINDEX.tar.gz"
            )
            indexes[arch] = record
        result["indexes"] = indexes
        public = dict(mapping(result.get("public_key")))
        public["local_path"] = move(
            text(public.get("local_path"), "APK key path"), "keys/haberdasher.rsa.pub"
        )
        result["public_key"] = public
    field = {"apt": "keyring", "rpm": "keyring", "arch": "public_key"}.get(name)
    if field is not None:
        result[field] = move(text(result.get(field), "public key path"), "keys/haberdasher.gpg")
    if name == "rpm":
        result["root"] = move(text(result.get("root"), "RPM root"), RPM_ROOT)
    return result


def unpublished(name: str) -> Published:
    return Published(name, None, None, (), RetainedFormat(name, (), (), {}, ()))


def read(store: Store, name: str) -> Published:
    core.format_name(name)
    current = store.read(name, INVENTORY_KEY, max_bytes=MAX_INVENTORY_BYTES)
    if current is None:
        return unpublished(name)
    data, observed = current
    return decode_published(name, data, observed.etag)


def decode_published(name: str, data: bytes, etag: str | None) -> Published:
    """Validate one format's haberdasher.json bytes."""
    try:
        value = parse(data)
        objects = tuple(decode_record(ObjectRef, item) for item in _items(value.get("objects")))
        record = mapping(value.get("state"))
        history = tuple(
            decode_record(AdmittedAsset, item) for item in _items(record.get("history"))
        )
        active = tuple(
            decode_record(NativeIdentity, item) for item in _items(record.get("active_identities"))
        )
        retained = RetainedFormat(
            name,
            history,
            active,
            mapping(record.get("metadata")),
            tuple(ref for ref in objects if ref.key not in BOOTSTRAP_KEYS),
        )
        if core.public_inventory(history, objects)["assets"] != value.get("assets"):
            raise ValueError("Inventory assets differ from inventory state")
    except ValueError as error:
        raise StateError(f"The published {name} inventory is invalid: {error}") from error
    if any(ref.bucket_role != name for ref in objects):
        raise StateError(f"The published {name} inventory names another bucket")
    return Published(name, etag, hashlib.sha256(data).hexdigest(), objects, retained, record)


def materialise(store: Store, published: Published, *, out: Path) -> RetainedFormat:
    """Download the published metadata that adapters read, and observe entry ETags.

    An entry whose bytes differ from the inventory is left out and listed as stale. Under the
    bucket lock only an interrupted run of this publisher writes entries, so the adapter
    rebuilds stale entries from the accepted history and replaces them on the observed ETag.
    """
    retained = published.retained
    if not retained.metadata:
        return retained
    refs = {ref.key: ref for ref in published.objects}
    out = safe_path(out.parent, out.name)
    out.mkdir(mode=0o700, parents=True)
    etags: dict[str, JSONValue] = {}
    stale: set[str] = set()
    for ref in retained.objects:
        if ref.object_class != "entry":
            continue
        observed = store.stat(ref)
        if observed is None:
            raise StateError(f"Published {published.format} entry {ref.key} is missing")
        etags[ref.key] = observed.etag
        if observed.size != ref.size:
            stale.add(ref.key)

    def fetch(key: str) -> Path:
        ref = refs.get(key)
        if ref is None:
            raise StateError(f"Published {published.format} metadata names an absent object")
        path = safe_path(out, key)
        if not path.exists() and key not in stale:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                store.download(ref, path)
            except ObjectChanged:
                if ref.object_class != "entry":
                    raise
                stale.add(key)
        return path

    def move(value: str, key: str) -> str:
        if value != key:
            raise StateError(f"Published {published.format} metadata path differs from its key")
        if key == RPM_ROOT:
            for name in refs:
                if name.startswith("repodata/"):
                    fetch(name)
            return str(out)
        return str(fetch(key))

    metadata = _paths(retained.format, retained.metadata, move)
    metadata["etags"] = etags
    metadata["stale"] = list[JSONValue](sorted(stale))
    if retained.format == "apk":
        metadata["indexes"] = {
            arch: {**mapping(value), "etag": etags[f"{arch}/APKINDEX.tar.gz"]}
            for arch, value in mapping(metadata.get("indexes")).items()
        }
    return replace(retained, metadata=metadata)


def _record(retained: RetainedFormat, objects: tuple[ObjectRef, ...]) -> dict[str, JSONValue]:
    refs = {ref.key: ref for ref in objects}

    def move(value: str, key: str) -> str:
        if key == RPM_ROOT:
            return key
        ref = refs.get(key)
        if ref is None or sha256_file(Path(value)) != (ref.sha256, ref.size):
            raise StateError("Native metadata differs from its public object")
        return key

    metadata = dict(retained.metadata)
    metadata.pop("etags", None)
    metadata.pop("stale", None)
    if retained.format == "apk" and metadata:
        metadata["indexes"] = {
            arch: {key: item for key, item in mapping(value).items() if key != "etag"}
            for arch, value in mapping(metadata.get("indexes")).items()
        }
    history = [
        core.json_value(
            replace(
                asset,
                inspected=replace(
                    asset.inspected,
                    verified=replace(
                        asset.inspected.verified,
                        local_path=Path("unavailable") / asset.inspected.verified.sha256,
                    ),
                ),
            )
        )
        for asset in retained.accepted_history
    ]
    return {
        "history": history,
        "active_identities": core.json_value(retained.active_identities),
        "metadata": _paths(retained.format, metadata, move),
    }


def inventory(
    prepared: PreparedFormat, bootstrap: tuple[ObjectRef, ...], published: Published
) -> bytes:
    """Build the public inventory, the explicit allow-list plus the state that adapters need."""
    objects = (*prepared.referenced_objects, *bootstrap)
    value = core.public_inventory(prepared.retained.accepted_history, objects)
    if not prepared.outputs and published.record is not None:
        value["state"] = published.record
    else:
        value["state"] = _record(prepared.retained, objects)
    return canonical_json(value)


def write_inventory(store: Store, published: Published, data: bytes) -> WriteReceipt:
    if len(data) > MAX_INVENTORY_BYTES:
        raise StateError("Public inventory exceeds its size limit")
    ref = _ref(published.format, INVENTORY_KEY, "inventory", data)
    return write_object(store, ref, data, published.etag)
