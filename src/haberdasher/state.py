"""Private ownership, immutable snapshots, and durable publication records."""

from __future__ import annotations

import hashlib
import json
import tempfile
import types
import uuid
from collections.abc import Callable
from dataclasses import dataclass, fields, is_dataclass, replace
from dataclasses import field as dataclass_field
from datetime import datetime
from pathlib import Path
from typing import Union, cast, get_args, get_origin, get_type_hints

from haberdasher import config, core, discovery
from haberdasher.core import (
    JSONValue,
    ObjectRef,
    ObjectStat,
    Ownership,
    PreparedGeneration,
    RetainedFormat,
    WriteReceipt,
    atomic_write,
    canonical_json,
    digest,
    safe_key,
    safe_path,
    sha256_file,
    text,
    utc_now,
)
from haberdasher.storage import LocalStore, R2Store

type Store = LocalStore | R2Store
MAX_CONTROL_BYTES = 32 * 1024 * 1024
EMPTY_HASH = "0" * 64


class StateError(RuntimeError):
    pass


@dataclass(frozen=True)
class FrozenGeneration:
    id: str
    manifest_hash: str

    def __post_init__(self) -> None:
        safe_key(self.id)
        if "/" in self.id:
            raise ValueError("Generation ID must be one path component")
        digest(self.manifest_hash)


@dataclass(frozen=True)
class CommittedState:
    generation_id: str | None
    completion_etag: str | None
    discovery: discovery.DiscoveryState
    formats: tuple[RetainedFormat, ...]
    config_digest: str | None
    policy_digest: str | None
    inventory_etags: dict[str, str]
    bootstrap_objects: tuple[ObjectRef, ...] = ()
    bootstrap_etags: dict[str, str] = dataclass_field(default_factory=dict)
    signing_fingerprint: str | None = None


@dataclass(frozen=True)
class WriteResolution:
    ordinal: int
    outcome: str
    etag: str | None = None

    def __post_init__(self) -> None:
        core.integer(self.ordinal, "write ordinal")
        if self.outcome not in {"written", "not-written"}:
            raise ValueError("Invalid resolved write outcome")
        if (self.outcome == "written") != (self.etag is not None):
            raise ValueError("A written resolution requires its exact ETag")
        if self.etag is not None:
            text(self.etag, "resolved ETag")


@dataclass(frozen=True)
class RecoveryEvidence:
    stopped_owner: bool
    requests_resolved: bool
    reference: str
    runner_identity: str
    writes: tuple[WriteResolution, ...] = ()

    def __post_init__(self) -> None:
        if self.stopped_owner is not True or self.requests_resolved is not True:
            raise ValueError("Recovery requires a stopped owner and resolved requests")
        text(self.reference, "recovery evidence reference")
        text(self.runner_identity, "recovery runner")
        if any(not isinstance(item, WriteResolution) for item in self.writes):
            raise ValueError("Invalid write resolution")
        if len({item.ordinal for item in self.writes}) != len(self.writes):
            raise ValueError("Duplicate write resolution")


_RECORDS = (
    core.SourceAsset,
    core.VerifiedAsset,
    core.NativeIdentity,
    core.InspectedAsset,
    core.AdmittedAsset,
    core.ObjectRef,
    core.OutputObject,
    core.RetainedFormat,
    core.PreparedFormat,
    core.PreparedGeneration,
    core.Ownership,
    core.ObjectStat,
    core.WriteReceipt,
    config.RuntimePolicy,
    config.TrustPolicy,
    config.FormatPolicy,
    discovery.ChecksumEntry,
    discovery.DiscoveredAsset,
    discovery.DiscoveryState,
    FrozenGeneration,
    WriteResolution,
    RecoveryEvidence,
)


def _decode(kind: object, value: JSONValue) -> object:
    if kind is JSONValue:
        return value
    if isinstance(kind, type) and any(
        kind is primitive for primitive in (str, int, bool, float, type(None))
    ):
        if type(value) is not kind:
            raise ValueError("Private record field has the wrong type")
        return value
    if kind is Path:
        return Path(text(value, "private path"))
    origin = get_origin(kind)
    args = cast(tuple[object, ...], get_args(kind))
    if origin in (Union, types.UnionType):
        for option in args:
            try:
                return _decode(option, value)
            except ValueError, TypeError:
                pass
        raise ValueError("Invalid private record union")
    if origin is tuple:
        if not isinstance(value, list) or len(args) != 2 or args[1] is not Ellipsis:
            raise ValueError("Invalid private record sequence")
        return tuple(_decode(args[0], item) for item in value)
    if origin is dict:
        if not isinstance(value, dict) or len(args) != 2 or args[0] is not str:
            raise ValueError("Invalid private record mapping")
        return {key: _decode(args[1], item) for key, item in value.items()}
    if isinstance(kind, type) and any(kind is record for record in _RECORDS) and is_dataclass(kind):
        data = dict(mapping(value))
        if kind is PreparedGeneration:
            data.setdefault("bootstrap_outputs", [])
            data.setdefault("bootstrap_objects", [])
            data.setdefault("signing_fingerprint", None)
        expected = {item.name for item in fields(kind)}
        if set(data) != expected:
            raise ValueError("Private record fields differ from schema version 1")
        hints = cast(dict[str, object], get_type_hints(kind))
        constructor = cast(Callable[..., object], kind)
        return constructor(**{name: _decode(hints[name], item) for name, item in data.items()})
    raise ValueError("Unsupported private record type")


def decode_record[T](kind: type[T], value: JSONValue) -> T:
    return cast(T, _decode(kind, value))


def mapping(value: JSONValue) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise ValueError("Expected a private JSON mapping")
    return value


def _pairs(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate private JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("Non-finite private JSON number")


def parse(data: bytes) -> dict[str, JSONValue]:
    if len(data) > MAX_CONTROL_BYTES:
        raise ValueError("Private JSON exceeds its size limit")
    try:
        value = cast(
            JSONValue, json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
        )
        result = mapping(value)
        if type(result.get("schema_version")) is not int or result["schema_version"] != 1:
            raise ValueError("Unsupported private state schema")
        canonical_json(result)
        return result
    except (RecursionError, UnicodeError) as error:
        raise ValueError("Invalid private JSON") from error


def read_control(store: Store, key: str) -> tuple[dict[str, JSONValue], ObjectStat] | None:
    result = store.read_private(key, max_bytes=MAX_CONTROL_BYTES)
    return None if result is None else (parse(result[0]), result[1])


def private_ref(key: str, data: bytes) -> ObjectRef:
    return ObjectRef(
        "private",
        key,
        "private",
        len(data),
        hashlib.sha256(data).hexdigest(),
        "application/octet-stream",
        "no-store",
    )


def write_control(
    store: Store, key: str, value: dict[str, JSONValue], *, expected: str | None
) -> WriteReceipt:
    data = canonical_json({"schema_version": 1, **value})
    if len(data) > MAX_CONTROL_BYTES:
        raise ValueError("Private control exceeds its size limit")
    ref = private_ref(key, data)
    with tempfile.TemporaryDirectory(prefix="hd-state-") as temporary:
        path = Path(temporary) / "control"
        atomic_write(path, data)
        receipt = (
            store.create(ref, path)
            if expected is None
            else store.replace(ref, path, expected_etag=expected)
        )
        observed = store.download(ref, Path(temporary) / "verified")
        if observed.etag != receipt.etag:
            raise StateError("Private control changed after acknowledgement")
        return receipt


def check_owner(store: Store, ownership: Ownership) -> dict[str, JSONValue]:
    current = read_control(store, "ownership.json")
    if (
        current is None
        or current[1].etag != ownership.etag
        or current[0].get("nonce") != ownership.owner_nonce
        or current[0].get("status") != "active"
    ):
        raise StateError("Publication ownership is absent or changed")
    return current[0]


def _completion(store: Store) -> tuple[FrozenGeneration, ObjectStat] | None:
    current = read_control(store, "completed.json")
    if current is None:
        return None
    return decode_record(FrozenGeneration, current[0].get("generation")), current[1]


def _pending(store: Store) -> tuple[FrozenGeneration, ObjectStat] | None:
    current = read_control(store, "pending.json")
    if current is None:
        return None
    return decode_record(FrozenGeneration, current[0].get("generation")), current[1]


def acquire(store: Store, *, owner: str) -> Ownership:
    text(owner, "runner identity")
    current = read_control(store, "ownership.json")
    completed = _completion(store)
    if current is not None:
        if current[0].get("status") != "idle":
            raise StateError("An owner already holds publication rights")
        if current[0].get("completion") != (completed[0].id if completed else None):
            raise StateError("The prior private completion is missing or changed")
    elif completed is not None or _pending(store) is not None:
        raise StateError("Missing ownership is not a new repository")
    nonce, acquired = uuid.uuid4().hex, utc_now().isoformat()
    receipt = write_control(
        store,
        "ownership.json",
        {
            "status": "active",
            "nonce": nonce,
            "runner": owner,
            "acquired_at": acquired,
            "completion": completed[0].id if completed else None,
        },
        expected=current[1].etag if current else None,
    )
    return Ownership(nonce, receipt.etag, owner, acquired)


def release(store: Store, ownership: Ownership) -> None:
    check_owner(store, ownership)
    pending, completed = _pending(store), _completion(store)
    if pending is not None and (completed is None or pending[0] != completed[0]):
        raise StateError("A pending generation prevents release")
    write_control(
        store,
        "ownership.json",
        {
            "status": "idle",
            "nonce": uuid.uuid4().hex,
            "runner": ownership.runner_identity,
            "acquired_at": utc_now().isoformat(),
            "completion": completed[0].id if completed else None,
        },
        expected=ownership.etag,
    )


def _file_ref(path: Path, key: str) -> ObjectRef:
    sha, size = sha256_file(path)
    return ObjectRef("private", key, "private", size, sha, "application/octet-stream", "no-store")


def _metadata_paths(
    retained: RetainedFormat,
    move: Callable[[str, str, ObjectRef | None], str],
    *,
    restoring: bool = False,
) -> RetainedFormat:
    metadata = dict(retained.metadata)
    refs = {ref.key: ref for ref in retained.objects}
    name = retained.format
    if not metadata:
        return retained
    for field in {
        "apt": ("files",),
        "rpm": (),
        "arch": ("paths",),
        "apk": (),
        "flatpak": ("files",),
    }[name]:
        metadata[field] = {
            key: move(
                text(path, "native metadata path"), f"{name}/native/{safe_key(key)}", refs[key]
            )
            for key, path in mapping(metadata.get(field)).items()
        }
    if name == "rpm":
        root = text(metadata.get("root"), "RPM root")
        token = "rpm/native"
        if restoring:
            metadata["root"] = move(root, token, None)
        else:
            for ref in retained.objects:
                path = safe_path(Path(root), ref.key)
                if ref.object_class != "package" and path.is_file():
                    move(str(path), f"{token}/{ref.key}", ref)
            metadata["root"] = token
    if name == "apk":
        indexes = mapping(metadata.get("indexes"))
        changed: dict[str, JSONValue] = {}
        for arch, value in indexes.items():
            record = dict(mapping(value))
            key = f"{safe_key(arch)}/APKINDEX.tar.gz"
            record["local_path"] = move(
                text(record.get("local_path"), "APK index path"), f"apk/native/{key}", refs[key]
            )
            changed[arch] = record
        metadata["indexes"] = changed
    field = "keyring" if name in {"apt", "rpm"} else "public_key"
    value = metadata.get(field)
    if isinstance(value, dict):
        record = dict(value)
        record["local_path"] = move(
            text(record.get("local_path"), "public key path"),
            f"{name}/trust",
            refs.get("keys/haberdasher.rsa.pub"),
        )
        metadata[field] = record
    elif name != "flatpak":
        metadata[field] = move(text(value, "public key path"), f"{name}/trust", None)
    history = tuple(
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
        for asset in retained.accepted_history
    )
    return replace(retained, metadata=metadata, accepted_history=history)


def _validate_generation(generation: PreparedGeneration) -> None:
    decode_record(PreparedGeneration, core.json_value(generation))
    decode_record(discovery.DiscoveryState, generation.scan.get("state"))
    policies = mapping(generation.scan.get("policies"))
    if set(policies) != {item.format for item in generation.formats}:
        raise ValueError("Frozen policies differ from selected formats")
    if set(generation.public_inventories) != set(policies):
        raise ValueError("Frozen inventories differ from selected formats")
    for prepared in generation.formats:
        policy = decode_record(config.FormatPolicy, policies[prepared.format])
        if policy.format != prepared.format:
            raise ValueError("Frozen policy format mismatch")
        expected = core.public_inventory(
            prepared.retained.accepted_history,
            (
                *prepared.referenced_objects,
                *(
                    ref
                    for ref in generation.bootstrap_objects
                    if ref.bucket_role == prepared.format
                ),
            ),
        )
        if generation.public_inventories[prepared.format] != expected:
            raise ValueError("Public inventory differs from its explicit allow-list")
        refs = {ref.key: ref for ref in prepared.referenced_objects}
        if len(refs) != len(prepared.referenced_objects) or tuple(
            prepared.retained.objects
        ) != tuple(prepared.referenced_objects):
            raise ValueError("Prepared references differ from retained objects")
        entry = False
        for output in prepared.outputs:
            if refs.get(output.ref.key) != output.ref or output.ref.object_class == "inventory":
                raise ValueError("Prepared output is not a declared native object")
            if output.ref.object_class == "entry":
                entry = True
            elif entry:
                raise ValueError("Dependencies and packages must precede entries")


def freeze(store: Store, ownership: Ownership, generation: PreparedGeneration) -> FrozenGeneration:
    check_owner(store, ownership)
    _validate_generation(generation)
    if generation.owner_nonce != ownership.owner_nonce:
        raise StateError("Generation belongs to another owner")
    FrozenGeneration(generation.id, EMPTY_HASH)
    completed, pending = _completion(store), _pending(store)
    previous = (completed[0].id, completed[1].etag) if completed else (None, None)
    if previous != (generation.previous_completion_id, generation.previous_completion_etag):
        raise StateError("Generation does not extend the current completion")
    if pending is not None and (completed is None or pending[0] != completed[0]):
        raise StateError("An unresolved generation already exists")
    committed_formats: dict[str, RetainedFormat] = {}
    committed_bootstrap: tuple[ObjectRef, ...] = ()
    bootstrap_etags: dict[str, str] = {}
    if completed is not None:
        with tempfile.TemporaryDirectory(prefix="hd-prior-") as temporary:
            committed = load_committed(store, ownership, out=Path(temporary) / "committed")
        if (committed.generation_id, committed.completion_etag) != previous:
            raise StateError("Previous completion changed during freeze")
        committed_formats = {item.format: item for item in committed.formats}
        committed_bootstrap = committed.bootstrap_objects
        bootstrap_etags = committed.bootstrap_etags
        if committed.signing_fingerprint not in (None, generation.signing_fingerprint):
            raise StateError("Signing fingerprint changes require explicit rotation approval")
    if not set(committed_bootstrap).issubset(generation.bootstrap_objects):
        raise StateError("Committed bootstrap references cannot change or disappear")
    files: dict[str, JSONValue] = {}

    def capture(filename: str, token: str, public: ObjectRef | None) -> str:
        path = Path(filename)
        ref = _file_ref(path, f"generations/{generation.id}/files/{safe_key(token)}")
        if public is not None and (ref.sha256, ref.size) != (public.sha256, public.size):
            raise StateError("Native metadata differs from its public reference")
        if token in files:
            if files[token] != core.json_value(ref):
                raise StateError("Conflicting frozen path")
            return token
        check_owner(store, ownership)
        store.create(ref, path)
        with tempfile.TemporaryDirectory(prefix="hd-freeze-") as temporary:
            store.download(ref, Path(temporary) / "verified")
        files[token] = core.json_value(ref)
        return token

    formats: list[core.PreparedFormat] = []
    prior_etags: dict[str, JSONValue] = {}
    for prepared in generation.formats:
        retained = _metadata_paths(prepared.retained, capture)
        outputs = tuple(
            replace(
                output,
                local_path=Path(
                    capture(
                        str(output.local_path),
                        f"{prepared.format}/outputs/{output.ordinal}",
                        output.ref,
                    )
                ),
            )
            for output in prepared.outputs
        )
        changed = {output.ref.key for output in outputs}
        etags = mapping(prepared.retained.metadata.get("etags", {}))
        prior = committed_formats.get(prepared.format)
        prior_refs = {ref.key: ref for ref in prior.objects} if prior is not None else {}
        committed_etags = mapping(prior.metadata.get("etags", {})) if prior is not None else {}
        for ref in prepared.referenced_objects:
            if ref.key not in changed:
                if prior_refs.get(ref.key) != ref:
                    raise StateError(
                        "Unchanged public reference differs from its committed reference"
                    )
                observed = store.stat(ref)
                if (
                    observed is None
                    or observed.size != ref.size
                    or etags.get(ref.key) != observed.etag
                    or committed_etags.get(ref.key) != observed.etag
                ):
                    raise StateError("Unchanged public reference lacks its exact prior ETag")
                prior_etags[f"{ref.bucket_role}/{ref.key}"] = observed.etag
        formats.append(replace(prepared, retained=retained, outputs=outputs))
    bootstrap_outputs = tuple(
        replace(
            output,
            local_path=Path(
                capture(str(output.local_path), f"bootstrap/{output.ordinal}", output.ref)
            ),
        )
        for output in generation.bootstrap_outputs
    )
    changed_bootstrap = {output.ref for output in bootstrap_outputs}
    for ref in generation.bootstrap_objects:
        key = f"{ref.bucket_role}/{ref.key}"
        if ref in changed_bootstrap:
            if ref in committed_bootstrap:
                raise StateError("Committed bootstrap objects must not be rewritten")
            continue
        if ref not in committed_bootstrap:
            raise StateError("Unchanged bootstrap reference is not committed")
        observed = store.stat(ref)
        if (
            observed is None
            or observed.size != ref.size
            or observed.etag != bootstrap_etags.get(key)
        ):
            raise StateError("Unchanged bootstrap reference lacks its exact prior ETag")
        prior_etags[key] = observed.etag
    frozen = replace(
        generation,
        formats=tuple(formats),
        bootstrap_outputs=bootstrap_outputs,
        frozen_manifest_hash=EMPTY_HASH,
    )
    data = canonical_json(
        {
            "schema_version": 1,
            "generation": core.json_value(frozen),
            "files": files,
            "prior_etags": prior_etags,
        }
    )
    if len(data) > MAX_CONTROL_BYTES:
        raise ValueError("Frozen manifest exceeds its size limit")
    ref = private_ref(f"generations/{generation.id}/manifest.json", data)
    with tempfile.TemporaryDirectory(prefix="hd-manifest-") as temporary:
        path = Path(temporary) / "manifest"
        atomic_write(path, data)
        check_owner(store, ownership)
        store.create(ref, path)
        store.download(ref, Path(temporary) / "verified")
    locator = FrozenGeneration(generation.id, ref.sha256)
    write_control(
        store,
        f"generations/{generation.id}/journal.json",
        {
            "generation": core.json_value(locator),
            "writes": {},
        },
        expected=None,
    )
    check_owner(store, ownership)
    write_control(
        store,
        "pending.json",
        {"generation": core.json_value(locator)},
        expected=pending[1].etag if pending else None,
    )
    return locator


def load_frozen(
    store: Store, frozen: FrozenGeneration, *, out: Path, materialise_outputs: bool = True
) -> tuple[PreparedGeneration, dict[str, JSONValue]]:
    frozen.__post_init__()
    result = store.read_private(
        f"generations/{frozen.id}/manifest.json", max_bytes=MAX_CONTROL_BYTES
    )
    if result is None or hashlib.sha256(result[0]).hexdigest() != frozen.manifest_hash:
        raise StateError("Frozen manifest is absent or changed")
    manifest = parse(result[0])
    generation = decode_record(PreparedGeneration, manifest.get("generation"))
    if generation.id != frozen.id or generation.frozen_manifest_hash != EMPTY_HASH:
        raise StateError("Frozen generation identity changed")
    _validate_generation(generation)
    out = safe_path(out.parent, out.name)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = mapping(manifest.get("files"))
    output_tokens: set[str] = set()
    for prepared in generation.formats:
        for output in prepared.outputs:
            token = f"{prepared.format}/outputs/{output.ordinal}"
            if str(output.local_path) != token or token not in files:
                raise StateError("Frozen output path is missing or changed")
            output_tokens.add(token)
    for output in generation.bootstrap_outputs:
        token = f"bootstrap/{output.ordinal}"
        if str(output.local_path) != token or token not in files:
            raise StateError("Frozen bootstrap path is missing or changed")
        output_tokens.add(token)
    for token, value in files.items():
        path = safe_path(out, token)
        ref = decode_record(ObjectRef, value)
        if ref.bucket_role != "private" or ref.key != f"generations/{frozen.id}/files/{token}":
            raise StateError("Frozen file escapes its private generation")
        if not materialise_outputs and token in output_tokens:
            continue
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        store.download(ref, path)

    def restore(token: str, expected: str, public: ObjectRef | None) -> str:
        if token != expected:
            raise StateError("Frozen native path differs from its declared location")
        path = safe_path(out, token)
        if expected != "rpm/native":
            if token not in files:
                raise StateError("Frozen native file is missing")
            if public is not None and sha256_file(path) != (public.sha256, public.size):
                raise StateError("Restored native file differs from its public reference")
        return str(path)

    formats: list[core.PreparedFormat] = []
    for prepared in generation.formats:
        retained = _metadata_paths(prepared.retained, restore, restoring=True)
        outputs: list[core.OutputObject] = []
        for output in prepared.outputs:
            token = f"{prepared.format}/outputs/{output.ordinal}"
            path = (
                restore(str(output.local_path), token, output.ref)
                if materialise_outputs
                else str(safe_path(out, token))
            )
            outputs.append(replace(output, local_path=Path(path)))
        formats.append(replace(prepared, retained=retained, outputs=tuple(outputs)))
    bootstrap_outputs = tuple(
        replace(
            output,
            local_path=Path(
                restore(str(output.local_path), f"bootstrap/{output.ordinal}", output.ref)
                if materialise_outputs
                else str(safe_path(out, f"bootstrap/{output.ordinal}"))
            ),
        )
        for output in generation.bootstrap_outputs
    )
    return replace(
        generation,
        formats=tuple(formats),
        bootstrap_outputs=bootstrap_outputs,
        frozen_manifest_hash=frozen.manifest_hash,
    ), manifest


def read_journal(store: Store, frozen: FrozenGeneration) -> tuple[dict[str, JSONValue], ObjectStat]:
    current = read_control(store, f"generations/{frozen.id}/journal.json")
    if current is None or decode_record(FrozenGeneration, current[0].get("generation")) != frozen:
        raise StateError("Generation journal is missing or changed")
    mapping(current[0].get("writes"))
    return current


def journal_write(
    store: Store,
    ownership: Ownership,
    frozen: FrozenGeneration,
    ordinal: int,
    value: dict[str, JSONValue],
) -> None:
    check_owner(store, ownership)
    current, stat = read_journal(store, frozen)
    writes = dict(mapping(current["writes"]))
    writes[str(ordinal)] = value
    write_control(
        store,
        f"generations/{frozen.id}/journal.json",
        {**current, "writes": writes},
        expected=stat.etag,
    )


def publication_outputs(
    generation: PreparedGeneration, *, out: Path
) -> tuple[core.OutputObject, ...]:
    outputs = list(generation.bootstrap_outputs)
    inventory_etags = mapping(generation.scan.get("inventory_etags", {}))
    for prepared in generation.formats:
        outputs.extend(prepared.outputs)
        data = canonical_json(generation.public_inventories[prepared.format])
        path = safe_path(out, f"{prepared.format}-inventory.json")
        atomic_write(path, data)
        ref = ObjectRef(
            prepared.format,
            "haberdasher.json",
            "inventory",
            len(data),
            hashlib.sha256(data).hexdigest(),
            "application/json",
            "no-cache",
        )
        etag = inventory_etags.get(prepared.format)
        if etag is not None:
            text(etag, "inventory ETag")
        outputs.append(
            core.OutputObject(
                ref,
                path,
                "create" if etag is None else "replace",
                cast(str | None, etag),
                len(outputs),
            )
        )
    return tuple(outputs)


def load_committed(store: Store, ownership: Ownership, *, out: Path) -> CommittedState:
    owner = check_owner(store, ownership)
    completed = _completion(store)
    pending = _pending(store)
    if pending is not None and (completed is None or pending[0] != completed[0]):
        raise StateError("Replay the pending generation before reconciliation")
    if completed is None:
        if owner.get("completion") is not None:
            raise StateError("Missing private completion is not a bootstrap")
        return CommittedState(None, None, discovery.DiscoveryState(), (), None, None, {})
    generation, manifest = load_frozen(store, completed[0], out=out, materialise_outputs=False)
    journal, _ = read_journal(store, completed[0])
    writes = mapping(journal["writes"])
    etags = dict(mapping(manifest.get("prior_etags")))
    inventory_etags: dict[str, str] = {}
    for ordinal, output in enumerate(publication_outputs(generation, out=out)):
        record = mapping(writes.get(str(ordinal)))
        if record.get("status") != "ack" or record.get("sha256") != output.ref.sha256:
            raise StateError("Private completion lacks a verified write acknowledgement")
        etag = text(record.get("etag"), "write ETag")
        etags[f"{output.ref.bucket_role}/{output.ref.key}"] = etag
        if output.ref.object_class == "inventory":
            observed = store.stat(output.ref)
            if observed is None or observed.etag != etag or observed.size != output.ref.size:
                raise StateError("Committed public inventory changed")
            inventory_etags[output.ref.bucket_role] = etag
    formats: list[RetainedFormat] = []
    for prepared in generation.formats:
        observed_etags: dict[str, JSONValue] = {}
        for ref in prepared.referenced_objects:
            observed = store.stat(ref)
            if (
                observed is None
                or observed.size != ref.size
                or observed.etag != etags.get(f"{ref.bucket_role}/{ref.key}")
            ):
                raise StateError("Committed public reference is missing or changed")
            observed_etags[ref.key] = observed.etag
        metadata = dict(prepared.retained.metadata)
        if metadata:
            metadata["etags"] = observed_etags
            if prepared.format == "apk":
                metadata["indexes"] = {
                    arch: {**mapping(value), "etag": observed_etags[f"{arch}/APKINDEX.tar.gz"]}
                    for arch, value in mapping(metadata.get("indexes")).items()
                }
        formats.append(
            replace(
                prepared.retained,
                prior_generation=(generation.id if metadata else None),
                metadata=metadata,
            )
        )
    bootstrap_etags: dict[str, str] = {}
    for ref in generation.bootstrap_objects:
        key = f"{ref.bucket_role}/{ref.key}"
        observed = store.download(ref, out / "verified-bootstrap")
        if observed.etag != etags.get(key):
            raise StateError("Committed bootstrap reference is missing or changed")
        bootstrap_etags[key] = observed.etag
    return CommittedState(
        generation.id,
        completed[1].etag,
        decode_record(discovery.DiscoveryState, generation.scan.get("state")),
        tuple(formats),
        generation.config_digest,
        generation.policy_digest,
        inventory_etags,
        generation.bootstrap_objects,
        bootstrap_etags,
        generation.signing_fingerprint,
    )


def recover_owner(store: Store, *, expected_nonce: str, evidence: RecoveryEvidence) -> Ownership:
    evidence.__post_init__()
    text(expected_nonce, "expected owner nonce")
    current = read_control(store, "ownership.json")
    if (
        current is None
        or current[0].get("status") != "active"
        or current[0].get("nonce") != expected_nonce
    ):
        raise StateError("Recovery does not match the current owner")
    pending = _pending(store)
    resolutions = {item.ordinal: item for item in evidence.writes}
    updates: dict[int, dict[str, JSONValue]] = {}
    if pending is not None:
        with tempfile.TemporaryDirectory(prefix="hd-recovery-") as temporary:
            root = Path(temporary)
            generation, _ = load_frozen(store, pending[0], out=root / "frozen")
            outputs = publication_outputs(generation, out=root)
            journal, _ = read_journal(store, pending[0])
            for key, value in mapping(journal["writes"]).items():
                record = mapping(value)
                if record.get("status") == "ack":
                    continue
                if not key.isdecimal() or int(key) >= len(outputs):
                    raise StateError("Invalid unresolved write ordinal")
                ordinal = int(key)
                resolution = resolutions.pop(ordinal, None)
                if resolution is None:
                    raise StateError("Outstanding write needs explicit resolution evidence")
                output = outputs[ordinal]
                if resolution.outcome == "written":
                    observed = store.download(output.ref, root / "resolved")
                    if observed.etag != resolution.etag:
                        raise StateError("Resolved write ETag differs from evidence")
                    updates[ordinal] = {
                        "status": "ack",
                        "sha256": output.ref.sha256,
                        "etag": observed.etag,
                        "evidence": evidence.reference,
                    }
                else:
                    observed = store.stat(output.ref)
                    if (output.mode == "create" and observed is not None) or (
                        output.mode == "replace"
                        and (observed is None or observed.etag != output.expected_etag)
                    ):
                        raise StateError("Resolved absence differs from the original precondition")
                    updates[ordinal] = {"status": "retry", "evidence": evidence.reference}
    if resolutions:
        raise StateError("Evidence names a write that is not outstanding")
    nonce, acquired = uuid.uuid4().hex, utc_now().isoformat()
    receipt = write_control(
        store,
        "ownership.json",
        {
            **current[0],
            "nonce": nonce,
            "runner": evidence.runner_identity,
            "acquired_at": acquired,
            "recovery": core.json_value(evidence),
        },
        expected=current[1].etag,
    )
    ownership = Ownership(nonce, receipt.etag, evidence.runner_identity, acquired)
    if pending is not None:
        for ordinal, value in updates.items():
            journal_write(store, ownership, pending[0], ordinal, value)
    return ownership


def complete(
    store: Store,
    ownership: Ownership,
    frozen: FrozenGeneration,
    generation: PreparedGeneration,
    *,
    clock: Callable[[], datetime] | None = None,
) -> None:
    check_owner(store, ownership)
    pending = _pending(store)
    if pending is None or pending[0] != frozen:
        raise StateError("Completion does not match the pending generation")
    journal, _ = read_journal(store, frozen)
    writes = mapping(journal["writes"])
    with tempfile.TemporaryDirectory(prefix="hd-complete-") as temporary:
        outputs = publication_outputs(generation, out=Path(temporary))
        if set(writes) != {str(index) for index in range(len(outputs))}:
            raise StateError("Completion requires every public write acknowledgement")
        for ordinal, output in enumerate(outputs):
            record = mapping(writes[str(ordinal)])
            observed = store.stat(output.ref)
            if (
                record.get("status") != "ack"
                or record.get("sha256") != output.ref.sha256
                or observed is None
                or observed.size != output.ref.size
                or observed.etag != record.get("etag")
            ):
                raise StateError("Completion requires unchanged acknowledged public objects")
    current = _completion(store)
    if current is not None and current[0] == frozen:
        return
    previous = (current[0].id, current[1].etag) if current else (None, None)
    if previous != (generation.previous_completion_id, generation.previous_completion_etag):
        raise StateError("Completion precondition changed")
    check_expiry(generation, (core.utc_now if clock is None else clock)())
    write_control(
        store,
        "completed.json",
        {"generation": core.json_value(frozen)},
        expected=generation.previous_completion_etag,
    )


def pending_generation(store: Store) -> FrozenGeneration | None:
    pending = _pending(store)
    return pending[0] if pending else None


def check_expiry(generation: PreparedGeneration, now: datetime) -> None:
    now = utc_now(lambda: now)
    for prepared in generation.formats:
        if (
            prepared.format == "apt"
            and prepared.expires_at is not None
            and datetime.fromisoformat(prepared.expires_at) <= now
        ):
            raise StateError("Frozen APT metadata expired; explicit regeneration is required")
