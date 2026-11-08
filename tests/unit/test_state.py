from __future__ import annotations

import base64
import hashlib
import shutil
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from haberdasher import core, publish, state
from haberdasher.config import FormatPolicy, StoragePolicy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    JSONValue,
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
)
from haberdasher.discovery import DiscoveryState
from haberdasher.runtime import Runtime
from haberdasher.storage import LocalStore, StorageError

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def local_store(root: Path) -> LocalStore:
    return LocalStore(
        StoragePolicy(
            "local", str(root / "private"), {name: str(root / name) for name in core.FORMATS}
        )
    )


def object_ref(path: Path, key: str, kind: str = "entry", name: str = "apt") -> ObjectRef:
    sha, size = core.sha256_file(path)
    return ObjectRef(name, key, kind, size, sha, "application/octet-stream", "no-cache")


def generation(
    root: Path,
    owner: Ownership,
    *,
    name: str = "apt",
    identifier: str = "generation-one",
    bootstrap: bool = False,
) -> PreparedGeneration:
    root.mkdir(mode=0o700, parents=True)
    package = root / "package"
    dependency = root / "dependency"
    entry = root / "entry"
    trust = root / "trust"
    for path in (package, dependency, entry, trust):
        core.atomic_write(path, path.name.encode())
    source = SourceAsset(
        "test/project", 1, 1, "test.deb", 7, NOW.isoformat(), "https://example.invalid/test.deb"
    )
    verified = VerifiedAsset(source, package, core.sha256_file(package)[0], 7, 2, "a" * 64)
    asset = AdmittedAsset(
        InspectedAsset(verified, NativeIdentity(name, "test", "amd64", "1"), {}, {}, "unsigned"),
        "preserve",
        "history",
        verified.sha256,
    )
    outputs = tuple(
        OutputObject(object_ref(path, key, kind, name), path, "create", None, index)
        for index, (path, key, kind) in enumerate(
            (
                (package, "pool/package", "package"),
                (dependency, "metadata/dependency", "dependency"),
                (entry, "metadata/entry", "entry"),
            )
        )
    )
    metadata: dict[str, JSONValue] = {
        "files": {"metadata/entry": str(entry)},
        "keyring": str(trust),
        "keyring_sha256": core.sha256_file(trust)[0],
        "fingerprint": "A" * 40,
        "expires_at": "2026-01-08T00:00:00+00:00",
        "policy": {},
        "etags": {},
    }
    retained = RetainedFormat(
        name,
        None,
        (asset,),
        (asset.inspected.identity,),
        metadata,
        tuple(output.ref for output in outputs),
    )
    prepared = PreparedFormat(
        name,
        retained,
        outputs,
        retained.objects,
        "2026-01-08T00:00:00+00:00" if name == "apt" else None,
    )
    bootstrap_outputs: tuple[OutputObject, ...] = ()
    if bootstrap:
        bootstrap_outputs = tuple(
            OutputObject(
                object_ref(trust, f"keys/haberdasher.{suffix}", "dependency", name),
                trust,
                "create",
                None,
                index,
            )
            for index, suffix in enumerate(("asc", "gpg"))
        )
    bootstrap_objects = tuple(output.ref for output in bootstrap_outputs)
    return PreparedGeneration(
        identifier,
        None,
        None,
        owner.owner_nonce,
        "b" * 64,
        "c" * 64,
        {
            "state": core.json_value(DiscoveryState()),
            "policies": {name: core.json_value(FormatPolicy(name))},
        },
        (prepared,),
        {
            name: core.public_inventory(
                retained.accepted_history, (*retained.objects, *bootstrap_objects)
            )
        },
        state.EMPTY_HASH,
        bootstrap_outputs,
        bootstrap_objects,
        "A" * 40 if bootstrap else None,
    )


def next_generation(
    root: Path,
    owner: Ownership,
    committed: state.CommittedState,
    *,
    identifier: str = "generation-two",
) -> PreparedGeneration:
    root.mkdir(mode=0o700, parents=True)
    retained = committed.formats[0]
    previous = next(ref for ref in retained.objects if ref.object_class == "entry")
    path = root / "new-entry"
    core.atomic_write(path, b"entry two")
    ref = object_ref(path, previous.key)
    etags = state.mapping(retained.metadata["etags"])
    output = OutputObject(ref, path, "replace", str(etags[ref.key]), 0)
    retained = replace(
        retained,
        metadata={**retained.metadata, "files": {ref.key: str(path)}},
        objects=tuple(ref if item.key == ref.key else item for item in retained.objects),
    )
    prepared = PreparedFormat(
        "apt", retained, (output,), retained.objects, "2026-01-08T00:00:00+00:00"
    )
    return PreparedGeneration(
        identifier,
        committed.generation_id,
        committed.completion_etag,
        owner.owner_nonce,
        "b" * 64,
        "c" * 64,
        {
            "state": core.json_value(committed.discovery),
            "policies": {"apt": core.json_value(FormatPolicy("apt"))},
            "inventory_etags": core.json_value(committed.inventory_etags),
        },
        (prepared,),
        {
            "apt": core.public_inventory(
                retained.accepted_history, (*retained.objects, *committed.bootstrap_objects)
            )
        },
        state.EMPTY_HASH,
        (),
        committed.bootstrap_objects,
        committed.signing_fingerprint,
    )


def test_typed_roundtrip_and_rejection(tmp_path: Path) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    assert state.decode_record(PreparedGeneration, core.json_value(original)) == original
    legacy = state.mapping(core.json_value(original))
    for field in ("bootstrap_objects", "bootstrap_outputs", "signing_fingerprint"):
        legacy.pop(field)
    assert state.decode_record(PreparedGeneration, legacy) == original
    encoded = state.mapping(core.json_value(original))
    encoded["unexpected"] = True
    with pytest.raises(ValueError, match="fields"):
        state.decode_record(PreparedGeneration, encoded)
    encoded.pop("unexpected")
    formats = cast(list[JSONValue], encoded["formats"])
    outputs = cast(list[JSONValue], state.mapping(formats[0])["outputs"])
    state.mapping(outputs[0])["ordinal"] = True
    with pytest.raises(ValueError, match="type"):
        state.decode_record(PreparedGeneration, encoded)
    with pytest.raises(ValueError, match="Duplicate"):
        state.parse(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match="Non-finite"):
        state.parse(b'{"schema_version":1,"value":NaN}')


def test_snapshot_has_private_bytes_and_explicit_public_inventory(tmp_path: Path) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    frozen = state.freeze(store, owner, original)
    loaded, manifest = state.load_frozen(store, frozen, out=tmp_path / "restored")
    assert loaded.frozen_manifest_hash == frozen.manifest_hash
    assert loaded.formats[0].outputs[0].local_path.read_bytes() == b"package"
    assert Path(str(loaded.formats[0].retained.metadata["keyring"])).read_bytes() == b"trust"
    assert state.mapping(manifest["files"])
    inventory = core.canonical_json(loaded.public_inventories)
    for forbidden in (str(tmp_path).encode(), b"checksum_sha256", b"owner_nonce", b"local_path"):
        assert forbidden not in inventory
    assert not (tmp_path / "store/apt/metadata/entry").exists()
    with pytest.raises(state.StateError, match="pending"):
        state.release(store, owner)


def test_changed_source_fails_before_publication(tmp_path: Path) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    original.formats[0].outputs[0].local_path.write_bytes(b"changed")
    with pytest.raises(state.StateError, match="differs"):
        state.freeze(store, owner, original)
    assert list((tmp_path / "store/apt").iterdir()) == []
    assert state.read_control(store, "completed.json") is None


def test_inventory_and_order_fail_closed(tmp_path: Path) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    with pytest.raises(ValueError, match="allow-list"):
        state.freeze(
            store, owner, replace(original, public_inventories={"apt": {"path": "/private"}})
        )
    prepared = original.formats[0]
    reordered = tuple(
        replace(output, ordinal=index) for index, output in enumerate(reversed(prepared.outputs))
    )
    with pytest.raises(ValueError, match="precede"):
        state.freeze(
            store, owner, replace(original, formats=(replace(prepared, outputs=reordered),))
        )


def test_private_manifest_hash_is_not_optional(tmp_path: Path) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    frozen = state.freeze(store, owner, generation(tmp_path / "input", owner))
    with pytest.raises(state.StateError, match="manifest"):
        state.load_frozen(
            store,
            replace(frozen, manifest_hash=hashlib.sha256(b"wrong").hexdigest()),
            out=tmp_path / "restored",
        )


@pytest.mark.parametrize("name", sorted(core.FORMATS))
def test_all_native_metadata_layouts_restore_private_paths(tmp_path: Path, name: str) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner, name=name)
    prepared = original.formats[0]
    outputs = prepared.outputs
    trust = tmp_path / "input/trust"
    fingerprint = "A" * 40
    metadata: dict[str, JSONValue]
    if name == "apt":
        metadata = prepared.retained.metadata
    elif name == "rpm":
        native = tmp_path / "input/native"
        for output in outputs[1:]:
            path = core.safe_path(native, output.ref.key)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(output.local_path, path)
        metadata = {
            "root": str(native),
            "keyring": str(trust),
            "keyring_sha256": core.sha256_file(trust)[0],
            "fingerprint": fingerprint,
        }
    elif name == "arch":
        metadata = {
            "paths": {outputs[-1].ref.key: str(outputs[-1].local_path)},
            "records": {"test": {"desc": "native record", "files": "file list"}},
            "public_key": str(trust),
            "fingerprint": fingerprint,
        }
    elif name == "apk":
        outputs = (
            outputs[0],
            replace(outputs[1], ref=replace(outputs[1].ref, key="keys/haberdasher.rsa.pub")),
            replace(outputs[2], ref=replace(outputs[2].ref, key="x86_64/APKINDEX.tar.gz")),
        )

        def file_record(output: OutputObject) -> dict[str, JSONValue]:
            return {
                "local_path": str(output.local_path),
                "sha256": output.ref.sha256,
                "size": output.ref.size,
            }

        metadata = {
            "indexes": {"x86_64": file_record(outputs[2])},
            "public_key": file_record(outputs[1]),
        }
    else:
        metadata = {
            "files": {output.ref.key: str(output.local_path) for output in outputs},
            "heads": {"app/test/x86_64/stable": "a" * 64},
            "public_key": base64.b64encode(b"synthetic public key").decode(),
            "fingerprint": fingerprint,
            "policy": {"format": "flatpak"},
            "etags": {},
        }
    refs = tuple(output.ref for output in outputs)
    retained = replace(prepared.retained, metadata=metadata, objects=refs)
    prepared = replace(prepared, retained=retained, outputs=outputs, referenced_objects=refs)
    original = replace(
        original,
        formats=(prepared,),
        public_inventories={name: core.public_inventory(retained.accepted_history, refs)},
    )
    frozen = state.freeze(store, owner, original)
    shutil.rmtree(tmp_path / "input")
    loaded, manifest = state.load_frozen(store, frozen, out=tmp_path / "restored")
    restored = loaded.formats[0].retained.metadata
    if name == "rpm":
        assert (Path(str(restored["root"])) / "metadata/entry").read_bytes() == b"entry"
        assert Path(str(restored["keyring"])).read_bytes() == b"trust"
    elif name == "apk":
        record = state.mapping(state.mapping(restored["indexes"])["x86_64"])
        assert Path(str(record["local_path"])).read_bytes() == b"entry"
        public_key = state.mapping(restored["public_key"])
        assert Path(str(public_key["local_path"])).read_bytes() == b"dependency"
    else:
        field = "paths" if name == "arch" else "files"
        for key, value in state.mapping(restored[field]).items():
            ref = next(ref for ref in refs if ref.key == key)
            assert core.sha256_file(Path(str(value))) == (ref.sha256, ref.size)
        if name == "flatpak":
            assert restored["public_key"] == metadata["public_key"]
            assert restored["heads"] == metadata["heads"]
        elif name == "arch":
            assert restored["records"] == metadata["records"]
    assert str(tmp_path / "input").encode() not in core.canonical_json(manifest)


@pytest.mark.parametrize(("suite", "component"), [("outputs", "main"), ("stable", "outputs")])
def test_apt_outputs_tokens_restore_native_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suite: str, component: str
) -> None:
    from tests.unit.test_publish import AdapterDouble

    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    prepared = original.formats[0]
    package, index, release = prepared.outputs
    index_key = f"dists/{suite}/{component}/binary-amd64/Packages"
    core.atomic_write(
        index.local_path,
        (
            "Package: test\nVersion: 1\nArchitecture: amd64\n"
            f"Filename: {package.ref.key}\nSize: {package.ref.size}\n"
            f"SHA256: {package.ref.sha256}\n\n"
        ).encode(),
    )
    index = replace(index, ref=object_ref(index.local_path, index_key, "dependency"))
    core.atomic_write(
        release.local_path,
        (
            f"Suite: {suite}\nComponents: {component}\nArchitectures: amd64\nSHA256:\n"
            f" {index.ref.sha256} {index.ref.size} {component}/binary-amd64/Packages\n"
        ).encode(),
    )
    release = replace(release, ref=object_ref(release.local_path, f"dists/{suite}/Release"))
    outputs = (package, index, release)
    refs = tuple(output.ref for output in outputs)
    retained = replace(
        prepared.retained,
        objects=refs,
        metadata={
            **prepared.retained.metadata,
            "files": {output.ref.key: str(output.local_path) for output in outputs[1:]},
        },
    )
    original = replace(
        original,
        formats=(replace(prepared, retained=retained, outputs=outputs, referenced_objects=refs),),
        scan={
            **original.scan,
            "policies": {"apt": core.json_value(FormatPolicy("apt", ("amd64",), suite, component))},
        },
        public_inventories={"apt": core.public_inventory(retained.accepted_history, refs)},
    )
    frozen = state.freeze(store, owner, original)
    for materialise in (True, False):
        loaded, _ = state.load_frozen(
            store, frozen, out=tmp_path / str(materialise), materialise_outputs=materialise
        )
        for output in loaded.formats[0].outputs:
            assert output.local_path.exists() is materialise
        for key, value in state.mapping(loaded.formats[0].retained.metadata["files"]).items():
            ref = next(ref for ref in refs if ref.key == key)
            assert core.sha256_file(Path(str(value))) == (ref.sha256, ref.size)
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    publish.replay(
        frozen,
        store=store,
        ownership=owner,
        runtime=Runtime(tmp_path / "runtime", environ={}),
        now=NOW,
        clock=lambda: NOW,
    )
    owner = state.acquire(store, owner="next")
    committed = state.load_committed(store, owner, out=tmp_path / "committed")
    assert committed.formats[0].objects == refs


@pytest.mark.parametrize("materialise", [False, True])
def test_frozen_output_cannot_claim_a_native_token(tmp_path: Path, materialise: bool) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    frozen = state.freeze(store, owner, generation(tmp_path / "input", owner))
    key = f"generations/{frozen.id}/manifest.json"
    current = state.read_control(store, key)
    assert current is not None
    manifest, observed = current
    original = state.decode_record(PreparedGeneration, manifest["generation"])
    prepared = original.formats[0]
    output = replace(prepared.outputs[-1], local_path=Path("apt/native/metadata/entry"))
    altered = replace(
        original, formats=(replace(prepared, outputs=(*prepared.outputs[:-1], output)),)
    )
    receipt = state.write_control(
        store, key, {**manifest, "generation": core.json_value(altered)}, expected=observed.etag
    )
    with pytest.raises(state.StateError, match="Frozen output path"):
        state.load_frozen(
            store,
            replace(frozen, manifest_hash=receipt.sha256),
            out=tmp_path / "restored",
            materialise_outputs=materialise,
        )


@pytest.fixture
def committed_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[LocalStore, Ownership, state.CommittedState]:
    from tests.unit.test_publish import AdapterDouble

    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    frozen = state.freeze(store, owner, generation(tmp_path / "input", owner))
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    publish.replay(
        frozen,
        store=store,
        ownership=owner,
        runtime=Runtime(tmp_path / "runtime", environ={}),
        now=NOW,
        clock=lambda: NOW,
    )
    owner = state.acquire(store, owner="next")
    committed = state.load_committed(store, owner, out=tmp_path / "committed")
    return store, owner, committed


@pytest.mark.parametrize("change", ["sha256", "size", "object_class", "key"])
def test_unchanged_reference_must_match_committed_reference(
    tmp_path: Path,
    committed_generation: tuple[LocalStore, Ownership, state.CommittedState],
    change: str,
) -> None:
    store, owner, committed = committed_generation
    original = next_generation(tmp_path / "next", owner, committed)
    prepared = original.formats[0]
    dependency = prepared.referenced_objects[1]
    changed = {
        "sha256": replace(dependency, sha256="e" * 64),
        "size": replace(dependency, size=dependency.size + 1),
        "object_class": replace(dependency, object_class="entry"),
        "key": replace(dependency, key="metadata/other"),
    }[change]
    refs = tuple(changed if ref == dependency else ref for ref in prepared.referenced_objects)
    retained = replace(prepared.retained, objects=refs)
    altered = replace(
        original,
        formats=(replace(prepared, retained=retained, referenced_objects=refs),),
        public_inventories={"apt": core.public_inventory(retained.accepted_history, refs)},
    )
    if change == "sha256":
        assert store.stat(changed) == store.stat(dependency)
        with pytest.raises(StorageError):
            store.download(changed, tmp_path / "wrong-digest")
    with pytest.raises(state.StateError, match="committed reference"):
        state.freeze(store, owner, altered)
    pending = state.pending_generation(store)
    assert pending is not None and pending.id == committed.generation_id


@pytest.mark.parametrize("change", ["manifest", "etag", "completion"])
def test_unchanged_reference_requires_authenticated_prior_generation(
    tmp_path: Path,
    committed_generation: tuple[LocalStore, Ownership, state.CommittedState],
    change: str,
) -> None:
    store, owner, committed = committed_generation
    original = next_generation(tmp_path / "next", owner, committed)
    if change == "manifest":
        key = f"generations/{committed.generation_id}/manifest.json"
        current = state.read_control(store, key)
        assert current is not None
        manifest, observed = current
        state.write_control(store, key, {**manifest, "altered": True}, expected=observed.etag)
        message = "Frozen manifest"
    elif change == "etag":
        prepared = original.formats[0]
        dependency = prepared.referenced_objects[1]
        observed = store.stat(dependency)
        assert observed is not None
        receipt = store.replace(
            dependency, tmp_path / "input/dependency", expected_etag=observed.etag
        )
        retained = replace(
            prepared.retained,
            metadata={
                **prepared.retained.metadata,
                "etags": {
                    **state.mapping(prepared.retained.metadata["etags"]),
                    dependency.key: receipt.etag,
                },
            },
        )
        original = replace(original, formats=(replace(prepared, retained=retained),))
        message = "Committed public reference"
    else:
        original = replace(original, previous_completion_id="not-the-committed-generation")
        message = "current completion"
    with pytest.raises(state.StateError, match=message):
        state.freeze(store, owner, original)


@pytest.mark.parametrize("wrong_digest", [False, True])
def test_unwritten_reference_without_committed_provenance_rejects(
    tmp_path: Path, wrong_digest: bool
) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    prepared = original.formats[0]
    package, dependency, entry = prepared.outputs
    receipt = store.create(dependency.ref, dependency.local_path)
    ref = replace(dependency.ref, sha256="e" * 64) if wrong_digest else dependency.ref
    refs = (package.ref, ref, entry.ref)
    retained = replace(
        prepared.retained,
        objects=refs,
        metadata={**prepared.retained.metadata, "etags": {ref.key: receipt.etag}},
    )
    altered = replace(
        original,
        formats=(
            replace(
                prepared,
                retained=retained,
                outputs=(package, entry),
                referenced_objects=refs,
            ),
        ),
        public_inventories={"apt": core.public_inventory(retained.accepted_history, refs)},
    )
    assert store.stat(ref) == ObjectStat(receipt.etag, ref.size)
    with pytest.raises(state.StateError, match="committed reference"):
        state.freeze(store, owner, altered)
    assert state.pending_generation(store) is None


@pytest.mark.parametrize("mode", ["incremental", "unchanged", "new"])
def test_committed_reuse_and_new_outputs_replay_without_pool_downloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    committed_generation: tuple[LocalStore, Ownership, state.CommittedState],
    mode: str,
) -> None:
    store, owner, committed = committed_generation
    original = next_generation(tmp_path / "next", owner, committed)
    prepared = original.formats[0]
    if mode == "unchanged":
        retained = committed.formats[0]
        prepared = replace(
            prepared, retained=retained, outputs=(), referenced_objects=retained.objects
        )
    elif mode == "new":
        path = tmp_path / "new-dependency"
        core.atomic_write(path, b"new dependency")
        ref = object_ref(path, "metadata/new", "dependency")
        refs = (*prepared.referenced_objects, ref)
        prepared = replace(
            prepared,
            retained=replace(prepared.retained, objects=refs),
            referenced_objects=refs,
            outputs=(
                OutputObject(ref, path, "create", None, 0),
                replace(prepared.outputs[0], ordinal=1),
            ),
        )
    original = replace(
        original,
        formats=(prepared,),
        public_inventories={
            "apt": core.public_inventory(
                prepared.retained.accepted_history,
                prepared.referenced_objects,
            )
        },
    )
    downloads: list[ObjectRef] = []
    download = store.download

    def counted(ref: ObjectRef, destination: Path) -> ObjectStat:
        downloads.append(ref)
        return download(ref, destination)

    monkeypatch.setattr(store, "download", counted)
    frozen = state.freeze(store, owner, original)
    publish.replay(
        frozen,
        store=store,
        ownership=owner,
        runtime=Runtime(tmp_path / "next-runtime", environ={}),
        now=NOW,
        clock=lambda: NOW,
    )
    owner = state.acquire(store, owner="verify")
    restored = state.load_committed(store, owner, out=tmp_path / "final")
    assert restored.formats[0].objects == prepared.referenced_objects
    public_downloads = [ref for ref in downloads if ref.bucket_role != "private"]
    assert all(ref.object_class != "package" for ref in public_downloads)
    assert all(ref.key != "metadata/dependency" for ref in public_downloads)
    assert len(public_downloads) == len(prepared.outputs) + 1


def test_missing_owner_is_not_bootstrap(tmp_path: Path) -> None:
    store = local_store(tmp_path / "store")
    state.write_control(
        store,
        "completed.json",
        {"generation": core.json_value(state.FrozenGeneration("old", "a" * 64))},
        expected=None,
    )
    with pytest.raises(state.StateError, match="not a new repository"):
        state.acquire(store, owner="CI")


@pytest.mark.parametrize("damage", ["changed", "missing"])
def test_bootstrap_bytes_freeze_before_any_public_write(tmp_path: Path, damage: str) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner, bootstrap=True)
    key = original.bootstrap_outputs[0].local_path
    if damage == "changed":
        key.write_bytes(b"changed public key")
    else:
        key.unlink()
    with pytest.raises((state.StateError, ValueError)):
        state.freeze(store, owner, original)
    assert not list((tmp_path / "store/apt").iterdir())
    assert state.pending_generation(store) is None


@pytest.mark.parametrize("damage", ["drop", "hash", "rewrite", "fingerprint", "replay-etag"])
def test_bootstrap_reuse_requires_authenticated_unchanged_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    from tests.unit.test_publish import AdapterDouble

    store = local_store(tmp_path / "store")
    runtime = Runtime(tmp_path / "runtime", environ={})
    owner = state.acquire(store, owner="local")
    first = generation(tmp_path / "input", owner, bootstrap=True)
    frozen = state.freeze(store, owner, first)
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    publish.replay(
        frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW
    )
    owner = state.acquire(store, owner="next")
    prior = state.load_committed(store, owner, out=tmp_path / "prior")
    second = next_generation(tmp_path / "next", owner, prior)
    if damage == "drop":
        second = replace(second, bootstrap_objects=())
    elif damage == "hash":
        second = replace(
            second,
            bootstrap_objects=tuple(
                replace(ref, sha256="f" * 64) for ref in second.bootstrap_objects
            ),
        )
    elif damage == "rewrite":
        second = replace(second, bootstrap_outputs=first.bootstrap_outputs)
    elif damage == "fingerprint":
        second = replace(second, signing_fingerprint="B" * 40)
    second = replace(
        second,
        public_inventories={
            "apt": core.public_inventory(
                second.formats[0].retained.accepted_history,
                (*second.formats[0].referenced_objects, *second.bootstrap_objects),
            )
        },
    )
    if damage != "replay-etag":
        with pytest.raises(state.StateError):
            state.freeze(store, owner, second)
        return
    frozen = state.freeze(store, owner, second)
    output = first.bootstrap_outputs[0]
    observed = store.stat(output.ref)
    assert observed is not None
    store.replace(output.ref, output.local_path, expected_etag=observed.etag)
    with pytest.raises(state.StateError, match="bootstrap"):
        publish.replay(
            frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW
        )
    completed = state.read_control(store, "completed.json")
    assert completed is not None
    assert state.mapping(completed[0]["generation"])["id"] == first.id
