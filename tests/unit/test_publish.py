from __future__ import annotations

import hashlib
import shutil
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from haberdasher import core, discovery, publish, state
from haberdasher.config import Config, FormatPolicy, Policy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    NativeIdentity,
    ObjectRef,
    ObjectStat,
    PreparedFormat,
    RetainedFormat,
    VerifiedAsset,
    WriteReceipt,
)
from haberdasher.formats import rpm
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession
from haberdasher.storage import LocalStore, PreconditionFailed
from tests.unit.test_rpm import mock_rpm_commands, retained_rpm
from tests.unit.test_state import NOW, generation, local_store, next_generation


class AdapterDouble:
    def __init__(self) -> None:
        self.validations = 0
        self.native_calls = 0
        self.prepared: PreparedFormat | None = None

    def select(self, name: str) -> AdapterDouble:
        return self

    def inspect(
        self, asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
    ) -> InspectedAsset:
        self.native_calls += 1
        return InspectedAsset(
            asset, NativeIdentity(policy.format, "test", "amd64", "1"), {}, {}, "unsigned"
        )

    def compare(
        self, left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime
    ) -> int | None:
        self.native_calls += 1
        return 0 if left == right else None

    def validate_retained(
        self, retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime
    ) -> None:
        self.validations += 1
        if retained.metadata:
            refs = {ref.key: ref for ref in retained.objects}
            for key, value in state.mapping(retained.metadata["files"]).items():
                ref = refs[key]
                assert core.sha256_file(Path(str(value))) == (ref.sha256, ref.size)
            assert Path(str(retained.metadata["keyring"])).read_bytes() == b"trust"

    def prepare(
        self,
        new: Sequence[AdmittedAsset],
        retained: RetainedFormat,
        *,
        policy: FormatPolicy,
        runtime: Runtime,
        signer: SigningSession,
        now: datetime,
        out: Path,
    ) -> PreparedFormat:
        self.native_calls += 1
        assert new and self.prepared is not None
        return self.prepared

    def validate_prepared(
        self, prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime, now: datetime
    ) -> None:
        self.validate_retained(prepared.retained, policy=policy, runtime=runtime)
        for output in prepared.outputs:
            assert core.sha256_file(output.local_path) == (output.ref.sha256, output.ref.size)


class CountingStore(LocalStore):
    def __init__(self, root: Path) -> None:
        from haberdasher.config import StoragePolicy

        super().__init__(StoragePolicy("local", str(root / "private"), {"apt": str(root / "apt")}))
        self.writes: list[ObjectRef] = []
        self.downloads: list[ObjectRef] = []

    def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
        self.writes.append(ref)
        return super().create(ref, source)

    def replace(self, ref: ObjectRef, source: Path, *, expected_etag: str) -> WriteReceipt:
        self.writes.append(ref)
        return super().replace(ref, source, expected_etag=expected_etag)

    def download(self, ref: ObjectRef, destination: Path) -> ObjectStat:
        self.downloads.append(ref)
        return super().download(ref, destination)


def test_replay_restores_lost_local_state_without_signers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CountingStore(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    frozen = state.freeze(store, owner, original)
    shutil.rmtree(tmp_path / "input")
    store = CountingStore(tmp_path / "store")
    owner = state.recover_owner(
        store,
        expected_nonce=owner.owner_nonce,
        evidence=state.RecoveryEvidence(
            True, True, "original process stopped before publication", "CI"
        ),
    )
    persisted = state.pending_generation(store)
    assert persisted == frozen
    adapter = AdapterDouble()
    monkeypatch.setattr(publish, "_adapter", adapter.select)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Replay attempted discovery or signing")

    monkeypatch.setattr(publish, "signing_session", forbidden)
    monkeypatch.setattr(discovery, "scan_releases", forbidden)
    runtime = Runtime(tmp_path / "runtime", environ={"HD_SIGNING_KEY": "synthetic sentinel"})
    assert "HD_SIGNING_KEY" not in runtime.environment
    result = publish.replay(
        frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW
    )
    assert result.published_objects == 4
    public = [ref for ref in store.writes if ref.bucket_role != "private"]
    assert [ref.object_class for ref in public] == ["package", "dependency", "entry", "inventory"]
    assert adapter.native_calls == 0
    next_owner = state.acquire(store, owner="CI")
    committed = state.load_committed(store, next_owner, out=tmp_path / "loaded")
    assert committed.generation_id == frozen.id
    assert committed.formats[0].metadata["etags"]
    assert committed.inventory_etags["apt"]
    state.release(store, next_owner)


def test_committed_public_reference_tampering_stops_restoration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = CountingStore(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    frozen = state.freeze(store, owner, original)
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    publish.replay(
        frozen,
        store=store,
        ownership=owner,
        runtime=Runtime(tmp_path / "runtime", environ={}),
        now=NOW,
        clock=lambda: NOW,
    )
    entry = original.formats[0].outputs[-1]
    observed = store.stat(entry.ref)
    assert observed is not None
    store.replace(entry.ref, entry.local_path, expected_etag=observed.etag)
    owner = state.acquire(store, owner="CI")
    with pytest.raises(state.StateError, match="public reference"):
        state.load_committed(store, owner, out=tmp_path / "restore")


def test_expired_replay_does_not_publish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = CountingStore(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    frozen = state.freeze(store, owner, generation(tmp_path / "input", owner))
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    with pytest.raises(state.StateError, match="expired"):
        publish.replay(
            frozen,
            store=store,
            ownership=owner,
            runtime=Runtime(tmp_path / "runtime", environ={}),
            now=NOW + timedelta(days=8),
            clock=lambda: NOW + timedelta(days=8),
        )
    assert not any(ref.bucket_role != "private" for ref in store.writes)
    assert state.read_control(store, "completed.json") is None


@pytest.mark.parametrize(
    "boundary", ["admission", "dependency", "entry-intent", "entry", "completion"]
)
@pytest.mark.parametrize("overrun", [timedelta(0), timedelta(microseconds=1)])
def test_replay_checks_live_expiry_at_publication_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    overrun: timedelta,
) -> None:
    current = NOW
    monkeypatch.setattr(core, "utc_now", lambda: current)
    adapter = AdapterDouble()
    monkeypatch.setattr(publish, "_adapter", adapter.select)
    store = CountingStore(tmp_path / "store")
    runtime = Runtime(tmp_path / "runtime", environ={})
    owner = state.acquire(store, owner="seed")
    first = generation(tmp_path / "input", owner)
    frozen = state.freeze(store, owner, first)
    publish.replay(frozen, store=store, ownership=owner, runtime=runtime, now=NOW)
    previous_completion = state.read_control(store, "completed.json")
    owner = state.acquire(store, owner="next")
    committed = state.load_committed(store, owner, out=tmp_path / "committed")
    original = next_generation(tmp_path / "next", owner, committed)
    prepared = original.formats[0]
    entry = prepared.outputs[0]
    dependency = replace(
        first.formats[0].outputs[1],
        ref=replace(first.formats[0].outputs[1].ref, key="metadata/new-dependency"),
    )
    last_entry = replace(
        entry, ref=replace(entry.ref, key="metadata/last-entry"), mode="create", expected_etag=None
    )
    refs = (*prepared.referenced_objects, dependency.ref, last_entry.ref)
    prepared = replace(
        prepared,
        retained=replace(prepared.retained, objects=refs),
        referenced_objects=refs,
        outputs=tuple(
            replace(output, ordinal=index)
            for index, output in enumerate((dependency, entry, last_entry))
        ),
    )
    original = replace(
        original,
        formats=(prepared,),
        public_inventories={"apt": core.public_inventory(prepared.retained.accepted_history, refs)},
    )
    frozen = state.freeze(store, owner, original)
    frozen_root = tmp_path / "store/private/generations" / frozen.id
    frozen_hashes = {
        path: core.sha256_file(path)
        for path in frozen_root.rglob("*")
        if path.is_file() and path.name != "journal.json"
    }
    assert prepared.expires_at is not None
    expiry = datetime.fromisoformat(prepared.expires_at)
    current = expiry + overrun if boundary == "admission" else expiry - timedelta(seconds=1)
    download, replace_object, stat = store.download, store.replace, store.stat

    def timed_download(ref: ObjectRef, destination: Path) -> ObjectStat:
        nonlocal current
        observed = download(ref, destination)
        if boundary == "dependency" and ref == dependency.ref:
            current = expiry + overrun
        if boundary == "entry-intent" and ref.key == f"generations/{frozen.id}/journal.json":
            writes = state.mapping(state.parse(destination.read_bytes())["writes"])
            if state.mapping(writes.get("1", {})).get("status") == "intent":
                current = expiry + overrun
        return observed

    def timed_replace(ref: ObjectRef, source: Path, *, expected_etag: str) -> WriteReceipt:
        nonlocal current
        receipt = replace_object(ref, source, expected_etag=expected_etag)
        if boundary == "entry" and ref == entry.ref:
            current = expiry + overrun
        return receipt

    def timed_stat(ref: ObjectRef) -> ObjectStat | None:
        nonlocal current
        observed = stat(ref)
        if boundary == "completion" and ref.object_class == "inventory":
            current = expiry + overrun
        return observed

    monkeypatch.setattr(store, "download", timed_download)
    monkeypatch.setattr(store, "replace", timed_replace)
    monkeypatch.setattr(store, "stat", timed_stat)
    store.writes.clear()
    with pytest.raises(state.StateError, match="expired"):
        publish.replay(frozen, store=store, ownership=owner, runtime=runtime, now=NOW)
    assert current >= expiry
    public = [ref for ref in store.writes if ref.bucket_role != "private"]
    expected = {
        "admission": [],
        "dependency": ["dependency"],
        "entry-intent": ["dependency"],
        "entry": ["dependency", "entry"],
        "completion": ["dependency", "entry", "entry", "inventory"],
    }
    assert [ref.object_class for ref in public] == expected[boundary]
    assert state.read_control(store, "completed.json") == previous_completion
    assert state.pending_generation(store) == frozen
    assert {path: core.sha256_file(path) for path in frozen_hashes} == frozen_hashes
    assert state.check_owner(store, owner)["status"] == "active"
    assert adapter.native_calls == 0
    with pytest.raises(state.StateError, match="already holds"):
        state.acquire(store, owner="competitor")
    with pytest.raises(state.StateError, match="pending"):
        state.release(store, owner)
    if boundary in {"dependency", "entry-intent", "entry"}:
        with pytest.raises(state.StateError, match="explicit resolution"):
            state.recover_owner(
                store,
                expected_nonce=owner.owner_nonce,
                evidence=state.RecoveryEvidence(True, True, "synthetic stopped process", "CI"),
            )
    assert state.check_owner(store, owner)["status"] == "active"


def test_completion_requires_every_acknowledgement(tmp_path: Path) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    frozen = state.freeze(store, owner, original)
    with pytest.raises(state.StateError, match="every public write"):
        state.complete(store, owner, frozen, original)
    assert state.read_control(store, "completed.json") is None


def test_stale_etag_never_refreshes_to_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CountingStore(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    prepared = original.formats[0]
    entry = prepared.outputs[-1]
    old = store.create(entry.ref, entry.local_path)
    changed = replace(entry, mode="replace", expected_etag=old.etag)
    original = replace(
        original, formats=(replace(prepared, outputs=(*prepared.outputs[:-1], changed)),)
    )
    frozen = state.freeze(store, owner, original)
    newer = store.replace(entry.ref, entry.local_path, expected_etag=old.etag)
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    with pytest.raises(PreconditionFailed):
        publish.replay(
            frozen,
            store=store,
            ownership=owner,
            runtime=Runtime(tmp_path / "runtime", environ={}),
            now=NOW,
            clock=lambda: NOW,
        )
    assert store.stat(entry.ref) == ObjectStat(newer.etag, entry.ref.size)
    assert state.read_control(store, "completed.json") is None
    with pytest.raises(state.StateError, match="Unresolved"):
        publish.replay(
            frozen,
            store=store,
            ownership=owner,
            runtime=Runtime(tmp_path / "runtime-2", environ={}),
            now=NOW,
            clock=lambda: NOW,
        )


@pytest.mark.parametrize("fail_inventory", [False, True])
def test_reconcile_commits_scan_only_after_publish_and_fresh_noop_is_cheap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_inventory: bool,
) -> None:
    from haberdasher.config import StoragePolicy

    storage = StoragePolicy(
        "local", str(tmp_path / "store/private"), {"apt": str(tmp_path / "store/apt")}
    )
    policy = Policy(storage, expected_signing_fingerprint="A" * 40)
    config = Config(("test/project",))

    class InventoryFailure(CountingStore):
        blocked = fail_inventory

        def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
            if self.blocked and ref.object_class == "inventory":
                raise RuntimeError("Injected inventory failure")
            return super().create(ref, source)

    store = InventoryFailure(tmp_path / "store")
    fake_owner = core.Ownership("test", "etag", "local", NOW.isoformat())
    template = generation(tmp_path / "input", fake_owner)
    adapter = AdapterDouble()
    adapter.prepared = template.formats[0]
    monkeypatch.setattr(publish, "_adapter", adapter.select)
    verified = adapter.prepared.retained.accepted_history[0].inspected.verified
    checksum_source = replace(verified.source, asset_id=2, filename="checksums.txt")
    checksum = discovery.ChecksumEntry(
        checksum_source, verified.source.filename, verified.sha256, verified.checksum_sha256
    )
    record = discovery.DiscoveredAsset(verified.source, checksum, "e" * 64)
    scan_state = discovery.DiscoveryState(
        (record,), (verified.source, checksum_source), config.sources
    )
    previous_states: list[discovery.DiscoveryState] = []

    def scan(
        config: Config, *, runtime: Runtime, previous: discovery.DiscoveryState
    ) -> discovery.CompleteScan:
        previous_states.append(previous)
        unchanged = any(
            prior.source == record.source
            and prior.checksum is not None
            and record.checksum is not None
            and prior.checksum.sha256 == record.checksum.sha256
            for prior in previous.records
        )
        return discovery.CompleteScan(
            scan_state,
            () if unchanged else (record,),
            (record,) if unchanged else (),
            (),
            (),
        )

    def verify(
        source: core.SourceAsset, checksum: discovery.ChecksumEntry, *, runtime: Runtime, out: Path
    ) -> VerifiedAsset:
        return verified

    class SignerDouble:
        fingerprint = "A" * 40

        def public_exports(self, out: Path) -> tuple[Path, Path, Path]:
            paths = tuple(
                out / name for name in ("haberdasher.asc", "haberdasher.gpg", "haberdasher.rsa.pub")
            )
            for path in paths:
                core.atomic_write(path, b"synthetic public export")
            return paths[0], paths[1], paths[2]

    @contextmanager
    def signing(runtime: Runtime, *, expected_fingerprint: str) -> Generator[SigningSession]:
        yield cast(SigningSession, SignerDouble())

    monkeypatch.setattr(discovery, "scan_releases", scan)
    monkeypatch.setattr(discovery, "verify_asset", verify)
    monkeypatch.setattr(publish, "signing_session", signing)
    runtime = Runtime(tmp_path / "runtime", environ={})
    if fail_inventory:
        with pytest.raises(RuntimeError, match="Injected inventory"):
            publish.reconcile(
                config, policy, store=store, runtime=runtime, now=NOW, clock=lambda: NOW
            )
        assert state.read_control(store, "completed.json") is None
        current = state.read_control(store, "ownership.json")
        assert current is not None
        frozen = state.pending_generation(store)
        assert frozen is not None
        owner = state.recover_owner(
            store,
            expected_nonce=str(current[0]["nonce"]),
            evidence=state.RecoveryEvidence(
                True,
                True,
                "failed request confirmed",
                "CI",
                (state.WriteResolution(5, "not-written"),),
            ),
        )
        store.blocked = False
        first = publish.replay(
            frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW
        )
    else:
        first = publish.reconcile(
            config, policy, store=store, runtime=runtime, now=NOW, clock=lambda: NOW
        )
    assert first.changed and previous_states == [discovery.DiscoveryState()]
    native = (adapter.validations, adapter.native_calls)
    store.downloads.clear()
    second = publish.reconcile(
        config, policy, store=store, runtime=runtime, now=NOW, clock=lambda: NOW
    )
    assert not second.changed and second.published_objects == 0
    assert previous_states[-1] == scan_state
    assert native == (adapter.validations, adapter.native_calls)
    assert not any(
        ref.object_class == "package" or "/outputs/" in ref.key for ref in store.downloads
    )

    previous_scan = scan_state
    checksum_source = replace(checksum_source, asset_id=3)
    checksum = replace(checksum, source=checksum_source, checksum_sha256="b" * 64)
    record = replace(record, checksum=checksum)
    scan_state = replace(scan_state, records=(record,), assets=(verified.source, checksum_source))
    previous_completion = state.read_control(store, "completed.json")
    replay = publish.replay

    def interrupted(*args: object, **kwargs: object) -> publish.RunResult:
        raise RuntimeError("Interrupted provenance publication")

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Provenance update repeated verification or signing")

    monkeypatch.setattr(publish, "replay", interrupted)
    monkeypatch.setattr(publish, "signing_session", forbidden)
    monkeypatch.setattr(discovery, "verify_asset", forbidden)
    with pytest.raises(RuntimeError, match="Interrupted provenance"):
        publish.reconcile(config, policy, store=store, runtime=runtime, now=NOW, clock=lambda: NOW)
    assert state.read_control(store, "completed.json") == previous_completion
    assert previous_states[-1] == previous_scan
    assert adapter.native_calls == native[1]
    current = state.read_control(store, "ownership.json")
    frozen = state.pending_generation(store)
    assert current is not None and frozen is not None
    owner = state.recover_owner(
        store,
        expected_nonce=str(current[0]["nonce"]),
        evidence=state.RecoveryEvidence(True, True, "stopped before replay", "CI"),
    )
    monkeypatch.setattr(publish, "replay", replay)
    replay(frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW)
    owner = state.acquire(store, owner="read-provenance")
    restored = state.load_committed(store, owner, out=tmp_path / "provenance")
    state.release(store, owner)
    assert restored.discovery == scan_state
    accepted = restored.formats[0].accepted_history[0]
    assert accepted.inspected.verified.checksum_asset_id == 2
    assert accepted.inspected.verified.checksum_sha256 == "a" * 64
    assert not accepted.inspected.verified.local_path.exists()
    assert adapter.native_calls == native[1]

    verified = replace(
        verified, source=replace(verified.source, updated_at=(NOW + timedelta(hours=1)).isoformat())
    )
    record = replace(record, source=verified.source)
    scan_state = replace(scan_state, records=(record,), assets=(verified.source, checksum_source))
    monkeypatch.setattr(discovery, "verify_asset", verify)
    monkeypatch.setattr(publish, "signing_session", signing)
    duplicate = publish.reconcile(
        config, policy, store=store, runtime=runtime, now=NOW, clock=lambda: NOW
    )
    assert duplicate.changed and adapter.native_calls == native[1] + 2
    owner = state.acquire(store, owner="read-canonical")
    restored = state.load_committed(store, owner, out=tmp_path / "canonical")
    state.release(store, owner)
    canonical = restored.formats[0].accepted_history[0]
    assert canonical == accepted
    assert not canonical.inspected.verified.local_path.exists()

    verified = replace(verified, sha256="c" * 64)
    checksum = replace(checksum, sha256=verified.sha256)
    record = replace(record, checksum=checksum)
    scan_state = replace(scan_state, records=(record,))
    previous_completion = state.read_control(store, "completed.json")
    with pytest.raises(ValueError, match="Changed bytes for an accepted native identity"):
        publish.reconcile(config, policy, store=store, runtime=runtime, now=NOW, clock=lambda: NOW)
    assert state.read_control(store, "completed.json") == previous_completion


@pytest.mark.parametrize("damage", ["bytes", "missing", "etag"])
def test_committed_bootstrap_changes_fail_before_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    from haberdasher.config import StoragePolicy
    from haberdasher.storage import StorageError

    store = CountingStore(tmp_path / "store")
    runtime = Runtime(tmp_path / "runtime", environ={})
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner, bootstrap=True)
    frozen = state.freeze(store, owner, original)
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    publish.replay(
        frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW
    )
    output = original.bootstrap_outputs[0]
    path = tmp_path / "store/apt" / output.ref.key
    if damage == "bytes":
        path.write_bytes(b"wrong")
    elif damage == "missing":
        path.unlink()
    else:
        observed = store.stat(output.ref)
        assert observed is not None
        store.replace(output.ref, output.local_path, expected_etag=observed.etag)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Damaged bootstrap reached discovery or signing")

    monkeypatch.setattr(discovery, "scan_releases", forbidden)
    monkeypatch.setattr(publish, "signing_session", forbidden)
    policy = Policy(
        StoragePolicy(
            "local", str(tmp_path / "store/private"), {"apt": str(tmp_path / "store/apt")}
        ),
        expected_signing_fingerprint="A" * 40,
    )
    with pytest.raises((state.StateError, StorageError, FileNotFoundError)):
        publish.reconcile(
            Config(("test/project",)),
            policy,
            store=store,
            runtime=runtime,
            now=NOW,
            clock=lambda: NOW,
        )


def test_signing_fingerprint_change_fails_before_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from haberdasher.config import StoragePolicy

    store = CountingStore(tmp_path / "store")
    runtime = Runtime(tmp_path / "runtime", environ={})
    owner = state.acquire(store, owner="local")
    frozen = state.freeze(store, owner, generation(tmp_path / "input", owner, bootstrap=True))
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    publish.replay(
        frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Fingerprint change reached discovery or signing")

    monkeypatch.setattr(discovery, "scan_releases", forbidden)
    monkeypatch.setattr(publish, "signing_session", forbidden)
    policy = Policy(
        StoragePolicy(
            "local", str(tmp_path / "store/private"), {"apt": str(tmp_path / "store/apt")}
        ),
        expected_signing_fingerprint="B" * 40,
    )
    with pytest.raises(state.StateError, match="rotation"):
        publish.reconcile(
            Config(("test/project",)),
            policy,
            store=store,
            runtime=runtime,
            now=NOW,
            clock=lambda: NOW,
        )


@pytest.mark.parametrize("architecture", ["x86_64", "noarch"])
def test_rpm_policy_change_validates_unchanged_history_before_freeze(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, architecture: str
) -> None:
    from haberdasher.config import StoragePolicy

    storage = StoragePolicy(
        "local", str(tmp_path / "store/private"), {"rpm": str(tmp_path / "store/rpm")}
    )
    store = LocalStore(storage)
    policy = Policy(storage, expected_signing_fingerprint="A" * 40)
    config = Config(("test/project",), {"rpm": FormatPolicy("rpm")})
    runtime = Runtime(tmp_path / "runtime", environ={})
    mock_rpm_commands(monkeypatch)
    retained = retained_rpm(tmp_path / "rpm", (architecture,))
    outputs = tuple(
        core.OutputObject(ref, tmp_path / "rpm" / ref.key, "create", None, index)
        for index, ref in enumerate(retained.objects)
    )
    prepared = PreparedFormat("rpm", retained, outputs, retained.objects)
    source = retained.accepted_history[0].inspected.verified.source
    scan_state = discovery.DiscoveryState((), (source,), config.sources)

    def scan(
        config: Config, *, runtime: Runtime, previous: discovery.DiscoveryState
    ) -> discovery.CompleteScan:
        assert previous == scan_state
        return discovery.CompleteScan(scan_state, (), (), (), ())

    owner = state.acquire(store, owner="seed")
    template = generation(tmp_path / "input", owner, name="rpm", bootstrap=True)
    original = replace(
        template,
        config_digest=hashlib.sha256(core.canonical_json(config)).hexdigest(),
        policy_digest=hashlib.sha256(core.canonical_json(policy)).hexdigest(),
        formats=(prepared,),
        scan={
            "state": core.json_value(scan_state),
            "policies": {"rpm": core.json_value(config.format_policy("rpm"))},
        },
        public_inventories={
            "rpm": core.public_inventory(
                retained.accepted_history, (*retained.objects, *template.bootstrap_objects)
            )
        },
    )
    frozen = state.freeze(store, owner, original)
    publish.replay(
        frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW
    )
    completion = state.read_control(store, "completed.json")
    public_before = {
        path.relative_to(tmp_path / "store/rpm"): path.read_bytes()
        for path in (tmp_path / "store/rpm").rglob("*")
        if path.is_file()
    }
    owner = state.acquire(store, owner="before")
    before = state.load_committed(store, owner, out=tmp_path / "before")
    state.release(store, owner)
    monkeypatch.setattr(discovery, "scan_releases", scan)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Policy-only change reached signing, rebuilding, or freeze")

    monkeypatch.setattr(publish, "signing_session", forbidden)
    monkeypatch.setattr(rpm, "prepare", forbidden)
    changed = replace(config, formats={"rpm": FormatPolicy("rpm", architectures=("aarch64",))})
    if architecture == "x86_64":
        monkeypatch.setattr(state, "freeze", forbidden)
        with pytest.raises(rpm.RpmFailure, match="architecture is not approved"):
            publish.reconcile(
                changed, policy, store=store, runtime=runtime, now=NOW, clock=lambda: NOW
            )
        assert state.read_control(store, "completed.json") == completion
        assert state.pending_generation(store) == frozen
        held = state.read_control(store, "ownership.json")
        assert held is not None
        owner = core.Ownership(
            str(held[0]["nonce"]),
            held[1].etag,
            str(held[0]["runner"]),
            str(held[0]["acquired_at"]),
        )
    else:
        result = publish.reconcile(
            changed, policy, store=store, runtime=runtime, now=NOW, clock=lambda: NOW
        )
        assert result.changed
        owner = state.acquire(store, owner="after")
    after = state.load_committed(store, owner, out=tmp_path / "after")
    assert after.config_digest == (
        before.config_digest
        if architecture == "x86_64"
        else hashlib.sha256(core.canonical_json(changed)).hexdigest()
    )
    assert after.policy_digest == before.policy_digest
    assert after.formats[0].accepted_history == before.formats[0].accepted_history
    assert after.formats[0].objects == before.formats[0].objects
    assert {
        path.relative_to(tmp_path / "store/rpm"): path.read_bytes()
        for path in (tmp_path / "store/rpm").rglob("*")
        if path.is_file()
    } == public_before


def test_adding_selected_format_retains_previous_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SignerDouble:
        fingerprint = "A" * 40

        def public_exports(self, out: Path) -> tuple[Path, Path, Path]:
            paths = tuple(
                out / name for name in ("haberdasher.asc", "haberdasher.gpg", "haberdasher.rsa.pub")
            )
            for path in paths:
                path.write_bytes(b"synthetic public export")
            return paths[0], paths[1], paths[2]

    signer = cast(SigningSession, SignerDouble())
    store = local_store(tmp_path / "store")
    runtime = Runtime(tmp_path / "runtime", environ={})
    owner = state.acquire(store, owner="local")
    empty = state.load_committed(store, owner, out=tmp_path / "empty")
    first = generation(tmp_path / "input", owner)
    outputs, refs = publish.prepare_bootstrap(
        first.formats, empty, signer, out=tmp_path / "exports-one"
    )
    first = replace(
        first,
        bootstrap_outputs=outputs,
        bootstrap_objects=refs,
        signing_fingerprint=signer.fingerprint,
        public_inventories={
            "apt": core.public_inventory(
                first.formats[0].retained.accepted_history,
                (*first.formats[0].referenced_objects, *refs),
            )
        },
    )
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    frozen = state.freeze(store, owner, first)
    publish.replay(
        frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW
    )
    owner = state.acquire(store, owner="next")
    prior = state.load_committed(store, owner, out=tmp_path / "prior")
    second = next_generation(tmp_path / "next", owner, prior)
    rpm = PreparedFormat("rpm", RetainedFormat("rpm", None, (), (), {}, ()), (), ())
    formats = (*second.formats, rpm)
    outputs, refs = publish.prepare_bootstrap(formats, prior, signer, out=tmp_path / "exports-two")
    assert len(outputs) == 2 and all(output.ref.bucket_role == "rpm" for output in outputs)
    assert set(prior.bootstrap_objects).issubset(refs)
    second = replace(
        second,
        formats=formats,
        bootstrap_outputs=outputs,
        bootstrap_objects=refs,
        scan={
            **second.scan,
            "policies": core.json_value({"apt": FormatPolicy("apt"), "rpm": FormatPolicy("rpm")}),
        },
        public_inventories={
            item.format: core.public_inventory(
                item.retained.accepted_history,
                (
                    *item.referenced_objects,
                    *(ref for ref in refs if ref.bucket_role == item.format),
                ),
            )
            for item in formats
        },
    )
    frozen = state.freeze(store, owner, second)
    publish.replay(
        frozen, store=store, ownership=owner, runtime=runtime, now=NOW, clock=lambda: NOW
    )
    owner = state.acquire(store, owner="verify")
    restored = state.load_committed(store, owner, out=tmp_path / "final")
    assert restored.bootstrap_objects == refs
    for key, etag in prior.bootstrap_etags.items():
        assert restored.bootstrap_etags[key] == etag
    state.release(store, owner)
