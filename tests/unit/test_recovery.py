from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from haberdasher import core, publish, state
from haberdasher.core import ObjectRef, ObjectStat, Ownership, WriteReceipt
from haberdasher.runtime import Runtime
from haberdasher.storage import UnknownWrite
from tests.unit.test_publish import AdapterDouble, CountingStore
from tests.unit.test_state import NOW, generation, next_generation


class InjectedFailure(RuntimeError):
    pass


class FaultStore(CountingStore):
    def __init__(self, root: Path, fail_at: int | None = None) -> None:
        super().__init__(root)
        self.fail_at = fail_at
        self.events: list[tuple[str, str, str]] = []

    def boundary(self, when: str, operation: str, ref: ObjectRef) -> None:
        self.events.append((when, operation, f"{ref.bucket_role}/{ref.key}"))
        if len(self.events) - 1 == self.fail_at:
            self.fail_at = None
            raise InjectedFailure(self.events[-1])

    def _operation[T](self, name: str, ref: ObjectRef, call: Callable[[], T]) -> T:
        self.boundary("before", name, ref)
        result = call()
        self.boundary("after", name, ref)
        return result

    def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
        return self._operation("create", ref, lambda: super(FaultStore, self).create(ref, source))

    def replace(self, ref: ObjectRef, source: Path, *, expected_etag: str) -> WriteReceipt:
        return self._operation(
            "replace",
            ref,
            lambda: super(FaultStore, self).replace(ref, source, expected_etag=expected_etag),
        )

    def download(self, ref: ObjectRef, destination: Path) -> ObjectStat:
        return self._operation(
            "download", ref, lambda: super(FaultStore, self).download(ref, destination)
        )


def resolutions(store: CountingStore, root: Path) -> tuple[state.WriteResolution, ...]:
    frozen = state.pending_generation(store)
    if frozen is None:
        return ()
    original, _ = state.load_frozen(store, frozen, out=root / "inspect-frozen")
    outputs = state.publication_outputs(original, out=root)
    journal, _ = state.read_journal(store, frozen)
    result: list[state.WriteResolution] = []
    for key, value in state.mapping(journal["writes"]).items():
        if state.mapping(value).get("status") == "ack":
            continue
        ordinal = int(key)
        output = outputs[ordinal]
        observed = store.stat(output.ref)
        if observed is None or observed.etag == output.expected_etag:
            result.append(state.WriteResolution(ordinal, "not-written"))
        else:
            store.download(output.ref, root / "resolved-by-test")
            result.append(state.WriteResolution(ordinal, "written", observed.etag))
    return tuple(result)


@pytest.mark.parametrize("bootstrap", [False, True])
def test_every_write_and_verification_boundary_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bootstrap: bool
) -> None:
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    baseline = FaultStore(tmp_path / "baseline/store")
    runtime = Runtime(tmp_path / "baseline/runtime", environ={})
    owner = state.acquire(baseline, owner="local")
    original = generation(tmp_path / "baseline/input", owner, bootstrap=bootstrap)
    frozen = state.freeze(baseline, owner, original)
    publish.replay(frozen, store=baseline, ownership=owner, runtime=runtime, now=NOW)
    assert len(baseline.events) > 70
    for boundary in range(len(baseline.events)):
        root = tmp_path / f"failure-{boundary}"
        store = FaultStore(root / "store", boundary)
        runtime = Runtime(root / "runtime", environ={})
        with pytest.raises(InjectedFailure):
            owner = state.acquire(store, owner="local")
            original = generation(root / "input", owner, bootstrap=bootstrap)
            frozen = state.freeze(store, owner, original)
            publish.replay(frozen, store=store, ownership=owner, runtime=runtime, now=NOW)
        completed = state.read_control(store, "completed.json")
        if completed is not None:
            for ref in baseline.writes:
                if ref.bucket_role != "private":
                    assert store.stat(ref) is not None, (boundary, baseline.events[boundary])
        current = state.read_control(store, "ownership.json")
        if current is not None and current[0]["status"] == "active":
            evidence = state.RecoveryEvidence(
                True, True, "test process stopped; requests settled", "CI", resolutions(store, root)
            )
            owner = state.recover_owner(
                store, expected_nonce=str(current[0]["nonce"]), evidence=evidence
            )
            pending = state.pending_generation(store)
            if pending is not None:
                publish.replay(pending, store=store, ownership=owner, runtime=runtime, now=NOW)
            else:
                original = generation(
                    root / "retry-input", owner, identifier="retry-generation", bootstrap=bootstrap
                )
                pending = state.freeze(store, owner, original)
                publish.replay(pending, store=store, ownership=owner, runtime=runtime, now=NOW)
        elif completed is None:
            owner = state.acquire(store, owner="CI")
            original = generation(
                root / "retry-input", owner, identifier="retry-generation", bootstrap=bootstrap
            )
            pending = state.freeze(store, owner, original)
            publish.replay(pending, store=store, ownership=owner, runtime=runtime, now=NOW)
        owner = state.acquire(store, owner="verification")
        committed = state.load_committed(store, owner, out=root / "final")
        assert committed.generation_id is not None
        state.release(store, owner)


@pytest.mark.parametrize("bootstrap", [False, True])
def test_every_replacement_boundary_preserves_prior_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bootstrap: bool,
) -> None:
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)

    def initial(root: Path) -> tuple[FaultStore, Runtime, Ownership, core.PreparedGeneration]:
        store = FaultStore(root / "store")
        runtime = Runtime(root / "runtime", environ={})
        owner = state.acquire(store, owner="local")
        first = generation(root / "input", owner, bootstrap=bootstrap)
        frozen = state.freeze(store, owner, first)
        publish.replay(frozen, store=store, ownership=owner, runtime=runtime, now=NOW)
        owner = state.acquire(store, owner="CI")
        committed = state.load_committed(store, owner, out=root / "prior")
        second = next_generation(root / "second", owner, committed)
        store.events.clear()
        return store, runtime, owner, second

    baseline, runtime, owner, second = initial(tmp_path / "baseline")
    frozen = state.freeze(baseline, owner, second)
    publish.replay(frozen, store=baseline, ownership=owner, runtime=runtime, now=NOW)
    assert any(
        operation == "replace" and key == "apt/metadata/entry"
        for _, operation, key in baseline.events
    )
    for boundary in range(len(baseline.events)):
        root = tmp_path / f"failure-{boundary}"
        store, runtime, owner, second = initial(root)
        store.fail_at = boundary
        with pytest.raises(InjectedFailure):
            frozen = state.freeze(store, owner, second)
            publish.replay(frozen, store=store, ownership=owner, runtime=runtime, now=NOW)
        completed = state.read_control(store, "completed.json")
        assert completed is not None
        completed_id = state.mapping(completed[0]["generation"])["id"]
        assert completed_id in {"generation-one", "generation-two"}
        current = state.read_control(store, "ownership.json")
        assert current is not None
        if current[0]["status"] == "active":
            owner = state.recover_owner(
                store,
                expected_nonce=str(current[0]["nonce"]),
                evidence=state.RecoveryEvidence(
                    True, True, "request outcomes confirmed", "CI", resolutions(store, root)
                ),
            )
            pending = state.pending_generation(store)
            assert pending is not None
            if pending.id == "generation-two":
                publish.replay(pending, store=store, ownership=owner, runtime=runtime, now=NOW)
            else:
                state.release(store, owner)
                owner = state.acquire(store, owner="CI")
                prior = state.load_committed(store, owner, out=root / "prior-retry")
                retry = next_generation(root / "retry", owner, prior, identifier="generation-retry")
                pending = state.freeze(store, owner, retry)
                publish.replay(pending, store=store, ownership=owner, runtime=runtime, now=NOW)
        owner = state.acquire(store, owner="verification")
        committed = state.load_committed(store, owner, out=root / "final")
        assert committed.generation_id in {"generation-two", "generation-retry"}
        entry = next(ref for ref in committed.formats[0].objects if ref.object_class == "entry")
        store.download(entry, root / "entry-verified")
        assert (root / "entry-verified").read_bytes() == b"entry two"
        state.release(store, owner)


class UncertainStore(CountingStore):
    def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
        receipt = super().create(ref, source)
        if ref.object_class == "package":
            raise UnknownWrite(receipt)
        return receipt


def test_unknown_write_observation_does_not_prove_generation_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = UncertainStore(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    frozen = state.freeze(store, owner, generation(tmp_path / "input", owner))
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    runtime = Runtime(tmp_path / "runtime", environ={})
    with pytest.raises(UnknownWrite) as uncertain:
        publish.replay(frozen, store=store, ownership=owner, runtime=runtime, now=NOW)
    assert uncertain.value.observation is not None
    assert [ref.object_class for ref in store.writes if ref.bucket_role != "private"] == ["package"]
    with pytest.raises(state.StateError, match="Unresolved"):
        publish.replay(frozen, store=store, ownership=owner, runtime=runtime, now=NOW)
    with pytest.raises(state.StateError, match="explicit resolution"):
        state.recover_owner(
            store,
            expected_nonce=owner.owner_nonce,
            evidence=state.RecoveryEvidence(True, True, "operator", "CI"),
        )
    recovered = state.recover_owner(
        store,
        expected_nonce=owner.owner_nonce,
        evidence=state.RecoveryEvidence(
            True,
            True,
            "request receipt confirmed by operator",
            "CI",
            (state.WriteResolution(0, "written", uncertain.value.observation.etag),),
        ),
    )
    publish.replay(frozen, store=store, ownership=recovered, runtime=runtime, now=NOW)
    assert state.read_control(store, "completed.json") is not None


def test_unresolved_request_cannot_use_an_absence_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class UnacceptedStore(CountingStore):
        def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
            if ref.object_class == "package":
                raise UnknownWrite()
            return super().create(ref, source)

    store = UnacceptedStore(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    frozen = state.freeze(store, owner, generation(tmp_path / "input", owner))
    monkeypatch.setattr(publish, "_adapter", AdapterDouble().select)
    with pytest.raises(UnknownWrite):
        publish.replay(
            frozen,
            store=store,
            ownership=owner,
            runtime=Runtime(tmp_path / "runtime", environ={}),
            now=NOW,
        )
    with pytest.raises(state.StateError, match="explicit resolution"):
        state.recover_owner(
            store,
            expected_nonce=owner.owner_nonce,
            evidence=state.RecoveryEvidence(True, True, "stopped", "CI"),
        )
    assert state.read_control(store, "completed.json") is None


def test_recovery_evidence_etag_must_match_verified_bytes(tmp_path: Path) -> None:
    store = CountingStore(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    original = generation(tmp_path / "input", owner)
    frozen = state.freeze(store, owner, original)
    output = original.formats[0].outputs[0]
    state.journal_write(
        store,
        owner,
        frozen,
        0,
        {
            "status": "intent",
            "ref": core.json_value(output.ref),
            "mode": "create",
            "expected_etag": None,
            "owner_nonce": owner.owner_nonce,
        },
    )
    store.create(output.ref, output.local_path)
    with pytest.raises(state.StateError, match="differs from evidence"):
        state.recover_owner(
            store,
            expected_nonce=owner.owner_nonce,
            evidence=state.RecoveryEvidence(
                True, True, "operator", "CI", (state.WriteResolution(0, "written", "stale"),)
            ),
        )
    state.check_owner(store, owner)


def test_old_owner_cannot_resume_after_explicit_recovery(tmp_path: Path) -> None:
    store = CountingStore(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    recovered = state.recover_owner(
        store,
        expected_nonce=owner.owner_nonce,
        evidence=state.RecoveryEvidence(True, True, "process stopped", "CI"),
    )
    with pytest.raises(state.StateError, match="changed"):
        state.freeze(store, owner, generation(tmp_path / "input", owner))
    assert isinstance(recovered, Ownership)
