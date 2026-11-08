from __future__ import annotations

import multiprocessing
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from haberdasher import state
from haberdasher.storage import PreconditionFailed
from tests.unit.test_state import NOW, local_store

if TYPE_CHECKING:
    from multiprocessing.queues import Queue
    from multiprocessing.synchronize import Event


def _owner_process(root: Path, label: str, ready: Queue[tuple[str, str]], stop: Event) -> None:
    store = local_store(root)
    try:
        owner = state.acquire(store, owner=label)
    except state.StateError, PreconditionFailed:
        ready.put((label, "blocked"))
        return
    ready.put((label, owner.owner_nonce))
    if not stop.wait(15):
        raise RuntimeError("Test owner did not receive its stop event")
    state.release(store, owner)


def test_paused_local_owner_blocks_distinct_ci_process(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    stop = context.Event()
    local = context.Process(target=_owner_process, args=(tmp_path / "store", "local", ready, stop))
    ci = context.Process(target=_owner_process, args=(tmp_path / "store", "CI", ready, stop))
    local.start()
    try:
        label, nonce = ready.get(timeout=10)
        assert label == "local" and nonce != "blocked"
        ci.start()
        assert ready.get(timeout=10) == ("CI", "blocked")
        ci.join(timeout=10)
        assert ci.exitcode == 0 and local.is_alive()
    finally:
        stop.set()
        local.join(timeout=10)
        if ci.pid is not None:
            ci.join(timeout=10)
    assert local.exitcode == 0
    next_ci = context.Process(target=_owner_process, args=(tmp_path / "store", "CI", ready, stop))
    next_ci.start()
    label, next_nonce = ready.get(timeout=10)
    next_ci.join(timeout=10)
    assert label == "CI" and next_nonce not in {nonce, "blocked"}
    assert next_ci.exitcode == 0
    ready.close()
    ready.join_thread()


def test_owner_never_expires_and_release_is_conditional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    monkeypatch.setattr(state, "utc_now", lambda: NOW + timedelta(days=36500))
    with pytest.raises(state.StateError, match="already holds"):
        state.acquire(store, owner="CI")
    state.release(store, owner)
    next_owner = state.acquire(store, owner="CI")
    with pytest.raises(state.StateError, match="changed"):
        state.release(store, owner)
    assert next_owner.owner_nonce != owner.owner_nonce
    assert next_owner.etag != owner.etag
    state.release(store, next_owner)


def test_recovery_requires_explicit_stopped_owner_evidence(tmp_path: Path) -> None:
    store = local_store(tmp_path / "store")
    owner = state.acquire(store, owner="local")
    for stopped, resolved in ((False, True), (True, False), (False, False)):
        with pytest.raises(ValueError, match="stopped owner"):
            state.RecoveryEvidence(stopped, resolved, "operator record", "CI")
    evidence = state.RecoveryEvidence(True, True, "operator checked process and requests", "CI")
    with pytest.raises(state.StateError, match="does not match"):
        state.recover_owner(store, expected_nonce="wrong", evidence=evidence)
    recovered = state.recover_owner(store, expected_nonce=owner.owner_nonce, evidence=evidence)
    assert recovered.owner_nonce != owner.owner_nonce
    with pytest.raises(state.StateError, match="changed"):
        state.check_owner(store, owner)
    state.release(store, recovered)
