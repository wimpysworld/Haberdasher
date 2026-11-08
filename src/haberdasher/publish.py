"""Reconciliation and replay of frozen, conditionally published generations."""

from __future__ import annotations

import hashlib
import os
import tempfile
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol

from haberdasher import admission, core, discovery, state
from haberdasher.config import Config, FormatPolicy, Policy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    NativeIdentity,
    ObjectRef,
    OutputObject,
    Ownership,
    PreparedFormat,
    PreparedGeneration,
    RetainedFormat,
    VerifiedAsset,
    canonical_json,
    json_value,
    public_inventory,
    sha256_file,
    utc_now,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession, signing_session
from haberdasher.state import FrozenGeneration, StateError, Store


class Adapter(Protocol):
    def inspect(
        self, asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
    ) -> InspectedAsset: ...
    def compare(
        self, left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime
    ) -> int | None: ...
    def validate_retained(
        self, retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime
    ) -> None: ...
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
    ) -> PreparedFormat: ...
    def validate_prepared(
        self, prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime, now: datetime
    ) -> None: ...


def _adapter(name: str) -> Adapter:
    match name:
        case "apt":
            from haberdasher.formats import apt

            return apt
        case "rpm":
            from haberdasher.formats import rpm

            return rpm
        case "arch":
            from haberdasher.formats import arch

            return arch
        case "apk":
            from haberdasher.formats import apk

            return apk
        case "flatpak":
            from haberdasher.formats import flatpak

            return flatpak
        case _:
            raise ValueError("Unknown publication format")


@dataclass(frozen=True)
class RunResult:
    generation_id: str | None
    changed: bool
    published_objects: int
    pending_assets: int = 0


def _format(filename: str) -> str | None:
    for suffix, name in (
        (".deb", "apt"),
        (".rpm", "rpm"),
        (".pkg.tar.zst", "arch"),
        (".apk", "apk"),
        (".flatpak", "flatpak"),
    ):
        if filename.endswith(suffix):
            return name
    return None


def _hash(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def prepare_bootstrap(
    prepared: Sequence[PreparedFormat],
    committed: state.CommittedState,
    signer: SigningSession,
    *,
    out: Path,
) -> tuple[tuple[OutputObject, ...], tuple[ObjectRef, ...]]:
    out.mkdir(mode=0o700)
    armoured, binary, rsa = signer.public_exports(out)
    refs = {(ref.bucket_role, ref.key): ref for ref in committed.bootstrap_objects}
    outputs: list[OutputObject] = []
    for item in prepared:
        if item.retained.metadata:
            if item.format == "apk":
                native = next(
                    ref for ref in item.referenced_objects if ref.key == "keys/haberdasher.rsa.pub"
                )
                if sha256_file(rsa) != (native.sha256, native.size):
                    raise StateError("APK bootstrap key differs from the approved signing primary")
            elif item.retained.metadata.get("fingerprint") != signer.fingerprint:
                raise StateError("Native metadata differs from the approved signing fingerprint")
        for path in (armoured, binary):
            sha, size = sha256_file(path)
            ref = ObjectRef(
                item.format,
                f"keys/{path.name}",
                "dependency",
                size,
                sha,
                "application/pgp-keys",
                "public, max-age=31536000, immutable",
            )
            previous = refs.get((item.format, ref.key))
            if previous is not None:
                if previous != ref:
                    raise StateError("Bootstrap key changes require explicit rotation approval")
            else:
                refs[item.format, ref.key] = ref
                outputs.append(OutputObject(ref, path, "create", None, len(outputs)))
    return tuple(outputs), tuple(refs.values())


def replay(
    frozen: FrozenGeneration,
    *,
    store: Store,
    ownership: Ownership,
    runtime: Runtime,
    now: datetime,
    clock: Callable[[], datetime] | None = None,
) -> RunResult:
    if clock is None:
        clock = core.utc_now
    state.check_owner(store, ownership)
    if state.pending_generation(store) != frozen:
        raise StateError("Replay must use the pending private generation")
    with tempfile.TemporaryDirectory(prefix="hd-replay-", dir=runtime.root) as temporary:
        root = Path(temporary)
        generation, manifest = state.load_frozen(store, frozen, out=root / "frozen")
        state.check_expiry(generation, clock())
        policies = state.mapping(generation.scan.get("policies"))
        for prepared in generation.formats:
            if prepared.retained.metadata:
                _adapter(prepared.format).validate_prepared(
                    prepared,
                    policy=state.decode_record(FormatPolicy, policies[prepared.format]),
                    runtime=runtime,
                    now=now,
                )
        outputs = state.publication_outputs(generation, out=root)
        prior_etags = state.mapping(manifest.get("prior_etags"))
        changed = {(output.ref.bucket_role, output.ref.key) for output in outputs}
        for prepared in generation.formats:
            for ref in prepared.referenced_objects:
                if (ref.bucket_role, ref.key) not in changed:
                    observed = store.stat(ref)
                    if (
                        observed is None
                        or observed.size != ref.size
                        or observed.etag != prior_etags.get(f"{ref.bucket_role}/{ref.key}")
                    ):
                        raise StateError("An unchanged public dependency changed before replay")
        for ref in generation.bootstrap_objects:
            if (ref.bucket_role, ref.key) not in changed:
                observed = store.download(ref, root / "verified-bootstrap")
                if observed.etag != prior_etags.get(f"{ref.bucket_role}/{ref.key}"):
                    raise StateError("An unchanged bootstrap dependency changed before replay")
        journal, _ = state.read_journal(store, frozen)
        writes = state.mapping(journal["writes"])
        count = 0
        for ordinal, output in enumerate(outputs):
            state.check_owner(store, ownership)
            record = state.mapping(writes.get(str(ordinal), {}))
            if record.get("status") == "ack":
                observed = (
                    store.download(output.ref, root / "verified-bootstrap")
                    if output.ref in generation.bootstrap_objects
                    else store.stat(output.ref)
                )
                if (
                    record.get("sha256") != output.ref.sha256
                    or observed is None
                    or observed.size != output.ref.size
                    or observed.etag != record.get("etag")
                ):
                    raise StateError("Acknowledged public object changed")
                continue
            if record and record.get("status") != "retry":
                raise StateError("Unresolved write intent requires stopped-owner recovery")
            state.journal_write(
                store,
                ownership,
                frozen,
                ordinal,
                {
                    "status": "intent",
                    "ref": json_value(output.ref),
                    "mode": output.mode,
                    "expected_etag": output.expected_etag,
                    "owner_nonce": ownership.owner_nonce,
                },
            )
            state.check_owner(store, ownership)
            if output.ref.bucket_role == "apt" and output.ref.object_class == "entry":
                state.check_expiry(generation, clock())
            receipt = (
                store.create(output.ref, output.local_path)
                if output.mode == "create"
                else store.replace(
                    output.ref, output.local_path, expected_etag=output.expected_etag or ""
                )
            )
            observed = store.download(output.ref, root / "verified-write")
            if (
                observed.etag != receipt.etag
                or receipt.sha256 != output.ref.sha256
                or receipt.size != output.ref.size
            ):
                raise StateError("Write acknowledgement differs from verified public bytes")
            state.journal_write(
                store,
                ownership,
                frozen,
                ordinal,
                {
                    "status": "ack",
                    "etag": observed.etag,
                    "sha256": output.ref.sha256,
                },
            )
            count += 1
        state.check_expiry(generation, clock())
        state.complete(store, ownership, frozen, generation, clock=clock)
        state.release(store, ownership)
        return RunResult(generation.id, True, count)


def reconcile(
    config: Config,
    policy: Policy,
    *,
    store: Store,
    runtime: Runtime,
    now: datetime,
    clock: Callable[[], datetime] | None = None,
) -> RunResult:
    now = utc_now(lambda: now)
    names = tuple(sorted(policy.storage.public))
    if not names:
        raise ValueError("Publication needs explicit public destinations")
    if policy.storage.backend == "r2":
        policy.require_remote(names)
    ownership = state.acquire(store, owner=f"local/CI:{os.getpid()}:{uuid.uuid4().hex}")
    with tempfile.TemporaryDirectory(prefix="hd-reconcile-", dir=runtime.root) as temporary:
        root = Path(temporary)
        committed = state.load_committed(store, ownership, out=root / "committed")
        if committed.signing_fingerprint not in (None, policy.expected_signing_fingerprint):
            raise StateError("Signing fingerprint changes require explicit rotation approval")
        for retained_format in committed.formats:
            fingerprint = retained_format.metadata.get("fingerprint")
            if fingerprint is not None and fingerprint != policy.expected_signing_fingerprint:
                raise StateError(
                    "Native signing fingerprint changes require explicit rotation approval"
                )
        scan = discovery.scan_releases(config, runtime=runtime, previous=committed.discovery)
        retained = {item.format: item for item in committed.formats}
        if retained.keys() - set(names):
            raise StateError("Publication cannot discard previously committed formats")
        new_formats = set(names) - retained.keys()
        for name in names:
            retained.setdefault(name, RetainedFormat(name, None, (), (), {}, ()))
        policies = {name: policy.format_policy(config, name) for name in names}
        changed: dict[str, list[discovery.DiscoveredAsset]] = {name: [] for name in names}
        candidates = (
            *scan.changed,
            *(item for item in scan.unchanged if _format(item.source.filename) in new_formats),
        )
        for item in candidates:
            name = _format(item.source.filename)
            if name in changed and item.checksum is not None:
                changed[name].append(item)
        renew: set[str] = set()
        if "apt" in retained and retained["apt"].metadata:
            expiry = retained["apt"].metadata.get("expires_at")
            if not isinstance(expiry, str):
                raise StateError("Committed APT state lacks expiry")
            if datetime.fromisoformat(expiry) - now <= timedelta(
                seconds=policies["apt"].renewal_seconds
            ):
                renew.add("apt")
        config_digest, policy_digest = _hash(config), _hash(policy)
        same_policy = (
            committed.config_digest == config_digest and committed.policy_digest == policy_digest
        )
        missing_bootstrap: set[str] = (
            set(names) - {ref.bucket_role for ref in committed.bootstrap_objects}
            if policy.expected_signing_fingerprint is not None
            else set()
        )
        if (
            not missing_bootstrap
            and not any(changed.values())
            and not renew
            and same_policy
            and scan.state == committed.discovery
        ):
            state.release(store, ownership)
            return RunResult(committed.generation_id, False, 0, len(scan.pending))
        prepared: list[PreparedFormat] = []
        bootstrap_outputs: tuple[OutputObject, ...] = ()
        bootstrap_objects = committed.bootstrap_objects
        needed = {name for name in names if changed[name]} | renew
        for name in names:
            if retained[name].metadata:
                _adapter(name).validate_retained(
                    retained[name], policy=policies[name], runtime=runtime
                )
        if needed or missing_bootstrap:
            if policy.expected_signing_fingerprint is None:
                raise ValueError("Publication requires the expected signing fingerprint")
            with signing_session(
                runtime, expected_fingerprint=policy.expected_signing_fingerprint
            ) as signer:
                for name in names:
                    if name not in needed:
                        expiry = retained[name].metadata.get("expires_at")
                        prepared.append(
                            PreparedFormat(
                                name,
                                retained[name],
                                (),
                                retained[name].objects,
                                expiry if isinstance(expiry, str) else None,
                            )
                        )
                        continue
                    adapter = _adapter(name)
                    additions: list[AdmittedAsset] = []
                    for index, item in enumerate(changed[name]):
                        if item.checksum is None:
                            raise StateError("Changed input lacks a verified checksum")
                        verified = discovery.verify_asset(
                            item.source,
                            item.checksum,
                            runtime=runtime,
                            out=root / f"{name}-{index}-asset",
                        )
                        inspected = adapter.inspect(
                            verified,
                            policy=policies[name],
                            runtime=runtime,
                            out=root / f"{name}-{index}-inspect",
                        )
                        accepted = admission.admit(
                            inspected,
                            (*retained[name].accepted_history, *additions),
                            compare=adapter.compare,
                            policy=policies[name],
                            runtime=runtime,
                        )
                        if (
                            accepted not in retained[name].accepted_history
                            and accepted not in additions
                        ):
                            additions.append(accepted)
                    if not additions and name not in renew:
                        expiry = retained[name].metadata.get("expires_at")
                        prepared.append(
                            PreparedFormat(
                                name,
                                retained[name],
                                (),
                                retained[name].objects,
                                expiry if isinstance(expiry, str) else None,
                            )
                        )
                        continue
                    result = adapter.prepare(
                        additions,
                        retained[name],
                        policy=policies[name],
                        runtime=runtime,
                        signer=signer,
                        now=now,
                        out=root / f"{name}-prepared",
                    )
                    prior_etags = state.mapping(retained[name].metadata.get("etags", {}))
                    prior_keys = {ref.key for ref in retained[name].objects}
                    for output in result.outputs:
                        if output.ref.key in prior_keys:
                            if output.mode != "replace" or output.expected_etag != prior_etags.get(
                                output.ref.key
                            ):
                                raise StateError(
                                    "Adapter changed the observed prior write precondition"
                                )
                        elif output.mode != "create":
                            raise StateError("A new object requires conditional creation")
                    if result.retained.metadata:
                        result = replace(
                            result,
                            retained=replace(
                                result.retained,
                                metadata={**result.retained.metadata, "etags": dict(prior_etags)},
                            ),
                        )
                    adapter.validate_prepared(
                        result, policy=policies[name], runtime=runtime, now=now
                    )
                    prepared.append(result)
                bootstrap_outputs, bootstrap_objects = prepare_bootstrap(
                    prepared, committed, signer, out=root / "bootstrap"
                )
        else:
            for name in names:
                expiry = retained[name].metadata.get("expires_at")
                prepared.append(
                    PreparedFormat(
                        name,
                        retained[name],
                        (),
                        retained[name].objects,
                        expiry if isinstance(expiry, str) else None,
                    )
                )
        inventories = {
            item.format: json_value(
                public_inventory(
                    item.retained.accepted_history,
                    (
                        *item.referenced_objects,
                        *(ref for ref in bootstrap_objects if ref.bucket_role == item.format),
                    ),
                )
            )
            for item in prepared
        }
        generation = PreparedGeneration(
            uuid.uuid4().hex,
            committed.generation_id,
            committed.completion_etag,
            ownership.owner_nonce,
            config_digest,
            policy_digest,
            {
                "state": json_value(scan.state),
                "policies": json_value(policies),
                "inventory_etags": json_value(committed.inventory_etags),
            },
            tuple(prepared),
            inventories,
            state.EMPTY_HASH,
            bootstrap_outputs,
            bootstrap_objects,
            policy.expected_signing_fingerprint,
        )
        frozen = state.freeze(store, ownership, generation)
        result = replay(
            frozen, store=store, ownership=ownership, runtime=runtime, now=now, clock=clock
        )
        return replace(result, pending_assets=len(scan.pending))
