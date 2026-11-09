"""Locked reconciliation of releases into each format's public bucket."""

from __future__ import annotations

import contextlib
import hashlib
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol

from haberdasher import admission, discovery, state
from haberdasher.config import Config, FormatPolicy, Policy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    NativeIdentity,
    ObjectRef,
    OutputObject,
    PreparedFormat,
    Report,
    RetainedFormat,
    VerifiedAsset,
    plural,
    quiet,
    sha256_file,
    step,
    utc_now,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession, signing_session
from haberdasher.state import Published, StateError, Store


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
    changed: bool
    published_objects: int
    pending_assets: int = 0
    packages: int = 0
    repositories: int = 0


def _format(filename: str) -> str | None:
    for suffix, name in (
        (".deb", "apt"),
        (".rpm", "rpm"),
        (".pkg.tar.zst", "arch"),
        (".pkg.tar.xz", "arch"),
        (".apk", "apk"),
        (".flatpak", "flatpak"),
    ):
        if filename.endswith(suffix):
            return name
    return None


def provided(scan: discovery.CompleteScan) -> set[str]:
    """Formats that the scanned release assets contain."""
    return {
        name
        for record in scan.state.records
        if (name := _format(record.source.filename)) is not None
    }


def new_assets(
    scan: discovery.CompleteScan, published: Mapping[str, Published]
) -> dict[str, list[discovery.DiscoveredAsset]]:
    """Group checksummed assets by format, without the bytes that each inventory already holds."""
    result: dict[str, list[discovery.DiscoveredAsset]] = {name: [] for name in published}
    for item in scan.checksummed:
        name = _format(item.source.filename)
        if name not in result or item.checksum is None:
            continue
        accepted = published[name].retained.accepted_history
        if any(asset.inspected.verified.sha256 == item.checksum.sha256 for asset in accepted):
            continue
        result[name].append(item)
    return result


def prepare_bootstrap(
    prepared: Sequence[PreparedFormat],
    published: Sequence[ObjectRef],
    signer: SigningSession,
    *,
    out: Path,
) -> tuple[tuple[OutputObject, ...], tuple[ObjectRef, ...]]:
    out.mkdir(mode=0o700)
    armoured, binary, rsa = signer.public_exports(out)
    refs = {(ref.bucket_role, ref.key): ref for ref in published}
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
                    raise StateError(
                        "Bootstrap key changes need a key rotation, which is not supported"
                    )
            else:
                refs[item.format, ref.key] = ref
                outputs.append(OutputObject(ref, path, "create", None, len(outputs)))
    return tuple(outputs), tuple(refs.values())


def _write(store: Store, output: OutputObject) -> None:
    """Replace published entries conditionally. Overwrite unreferenced leftovers of a failed run."""
    if output.mode == "replace":
        store.replace(output.ref, output.local_path, expected_etag=output.expected_etag or "")
        return
    observed = store.stat(output.ref)
    if observed is None:
        store.create(output.ref, output.local_path)
    else:
        store.replace(output.ref, output.local_path, expected_etag=observed.etag)


def _unchanged(published: Published) -> PreparedFormat:
    expiry = published.retained.metadata.get("expires_at")
    return PreparedFormat(
        published.format,
        published.retained,
        (),
        published.retained.objects,
        expiry if isinstance(expiry, str) else None,
    )


def reconcile(
    config: Config,
    policy: Policy,
    *,
    store: Store,
    runtime: Runtime,
    now: datetime,
    report: Report = quiet,
    scan: discovery.CompleteScan | None = None,
) -> RunResult:
    now = utc_now(lambda: now)
    if not policy.storage.public:
        raise ValueError("Publication needs explicit public destinations")
    if policy.storage.backend == "r2":
        policy.require_remote()
    names = sorted(policy.storage.public)
    lock = state.acquire(store, policy.storage.public, now=now)
    for name in names:
        step(report, name, "locked")
    try:
        result = _reconcile(
            config, policy, store=store, runtime=runtime, now=now, report=report, scan=scan
        )
    except BaseException:
        with contextlib.suppress(Exception):
            state.release(store, lock)
            for name in names:
                step(report, name, "unlocked")
        raise
    state.release(store, lock)
    for name in names:
        step(report, name, "unlocked")
    return result


def _reconcile(
    config: Config,
    policy: Policy,
    *,
    store: Store,
    runtime: Runtime,
    now: datetime,
    report: Report,
    scan: discovery.CompleteScan | None,
) -> RunResult:
    names = tuple(sorted(policy.storage.public))
    fingerprint = policy.expected_signing_fingerprint
    published = {name: state.read(store, name) for name in names}
    for item in published.values():
        value = item.retained.metadata.get("fingerprint")
        if value is not None and value != fingerprint:
            raise StateError(
                "Native signing fingerprint changes need a key rotation, which is not supported"
            )
    policies = {name: config.format_policy(name) for name in names}
    if scan is None:
        scan = discovery.scan_releases(config, runtime=runtime, report=report)
    changed = new_assets(scan, published)
    renew: set[str] = set()
    if "apt" in published and published["apt"].retained.metadata:
        expiry = published["apt"].retained.metadata.get("expires_at")
        if not isinstance(expiry, str):
            raise StateError("Published APT state lacks expiry")
        if datetime.fromisoformat(expiry) - now <= timedelta(
            seconds=policies["apt"].renewal_seconds
        ):
            renew.add("apt")
    if "flatpak" in published and published["flatpak"].retained.metadata:
        from haberdasher.formats import flatpak

        if flatpak.missing_entries(published["flatpak"].retained):
            renew.add("flatpak")
    missing_bootstrap: set[str] = (
        {name for name in names if len(published[name].bootstrap) != 2}
        if fingerprint is not None
        else set()
    )
    needed = {name for name in names if changed[name]} | renew
    if not missing_bootstrap and not needed:
        for name in names:
            step(report, name, "unchanged")
        return RunResult(False, 0, len(scan.pending))
    if fingerprint is None:
        raise ValueError("Publication requires the expected signing fingerprint")
    with tempfile.TemporaryDirectory(prefix="hd-reconcile-", dir=runtime.root) as temporary:
        root = Path(temporary)
        prepared: list[PreparedFormat] = []
        with signing_session(runtime, expected_fingerprint=fingerprint) as signer:
            for name in names:
                if name not in needed:
                    step(
                        report,
                        name,
                        "adding public keys" if name in missing_bootstrap else "unchanged",
                    )
                    prepared.append(_unchanged(published[name]))
                    continue
                step(
                    report,
                    name,
                    f"preparing {plural(len(changed[name]), 'new package')}"
                    if changed[name]
                    else "renewing metadata",
                )
                prepared.append(
                    _prepare(
                        name,
                        changed[name],
                        state.materialise(store, published[name], out=root / f"{name}-published"),
                        renew=name in renew,
                        policy=policies[name],
                        runtime=runtime,
                        signer=signer,
                        now=now,
                        out=root / name,
                    )
                )
                if prepared[-1].outputs:
                    step(report, name, "signed metadata")
            bootstrap_outputs, bootstrap_objects = prepare_bootstrap(
                prepared,
                tuple(ref for item in published.values() for ref in item.bootstrap),
                signer,
                out=root / "bootstrap",
            )
        count = 0
        packages = 0
        repositories = 0
        for item in prepared:
            current = published[item.format]
            bootstrap = tuple(ref for ref in bootstrap_objects if ref.bucket_role == item.format)
            data = state.inventory(item, bootstrap, current)
            outputs = (
                *(output for output in bootstrap_outputs if output.ref.bucket_role == item.format),
                *item.outputs,
            )
            if not outputs and hashlib.sha256(data).hexdigest() == current.sha256:
                continue
            for output in outputs:
                if (
                    output.ref.object_class == "entry"
                    and item.expires_at is not None
                    and datetime.fromisoformat(item.expires_at) <= utc_now()
                ):
                    raise StateError("APT metadata expired before publication; rerun")
                _write(store, output)
                count += 1
            if outputs:
                step(report, item.format, f"uploaded {plural(len(outputs), 'object')}")
            state.write_inventory(store, current, data)
            step(report, item.format, f"wrote {state.INVENTORY_KEY}")
            count += 1
            repositories += 1
            packages += len(item.retained.accepted_history) - len(current.retained.accepted_history)
        return RunResult(True, count, len(scan.pending), packages, repositories)


def _prepare(
    name: str,
    changed: Sequence[discovery.DiscoveredAsset],
    retained: RetainedFormat,
    *,
    renew: bool,
    policy: FormatPolicy,
    runtime: Runtime,
    signer: SigningSession,
    now: datetime,
    out: Path,
) -> PreparedFormat:
    adapter = _adapter(name)
    adapter.validate_retained(retained, policy=policy, runtime=runtime)
    additions: list[AdmittedAsset] = []
    inspected_assets: list[InspectedAsset] = []
    for index, item in enumerate(changed):
        if item.checksum is None:
            raise StateError("Changed input lacks a verified checksum")
        verified = discovery.verify_asset(
            item.source, item.checksum, runtime=runtime, out=out.with_name(f"{name}-{index}-asset")
        )
        inspected_assets.append(
            adapter.inspect(
                verified,
                policy=policy,
                runtime=runtime,
                out=out.with_name(f"{name}-{index}-inspect"),
            )
        )
    for inspected in inspected_assets:
        accepted = admission.admit(
            inspected,
            (*retained.accepted_history, *additions),
            compare=adapter.compare,
            policy=policy,
            runtime=runtime,
        )
        if accepted not in retained.accepted_history and accepted not in additions:
            additions.append(accepted)
    if not additions and not renew:
        return PreparedFormat(name, retained, (), retained.objects)
    result = adapter.prepare(
        additions, retained, policy=policy, runtime=runtime, signer=signer, now=now, out=out
    )
    etags = state.mapping(retained.metadata.get("etags", {}))
    prior = {ref.key for ref in retained.objects}
    for output in result.outputs:
        if output.ref.key in prior:
            if output.mode != "replace" or output.expected_etag != etags.get(output.ref.key):
                raise StateError("Adapter changed the observed prior write precondition")
        elif output.mode != "create":
            raise StateError("A new object requires conditional creation")
    adapter.validate_prepared(result, policy=policy, runtime=runtime, now=now)
    return result
