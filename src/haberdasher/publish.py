"""Locked reconciliation of releases into each format's public bucket."""

from __future__ import annotations

import contextlib
import hashlib
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from haberdasher import admission, discovery, site, state
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
    UnsupportedAsset,
    VerifiedAsset,
    plural,
    quiet,
    sha256_file,
    size_text,
    stale_entries,
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
        self, prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime
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
        case "brew":
            from haberdasher.formats import brew

            return brew
        case "scoop":
            from haberdasher.formats import scoop

            return scoop
        case "nix":
            from haberdasher.formats import nix

            return nix
        case _:
            raise ValueError("Unknown publication format")


@dataclass(frozen=True)
class RunResult:
    changed: bool
    published_objects: int
    pending_assets: int = 0
    packages: int = 0
    repositories: tuple[str, ...] = ()
    pages: tuple[str, ...] = ()


def _siblings(scan: discovery.CompleteScan) -> dict[tuple[str, int], set[str]]:
    groups: dict[tuple[str, int], set[str]] = {}
    for asset in scan.state.assets:
        groups.setdefault((asset.repository, asset.release_id), set()).add(asset.filename)
    return groups


def provided(scan: discovery.CompleteScan) -> set[str]:
    """Formats that the scanned release assets contain."""
    siblings = _siblings(scan)
    return {
        name
        for record in scan.state.records
        for name in discovery.asset_formats(
            record.source.filename,
            siblings.get((record.source.repository, record.source.release_id), ()),
        )
    }


def new_assets(
    scan: discovery.CompleteScan, published: Mapping[str, Published]
) -> dict[str, list[discovery.DiscoveredAsset]]:
    """Group checksummed assets by format, without the bytes that each inventory already holds."""
    siblings = _siblings(scan)
    result: dict[str, list[discovery.DiscoveredAsset]] = {name: [] for name in published}
    for item in scan.checksummed:
        if item.checksum is None:
            continue
        group = siblings.get((item.source.repository, item.source.release_id), ())
        for name in discovery.asset_formats(item.source.filename, group):
            if name not in result:
                continue
            accepted = published[name].retained.accepted_history
            if any(asset.inspected.verified.sha256 == item.checksum.sha256 for asset in accepted):
                continue
            result[name].append(item)
    return result


# Homebrew and Scoop trust HTTPS and the manifest hash, so their buckets hold no public keys.
UNSIGNED = frozenset({"brew", "scoop"})


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
        if item.format in UNSIGNED:
            continue
        if item.retained.metadata:
            if item.format == "apk":
                native = next(
                    ref for ref in item.referenced_objects if ref.key == "keys/haberdasher.rsa.pub"
                )
                if sha256_file(rsa) != (native.sha256, native.size):
                    raise StateError(
                        "APK bootstrap key differs from the Haberdasher signing primary"
                    )
            elif item.retained.metadata.get("fingerprint") != signer.fingerprint:
                raise StateError("Native metadata differs from the expected signing fingerprint")
            if item.format == "nix":
                _, nix_pub, _ = signer.nix_key()
                nix_ref = next(
                    ref for ref in item.referenced_objects if ref.key == "keys/haberdasher-nix.pub"
                )
                if sha256_file(nix_pub) != (nix_ref.sha256, nix_ref.size):
                    raise StateError("Nix public key differs from the Haberdasher signing primary")
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


def _listing(name: str, refs: Sequence[ObjectRef]) -> list[str]:
    """Name each object and its size in key order, with Flatpak and Git objects as one line."""
    lines: dict[str, str] = {}
    folded = {
        "flatpak": "objects/",
        "brew": "tap.git/objects/",
        "scoop": "wimpysworld/haberdasher.git/objects/",
        "nix": "packages.git/objects/",
    }.get(name)
    objects = [ref for ref in refs if folded and ref.key.startswith(folded)]
    for ref in refs:
        if ref not in objects:
            lines[ref.key] = f"{ref.key} ({size_text(ref.size)})"
    if objects:
        size = size_text(sum(ref.size for ref in objects))
        lines[folded or ""] = f"{folded} {plural(len(objects), 'file')} ({size})"
    return [f"  {lines[key]}" for key in sorted(lines)]


def _duration(seconds: float) -> str:
    minutes, seconds = divmod(round(seconds), 60)
    return f"{minutes}m{seconds:02d}s" if minutes else f"{seconds}s"


def write_page(
    store: Store,
    published: Published,
    *,
    fingerprint: str,
    fallback: Mapping[str, str],
    now: datetime,
    report: Report = quiet,
) -> int:
    """Write a format's og.png and index.html when each is missing or differs. Count the writes."""
    count = write_image(store, published.format, report=report)
    data, digest = site.page(
        published.format, published, fingerprint=fingerprint, fallback=fallback, now=now
    )
    current = store.read(published.format, site.PAGE_KEY, max_bytes=site.MAX_PAGE_BYTES)
    if current is not None and site.content_hash(current[0]) == digest:
        return count
    expected = None if current is None else current[1].etag
    state.write_object(store, site.ref(published.format, data), data, expected)
    step(report, published.format, f"wrote {site.PAGE_KEY}")
    return count + 1


def write_image(store: Store, name: str, *, report: Report = quiet) -> int:
    """Write a format's og.png when it is missing or its bytes differ."""
    data = site.image(name)
    current = store.read(name, site.IMAGE_KEY, max_bytes=site.MAX_IMAGE_BYTES)
    if current is not None and current[0] == data:
        return 0
    expected = None if current is None else current[1].etag
    state.write_object(store, site.image_ref(name, data), data, expected)
    step(report, name, f"wrote {site.IMAGE_KEY}")
    return 1


def _unchanged(published: Published) -> PreparedFormat:
    return PreparedFormat(published.format, published.retained, (), published.retained.objects)


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


def inspect_new(
    name: str,
    changed: Sequence[discovery.DiscoveredAsset],
    *,
    policy: FormatPolicy,
    runtime: Runtime,
    out: Path,
    report: Report = quiet,
    verified_cache: dict[tuple[str, int], VerifiedAsset] | None = None,
) -> list[InspectedAsset]:
    """Download, verify, and inspect new assets. Skip an unsupported asset with one line."""
    adapter = _adapter(name)
    inspected: list[InspectedAsset] = []
    for index, item in enumerate(changed):
        if item.checksum is None:
            raise StateError("Changed input lacks a verified checksum")
        cache_key = (item.source.repository, item.source.asset_id)
        verified = None if verified_cache is None else verified_cache.get(cache_key)
        if verified is None:
            verified = discovery.verify_asset(
                item.source,
                item.checksum,
                runtime=runtime,
                out=out.with_name(f"{name}-{index}-asset"),
            )
            if verified_cache is not None:
                verified_cache[cache_key] = verified
        try:
            inspected.append(
                adapter.inspect(
                    verified,
                    policy=policy,
                    runtime=runtime,
                    out=out.with_name(f"{name}-{index}-inspect"),
                )
            )
        except UnsupportedAsset as error:
            step(report, name, f"skipped {error}")
    return inspected


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
    missing_bootstrap: set[str] = (
        {name for name in names if name not in UNSIGNED and len(published[name].bootstrap) != 2}
        if fingerprint is not None
        else set()
    )
    with tempfile.TemporaryDirectory(prefix="hd-reconcile-", dir=runtime.root) as temporary:
        root = Path(temporary)
        verified_cache: dict[tuple[str, int], VerifiedAsset] = {}
        inspected = {
            name: inspect_new(
                name,
                changed[name],
                policy=policies[name],
                runtime=runtime,
                out=root / name,
                report=report,
                verified_cache=verified_cache,
            )
            for name in names
        }
        if not missing_bootstrap and not any(inspected.values()):
            for name in names:
                step(report, name, "unchanged")
            if fingerprint is None:
                return RunResult(False, 0, len(scan.pending))
            fallback = site.descriptions(
                item.retained.accepted_history for item in published.values()
            )
            writes = {
                name: write_page(
                    store,
                    published[name],
                    fingerprint=fingerprint,
                    fallback=fallback,
                    now=now,
                    report=report,
                )
                for name in names
            }
            pages = tuple(name for name in names if writes[name])
            return RunResult(bool(pages), sum(writes.values()), len(scan.pending), pages=pages)
        if fingerprint is None:
            raise ValueError("Publication requires the expected signing fingerprint")
        prepared: list[PreparedFormat] = []
        with signing_session(runtime, expected_fingerprint=fingerprint) as signer:
            for name in names:
                if not inspected[name]:
                    step(
                        report,
                        name,
                        "adding public keys" if name in missing_bootstrap else "unchanged",
                    )
                    prepared.append(_unchanged(published[name]))
                    continue
                step(report, name, f"preparing {plural(len(inspected[name]), 'new package')}")
                prepared.append(
                    _prepare(
                        name,
                        inspected[name],
                        state.materialise(store, published[name], out=root / f"{name}-published"),
                        policy=policies[name],
                        runtime=runtime,
                        signer=signer,
                        now=now,
                        out=root / name,
                    )
                )
                if prepared[-1].outputs and name not in UNSIGNED:
                    step(report, name, "signed metadata")
            bootstrap_outputs, bootstrap_objects = prepare_bootstrap(
                prepared,
                tuple(ref for item in published.values() for ref in item.bootstrap),
                signer,
                out=root / "bootstrap",
            )
        count = 0
        packages = 0
        repositories: list[str] = []
        written: list[str] = []
        fallback = site.descriptions(item.retained.accepted_history for item in prepared)
        for item in prepared:
            current = published[item.format]
            bootstrap = tuple(ref for ref in bootstrap_objects if ref.bucket_role == item.format)
            data = state.inventory(item, bootstrap, current)
            outputs = (
                *(output for output in bootstrap_outputs if output.ref.bucket_role == item.format),
                *item.outputs,
            )
            if not outputs and hashlib.sha256(data).hexdigest() == current.sha256:
                if wrote := write_page(
                    store,
                    current,
                    fingerprint=fingerprint,
                    fallback=fallback,
                    now=now,
                    report=report,
                ):
                    written.append(item.format)
                    count += wrote
                continue
            batch = [
                output
                for output in outputs
                if output.mode == "create" and output.ref.object_class != "entry"
            ]
            if batch:
                size = sum(output.ref.size for output in batch)
                step(
                    report,
                    item.format,
                    f"uploading {plural(len(batch), 'object')} ({size_text(size)})",
                )
                for line in _listing(item.format, [output.ref for output in batch]):
                    step(report, item.format, line)
                started = time.monotonic()
                store.upload(
                    batch, progress=lambda line, name=item.format: step(report, name, line)
                )
                elapsed = _duration(time.monotonic() - started)
                step(report, item.format, f"uploaded {plural(len(batch), 'object')} in {elapsed}")
                count += len(batch)
            for output in outputs:
                if output in batch:
                    continue
                step(report, item.format, f"  {output.ref.key} ({size_text(output.ref.size)})")
                _write(store, output)
                count += 1
            state.write_inventory(store, current, data)
            step(report, item.format, f"wrote {state.INVENTORY_KEY}")
            count += 1
            repositories.append(item.format)
            packages += len(item.retained.accepted_history) - len(current.retained.accepted_history)
            if wrote := write_page(
                store,
                state.decode_published(item.format, data, None),
                fingerprint=fingerprint,
                fallback=fallback,
                now=now,
                report=report,
            ):
                written.append(item.format)
                count += wrote
        return RunResult(
            True, count, len(scan.pending), packages, tuple(repositories), tuple(written)
        )


def _prepare(
    name: str,
    inspected_assets: Sequence[InspectedAsset],
    retained: RetainedFormat,
    *,
    policy: FormatPolicy,
    runtime: Runtime,
    signer: SigningSession,
    now: datetime,
    out: Path,
) -> PreparedFormat:
    adapter = _adapter(name)
    adapter.validate_retained(retained, policy=policy, runtime=runtime)
    additions: list[AdmittedAsset] = []
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
    if not additions and not stale_entries(retained):
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
    adapter.validate_prepared(result, policy=policy, runtime=runtime)
    return result
