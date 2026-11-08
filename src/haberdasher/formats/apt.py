"""Native APT records, immutable DEBs and expiring signed Release entries.

Retained metadata contains private ``files`` (public key to restored path),
``etags`` (public key to observed revision), ``keyring`` and its SHA256,
``fingerprint``, ``expires_at`` and ``policy``. The state layer restores files
and supplies observed ETags before replacement. Historical DEBs are not required.
"""

from __future__ import annotations

import gzip
import hashlib
import re
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timedelta
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path

from haberdasher.config import FormatPolicy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    JSONValue,
    NativeIdentity,
    ObjectRef,
    OutputObject,
    PreparedFormat,
    RetainedFormat,
    VerifiedAsset,
    atomic_write,
    safe_path,
    sha256_file,
    utc_now,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession


class AptFailure(ValueError):
    pass


def _run(runtime: Runtime, argv: Sequence[str], *, cwd: Path | None = None) -> bytes:
    result = runtime.run(argv, cwd=cwd)
    if result.returncode:
        raise AptFailure(f"APT native command failed: {argv[0]}")
    return result.stdout


def _fields(record: str) -> dict[str, str]:
    if not record or len(record.encode()) > 4 * 1024 * 1024 or "\r" in record:
        raise AptFailure("Invalid or oversized APT record")
    fields: dict[str, str] = {}
    name = ""
    for line in record.rstrip("\n").split("\n"):
        if line.startswith((" ", "\t")) and name:
            fields[name] += "\n" + line
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*(.*)", line)
        if match is None or match[1] in fields:
            raise AptFailure("Malformed or duplicate APT field")
        name = match[1]
        fields[name] = match[2]
    return fields


def _policy(policy: FormatPolicy) -> dict[str, JSONValue]:
    if policy.format != "apt" or "all" in policy.architectures:
        raise AptFailure("APT requires concrete index architectures")
    return {
        "architectures": list(policy.architectures),
        "suite": policy.suite,
        "component": policy.component,
        "validity_seconds": policy.validity_seconds,
        "renewal_seconds": policy.renewal_seconds,
    }


def _identity(fields: dict[str, str], policy: FormatPolicy) -> NativeIdentity:
    name, version, arch = (fields.get(key, "") for key in ("Package", "Version", "Architecture"))
    if (
        re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name) is None
        or re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", version) is None
        or arch not in (*policy.architectures, "all")
    ):
        raise AptFailure("Invalid or unapproved Debian identity")
    return NativeIdentity("apt", name, arch, version)


def _record(asset: AdmittedAsset, policy: FormatPolicy) -> str:
    inspected = asset.inspected
    record = inspected.metadata.get("record")
    if not isinstance(record, str):
        raise AptFailure("Complete apt-ftparchive record is missing")
    fields = _fields(record)
    if (
        _identity(fields, policy) != inspected.identity
        or fields.get("SHA256") != inspected.verified.sha256
        or fields.get("Size") != str(inspected.verified.size)
        or fields.get("Filename") != f"pool/{inspected.verified.sha256}.deb"
        or asset.transformation_policy != "preserve"
        or asset.published_sha256 not in (None, inspected.verified.sha256)
    ):
        raise AptFailure("APT record differs from accepted identity or bytes")
    return record.rstrip("\n") + "\n\n"


def inspect(
    asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
) -> InspectedAsset:
    _policy(policy)
    if sha256_file(asset.local_path) != (asset.sha256, asset.size):
        raise AptFailure("Verified DEB bytes changed before inspection")
    control = _run(runtime, ["dpkg-deb", "-f", str(asset.local_path)]).decode("utf-8")
    identity = _identity(_fields(control), policy)
    filename = f"pool/{asset.sha256}.deb"
    target = safe_path(out, filename)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(asset.local_path, target)
    raw = _run(runtime, ["apt-ftparchive", "packages", filename], cwd=out).decode("utf-8")
    fields = _fields(raw)
    inspected = InspectedAsset(
        asset,
        identity,
        {"record": raw},
        {
            "dependencies": {
                key: value
                for key, value in fields.items()
                if key
                in {
                    "Depends",
                    "Pre-Depends",
                    "Recommends",
                    "Suggests",
                    "Provides",
                    "Conflicts",
                    "Breaks",
                    "Replaces",
                    "Multi-Arch",
                }
            }
        },
        "unsigned",
    )
    _record(AdmittedAsset(inspected, "preserve", "inspection"), policy)
    if sha256_file(target) != (asset.sha256, asset.size):
        raise AptFailure("DEB bytes changed during inspection")
    return inspected


def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
    if (left.format, left.name, left.architecture) != (
        right.format,
        right.name,
        right.architecture,
    ):
        return None
    if left.format != "apt":
        raise AptFailure("APT comparison requires Debian identities")
    for operation, order in (("eq", 0), ("lt", -1), ("gt", 1)):
        result = runtime.run(["dpkg", "--compare-versions", left.version, operation, right.version])
        if result.returncode == 0:
            return order
        if result.returncode != 1:
            raise AptFailure("Native Debian version comparison failed")
    raise AptFailure("Native Debian versions have no ordering")


def _indexes(history: Sequence[AdmittedAsset], policy: FormatPolicy) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    records = sorted(
        (asset.inspected.identity.architecture, _record(asset, policy)) for asset in history
    )
    for arch in policy.architectures:
        prefix = f"dists/{policy.suite}/{policy.component}/binary-{arch}/Packages"
        data = "".join(
            record for architecture, record in records if architecture in (arch, "all")
        ).encode()
        result[prefix] = data
        result[prefix + ".gz"] = gzip.compress(data, mtime=0)
    return result


def _strings(value: JSONValue, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or any(not isinstance(item, str) for item in value.values()):
        raise AptFailure(f"Missing or invalid {label}")
    return {key: str(item) for key, item in value.items()}


def _string(metadata: dict[str, JSONValue], name: str) -> str:
    value = metadata.get(name)
    if not isinstance(value, str) or not value:
        raise AptFailure(f"Missing APT {name}")
    return value


def _refs(retained: RetainedFormat) -> dict[str, ObjectRef]:
    refs = {ref.key: ref for ref in retained.objects}
    if len(refs) != len(retained.objects):
        raise AptFailure("Duplicate retained object keys")
    return refs


def _entries(policy: FormatPolicy) -> tuple[str, str, str]:
    prefix = f"dists/{policy.suite}/"
    return prefix + "Release", prefix + "Release.gpg", prefix + "InRelease"


def _byhash(key: str, sha256: str) -> str:
    return key.rsplit("/", 1)[0] + "/by-hash/SHA256/" + sha256


def _verify_release(retained: RetainedFormat, policy: FormatPolicy) -> None:
    files = _strings(retained.metadata.get("files"), "restored metadata files")
    release = _fields(Path(files[_entries(policy)[0]]).read_text())
    if any(
        release.get(key) != value
        for key, value in {
            "Suite": policy.suite,
            "Codename": policy.suite,
            "Components": policy.component,
            "Architectures": " ".join(policy.architectures),
            "Acquire-By-Hash": "yes",
        }.items()
    ):
        raise AptFailure("Release policy differs from approved policy")
    expiry = datetime.fromisoformat(_string(retained.metadata, "expires_at"))
    try:
        date = parsedate_to_datetime(release["Date"])
        valid = parsedate_to_datetime(release["Valid-Until"])
    except (KeyError, ValueError, TypeError) as error:
        raise AptFailure("Invalid Release validity") from error
    if valid != expiry or valid - date != timedelta(seconds=policy.validity_seconds):
        raise AptFailure("Release expiry differs from retained state")
    checksums: dict[str, tuple[str, int]] = {}
    for line in release.get("SHA256", "").splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3 or not parts[1].isdigit() or parts[2] in checksums:
            raise AptFailure("Invalid Release SHA256 list")
        checksums[parts[2]] = (parts[0], int(parts[1]))
    expected = {
        key.removeprefix(f"dists/{policy.suite}/"): (hashlib.sha256(data).hexdigest(), len(data))
        for key, data in _indexes(retained.accepted_history, policy).items()
    }
    if checksums != expected:
        raise AptFailure("Release does not bind the complete indexes")


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    expected_policy = _policy(policy)
    if retained.format != "apt":
        raise AptFailure("Expected APT retained state")
    if not retained.accepted_history:
        if (
            retained.prior_generation is not None
            or retained.objects
            or retained.metadata
            or retained.active_identities
        ):
            raise AptFailure("Incomplete retained APT history")
        return
    if retained.metadata.get("policy") != expected_policy:
        raise AptFailure("Retained APT policy differs from configured policy")
    refs = _refs(retained)
    files = _strings(retained.metadata.get("files"), "restored metadata files")
    _strings(retained.metadata.get("etags"), "observed ETags")
    keyring = Path(_string(retained.metadata, "keyring"))
    if sha256_file(keyring)[0] != _string(retained.metadata, "keyring_sha256"):
        raise AptFailure("Retained public keyring changed")
    if re.fullmatch(r"[A-F0-9]{40}", _string(retained.metadata, "fingerprint")) is None:
        raise AptFailure("Invalid retained signing fingerprint")
    identities = tuple(asset.inspected.identity for asset in retained.accepted_history)
    if identities != retained.active_identities or len(
        set(asset.history_key for asset in retained.accepted_history)
    ) != len(identities):
        raise AptFailure("Incomplete or duplicate active APT history")
    for asset in retained.accepted_history:
        _record(asset, policy)
        verified = asset.inspected.verified
        ref = refs.get(f"pool/{verified.sha256}.deb")
        if ref is None or (ref.sha256, ref.size, ref.object_class) != (
            verified.sha256,
            verified.size,
            "package",
        ):
            raise AptFailure("Retained DEB reference is missing or changed")
        if asset.published_sha256 != verified.sha256:
            raise AptFailure("Published DEB digest must equal its source digest")
    indexes = _indexes(retained.accepted_history, policy)
    if set(files) != set(indexes) | set(_entries(policy)):
        raise AptFailure("Incomplete restored APT metadata")
    for key, filename in files.items():
        ref = refs.get(key)
        if (
            ref is None
            or ref.object_class != "entry"
            or sha256_file(Path(filename)) != (ref.sha256, ref.size)
        ):
            raise AptFailure("Retained metadata bytes are missing or changed")
    for key, data in indexes.items():
        sha = hashlib.sha256(data).hexdigest()
        ref = refs[key]
        hashed = refs.get(_byhash(key, sha))
        if (
            (ref.sha256, ref.size) != (sha, len(data))
            or hashed is None
            or (hashed.sha256, hashed.size, hashed.object_class) != (sha, len(data), "dependency")
        ):
            raise AptFailure("Retained indexes or by-hash references are incomplete")
    _verify_release(retained, policy)


def prepare(
    new: Sequence[AdmittedAsset],
    retained: RetainedFormat,
    *,
    policy: FormatPolicy,
    runtime: Runtime,
    signer: SigningSession,
    now: datetime,
    out: Path,
) -> PreparedFormat:
    now = utc_now(lambda: now).replace(microsecond=0)
    validate_retained(retained, policy=policy, runtime=runtime)
    history = list(retained.accepted_history)
    additions: list[AdmittedAsset] = []
    for asset in new:
        _record(asset, policy)
        if any(
            asset.inspected.identity == prior.inspected.identity
            and asset.inspected.verified.sha256 == prior.inspected.verified.sha256
            for prior in history
        ):
            continue
        for prior in history:
            if compare(asset.inspected.identity, prior.inspected.identity, runtime=runtime) == 0:
                if asset.inspected.verified.sha256 != prior.inspected.verified.sha256:
                    raise AptFailure("Changed bytes for an accepted Debian identity")
                break
        else:
            accepted = replace(asset, published_sha256=asset.inspected.verified.sha256)
            history.append(accepted)
            additions.append(accepted)
    if not history:
        return PreparedFormat("apt", retained, (), retained.objects)
    if retained.accepted_history and not additions:
        expires = _string(retained.metadata, "expires_at")
        if datetime.fromisoformat(expires) - now > timedelta(seconds=policy.renewal_seconds):
            return PreparedFormat("apt", retained, (), retained.objects, expires)
    if retained.accepted_history and signer.fingerprint != retained.metadata["fingerprint"]:
        raise AptFailure("APT signing primary changed without a trust transition")
    safe_path(out, "validation")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise AptFailure("APT preparation requires an empty output directory")
    refs = _refs(retained)
    old_refs = dict(refs)
    etags = _strings(retained.metadata.get("etags", {}), "observed ETags")
    files: dict[str, JSONValue] = {}
    outputs: list[OutputObject] = []

    def output(key: str, path: Path, kind: str) -> None:
        sha, size = sha256_file(path)
        immutable = kind in {"package", "dependency"}
        ref = ObjectRef(
            "apt",
            key,
            kind,
            size,
            sha,
            "application/vnd.debian.binary-package"
            if kind == "package"
            else "application/gzip"
            if key.endswith(".gz")
            else "application/octet-stream",
            "public, max-age=31536000, immutable" if immutable else "no-cache",
        )
        previous = old_refs.get(key)
        if previous is not None and previous.sha256 == sha and previous.size == size:
            refs[key] = previous
            return
        if previous is not None and immutable:
            raise AptFailure("Immutable APT object changed")
        if previous is not None and key not in etags:
            raise AptFailure("Replacement requires an observed retained ETag")
        outputs.append(
            OutputObject(
                ref,
                path,
                "replace" if previous else "create",
                etags.get(key) if previous else None,
                len(outputs),
            )
        )
        refs[key] = ref

    for asset in additions:
        verified = asset.inspected.verified
        if sha256_file(verified.local_path) != (verified.sha256, verified.size):
            raise AptFailure("Admitted DEB bytes changed")
        key = f"pool/{verified.sha256}.deb"
        path = safe_path(out, key)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(verified.local_path, path)
        output(key, path, "package")
    indexes = _indexes(history, policy)
    if additions:
        for key, data in indexes.items():
            path = safe_path(out, key)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic_write(path, data)
            files[key] = str(path)
            hashed = _byhash(key, hashlib.sha256(data).hexdigest())
            hashed_path = safe_path(out, hashed)
            hashed_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic_write(hashed_path, data)
            output(hashed, hashed_path, "dependency")
        for key in indexes:
            output(key, safe_path(out, key), "entry")
    else:
        previous_files = _strings(retained.metadata.get("files"), "restored metadata files")
        files.update({key: previous_files[key] for key in indexes})
    release_key, detached_key, clear_key = _entries(policy)
    release_path = safe_path(out, release_key)
    release_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    expiry = now + timedelta(seconds=policy.validity_seconds)
    options = {
        "MD5": "false",
        "SHA1": "false",
        "SHA512": "false",
        "Suite": policy.suite,
        "Codename": policy.suite,
        "Architectures": " ".join(policy.architectures),
        "Components": policy.component,
        "Acquire-By-Hash": "yes",
        "Date": format_datetime(now, usegmt=True),
    }
    if additions or not retained.accepted_history:
        args = [
            item
            for key, value in options.items()
            for item in ("-o", f"APT::FTPArchive::Release::{key}={value}")
        ]
        release = _run(
            runtime, ["apt-ftparchive", *args, "release", "."], cwd=release_path.parent
        ).decode()
        if "Valid-Until:" in release:
            raise AptFailure("Unexpected native Release expiry")
        release += f"Valid-Until: {format_datetime(expiry, usegmt=True)}\n"
    else:
        previous_files = _strings(retained.metadata.get("files"), "restored metadata files")
        release = Path(previous_files[release_key]).read_text()
        release = re.sub(
            r"^Date:.*$", f"Date: {format_datetime(now, usegmt=True)}", release, flags=re.M
        )
        release = re.sub(
            r"^Valid-Until:.*$",
            f"Valid-Until: {format_datetime(expiry, usegmt=True)}",
            release,
            flags=re.M,
        )
    atomic_write(release_path, release.encode())
    signer.sign_file(release_path, safe_path(out, detached_key))
    signer.sign_file(release_path, safe_path(out, clear_key), clear=True)
    for key in (release_key, detached_key, clear_key):
        path = safe_path(out, key)
        files[key] = str(path)
        output(key, path, "entry")
    keyring = safe_path(out, "trust.gpg")
    if retained.accepted_history:
        atomic_write(keyring, Path(_string(retained.metadata, "keyring")).read_bytes())
    else:
        atomic_write(
            keyring,
            _run(
                runtime,
                [
                    "gpg",
                    "--no-options",
                    "--homedir",
                    str(signer.gnupghome),
                    "--batch",
                    "--export",
                    signer.fingerprint,
                ],
            ),
        )
    if not keyring.stat().st_size:
        raise AptFailure("Empty APT public key export")
    resulting = RetainedFormat(
        "apt",
        retained.prior_generation,
        tuple(history),
        tuple(asset.inspected.identity for asset in history),
        {
            "files": files,
            "etags": dict(etags),
            "keyring": str(keyring),
            "keyring_sha256": sha256_file(keyring)[0],
            "fingerprint": signer.fingerprint,
            "expires_at": expiry.isoformat(),
            "policy": _policy(policy),
        },
        tuple(refs.values()),
    )
    prepared = PreparedFormat(
        "apt", resulting, tuple(outputs), resulting.objects, expiry.isoformat()
    )
    validate_prepared(prepared, policy=policy, runtime=runtime, now=now)
    return prepared


def validate_prepared(
    prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime, now: datetime
) -> None:
    now = utc_now(lambda: now)
    if prepared.format != "apt" or prepared.referenced_objects != prepared.retained.objects:
        raise AptFailure("Prepared APT references differ from retained state")
    validate_retained(prepared.retained, policy=policy, runtime=runtime)
    if not prepared.retained.accepted_history:
        if prepared.outputs or prepared.expires_at is not None:
            raise AptFailure("Empty APT state contains outputs")
        return
    if prepared.expires_at != prepared.retained.metadata["expires_at"]:
        raise AptFailure("Frozen APT expiry differs from Release")
    if datetime.fromisoformat(str(prepared.expires_at)) <= now:
        raise AptFailure("Frozen APT Release expired; regeneration is required")
    refs = _refs(prepared.retained)
    previous_rank = -1
    entries = _entries(policy)
    for output in prepared.outputs:
        if refs.get(output.ref.key) != output.ref or sha256_file(output.local_path) != (
            output.ref.sha256,
            output.ref.size,
        ):
            raise AptFailure("Frozen APT output bytes changed")
        rank = (
            0
            if output.ref.object_class == "package"
            else 1
            if output.ref.object_class == "dependency"
            else 3 + entries.index(output.ref.key)
            if output.ref.key in entries
            else 2
        )
        if rank < previous_rank:
            raise AptFailure("Unsafe APT publication order")
        previous_rank = rank
    metadata = prepared.retained.metadata
    files = _strings(metadata.get("files"), "restored metadata files")
    with tempfile.TemporaryDirectory(prefix="apt-verify-", dir=runtime.root / "tmp") as directory:
        extracted = Path(directory) / "Release"
        for key in (entries[1], entries[2]):
            clear = key == entries[2]
            status = _run(
                runtime,
                [
                    "gpgv",
                    "--homedir",
                    str(runtime.root / "gnupg"),
                    "--keyring",
                    _string(metadata, "keyring"),
                    "--status-fd",
                    "1",
                    *(["--output", str(extracted)] if clear else []),
                    files[key],
                    *([] if clear else [files[entries[0]]]),
                ],
            )
            signatures = [
                line.split()
                for line in status.splitlines()
                if line.startswith(b"[GNUPG:] VALIDSIG ")
            ]
            fingerprint = _string(metadata, "fingerprint").encode()
            if (
                len(signatures) != 1
                or len(signatures[0]) < 12
                or signatures[0][2] != fingerprint
                or signatures[0][8:10] != [b"1", b"8"]
                or signatures[0][11] != fingerprint
            ):
                raise AptFailure("Release signature does not use the scoped SHA256 primary")
        if extracted.read_bytes() != Path(files[entries[0]]).read_bytes():
            raise AptFailure("InRelease differs from detached Release")
