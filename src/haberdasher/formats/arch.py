"""Qualified x86_64 and aarch64 Arch publication with native metadata and detached signatures."""

from __future__ import annotations

import base64
import hashlib
import re
import shutil
import tarfile
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from haberdasher.admission import admit
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
    safe_key,
    safe_path,
    sha256_file,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession

ARCHITECTURES = ("x86_64", "aarch64")
REPOSITORY = "haberdasher"
MAX_METADATA = 16 * 1024 * 1024


class ArchFailure(ValueError):
    pass


def entries(architecture: str) -> tuple[str, ...]:
    """Return the ordered entry metadata keys of one pacman `$arch` repository."""
    if architecture not in ARCHITECTURES:
        raise ArchFailure("Unqualified Arch architecture")
    return tuple(
        f"{architecture}/{REPOSITORY}{suffix}"
        for kind in ("db", "files")
        for suffix in (f".{kind}.tar.gz", f".{kind}.tar.gz.sig", f".{kind}", f".{kind}.sig")
    )


def _run(runtime: Runtime, argv: Sequence[str], *, cwd: Path | None = None) -> bytes:
    result = runtime.run(argv, cwd=cwd)
    if result.returncode:
        raise ArchFailure(f"Arch command failed: {argv[0]}")
    return result.stdout


def _policy(policy: FormatPolicy) -> None:
    if policy.format != "arch" or not set(policy.architectures) <= set(ARCHITECTURES):
        raise ArchFailure("Only qualified x86_64 and aarch64 Arch placement is supported")


def _filename(identity: NativeIdentity) -> str:
    if (
        identity.format != "arch"
        or identity.architecture not in ARCHITECTURES
        or re.fullmatch(r"[a-zA-Z0-9@_+][a-zA-Z0-9@_.+\-]*", identity.name) is None
        or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9:.+_\-]*", identity.version) is None
        or identity.epoch != 0
        or identity.release
    ):
        raise ArchFailure("Invalid qualified Arch identity")
    return f"{identity.name}-{identity.version}-{identity.architecture}.pkg.tar.zst"


def _key(identity: NativeIdentity) -> str:
    return f"{identity.architecture}/{_filename(identity)}"


def _fields(record: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for block in record.strip().split("\n\n"):
        lines = block.splitlines()
        if len(lines) < 2 or re.fullmatch(r"%[A-Z0-9_]+%", lines[0]) is None or lines[0] in fields:
            raise ArchFailure("Invalid native Arch record")
        fields[lines[0]] = lines[1:]
    return fields


def _archives(directory: Path) -> dict[str, JSONValue]:
    archives: dict[str, dict[str, str]] = {}
    for kind in ("db", "files"):
        path = safe_path(directory, f"{REPOSITORY}.{kind}.tar.gz")
        records: dict[str, str] = {}
        total = 0
        try:
            with tarfile.open(path, "r:gz") as archive:
                for index, member in enumerate(archive):
                    if index >= 100_000:
                        raise ArchFailure("Too many Arch metadata members")
                    name = safe_key(member.name.rstrip("/"))
                    if member.isdir():
                        continue
                    if (
                        not member.isfile()
                        or name in records
                        or len(name.split("/")) != 2
                        or name.split("/")[1] not in {"desc", "files"}
                        or member.size > MAX_METADATA
                    ):
                        raise ArchFailure("Unsafe Arch metadata member")
                    total += member.size
                    if total > MAX_METADATA:
                        raise ArchFailure("Arch metadata exceeds the size limit")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ArchFailure("Missing Arch metadata member")
                    records[name] = stream.read(MAX_METADATA + 1).decode("utf-8")
        except (tarfile.TarError, UnicodeError, OSError) as error:
            raise ArchFailure("Cannot read complete Arch archives") from error
        archives[kind] = records
    db, files = archives["db"], archives["files"]
    if not db or any(not key.endswith("/desc") for key in db):
        raise ArchFailure("Incomplete Arch database records")
    if set(files) != set(db) | {key.removesuffix("desc") + "files" for key in db}:
        raise ArchFailure("Database and files records differ")
    result: dict[str, JSONValue] = {}
    for key, desc in db.items():
        if files[key] != desc:
            raise ArchFailure("Database and files descriptions differ")
        fields = _fields(desc)
        names = fields.get("%NAME%", [])
        if len(names) != 1 or names[0] in result:
            raise ArchFailure("Duplicate or missing native package name")
        result[names[0]] = {"desc": desc, "files": files[key.removesuffix("desc") + "files"]}
    return result


def _mapping(value: JSONValue) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise ArchFailure("Missing Arch state mapping")
    return value


def _string(value: JSONValue) -> str:
    if not isinstance(value, str) or not value:
        raise ArchFailure("Missing Arch state string")
    return value


def inspect(
    asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
) -> InspectedAsset:
    _policy(policy)
    if sha256_file(asset.local_path) != (asset.sha256, asset.size):
        raise ArchFailure("Source checksum changed before inspection")
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ("root", "db"):
        (out / name).mkdir(mode=0o700)
    command = [
        "pacman",
        "--config",
        "/dev/null",
        "--root",
        str(out / "root"),
        "--dbpath",
        str(out / "db"),
    ]
    identity_fields = _run(runtime, [*command, "-Qp", str(asset.local_path)]).decode().split()
    info = _run(runtime, [*command, "-Qip", str(asset.local_path)]).decode()
    architectures = re.findall(r"^Architecture\s*:\s*(\S+)\s*$", info, re.MULTILINE)
    if len(identity_fields) != 2 or len(architectures) != 1:
        raise ArchFailure("Package lacks qualified Arch metadata")
    if architectures[0] not in policy.architectures:
        raise ArchFailure("Arch package architecture is not qualified by policy")
    identity = NativeIdentity("arch", identity_fields[0], architectures[0], identity_fields[1])
    package = safe_path(out, _filename(identity))
    shutil.copyfile(asset.local_path, package)
    _run(runtime, ["repo-add", str(out / f"{REPOSITORY}.db.tar.gz"), str(package)], cwd=out)
    records = _archives(out)
    if set(records) != {identity.name}:
        raise ArchFailure("Native inspection did not produce exactly one record")
    metadata = _mapping(records[identity.name])
    fields = _fields(_string(metadata.get("desc")))
    if fields.get("%VERSION%") != [identity.version] or fields.get("%ARCH%") != [
        identity.architecture
    ]:
        raise ArchFailure("Native identity and index disagree")
    return InspectedAsset(
        asset,
        identity,
        metadata,
        {
            "dependencies": list(fields.get("%DEPENDS%", [])),
            "files": _string(metadata.get("files")),
        },
        "unsigned",
    )


def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
    if (left.format, left.name, left.architecture) != (
        right.format,
        right.name,
        right.architecture,
    ):
        return None
    _filename(left)
    _filename(right)
    value = _run(runtime, ["vercmp", left.version, right.version]).strip()
    if value not in {b"-1", b"0", b"1"}:
        raise ArchFailure("Invalid native version comparison")
    return int(value)


def _verify(
    runtime: Runtime, source: Path, signature: Path, public: Path, fingerprint: str
) -> None:
    for path in (source, signature, public):
        if sha256_file(path)[1] == 0:
            raise ArchFailure("Missing or empty signature input")
    status = _run(
        runtime,
        [
            "gpgv",
            "--homedir",
            str(runtime.root / "gnupg"),
            "--keyring",
            str(public),
            "--status-fd",
            "1",
            str(signature),
            str(source),
        ],
    )
    signatures = [
        line.split() for line in status.splitlines() if line.startswith(b"[GNUPG:] VALIDSIG ")
    ]
    if (
        len(signatures) != 1
        or len(signatures[0]) < 12
        or signatures[0][2] != fingerprint.encode()
        or signatures[0][8:10] != [b"1", b"8"]
        or signatures[0][11] != fingerprint.encode()
    ):
        raise ArchFailure("Expected the approved SHA256 primary signature")


def _heads(
    history: Sequence[AdmittedAsset], runtime: Runtime
) -> dict[tuple[str, str], AdmittedAsset]:
    heads: dict[tuple[str, str], AdmittedAsset] = {}
    for item in history:
        identity = item.inspected.identity
        _filename(identity)
        slot = identity.architecture, identity.name
        previous = heads.get(slot)
        if previous is None or compare(identity, previous.inspected.identity, runtime=runtime) == 1:
            heads[slot] = item
    return heads


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    _policy(policy)
    if retained.format != "arch":
        raise ArchFailure("Wrong retained format")
    if not retained.accepted_history:
        if (
            retained.prior_generation is not None
            or retained.active_identities
            or retained.metadata
            or retained.objects
        ):
            raise ArchFailure("Incomplete retained Arch state")
        return
    paths = _mapping(retained.metadata.get("paths"))
    records = _mapping(retained.metadata.get("records"))
    public = Path(_string(retained.metadata.get("public_key")))
    fingerprint = _string(retained.metadata.get("fingerprint"))
    if re.fullmatch(r"[A-F0-9]{40}", fingerprint) is None:
        raise ArchFailure("Invalid retained fingerprint")
    architectures = sorted(
        {item.inspected.identity.architecture for item in retained.accepted_history}
    )
    if not set(architectures) <= set(policy.architectures):
        raise ArchFailure("Retained Arch architecture is not qualified by policy")
    refs = {ref.key: ref for ref in retained.objects}
    all_entries = [key for architecture in architectures for key in entries(architecture)]
    if (
        len(refs) != len(retained.objects)
        or set(paths) != set(all_entries)
        or set(records) != set(architectures)
    ):
        raise ArchFailure("Incomplete retained object references")
    for key in all_entries:
        path = Path(_string(paths[key]))
        ref = refs.get(key)
        if (
            ref is None
            or ref.object_class != "entry"
            or sha256_file(path) != (ref.sha256, ref.size)
        ):
            raise ArchFailure("Retained metadata bytes changed")
    for architecture in architectures:
        for kind in ("db", "files"):
            key = f"{architecture}/{REPOSITORY}.{kind}"
            archive = Path(_string(paths[key + ".tar.gz"]))
            signature = Path(_string(paths[key + ".tar.gz.sig"]))
            _verify(runtime, archive, signature, public, fingerprint)
            if (
                refs[key].sha256 != refs[key + ".tar.gz"].sha256
                or refs[key + ".sig"].sha256 != refs[key + ".tar.gz.sig"].sha256
            ):
                raise ArchFailure("Published aliases differ from archive bytes")
        directory = Path(_string(paths[entries(architecture)[0]])).parent
        if _archives(directory) != records[architecture]:
            raise ArchFailure("Retained complete records differ from native archives")
    history: list[AdmittedAsset] = []
    for item in retained.accepted_history:
        accepted = admit(item.inspected, history, compare=compare, policy=policy, runtime=runtime)
        if (
            accepted.history_key != item.history_key
            or accepted.transformation_policy != item.transformation_policy
        ):
            raise ArchFailure("Invalid retained admission")
        if any(prior.history_key == item.history_key for prior in history):
            raise ArchFailure("Duplicate retained admission")
        history.append(item)
        source = item.inspected.verified
        key = _key(item.inspected.identity)
        package = refs.get(key)
        signature = refs.get(key + ".sig")
        if (
            package is None
            or package.object_class != "package"
            or (package.sha256, package.size) != (source.sha256, source.size)
            or item.published_sha256 != source.sha256
            or signature is None
            or signature.object_class != "dependency"
            or not signature.size
        ):
            raise ArchFailure("Missing historical package or signature reference")
    heads = _heads(history, runtime)
    if (
        any(
            set(_mapping(records[architecture]))
            != {name for slot, name in heads if slot == architecture}
            for architecture in architectures
        )
        or set(retained.active_identities) != {item.inspected.identity for item in heads.values()}
        or len(retained.active_identities) != len(heads)
    ):
        raise ArchFailure("Active Arch identities differ from accepted history")
    expected_keys = set(all_entries)
    for item in history:
        key = _key(item.inspected.identity)
        expected_keys.update((key, key + ".sig"))
    if set(refs) != expected_keys:
        raise ArchFailure("Unexpected retained Arch objects")
    for (architecture, name), item in heads.items():
        record = _mapping(_mapping(records[architecture])[name])
        fields = _fields(_string(record.get("desc")))
        embedded = fields.pop("%PGPSIG%", [])
        if len(embedded) != 1:
            raise ArchFailure("Missing embedded package signature")
        try:
            signature_bytes = base64.b64decode(embedded[0], validate=True)
        except ValueError as error:
            raise ArchFailure("Invalid embedded package signature") from error
        ref = refs[_key(item.inspected.identity) + ".sig"]
        if (hashlib.sha256(signature_bytes).hexdigest(), len(signature_bytes)) != (
            ref.sha256,
            ref.size,
        ):
            raise ArchFailure("Embedded signature differs from the accepted signature")
        if (
            fields != _fields(_string(item.inspected.metadata.get("desc")))
            or record.get("files") != item.inspected.metadata.get("files")
            or fields.get("%SHA256SUM%") != [item.inspected.verified.sha256]
            or fields.get("%FILENAME%") != [_filename(item.inspected.identity)]
        ):
            raise ArchFailure("Native records lost accepted metadata")


def _ref(path: Path, key: str, category: str) -> ObjectRef:
    digest, size = sha256_file(path)
    return ObjectRef(
        "arch",
        key,
        category,
        size,
        digest,
        "application/octet-stream",
        "no-cache" if category == "entry" else "public, max-age=31536000, immutable",
    )


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
    validate_retained(retained, policy=policy, runtime=runtime)
    history = list(retained.accepted_history)
    additions: list[AdmittedAsset] = []
    for item in new:
        accepted = admit(item.inspected, history, compare=compare, policy=policy, runtime=runtime)
        if accepted.history_key != item.history_key or item.transformation_policy != "preserve":
            raise ArchFailure("Arch input was not admitted under the preserve policy")
        if any(prior.history_key == accepted.history_key for prior in history):
            continue
        accepted = replace(accepted, published_sha256=accepted.inspected.verified.sha256)
        history.append(accepted)
        additions.append(accepted)
    if not additions:
        return PreparedFormat("arch", retained, (), retained.objects)
    changed = sorted({item.inspected.identity.architecture for item in additions})
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    for architecture in changed:
        (out / architecture).mkdir(mode=0o700)
    public = out / "public.gpg"
    exported = _run(
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
    )
    public.write_bytes(exported)
    refs = {ref.key: ref for ref in retained.objects}
    outputs: list[OutputObject] = []
    paths: dict[str, JSONValue] = {}
    records: dict[str, JSONValue] = {}
    etags = _mapping(retained.metadata.get("etags", {}))

    def output(path: Path, key: str, category: str) -> None:
        previous = refs.get(key)
        ref = _ref(path, key, category)
        etag = _string(etags.get(key)) if previous is not None else None
        outputs.append(
            OutputObject(ref, path, "replace" if previous else "create", etag, len(outputs))
        )
        refs[key] = ref
        if category == "entry":
            paths[key] = str(path)

    if retained.accepted_history:
        if retained.metadata.get("fingerprint") != signer.fingerprint:
            raise ArchFailure("Arch signing identity changed")
        old_paths = _mapping(retained.metadata.get("paths"))
        old_records = _mapping(retained.metadata.get("records"))
        for architecture, value in old_records.items():
            if architecture not in changed:
                records[architecture] = value
                for key in entries(architecture):
                    paths[key] = old_paths[key]
                continue
            for kind in ("db", "files"):
                for suffix in (".tar.gz", ".tar.gz.sig"):
                    name = f"{REPOSITORY}.{kind}{suffix}"
                    shutil.copyfile(
                        Path(_string(old_paths[f"{architecture}/{name}"])),
                        out / architecture / name,
                    )
    for item in additions:
        asset = item.inspected.verified
        if sha256_file(asset.local_path) != (asset.sha256, asset.size):
            raise ArchFailure("Source checksum changed before preparation")
        package = safe_path(out, _key(item.inspected.identity))
        shutil.copyfile(asset.local_path, package)
        signature = package.with_name(package.name + ".sig")
        signer.sign_file(package, signature, armour=False)
        _verify(runtime, package, signature, public, signer.fingerprint)
        if sha256_file(package) != (asset.sha256, asset.size):
            raise ArchFailure("Package signing changed source bytes")
        output(package, _key(item.inspected.identity), "package")
        output(signature, _key(item.inspected.identity) + ".sig", "dependency")
    heads = _heads(history, runtime)
    for architecture in changed:
        directory = out / architecture
        active_new = [
            directory / _filename(item.inspected.identity)
            for item in additions
            if heads[item.inspected.identity.architecture, item.inspected.identity.name] == item
            and item.inspected.identity.architecture == architecture
        ]
        if active_new:
            _run(
                runtime,
                [
                    "env",
                    f"GNUPGHOME={signer.gnupghome}",
                    "repo-add",
                    "--include-sigs",
                    "--sign",
                    "--key",
                    signer.fingerprint + "!",
                    str(directory / f"{REPOSITORY}.db.tar.gz"),
                    *(str(path) for path in active_new),
                ],
                cwd=directory,
            )
        for kind in ("db", "files"):
            name = f"{REPOSITORY}.{kind}"
            archive = directory / (name + ".tar.gz")
            signature = directory / (name + ".tar.gz.sig")
            _verify(runtime, archive, signature, public, signer.fingerprint)
            for suffix in ("", ".sig"):
                alias = directory / (name + suffix)
                if alias.is_symlink():
                    alias.unlink()
                alias.write_bytes((directory / (name + ".tar.gz" + suffix)).read_bytes())
            for suffix in (".tar.gz", ".tar.gz.sig", "", ".sig"):
                output(directory / (name + suffix), f"{architecture}/{name}{suffix}", "entry")
        records[architecture] = _archives(directory)
    state = RetainedFormat(
        "arch",
        retained.prior_generation,
        tuple(history),
        tuple(heads[slot].inspected.identity for slot in sorted(heads)),
        {
            "paths": paths,
            "records": records,
            "public_key": str(public),
            "fingerprint": signer.fingerprint,
        },
        tuple(refs[key] for key in sorted(refs)),
    )
    prepared = PreparedFormat("arch", state, tuple(outputs), state.objects)
    validate_prepared(prepared, policy=policy, runtime=runtime, now=now)
    return prepared


def validate_prepared(
    prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime, now: datetime
) -> None:
    if prepared.format != "arch" or prepared.expires_at is not None:
        raise ArchFailure("Invalid prepared Arch state")
    validate_retained(prepared.retained, policy=policy, runtime=runtime)
    if prepared.referenced_objects != prepared.retained.objects:
        raise ArchFailure("Prepared references differ from retained state")
    refs = {ref.key: ref for ref in prepared.referenced_objects}
    entry_keys: list[str] = []
    public_value = prepared.retained.metadata.get("public_key")
    for ordinal, output in enumerate(prepared.outputs):
        if (
            output.ordinal != ordinal
            or refs.get(output.ref.key) != output.ref
            or sha256_file(output.local_path) != (output.ref.sha256, output.ref.size)
        ):
            raise ArchFailure("Prepared Arch output changed")
        if output.ref.object_class == "entry":
            entry_keys.append(output.ref.key)
        elif entry_keys:
            raise ArchFailure("Package dependencies must precede entries")
        if output.ref.object_class == "package":
            signatures = [
                item for item in prepared.outputs if item.ref.key == output.ref.key + ".sig"
            ]
            if len(signatures) != 1:
                raise ArchFailure("Missing prepared package signature")
            _verify(
                runtime,
                output.local_path,
                signatures[0].local_path,
                Path(_string(public_value)),
                _string(prepared.retained.metadata.get("fingerprint")),
            )
    changed = sorted(
        {
            output.ref.key.split("/", 1)[0]
            for output in prepared.outputs
            if output.ref.object_class == "package"
        }
    )
    if entry_keys != [key for architecture in changed for key in entries(architecture)]:
        raise ArchFailure("Incomplete or reordered prepared Arch entries")
