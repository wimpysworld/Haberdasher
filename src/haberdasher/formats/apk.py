"""Native APK v2 publication, with unsigned packages and RSA256 indexes."""

from __future__ import annotations

import re
import shutil
import tempfile
import zlib
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
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
    digest,
    safe_path,
    sha256_file,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import ALPINE_SIGNATURE_MEMBER, SigningSession

MAX_METADATA = 16 * 1024 * 1024
PUBLIC_KEY = "haberdasher.rsa.pub"
ARCHITECTURES = ("x86_64", "aarch64")


# Signed upstream APKs lose their signature stream. Unsigned upstream APKs keep their bytes.
_TRANSFORMATIONS = {"unsigned": "preserve", "signed": "apk-unsign"}


class ApkFailure(ValueError):
    pass


def _run(runtime: Runtime, argv: Sequence[str], *, data: bytes | None = None) -> bytes:
    result = runtime.run(argv, input=data)
    if result.returncode:
        raise ApkFailure(f"Native APK command failed: {argv[0]}")
    return result.stdout


def _apk(keys: Path, *args: str) -> list[str]:
    return [
        "apk",
        "--no-network",
        "--no-logfile",
        "--no-progress",
        "--no-interactive",
        "--repositories-file",
        "/dev/null",
        "--keys-dir",
        str(keys),
        *args,
    ]


def _policy(policy: FormatPolicy) -> None:
    if policy.format != "apk" or not set(policy.architectures) <= set(ARCHITECTURES):
        raise ApkFailure("Only qualified APK x86_64 and aarch64 placement is supported")


def _check(path: Path, digest: str, size: int) -> None:
    if not path.is_absolute():
        raise ApkFailure("APK input paths must be absolute")
    if sha256_file(path) != (digest, size) or not size:
        raise ApkFailure("Missing or changed APK input")


def _parts(path: Path, out: Path) -> list[Path]:
    """Split gzip members without keeping expanded package payloads in memory."""
    parts: list[Path] = []
    limit = min(5 * 1024**3, max(MAX_METADATA, path.stat().st_size * 1024))
    expanded = 0
    with path.open("rb") as source:
        pending = source.read(65536)
        if pending.startswith(b"ADB"):
            raise ApkFailure("APK v3 ADB is not supported")
        while pending:
            if len(parts) == 3:
                raise ApkFailure("Unexpected APK gzip member")
            target = out / f"member-{len(parts)}.gz"
            decoder = zlib.decompressobj(31)
            with target.open("xb") as stream:
                while True:
                    try:
                        decoded = decoder.decompress(pending, 1024 * 1024)
                    except zlib.error as error:
                        raise ApkFailure("Invalid APK gzip stream") from error
                    expanded += len(decoded)
                    if expanded > limit:
                        raise ApkFailure("APK expanded data exceeds the limit")
                    tail = decoder.unused_data if decoder.eof else decoder.unconsumed_tail
                    stream.write(pending[: len(pending) - len(tail)])
                    pending = tail
                    if decoder.eof:
                        break
                    if not pending:
                        pending = source.read(65536)
                    if not pending:
                        raise ApkFailure("Truncated APK gzip stream")
            parts.append(target)
            if not pending:
                pending = source.read(65536)
    return parts


def _members(path: Path, runtime: Runtime) -> list[str]:
    return [
        name.removeprefix("./")
        for name in _run(runtime, ["tar", "-tzf", str(path)]).decode("utf-8").splitlines()
    ]


def _extract(path: Path, member: str, runtime: Runtime) -> str:
    data = _run(runtime, ["tar", "-xOzf", str(path), member])
    if len(data) > MAX_METADATA:
        raise ApkFailure("APK metadata exceeds the limit")
    return data.decode("utf-8")


def _records(data: str) -> dict[tuple[str, str, str], str]:
    if not data or not data.endswith("\n\n") or len(data.encode()) > MAX_METADATA:
        raise ApkFailure("Incomplete APKINDEX records")
    records: dict[tuple[str, str, str], str] = {}
    for stanza in data[:-2].split("\n\n"):
        fields: dict[str, str] = {}
        for line in stanza.splitlines():
            if len(line) < 2 or line[1] != ":" or line[0] in fields:
                raise ApkFailure("Malformed or duplicate APKINDEX field")
            fields[line[0]] = line[2:]
        if not all(fields.get(key) for key in ("P", "V", "A", "C", "S", "I", "T", "L")):
            raise ApkFailure("Incomplete native APK record")
        if re.fullmatch(r"Q1[A-Za-z0-9+/]{27}=", fields["C"]) is None:
            raise ApkFailure("Expected the APK v2 SHA1 control identity")
        for key in ("S", "I"):
            if not fields[key].isdigit():
                raise ApkFailure("Invalid APK record size")
        identity = fields["P"], fields["V"], fields["A"]
        if identity in records:
            raise ApkFailure("Duplicate APK native identity")
        _filename(NativeIdentity("apk", identity[0], identity[2], identity[1]))
        records[identity] = stanza + "\n\n"
    return records


def _fields(stanza: str) -> dict[str, str]:
    return {line[0]: line[2:] for line in stanza.splitlines() if line}


def _filename(identity: NativeIdentity) -> str:
    for value in (identity.name, identity.version, identity.architecture):
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+~-]*", value) is None:
            raise ApkFailure("Unsafe native APK filename")
    if identity.format != "apk" or identity.epoch or identity.release:
        raise ApkFailure("Invalid APK identity fields")
    return f"{identity.architecture}/{identity.name}-{identity.version}.apk"


def _slots(architecture: str, policy: FormatPolicy) -> tuple[str, ...]:
    """Indexes that list a package. Every architecture index lists noarch packages.

    The apk client fetches each package from the directory of its own architecture,
    so a noarch package has one object under noarch/.
    """
    return policy.architectures if architecture == "noarch" else (architecture,)


def _control(info: str, identity: NativeIdentity | None = None) -> str:
    if not info or len(info.encode()) > MAX_METADATA or "\0" in info:
        raise ApkFailure("Invalid APK control metadata")
    values: dict[str, str] = {}
    for line in info.splitlines():
        name, separator, value = line.partition(" = ")
        if name not in {"pkgname", "pkgver", "arch", "datahash"}:
            continue
        if not separator or not value or name in values:
            raise ApkFailure("Duplicate or invalid APK control field")
        values[name] = value
    if values.keys() != {"pkgname", "pkgver", "arch", "datahash"}:
        raise ApkFailure("Incomplete APK control metadata")
    if identity is not None and (values["pkgname"], values["pkgver"], values["arch"]) != (
        identity.name,
        identity.version,
        identity.architecture,
    ):
        raise ApkFailure("APK control and native identity differ")
    return digest(values["datahash"])


def inspect(
    asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
) -> InspectedAsset:
    _policy(policy)
    _check(asset.local_path, asset.sha256, asset.size)
    safe_path(out, "validation")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out, prefix="inspect-") as temporary:
        work = Path(temporary)
        parts = _parts(asset.local_path, work)
        if not parts:
            raise ApkFailure("Empty APK input")
        status, package = _unsigned(asset.local_path, parts, work, runtime)
        control, payload = parts[-2:]
        members = _members(control, runtime)
        if members.count(".PKGINFO") != 1 or any(name.startswith(".SIGN") for name in members):
            raise ApkFailure("Invalid APK control members")
        info = _extract(control, ".PKGINFO", runtime)
        datahash = _control(info)
        if sha256_file(payload)[0] != datahash:
            raise ApkFailure("APK compressed payload datahash mismatch")
        keys = work / "empty-keys"
        keys.mkdir(mode=0o700)
        index = work / "APKINDEX.tar.gz"
        _run(
            runtime,
            _apk(keys, "index", "--allow-untrusted", "--output", str(index), str(package)),
        )
        records = _records(_extract(index, "APKINDEX", runtime))
        if len(records) != 1:
            raise ApkFailure("Native APK inspection omitted the input")
        (name, version, arch), stanza = next(iter(records.items()))
        if arch not in (*policy.architectures, "noarch"):
            raise ApkFailure(f"{asset.source.filename}: unsupported APK architecture {arch!r}")
        identity = NativeIdentity("apk", name, arch, version)
        _filename(identity)
        _control(info, identity)
        _run(runtime, ["apk", "version", "--check", version])
        _check(asset.local_path, asset.sha256, asset.size)
        published, size = sha256_file(package)
        fields = _fields(stanza)
        if int(fields["S"]) != size:
            raise ApkFailure("Native APK size differs from the published package")
        metadata: dict[str, JSONValue] = {"stanza": stanza, "pkginfo": info, "datahash": datahash}
        if status == "signed":
            metadata |= {"published_sha256": published, "published_size": size}
        return InspectedAsset(
            asset,
            identity,
            metadata,
            {"dependencies": fields.get("D", ""), "control_identity": fields["C"]},
            status,
        )


def _unsigned(path: Path, parts: Sequence[Path], work: Path, runtime: Runtime) -> tuple[str, Path]:
    """Return the APK without its upstream signature stream, as an unsigned package has it."""
    signatures = [name for name in _members(parts[0], runtime) if name.startswith(".SIGN")]
    if not signatures:
        if len(parts) != 2:
            raise ApkFailure("Expected an unsigned APK v2 control and payload")
        return "unsigned", path
    if len(parts) != 3 or _members(parts[0], runtime) != signatures:
        raise ApkFailure("Malformed signed APK input")
    package = work / "unsigned.apk"
    with package.open("xb") as stream:
        for part in parts[1:]:
            stream.write(part.read_bytes())
    return "signed", package


def _published(item: InspectedAsset) -> tuple[str, int]:
    """Return the digest and size of the package bytes that the repository serves."""
    if item.upstream_signature == "unsigned":
        return item.verified.sha256, item.verified.size
    digest_value, size = item.metadata.get("published_sha256"), item.metadata.get("published_size")
    if not isinstance(digest_value, str) or type(size) is not int:
        raise ApkFailure("Missing published APK digest evidence")
    return digest(digest_value), size


def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
    if (left.format, left.name, left.architecture) != (
        right.format,
        right.name,
        right.architecture,
    ):
        return None
    _filename(left)
    _filename(right)
    _run(runtime, ["apk", "version", "--check", left.version, right.version])
    result = _run(runtime, ["apk", "version", "--test", left.version, right.version]).strip()
    if result not in {b"<", b"=", b">"}:
        raise ApkFailure("Invalid native APK comparison")
    return {b"<": -1, b"=": 0, b">": 1}[result]


def _mapping(value: JSONValue) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise ApkFailure("Missing APK retained metadata mapping")
    return value


def _string(value: JSONValue) -> str:
    if not isinstance(value, str) or not value:
        raise ApkFailure("Missing APK retained metadata value")
    return value


def _file(value: JSONValue) -> Path:
    entry = _mapping(value)
    path = Path(_string(entry.get("local_path")))
    if not path.is_absolute():
        raise ApkFailure("Retained APK paths must be absolute")
    size = entry.get("size")
    if type(size) is not int:
        raise ApkFailure("Missing APK retained file size")
    _check(path, _string(entry.get("sha256")), size)
    return path


def _file_record(path: Path) -> dict[str, JSONValue]:
    digest, size = sha256_file(path)
    return {"local_path": str(path), "sha256": digest, "size": size}


def _expected(
    history: Sequence[AdmittedAsset], policy: FormatPolicy
) -> dict[tuple[str, str, str], str]:
    records: dict[tuple[str, str, str], str] = {}
    for accepted in history:
        item = accepted.inspected
        identity = item.identity
        _filename(identity)
        if identity.architecture not in (*policy.architectures, "noarch") or (
            accepted.transformation_policy != _TRANSFORMATIONS.get(item.upstream_signature)
        ):
            raise ApkFailure("Invalid retained APK policy")
        published, size = _published(item)
        if accepted.published_sha256 != published or (published == item.verified.sha256) != (
            item.upstream_signature == "unsigned"
        ):
            raise ApkFailure("Retained APK source and published digests differ")
        stanza = _string(item.metadata.get("stanza"))
        parsed = _records(stanza)
        key = identity.name, identity.version, identity.architecture
        if list(parsed) != [key] or key in records:
            raise ApkFailure("Retained APK identity differs from complete native metadata")
        fields = _fields(stanza)
        datahash = _control(_string(item.metadata.get("pkginfo")), identity)
        if (
            item.metadata.get("datahash") != datahash
            or item.evidence.get("control_identity") != fields["C"]
        ):
            raise ApkFailure("Incomplete retained APK control evidence")
        if int(fields["S"]) != size or item.evidence.get("dependencies") != fields.get("D", ""):
            raise ApkFailure("Retained APK evidence differs from native metadata")
        records[key] = stanza
    return records


def _verify_index(path: Path, key: Path, runtime: Runtime) -> dict[tuple[str, str, str], str]:
    with tempfile.TemporaryDirectory(dir=runtime.root / "tmp", prefix="apk-trust-") as temporary:
        work = Path(temporary)
        keys = work / "keys"
        keys.mkdir(mode=0o700)
        atomic_write(keys / PUBLIC_KEY, key.read_bytes())
        _run(runtime, _apk(keys, "verify", str(path)))
        parts = _parts(path, work)
        if len(parts) != 2 or _members(parts[0], runtime) != [ALPINE_SIGNATURE_MEMBER]:
            raise ApkFailure("Index must have exactly the Haberdasher RSA256 signature")
        if sorted(_members(parts[1], runtime)) != ["APKINDEX", "DESCRIPTION"]:
            raise ApkFailure("Unexpected signed APK index members")
        return _records(_extract(parts[1], "APKINDEX", runtime))


def _sign_index(
    path: Path, private: Path, public: Path, *, signer: SigningSession, runtime: Runtime
) -> None:
    _run(
        runtime,
        [
            "env",
            f"GNUPGHOME={signer.gnupghome}",
            "ABUILD_CONF=/dev/null",
            "ABUILD_USERCONF=/dev/null",
            "ABUILD_DEFCONF=/dev/null",
            "abuild-sign",
            "-t",
            "RSA256",
            "-k",
            str(private),
            "-p",
            str(public),
            str(path),
        ],
    )
    _verify_index(path, public, runtime)


def _ref(path: Path, key: str, kind: str) -> ObjectRef:
    digest, size = sha256_file(path)
    return ObjectRef(
        "apk",
        key,
        kind,
        size,
        digest,
        "application/vnd.alpine.apk" if kind == "package" else "application/octet-stream",
        "no-cache" if kind == "entry" else "public, max-age=31536000, immutable",
    )


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    _policy(policy)
    if retained.format != "apk":
        raise ApkFailure("Expected APK retained state")
    if not retained.accepted_history:
        if (
            retained.prior_generation is not None
            or retained.metadata
            or retained.objects
            or retained.active_identities
        ):
            raise ApkFailure("Incomplete APK retained state")
        return
    expected = _expected(retained.accepted_history, policy)
    if retained.active_identities != tuple(
        item.inspected.identity for item in retained.accepted_history
    ):
        raise ApkFailure("Incomplete retained APK identities")
    key = _file(retained.metadata.get("public_key"))
    indexes = _mapping(retained.metadata.get("indexes"))
    if set(indexes) != {slot for identity in expected for slot in _slots(identity[2], policy)}:
        raise ApkFailure("Missing retained APK index")
    refs: dict[str, ObjectRef] = {}
    for ref in retained.objects:
        if ref.key in refs:
            raise ApkFailure("Duplicate retained APK object")
        refs[ref.key] = ref
    required = {"keys/" + PUBLIC_KEY}
    if refs.get("keys/" + PUBLIC_KEY) != _ref(key, "keys/" + PUBLIC_KEY, "dependency"):
        raise ApkFailure("Missing retained APK public key reference")
    for arch, record in indexes.items():
        path = _file(record)
        if _verify_index(path, key, runtime) != {
            k: v for k, v in expected.items() if k[2] in (arch, "noarch")
        }:
            raise ApkFailure("Retained APK index does not contain the complete accepted records")
        index_key = f"{arch}/APKINDEX.tar.gz"
        required.add(index_key)
        if refs.get(index_key) != _ref(path, index_key, "entry"):
            raise ApkFailure("Missing retained APK index reference")
    for item in retained.accepted_history:
        object_key = _filename(item.inspected.identity)
        required.add(object_key)
        ref = refs.get(object_key)
        if (
            ref is None
            or ref.object_class != "package"
            or (ref.sha256, ref.size) != _published(item.inspected)
        ):
            raise ApkFailure("Missing retained APK package reference")
    if refs.keys() != required:
        raise ApkFailure("Unexpected retained APK object")


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
    out = safe_path(out, "validation").parent
    history = list(retained.accepted_history)
    additions: list[AdmittedAsset] = []
    for candidate in new:
        if candidate.transformation_policy != _TRANSFORMATIONS.get(
            candidate.inspected.upstream_signature
        ):
            raise ApkFailure("Unexpected APK package transformation")
        equivalent = next(
            (
                old
                for old in history
                if compare(
                    candidate.inspected.identity,
                    old.inspected.identity,
                    runtime=runtime,
                )
                == 0
            ),
            None,
        )
        if equivalent is not None:
            if equivalent.inspected.verified.sha256 != candidate.inspected.verified.sha256:
                raise ApkFailure("Changed bytes for an accepted APK identity")
            continue
        inspected = inspect(candidate.inspected.verified, policy=policy, runtime=runtime, out=out)
        if inspected != candidate.inspected:
            raise ApkFailure("APK input changed after admission")
        item = replace(candidate, published_sha256=_published(inspected)[0])
        additions.append(item)
        history.append(item)
    if not additions:
        return PreparedFormat("apk", retained, (), retained.objects)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    expected = _expected(history, policy)
    private, public = signer.alpine_key()
    if public.name != PUBLIC_KEY or not private.is_file() or not private.stat().st_size:
        raise ApkFailure("Missing APK signing key or incorrect public basename")
    if retained.accepted_history and sha256_file(
        _file(retained.metadata.get("public_key"))
    ) != sha256_file(public):
        raise ApkFailure("APK key rotation is not supported")
    key = out / PUBLIC_KEY
    atomic_write(key, public.read_bytes())
    refs = {ref.key: ref for ref in retained.objects}
    outputs: list[OutputObject] = []

    def output(path: Path, object_key: str, kind: str, etag: str | None = None) -> None:
        ref = _ref(path, object_key, kind)
        outputs.append(
            OutputObject(ref, path, "create" if etag is None else "replace", etag, len(outputs))
        )
        refs[object_key] = ref

    if not retained.accepted_history:
        output(key, "keys/" + PUBLIC_KEY, "dependency")
    for item in additions:
        object_key = _filename(item.inspected.identity)
        path = safe_path(out, object_key)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source = item.inspected.verified
        if item.inspected.upstream_signature == "unsigned":
            shutil.copyfile(source.local_path, path)
        else:
            with tempfile.TemporaryDirectory(dir=out, prefix="unsign-") as temporary:
                work = Path(temporary)
                parts = _parts(source.local_path, work)
                shutil.copyfile(_unsigned(source.local_path, parts, work, runtime)[1], path)
        _check(path, *_published(item.inspected))
        output(path, object_key, "package")
    indexes = dict(_mapping(retained.metadata["indexes"])) if retained.accepted_history else {}
    with tempfile.TemporaryDirectory(dir=out, prefix="index-") as temporary:
        work = Path(temporary)
        keys = work / "keys"
        keys.mkdir(mode=0o700)
        atomic_write(keys / PUBLIC_KEY, key.read_bytes())
        changed = {
            slot
            for item in additions
            for slot in _slots(item.inspected.identity.architecture, policy)
        }
        for arch in sorted(changed):
            etag = _string(_mapping(indexes[arch]).get("etag")) if arch in indexes else None
            records = {k: v for k, v in expected.items() if k[2] in (arch, "noarch")}
            # Native inspection and retained validation use separate trust roots.
            # Reuse their complete stanzas, never upstream keys, for the repository merge.
            content = work / arch
            content.mkdir(mode=0o700)
            atomic_write(content / "APKINDEX", "".join(records.values()).encode())
            atomic_write(content / "DESCRIPTION", b"Haberdasher")
            seed = work / f"{arch}-seed.tar.gz"
            _run(
                runtime,
                [
                    "tar",
                    "--format=ustar",
                    "-czf",
                    str(seed),
                    "-C",
                    str(content),
                    "DESCRIPTION",
                    "APKINDEX",
                ],
            )
            _sign_index(seed, private, key, signer=signer, runtime=runtime)
            target = out / arch / "APKINDEX.tar.gz"
            target.parent.mkdir(mode=0o700, exist_ok=True)
            _run(
                runtime,
                _apk(
                    keys,
                    "index",
                    "--merge",
                    "--index",
                    str(seed),
                    "--description",
                    "Haberdasher",
                    "--output",
                    str(target),
                ),
            )
            if _records(_extract(target, "APKINDEX", runtime)) != records:
                raise ApkFailure("Native APK merge omitted or changed accepted records")
            _sign_index(target, private, key, signer=signer, runtime=runtime)
            indexes[arch] = _file_record(target)
            output(target, f"{arch}/APKINDEX.tar.gz", "entry", etag)
    objects = tuple(refs.values())
    result = RetainedFormat(
        "apk",
        retained.prior_generation,
        tuple(history),
        tuple(item.inspected.identity for item in history),
        {"indexes": indexes, "public_key": _file_record(key)},
        objects,
    )
    prepared = PreparedFormat("apk", result, tuple(outputs), objects)
    validate_prepared(prepared, policy=policy, runtime=runtime, now=now)
    return prepared


def validate_prepared(
    prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime, now: datetime
) -> None:
    if prepared.format != "apk":
        raise ApkFailure("Invalid prepared APK format")
    validate_retained(prepared.retained, policy=policy, runtime=runtime)
    if prepared.referenced_objects != prepared.retained.objects:
        raise ApkFailure("Incomplete prepared APK references")
    entry_seen = False
    for output in prepared.outputs:
        if output.ref not in prepared.referenced_objects:
            raise ApkFailure("Unreferenced prepared APK output")
        _check(output.local_path, output.ref.sha256, output.ref.size)
        if output.ref.object_class == "entry":
            entry_seen = True
        elif entry_seen:
            raise ApkFailure("APK packages and keys must precede indexes")
        if output.ref.object_class != "entry" and output.mode != "create":
            raise ApkFailure("APK package and key objects must be immutable")
