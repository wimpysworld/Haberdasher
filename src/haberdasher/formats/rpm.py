"""RPM signing and complete incremental repository metadata."""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import cast

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
    canonical_json,
    safe_key,
    safe_path,
    sha256_file,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession

REPO = "{http://linux.duke.edu/metadata/repo}"
COMMON = "{http://linux.duke.edu/metadata/common}"
NAMESPACES = {
    "primary": (COMMON, "metadata"),
    "filelists": ("{http://linux.duke.edu/metadata/filelists}", "filelists"),
    "other": ("{http://linux.duke.edu/metadata/other}", "otherdata"),
}
MAX_XML = 32 * 1024 * 1024
IDENTITY_QUERY = "%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}"
SIGNATURE_QUERY = "%{SIGPGP:pgpsig}|%{SIGGPG:pgpsig}|%{RSAHEADER:pgpsig}|%{DSAHEADER:pgpsig}"
ENTRIES = ("repodata/repomd.xml", "repodata/repomd.xml.asc")


class RpmFailure(ValueError):
    pass


def _run(runtime: Runtime, argv: Sequence[str]) -> bytes:
    result = runtime.run(argv)
    if result.returncode:
        raise RpmFailure(f"RPM command failed: {argv[0]}: {result.stderr.decode(errors='replace')}")
    return result.stdout


def _policy(policy: FormatPolicy) -> None:
    if policy.format != "rpm":
        raise RpmFailure("Expected RPM policy")


def _token(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_+.~^:-]+", value) is None:
        raise RpmFailure("Unsafe RPM identity token")
    return value


def _identity(path: Path, runtime: Runtime) -> NativeIdentity:
    data = _run(runtime, ["rpm", "-qp", "--qf", IDENTITY_QUERY, str(path)])
    try:
        name, epoch, version, release, arch = data.decode().split("|")
        return NativeIdentity(
            "rpm", _token(name), _token(arch), _token(version), int(epoch), _token(release)
        )
    except (UnicodeError, ValueError) as error:
        raise RpmFailure("Invalid native RPM identity") from error


def _signed(path: Path, runtime: Runtime) -> bool:
    signatures = _run(runtime, ["rpm", "-qp", "--qf", SIGNATURE_QUERY, str(path)])
    return signatures != b"(none)|(none)|(none)|(none)"


def _unsign(source: Path, target: Path, runtime: Runtime) -> str:
    """Copy source to target without upstream signatures, and check the package digests."""
    shutil.copyfile(source, target)
    status = "signed" if _signed(target, runtime) else "unsigned"
    if status == "signed":
        _run(runtime, ["rpmsign", "--delsign", str(target)])
        if _signed(target, runtime):
            raise RpmFailure("RPM upstream signature removal failed")
    _run(runtime, ["rpmkeys", "--checksig", str(target)])
    return status


def inspect(
    asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
) -> InspectedAsset:
    _policy(policy)
    if sha256_file(asset.local_path) != (asset.sha256, asset.size):
        raise RpmFailure("Verified RPM bytes changed")
    identity = _identity(asset.local_path, runtime)
    if identity.architecture not in (*policy.architectures, "noarch"):
        raise RpmFailure(
            f"{asset.source.filename}: unsupported RPM architecture {identity.architecture!r}"
        )
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rpm-inspect-", dir=out) as directory:
        status = _unsign(asset.local_path, Path(directory) / "package.rpm", runtime)
    header = _run(runtime, ["rpm", "-qp", "--xml", str(asset.local_path)])
    parse_xml(header)
    requires = _run(runtime, ["rpm", "-qp", "--requires", str(asset.local_path)]).decode()
    return InspectedAsset(
        asset, identity, {"header_xml": header.decode()}, {"requires": requires}, status
    )


def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
    if (left.format, left.name, left.architecture) != (
        right.format,
        right.name,
        right.architecture,
    ):
        return None
    if left.format != "rpm":
        raise RpmFailure("Expected RPM identities")
    for a, b in (
        (str(left.epoch), str(right.epoch)),
        (left.version, right.version),
        (left.release, right.release),
    ):
        expression = '%{lua:print(rpm.vercmp("' + _token(a) + '","' + _token(b) + '"))}'
        value = _run(runtime, ["rpm", "--eval", expression]).strip()
        if value not in (b"-1", b"0", b"1"):
            raise RpmFailure("Invalid native RPM comparison")
        if value != b"0":
            return int(value)
    return 0


def parse_xml(data: bytes) -> ET.Element:
    if len(data) > MAX_XML:
        raise RpmFailure("RPM XML exceeds the size limit")
    try:
        value = data.decode("utf-8")
        if "<!DOCTYPE" in value.upper() or "<!ENTITY" in value.upper():
            raise RpmFailure("XML declarations are forbidden")
        parser: ET.XMLPullParser[ET.Element] = ET.XMLPullParser(events=("start", "end"))
        depth = count = 0
        root: ET.Element | None = None
        for offset in range(0, len(value), 8192):
            parser.feed(value[offset : offset + 8192])
            for event, node in cast(Iterable[tuple[str, ET.Element]], parser.read_events()):
                if event == "start":
                    depth += 1
                    count += 1
                    if root is None:
                        root = node
                    if depth > 64 or count > 200_000:
                        raise RpmFailure("RPM XML exceeds structural limits")
                else:
                    depth -= 1
        parser.close()
        if root is None:
            raise RpmFailure("Empty RPM XML")
        return root
    except (UnicodeError, ET.ParseError) as error:
        raise RpmFailure("Malformed RPM XML") from error


def _read(path: Path) -> bytes:
    path = safe_path(path.parent, path.name)
    with path.open("rb") as stream:
        data = stream.read(MAX_XML + 1)
    if len(data) > MAX_XML:
        raise RpmFailure("RPM metadata exceeds the size limit")
    return data


def _child(node: ET.Element, tag: str) -> ET.Element:
    matches = node.findall(tag)
    if len(matches) != 1:
        raise RpmFailure(f"Expected one XML element: {tag}")
    return matches[0]


def _text(node: ET.Element, tag: str) -> str:
    value = _child(node, tag).text
    if not value:
        raise RpmFailure(f"Empty XML element: {tag}")
    return value


def _semantic(node: ET.Element) -> JSONValue:
    children = [_semantic(child) for child in node]
    children.sort(key=canonical_json)
    return [node.tag, dict(sorted(node.attrib.items())), (node.text or "").strip(), children]


def metadata_documents(root: Path) -> dict[str, tuple[str, ET.Element]]:
    repomd = parse_xml(_read(safe_path(root, ENTRIES[0])))
    if repomd.tag != REPO + "repomd":
        raise RpmFailure("Invalid repomd root")
    documents: dict[str, tuple[str, ET.Element]] = {}
    for entry in repomd.findall(REPO + "data"):
        kind = entry.attrib.get("type", "")
        if kind not in NAMESPACES or kind in documents:
            raise RpmFailure("Unexpected or duplicate RPM metadata type")
        location = safe_key(_child(entry, REPO + "location").attrib.get("href", ""))
        if not location.startswith("repodata/") or not location.endswith(".gz"):
            raise RpmFailure("Expected compressed metadata in repodata")
        raw = _read(safe_path(root, location))
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                opened = stream.read(MAX_XML + 1)
        except (OSError, EOFError) as error:
            raise RpmFailure("Invalid compressed RPM metadata") from error
        for prefix, content in (("", raw), ("open-", opened)):
            checksum = _child(entry, REPO + prefix + "checksum")
            if (
                len(content) > MAX_XML
                or checksum.attrib.get("type") != "sha256"
                or hashlib.sha256(content).hexdigest() != checksum.text
                or str(len(content)) != _text(entry, REPO + prefix + "size")
            ):
                raise RpmFailure("RPM metadata checksum or size mismatch")
        document = parse_xml(opened)
        namespace, name = NAMESPACES[kind]
        if (
            document.tag != namespace + name
            or document.attrib.get("packages") != str(len(document))
            or any(package.tag != namespace + "package" for package in document)
        ):
            raise RpmFailure("Invalid RPM metadata document")
        documents[kind] = location, document
    if set(documents) != set(NAMESPACES):
        raise RpmFailure("Incomplete primary/filelists/other metadata")
    return documents


def _package_identity(package: ET.Element, kind: str) -> NativeIdentity:
    namespace = NAMESPACES[kind][0]
    version = _child(package, namespace + "version")
    try:
        name = _text(package, COMMON + "name") if kind == "primary" else package.attrib["name"]
        arch = _text(package, COMMON + "arch") if kind == "primary" else package.attrib["arch"]
        return NativeIdentity(
            "rpm",
            _token(name),
            _token(arch),
            _token(version.attrib["ver"]),
            int(version.attrib["epoch"]),
            _token(version.attrib["rel"]),
        )
    except (KeyError, ValueError) as error:
        raise RpmFailure("Invalid package identity in metadata") from error


def _records(root: Path, history: Sequence[AdmittedAsset]) -> dict[str, dict[str, JSONValue]]:
    expected = {asset.inspected.identity: asset for asset in history}
    if len(expected) != len(history) or len({asset.history_key for asset in history}) != len(
        history
    ):
        raise RpmFailure("Duplicate retained RPM identity or history key")
    result: dict[str, dict[str, JSONValue]] = {asset.history_key: {} for asset in history}
    for kind, (_, document) in metadata_documents(root).items():
        seen: set[NativeIdentity] = set()
        for package in document:
            identity = _package_identity(package, kind)
            if identity not in expected or identity in seen:
                raise RpmFailure("Unexpected or duplicate RPM record")
            seen.add(identity)
            asset = expected[identity]
            if kind == "primary":
                checksum = _child(package, COMMON + "checksum")
                if (
                    checksum.attrib.get("type") != "sha256"
                    or checksum.text != asset.published_sha256
                    or _child(package, COMMON + "location").attrib.get("href")
                    != asset.inspected.metadata.get("location")
                    or _child(package, COMMON + "size").attrib.get("package")
                    != str(asset.inspected.metadata.get("published_size"))
                ):
                    raise RpmFailure("RPM primary does not match published bytes")
            elif package.attrib.get("pkgid") != asset.published_sha256:
                raise RpmFailure("RPM pkgid does not match published bytes")
            result[asset.history_key][kind] = _semantic(package)
        if seen != set(expected):
            raise RpmFailure(f"Incomplete {kind} package records")
    return result


def _string(metadata: dict[str, JSONValue], key: str) -> str:
    value = metadata.get(key)
    if not isinstance(value, str) or not value:
        raise RpmFailure(f"Missing RPM state field: {key}")
    return value


def _trust(retained: RetainedFormat, runtime: Runtime) -> Path:
    keyring = Path(_string(retained.metadata, "keyring"))
    fingerprint = _string(retained.metadata, "fingerprint")
    if re.fullmatch(r"[A-F0-9]{40}", fingerprint) is None:
        raise RpmFailure("Invalid retained signing fingerprint")
    if sha256_file(keyring)[0] != _string(retained.metadata, "keyring_sha256"):
        raise RpmFailure("Retained public trust changed")
    listing = _run(runtime, ["gpg", "--batch", "--with-colons", "--show-keys", str(keyring)])
    fingerprints = [
        line.split(b":")[9].decode() for line in listing.splitlines() if line.startswith(b"fpr:")
    ]
    if fingerprints != [fingerprint]:
        raise RpmFailure("Retained public trust must contain only the approved primary")
    root = Path(_string(retained.metadata, "root"))
    status = _run(
        runtime,
        [
            "gpgv",
            "--status-fd",
            "1",
            "--keyring",
            str(keyring),
            str(safe_path(root, ENTRIES[1])),
            str(safe_path(root, ENTRIES[0])),
        ],
    )
    signatures = [
        line.split() for line in status.splitlines() if line.startswith(b"[GNUPG:] VALIDSIG ")
    ]
    if (
        len(signatures) != 1
        or len(signatures[0]) < 12
        or signatures[0][2].decode() != fingerprint
        or signatures[0][8:10] != [b"1", b"8"]
        or signatures[0][11].decode() != fingerprint
    ):
        raise RpmFailure("Metadata signature must use the approved primary and SHA256")
    return keyring


def _verify_package(path: Path, keyring: Path, runtime: Runtime) -> None:
    with tempfile.TemporaryDirectory(prefix="rpmdb-", dir=runtime.root) as directory:
        args = ["--dbpath", directory]
        public = Path(directory) / "public.asc"
        atomic_write(
            public,
            _run(
                runtime,
                [
                    "gpg",
                    "--batch",
                    "--no-default-keyring",
                    "--keyring",
                    str(keyring),
                    "--armor",
                    "--export",
                ],
            ),
        )
        _run(runtime, ["rpm", *args, "--initdb"])
        _run(runtime, ["rpmkeys", *args, "--import", str(public)])
        status = _run(
            runtime,
            [
                "rpmkeys",
                *args,
                "--define",
                "_pkgverify_level signature",
                "--checksig",
                "--verbose",
                str(path),
            ],
        )
        if not re.search(rb"RSA/SHA256 Signature.*: OK", status):
            raise RpmFailure("RPM needs a valid RSA/SHA256 package signature")


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    _policy(policy)
    if retained.format != "rpm":
        raise RpmFailure("Expected retained RPM state")
    if not retained.accepted_history:
        if (
            retained.prior_generation is not None
            or retained.metadata
            or retained.objects
            or retained.active_identities
        ):
            raise RpmFailure("Incomplete retained RPM state")
        return
    _trust(retained, runtime)
    root = Path(_string(retained.metadata, "root"))
    records = _records(root, retained.accepted_history)
    objects = {ref.key: ref for ref in retained.objects}
    if len(objects) != len(retained.objects):
        raise RpmFailure("Duplicate retained object")
    if set(retained.active_identities) != {
        asset.inspected.identity for asset in retained.accepted_history
    }:
        raise RpmFailure("Incomplete active RPM identities")
    for asset in retained.accepted_history:
        if asset.inspected.identity.architecture not in (*policy.architectures, "noarch"):
            raise RpmFailure("Retained RPM architecture is not approved")
        if asset.inspected.metadata.get("rpm_records") != records[asset.history_key]:
            raise RpmFailure("Complete retained RPM records changed")
        if asset.transformation_policy != "rpm-sign" or asset.inspected.upstream_signature not in {
            "unsigned",
            "signed",
        }:
            raise RpmFailure("Invalid retained RPM transformation")
        location = _string(asset.inspected.metadata, "location")
        ref = objects.get(location)
        if (
            ref is None
            or ref.object_class != "package"
            or ref.sha256 != asset.published_sha256
            or ref.size != asset.inspected.metadata.get("published_size")
            or asset.published_sha256 == asset.inspected.verified.sha256
        ):
            raise RpmFailure("Incomplete source/signed RPM digest evidence")
    for key in (*ENTRIES, *(location for location, _ in metadata_documents(root).values())):
        ref = objects.get(key)
        if ref is None or sha256_file(safe_path(root, key)) != (ref.sha256, ref.size):
            raise RpmFailure("Retained metadata reference mismatch")


def _location(identity: NativeIdentity) -> str:
    """Name a package `<name>-<version>-<release>.<arch>.rpm`, without the epoch, as Fedora does."""
    return safe_key(
        f"packages/{identity.name}-{identity.version}-{identity.release}"
        f".{identity.architecture}.rpm"
    )


def _ref(path: Path, key: str, kind: str) -> ObjectRef:
    digest, size = sha256_file(path)
    content_type = {
        "package": "application/x-rpm",
        "dependency": "application/gzip",
        "entry": "application/pgp-signature" if key.endswith(".asc") else "application/xml",
    }[kind]
    return ObjectRef(
        "rpm",
        key,
        kind,
        size,
        digest,
        content_type,
        "no-cache" if kind == "entry" else "public,max-age=31536000,immutable",
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
    for asset in new:
        if (
            asset.inspected.identity.format != "rpm"
            or asset.transformation_policy != "rpm-sign"
            or asset.inspected.upstream_signature not in {"unsigned", "signed"}
        ):
            raise RpmFailure("Expected an admitted RPM")
        equivalents = [
            prior
            for prior in (*history, *additions)
            if compare(asset.inspected.identity, prior.inspected.identity, runtime=runtime) == 0
        ]
        if equivalents:
            if any(
                prior.inspected.verified.sha256 != asset.inspected.verified.sha256
                for prior in equivalents
            ):
                raise RpmFailure("Changed bytes for accepted native RPM identity")
        else:
            additions.append(asset)
    if not additions:
        return PreparedFormat("rpm", retained, (), retained.objects)
    out = safe_path(out.parent, out.name)
    out.mkdir(mode=0o700)
    keyring = out / "public.gpg"
    atomic_write(
        keyring,
        _run(
            runtime,
            ["gpg", "--homedir", str(signer.gnupghome), "--batch", "--export", signer.fingerprint],
        ),
    )
    if retained.accepted_history and signer.fingerprint != retained.metadata.get("fingerprint"):
        raise RpmFailure("RPM signing identity changed")
    if retained.accepted_history:
        old_root = Path(_string(retained.metadata, "root"))
        (out / "repodata").mkdir(mode=0o700)
        for key in (
            ENTRIES[0],
            *(location for location, _ in metadata_documents(old_root).values()),
        ):
            shutil.copyfile(safe_path(old_root, key), safe_path(out, key))
    paths: list[tuple[Path, str, str]] = []
    for asset in additions:
        source = asset.inspected.verified
        if sha256_file(source.local_path) != (source.sha256, source.size):
            raise RpmFailure("Verified RPM bytes changed before signing")
        identity = asset.inspected.identity
        if _identity(source.local_path, runtime) != identity:
            raise RpmFailure("RPM identity changed before signing")
        key = _location(identity)
        for prior in history:
            if _location(prior.inspected.identity) == key:
                raise RpmFailure(
                    f"{key} comes from both {prior.inspected.verified.source.repository}"
                    f" ({prior.inspected.verified.source.filename}) and {source.source.repository}"
                    f" ({source.source.filename}); publish one of them"
                )
        target = safe_path(out, key)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if _unsign(source.local_path, target, runtime) != asset.inspected.upstream_signature:
            raise RpmFailure("RPM upstream signature status changed before signing")
        gpg = shutil.which("gpg", path=runtime.environment["PATH"])
        if gpg is None:
            raise RpmFailure("GPG is unavailable")
        _run(
            runtime,
            [
                "env",
                f"GNUPGHOME={signer.gnupghome}",
                "rpmsign",
                "--define",
                f"_gpg_name {signer.fingerprint}!",
                "--define",
                f"_gpg_path {signer.gnupghome}",
                "--define",
                f"__gpg {gpg}",
                "--define",
                "_gpg_digest_algo sha256",
                "--addsign",
                str(target),
            ],
        )
        _verify_package(target, keyring, runtime)
        digest, size = sha256_file(target)
        if digest == source.sha256 or _identity(target, runtime) != identity:
            raise RpmFailure("RPM signing did not preserve identity and change source bytes")
        metadata = {**asset.inspected.metadata, "location": key, "published_size": size}
        history.append(
            replace(
                asset,
                inspected=replace(asset.inspected, metadata=metadata),
                published_sha256=digest,
            )
        )
        paths.append((target, key, "package"))
    package_list = out / "new.list"
    atomic_write(package_list, ("\n".join(key for _, key, _ in paths) + "\n").encode())
    read_list = out / "read.list"
    _run(
        runtime,
        [
            "createrepo_c",
            "--general-compress-type",
            "gz",
            "--checksum",
            "sha256",
            "--no-database",
            "--update",
            "--recycle-pkglist",
            "--skip-stat",
            "--pkglist",
            str(package_list),
            "--read-pkgs-list",
            str(read_list),
            str(out),
        ],
    )
    reads = _read(read_list).decode().splitlines()
    if sorted(reads) != sorted(key for _, key, _ in paths):
        raise RpmFailure("Indexer did not read exactly the new RPMs")
    records = _records(out, history)
    for prior in retained.accepted_history:
        if records[prior.history_key] != prior.inspected.metadata.get("rpm_records"):
            raise RpmFailure("Indexer changed historical RPM records")
    history = [
        replace(
            asset,
            inspected=replace(
                asset.inspected,
                metadata={**asset.inspected.metadata, "rpm_records": records[asset.history_key]},
            ),
        )
        for asset in history
    ]
    signer.sign_file(out / ENTRIES[0], out / ENTRIES[1])
    paths.extend(
        (safe_path(out, key), key, "dependency") for key, _ in metadata_documents(out).values()
    )
    paths.extend((out / key, key, "entry") for key in ENTRIES)
    objects = {ref.key: ref for ref in retained.objects}
    outputs: list[OutputObject] = []
    etags = retained.metadata.get("etags", {})
    if not isinstance(etags, dict):
        raise RpmFailure("Invalid retained entry ETags")
    for path, key, kind in paths:
        ref = _ref(path, key, kind)
        prior = objects.get(key)
        if prior is not None and kind != "entry":
            if prior != ref:
                raise RpmFailure("Immutable RPM object changed")
            continue
        etag = etags.get(key) if prior else None
        if prior and (not isinstance(etag, str) or not etag):
            raise RpmFailure("Retained mutable entry needs its expected ETag")
        outputs.append(
            OutputObject(
                ref, path, "replace" if prior else "create", cast(str | None, etag), len(outputs)
            )
        )
        objects[key] = ref
    metadata: dict[str, JSONValue] = {
        "root": str(out),
        "keyring": str(keyring),
        "keyring_sha256": sha256_file(keyring)[0],
        "fingerprint": signer.fingerprint,
    }
    resulting = RetainedFormat(
        "rpm",
        retained.prior_generation,
        tuple(history),
        tuple(asset.inspected.identity for asset in history),
        metadata,
        tuple(objects.values()),
    )
    prepared = PreparedFormat("rpm", resulting, tuple(outputs), resulting.objects)
    validate_prepared(prepared, policy=policy, runtime=runtime, now=now)
    return prepared


def validate_prepared(
    prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime, now: datetime
) -> None:
    if prepared.format != "rpm" or prepared.expires_at is not None:
        raise RpmFailure("Invalid prepared RPM format")
    validate_retained(prepared.retained, policy=policy, runtime=runtime)
    if prepared.referenced_objects != prepared.retained.objects:
        raise RpmFailure("Incomplete prepared RPM object references")
    refs = {ref.key: ref for ref in prepared.referenced_objects}
    keys: list[str] = []
    for output in prepared.outputs:
        ref = output.ref
        if refs.get(ref.key) != ref or sha256_file(output.local_path) != (ref.sha256, ref.size):
            raise RpmFailure("Prepared RPM output bytes changed")
        keys.append(ref.key)
        if ref.object_class == "package":
            _verify_package(
                output.local_path, Path(_string(prepared.retained.metadata, "keyring")), runtime
            )
    if keys and (keys[-2:] != list(ENTRIES) or any(key in ENTRIES for key in keys[:-2])):
        raise RpmFailure("RPM metadata entries must follow all dependencies")
