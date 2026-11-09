"""Publish upstream Flatpak commits, signed with the publisher key, without rebuilding refs."""

from __future__ import annotations

import base64
import gzip
import json
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from haberdasher.admission import admit
from haberdasher.config import PUBLIC, FormatPolicy
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
    canonical_json,
    digest,
    json_value,
    safe_key,
    safe_path,
    sha256_file,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession

MAX_METADATA = 1024 * 1024
_REF = re.compile(r"app/([A-Za-z0-9_]+(?:\.[A-Za-z0-9_-]+){2,})/([A-Za-z0-9_]+)/([A-Za-z0-9_.-]+)")
_OBJECT = re.compile(r"objects/[0-9a-f]{2}/[0-9a-f]{62}\.(commit|dirtree|dirmeta|filez|commitmeta)")
_SUMMARY = re.compile(
    r"summaries/(?:[0-9a-f]{64}\.(?:gz|idx|idx\.sig)|[0-9a-f]{64}-[0-9a-f]{64}\.delta)"
)
_ENTRIES = ("config", "summary", "summary.sig", "summary.idx", "summary.idx.sig")
# Runtime source for bundles that do not name one. Electron and Freedesktop runtimes live there.
FLATHUB = "https://dl.flathub.org/repo/flathub.flatpakrepo"
FLATPAKREPO = "wimpysworld.flatpakrepo"
TITLE = "Wimpy's World"


class FlatpakFailure(ValueError):
    pass


def _run(runtime: Runtime, *args: str) -> bytes:
    result = runtime.run(args)
    if result.returncode:
        raise FlatpakFailure(f"Native Flatpak command failed: {args[0]}: {result.stderr.decode()}")
    return result.stdout


def _native(runtime: Runtime, **request: str) -> dict[str, JSONValue]:
    result = runtime.run(["haberdasher-flatpak-metadata"], input=canonical_json(request))
    if result.returncode:
        raise FlatpakFailure("Native Flatpak metadata inspection failed")
    value: object = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise FlatpakFailure("Invalid native metadata response")
    return cast(dict[str, JSONValue], value)


def _mapping(value: JSONValue) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise FlatpakFailure("Missing metadata mapping")
    return value


def _string(value: JSONValue) -> str:
    if not isinstance(value, str) or not value:
        raise FlatpakFailure("Missing metadata string")
    return value


def _runtime_repo(value: JSONValue) -> str:
    if value is None:
        return FLATHUB
    parsed = urlsplit(_string(value))
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or (parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"})
    ):
        raise FlatpakFailure("Runtime repository must be an HTTPS URL")
    return _string(value)


def _runtime_repos(history: Sequence[AdmittedAsset]) -> str:
    repos = sorted({_string(item.inspected.evidence.get("runtime_repo")) for item in history})
    if len(repos) != 1:
        raise FlatpakFailure(
            "Flatpak bundles name different runtime repositories: " + ", ".join(repos)
        )
    return repos[0]


def _flatpakrepo(public: bytes, runtime_repo: str) -> bytes:
    """The remote description that users add, with the publisher key and the runtime source."""
    return (
        f"[Flatpak Repo]\nTitle={TITLE}\nUrl={PUBLIC['flatpak'][1]}/\n"
        f"GPGKey={base64.b64encode(public).decode()}\nRuntimeRepo={runtime_repo}\n"
    ).encode()


def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
    if (left.format, left.name, left.architecture) != (
        right.format,
        right.name,
        right.architecture,
    ):
        return None
    if left.format != "flatpak":
        return None
    for version in (left.version, right.version):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}", version):
            raise FlatpakFailure("Unqualified AppStream version")
    output = _run(runtime, "appstreamcli", "vercmp", left.version, right.version).decode().strip()
    for marker, result in ((" << ", -1), (" == ", 0), (" >> ", 1)):
        if output == f"{left.version}{marker}{right.version}":
            return result
    raise FlatpakFailure("Invalid native AppStream comparison")


def _xml(path: Path) -> ET.Element:
    path = safe_path(path.parent, path.name)
    with path.open("rb") as stream:
        if path.suffix == ".gz":
            with gzip.GzipFile(fileobj=stream) as archive:
                data = archive.read(MAX_METADATA + 1)
        else:
            data = stream.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise FlatpakFailure("Unsafe or oversized AppStream metadata")
    try:
        return ET.fromstring(data)
    except ET.ParseError as error:
        raise FlatpakFailure("Invalid AppStream metadata") from error


def _version(path: Path, ref: str, runtime: Runtime) -> str:
    xml = _xml(path)
    app = ref.split("/")[1]
    components = [xml] if xml.tag == "component" else list(xml.findall("component"))
    matches = [node for node in components if node.findtext("id") in {app, app + ".desktop"}]
    if len(matches) != 1 or len(components) != 1:
        raise FlatpakFailure("AppStream must identify exactly one application")
    component = matches[0]
    if any(
        bundle.get("type") != "flatpak" or bundle.text != ref
        for bundle in component.findall("bundle")
    ):
        raise FlatpakFailure("AppStream ref differs from the upstream ref")
    releases = component.findall("releases/release")
    if not releases or len(releases) > 1000:
        raise FlatpakFailure("AppStream version evidence is missing or excessive")
    versions = [release.get("version", "") for release in releases]
    identity = NativeIdentity("flatpak", ref, ref.split("/")[2], versions[0] or "invalid")
    for index, version in enumerate(versions):
        candidate = NativeIdentity("flatpak", ref, identity.architecture, version or "invalid")
        order = compare(identity, candidate, runtime=runtime)
        if not version or order == -1 or (index and order == 0):
            raise FlatpakFailure("AppStream version evidence is ambiguous")
    return versions[0]


def _metadata(runtime: Runtime, repo: Path, commit: str) -> dict[str, JSONValue]:
    metadata = _run(runtime, "ostree", f"--repo={repo}", "cat", commit, "/metadata")
    if len(metadata) > MAX_METADATA:
        raise FlatpakFailure("Application metadata exceeds 1 MiB")
    return _native(runtime, repository=str(repo), commit=commit, metadata=metadata.decode())


def _check_metadata(data: dict[str, JSONValue], ref: str) -> str:
    """Return the runtime ref that the application metadata names for the bundle's architecture."""
    commit = _mapping(data.get("commit"))
    keyfile = _mapping(data.get("keyfile"))
    application = _mapping(keyfile.get("Application"))
    runtime = _string(application.get("runtime"))
    match = _REF.fullmatch("app/" + runtime)
    if (
        commit.get("ostree.ref-binding") != [ref]
        or commit.get("ostree.collection-binding") != ""
        or application.get("name") != ref.split("/")[1]
        or match is None
        or match[2] != ref.split("/")[2]
        or data.get("extra_data") is not False
        or any(group.lower() == "extra data" for group in keyfile)
        or "extra-data" in application
    ):
        raise FlatpakFailure("Invalid ref, collection, runtime or extra-data")
    for group, values in keyfile.items():
        if group.startswith("Extension "):
            safe_key(_string(_mapping(values).get("directory")))
    if "Runtime" in keyfile or "ExtensionOf" in keyfile:
        raise FlatpakFailure("Only application bundles are qualified")
    return "runtime/" + runtime


def _checkout(runtime: Runtime, repo: Path, commit: str, target: Path) -> None:
    _run(runtime, "ostree", f"--repo={repo}", "checkout", "--user-mode", commit, str(target))


def _appstream(tree: Path, ref: str, runtime: Runtime) -> str:
    directory = safe_path(tree, "files/share/app-info/xmls")
    files = list(directory.iterdir()) if directory.is_dir() else []
    if len(files) != 1 or files[0].suffix not in {".gz", ".xml"}:
        raise FlatpakFailure("One native AppStream catalogue is required")
    return _version(safe_path(tree, str(files[0].relative_to(tree))), ref, runtime)


def inspect(
    asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
) -> InspectedAsset:
    if sha256_file(asset.local_path) != (asset.sha256, asset.size):
        raise FlatpakFailure("Bundle bytes differ from verified input")
    bundle = _mapping(_native(runtime, bundle=str(asset.local_path)).get("bundle"))
    ref = _string(bundle.get("ref"))
    commit = digest(bundle.get("commit"))
    match = _REF.fullmatch(ref)
    if match is None:
        raise FlatpakFailure(f"{asset.source.filename}: not an application bundle: {ref!r}")
    if match[2] not in policy.architectures:
        raise FlatpakFailure(
            f"{asset.source.filename}: unsupported Flatpak architecture {match[2]!r}"
        )
    if bundle.get("collection") != "":
        raise FlatpakFailure(
            f"{asset.source.filename}: bundles with a collection ID are not supported"
        )
    runtime_repo = _runtime_repo(bundle.get("runtime_repo"))
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out, prefix="quarantine-") as work:
        repo = Path(work) / "repo"
        _run(runtime, "ostree", f"--repo={repo}", "init", "--mode=archive-z2")
        _run(
            runtime,
            "flatpak",
            "build-import-bundle",
            "--no-update-summary",
            str(repo),
            str(asset.local_path),
        )
        if _heads(runtime, repo) != {ref: commit}:
            raise FlatpakFailure("Imported refs differ from bundle identity")
        _run(runtime, "ostree", f"--repo={repo}", "fsck")
        data = _metadata(runtime, repo, commit)
        runtime_ref = _check_metadata(data, ref)
        native_commit = _mapping(data.get("commit"))
        if native_commit.get("xa.metadata") != bundle.get("metadata"):
            raise FlatpakFailure("Bundle and commit metadata differ")
        tree = Path(work) / "tree"
        _checkout(runtime, repo, commit, tree)
        if safe_path(tree, "metadata").read_text() != bundle.get("metadata"):
            raise FlatpakFailure("Commit metadata and payload differ")
        version = _appstream(tree, ref, runtime)
    # Preparation replaces any upstream signature with the publisher signature.
    signed = bool(data.pop("signatures", None))
    return InspectedAsset(
        asset,
        NativeIdentity("flatpak", ref, match[2], version, source_commit=commit),
        {"bundle": bundle, "native": data},
        {
            "runtime": runtime_ref,
            "runtime_repo": runtime_repo,
            "version_source": "commit-appstream",
        },
        "signed" if signed else "unsigned",
    )


def _heads(runtime: Runtime, repo: Path) -> dict[str, str]:
    refs = _run(runtime, "ostree", f"--repo={repo}", "refs").decode().splitlines()
    return {
        ref: digest(_run(runtime, "ostree", f"--repo={repo}", "rev-parse", ref).decode().strip())
        for ref in refs
    }


def _classify(key: str) -> tuple[str, bool, int]:
    if _OBJECT.fullmatch(key):
        return "dependency", key.endswith(".commitmeta"), 0
    if _SUMMARY.fullmatch(key):
        return "dependency", False, 1
    if key == "config":
        return "entry", True, 2
    if key.startswith("refs/heads/"):
        return "entry", True, 3
    if key in _ENTRIES[1:]:
        return "entry", True, 4 + _ENTRIES.index(key)
    if key == FLATPAKREPO:
        return "entry", True, 4 + len(_ENTRIES)
    raise FlatpakFailure(f"Unexpected public repository file: {key}")


def _files(repo: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in repo.rglob("*"):
        key = path.relative_to(repo).as_posix()
        if path.is_symlink():
            raise FlatpakFailure("Repository file is a symlink")
        if (
            path.is_file()
            and not key.startswith(("tmp/", "state/", "extensions/"))
            and key not in {"lock", ".lock"}
        ):
            _classify(key)
            result[key] = path
    return result


def _verify_signatures(
    runtime: Runtime,
    source: Path,
    signatures: JSONValue,
    public: Path,
    fingerprint: str,
    work: Path,
) -> None:
    if not isinstance(signatures, list) or not signatures:
        raise FlatpakFailure("Missing native GPG signature")
    home = work / "verify-home"
    home.mkdir(mode=0o700, exist_ok=True)
    for index, signature in enumerate(signatures):
        sig = work / f"signature-{index}"
        sig.write_bytes(base64.b64decode(_string(signature), validate=True))
        output = _run(
            runtime,
            "gpgv",
            "--homedir",
            str(home),
            "--keyring",
            str(public),
            "--status-fd",
            "1",
            str(sig),
            str(source),
        )
        valid = [
            line.split() for line in output.splitlines() if line.startswith(b"[GNUPG:] VALIDSIG ")
        ]
        if (
            len(valid) != 1
            or len(valid[0]) < 12
            or valid[0][2] != fingerprint.encode()
            or valid[0][8:10] != [b"1", b"8"]
            or valid[0][11] != fingerprint.encode()
        ):
            raise FlatpakFailure("Signature must use the approved primary and SHA256")


def _validate_repo(
    retained: RetainedFormat, policy: FormatPolicy, runtime: Runtime, repo: Path
) -> None:
    config = repo / "config"
    with config.open("rb") as stream:
        data = stream.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA or _native(runtime, metadata=data.decode()).get("keyfile") != {
        "core": {"repo_version": "1", "mode": "archive-z2", "indexed-deltas": "true"}
    }:
        raise FlatpakFailure("Unapproved retained repository configuration")
    heads = _heads(runtime, repo)
    if heads != retained.metadata.get("heads"):
        raise FlatpakFailure("Retained heads differ from native refs")
    expected = {identity.name: identity.source_commit for identity in retained.active_identities}
    apps = {ref: commit for ref, commit in heads.items() if ref.startswith("app/")}
    if apps != expected or any(
        ref not in expected
        and ref not in {f"appstream/{arch}" for arch in policy.architectures}
        and ref not in {f"appstream2/{arch}" for arch in policy.architectures}
        for ref in heads
    ):
        raise FlatpakFailure("Unexpected repository heads")
    _run(runtime, "ostree", f"--repo={repo}", "fsck")
    with tempfile.TemporaryDirectory(dir=runtime.root, prefix="validate-flatpak-") as directory:
        work = Path(directory)
        public = work / "public.gpg"
        public.write_bytes(
            base64.b64decode(_string(retained.metadata.get("public_key")), validate=True)
        )
        fingerprint = _string(retained.metadata.get("fingerprint"))
        expected_repo = _flatpakrepo(public.read_bytes(), _runtime_repos(retained.accepted_history))
        if (repo / FLATPAKREPO).read_bytes() != expected_repo:
            raise FlatpakFailure(f"Retained {FLATPAKREPO} differs from the signing key or runtime")
        for index, (ref, commit) in enumerate(heads.items()):
            data = _native(runtime, repository=str(repo), commit=commit)
            source = safe_path(repo, f"objects/{commit[:2]}/{commit[2:]}.commit")
            _verify_signatures(runtime, source, data.get("signatures"), public, fingerprint, work)
            tree = work / f"tree-{index}"
            _checkout(runtime, repo, commit, tree)
            if ref in expected:
                _check_metadata(_metadata(runtime, repo, commit), ref)
                version = _appstream(tree, ref, runtime)
                if version != next(
                    identity.version
                    for identity in retained.active_identities
                    if identity.name == ref
                ):
                    raise FlatpakFailure("Retained version differs from application payload")
        for name in ("summary", "summary.idx"):
            data = _native(runtime, summary_signature=str(repo / (name + ".sig")))
            _verify_signatures(
                runtime, repo / name, data.get("signatures"), public, fingerprint, work
            )


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    if policy.format != "flatpak" or retained.format != "flatpak":
        raise FlatpakFailure("Wrong retained format")
    if retained.prior_generation is None and not retained.accepted_history and not retained.objects:
        if retained.metadata or retained.active_identities:
            raise FlatpakFailure("Incomplete initial state")
        return
    if not retained.objects or not retained.accepted_history:
        raise FlatpakFailure("Missing retained history or objects")
    if retained.metadata.get("policy") != json.loads(canonical_json(policy)):
        raise FlatpakFailure("Retained policy changed")
    files = _mapping(retained.metadata.get("files"))
    if set(files) != {ref.key for ref in retained.objects}:
        raise FlatpakFailure("Retained object closure is incomplete")
    for ref in retained.objects:
        _classify(ref.key)
        if sha256_file(Path(_string(files[ref.key]))) != (ref.sha256, ref.size):
            raise FlatpakFailure("Retained file is missing or corrupt")
    active = {identity.name: identity for identity in retained.active_identities}
    if len(active) != len(retained.active_identities):
        raise FlatpakFailure("Duplicate active ref")
    for identity in active.values():
        if not any(item.inspected.identity == identity for item in retained.accepted_history):
            raise FlatpakFailure("Active identity is absent from accepted history")
    for item in retained.accepted_history:
        identity = item.inspected.identity
        if (
            identity.name not in active
            or compare(identity, active[identity.name], runtime=runtime) == 1
        ):
            raise FlatpakFailure("Retained head moved backwards or disappeared")
    with tempfile.TemporaryDirectory(dir=runtime.root, prefix="retained-flatpak-") as directory:
        repo = Path(directory) / "repo"
        _restore(runtime, retained, repo)
        _validate_repo(retained, policy, runtime, repo)


def _restore(runtime: Runtime, retained: RetainedFormat, repo: Path) -> None:
    _run(runtime, "ostree", f"--repo={repo}", "init", "--mode=archive-z2")
    if retained.objects:
        files = _mapping(retained.metadata.get("files"))
        for ref in retained.objects:
            target = safe_path(repo, ref.key)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(Path(_string(files[ref.key])), target)


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
    if retained.objects and retained.metadata.get("fingerprint") != signer.fingerprint:
        raise FlatpakFailure("Signing identity changed without a trust transition")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    repo = out / "repo"
    if repo.exists():
        raise FlatpakFailure("Preparation requires a new repository path")
    _restore(runtime, retained, repo)
    history = list(retained.accepted_history)
    active = {identity.name: identity for identity in retained.active_identities}
    sign = (f"--gpg-sign={signer.fingerprint}!", f"--gpg-homedir={signer.gnupghome}")
    for asset in new:
        if asset in history:
            continue
        inspected = inspect(asset.inspected.verified, policy=policy, runtime=runtime, out=out)
        if inspected != asset.inspected:
            raise FlatpakFailure("Admission evidence changed")
        accepted = admit(inspected, history, compare=compare, policy=policy, runtime=runtime)
        if accepted != asset:
            raise FlatpakFailure("Admission record differs from the approved transformation")
        _run(
            runtime,
            "flatpak",
            "build-import-bundle",
            "--no-update-summary",
            str(repo),
            str(inspected.verified.local_path),
        )
        commit = digest(inspected.identity.source_commit)
        if _heads(runtime, repo).get(inspected.identity.name) != commit:
            raise FlatpakFailure("Import changed the source commit")
        # Detached metadata holds the upstream signatures. Replace it with the publisher signature.
        safe_path(repo, f"objects/{commit[:2]}/{commit[2:]}.commitmeta").unlink(missing_ok=True)
        _run(
            runtime,
            "ostree",
            f"--repo={repo}",
            "gpg-sign",
            f"--gpg-homedir={signer.gnupghome}",
            commit,
            f"{signer.fingerprint}!",
        )
        if sha256_file(inspected.verified.local_path) != (
            inspected.verified.sha256,
            inspected.verified.size,
        ):
            raise FlatpakFailure("Import changed the source bundle")
        history.append(asset)
        active[inspected.identity.name] = inspected.identity
    if not history:
        raise FlatpakFailure("Cannot publish an empty Flatpak repository")
    _run(runtime, "flatpak", "build-update-repo", *sign, str(repo))
    public = _run(
        runtime,
        "gpg",
        "--homedir",
        str(signer.gnupghome),
        "--batch",
        "--export",
        signer.fingerprint,
    )
    if not public:
        raise FlatpakFailure("Missing public signing key")
    (repo / FLATPAKREPO).write_bytes(_flatpakrepo(public, _runtime_repos(history)))
    files = _files(repo)
    old = {ref.key: ref for ref in retained.objects}
    oldfiles = _mapping(retained.metadata.get("files", {}))
    for key in old.keys() - files.keys():
        if _classify(key)[1]:
            raise FlatpakFailure("Native update removed a retained mutable entry")
        target = safe_path(repo, key)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(Path(_string(oldfiles[key])), target)
        files[key] = target
    refs: list[ObjectRef] = []
    outputs: list[OutputObject] = []
    etags = _mapping(retained.metadata.get("etags", {}))
    for key in sorted(files, key=lambda key: (_classify(key)[2], key)):
        kind, mutable, _ = _classify(key)
        sha, size = sha256_file(files[key])
        ref = ObjectRef(
            "flatpak",
            key,
            kind,
            size,
            sha,
            "application/octet-stream",
            "no-cache" if mutable else "public,max-age=31536000,immutable",
        )
        refs.append(ref)
        prior = old.get(key)
        if prior is not None and prior.sha256 == sha and prior.size == size:
            continue
        if prior is not None and not mutable:
            raise FlatpakFailure("Immutable repository object changed")
        etag = _string(etags.get(key)) if prior is not None else None
        outputs.append(
            OutputObject(ref, files[key], "replace" if prior else "create", etag, len(outputs))
        )
    result = RetainedFormat(
        "flatpak",
        retained.prior_generation,
        tuple(history),
        tuple(active.values()),
        {
            "files": {key: str(path) for key, path in files.items()},
            "heads": json_value(_heads(runtime, repo)),
            "public_key": base64.b64encode(public).decode(),
            "fingerprint": signer.fingerprint,
            "policy": json.loads(canonical_json(policy)),
            "etags": {},
        },
        tuple(refs),
    )
    prepared = PreparedFormat("flatpak", result, tuple(outputs), tuple(refs))
    validate_prepared(prepared, policy=policy, runtime=runtime, now=now)
    return prepared


def validate_prepared(
    prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime, now: datetime
) -> None:
    if prepared.format != "flatpak" or prepared.referenced_objects != prepared.retained.objects:
        raise FlatpakFailure("Prepared object closure differs from retained state")
    files = _mapping(prepared.retained.metadata.get("files"))
    objects = {ref.key: ref for ref in prepared.referenced_objects}
    order = -1
    for ordinal, output in enumerate(prepared.outputs):
        if objects.get(output.ref.key) != output.ref or output.ref.key not in files:
            raise FlatpakFailure("Output differs from the prepared object manifest")
        rank = _classify(output.ref.key)[2]
        if (
            output.ordinal != ordinal
            or rank < order
            or sha256_file(output.local_path) != (output.ref.sha256, output.ref.size)
        ):
            raise FlatpakFailure("Prepared output bytes or publication order changed")
        order = rank
    validate_retained(prepared.retained, policy=policy, runtime=runtime)
