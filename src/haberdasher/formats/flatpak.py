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
    UnsupportedAsset,
    VerifiedAsset,
    canonical_json,
    digest,
    json_value,
    safe_key,
    safe_path,
    sha256_file,
    stale_entries,
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
_FLATPAKREF = re.compile(r"([A-Za-z0-9_]+(?:\.[A-Za-z0-9_-]+){2,})\.flatpakref")
# Runtime source for bundles that do not name one. Electron and Freedesktop runtimes live there.
FLATHUB = "https://dl.flathub.org/repo/flathub.flatpakrepo"
REMOTE = "wimpysworld"
FLATPAKREPO = f"{REMOTE}.flatpakrepo"
TITLE = "Wimpy's World"
# Preparation reads only these paths of an application head. AppStream regeneration needs them.
_APP_PATHS = ("/metadata", "/files/share/app-info")


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
    url = _string(value)
    # urlsplit drops control characters, but the key files keep the original value.
    parsed = urlsplit(url)
    if (
        any(char <= " " or char == "\x7f" for char in url)
        or parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or (parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"})
    ):
        raise FlatpakFailure("Runtime repository must be an HTTPS URL")
    return url


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


def _flatpakref(app: str, branch: str, title: str, public: bytes, runtime_repo: str) -> bytes:
    """The install file for one application, which adds the remote and the runtime source."""
    return (
        f"[Flatpak Ref]\nName={app}\nBranch={branch}\nTitle={title}\n"
        f"Url={PUBLIC['flatpak'][1]}/\nGPGKey={base64.b64encode(public).decode()}\n"
        f"IsRuntime=false\nRuntimeRepo={runtime_repo}\nSuggestRemoteName={REMOTE}\n"
    ).encode()


def _flatpakrefs(
    runtime: Runtime, repo: Path, history: Sequence[AdmittedAsset], public: bytes, work: Path
) -> dict[str, bytes]:
    """Expected install files, from each application head and its bundle's runtime source."""
    apps: dict[str, set[tuple[str, str, str]]] = {}
    for ref, commit in _heads(runtime, repo).items():
        if not ref.startswith("app/"):
            continue
        _, app, _, branch = ref.split("/")
        info = _app_info(runtime, repo, commit, work / f"flatpakref-{commit}")
        runtime_repo = _runtime_repos(
            [item for item in history if item.inspected.identity.name == ref]
        )
        apps.setdefault(app, set()).add((branch, _title(_catalogue(info), ref), runtime_repo))
    result: dict[str, bytes] = {}
    for app, values in apps.items():
        if len(values) != 1:
            raise FlatpakFailure(f"{app}: architectures differ in branch, name or runtime")
        branch, title, runtime_repo = values.pop()
        result[f"{app}.flatpakref"] = _flatpakref(app, branch, title, public, runtime_repo)
    return result


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


def _component(path: Path, ref: str) -> ET.Element:
    xml = _xml(path)
    app = ref.split("/")[1]
    components = [xml] if xml.tag == "component" else list(xml.findall("component"))
    matches = [node for node in components if node.findtext("id") in {app, app + ".desktop"}]
    if len(matches) != 1 or len(components) != 1:
        raise FlatpakFailure("AppStream must identify exactly one application")
    return matches[0]


def _untranslated(path: Path, ref: str, tag: str) -> str:
    """The untranslated AppStream text of one element on one line, or an empty string."""
    values = [
        " ".join((node.text or "").split())
        for node in _component(path, ref).findall(tag)
        if "{http://www.w3.org/XML/1998/namespace}lang" not in node.attrib
    ]
    return next((value for value in values if value), "")


def _title(path: Path, ref: str) -> str:
    """The untranslated AppStream name, or the app ID when there is none."""
    return _untranslated(path, ref, "name") or ref.split("/")[1]


def _version(path: Path, ref: str, runtime: Runtime) -> str:
    component = _component(path, ref)
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


def _app_info(runtime: Runtime, repo: Path, commit: str, target: Path) -> Path:
    """Check out only the AppStream directory, which a restored application head keeps."""
    _run(
        runtime,
        "ostree",
        f"--repo={repo}",
        "checkout",
        "--user-mode",
        "--disable-cache",
        f"--subpath={_APP_PATHS[1]}",
        commit,
        str(target),
    )
    return target


def _catalogue(info: Path) -> Path:
    directory = safe_path(info, "xmls")
    files = list(directory.iterdir()) if directory.is_dir() else []
    if len(files) != 1 or files[0].suffix not in {".gz", ".xml"}:
        raise FlatpakFailure("One native AppStream catalogue is required")
    return safe_path(info, str(files[0].relative_to(info)))


def _appstream(info: Path, ref: str, runtime: Runtime) -> str:
    return _version(_catalogue(info), ref, runtime)


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
        raise UnsupportedAsset(
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
        info = safe_path(tree, _APP_PATHS[1].lstrip("/"))
        version = _appstream(info, ref, runtime)
        summary = _untranslated(_catalogue(info), ref, "summary")
    # Preparation replaces any upstream signature with the publisher signature.
    signed = bool(data.pop("signatures", None))
    return InspectedAsset(
        asset,
        NativeIdentity("flatpak", ref, match[2], version, source_commit=commit),
        {"bundle": bundle, "native": data, "summary": summary},
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
    if key == FLATPAKREPO or _FLATPAKREF.fullmatch(key):
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
            raise FlatpakFailure("Signature must use the Haberdasher signing primary and SHA256")


def _validate_repo(
    retained: RetainedFormat, policy: FormatPolicy, runtime: Runtime, repo: Path
) -> None:
    stale = stale_entries(retained)
    config = repo / "config"
    with config.open("rb") as stream:
        data = stream.read(MAX_METADATA + 1)
    if "config" not in stale and (
        len(data) > MAX_METADATA
        or _native(runtime, metadata=data.decode()).get("keyfile")
        != {"core": {"repo_version": "1", "mode": "archive-z2", "indexed-deltas": "true"}}
    ):
        raise FlatpakFailure("Unsupported retained repository configuration")
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
        if FLATPAKREPO not in stale and (repo / FLATPAKREPO).read_bytes() != expected_repo:
            raise FlatpakFailure(f"Retained {FLATPAKREPO} differs from the signing key or runtime")
        refs = _flatpakrefs(runtime, repo, retained.accepted_history, public.read_bytes(), work)
        for path in repo.glob("*.flatpakref"):
            if refs.get(path.name) != path.read_bytes():
                raise FlatpakFailure(f"Retained {path.name} differs from its application")
        for index, (ref, commit) in enumerate(heads.items()):
            data = _native(runtime, repository=str(repo), commit=commit)
            source = safe_path(repo, f"objects/{commit[:2]}/{commit[2:]}.commit")
            _verify_signatures(runtime, source, data.get("signatures"), public, fingerprint, work)
            tree = work / f"tree-{index}"
            if ref not in expected:
                _checkout(runtime, repo, commit, tree)
            else:
                _check_metadata(_metadata(runtime, repo, commit), ref)
                version = _appstream(_app_info(runtime, repo, commit, tree), ref, runtime)
                if version != next(
                    identity.version
                    for identity in retained.active_identities
                    if identity.name == ref
                ):
                    raise FlatpakFailure("Retained version differs from application payload")
        for name in ("summary", "summary.idx"):
            if {name, name + ".sig"} & stale:
                continue
            data = _native(runtime, summary_signature=str(repo / (name + ".sig")))
            _verify_signatures(
                runtime, repo / name, data.get("signatures"), public, fingerprint, work
            )


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    if policy.format != "flatpak" or retained.format != "flatpak":
        raise FlatpakFailure("Wrong retained format")
    if not retained.accepted_history and not retained.objects:
        if retained.metadata or retained.active_identities:
            raise FlatpakFailure("Incomplete initial state")
        return
    if not retained.objects or not retained.accepted_history:
        raise FlatpakFailure("Missing retained history or objects")
    files = _mapping(retained.metadata.get("files"))
    stale = stale_entries(retained)
    objects = {ref.key: ref for ref in retained.objects}
    # The files are the working set that the next preparation restores, not every object.
    if not set(files) <= set(objects) or any(
        _classify(key)[0] == "entry" and key not in files for key in objects
    ):
        raise FlatpakFailure("Retained object closure is incomplete")
    for key, ref in objects.items():
        _classify(key)
        if (
            key in files
            and key not in stale
            and sha256_file(Path(_string(files[key]))) != (ref.sha256, ref.size)
        ):
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
        heads = _mapping(retained.metadata.get("heads", {}))
        stale = stale_entries(retained)
        for key, path in files.items():
            target = safe_path(repo, key)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if key not in stale:
                shutil.copyfile(Path(_string(path)), target)
            elif key.startswith("refs/heads/"):
                # A head names its commit, which the retained heads record.
                target.write_text(digest(heads.get(key.removeprefix("refs/heads/"))) + "\n")
        # Restored application heads hold only their AppStream and metadata paths.
        # The partial marker makes fsck verify what is present instead of failing on the rest.
        for ref, commit in heads.items():
            if ref.startswith("app/"):
                commit = digest(commit)
                safe_path(repo, f"state/{commit}.commitpartial").write_bytes(b"")


def _working_set(runtime: Runtime, repo: Path, public: Path, work: Path) -> set[str]:
    """Keys that the next run restores: entries, summaries, heads and the paths that update reads.

    A native pull of the signed repository selects the head commits, their signatures, the
    AppStream trees and each application's metadata and AppStream paths. Payload files and
    earlier commits stay published but are not downloaded again.
    """
    scratch = work / "working-set"
    ostree = ("ostree", f"--repo={scratch}")
    _run(runtime, *ostree, "init", "--mode=archive-z2")
    _run(runtime, *ostree, "remote", "add", f"--gpg-import={public}", "origin", repo.as_uri())
    heads = _heads(runtime, repo)
    apps = [ref for ref in heads if ref.startswith("app/")]
    _run(runtime, *ostree, "pull", "--depth=0", "origin", *sorted(set(heads) - set(apps)))
    paths = [f"--subpath={path}" for path in _APP_PATHS]
    _run(runtime, *ostree, "pull", "--depth=0", *paths, "origin", *apps)
    keys = {
        path.relative_to(scratch).as_posix()
        for path in (scratch / "objects").rglob("*")
        if path.is_file()
    }
    if not all(_OBJECT.fullmatch(key) for key in keys):
        raise FlatpakFailure("Unexpected object in the working set")
    keys |= {f"objects/{commit[:2]}/{commit[2:]}.commitmeta" for commit in heads.values()}
    return keys | {key for key in _files(repo) if not key.startswith("objects/")}


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
            raise FlatpakFailure("Admission record differs from the expected transformation")
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
    with tempfile.TemporaryDirectory(dir=out, prefix="entries-") as directory:
        work = Path(directory)
        for name, data in _flatpakrefs(runtime, repo, history, public, work).items():
            safe_path(repo, name).write_bytes(data)
        (work / "public.gpg").write_bytes(public)
        working = _working_set(runtime, repo, work / "public.gpg", work)
    files = _files(repo)
    old = {ref.key: ref for ref in retained.objects}
    oldfiles = _mapping(retained.metadata.get("files", {}))
    if any(_classify(key)[1] for key in oldfiles.keys() - files.keys()):
        raise FlatpakFailure("Native update removed a retained mutable entry")
    if not working <= files.keys():
        raise FlatpakFailure("Working set names an absent repository file")
    refs: list[ObjectRef] = []
    outputs: list[OutputObject] = []
    etags = _mapping(retained.metadata.get("etags", {}))
    stale = stale_entries(retained)
    # Published objects that this run did not restore stay referenced, unchanged.
    for key in sorted(old.keys() | files.keys(), key=lambda key: (_classify(key)[2], key)):
        if key not in files:
            refs.append(old[key])
            continue
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
        if prior is not None and (prior.sha256, prior.size) == (sha, size) and key not in stale:
            continue
        if prior is not None and not mutable:
            raise FlatpakFailure("Immutable repository object changed")
        etag = _string(etags.get(key)) if prior is not None else None
        outputs.append(
            OutputObject(ref, files[key], "replace" if prior else "create", etag, len(outputs))
        )
    result = RetainedFormat(
        "flatpak",
        tuple(history),
        tuple(active.values()),
        {
            "files": {key: str(files[key]) for key in sorted(working)},
            "heads": json_value(_heads(runtime, repo)),
            "public_key": base64.b64encode(public).decode(),
            "fingerprint": signer.fingerprint,
            "etags": {},
        },
        tuple(refs),
    )
    prepared = PreparedFormat("flatpak", result, tuple(outputs), tuple(refs))
    validate_prepared(prepared, policy=policy, runtime=runtime)
    return prepared


def validate_prepared(prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    if prepared.format != "flatpak" or prepared.referenced_objects != prepared.retained.objects:
        raise FlatpakFailure("Prepared object closure differs from retained state")
    files = _mapping(prepared.retained.metadata.get("files"))
    objects = {ref.key: ref for ref in prepared.referenced_objects}
    order = -1
    apps = {identity.name.split("/")[1] for identity in prepared.retained.active_identities}
    if any(f"{app}.flatpakref" not in files for app in apps):
        raise FlatpakFailure("Prepared state lacks an application flatpakref")
    for ordinal, output in enumerate(prepared.outputs):
        if objects.get(output.ref.key) != output.ref:
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
