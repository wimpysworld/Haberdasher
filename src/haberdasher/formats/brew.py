"""Homebrew casks for macOS binaries and apps, in a Git tap that the bucket serves over dumb HTTP."""

from __future__ import annotations

import plistlib
import re
import shutil
import struct
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from haberdasher import discovery
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
    atomic_write,
    safe_path,
    sha256_file,
    stale_entries,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession

TAP = "tap.git"
TAP_NAME = "wimpysworld/haberdasher"
AUTHOR = ("Haberdasher", "code@wimpress.io")
# Dumb HTTP clients read these mutable files, in this order, after the immutable objects.
ENTRIES = ("info/refs", "objects/info/packs", "refs/heads/main", "HEAD")
_OBJECT = re.compile(r"objects/(?:[0-9a-f]{2}/[0-9a-f]{38}|pack/pack-[0-9a-f]{40}\.(?:pack|idx))")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9.+-]*")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
_CPU = {0x01000007: "intel", 0x0100000C: "arm"}
MH_EXECUTE = 2
MAX_PLIST = 1024 * 1024
IMMUTABLE = "public, max-age=31536000, immutable"


class BrewFailure(ValueError):
    pass


def macho_architectures(header: bytes) -> tuple[str, ...]:
    """The Homebrew architectures of a Mach-O executable header, or none for other bytes."""
    magic = header[:4]
    if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") and len(header) >= 16:
        cpu, _, kind = struct.unpack((">" if magic[0] == 0xFE else "<") + "III", header[4:16])
        return (_CPU[cpu],) if cpu in _CPU and kind == MH_EXECUTE else ()
    if magic == b"\xca\xfe\xba\xbe" and len(header) >= 8:
        # Java class files share this magic. Their version field reads as a large slice count.
        (count,) = struct.unpack(">I", header[4:8])
        if not 0 < count <= 8 or len(header) < 8 + 20 * count:
            return ()
        cpus = {struct.unpack(">I", header[8 + 20 * i : 12 + 20 * i])[0] for i in range(count)}
        return tuple(sorted(_CPU[cpu] for cpu in cpus if cpu in _CPU))
    return ()


def _architecture(architectures: Sequence[str]) -> str:
    return architectures[0] if len(architectures) == 1 else "universal"


def zip_app(path: Path) -> tuple[str, tuple[str, ...]]:
    """The one top-level app bundle of a zip file and the architectures of its executable."""
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            tops = {name.split("/", 1)[0] for name in names}
            app = next(iter(tops)) if len(tops) == 1 else ""
            if not app.endswith(".app") or not any(name.startswith(f"{app}/") for name in names):
                return "", ()
            plist = archive.getinfo(f"{app}/Contents/Info.plist")
            if plist.file_size > MAX_PLIST:
                return "", ()
            executable = plistlib.loads(archive.read(plist)).get("CFBundleExecutable")
            if not isinstance(executable, str) or not executable or "/" in executable:
                return "", ()
            with archive.open(f"{app}/Contents/MacOS/{executable}") as stream:
                header = stream.read(4096)
    except KeyError, zipfile.BadZipFile, plistlib.InvalidFileException, ValueError:
        return "", ()
    return app, macho_architectures(header)


def token(filename: str, app: str = "") -> str:
    """The cask name: the app name, or the asset name before its operating system."""
    if app:
        return app.removesuffix(".app").lower().replace(" ", "-")
    match = discovery.MACOS_BINARY.fullmatch(filename)
    return match[1].lower().replace("_", "-") if match else ""


def version(tag: str) -> str:
    return tag.removeprefix("v")


def _check(asset: VerifiedAsset) -> None:
    if sha256_file(asset.local_path) != (asset.sha256, asset.size):
        raise BrewFailure("Missing or changed Homebrew input")


def inspect(
    asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
) -> InspectedAsset:
    _check(asset)
    filename = asset.source.filename
    app = ""
    if filename.endswith(".zip"):
        app, architectures = zip_app(asset.local_path)
        if not app:
            raise UnsupportedAsset(f"{filename}: not a zip file of one macOS app")
    else:
        with asset.local_path.open("rb") as stream:
            architectures = macho_architectures(stream.read(4096))
    if not architectures:
        raise UnsupportedAsset(f"{filename}: not a macOS executable")
    name = token(filename, app)
    tag, description = discovery.release_details(asset.source, runtime)
    if _TOKEN.fullmatch(name) is None or _VERSION.fullmatch(version(tag)) is None:
        raise UnsupportedAsset(f"{filename}: no valid cask name or version")
    architecture = _architecture(architectures)
    if architecture not in policy.architectures:
        raise UnsupportedAsset(f"{filename}: unsupported architecture {architecture!r}")
    metadata: dict[str, JSONValue] = {"desc": description}
    if app:
        metadata["app"] = app
    return InspectedAsset(
        asset, NativeIdentity("brew", name, architecture, version(tag)), metadata, {}, "unsigned"
    )


def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
    same = (left.format, left.name, left.architecture, left.version) == (
        right.format,
        right.name,
        right.architecture,
        right.version,
    )
    return 0 if same else None


def _key(item: InspectedAsset) -> str:
    identity = item.identity
    return f"{identity.name}/{identity.version}/{item.verified.source.filename}"


def _ruby(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("#", "\\#")
    return f'"{escaped}"'


def cask(items: Sequence[InspectedAsset]) -> str:
    """The cask text for the assets of one tool version."""
    first = items[0]
    name, release = first.identity.name, first.identity.version
    app = first.metadata.get("app")
    app = app if isinstance(app, str) else ""
    desc = first.metadata.get("desc")
    architectures = {item.identity.architecture: item for item in items}

    def source(item: InspectedAsset, indent: str) -> list[str]:
        url = f"{PUBLIC['brew'][1]}/{quote(_key(item))}"
        return [f'{indent}sha256 "{item.verified.sha256}"', f"{indent}url {_ruby(url)}"]

    def binary(item: InspectedAsset, indent: str) -> list[str]:
        filename = item.verified.source.filename
        return [] if app else [f"{indent}binary {_ruby(filename)}, target: {_ruby(name)}"]

    lines = [f"cask {_ruby(name)} do", f"  version {_ruby(release)}", ""]
    universal = architectures.get("universal")
    if universal is not None:
        lines += [*source(universal, "  ")]
    else:
        for architecture in ("arm", "intel"):
            item = architectures.get(architecture)
            if item is not None:
                lines += [
                    f"  on_{architecture} do",
                    *source(item, "    "),
                    *(["", *binary(item, "    ")] if not app else []),
                    "  end",
                ]
    lines += ["", f"  name {_ruby(app.removesuffix('.app') if app else name)}"]
    if isinstance(desc, str) and desc:
        lines.append(f"  desc {_ruby(desc)}")
    lines.append(f"  homepage {_ruby(f'https://github.com/{first.verified.source.repository}')}")
    if universal is None and len(architectures) == 1:
        only = next(iter(architectures))
        lines += ["", f"  depends_on arch: :{'arm64' if only == 'arm' else 'intel'}"]
    if app:
        lines += ["", f"  app {_ruby(app)}"]
    elif universal is not None:
        lines += ["", *binary(universal, "  ")]
    target = f"{{{{appdir}}}}/{app}" if app else "{{staged_path}}"
    lines += [
        "",
        "  postflight_steps do",
        f'    run "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", {_ruby(target)}]',
        "  end",
        "end",
        "",
    ]
    return "\n".join(lines)


def casks(history: Sequence[AdmittedAsset]) -> dict[str, str]:
    """One cask per tool, for the newest published version of each."""
    latest: dict[str, str] = {}
    for item in history:
        latest[item.inspected.identity.name] = item.inspected.identity.version
    return {
        name: cask(
            [
                item.inspected
                for item in history
                if (item.inspected.identity.name, item.inspected.identity.version)
                == (name, release)
            ]
        )
        for name, release in sorted(latest.items())
    }


def readme(names: Sequence[str]) -> str:
    installs = "\n".join(f"brew install --cask {TAP_NAME}/{name}" for name in names)
    return (
        "# Haberdasher tap\n\n"
        "Homebrew casks for the macOS builds of projects by Martin Wimpress.\n"
        f"Haberdasher writes this tap. See {PUBLIC['brew'][1]}/ for details.\n\n"
        "```sh\n"
        f"brew tap {TAP_NAME} {PUBLIC['brew'][1]}/{TAP}\n"
        f"{installs}\n"
        "```\n"
    )


def _git(
    runtime: Runtime, repo: Path, *args: str, now: datetime | None = None, cwd: Path | None = None
) -> str:
    environment = [
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_GLOBAL=/dev/null",
        f"GIT_INDEX_FILE={repo.parent / 'index'}",
    ]
    if now is not None:
        stamp = now.strftime("%Y-%m-%dT%H:%M:%S+0000")
        for role in ("AUTHOR", "COMMITTER"):
            environment += [
                f"GIT_{role}_NAME={AUTHOR[0]}",
                f"GIT_{role}_EMAIL={AUTHOR[1]}",
                f"GIT_{role}_DATE={stamp}",
            ]
    result = runtime.run(
        ["env", *environment, "git", "-c", "gc.auto=0", f"--git-dir={repo}", *args], cwd=cwd
    )
    if result.returncode:
        raise BrewFailure(f"Native git command failed: git {args[0]}")
    return result.stdout.decode().strip()


def tap(
    objects: Mapping[str, Path],
    head: str | None,
    files: Mapping[str, str],
    *,
    runtime: Runtime,
    out: Path,
    now: datetime,
) -> tuple[str, Path]:
    """Restore the tap objects, commit the files on main when they change, and update server info.

    Return the new head and the bare repository. History accumulates, so clients fast-forward.
    """
    out.mkdir(mode=0o700, parents=True)
    repo = out / TAP
    _git(runtime, repo, "init", "--quiet", "--bare", "--initial-branch=main")
    for key, path in objects.items():
        if _OBJECT.fullmatch(key) is None:
            raise BrewFailure(f"Unexpected tap object: {key}")
        target = safe_path(repo, key)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    if head is not None:
        _git(runtime, repo, "update-ref", "refs/heads/main", head)
    work = out / "work"
    for name, data in files.items():
        path = safe_path(work, name)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_write(path, data.encode())
    _git(runtime, repo, f"--work-tree={work}", "add", "--all", cwd=work)
    tree = _git(runtime, repo, "write-tree")
    if head is None or _git(runtime, repo, "rev-parse", f"{head}^{{tree}}") != tree:
        parent = ("-p", head) if head is not None else ()
        head = _git(runtime, repo, "commit-tree", tree, *parent, "-m", "Update casks", now=now)
        _git(runtime, repo, "update-ref", "refs/heads/main", head)
    _git(runtime, repo, "update-server-info")
    return head, repo


def published_files(repo: Path) -> dict[str, Path]:
    """The tap files that dumb HTTP clients read, objects first and then the entries in order."""
    result = {
        key: path
        for path in sorted(repo.rglob("*"))
        if path.is_file() and _OBJECT.fullmatch(key := path.relative_to(repo).as_posix())
    }
    for key in ENTRIES:
        path = safe_path(repo, key)
        if not path.is_file():
            raise BrewFailure(f"Tap lacks {key}")
        result[key] = path
    return result


def _ref(path: Path, key: str, kind: str) -> ObjectRef:
    digest, size = sha256_file(path)
    if kind == "entry":
        content_type = "text/plain; charset=utf-8"
    else:
        content_type = "application/zip" if key.endswith(".zip") else "application/octet-stream"
    return ObjectRef(
        "brew", key, kind, size, digest, content_type, "no-cache" if kind == "entry" else IMMUTABLE
    )


def _string(value: JSONValue) -> str:
    if not isinstance(value, str) or not value:
        raise BrewFailure("Missing Homebrew retained metadata value")
    return value


def _mapping(value: JSONValue) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise BrewFailure("Missing Homebrew retained metadata mapping")
    return value


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    if retained.format != "brew" or policy.format != "brew":
        raise BrewFailure("Expected Homebrew retained state")
    if not retained.accepted_history:
        if retained.metadata or retained.objects or retained.active_identities:
            raise BrewFailure("Incomplete Homebrew retained state")
        return
    if retained.active_identities != tuple(
        item.inspected.identity for item in retained.accepted_history
    ):
        raise BrewFailure("Incomplete retained Homebrew identities")
    refs = {ref.key: ref for ref in retained.objects}
    for item in retained.accepted_history:
        verified = item.inspected.verified
        ref = refs.get(_key(item.inspected))
        if (
            ref is None
            or ref.object_class != "package"
            or (ref.sha256, ref.size) != (verified.sha256, verified.size)
            or item.published_sha256 != verified.sha256
        ):
            raise BrewFailure("Missing retained Homebrew package reference")
    if re.fullmatch(r"[0-9a-f]{40}", _string(retained.metadata.get("head"))) is None:
        raise BrewFailure("Invalid retained tap head")
    for key, value in _mapping(retained.metadata.get("files")).items():
        ref = refs.get(key)
        if ref is None or ref.object_class != "dependency":
            raise BrewFailure("Missing retained tap object reference")
        if sha256_file(Path(_string(value))) != (ref.sha256, ref.size):
            raise BrewFailure("Retained tap object is missing or corrupt")
    if any(refs.get(f"{TAP}/{key}") is None for key in ENTRIES):
        raise BrewFailure("Missing retained tap entry")


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
    """Mirror new assets, then commit every cask to the tap. Homebrew needs no signatures."""
    validate_retained(retained, policy=policy, runtime=runtime)
    history = list(retained.accepted_history)
    additions: list[AdmittedAsset] = []
    for candidate in new:
        if candidate in history:
            continue
        if candidate.transformation_policy != "preserve":
            raise BrewFailure("Unexpected Homebrew transformation")
        _check(candidate.inspected.verified)
        item = replace(candidate, published_sha256=candidate.inspected.verified.sha256)
        additions.append(item)
        history.append(item)
    stale = stale_entries(retained)
    if not additions and not stale:
        return PreparedFormat("brew", retained, (), retained.objects)
    out = safe_path(out, "validation").parent
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    old = {ref.key: ref for ref in retained.objects}
    refs = dict(old)
    outputs: list[OutputObject] = []
    for item in additions:
        key = _key(item.inspected)
        path = safe_path(out, key)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(item.inspected.verified.local_path, path)
        refs[key] = _ref(path, key, "package")
        outputs.append(OutputObject(refs[key], path, "create", None, len(outputs)))
    files = _mapping(retained.metadata.get("files", {}))
    tools = casks(history)
    head, repo = tap(
        {key.removeprefix(f"{TAP}/"): Path(_string(value)) for key, value in files.items()},
        _string(retained.metadata["head"]) if retained.accepted_history else None,
        {"README.md": readme(list(tools)), **{f"Casks/{n}.rb": text for n, text in tools.items()}},
        runtime=runtime,
        out=out / "tap",
        now=now,
    )
    etags = _mapping(retained.metadata.get("etags", {}))
    objects: dict[str, JSONValue] = {}
    for name, path in published_files(repo).items():
        key = f"{TAP}/{name}"
        entry = name in ENTRIES
        ref = _ref(path, key, "entry" if entry else "dependency")
        if not entry:
            objects[key] = str(path)
        refs[key] = ref
        prior = old.get(key)
        if prior is not None and (prior.sha256, prior.size) == (ref.sha256, ref.size):
            if key not in stale:
                continue
        elif prior is not None and not entry:
            raise BrewFailure("Immutable tap object changed")
        etag = None if prior is None else _string(etags.get(key))
        outputs.append(
            OutputObject(ref, path, "create" if prior is None else "replace", etag, len(outputs))
        )
    result = RetainedFormat(
        "brew",
        tuple(history),
        tuple(item.inspected.identity for item in history),
        {"head": head, "files": objects},
        tuple(refs.values()),
    )
    prepared = PreparedFormat("brew", result, tuple(outputs), result.objects)
    validate_prepared(prepared, policy=policy, runtime=runtime)
    return prepared


def validate_prepared(prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    if prepared.format != "brew" or prepared.referenced_objects != prepared.retained.objects:
        raise BrewFailure("Prepared Homebrew references differ from retained state")
    validate_retained(prepared.retained, policy=policy, runtime=runtime)
    entry_seen = False
    for output in prepared.outputs:
        if output.ref not in prepared.referenced_objects:
            raise BrewFailure("Unreferenced prepared Homebrew output")
        if sha256_file(output.local_path) != (output.ref.sha256, output.ref.size):
            raise BrewFailure("Prepared Homebrew output changed")
        if output.ref.object_class == "entry":
            entry_seen = True
        elif entry_seen or output.mode != "create":
            raise BrewFailure("Homebrew files and tap objects must be new and precede tap entries")
