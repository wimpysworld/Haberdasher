"""Copies of release assets and a Git repository over dumb HTTP, for Homebrew and Scoop."""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    JSONValue,
    ObjectRef,
    OutputObject,
    PreparedFormat,
    RetainedFormat,
    VerifiedAsset,
    atomic_write,
    safe_path,
    sha256_file,
    stale_entries,
)
from haberdasher.runtime import Runtime

AUTHOR = ("Haberdasher", "code@wimpress.io")
# Dumb HTTP clients read these mutable files, in this order, after the immutable objects.
ENTRIES = ("info/refs", "objects/info/packs", "refs/heads/main", "HEAD")
_OBJECT = re.compile(r"objects/(?:[0-9a-f]{2}/[0-9a-f]{38}|pack/pack-[0-9a-f]{40}\.(?:pack|idx))")
_NAME = re.compile(r"[a-z0-9][a-z0-9.+-]*")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
IMMUTABLE = "public, max-age=31536000, immutable"


class MirrorFailure(ValueError):
    pass


def name(value: str) -> str:
    """The tool name: lower case, with a hyphen for each space or underscore."""
    return value.lower().replace(" ", "-").replace("_", "-")


def version(tag: str) -> str:
    return tag.removeprefix("v")


def valid(tool: str, release: str) -> bool:
    return _NAME.fullmatch(tool) is not None and _VERSION.fullmatch(release) is not None


def check(asset: VerifiedAsset) -> None:
    if sha256_file(asset.local_path) != (asset.sha256, asset.size):
        raise MirrorFailure("Missing or changed input asset")


def key(item: InspectedAsset) -> str:
    identity = item.identity
    return f"{identity.name}/{identity.version}/{item.verified.source.filename}"


def latest(history: Sequence[AdmittedAsset]) -> dict[str, list[InspectedAsset]]:
    """The assets of the newest version of each tool, by tool name."""
    newest: dict[str, str] = {}
    for item in history:
        newest[item.inspected.identity.name] = item.inspected.identity.version
    return {
        tool: [
            item.inspected
            for item in history
            if (item.inspected.identity.name, item.inspected.identity.version) == (tool, release)
        ]
        for tool, release in sorted(newest.items())
    }


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
        raise MirrorFailure(f"Native git command failed: git {args[0]}")
    return result.stdout.decode().strip()


def repository(
    objects: Mapping[str, Path],
    head: str | None,
    files: Mapping[str, str],
    *,
    runtime: Runtime,
    out: Path,
    now: datetime,
    message: str,
) -> tuple[str, Path]:
    """Restore the objects, commit changed files on main, and update the server info.

    Return the new head and the bare repository. Each commit adds to the history, so clients
    fast-forward.
    """
    out.mkdir(mode=0o700, parents=True)
    repo = out / "repo.git"
    _git(runtime, repo, "init", "--quiet", "--bare", "--initial-branch=main")
    for name, path in objects.items():
        if _OBJECT.fullmatch(name) is None:
            raise MirrorFailure(f"Unexpected Git object: {name}")
        target = safe_path(repo, name)
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
        head = _git(runtime, repo, "commit-tree", tree, *parent, "-m", message, now=now)
        _git(runtime, repo, "update-ref", "refs/heads/main", head)
    _git(runtime, repo, "update-server-info")
    return head, repo


def published_files(repo: Path) -> dict[str, Path]:
    """The files that dumb HTTP clients read: the objects first, then the entries in order."""
    result = {
        name: path
        for path in sorted(repo.rglob("*"))
        if path.is_file() and _OBJECT.fullmatch(name := path.relative_to(repo).as_posix())
    }
    for name in ENTRIES:
        path = safe_path(repo, name)
        if not path.is_file():
            raise MirrorFailure(f"Git repository lacks {name}")
        result[name] = path
    return result


def _ref(form: str, path: Path, name: str, kind: str) -> ObjectRef:
    digest, size = sha256_file(path)
    if kind == "entry":
        content_type = "text/plain; charset=utf-8"
    else:
        content_type = "application/zip" if name.endswith(".zip") else "application/octet-stream"
    return ObjectRef(
        form, name, kind, size, digest, content_type, "no-cache" if kind == "entry" else IMMUTABLE
    )


def _string(value: JSONValue) -> str:
    if not isinstance(value, str) or not value:
        raise MirrorFailure("Missing retained metadata value")
    return value


def _mapping(value: JSONValue) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise MirrorFailure("Missing retained metadata mapping")
    return value


def validate_retained(retained: RetainedFormat, form: str, root: str) -> None:
    """Check the asset copies and the Git repository at the root key."""
    if retained.format != form:
        raise MirrorFailure(f"Expected {form} retained state")
    if not retained.accepted_history:
        if retained.metadata or retained.objects or retained.active_identities:
            raise MirrorFailure(f"Incomplete {form} retained state")
        return
    if retained.active_identities != tuple(
        item.inspected.identity for item in retained.accepted_history
    ):
        raise MirrorFailure(f"Incomplete retained {form} identities")
    refs = {ref.key: ref for ref in retained.objects}
    for item in retained.accepted_history:
        verified = item.inspected.verified
        ref = refs.get(key(item.inspected))
        if (
            ref is None
            or ref.object_class != "package"
            or (ref.sha256, ref.size) != (verified.sha256, verified.size)
            or item.published_sha256 != verified.sha256
        ):
            raise MirrorFailure(f"Missing retained {form} package reference")
    if re.fullmatch(r"[0-9a-f]{40}", _string(retained.metadata.get("head"))) is None:
        raise MirrorFailure("Invalid retained Git head")
    for name, value in _mapping(retained.metadata.get("files")).items():
        ref = refs.get(name)
        if ref is None or ref.object_class != "dependency":
            raise MirrorFailure("Missing retained Git object reference")
        if sha256_file(Path(_string(value))) != (ref.sha256, ref.size):
            raise MirrorFailure("Retained Git object is missing or corrupt")
    if any(refs.get(f"{root}/{name}") is None for name in ENTRIES):
        raise MirrorFailure("Missing retained Git entry")


def prepare(
    new: Sequence[AdmittedAsset],
    retained: RetainedFormat,
    *,
    form: str,
    root: str,
    files: Callable[[Sequence[AdmittedAsset]], dict[str, str]],
    message: str,
    runtime: Runtime,
    now: datetime,
    out: Path,
) -> PreparedFormat:
    """Copy new assets, then commit the files that the history gives to the Git repository."""
    validate_retained(retained, form, root)
    history = list(retained.accepted_history)
    additions: list[AdmittedAsset] = []
    for candidate in new:
        if candidate in history:
            continue
        if candidate.transformation_policy != "preserve":
            raise MirrorFailure(f"Unexpected {form} transformation")
        check(candidate.inspected.verified)
        item = replace(candidate, published_sha256=candidate.inspected.verified.sha256)
        additions.append(item)
        history.append(item)
    stale = stale_entries(retained)
    if not additions and not stale:
        return PreparedFormat(form, retained, (), retained.objects)
    out = safe_path(out, "validation").parent
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    old = {ref.key: ref for ref in retained.objects}
    refs = dict(old)
    outputs: list[OutputObject] = []
    for item in additions:
        name = key(item.inspected)
        path = safe_path(out, name)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(item.inspected.verified.local_path, path)
        refs[name] = _ref(form, path, name, "package")
        outputs.append(OutputObject(refs[name], path, "create", None, len(outputs)))
    restored = _mapping(retained.metadata.get("files", {}))
    head, repo = repository(
        {name.removeprefix(f"{root}/"): Path(_string(value)) for name, value in restored.items()},
        _string(retained.metadata["head"]) if retained.accepted_history else None,
        files(history),
        runtime=runtime,
        out=out / "git",
        now=now,
        message=message,
    )
    etags = _mapping(retained.metadata.get("etags", {}))
    objects: dict[str, JSONValue] = {}
    for inner, path in published_files(repo).items():
        name = f"{root}/{inner}"
        entry = inner in ENTRIES
        ref = _ref(form, path, name, "entry" if entry else "dependency")
        if not entry:
            objects[name] = str(path)
        refs[name] = ref
        prior = old.get(name)
        if prior is not None and (prior.sha256, prior.size) == (ref.sha256, ref.size):
            if name not in stale:
                continue
        elif prior is not None and not entry:
            raise MirrorFailure("Immutable Git object changed")
        etag = None if prior is None else _string(etags.get(name))
        outputs.append(
            OutputObject(ref, path, "create" if prior is None else "replace", etag, len(outputs))
        )
    result = RetainedFormat(
        form,
        tuple(history),
        tuple(item.inspected.identity for item in history),
        {"head": head, "files": objects},
        tuple(refs.values()),
    )
    prepared = PreparedFormat(form, result, tuple(outputs), result.objects)
    validate_prepared(prepared, form, root)
    return prepared


def validate_prepared(prepared: PreparedFormat, form: str, root: str) -> None:
    if prepared.format != form or prepared.referenced_objects != prepared.retained.objects:
        raise MirrorFailure(f"Prepared {form} references differ from retained state")
    validate_retained(prepared.retained, form, root)
    entry_seen = False
    for output in prepared.outputs:
        if output.ref not in prepared.referenced_objects:
            raise MirrorFailure(f"Unreferenced prepared {form} output")
        if sha256_file(output.local_path) != (output.ref.sha256, output.ref.size):
            raise MirrorFailure(f"Prepared {form} output changed")
        if output.ref.object_class == "entry":
            entry_seen = True
        elif entry_seen or output.mode != "create":
            raise MirrorFailure("Asset copies and Git objects must be new and precede Git entries")
