"""Signed HTTP binary cache of the packages in each source's own flake."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import cast

from haberdasher import discovery
from haberdasher.core import (
    JSONValue,
    NativeIdentity,
    ObjectRef,
    OutputObject,
    PreparedFormat,
    Report,
    RetainedFormat,
    atomic_write,
    quiet,
    safe_path,
    sha256_file,
    stale_entries,
    step,
    text,
)
from haberdasher.runtime import Runtime, RuntimeFailure
from haberdasher.signing import NIX_KEY_NAME, SigningSession

PUBKEY_KEY = "keys/haberdasher-nix.pub"
CACHE_INFO_KEY = "nix-cache-info"
CACHE_INFO = b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 41\n"
IMMUTABLE = "public, max-age=31536000, immutable"
BUILD_TIMEOUT = 3600
# The flake repository that earlier releases generated. Its objects stay in the bucket.
LEGACY_REPO = "packages.git/"
_NIX32 = "[0-9a-df-np-sv-z]"
_NAR = re.compile(rf"nar/{_NIX32}{{52}}\.nar\.zst")
_NARINFO = re.compile(rf"{_NIX32}{{32}}\.narinfo")
_STORE_PATH = re.compile(rf"/nix/store/({_NIX32}{{32}})-[A-Za-z0-9+._?=-]+")
_ATTRIBUTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*")
# The name, version, store path, description, and platform names of each package of one system.
# A platform pattern that is not a system name evaluates to null.
_APPLY = (
    "packages: builtins.mapAttrs (attribute: package: "
    "let parsed = builtins.parseDrvName package.name; in { "
    "name = package.pname or parsed.name; "
    "version = package.version or parsed.version; "
    "path = package.outPath; "
    'description = package.meta.description or ""; '
    "platforms = if package.meta ? platforms then map "
    "(platform: if builtins.isString platform then platform else null) "
    "package.meta.platforms else null; }) packages"
)


class NixFailure(RuntimeFailure):
    pass


@dataclass(frozen=True)
class Package:
    """One flake package for one system, from the latest release tag of its source."""

    repository: str
    tag: str
    flake: str
    attribute: str
    name: str
    version: str
    system: str
    path: str
    description: str = ""
    # The version that the derivation reports. A flake cannot see its tag, so it can differ.
    derivation_version: str = ""

    def __post_init__(self) -> None:
        for value in (self.repository, self.tag, self.flake, self.name, self.version, self.system):
            text(value, "Nix package field")
        if _ATTRIBUTE.fullmatch(self.attribute) is None:
            raise NixFailure(f"Invalid Nix package attribute {self.attribute!r}")
        if _STORE_PATH.fullmatch(self.path) is None:
            raise NixFailure(f"Invalid Nix store path {self.path!r}")
        if not isinstance(self.description, str) or not isinstance(self.derivation_version, str):
            raise NixFailure("Invalid Nix package description")

    @property
    def identity(self) -> NativeIdentity:
        return NativeIdentity("nix", self.name, self.system, self.version)

    @property
    def narinfo(self) -> str:
        return f"{self.path.removeprefix('/nix/store/')[:32]}.narinfo"

    def record(self) -> dict[str, JSONValue]:
        return {item.name: getattr(self, item.name) for item in fields(self)}


def _run(runtime: Runtime, argv: Sequence[str], *, timeout: float = 600) -> bytes:
    result = runtime.run(argv, timeout=timeout)
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise NixFailure(f"Native Nix command failed ({argv[0]}): {detail}")
    return result.stdout


def _command(*args: str) -> list[str]:
    return ["nix", "--extra-experimental-features", "nix-command flakes", *args]


def _nix(runtime: Runtime, *args: str, timeout: float = 600) -> bytes:
    return _run(runtime, _command(*args), timeout=timeout)


def _string(value: JSONValue, label: str = "metadata value") -> str:
    if not isinstance(value, str) or not value:
        raise NixFailure(f"Missing or invalid Nix {label}")
    return value


def _mapping(value: JSONValue, label: str = "metadata mapping") -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise NixFailure(f"Missing or invalid Nix {label}")
    return value


@dataclass(frozen=True)
class Target:
    """The flake to build for the latest release of one source."""

    repository: str
    tag: str
    flake: str
    # True when the flake is at the commit that the `latest` tag names.
    latest: bool


def target(repository: str, tag: str, runtime: Runtime) -> Target:
    """The release tag, or the commit of the `latest` tag when it is at or after the release.

    Consumers follow `latest` without `follows`, so the cache serves them only when it
    holds a build of that commit. Pin the commit, not the moving tag.
    """
    flake = f"github:{repository}/{tag}"
    commit = discovery.tag_commit(repository, "latest", runtime)
    if commit is None:
        return Target(repository, tag, flake, False)
    match discovery.compare_status(repository, tag, commit, runtime):
        case "identical":
            return Target(repository, tag, flake, True)
        case "ahead":
            return Target(repository, tag, f"github:{repository}/{commit}", True)
        case _:
            return Target(repository, tag, flake, False)


def targets(releases: Sequence[tuple[str, str]], *, runtime: Runtime) -> list[Target]:
    return [target(repository, tag, runtime) for repository, tag in releases]


def with_references(retained: RetainedFormat, found: Sequence[Target]) -> RetainedFormat:
    """Record the flake reference that the page shows for each source with published packages.

    It is the `latest` tag when every package of the release is built from the commit that
    `latest` names, so a lock file holds the commit that the cache serves. Otherwise it is the
    default branch.
    """
    items = published(retained)
    chosen: dict[str, JSONValue] = {}
    for item in sorted(found, key=lambda value: value.repository):
        if not any(package.repository == item.repository for package in items):
            continue
        flakes = {
            package.flake
            for package in items
            if (package.repository, package.tag) == (item.repository, item.tag)
        }
        follows = item.latest and flakes == {item.flake}
        chosen[item.repository] = f"github:{item.repository}" + ("/latest" if follows else "")
    metadata = {key: value for key, value in retained.metadata.items() if key != "references"}
    if chosen:
        metadata["references"] = chosen
    if metadata == retained.metadata:
        return retained
    return replace(retained, metadata=metadata)


def flake_references(retained: RetainedFormat) -> dict[str, str]:
    """The recorded flake reference of each source."""
    value = _mapping(retained.metadata.get("references", {}), "flake references")
    sources = {item.repository for item in published(retained)}
    result: dict[str, str] = {}
    for repository, reference in value.items():
        if repository not in sources or reference not in (
            f"github:{repository}",
            f"github:{repository}/latest",
        ):
            raise NixFailure(f"Invalid flake reference for {repository}")
        result[repository] = reference
    return result


def release_version(tag: str) -> str:
    """The package version: the release tag without a leading v, as for Homebrew and Scoop."""
    return tag.removeprefix("v")


def host_system(runtime: Runtime) -> str:
    """The Nix system that this publisher builds natively."""
    raw = _nix(runtime, "eval", "--raw", "--impure", "--expr", "builtins.currentSystem")
    return raw.decode("utf-8").strip()


def published(retained: RetainedFormat) -> list[Package]:
    """The published packages, in publication order."""
    value = retained.metadata.get("packages", [])
    if not isinstance(value, list):
        raise NixFailure("Invalid retained Nix packages")
    names = {item.name for item in fields(Package)}
    result: list[Package] = []
    for item in value:
        record = _mapping(item, "package record")
        if set(record) != names:
            raise NixFailure("Retained Nix package fields differ from schema version 1")
        result.append(Package(**cast(dict[str, str], record)))
    return result


def _legacy(retained: RetainedFormat) -> bool:
    return bool(retained.accepted_history) or "head" in retained.metadata


def current(retained: RetainedFormat) -> RetainedFormat:
    """Drop the history and Git objects of the generated flake repository, and keep the cache."""
    if not _legacy(retained):
        return retained
    keep = {"public_key", "fingerprint", "etags"}
    metadata: dict[str, JSONValue] = {
        key: value for key, value in retained.metadata.items() if key in keep
    }
    metadata["packages"] = []
    stale = [key for key in stale_entries(retained) if not key.startswith(LEGACY_REPO)]
    if "stale" in retained.metadata:
        metadata["stale"] = list[JSONValue](stale)
    objects = tuple(ref for ref in retained.objects if not ref.key.startswith(LEGACY_REPO))
    return RetainedFormat("nix", (), (), metadata, objects)


def _evaluate(flake: str, system: str, runtime: Runtime) -> dict[str, JSONValue] | str:
    """The packages of a flake for one system, or the reason that it has none."""
    result = runtime.run(
        _command("eval", "--json", f"{flake}#packages.{system}", "--apply", _APPLY), timeout=600
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace")
        if "flake.nix' does not exist" in detail:
            return "no flake"
        if "does not provide attribute" in detail:
            return f"no packages for {system}"
        lines = [line.strip() for line in detail.splitlines() if line.strip()]
        return lines[-1] if lines else "evaluation failed"
    try:
        value = cast(JSONValue, json.loads(result.stdout))
    except ValueError:
        return "invalid evaluation output"
    return value if isinstance(value, dict) else "invalid evaluation output"


def pending(
    found_targets: Sequence[Target],
    retained: RetainedFormat,
    *,
    runtime: Runtime,
    report: Report = quiet,
) -> list[Package]:
    """Evaluate each target flake that no published package was built from.

    Skip a source without packages with one line. A package of the same release from another
    commit replaces the published one.
    """
    known = published(retained)
    built = {(item.repository, item.tag, item.flake) for item in known}
    prior = {item.identity: item for item in known}
    todo = [item for item in found_targets if (item.repository, item.tag, item.flake) not in built]
    if not todo:
        return []
    system = host_system(runtime)
    result: list[Package] = []
    for chosen in todo:
        repository, tag, flake = chosen.repository, chosen.tag, chosen.flake
        found = _evaluate(flake, system, runtime)
        if isinstance(found, str):
            step(report, "nix", f"skipped {repository} {tag}: {found}")
            continue
        items: list[Package] = []
        platforms: dict[str, JSONValue] = {}
        for attribute, raw in sorted(found.items()):
            info = _mapping(raw, "package evaluation")
            platforms[attribute] = info.get("platforms")
            try:
                items.append(
                    Package(
                        repository,
                        tag,
                        flake,
                        attribute,
                        _string(info.get("name"), "package name"),
                        release_version(tag),
                        system,
                        _string(info.get("path"), "store path"),
                        " ".join(str(info.get("description") or "").split()),
                        _string(info.get("version"), "package version"),
                    )
                )
            except (ValueError, NixFailure) as error:
                step(report, "nix", f"skipped {repository} {tag} {attribute}: {error}")
        named = {item.path for item in items if item.attribute != "default"}
        items = [item for item in items if item.attribute != "default" or item.path not in named]
        if not items:
            step(report, "nix", f"skipped {repository} {tag}: no packages for {system}")
        for item in items:
            names = platforms[item.attribute]
            if isinstance(names, list) and None not in names and system not in names:
                step(
                    report,
                    "nix",
                    f"skipped {repository} {tag} {item.attribute}: meta.platforms excludes {system}",
                )
                continue
            old = prior.get(item.identity)
            if old is not None and (old.path, old.flake) == (item.path, item.flake):
                continue
            if old is not None and (old.tag != item.tag or old.flake == item.flake):
                step(
                    report,
                    "nix",
                    f"skipped {repository} {tag} {item.attribute}: {item.name} {item.version} "
                    "is already published from another store path. Release a new version",
                )
                continue
            result.append(item)
    return result


def _classify(key: str) -> tuple[str, str, bool, int]:
    if _NAR.fullmatch(key):
        return "package", "application/x-nix-nar", False, 0
    if _NARINFO.fullmatch(key):
        return "dependency", "text/x-nix-narinfo", False, 1
    if key == PUBKEY_KEY:
        return "dependency", "text/plain; charset=utf-8", False, 1
    if key == CACHE_INFO_KEY:
        return "entry", "text/x-nix-cache-info", True, 2
    raise NixFailure(f"Unexpected public Nix object: {key}")


def validate_retained(retained: RetainedFormat) -> None:
    if retained.format != "nix" or retained.accepted_history:
        raise NixFailure("Expected Nix retained state without release assets")
    native = {key for key in retained.metadata if key not in {"etags", "stale"}}
    if not native:
        if retained.objects or retained.active_identities:
            raise NixFailure("Incomplete initial Nix retained state")
        return
    items = published(retained)
    if retained.active_identities != tuple(item.identity for item in items):
        raise NixFailure("Retained Nix active identities differ from the published packages")
    if len(set(retained.active_identities)) != len(items):
        raise NixFailure("Duplicate retained Nix package identity")
    flake_references(retained)
    public_key = _string(retained.metadata.get("public_key"), "public key")
    if not public_key.startswith(f"{NIX_KEY_NAME}:"):
        raise NixFailure("Unexpected retained Nix public key name")
    if re.fullmatch(r"[A-F0-9]{40}", _string(retained.metadata.get("fingerprint"))) is None:
        raise NixFailure("Invalid retained Nix signing fingerprint")
    refs = {ref.key: ref for ref in retained.objects}
    if len(refs) != len(retained.objects):
        raise NixFailure("Duplicate retained Nix object keys")
    for key, ref in refs.items():
        kind, content_type, mutable, _ = _classify(key)
        if ref.object_class != kind or ref.content_type != content_type:
            raise NixFailure(f"Retained Nix object metadata mismatch for {key}")
        if ref.cache_control != ("no-cache" if mutable else IMMUTABLE):
            raise NixFailure(f"Retained Nix cache policy mismatch for {key}")
    expected = {
        CACHE_INFO_KEY: CACHE_INFO,
        PUBKEY_KEY: f"{public_key}\n".encode("ascii"),
    }
    for key, data in expected.items():
        ref = refs.get(key)
        if ref is None or (ref.sha256, ref.size) != (hashlib.sha256(data).hexdigest(), len(data)):
            raise NixFailure(f"Retained Nix {key} is missing or differs from the signing key")
    if any(item.narinfo not in refs for item in items):
        raise NixFailure("A published Nix package has no narinfo in the cache")


def _closure(
    runtime: Runtime, path: str, cached: set[str]
) -> tuple[set[str], dict[str, dict[str, JSONValue]]]:
    """Store paths to upload, and the reference entries that cache.nixos.org or this cache serve."""
    raw = json.loads(_nix(runtime, "path-info", "--json", "--json-format", "2", "-r", path))
    info = _mapping(_mapping(cast(JSONValue, raw), "path-info").get("info"), "path-info map")
    own = path.removeprefix("/nix/store/")
    exports = {own}
    stubs: dict[str, dict[str, JSONValue]] = {}
    for key, value in info.items():
        entry = _mapping(value, "path-info entry")
        if key == own:
            continue
        signatures = entry.get("signatures", [])
        upstream = isinstance(signatures, list) and any(
            isinstance(sig, str) and sig.startswith("cache.nixos.org-1:") for sig in signatures
        )
        if upstream or f"{key[:32]}.narinfo" in cached:
            stubs[key] = entry
        else:
            exports.add(key)
    return exports, stubs


def _export(
    runtime: Runtime,
    exports: set[str],
    stubs: dict[str, dict[str, JSONValue]],
    cache: Path,
    secret_key: Path,
    public_value: str,
) -> None:
    """Sign and compress the store paths into a file binary cache, then verify them."""
    stub_names: list[str] = []
    for key, entry in stubs.items():
        if key in exports:
            continue
        references = entry.get("references", [])
        names = [str(item) for item in references] if isinstance(references, list) else []
        stub = (
            f"StorePath: /nix/store/{key}\n"
            f"URL: nar/{'0' * 52}.nar.zst\n"
            "Compression: zstd\n"
            f"NarHash: {_string(entry.get('narHash'), 'narHash')}\n"
            f"NarSize: {entry.get('narSize')}\n"
            f"References: {' '.join(sorted(names))}\n"
        )
        stub_names.append(f"{key[:32]}.narinfo")
        atomic_write(safe_path(cache, stub_names[-1]), stub.encode("utf-8"))
    paths = [f"/nix/store/{key}" for key in sorted(exports)]
    destination = f"file://{cache}?compression=zstd&secret-key={secret_key}"
    _nix(runtime, "copy", "--no-recursive", "--to", destination, *paths)
    for name in stub_names:
        safe_path(cache, name).unlink(missing_ok=True)
    verify = ("store", "verify", "--store", f"file://{cache}", "--trusted-public-keys")
    _nix(runtime, *verify, public_value, *paths)


def prepare(
    new: Sequence[Package],
    retained: RetainedFormat,
    *,
    runtime: Runtime,
    signer: SigningSession,
    out: Path,
    report: Report = quiet,
) -> PreparedFormat:
    """Build each new package, then sign the store paths that cache.nixos.org does not serve.

    A package whose build fails is skipped with one line. Without a built package, the
    retained state is returned unchanged.
    """
    state = current(retained)
    validate_retained(state)
    if state.metadata.get("fingerprint") not in (None, signer.fingerprint):
        raise NixFailure("Nix signing primary changed without a trust transition")
    out = safe_path(out, "validation").parent
    cache = safe_path(out, "cache")
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    old_refs = {ref.key: ref for ref in state.objects}
    exports: set[str] = set()
    stubs: dict[str, dict[str, JSONValue]] = {}
    built: list[Package] = []
    for item in new:
        # The cache already serves this store path, so only the package record changes.
        if item.narinfo in old_refs:
            built.append(item)
            continue
        installable = f"{item.flake}#packages.{item.system}.{item.attribute}"
        result = runtime.run(
            _command("build", "--no-link", "--print-out-paths", installable), timeout=BUILD_TIMEOUT
        )
        if result.returncode or item.path not in result.stdout.decode(errors="replace").split():
            label = f"{item.repository} {item.tag} {item.attribute}"
            step(report, "nix", f"skipped {label}: the build failed")
            continue
        built.append(item)
        paths, entries = _closure(runtime, item.path, set(old_refs))
        exports |= paths
        stubs.update(entries)
    if not built:
        return PreparedFormat("nix", retained, (), retained.objects)
    secret_key, public_key_file, public_value = signer.nix_key()
    if state.metadata.get("public_key") not in (None, public_value):
        raise NixFailure("Derived Nix public key changed without a trust transition")
    if exports:
        _export(runtime, exports, stubs, cache, secret_key, public_value)
    atomic_write(safe_path(cache, CACHE_INFO_KEY), CACHE_INFO)
    staged: dict[str, Path] = {}
    for path in sorted(cache.rglob("*")):
        relative = path.relative_to(cache).as_posix()
        if path.is_file() and (
            relative == CACHE_INFO_KEY or _NAR.fullmatch(relative) or _NARINFO.fullmatch(relative)
        ):
            staged[relative] = path
    key_path = safe_path(out, PUBKEY_KEY)
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(public_key_file, key_path)
    staged[PUBKEY_KEY] = key_path
    stale = stale_entries(state)
    etags = _mapping(state.metadata.get("etags", {}), "entry ETags")
    refs: list[ObjectRef] = []
    outputs: list[OutputObject] = []
    for key in sorted(old_refs.keys() | staged.keys(), key=lambda item: (_classify(item)[3], item)):
        kind, content_type, mutable, _ = _classify(key)
        prior = old_refs.get(key)
        if key not in staged:
            refs.append(old_refs[key])
            continue
        sha, size = sha256_file(staged[key])
        ref = ObjectRef(
            "nix", key, kind, size, sha, content_type, "no-cache" if mutable else IMMUTABLE
        )
        refs.append(ref)
        if prior is not None and (prior.sha256, prior.size) == (sha, size) and key not in stale:
            continue
        if prior is not None and not mutable:
            raise NixFailure(f"Immutable Nix object {key} changed")
        etag = _string(etags.get(key), "entry ETag") if prior is not None else None
        outputs.append(
            OutputObject(ref, staged[key], "replace" if prior else "create", etag, len(outputs))
        )
    # A rebuild of a release from another commit replaces its package record. The objects of
    # the earlier store path stay in the bucket.
    replaced = {item.identity for item in built}
    items = [*(item for item in published(state) if item.identity not in replaced), *built]
    metadata: dict[str, JSONValue] = {
        "public_key": public_value,
        "fingerprint": signer.fingerprint,
        "packages": [item.record() for item in items],
    }
    result = RetainedFormat(
        "nix", (), tuple(item.identity for item in items), metadata, tuple(refs)
    )
    prepared = PreparedFormat("nix", result, tuple(outputs), result.objects)
    validate_prepared(prepared)
    return prepared


def validate_prepared(prepared: PreparedFormat) -> None:
    if prepared.format != "nix" or prepared.referenced_objects != prepared.retained.objects:
        raise NixFailure("Prepared Nix object closure differs from retained state")
    validate_retained(prepared.retained)
    refs = {ref.key: ref for ref in prepared.referenced_objects}
    previous_rank = -1
    for ordinal, output in enumerate(prepared.outputs):
        if refs.get(output.ref.key) != output.ref:
            raise NixFailure("Prepared Nix output differs from referenced objects")
        _kind, _ctype, mutable, rank = _classify(output.ref.key)
        if (
            output.ordinal != ordinal
            or rank < previous_rank
            or (not mutable and output.mode != "create")
            or sha256_file(output.local_path) != (output.ref.sha256, output.ref.size)
        ):
            raise NixFailure("Prepared Nix output bytes or publication order is invalid")
        previous_rank = rank
