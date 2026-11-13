"""Homebrew casks for macOS binaries and apps, in a Git tap that the bucket serves over dumb HTTP."""

from __future__ import annotations

import plistlib
import struct
import zipfile
from collections.abc import Sequence
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
    PreparedFormat,
    RetainedFormat,
    UnsupportedAsset,
    VerifiedAsset,
)
from haberdasher.formats import mirror
from haberdasher.formats.mirror import version
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession

TAP = "tap.git"
TAP_NAME = "wimpysworld/tap"
_CPU = {0x01000007: "intel", 0x0100000C: "arm"}
MH_EXECUTE = 2
MAX_PLIST = 1024 * 1024


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
    except (
        KeyError,
        zipfile.BadZipFile,
        plistlib.InvalidFileException,
        ValueError,
        NotImplementedError,
        RuntimeError,
    ):
        return "", ()
    return app, macho_architectures(header)


def token(filename: str, app: str = "") -> str:
    """The cask name: the app name, or the asset name before its operating system."""
    if app:
        return mirror.name(app.removesuffix(".app"))
    match = discovery.MACOS_BINARY.fullmatch(filename)
    return mirror.name(match[1]) if match else ""


def inspect(
    asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
) -> InspectedAsset:
    mirror.check(asset)
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
    tag, description, _ = discovery.release_details(asset.source, runtime)
    if not mirror.valid(name, version(tag)):
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
        url = f"{PUBLIC['brew'][1]}/{quote(mirror.key(item))}"
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
    return {name: cask(items) for name, items in mirror.latest(history).items()}


def readme(names: Sequence[str]) -> str:
    installs = "\n".join(f"brew install --cask {TAP_NAME}/{name}" for name in names)
    return (
        "# Wimpy's World tap\n\n"
        "Homebrew casks for the macOS builds of projects by Martin Wimpress.\n"
        f"See {PUBLIC['brew'][1]}/ for details.\n\n"
        "```sh\n"
        f"brew tap {TAP_NAME} {PUBLIC['brew'][1]}/{TAP}\n"
        f"{installs}\n"
        "```\n"
    )


def files(history: Sequence[AdmittedAsset]) -> dict[str, str]:
    """The tap files: the README and one cask per tool."""
    tools = casks(history)
    return {"README.md": readme(list(tools)), **{f"Casks/{n}.rb": t for n, t in tools.items()}}


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    if policy.format != "brew":
        raise mirror.MirrorFailure("Expected the Homebrew policy")
    mirror.validate_retained(retained, "brew", TAP)


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
    """Copy new assets, then commit every cask to the tap. Homebrew needs no signatures."""
    validate_retained(retained, policy=policy, runtime=runtime)
    return mirror.prepare(
        new,
        retained,
        form="brew",
        root=TAP,
        files=files,
        message="Update casks",
        runtime=runtime,
        now=now,
        out=out,
    )


def validate_prepared(prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    mirror.validate_prepared(prepared, "brew", TAP)
