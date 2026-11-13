"""Scoop manifests for Windows executables, in a Git bucket that the bucket serves over dumb HTTP."""

from __future__ import annotations

import json
import re
import struct
import zipfile
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import IO
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

# Scoop accepts only a <host>/<user>/<repo> bucket URL.
REPO = "wimpysworld/bucket.git"
BUCKET = "wimpysworld"
_MACHINE = {0x8664: "64bit", 0xAA64: "arm64", 0x14C: "32bit"}
IMAGE_FILE_EXECUTABLE = 0x0002
IMAGE_FILE_DLL = 0x2000
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
# NSIS and Inno Setup write these markers into every installer they build.
INSTALLERS = (b"NullsoftInst", b"Inno Setup Setup Data")
# The tool name is the asset name before its version, operating system, or architecture.
_TOOL = re.compile(
    r"(.+?)(?:[-_](?:v?\d+|windows|win(?:32|64)?|x86_64|amd64|x64|arm64|aarch64|i[36]86|x86|386)"
    r"(?=[-_.]).*)?\.(?:exe|zip)",
    re.IGNORECASE,
)
ORDER = ("64bit", "32bit", "arm64")


def pe_architecture(header: bytes) -> str:
    """The Scoop architecture of a PE executable header, or an empty string for other bytes."""
    if len(header) < 64 or header[:2] != b"MZ":
        return ""
    (offset,) = struct.unpack_from("<I", header, 0x3C)
    if len(header) < offset + 24 or header[offset : offset + 4] != b"PE\0\0":
        return ""
    (machine,) = struct.unpack_from("<H", header, offset + 4)
    (characteristics,) = struct.unpack_from("<H", header, offset + 22)
    if not characteristics & IMAGE_FILE_EXECUTABLE or characteristics & IMAGE_FILE_DLL:
        return ""
    return _MACHINE.get(machine, "")


def pe_gui(header: bytes) -> bool:
    """Whether the optional header of a PE executable names the Windows GUI subsystem."""
    (offset,) = struct.unpack_from("<I", header, 0x3C)
    # The Subsystem field is at the same optional header offset in PE32 and PE32+.
    field = offset + 24 + 68
    if len(header) < field + 2:
        return False
    return struct.unpack_from("<H", header, field)[0] == IMAGE_SUBSYSTEM_WINDOWS_GUI


def installer(stream: IO[bytes]) -> bool:
    """Whether the bytes hold an NSIS or Inno Setup marker."""
    overlap = max(len(marker) for marker in INSTALLERS) - 1
    tail = b""
    while chunk := stream.read(1024 * 1024):
        window = tail + chunk
        if any(marker in window for marker in INSTALLERS):
            return True
        tail = window[-overlap:]
    return False


def _executable(stream: IO[bytes]) -> tuple[str, bool]:
    header = stream.read(4096)
    architecture = pe_architecture(header)
    stream.seek(0)
    if not architecture or installer(stream):
        return "", False
    return architecture, pe_gui(header)


def zip_exe(path: Path, app: str) -> tuple[str, str, bool]:
    """The app's .exe file in a zip file, its architecture, and whether it is a GUI app.

    The app's .exe file is the one named after the app, or else the only .exe file.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            exes = [
                info
                for info in archive.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".exe")
            ]
            named = [info for info in exes if exe_name(info.filename).lower() == app.lower()]
            choice = named if len(named) == 1 else exes
            if len(choice) != 1:
                return "", "", False
            with archive.open(choice[0]) as stream:
                return choice[0].filename, *_executable(stream)
    except zipfile.BadZipFile, ValueError, NotImplementedError, RuntimeError:
        return "", "", False


def exe_name(path: str) -> str:
    """The base name of an .exe file path in a zip file, without its suffix."""
    return path.rsplit("/", 1)[-1][: -len(".exe")]


def app_name(filename: str) -> str:
    """The asset name before its version, operating system, or architecture."""
    match = _TOOL.fullmatch(filename)
    return match[1] if match else ""


def tool(filename: str) -> str:
    """The manifest name: the app name of the asset in manifest form."""
    app = app_name(filename)
    return mirror.name(app) if app else ""


def inspect(
    asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
) -> InspectedAsset:
    mirror.check(asset)
    filename = asset.source.filename
    exe = ""
    app = app_name(filename)
    if filename.endswith(".zip"):
        exe, architecture, gui = zip_exe(asset.local_path, app)
        if not exe:
            raise UnsupportedAsset(
                f"{filename}: not a zip file of one .exe file or of one {app}.exe file"
            )
        app = exe_name(exe)
    else:
        with asset.local_path.open("rb") as stream:
            architecture, gui = _executable(stream)
    if not architecture:
        raise UnsupportedAsset(f"{filename}: not a portable Windows executable")
    name = tool(filename)
    tag, description, licence = discovery.release_details(asset.source, runtime)
    if not mirror.valid(name, version(tag)):
        raise UnsupportedAsset(f"{filename}: no valid manifest name or version")
    if architecture not in policy.architectures:
        raise UnsupportedAsset(f"{filename}: unsupported architecture {architecture!r}")
    metadata: dict[str, JSONValue] = {"desc": description, "license": licence}
    if exe:
        metadata["exe"] = exe
    if gui:
        metadata["shortcut"] = app
    return InspectedAsset(
        asset, NativeIdentity("scoop", name, architecture, version(tag)), metadata, {}, "unsigned"
    )


def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
    same = (left.format, left.name, left.architecture, left.version) == (
        right.format,
        right.name,
        right.architecture,
        right.version,
    )
    return 0 if same else None


def manifest(items: Sequence[InspectedAsset]) -> str:
    """The manifest JSON for the assets of one tool version."""
    first = items[0]
    name = first.identity.name
    architectures: dict[str, JSONValue] = {}
    for item in sorted(items, key=lambda item: ORDER.index(item.identity.architecture)):
        exe = item.metadata.get("exe")
        path = exe if isinstance(exe, str) else item.verified.source.filename
        shortcut = item.metadata.get("shortcut")
        entry: dict[str, JSONValue] = {
            "url": f"{PUBLIC['scoop'][1]}/{quote(mirror.key(item))}",
            "hash": item.verified.sha256,
        }
        if isinstance(shortcut, str):
            entry["shortcuts"] = [[path, shortcut]]
        else:
            entry["bin"] = [[path, name]]
        architectures[item.identity.architecture] = entry
    data: dict[str, JSONValue] = {"version": first.identity.version}
    desc = first.metadata.get("desc")
    if isinstance(desc, str) and desc:
        data["description"] = desc
    data["homepage"] = f"https://github.com/{first.verified.source.repository}"
    data["license"] = first.metadata.get("license") or "Unknown"
    data["architecture"] = architectures
    return json.dumps(data, indent=4) + "\n"


def manifests(history: Sequence[AdmittedAsset]) -> dict[str, str]:
    """One manifest per tool, for the newest published version of each."""
    return {name: manifest(items) for name, items in mirror.latest(history).items()}


def readme(names: Sequence[str]) -> str:
    installs = "\n".join(f"scoop install {BUCKET}/{name}" for name in names)
    return (
        "# Wimpy's World bucket\n\n"
        "Scoop manifests for the Windows builds of projects by Martin Wimpress.\n"
        f"See {PUBLIC['scoop'][1]}/ for details.\n\n"
        "```powershell\n"
        f"scoop bucket add {BUCKET} {PUBLIC['scoop'][1]}/{REPO}\n"
        f"{installs}\n"
        "```\n"
    )


def files(history: Sequence[AdmittedAsset]) -> dict[str, str]:
    """The bucket files: the README and one manifest per tool."""
    tools = manifests(history)
    return {"README.md": readme(list(tools)), **{f"bucket/{n}.json": t for n, t in tools.items()}}


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    if policy.format != "scoop":
        raise mirror.MirrorFailure("Expected the Scoop policy")
    mirror.validate_retained(retained, "scoop", REPO)


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
    """Copy new assets, then commit every manifest to the bucket. Scoop needs no signatures."""
    validate_retained(retained, policy=policy, runtime=runtime)
    return mirror.prepare(
        new,
        retained,
        form="scoop",
        root=REPO,
        files=files,
        message="Update manifests",
        runtime=runtime,
        now=now,
        out=out,
    )


def validate_prepared(prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    mirror.validate_prepared(prepared, "scoop", REPO)
