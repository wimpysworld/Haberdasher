"""Trusted, data-only Flatpak bundles and a separate synthetic runtime provider."""

from __future__ import annotations

import gzip
import shutil
import struct
import zlib
from pathlib import Path

from haberdasher.core import SourceAsset, VerifiedAsset, sha256_file
from haberdasher.runtime import Runtime

APP = "world.wimpress.HaberdasherTest"
RUNTIME = "world.wimpress.HaberdasherRuntime"
ARCH = "x86_64"
REF = f"app/{APP}/{ARCH}/stable"
RREF = f"runtime/{RUNTIME}/{ARCH}/stable"
EXTENSION = RUNTIME + ".Extension"
EREF = f"runtime/{EXTENSION}/{ARCH}/stable"


def mime_directory() -> Path:
    command = shutil.which("update-mime-database")
    if command is None:
        raise RuntimeError("Pinned shared-mime-info is required")
    directory = Path(command).resolve().parent.parent / "share"
    if not (directory / "mime/mime.cache").is_file():
        raise RuntimeError("Pinned MIME database is missing")
    return directory


def run(runtime: Runtime, *argv: str) -> bytes:
    result = runtime.run(["env", f"XDG_DATA_DIRS={mime_directory()}", *argv])
    if result.returncode:
        raise RuntimeError(f"Fixture command failed: {argv}: {result.stderr.decode()}")
    return result.stdout


def png(size: int) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    pixels = (b"\0" + b"\x28\x80\xb0\xff" * size) * size
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(pixels))
        + chunk(b"IEND", b"")
    )


def bundle(runtime: Runtime, root: Path, version: str, number: int) -> VerifiedAsset:
    tree = root / f"app-{number}"
    files = tree / "files"
    (files / "share/applications").mkdir(parents=True)
    (files / "share/app-info/xmls").mkdir(parents=True)
    (tree / "metadata").write_text(
        f"[Application]\nname={APP}\nruntime={RUNTIME}/{ARCH}/stable\n"
        f"sdk={RUNTIME}/{ARCH}/stable\n[Context]\nshared=\n"
        "[Instance]\nversion=not-the-native-version\n"
    )
    (files / "version").write_text(version + "\n")
    (files / "share/applications" / f"{APP}.desktop").write_text(
        f"[Desktop Entry]\nType=Application\nName=Haberdasher Test\nExec=not-executable\nIcon={APP}\n"
    )
    xml = f'''<components version="0.8"><component type="desktop-application">
<id>{APP}</id><name>Haberdasher Test</name><summary>Local data only test</summary>
<metadata_license>CC0-1.0</metadata_license><project_license>CC0-1.0</project_license>
<launchable type="desktop-id">{APP}.desktop</launchable>
<icon type="cached" width="64" height="64">{APP}.png</icon>
<icon type="cached" width="128" height="128">{APP}.png</icon>
<releases><release version="{version}" timestamp="1700000000"/></releases>
<bundle type="flatpak">{REF}</bundle></component></components>'''
    (files / "share/app-info/xmls" / f"{APP}.xml.gz").write_bytes(
        gzip.compress(xml.encode(), mtime=0)
    )
    for size in (64, 128):
        directory = files / f"share/app-info/icons/flatpak/{size}x{size}"
        directory.mkdir(parents=True)
        (directory / f"{APP}.png").write_bytes(png(size))
    source = root / "source"
    target = root / f"app-{number}.flatpak"
    run(runtime, "flatpak", "build-finish", str(tree))
    run(runtime, "flatpak", "build-export", "--no-update-summary", str(source), str(tree), "stable")
    run(
        runtime,
        "flatpak",
        "build-bundle",
        f"--arch={ARCH}",
        str(source),
        str(target),
        APP,
        "stable",
    )
    sha, size = sha256_file(target)
    return VerifiedAsset(
        SourceAsset(
            "wimpysworld/fixture",
            number,
            number,
            target.name,
            size,
            "2026-01-01T00:00:00Z",
            f"https://example.invalid/{target.name}",
        ),
        target,
        sha,
        size,
        number + 100,
        "a" * 64,
    )


def runtime_repo(runtime: Runtime, root: Path, fingerprint: str, home: Path) -> tuple[str, str]:
    tree = root / "runtime-tree"
    (tree / "usr").mkdir(parents=True)
    (tree / "files").mkdir()
    (tree / "metadata").write_text(
        f"[Runtime]\nname={RUNTIME}\nruntime={RUNTIME}/{ARCH}/stable\nsdk={RUNTIME}/{ARCH}/stable\n"
        f"[Extension {EXTENSION}]\ndirectory=extensions/test\nversion=stable\n"
        "no-autodownload=false\n"
    )
    (tree / "usr/runtime-version").write_text("1\n")
    repo = root / "runtime-repo"
    sign = (f"--gpg-sign={fingerprint}!", f"--gpg-homedir={home}")
    run(
        runtime,
        "flatpak",
        "build-export",
        "--runtime",
        "--no-update-summary",
        *sign,
        str(repo),
        str(tree),
        "stable",
    )
    extension = root / "extension-tree"
    (extension / "usr").mkdir(parents=True)
    (extension / "files").mkdir()
    (extension / "metadata").write_text(
        f"[Runtime]\nname={EXTENSION}\n[ExtensionOf]\nref={RREF}\nruntime={RUNTIME}/{ARCH}/stable\n"
    )
    (extension / "files/extension-version").write_text("1\n")
    run(
        runtime,
        "flatpak",
        "build-export",
        "--runtime",
        "--no-update-summary",
        *sign,
        str(repo),
        str(extension),
        "stable",
    )
    run(runtime, "flatpak", "build-update-repo", *sign, str(repo))
    return (
        run(runtime, "ostree", f"--repo={repo}", "rev-parse", RREF).decode().strip(),
        run(runtime, "ostree", f"--repo={repo}", "rev-parse", EREF).decode().strip(),
    )
