#!/usr/bin/env python3
"""Create and check data-only Flatpak fixtures."""

import gzip
import hashlib
import json
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path


def png(size):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    pixels = (b"\0" + b"\x28\x80\xb0\xff" * size) * size
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


def fixture(root, app, runtime, arch, version):
    root = Path(root)
    files = root / "files"
    (files / "share/applications").mkdir(parents=True)
    (files / "share/app-info/xmls").mkdir(parents=True)
    (root / "metadata").write_text(
        f"[Application]\nname={app}\nruntime={runtime}/{arch}/stable\nsdk={runtime}/{arch}/stable\n"
        f"[Context]\nshared=\n[Instance]\nversion={version}\n")
    (files / "version").write_text(version + "\n")
    (files / "share/applications" / f"{app}.desktop").write_text(
        f"[Desktop Entry]\nType=Application\nName=Haberdasher Proof\nExec=not-executable\nIcon={app}\n")
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<components version="0.8"><component type="desktop-application">
<id>{app}</id><name>Haberdasher Proof</name><summary>Local data only proof</summary>
<metadata_license>CC0-1.0</metadata_license><project_license>CC0-1.0</project_license>
<launchable type="desktop-id">{app}.desktop</launchable>
<icon type="cached" width="64" height="64">{app}.png</icon>
<icon type="cached" width="128" height="128">{app}.png</icon>
<releases><release version="{version}" timestamp="1700000000"/></releases>
<bundle type="flatpak">app/{app}/{arch}/stable</bundle>
</component></components>'''
    (files / "share/app-info/xmls" / f"{app}.xml.gz").write_bytes(gzip.compress(xml.encode(), mtime=0))
    for size in (64, 128):
        directory = files / f"share/app-info/icons/flatpak/{size}x{size}"
        directory.mkdir(parents=True)
        (directory / f"{app}.png").write_bytes(png(size))


def catalogue(root, app, version):
    root = Path(root)
    xml = ET.fromstring(gzip.decompress((root / "appstream.xml.gz").read_bytes()))
    components = [c for c in xml.findall("component") if c.findtext("id") in (app, app + ".desktop")]
    assert len(components) == 1, "Missing or duplicate catalogue entry"
    release = components[0].find("releases/release")
    assert release is not None and release.get("version") == version, "Wrong catalogue version"
    for size in (64, 128):
        icon = root / f"icons/{size}x{size}/{app}.png"
        data = icon.read_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        assert struct.unpack(">II", data[16:24]) == (size, size)
    print(f"Catalogue: {app} version={version} icons=64,128")


def inventory(root):
    root = Path(root)
    entries = {str(p.relative_to(root)): {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "bytes": p.stat().st_size}
               for p in sorted(root.rglob("*")) if p.is_file()}
    print(json.dumps(entries, indent=2, sort_keys=True))


def signature(source, target):
    values = re.findall(r"0x([0-9a-f]{2})", Path(source).read_text())
    assert values, "Native GVariant output contains no signature bytes"
    Path(target).write_bytes(bytes(int(value, 16) for value in values))


if __name__ == "__main__":
    {"fixture": fixture, "catalogue": catalogue, "inventory": inventory,
     "signature": signature}[sys.argv[1]](*sys.argv[2:])
