#!/usr/bin/env python3
"""Check retained RPM metadata without opening historical packages."""

import gzip
import hashlib
import json
import sys
import xml.etree.ElementTree as ET  # nosec B405 - locally generated fixtures only
from pathlib import Path

REPO = "{http://linux.duke.edu/metadata/repo}"
COMMON = "{http://linux.duke.edu/metadata/common}"
RPM = "{http://linux.duke.edu/metadata/rpm}"
NAMESPACES = {
    "primary": COMMON,
    "filelists": "{http://linux.duke.edu/metadata/filelists}",
    "other": "{http://linux.duke.edu/metadata/other}",
}
TYPES = ("primary", "filelists", "other")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def child(element, tag):
    result = element.find(tag)
    assert result is not None, f"missing XML element: {tag}"
    return result


def text(element, tag):
    result = child(element, tag).text
    assert result is not None, f"empty XML element: {tag}"
    return result


def identity(package, kind):
    version = child(package, f"{NAMESPACES[kind]}version")
    name = text(package, f"{COMMON}name") if kind == "primary" else package.attrib["name"]
    arch = text(package, f"{COMMON}arch") if kind == "primary" else package.attrib["arch"]
    return "|".join((name, str(int(version.attrib.get("epoch", "0"))),
                     version.attrib["ver"], version.attrib["rel"], arch))


def semantic(element):
    return [element.tag, sorted(element.attrib.items()), (element.text or "").strip(),
            sorted((semantic(child) for child in element), key=repr)]


def documents(directory):
    root = Path(directory)
    repomd = ET.parse(root / "repodata/repomd.xml")  # noqa: S314 - local fixture
    assert repomd.getroot().tag == f"{REPO}repomd", "invalid repomd root"
    records = {}
    for entry in repomd.getroot().findall(f"{REPO}data"):
        kind = entry.attrib["type"]
        if kind not in TYPES:
            continue
        assert kind not in records, f"duplicate {kind}"
        relative = Path(child(entry, f"{REPO}location").attrib["href"])
        assert not relative.is_absolute() and ".." not in relative.parts
        path = root / relative
        raw = path.read_bytes()
        checksum = child(entry, f"{REPO}checksum")
        assert checksum.attrib["type"] == "sha256"
        assert digest(raw) == checksum.text, f"{kind} checksum mismatch"
        assert len(raw) == int(text(entry, f"{REPO}size"))
        opened = gzip.decompress(raw)
        checksum = child(entry, f"{REPO}open-checksum")
        assert checksum.attrib["type"] == "sha256"
        assert digest(opened) == checksum.text, f"{kind} open checksum mismatch"
        assert len(opened) == int(text(entry, f"{REPO}open-size"))
        document = ET.fromstring(opened)  # noqa: S314 - locally generated fixture
        namespace = NAMESPACES[kind]
        root_name = {
            "primary": "metadata", "filelists": "filelists", "other": "otherdata"
        }[kind]
        assert document.tag == f"{namespace}{root_name}", f"invalid {kind} root"
        assert all(package.tag == f"{namespace}package" for package in document)
        assert int(document.attrib["packages"]) == len(document)
        records[kind] = (entry, path, document)
    assert set(records) == set(TYPES), "missing retained XML type"
    return repomd, records


def snapshot(directory, inventory):
    _, records = documents(directory)
    expected = {}
    for line in Path(inventory).read_text().splitlines():
        key, source, published, location = line.split("\t")
        assert key not in expected, "duplicate inventory identity"
        assert len(source) == len(published) == 64
        expected[key] = (published, location)
    result = {}
    for kind, (_, _, document) in records.items():
        packages = {}
        for package in document:
            key = identity(package, kind)
            assert key not in packages, f"duplicate {kind} identity"
            assert key in expected, f"unexpected {kind} identity: {key}"
            if kind == "primary":
                checksum = child(package, f"{COMMON}checksum")
                assert checksum.attrib["type"] == "sha256"
                assert checksum.text == expected[key][0], "package checksum mismatch"
                assert child(package, f"{COMMON}location").attrib["href"] == expected[key][1]
                if key.startswith("hd-proof-app|"):
                    requires = child(package, f"{COMMON}format/{RPM}requires")
                    assert all(entry.tag == f"{RPM}entry" for entry in requires)
                    names = {entry.attrib["name"] for entry in requires}
                    assert {"hd-proof-data", "/opt/hd-proof/hd-proof-data"} <= names
            else:
                assert package.attrib["pkgid"] == expected[key][0]
                if kind == "filelists":
                    assert text(package, f"{NAMESPACES[kind]}file") == f"/opt/hd-proof/{package.attrib['name']}"
                else:
                    assert text(package, f"{NAMESPACES[kind]}changelog").startswith("- Fixture payload ")
            packages[key] = semantic(package)
        assert set(packages) == set(expected), f"incomplete {kind} inventory"
        result[kind] = packages
    return result


def damage(directory, kind, mode):
    repomd, records = documents(directory)
    entry, path, document = records[kind]
    if mode == "missing":
        path.unlink()
    elif mode == "corrupt":
        path.write_bytes(b"corrupt retained XML\n")
    else:
        if mode == "incomplete":
            document.remove(document[0])
            document.set("packages", str(len(document)))
            opened = ET.tostring(document)
        elif mode == "malformed":
            opened = b"<broken>"
        else:
            raise ValueError(mode)
        raw = gzip.compress(opened, mtime=0)
        path.write_bytes(raw)
        for field, value in (("checksum", digest(raw)), ("open-checksum", digest(opened)),
                             ("size", str(len(raw))), ("open-size", str(len(opened)))):
            child(entry, f"{REPO}{field}").text = value
        repomd.write(Path(directory) / "repodata/repomd.xml", encoding="utf-8", xml_declaration=True)


def main():
    command, *args = sys.argv[1:]
    if command == "snapshot":
        print(json.dumps(snapshot(*args), sort_keys=True))
    elif command == "compare":
        before, after = (json.loads(Path(path).read_text()) for path in args)
        for kind in TYPES:
            for key, value in before[kind].items():
                assert after[kind][key] == value, f"changed historical {kind}: {key}"
    elif command == "damage":
        damage(*args)
    else:
        raise ValueError(command)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError, ET.ParseError) as error:
        sys.exit(f"metadata rejected: {error}")
