"""Namespace and cardinality checks against metadata from native RPM tools."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from types import ModuleType

import pytest

REPO = "{http://linux.duke.edu/metadata/repo}"
COMMON = "{http://linux.duke.edu/metadata/common}"
RPM = "{http://linux.duke.edu/metadata/rpm}"
FILELISTS = "{http://linux.duke.edu/metadata/filelists}"
OTHER = "{http://linux.duke.edu/metadata/other}"


@pytest.fixture(scope="module")
def helper() -> ModuleType:
    path = Path(__file__).parents[1] / "proofs/rpm/metadata.py"
    spec = importlib.util.spec_from_file_location("rpm_metadata_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def native_repository(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    if not all(shutil.which(tool) for tool in ("rpmbuild", "createrepo_c")):
        pytest.skip("native RPM tools are required")
    work = tmp_path_factory.mktemp("rpm-metadata")
    home = work / "home"
    home.mkdir()
    build = work / "build"
    repository = work / "repository"
    repository.mkdir()
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "TMPDIR": str(work), "LC_ALL": "C"}
    spec = work / "fixture.spec"
    spec.write_text("""Name: hd-proof-app
Version: 1
Release: 1
Summary: Disposable RPM metadata fixture
License: MIT
BuildArch: noarch
AutoReqProv: no
Requires: hd-proof-data = 1-1
Requires: /opt/hd-proof/hd-proof-data
%description
Disposable metadata fixture.
%install
mkdir -p %{buildroot}/opt/hd-proof
printf 'fixture\\n' > %{buildroot}/opt/hd-proof/hd-proof-app
printf 'extra\\n' > %{buildroot}/opt/hd-proof/hd-proof-app-extra
%files
/opt/hd-proof/hd-proof-app
/opt/hd-proof/hd-proof-app-extra
%changelog
* Wed Jun 17 2026 Proof <proof@invalid> - 1-1
- Fixture payload metadata test.
* Tue Jun 16 2026 Proof <proof@invalid> - 0-1
- Fixture payload earlier version.
""")
    subprocess.run(
        [
            "rpmbuild",
            "--define",
            f"_topdir {build}",
            "--define",
            f"_tmppath {work}",
            "--define",
            "__os_install_post %{nil}",
            "--define",
            "_build_id_links none",
            "-bb",
            str(spec),
        ],
        env=env,
        check=True,
        capture_output=True,
    )
    package = repository / "hd-proof-app-1-1.noarch.rpm"
    shutil.copyfile(build / "RPMS/noarch" / package.name, package)
    subprocess.run(
        [
            "createrepo_c",
            "--general-compress-type",
            "gz",
            "--checksum",
            "sha256",
            "--no-database",
            str(repository),
        ],
        env=env,
        check=True,
        capture_output=True,
    )
    checksum = hashlib.sha256(package.read_bytes()).hexdigest()
    inventory = work / "inventory"
    inventory.write_text(f"hd-proof-app|0|1|1|noarch\t{checksum}\t{checksum}\t{package.name}\n")
    return repository, inventory


def test_native_metadata(helper: ModuleType, native_repository: tuple[Path, Path]) -> None:
    snapshot = helper.snapshot(*native_repository)
    assert set(snapshot) == {"primary", "filelists", "other"}
    assert all(set(packages) == {"hd-proof-app|0|1|1|noarch"} for packages in snapshot.values())
    _, records = helper.documents(native_repository[0])
    assert len(records["filelists"][2].findall(f"{FILELISTS}package/{FILELISTS}file")) == 2
    assert len(records["other"][2].findall(f"{OTHER}package/{OTHER}changelog")) == 2
    requires = records["primary"][2].findall(
        f"{COMMON}package/{COMMON}format/{RPM}requires/{RPM}entry"
    )
    assert len(requires) >= 2


def write_document(helper: ModuleType, repository: Path, kind: str, document: ET.Element) -> None:
    repomd, records = helper.documents(repository)
    if kind == "repomd":
        repomd = ET.ElementTree(document)
    else:
        entry, metadata_path, _ = records[kind]
        opened = ET.tostring(document)
        raw = gzip.compress(opened, mtime=0)
        metadata_path.write_bytes(raw)
        for field, value in (
            ("checksum", hashlib.sha256(raw).hexdigest()),
            ("open-checksum", hashlib.sha256(opened).hexdigest()),
            ("size", str(len(raw))),
            ("open-size", str(len(opened))),
        ):
            helper.child(entry, f"{REPO}{field}").text = value
    repomd.write(repository / "repodata/repomd.xml", encoding="utf-8", xml_declaration=True)


TARGETS = [
    ("repomd", "."),
    ("primary", "."),
    ("filelists", "."),
    ("other", "."),
    ("repomd", f"{REPO}data"),
    *(
        ("repomd", f"{REPO}data/{REPO}{field}")
        for field in ("location", "checksum", "size", "open-checksum", "open-size")
    ),
    ("primary", f"{COMMON}package"),
    *(
        ("primary", f"{COMMON}package/{COMMON}{field}")
        for field in ("name", "arch", "version", "checksum", "location", "format")
    ),
    ("primary", f"{COMMON}package/{COMMON}format/{RPM}requires"),
    ("primary", f"{COMMON}package/{COMMON}format/{RPM}requires/{RPM}entry"),
    ("filelists", f"{FILELISTS}package"),
    ("filelists", f"{FILELISTS}package/{FILELISTS}version"),
    ("filelists", f"{FILELISTS}package/{FILELISTS}file"),
    ("other", f"{OTHER}package"),
    ("other", f"{OTHER}package/{OTHER}version"),
    ("other", f"{OTHER}package/{OTHER}changelog"),
]


@pytest.mark.parametrize(("kind", "path"), TARGETS)
@pytest.mark.parametrize("namespace", ["", "{urn:wrong}"])
def test_wrong_namespace_rejected(
    helper: ModuleType,
    native_repository: tuple[Path, Path],
    tmp_path: Path,
    kind: str,
    path: str,
    namespace: str,
) -> None:
    source, inventory = native_repository
    repository = tmp_path / "repository"
    shutil.copytree(source, repository)
    repomd, records = helper.documents(repository)
    document = repomd.getroot() if kind == "repomd" else records[kind][2]
    elements = document.findall(path)
    assert elements
    for element in elements:
        element.tag = namespace + element.tag.rsplit("}", 1)[-1]
    write_document(helper, repository, kind, document)
    with pytest.raises(AssertionError):
        helper.snapshot(repository, inventory)


DUPLICATE_TARGETS = [
    *(
        ("repomd", f"{REPO}data[@type='{kind}']", f"{REPO}{field}")
        for kind in ("primary", "filelists", "other")
        for field in ("location", "checksum", "size", "open-checksum", "open-size")
    ),
    *(
        ("primary", f"{COMMON}package", f"{COMMON}{field}")
        for field in ("name", "arch", "version", "checksum", "location", "format")
    ),
    ("primary", f"{COMMON}package/{COMMON}format", f"{RPM}requires"),
    ("filelists", f"{FILELISTS}package", f"{FILELISTS}version"),
    ("other", f"{OTHER}package", f"{OTHER}version"),
]


@pytest.mark.parametrize(("kind", "parent_path", "tag"), DUPLICATE_TARGETS)
def test_duplicate_scalar_rejected(
    helper: ModuleType,
    native_repository: tuple[Path, Path],
    tmp_path: Path,
    kind: str,
    parent_path: str,
    tag: str,
) -> None:
    source, inventory = native_repository
    repository = tmp_path / "repository"
    shutil.copytree(source, repository)
    repomd, records = helper.documents(repository)
    document = repomd.getroot() if kind == "repomd" else records[kind][2]
    parent = document.find(parent_path)
    assert parent is not None
    original = parent.find(tag)
    assert original is not None
    duplicate = ET.SubElement(parent, tag, {key: "conflict" for key in original.attrib})
    duplicate.text = "conflict"
    write_document(helper, repository, kind, document)
    with pytest.raises(AssertionError, match="expected one XML element"):
        helper.snapshot(repository, inventory)
