import io
import json
import re
import struct
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from haberdasher import discovery, site, state
from haberdasher.config import Config
from haberdasher.core import InspectedAsset, NativeIdentity, UnsupportedAsset
from haberdasher.formats import mirror, scoop
from haberdasher.runtime import Runtime, private_workspace
from tests.unit.test_brew import verified

POLICY = Config(("example/test",)).format_policy("scoop")
NOW = datetime(2026, 11, 11, 12, tzinfo=UTC)
AMD64, ARM64, I386 = 0x8664, 0xAA64, 0x14C


GUI, CONSOLE = 2, 3


def pe(
    machine: int = AMD64,
    *,
    characteristics: int = 0x0022,
    subsystem: int | None = None,
    tail: bytes = b"",
) -> bytes:
    """A DOS header that points at a PE signature, a COFF file header and the Subsystem field."""
    dos = b"MZ" + bytes(58) + struct.pack("<I", 64)
    coff = struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, 0, characteristics)
    optional = b"" if subsystem is None else bytes(68) + struct.pack("<H", subsystem)
    return dos + b"PE\0\0" + coff + optional + tail


def exe_zip(*members: tuple[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (pe(AMD64), "64bit"),
        (pe(ARM64), "arm64"),
        (pe(I386), "32bit"),
        (pe(0x1C4), ""),
        (pe(AMD64, characteristics=0x2022), ""),
        (pe(AMD64, characteristics=0x0020), ""),
        (pe(AMD64)[:70], ""),
        (b"MZ" + bytes(62), ""),
        (b"\x7fELF" + bytes(60), ""),
        (b"", ""),
    ],
)
def test_pe_architecture_comes_from_the_coff_header(header: bytes, expected: str) -> None:
    assert scoop.pe_architecture(header) == expected


def test_installers_carry_an_nsis_or_inno_setup_marker() -> None:
    assert scoop.installer(io.BytesIO(pe(tail=b"\xef\xbe\xad\xdeNullsoftInst")))
    assert scoop.installer(io.BytesIO(pe(tail=b"Inno Setup Setup Data (6.2.0)")))
    split = bytes(1024 * 1024 - 5) + b"NullsoftInst"
    assert scoop.installer(io.BytesIO(split))
    assert not scoop.installer(io.BytesIO(pe(tail=b"Nullsoft is a word")))


def test_zip_exe_finds_the_app_executable(tmp_path: Path) -> None:
    def check(data: bytes, app: str = "tool") -> tuple[str, str, bool]:
        path = tmp_path / "a.zip"
        path.write_bytes(data)
        return scoop.zip_exe(path, app)

    assert check(exe_zip(("tool.exe", pe()), ("README.md", b"x"))) == ("tool.exe", "64bit", False)
    assert check(exe_zip(("tool-1.0/bin/tool.EXE", pe(I386)))) == (
        "tool-1.0/bin/tool.EXE",
        "32bit",
        False,
    )
    assert check(exe_zip(("other.exe", pe()))) == ("other.exe", "64bit", False)
    assert check(exe_zip(("a.exe", pe()), ("b.exe", pe()))) == ("", "", False)
    assert check(exe_zip(("plugin.dll", pe()))) == ("", "", False)
    assert check(exe_zip(("setup.exe", pe(tail=b"NullsoftInst")))) == ("setup.exe", "", False)
    assert check(b"not a zip") == ("", "", False)


def test_zip_exe_picks_the_exe_named_after_the_app(tmp_path: Path) -> None:
    path = tmp_path / "Sidra-1.4.0-win-x64.zip"
    members = (
        ("Sidra.exe", pe(subsystem=GUI)),
        ("resources/elevate.exe", pe(subsystem=CONSOLE)),
        ("Squirrel.exe", pe(subsystem=GUI)),
    )
    path.write_bytes(exe_zip(*members))
    assert scoop.zip_exe(path, "sidra") == ("Sidra.exe", "64bit", True)
    path.write_bytes(exe_zip(*members[1:]))
    assert scoop.zip_exe(path, "Sidra") == ("", "", False)


@pytest.mark.parametrize(("subsystem", "expected"), [(GUI, True), (CONSOLE, False), (None, False)])
def test_pe_gui_comes_from_the_subsystem_field(subsystem: int | None, expected: bool) -> None:
    assert scoop.pe_gui(pe(subsystem=subsystem)) is expected


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("tailor-windows-amd64.exe", "scoop"),
        ("Sidra-1.3.0-win-x64.exe", "scoop"),
        ("critters-lsp-0.1.0-x86_64-pc-windows-msvc.zip", "scoop"),
        ("tailor_0.6.0_windows_arm64.zip", "scoop"),
        ("Sidra-1.3.0-mac-arm64.zip", "brew"),
        ("Template-0.1.2.zip", "brew"),
        ("winnow-darwin-arm64.zip", "brew"),
        ("Sidra-1.3.0-win-x64.exe.blockmap", None),
    ],
)
def test_asset_names_select_candidates(filename: str, expected: str | None) -> None:
    assert discovery.asset_format(filename) == expected


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("tailor-windows-amd64.exe", "tailor"),
        ("tailor_0.6.0_windows_arm64.zip", "tailor"),
        ("critters-lsp-0.1.0-x86_64-pc-windows-msvc.zip", "critters-lsp"),
        ("little-spy-v1.0.6-windows-x86_64.zip", "little-spy"),
        ("antsy-alien-attack-pico_windows.zip", "antsy-alien-attack-pico"),
        ("My_Tool.exe", "my-tool"),
        ("tool2fa-win64.exe", "tool2fa"),
    ],
)
def test_tool_name_is_the_asset_name_before_its_platform(filename: str, expected: str) -> None:
    assert scoop.tool(filename) == expected


def inspect(
    tmp_path: Path, filename: str, data: bytes, asset_id: int = 1, licence: str = "MIT"
) -> InspectedAsset:
    with patch.object(
        discovery, "release_details", return_value=("v0.6.0", "Ready-to-wear templates", licence)
    ):
        return scoop.inspect(
            verified(tmp_path, filename, data, asset_id),
            policy=POLICY,
            runtime=None,  # pyright: ignore[reportArgumentType]
            out=tmp_path / "out",
        )


def test_inspect_identifies_executables_and_zips(tmp_path: Path) -> None:
    item = inspect(tmp_path, "tailor-windows-amd64.exe", pe())
    assert item.identity == NativeIdentity("scoop", "tailor", "64bit", "0.6.0")
    assert item.metadata == {"desc": "Ready-to-wear templates", "license": "MIT"}
    data = exe_zip(("tailor/tailor.exe", pe(ARM64)))
    packed = inspect(tmp_path, "tailor_0.6.0_windows_arm64.zip", data, 2)
    assert packed.identity == NativeIdentity("scoop", "tailor", "arm64", "0.6.0")
    assert packed.metadata["exe"] == "tailor/tailor.exe"
    with pytest.raises(UnsupportedAsset, match="not a portable Windows executable"):
        inspect(tmp_path, "Sidra-1.3.0-win-x64.exe", pe(I386, tail=b"NullsoftInst"), 3)
    with pytest.raises(UnsupportedAsset, match="not a zip file of one .exe file"):
        inspect(tmp_path, "plugin-windows-x64.zip", exe_zip(("bin/p.dll", pe())), 4)
    data = exe_zip(("a.exe", pe()), ("b.exe", pe()))
    with pytest.raises(UnsupportedAsset, match="or of one App.exe file"):
        inspect(tmp_path, "App-1.0-win-x64.zip", data, 5)


def test_manifest_for_a_bare_executable(tmp_path: Path) -> None:
    item = inspect(tmp_path, "tailor-windows-amd64.exe", pe(), licence="Unknown")
    assert scoop.manifest([item]) == (
        "{\n"
        '    "version": "0.6.0",\n'
        '    "description": "Ready-to-wear templates",\n'
        '    "homepage": "https://github.com/wimpysworld/tailor",\n'
        '    "license": "Unknown",\n'
        '    "architecture": {\n'
        '        "64bit": {\n'
        '            "url": "https://scoop.wimpys.world/tailor/0.6.0/tailor-windows-amd64.exe",\n'
        f'            "hash": "{item.verified.sha256}",\n'
        '            "bin": [\n'
        "                [\n"
        '                    "tailor-windows-amd64.exe",\n'
        '                    "tailor"\n'
        "                ]\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}\n"
    )


def test_manifest_for_two_zips(tmp_path: Path) -> None:
    arm = inspect(tmp_path, "tool-1.0-windows-arm64.zip", exe_zip(("arm/tool.exe", pe(ARM64))), 1)
    x64 = inspect(tmp_path, "tool-1.0-windows-amd64.zip", exe_zip(("x64/tool.exe", pe())), 2)
    data = json.loads(scoop.manifest([arm, x64]))
    assert list(data) == ["version", "description", "homepage", "license", "architecture"]
    assert list(data["architecture"]) == ["64bit", "arm64"]
    assert data["architecture"]["64bit"] == {
        "url": "https://scoop.wimpys.world/tool/0.6.0/tool-1.0-windows-amd64.zip",
        "hash": x64.verified.sha256,
        "bin": [["x64/tool.exe", "tool"]],
    }
    assert data["architecture"]["arm64"]["bin"] == [["arm/tool.exe", "tool"]]


def test_manifest_gives_a_gui_app_a_shortcut(tmp_path: Path) -> None:
    data = exe_zip(("Sidra.exe", pe(subsystem=GUI)), ("Squirrel.exe", pe(subsystem=GUI)))
    item = inspect(tmp_path, "Sidra-1.4.0-win-x64.zip", data)
    assert item.metadata["shortcut"] == "Sidra"
    assert json.loads(scoop.manifest([item]))["architecture"]["64bit"] == {
        "url": "https://scoop.wimpys.world/sidra/0.6.0/Sidra-1.4.0-win-x64.zip",
        "hash": item.verified.sha256,
        "shortcuts": [["Sidra.exe", "Sidra"]],
    }
    console = inspect(tmp_path, "tool-windows-amd64.exe", pe(subsystem=CONSOLE), 2)
    assert "shortcut" not in console.metadata


def test_empty_page_shows_the_setup_command() -> None:
    page, _ = site.page(
        "scoop", state.unpublished("scoop"), fingerprint="A" * 40, fallback={}, now=NOW
    )
    text = re.sub(r"<[^>]+>", "", page.decode())
    assert "No Windows packages are published yet." in text
    assert "https://scoop.wimpys.world/wimpysworld/haberdasher.git" in text
    assert "scoop bucket rm haberdasher" in text
    apt, _ = site.page("apt", state.unpublished("apt"), fingerprint="A" * 40, fallback={}, now=NOW)
    assert 'href="https://scoop.wimpys.world/"' in apt.decode()


@pytest.fixture
def runtime() -> Iterator[Runtime]:
    with private_workspace() as value:
        yield value


def test_bucket_repository_first_later_and_unchanged_runs(runtime: Runtime) -> None:
    def run(
        files: dict[str, str], head: str | None, repo: Path | None, out: str
    ) -> tuple[str, Path]:
        objects = (
            {}
            if repo is None
            else {
                key: path
                for key, path in mirror.published_files(repo).items()
                if key not in mirror.ENTRIES
            }
        )
        return mirror.repository(
            objects, head, files, runtime=runtime, out=runtime.root / out, now=NOW, message="M"
        )

    files = {"README.md": "Bucket\n", "bucket/tailor.json": "{}\n"}
    head, repo = run(files, None, None, "a")
    first = {key: path.read_bytes() for key, path in mirror.published_files(repo).items()}
    tree = runtime.run(["git", f"--git-dir={repo}", "ls-tree", "-r", "--name-only", head])
    assert tree.stdout.decode().split() == ["README.md", "bucket/tailor.json"]

    same, again = run(files, head, repo, "b")
    assert same == head
    assert {key: path.read_bytes() for key, path in mirror.published_files(again).items()} == first

    later, repo = run({**files, "bucket/tool.json": "{}\n"}, head, again, "c")
    count = runtime.run(["git", f"--git-dir={repo}", "rev-list", "--count", later])
    assert later != head and count.stdout.decode().strip() == "2"
