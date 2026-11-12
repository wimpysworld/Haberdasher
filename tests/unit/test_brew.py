import hashlib
import plistlib
import struct
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from haberdasher import discovery
from haberdasher.config import Config
from haberdasher.core import (
    InspectedAsset,
    NativeIdentity,
    SourceAsset,
    UnsupportedAsset,
    VerifiedAsset,
)
from haberdasher.formats import brew, mirror
from haberdasher.runtime import Runtime, private_workspace

POLICY = Config(("example/test",)).format_policy("brew")
NOW = datetime(2026, 11, 11, 12, tzinfo=UTC)
ARM, INTEL = 0x0100000C, 0x01000007


def thin(cpu: int, *, big: bool = False, kind: int = 2) -> bytes:
    """A 64-bit Mach-O header: magic, CPU type, CPU subtype, and file type."""
    if big:
        return b"\xfe\xed\xfa\xcf" + struct.pack(">III", cpu, 0, kind) + bytes(16)
    return b"\xcf\xfa\xed\xfe" + struct.pack("<III", cpu, 0, kind) + bytes(16)


def fat(*cpus: int) -> bytes:
    slices = b"".join(struct.pack(">IIIII", cpu, 0, 4096, 32, 12) for cpu in cpus)
    return b"\xca\xfe\xba\xbe" + struct.pack(">I", len(cpus)) + slices


def app_zip(path: Path, app: str = "Sidra.app", header: bytes = thin(ARM)) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{app}/Contents/Info.plist", plistlib.dumps({"CFBundleExecutable": "X"}))
        archive.writestr(f"{app}/Contents/MacOS/X", header)
    return path


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (thin(ARM), ("arm",)),
        (thin(INTEL), ("intel",)),
        (thin(ARM, big=True), ("arm",)),
        (fat(INTEL, ARM), ("arm", "intel")),
        (fat(ARM, 7), ("arm",)),
        (thin(ARM, kind=6), ()),
        (thin(18), ()),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + bytes(64), ()),
        (b"\x7fELF" + bytes(60), ()),
        (b"", ()),
    ],
)
def test_macho_architectures_come_from_the_header(header: bytes, expected: tuple[str, ...]) -> None:
    assert brew.macho_architectures(header) == expected


def test_zip_app_reads_the_bundle_executable(tmp_path: Path) -> None:
    assert brew.zip_app(app_zip(tmp_path / "a.zip")) == ("Sidra.app", ("arm",))
    assert brew.zip_app(app_zip(tmp_path / "b.zip", header=fat(ARM, INTEL))) == (
        "Sidra.app",
        ("arm", "intel"),
    )
    two = app_zip(tmp_path / "c.zip")
    with zipfile.ZipFile(two, "a") as archive:
        archive.writestr("Other.app/Contents/Info.plist", b"")
    plain = tmp_path / "d.zip"
    with zipfile.ZipFile(plain, "w") as archive:
        archive.writestr("tool/readme.txt", b"text")
    (tmp_path / "e.zip").write_bytes(b"not a zip")
    for name in ("c.zip", "d.zip", "e.zip"):
        assert brew.zip_app(tmp_path / name) == ("", ())


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("tailor-darwin-arm64", "brew"),
        ("tailor_macos_universal", "brew"),
        ("Sidra-1.3.0-mac-arm64.zip", "brew"),
        ("tailor-linux-amd64", None),
        ("tailor_0.6.0_darwin_arm64.tar.gz", None),
        ("Sidra-1.3.0-mac-arm64.dmg", None),
        ("Sidra-1.3.0-mac-arm64.dmg.blockmap", None),
        ("latest-mac.yml", None),
        ("tailor.deb", "apt"),
    ],
)
def test_asset_names_select_candidates(filename: str, expected: str | None) -> None:
    assert discovery.asset_format(filename) == expected


def test_token_and_version_derivation() -> None:
    assert brew.token("tailor-darwin-arm64") == "tailor"
    assert brew.token("My_Tool-macos") == "my-tool"
    assert brew.token("Sidra-1.3.0-mac-arm64.zip", "Sidra.app") == "sidra"
    assert brew.token("x.zip", "Big App.app") == "big-app"
    assert brew.version("v0.6.0") == "0.6.0"
    assert brew.version("1.3.0") == "1.3.0"


def verified(tmp_path: Path, filename: str, data: bytes, asset_id: int = 1) -> VerifiedAsset:
    path = tmp_path / f"asset-{asset_id}"
    path.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    source = SourceAsset(
        "wimpysworld/tailor",
        7,
        asset_id,
        filename,
        len(data),
        "2026-01-01T00:00:00Z",
        f"https://github.com/wimpysworld/tailor/releases/download/v0.6.0/{filename}",
        sha,
    )
    return VerifiedAsset(source, path, sha, len(data), 99, "0" * 64)


def inspect(tmp_path: Path, filename: str, data: bytes, asset_id: int = 1) -> InspectedAsset:
    with (
        private_workspace(tmp_path) as runtime,
        patch.object(
            discovery,
            "release_details",
            return_value=("v0.6.0", 'Ready-to-wear "templates" #1', "MIT"),
        ),
    ):
        return brew.inspect(
            verified(tmp_path, filename, data, asset_id),
            policy=POLICY,
            runtime=runtime,
            out=tmp_path / "out",
        )


def test_inspect_identifies_binaries_and_apps(tmp_path: Path) -> None:
    item = inspect(tmp_path, "tailor-darwin-arm64", thin(ARM))
    assert item.identity == NativeIdentity("brew", "tailor", "arm", "0.6.0")
    assert item.metadata == {"desc": 'Ready-to-wear "templates" #1'}
    app = inspect(tmp_path, "Sidra-1.3.0-mac.zip", app_zip(tmp_path / "s.zip").read_bytes(), 2)
    assert app.identity == NativeIdentity("brew", "sidra", "arm", "0.6.0")
    assert app.metadata["app"] == "Sidra.app"
    with pytest.raises(UnsupportedAsset, match="not a macOS executable"):
        inspect(tmp_path, "tailor-darwin-arm64", b"\x7fELF" + bytes(60), 3)
    with pytest.raises(UnsupportedAsset, match="one macOS app"):
        inspect(tmp_path, "notes.zip", b"not a zip", 4)


def test_cask_with_both_architectures(tmp_path: Path) -> None:
    arm = inspect(tmp_path, "tailor-darwin-arm64", thin(ARM), 1)
    intel = inspect(tmp_path, "tailor-darwin-amd64", thin(INTEL), 2)
    text = brew.cask([arm, intel])
    assert text == (
        'cask "tailor" do\n'
        '  version "0.6.0"\n'
        "\n"
        "  on_arm do\n"
        f'    sha256 "{arm.verified.sha256}"\n'
        '    url "https://brew.wimpys.world/tailor/0.6.0/tailor-darwin-arm64"\n'
        "\n"
        '    binary "tailor-darwin-arm64", target: "tailor"\n'
        "  end\n"
        "  on_intel do\n"
        f'    sha256 "{intel.verified.sha256}"\n'
        '    url "https://brew.wimpys.world/tailor/0.6.0/tailor-darwin-amd64"\n'
        "\n"
        '    binary "tailor-darwin-amd64", target: "tailor"\n'
        "  end\n"
        "\n"
        '  name "tailor"\n'
        '  desc "Ready-to-wear \\"templates\\" \\#1"\n'
        '  homepage "https://github.com/wimpysworld/tailor"\n'
        "\n"
        "  postflight_steps do\n"
        '    run "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "{{staged_path}}"]\n'
        "  end\n"
        "end\n"
    )


def test_cask_with_one_architecture_and_an_app(tmp_path: Path) -> None:
    data = app_zip(tmp_path / "s.zip", header=thin(INTEL)).read_bytes()
    text = brew.cask([inspect(tmp_path, "Sidra 1.3.0.zip", data)])
    assert "  on_intel do\n" in text and "on_arm" not in text and "binary" not in text
    assert '    url "https://brew.wimpys.world/sidra/0.6.0/Sidra%201.3.0.zip"\n' in text
    assert '  name "Sidra"\n' in text
    assert text.endswith(
        '  homepage "https://github.com/wimpysworld/tailor"\n'
        "\n"
        "  depends_on arch: :intel\n"
        "\n"
        '  app "Sidra.app"\n'
        "\n"
        "  postflight_steps do\n"
        '    run "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "{{appdir}}/Sidra.app"]\n'
        "  end\n"
        "end\n"
    )


def test_cask_with_a_universal_binary(tmp_path: Path) -> None:
    text = brew.cask([inspect(tmp_path, "tailor-darwin-universal", fat(ARM, INTEL))])
    assert "on_" not in text and "depends_on" not in text
    assert '\n  binary "tailor-darwin-universal", target: "tailor"\n' in text
    assert text.index("homepage") < text.index("binary") < text.index("postflight_steps")


@pytest.fixture
def runtime(monkeypatch: pytest.MonkeyPatch) -> Iterator[Runtime]:
    monkeypatch.delenv("HABERDASHER_TOOL_PATH", raising=False)
    with private_workspace() as value:
        yield value


def objects(repo: Path) -> dict[str, Path]:
    files = mirror.published_files(repo).items()
    return {key: path for key, path in files if key not in mirror.ENTRIES}


def repository(
    objects: dict[str, Path], head: str | None, files: dict[str, str], runtime: Runtime, out: str
) -> tuple[str, Path]:
    return mirror.repository(
        objects, head, files, runtime=runtime, out=runtime.root / out, now=NOW, message="Update"
    )


def test_repository_first_run_later_commit_and_unchanged_run(runtime: Runtime) -> None:
    files = {"README.md": "Tap\n", "Casks/tailor.rb": "one\n"}
    head, repo = repository({}, None, files, runtime, "a")
    first = mirror.published_files(repo)
    assert list(first)[-4:] == list(mirror.ENTRIES)
    assert (repo / "HEAD").read_text() == "ref: refs/heads/main\n"
    assert (repo / "info/refs").read_text() == f"{head}\trefs/heads/main\n"
    log = runtime.run(["git", f"--git-dir={repo}", "log", "--format=%an <%ae> %P", "main"])
    assert log.stdout.decode() == "Haberdasher <code@wimpress.io> \n"

    same, again = repository(objects(repo), head, files, runtime, "b")
    assert same == head
    assert {key: path.read_bytes() for key, path in mirror.published_files(again).items()} == {
        key: path.read_bytes() for key, path in first.items()
    }

    changed = {**files, "Casks/tailor.rb": "two\n"}
    later, repo = repository(objects(repo), head, changed, runtime, "c")
    assert later != head
    parents = runtime.run(["git", f"--git-dir={repo}", "rev-list", "--parents", "-n1", later])
    assert parents.stdout.decode().split() == [later, head]
    assert set(first) - {"info/refs", "refs/heads/main"} <= set(mirror.published_files(repo))
