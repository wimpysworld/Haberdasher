from __future__ import annotations

import base64
import hashlib
import io
import json
import plistlib
import shutil
import struct
import subprocess
import tarfile
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from haberdasher import discovery
from haberdasher.config import Config
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    JSONValue,
    NativeIdentity,
    ObjectRef,
    OutputObject,
    PreparedFormat,
    RetainedFormat,
    SourceAsset,
    UnsupportedAsset,
    VerifiedAsset,
    atomic_write,
    sha256_file,
)
from haberdasher.formats import nix
from haberdasher.formats.nix import (
    CACHE_INFO,
    CACHE_INFO_KEY,
    IMMUTABLE,
    PUBKEY_KEY,
    REPO,
    NixFailure,
)
from haberdasher.runtime import private_workspace
from haberdasher.signing import NIX_KEY_NAME, SigningSession
from tests.unit.test_brew import ARM, INTEL, fat, thin

POLICY = Config(("wimpysworld/tailor",)).format_policy("nix")
PUB_VALUE = f"{NIX_KEY_NAME}:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
FINGERPRINT = "A" * 40
HEAD = "a" * 40


def elf64(machine: int = 0x3E, *, dynamic: bool = False, e_type: int = 2) -> bytes:
    """Build a synthetic 64-bit little-endian ELF executable header with optional PT_INTERP."""
    phnum = 1 if dynamic else 0
    phoff = 64 if dynamic else 0
    header = (
        b"\x7fELF\x02\x01\x01"
        + bytes(9)
        + struct.pack(
            "<HHIQQQIHHHHHH",
            e_type,
            machine,
            1,
            0x400000,
            phoff,
            0,
            0,
            64,
            56,
            phnum,
            0,
            0,
            0,
        )
    )
    if not dynamic:
        return header
    p_type = 3  # PT_INTERP
    phdr = struct.pack("<IIQQQQQQ", p_type, 4, 0, 0, 0, 0, 0, 1)
    return header + phdr


def tar_gz(*members: tuple[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def verified_asset(
    tmp_path: Path,
    filename: str,
    data: bytes,
    *,
    repository: str = "wimpysworld/tailor",
    tag: str = "v0.6.0",
    asset_id: int = 1,
) -> VerifiedAsset:
    path = tmp_path / f"asset-{asset_id}-{filename}"
    path.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    source = SourceAsset(
        repository,
        7,
        asset_id,
        filename,
        len(data),
        "2026-01-01T00:00:00Z",
        f"https://github.com/{repository}/releases/download/{tag}/{filename}",
        sha,
    )
    return VerifiedAsset(source, path, sha, len(data), 99, "0" * 64)


def sri_hash(sha256_hex: str) -> str:
    return "sha256-" + base64.b64encode(bytes.fromhex(sha256_hex)).decode("ascii")


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (elf64(0x3E, dynamic=False), ("x86_64-linux", False)),
        (elf64(0x3E, dynamic=True), ("x86_64-linux", True)),
        (elf64(0xB7, dynamic=True, e_type=3), ("aarch64-linux", True)),
        (elf64(0x3E, e_type=1), ("", False)),
        (elf64(0x03), ("", False)),
        (b"not-an-elf", ("", False)),
    ],
)
def test_elf_binary_detects_architecture_and_pt_interp(
    data: bytes, expected: tuple[str, bool]
) -> None:
    assert nix.elf_binary(data) == expected


def test_darwin_systems_maps_macho_headers() -> None:
    assert nix.darwin_systems(thin(ARM)) == ("aarch64-darwin",)
    assert nix.darwin_systems(thin(INTEL)) == ("x86_64-darwin",)
    assert nix.darwin_systems(fat(ARM, INTEL)) == ("aarch64-darwin", "x86_64-darwin")


def test_inspect_tarball_static_dynamic_and_macho(tmp_path: Path) -> None:
    with (
        private_workspace(tmp_path) as runtime,
        patch.object(discovery, "release_details", return_value=("v0.6.0", "Fast tool", "MIT")),
        patch.object(discovery, "tag_nix_files", return_value=None),
    ):
        static_tar = tar_gz(("tailor", elf64(0x3E, dynamic=False)), ("README.md", b"docs"))
        static_item = nix.inspect(
            verified_asset(tmp_path, "tailor_0.6.0_linux_x86_64.tar.gz", static_tar, asset_id=1),
            policy=POLICY,
            runtime=runtime,
            out=tmp_path / "out-1",
        )
        assert static_item.identity == NativeIdentity("nix", "tailor", "x86_64-linux", "0.6.0")
        assert static_item.metadata == {
            "mode": "tarball",
            "desc": "Fast tool",
            "license": "MIT",
            "binary": "tailor",
            "dynamic_elf": False,
        }
        static_expr, static_sys = nix._tarball_nix([static_item])  # pyright: ignore[reportPrivateUsage]
        assert static_sys == ("x86_64-linux",)
        assert "stdenvNoCC" in static_expr
        assert "dynamic = false;" in static_expr and "dynamic = true;" not in static_expr

        dyn_tar = tar_gz(("bin/tailor", elf64(0xB7, dynamic=True)))
        dyn_item = nix.inspect(
            verified_asset(tmp_path, "tailor_0.6.0_linux_arm64.tar.gz", dyn_tar, asset_id=2),
            policy=POLICY,
            runtime=runtime,
            out=tmp_path / "out-2",
        )
        assert dyn_item.identity == NativeIdentity("nix", "tailor", "aarch64-linux", "0.6.0")
        assert dyn_item.metadata["dynamic_elf"] is True
        dyn_expr, _ = nix._tarball_nix([dyn_item])  # pyright: ignore[reportPrivateUsage]
        assert "dynamic = true;" in dyn_expr
        assert "autoPatchelfHook" in dyn_expr and "stdenv.cc.cc.lib" in dyn_expr

        mac_tar = tar_gz(("tailor", fat(ARM, INTEL)))
        mac_item = nix.inspect(
            verified_asset(tmp_path, "tailor_0.6.0_darwin_arm64.tar.gz", mac_tar, asset_id=3),
            policy=POLICY,
            runtime=runtime,
            out=tmp_path / "out-3",
        )
        assert mac_item.identity == NativeIdentity("nix", "tailor", "aarch64-darwin", "0.6.0")
        assert mac_item.metadata["universal"] is True
        _, mac_sys = nix._tarball_nix([mac_item])  # pyright: ignore[reportPrivateUsage]
        assert mac_sys == ("x86_64-darwin", "aarch64-darwin")

        empty_tar = tar_gz(("README.md", b"only docs"))
        with pytest.raises(UnsupportedAsset, match="no single supported"):
            nix.inspect(
                verified_asset(tmp_path, "tailor_0.6.0_linux_x86_64.tar.gz", empty_tar, asset_id=4),
                policy=POLICY,
                runtime=runtime,
                out=tmp_path / "out-4",
            )


def test_inspect_upstream_nix_rewrites_stale_tag_hashes_and_rejects_unreferenced(
    tmp_path: Path,
) -> None:
    stale_linux = "sha256-59b0f813bf7ef5e2c4da4b5e9a3fb33ee82ad49c7bc644fa4e83a19b264e32a1"
    stale_darwin = "sha256-bf20810ca11e1d498bf00c11b0c9f085dc48ec94d5bc543d0f9b10862e39a409"
    upstream_files = {
        "flake.nix": '{ description = "Sidra"; outputs = _: {}; }\n',
        "nix/linux.nix": (
            "{\n"
            "  lib,\n"
            "  stdenv,\n"
            "  fetchurl,\n"
            '  version ? "1.2.1",\n'
            "}:\n"
            "let\n"
            '  pname = "sidra";\n'
            "  sources = {\n"
            "    x86_64-linux = {\n"
            '      url = "https://github.com/wimpysworld/sidra/releases/download/1.3.0/Sidra-1.3.0-linux-amd64.deb";\n'
            f'      hash = "{stale_linux}";\n'
            "    };\n"
            "  };\n"
            "in\n"
            "stdenv.mkDerivation { inherit pname version; }\n"
        ),
        "nix/darwin.nix": (
            "{\n"
            "  lib,\n"
            "  stdenvNoCC,\n"
            "  fetchurl,\n"
            '  version ? "1.2.1",\n'
            "}:\n"
            "stdenvNoCC.mkDerivation {\n"
            '  pname = "sidra";\n'
            "  inherit version;\n"
            "  src = fetchurl {\n"
            '    url = "https://github.com/wimpysworld/sidra/releases/download/1.3.0/Sidra-1.3.0-mac-arm64.dmg";\n'
            f'      hash = "{stale_darwin}";\n'
            "  };\n"
            '  meta = { platforms = [ "aarch64-darwin" ]; };\n'
            "}\n"
        ),
    }
    deb_asset = verified_asset(
        tmp_path,
        "Sidra-1.3.0-linux-amd64.deb",
        b"sidra-1.3.0-deb-bytes",
        repository="wimpysworld/sidra",
        tag="1.3.0",
        asset_id=10,
    )
    dmg_asset = verified_asset(
        tmp_path,
        "Sidra-1.3.0-mac-arm64.dmg",
        b"sidra-1.3.0-dmg-bytes",
        repository="wimpysworld/sidra",
        tag="1.3.0",
        asset_id=11,
    )
    unreferenced = verified_asset(
        tmp_path,
        "Sidra-1.3.0-mac-arm64.zip",
        b"sidra-1.3.0-zip-bytes",
        repository="wimpysworld/sidra",
        tag="1.3.0",
        asset_id=12,
    )
    with (
        private_workspace(tmp_path) as runtime,
        patch.object(discovery, "release_details", return_value=("1.3.0", "Sidra desktop", "MIT")),
        patch.object(discovery, "tag_nix_files", return_value=upstream_files),
    ):
        inspected_deb = nix.inspect(deb_asset, policy=POLICY, runtime=runtime, out=tmp_path / "o1")
        inspected_dmg = nix.inspect(dmg_asset, policy=POLICY, runtime=runtime, out=tmp_path / "o2")
        assert inspected_deb.identity == NativeIdentity("nix", "sidra", "x86_64-linux", "1.3.0")
        assert inspected_dmg.identity == NativeIdentity("nix", "sidra", "aarch64-darwin", "1.3.0")
        assert inspected_deb.metadata["mode"] == "upstream-nix"
        with pytest.raises(UnsupportedAsset, match="not referenced"):
            nix.inspect(unreferenced, policy=POLICY, runtime=runtime, out=tmp_path / "o3")

    pkg_files, systems = nix._rewrite_upstream_nix([inspected_deb, inspected_dmg])  # pyright: ignore[reportPrivateUsage]
    assert systems == ("x86_64-linux", "aarch64-darwin")
    assert stale_linux not in pkg_files["pkgs/sidra/linux.nix"]
    assert stale_darwin not in pkg_files["pkgs/sidra/darwin.nix"]
    assert sri_hash(deb_asset.sha256) in pkg_files["pkgs/sidra/linux.nix"]
    assert sri_hash(dmg_asset.sha256) in pkg_files["pkgs/sidra/darwin.nix"]
    assert deb_asset.source.public_url in pkg_files["pkgs/sidra/linux.nix"]
    assert dmg_asset.source.public_url in pkg_files["pkgs/sidra/darwin.nix"]
    assert 'version = "1.3.0";' in pkg_files["pkgs/sidra/default.nix"]
    assert (
        "if stdenv.hostPlatform.isDarwin then call ./darwin.nix else call ./linux.nix"
        in (pkg_files["pkgs/sidra/default.nix"])
    )


@pytest.mark.parametrize(
    "platforms_expr",
    [
        '[ "aarch64-darwin" "x86_64-darwin" ]',
        "lib.platforms.darwin",
    ],
)
def test_inspect_upstream_nix_universal_darwin_dmg(tmp_path: Path, platforms_expr: str) -> None:
    stale_darwin = "sha256-bf20810ca11e1d498bf00c11b0c9f085dc48ec94d5bc543d0f9b10862e39a409"
    upstream_files = {
        "flake.nix": '{ description = "Sidra"; outputs = _: {}; }\n',
        "nix/darwin.nix": (
            "{\n"
            "  lib,\n"
            "  stdenvNoCC,\n"
            "  fetchurl,\n"
            '  version ? "1.2.1",\n'
            "}:\n"
            "stdenvNoCC.mkDerivation {\n"
            '  pname = "sidra";\n'
            "  inherit version;\n"
            "  src = fetchurl {\n"
            '    url = "https://github.com/wimpysworld/sidra/releases/download/${version}/Sidra-${version}-mac-universal.dmg";\n'
            f'    hash = "{stale_darwin}";\n'
            "  };\n"
            f"  meta = {{ platforms = {platforms_expr}; }};\n"
            "}\n"
        ),
    }
    dmg_asset = verified_asset(
        tmp_path,
        "Sidra-1.3.0-mac-universal.dmg",
        b"sidra-1.3.0-universal-dmg-bytes",
        repository="wimpysworld/sidra",
        tag="1.3.0",
        asset_id=15,
    )
    with (
        private_workspace(tmp_path) as runtime,
        patch.object(discovery, "release_details", return_value=("1.3.0", "Sidra desktop", "MIT")),
        patch.object(discovery, "tag_nix_files", return_value=upstream_files),
    ):
        inspected_dmg = nix.inspect(dmg_asset, policy=POLICY, runtime=runtime, out=tmp_path / "ou")

    assert inspected_dmg.identity == NativeIdentity("nix", "sidra", "aarch64-darwin", "1.3.0")
    assert inspected_dmg.metadata["universal"] is True
    assert nix._item_systems(inspected_dmg) == ("aarch64-darwin", "x86_64-darwin")  # pyright: ignore[reportPrivateUsage]

    pkg_files, systems = nix._rewrite_upstream_nix([inspected_dmg])  # pyright: ignore[reportPrivateUsage]
    assert systems == ("x86_64-darwin", "aarch64-darwin")
    assert stale_darwin not in pkg_files["pkgs/sidra/darwin.nix"]
    assert sri_hash(dmg_asset.sha256) in pkg_files["pkgs/sidra/darwin.nix"]
    flake_text = nix._flake_nix({"sidra": systems}, "github:NixOS/nixpkgs/nixos-unstable")  # pyright: ignore[reportPrivateUsage]
    assert "x86_64-darwin =" in flake_text
    assert "aarch64-darwin =" in flake_text


@pytest.mark.parametrize("fetchurl_binding", [False, True])
def test_upstream_nix_omits_unmatched_files_strips_unmatched_systems_and_guards_overlay(
    tmp_path: Path, fetchurl_binding: bool
) -> None:
    stale_amd64 = "sha256-59b0f813bf7ef5e2c4da4b5e9a3fb33ee82ad49c7bc644fa4e83a19b264e32a1"
    stale_arm64 = "sha256-1111111111111111111111111111111111111111111111111111111111111111"
    stale_darwin = "sha256-bf20810ca11e1d498bf00c11b0c9f085dc48ec94d5bc543d0f9b10862e39a409"
    amd64_url = (
        "https://github.com/wimpysworld/sidra/releases/download/1.3.0/Sidra-1.3.0-linux-amd64.deb"
    )
    arm64_url = (
        "https://github.com/wimpysworld/sidra/releases/download/1.3.0/Sidra-1.3.0-linux-arm64.deb"
    )
    darwin_url = (
        "https://github.com/wimpysworld/sidra/releases/download/1.3.0/Sidra-1.3.0-mac-arm64.dmg"
    )
    if fetchurl_binding:
        sources_block = (
            "  sources = {\n"
            "    x86_64-linux = fetchurl {\n"
            f'      url = "{amd64_url}";\n'
            f'      hash = "{stale_amd64}";\n'
            "    };\n"
            "    aarch64-linux = fetchurl {\n"
            f'      url = "{arm64_url}";\n'
            f'      hash = "{stale_arm64}";\n'
            "    };\n"
            "  };\n"
        )
        src_expr = "sources.${stdenv.hostPlatform.system}"
    else:
        sources_block = (
            "  sources = {\n"
            "    x86_64-linux = {\n"
            f'      url = "{amd64_url}";\n'
            f'      hash = "{stale_amd64}";\n'
            "    };\n"
            "    aarch64-linux = {\n"
            f'      url = "{arm64_url}";\n'
            f'      hash = "{stale_arm64}";\n'
            "    };\n"
            "  };\n"
        )
        src_expr = "fetchurl sources.${stdenv.hostPlatform.system}"
    upstream_files = {
        "flake.nix": '{ description = "Sidra"; outputs = _: {}; }\n',
        "nix/default.nix": "{ callPackage }: callPackage ./darwin.nix { }\n",
        "nix/linux.nix": (
            "{\n"
            "  lib,\n"
            "  stdenv,\n"
            "  fetchurl,\n"
            '  version ? "1.2.1",\n'
            "}:\n"
            "let\n"
            '  pname = "sidra";\n' + sources_block + "in\n"
            f"stdenv.mkDerivation {{ inherit pname version; src = {src_expr}; }}\n"
        ),
        "nix/darwin.nix": (
            "{\n"
            "  lib,\n"
            "  stdenvNoCC,\n"
            "  fetchurl,\n"
            '  version ? "1.2.1",\n'
            "}:\n"
            "stdenvNoCC.mkDerivation {\n"
            '  pname = "sidra";\n'
            "  inherit version;\n"
            "  src = fetchurl {\n"
            f'    url = "{darwin_url}";\n'
            f'    hash = "{stale_darwin}";\n'
            "  };\n"
            '  meta = { platforms = [ "aarch64-darwin" ]; };\n'
            "}\n"
        ),
    }
    deb_asset = verified_asset(
        tmp_path,
        "Sidra-1.3.0-linux-amd64.deb",
        b"sidra-1.3.0-deb-only-bytes",
        repository="wimpysworld/sidra",
        tag="1.3.0",
        asset_id=60,
    )
    with (
        private_workspace(tmp_path) as runtime,
        patch.object(discovery, "release_details", return_value=("1.3.0", "Sidra desktop", "MIT")),
        patch.object(discovery, "tag_nix_files", return_value=upstream_files),
    ):
        inspected_deb = nix.inspect(
            deb_asset, policy=POLICY, runtime=runtime, out=tmp_path / "out-deb-only"
        )
        pkg_files, systems = nix._rewrite_upstream_nix([inspected_deb])  # pyright: ignore[reportPrivateUsage]
        assert systems == ("x86_64-linux",)
        assert set(pkg_files) == {"pkgs/sidra/linux.nix", "pkgs/sidra/default.nix"}
        assert "pkgs/sidra/darwin.nix" not in pkg_files
        assert "pkgs/sidra/upstream.nix" not in pkg_files
        assert "./darwin.nix" not in pkg_files["pkgs/sidra/default.nix"]
        assert "call ./linux.nix" in pkg_files["pkgs/sidra/default.nix"]

        linux_out = pkg_files["pkgs/sidra/linux.nix"]
        assert sri_hash(deb_asset.sha256) in linux_out
        assert amd64_url in linux_out
        assert "aarch64-linux" not in linux_out
        assert arm64_url not in linux_out
        for text in pkg_files.values():
            assert stale_amd64 not in text
            assert stale_arm64 not in text
            assert stale_darwin not in text
            assert darwin_url not in text

        flake_text = nix._flake_nix({"sidra": systems}, "github:NixOS/nixpkgs/nixos-unstable")  # pyright: ignore[reportPrivateUsage]
        repo_dir = tmp_path / "flake-eval"
        for rel, content in {**pkg_files, "flake.nix": flake_text}.items():
            target = repo_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(target, content.encode("utf-8"))
        nix_paths = [str(repo_dir / rel) for rel in sorted({*pkg_files, "flake.nix"})]
        fmt = runtime.run(["nixfmt", *nix_paths])
        assert fmt.returncode == 0, fmt.stderr.decode(errors="replace")

        if shutil.which("nix-instantiate", path=runtime.environment["PATH"]) is None:
            return
        eval_expr = (
            "let\n"
            f"  flake = import {repo_dir / 'flake.nix'};\n"
            "  outputs = flake.outputs { nixpkgs = null; };\n"
            "  mkPkgs = system:\n"
            "    let\n"
            "      lib = {\n"
            "        optionalAttrs = cond: attrs: if cond then attrs else { };\n"
            "      };\n"
            "      stdenv = {\n"
            "        hostPlatform = {\n"
            "          inherit system;\n"
            '          isDarwin = builtins.elem system [ "x86_64-darwin" "aarch64-darwin" ];\n'
            "        };\n"
            "        mkDerivation = attrs: attrs;\n"
            "      };\n"
            "      base = rec {\n"
            "        inherit lib stdenv;\n"
            "        fetchurl = { url, hash }: { inherit url hash; };\n"
            "        callPackage = fn: extra:\n"
            "          let f = if builtins.isFunction fn then fn else import fn;\n"
            "          in f ((builtins.intersectAttrs (builtins.functionArgs f) base) // extra);\n"
            "      };\n"
            "      final = base // (outputs.overlays.default final base);\n"
            "    in\n"
            "    final;\n"
            '  linuxPkgs = mkPkgs "x86_64-linux";\n'
            '  armPkgs = mkPkgs "aarch64-linux";\n'
            '  darwinPkgs = mkPkgs "aarch64-darwin";\n'
            "in\n"
            "{\n"
            "  linuxHasSidra = linuxPkgs ? sidra;\n"
            "  linuxSrc = linuxPkgs.sidra.src;\n"
            "  armHasSidra = armPkgs ? sidra;\n"
            "  darwinHasSidra = darwinPkgs ? sidra;\n"
            "  directDarwinRejected = !(builtins.tryEval (darwinPkgs.callPackage "
            f"{repo_dir / 'pkgs/sidra/default.nix'} {{ }})).success;\n"
            "}\n"
        )
        res = runtime.run(
            ["nix-instantiate", "--readonly-mode", "--eval", "--strict", "--json", "-E", eval_expr]
        )
        assert res.returncode == 0, res.stderr.decode(errors="replace")
        evaluated = json.loads(res.stdout)
        assert evaluated == {
            "linuxHasSidra": True,
            "linuxSrc": {"url": amd64_url, "hash": sri_hash(deb_asset.sha256)},
            "armHasSidra": False,
            "darwinHasSidra": False,
            "directDarwinRejected": True,
        }


def test_upstream_nix_rejects_unremovable_unmatched_fetchurl_block(tmp_path: Path) -> None:
    stale_amd64 = "sha256-59b0f813bf7ef5e2c4da4b5e9a3fb33ee82ad49c7bc644fa4e83a19b264e32a1"
    stale_extra = "sha256-2222222222222222222222222222222222222222222222222222222222222222"
    upstream_files = {
        "flake.nix": '{ description = "Sidra"; outputs = _: {}; }\n',
        "nix/linux.nix": (
            "{\n"
            "  lib,\n"
            "  stdenv,\n"
            "  fetchurl,\n"
            '  version ? "1.2.1",\n'
            "}:\n"
            "stdenv.mkDerivation {\n"
            '  pname = "sidra";\n'
            "  inherit version;\n"
            "  src =\n"
            '    if stdenv.hostPlatform.system == "x86_64-linux" then\n'
            "      fetchurl {\n"
            '        url = "https://github.com/wimpysworld/sidra/releases/download/1.3.0/Sidra-1.3.0-linux-amd64.deb";\n'
            f'        hash = "{stale_amd64}";\n'
            "      }\n"
            "    else\n"
            "      fetchurl {\n"
            '        url = "https://github.com/wimpysworld/sidra/releases/download/1.3.0/Sidra-1.3.0-linux-arm64.deb";\n'
            f'        hash = "{stale_extra}";\n'
            "      };\n"
            '  meta = { platforms = [ "x86_64-linux" "aarch64-linux" ]; };\n'
            "}\n"
        ),
    }
    deb_asset = verified_asset(
        tmp_path,
        "Sidra-1.3.0-linux-amd64.deb",
        b"sidra-1.3.0-deb-bytes",
        repository="wimpysworld/sidra",
        tag="1.3.0",
        asset_id=61,
    )
    with (
        private_workspace(tmp_path) as runtime,
        patch.object(discovery, "release_details", return_value=("1.3.0", "Sidra desktop", "MIT")),
        patch.object(discovery, "tag_nix_files", return_value=upstream_files),
    ):
        inspected_deb = nix.inspect(deb_asset, policy=POLICY, runtime=runtime, out=tmp_path / "o61")
        with pytest.raises(NixFailure, match="Unmatched fetchurl block"):
            nix._rewrite_upstream_nix([inspected_deb])  # pyright: ignore[reportPrivateUsage]


def test_inspect_deb_and_zip_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fsys_bytes = io.BytesIO()
    with tarfile.open(fileobj=fsys_bytes, mode="w") as archive:
        payload = elf64(0x3E, dynamic=True)
        info = tarfile.TarInfo("./usr/bin/tool")
        info.size = len(payload)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(payload))

    with private_workspace(tmp_path) as runtime:

        def fake_run(
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            input: bytes | None = None,
            timeout: float = 120,
            env_kind: str = "native",
            progress: Callable[[str], None] | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[0] == "gpgconf":
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[:2] == ["dpkg-deb", "-f"]:
                control = (
                    b"Package: tool\nVersion: 1:1.4.0-1\nArchitecture: amd64\n"
                    b"Description: Fallback DEB tool\n"
                )
                return subprocess.CompletedProcess(argv, 0, control, b"")
            assert argv[:2] == ["dpkg-deb", "--fsys-tarfile"]
            return subprocess.CompletedProcess(argv, 0, fsys_bytes.getvalue(), b"")

        monkeypatch.setattr(runtime, "run", fake_run)
        with (
            patch.object(discovery, "release_details", return_value=("v1.4.0", "", "GPL-3.0-only")),
            patch.object(discovery, "tag_nix_files", return_value=None),
        ):
            deb_item = nix.inspect(
                verified_asset(tmp_path, "tool_1.4.0_amd64.deb", b"deb", asset_id=20),
                policy=POLICY,
                runtime=runtime,
                out=tmp_path / "deb-out",
            )
            assert deb_item.identity == NativeIdentity("nix", "tool", "x86_64-linux", "1.4.0")
            assert deb_item.metadata == {
                "mode": "deb",
                "desc": "Fallback DEB tool",
                "license": "GPL-3.0-only",
                "dynamic_elf": True,
            }
            zip_path = tmp_path / "app.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr(
                    "Tool.app/Contents/Info.plist",
                    plistlib.dumps({"CFBundleExecutable": "ToolBin"}),
                )
                zf.writestr("Tool.app/Contents/MacOS/ToolBin", thin(ARM))
            zip_item = nix.inspect(
                verified_asset(
                    tmp_path, "Tool-1.4.0-mac-arm64.zip", zip_path.read_bytes(), asset_id=21
                ),
                policy=POLICY,
                runtime=runtime,
                out=tmp_path / "zip-out",
            )
            assert zip_item.identity == NativeIdentity("nix", "tool", "aarch64-darwin", "1.4.0")
            assert zip_item.metadata == {
                "mode": "zip",
                "desc": "",
                "license": "GPL-3.0-only",
                "app": "Tool.app",
                "executable": "ToolBin",
            }
            expr, systems = nix._fallback_nix([deb_item, zip_item])  # pyright: ignore[reportPrivateUsage]
            assert systems == ("x86_64-linux", "aarch64-darwin")
            assert "autoPatchelfHook" in expr and "makeWrapper" in expr
            assert "lib.licenses.gpl3Only" in expr

            with pytest.raises(UnsupportedAsset, match="macOS disk images require"):
                nix.inspect(
                    verified_asset(tmp_path, "Tool-1.4.0.dmg", b"dmg", asset_id=22),
                    policy=POLICY,
                    runtime=runtime,
                    out=tmp_path / "dmg-out",
                )


def test_generated_install_phases_escape_shell_metacharacters(tmp_path: Path) -> None:
    weird_bin = "-$(touch pwned) \"quote\" `uname` 'single' ${bad}/tailor"
    weird_exe = "Tool \"$(touch pwned)\" `uname` 'single' ${bad}"
    with (
        private_workspace(tmp_path) as runtime,
        patch.object(discovery, "release_details", return_value=("v1.4.0", "", "MIT")),
        patch.object(discovery, "tag_nix_files", return_value=None),
    ):
        tar_data = tar_gz((weird_bin, elf64(0x3E, dynamic=False)))
        tar_item = nix.inspect(
            verified_asset(tmp_path, "tailor_1.4.0_linux_x86_64.tar.gz", tar_data, asset_id=30),
            policy=POLICY,
            runtime=runtime,
            out=tmp_path / "tar-weird",
        )
        tar_expr, _ = nix._tarball_nix([tar_item])  # pyright: ignore[reportPrivateUsage]
        assert 'install -Dm755 -- ${lib.escapeShellArg source.bin} "$out/bin/tailor"' in tar_expr
        assert '"${source.bin}"' not in tar_expr

        zip_path = tmp_path / "weird.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(
                "Tool.app/Contents/Info.plist",
                plistlib.dumps({"CFBundleExecutable": weird_exe}),
            )
            zf.writestr(f"Tool.app/Contents/MacOS/{weird_exe}", thin(ARM))
        zip_item = nix.inspect(
            verified_asset(
                tmp_path, "Tool-1.4.0-mac-arm64.zip", zip_path.read_bytes(), asset_id=31
            ),
            policy=POLICY,
            runtime=runtime,
            out=tmp_path / "zip-weird",
        )
        zip_item_weird_app = replace(
            zip_item,
            metadata={**zip_item.metadata, "app": "-Tool \"$(touch pwned)\" `uname` 's'.app"},
        )
        zip_expr, _ = nix._fallback_nix([zip_item_weird_app])  # pyright: ignore[reportPrivateUsage]
        assert 'cp -R -- ${lib.escapeShellArg source.app} "$out/Applications/"' in zip_expr
        assert (
            'makeWrapper "$out/Applications/"'
            '${lib.escapeShellArg "${source.app}/Contents/MacOS/${source.exe}"} '
            '"$out/bin/tool"' in zip_expr
        )
        assert '"${source.app}"' not in zip_expr
        assert '"$out/Applications/${source.app}/Contents/MacOS/${source.exe}"' not in zip_expr
        for expr in (tar_expr, zip_expr):
            parsed = runtime.run(["nix-instantiate", "--parse", "-"], input=expr.encode("utf-8"))
            assert parsed.returncode == 0, parsed.stderr.decode(errors="replace")


def test_inspect_deb_rejects_library_only_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fsys_bytes = io.BytesIO()
    with tarfile.open(fileobj=fsys_bytes, mode="w") as archive:
        lib_payload = elf64(0x3E, dynamic=True, e_type=3)
        lib_info = tarfile.TarInfo("./usr/lib/libfoo.so.1")
        lib_info.size = len(lib_payload)
        lib_info.mode = 0o755
        archive.addfile(lib_info, io.BytesIO(lib_payload))
        doc_payload = b"Copyright\n"
        doc_info = tarfile.TarInfo("./usr/share/doc/libfoo1/copyright")
        doc_info.size = len(doc_payload)
        doc_info.mode = 0o644
        archive.addfile(doc_info, io.BytesIO(doc_payload))

    with private_workspace(tmp_path) as runtime:

        def fake_run(
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            input: bytes | None = None,
            timeout: float = 120,
            env_kind: str = "native",
            progress: Callable[[str], None] | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[0] == "gpgconf":
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[:2] == ["dpkg-deb", "-f"]:
                control = (
                    b"Package: libfoo1\nVersion: 1.0.0-1\nArchitecture: amd64\n"
                    b"Description: Shared library only\n"
                )
                return subprocess.CompletedProcess(argv, 0, control, b"")
            assert argv[:2] == ["dpkg-deb", "--fsys-tarfile"]
            return subprocess.CompletedProcess(argv, 0, fsys_bytes.getvalue(), b"")

        monkeypatch.setattr(runtime, "run", fake_run)
        with (
            patch.object(discovery, "release_details", return_value=("v1.0.0", "", "MIT")),
            patch.object(discovery, "tag_nix_files", return_value=None),
            pytest.raises(UnsupportedAsset, match="DEB contains no executable program"),
        ):
            nix.inspect(
                verified_asset(tmp_path, "libfoo1_1.0.0_amd64.deb", b"deb", asset_id=23),
                policy=POLICY,
                runtime=runtime,
                out=tmp_path / "lib-out",
            )


def test_compare_and_validate_retained_and_prepared(tmp_path: Path) -> None:
    with private_workspace(tmp_path) as runtime:
        left = NativeIdentity("nix", "tailor", "x86_64-linux", "0.6.0")
        same = NativeIdentity("nix", "tailor", "x86_64-linux", "0.6.0")
        diff = NativeIdentity("nix", "tailor", "x86_64-linux", "0.7.0")
        assert nix.compare(left, same, runtime=runtime) == 0
        assert nix.compare(left, diff, runtime=runtime) is None

        empty = RetainedFormat("nix", (), (), {}, ())
        nix.validate_retained(empty, policy=POLICY, runtime=runtime)
        nix.validate_prepared(PreparedFormat("nix", empty, (), ()), policy=POLICY, runtime=runtime)

        v_asset = verified_asset(
            tmp_path, "tailor_0.6.0_linux_x86_64.tar.gz", tar_gz(("tailor", elf64()))
        )
        admitted = AdmittedAsset(
            InspectedAsset(
                v_asset,
                left,
                {"mode": "tarball", "binary": "tailor", "dynamic_elf": False},
                {},
                "unsigned",
            ),
            "preserve",
            v_asset.sha256,
        )
        nar_key = f"nar/{'0' * 52}.nar.zst"
        narinfo_key = f"{'0' * 32}.narinfo"
        git_obj_key = f"{REPO}/objects/aa/{'b' * 38}"
        git_tag_key = f"{REPO}/refs/tags/{HEAD}"
        file_payloads: dict[str, bytes] = {
            nar_key: b"zstd-nar",
            narinfo_key: b"StorePath: /nix/store/00000000000000000000000000000000-tailor\n",
            PUBKEY_KEY: f"{PUB_VALUE}\n".encode(),
            git_obj_key: b"git-object",
            git_tag_key: f"{HEAD}\n".encode(),
            CACHE_INFO_KEY: CACHE_INFO,
            f"{REPO}/info/refs": f"{HEAD}\trefs/heads/main\n".encode(),
            f"{REPO}/objects/info/packs": b"\n",
            f"{REPO}/refs/heads/main": f"{HEAD}\n".encode(),
            f"{REPO}/HEAD": b"ref: refs/heads/main\n",
        }
        paths: dict[str, Path] = {}
        refs: list[ObjectRef] = []
        outputs: list[OutputObject] = []
        ordered_keys = sorted(
            file_payloads,
            key=lambda key: (nix._classify(key)[3], key),  # pyright: ignore[reportPrivateUsage]
        )
        for ordinal, key in enumerate(ordered_keys):
            p = tmp_path / "staged" / key
            p.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(p, file_payloads[key])
            paths[key] = p
            kind, ctype, mutable, _ = nix._classify(key)  # pyright: ignore[reportPrivateUsage]
            sha, size = sha256_file(p)
            ref = ObjectRef(
                "nix", key, kind, size, sha, ctype, "no-cache" if mutable else IMMUTABLE
            )
            refs.append(ref)
            outputs.append(OutputObject(ref, p, "create", None, ordinal))

        working_files: dict[str, JSONValue] = {
            key: str(paths[key]) for key in ordered_keys if key not in {nar_key, narinfo_key}
        }
        retained = RetainedFormat(
            "nix",
            (admitted,),
            (left,),
            {
                "head": HEAD,
                "files": working_files,
                "public_key": PUB_VALUE,
                "fingerprint": FINGERPRINT,
                "flake_lock": {"version": 7, "nodes": {}},
            },
            tuple(refs),
        )
        nix.validate_retained(retained, policy=POLICY, runtime=runtime)
        prepared = PreparedFormat("nix", retained, tuple(outputs), retained.objects)
        nix.validate_prepared(prepared, policy=POLICY, runtime=runtime)

        # Out-of-order outputs (entry before package) must fail validate_prepared
        reversed_outputs = tuple(
            replace(out, ordinal=idx) for idx, out in enumerate(reversed(outputs))
        )
        with pytest.raises(NixFailure, match="publication order"):
            nix.validate_prepared(
                PreparedFormat("nix", retained, reversed_outputs, retained.objects),
                policy=POLICY,
                runtime=runtime,
            )

        # Tampered nix-cache-info content must fail validate_retained
        atomic_write(paths[CACHE_INFO_KEY], b"StoreDir: /nix/store\nPriority: 99\n")
        bad_sha, bad_size = sha256_file(paths[CACHE_INFO_KEY])
        bad_refs = tuple(
            replace(r, sha256=bad_sha, size=bad_size) if r.key == CACHE_INFO_KEY else r
            for r in refs
        )
        with pytest.raises(NixFailure, match="nix-cache-info"):
            nix.validate_retained(
                replace(retained, objects=bad_refs), policy=POLICY, runtime=runtime
            )


def test_per_system_derivation_invariance_when_sibling_systems_added(tmp_path: Path) -> None:
    with private_workspace(tmp_path) as runtime:
        tar_x86_static = InspectedAsset(
            verified_asset(
                tmp_path,
                "tailor_0.6.0_linux_x86_64.tar.gz",
                tar_gz(("tailor", elf64(0x3E, dynamic=False))),
                asset_id=40,
            ),
            NativeIdentity("nix", "tailor", "x86_64-linux", "0.6.0"),
            {
                "mode": "tarball",
                "desc": "Fast tool",
                "license": "MIT",
                "binary": "tailor",
                "dynamic_elf": False,
            },
            {},
            "unsigned",
        )
        tar_x86_dynamic = replace(
            tar_x86_static,
            metadata={**tar_x86_static.metadata, "dynamic_elf": True},
        )
        tar_arm_dynamic = InspectedAsset(
            verified_asset(
                tmp_path,
                "tailor_0.6.0_linux_arm64.tar.gz",
                tar_gz(("tailor", elf64(0xB7, dynamic=True))),
                asset_id=41,
            ),
            NativeIdentity("nix", "tailor", "aarch64-linux", "0.6.0"),
            {
                "mode": "tarball",
                "desc": "Fast tool",
                "license": "MIT",
                "binary": "tailor",
                "dynamic_elf": True,
            },
            {},
            "unsigned",
        )
        tar_arm_static = replace(
            tar_arm_dynamic,
            metadata={**tar_arm_dynamic.metadata, "dynamic_elf": False},
        )
        tar_mac_universal = InspectedAsset(
            verified_asset(
                tmp_path,
                "tailor_0.6.0_darwin_all.tar.gz",
                tar_gz(("tailor", fat(ARM, INTEL))),
                asset_id=42,
            ),
            NativeIdentity("nix", "tailor", "aarch64-darwin", "0.6.0"),
            {
                "mode": "tarball",
                "desc": "Fast tool",
                "license": "MIT",
                "binary": "tailor",
                "dynamic_elf": False,
                "universal": True,
            },
            {},
            "unsigned",
        )

        deb_x86_dynamic = InspectedAsset(
            verified_asset(tmp_path, "tool_1.4.0_amd64.deb", b"deb-x86", asset_id=50),
            NativeIdentity("nix", "tool", "x86_64-linux", "1.4.0"),
            {
                "mode": "deb",
                "desc": "Fallback DEB tool",
                "license": "GPL-3.0-only",
                "dynamic_elf": True,
            },
            {},
            "unsigned",
        )
        deb_x86_static = replace(
            deb_x86_dynamic,
            metadata={**deb_x86_dynamic.metadata, "dynamic_elf": False},
        )
        deb_arm_static = InspectedAsset(
            verified_asset(tmp_path, "tool_1.4.0_arm64.deb", b"deb-arm", asset_id=51),
            NativeIdentity("nix", "tool", "aarch64-linux", "1.4.0"),
            {
                "mode": "deb",
                "desc": "Fallback DEB tool",
                "license": "GPL-3.0-only",
                "dynamic_elf": False,
            },
            {},
            "unsigned",
        )
        deb_arm_dynamic = replace(
            deb_arm_static,
            metadata={**deb_arm_static.metadata, "dynamic_elf": True},
        )
        zip_mac = InspectedAsset(
            verified_asset(tmp_path, "Tool-1.4.0-mac-arm64.zip", b"zip-mac", asset_id=52),
            NativeIdentity("nix", "tool", "aarch64-darwin", "1.4.0"),
            {
                "mode": "zip",
                "desc": "",
                "license": "GPL-3.0-only",
                "app": "Tool.app",
                "executable": "ToolBin",
            },
            {},
            "unsigned",
        )

        tar_solo_static, _ = nix._tarball_nix([tar_x86_static])  # pyright: ignore[reportPrivateUsage]
        tar_multi_static, _ = nix._tarball_nix(  # pyright: ignore[reportPrivateUsage]
            [tar_x86_static, tar_arm_dynamic, tar_mac_universal]
        )
        tar_solo_dyn, _ = nix._tarball_nix([tar_x86_dynamic])  # pyright: ignore[reportPrivateUsage]
        tar_multi_dyn, _ = nix._tarball_nix(  # pyright: ignore[reportPrivateUsage]
            [tar_x86_dynamic, tar_arm_static, tar_mac_universal]
        )
        fb_solo_dyn, _ = nix._fallback_nix([deb_x86_dynamic])  # pyright: ignore[reportPrivateUsage]
        fb_multi_dyn, _ = nix._fallback_nix(  # pyright: ignore[reportPrivateUsage]
            [deb_x86_dynamic, deb_arm_static, zip_mac]
        )
        fb_solo_static, _ = nix._fallback_nix([deb_x86_static])  # pyright: ignore[reportPrivateUsage]
        fb_multi_static, _ = nix._fallback_nix(  # pyright: ignore[reportPrivateUsage]
            [deb_x86_static, deb_arm_dynamic, zip_mac]
        )
        fb_solo_zip, _ = nix._fallback_nix([zip_mac])  # pyright: ignore[reportPrivateUsage]

        expr_files: dict[str, Path] = {}
        for idx, (label, expr) in enumerate(
            [
                ("tar_solo_static", tar_solo_static),
                ("tar_multi_static", tar_multi_static),
                ("tar_solo_dyn", tar_solo_dyn),
                ("tar_multi_dyn", tar_multi_dyn),
                ("fb_solo_dyn", fb_solo_dyn),
                ("fb_multi_dyn", fb_multi_dyn),
                ("fb_solo_static", fb_solo_static),
                ("fb_multi_static", fb_multi_static),
                ("fb_solo_zip", fb_solo_zip),
            ]
        ):
            expr_path = tmp_path / f"expr-{idx}-{label}.nix"
            atomic_write(expr_path, expr.encode("utf-8"))
            fmt = runtime.run(["nixfmt", str(expr_path)])
            assert fmt.returncode == 0, fmt.stderr.decode(errors="replace")
            expr_files[label] = expr_path

        tool_path = runtime.environment["PATH"]
        if shutil.which("nix-instantiate", path=tool_path) is None:
            return

        harness = (
            "let\n"
            "  evalInputs = file: system:\n"
            "    let\n"
            "      fn = import file;\n"
            "      lib = {\n"
            "        optionals = cond: xs: if cond then xs else [ ];\n"
            "        escapeShellArg = s:\n"
            """          "'${builtins.replaceStrings [ "'" ] [ "'\\\\''" ] (toString s)}'";\n"""
            '        getExe\' = pkg: prog: "${pkg}/bin/${prog}";\n'
            "        licenses = {\n"
            '          mit = "mit";\n'
            '          gpl3Only = "gpl3Only";\n'
            "        };\n"
            '        sourceTypes.binaryNativeCode = "binaryNativeCode";\n'
            "      };\n"
            "      mkStdenv = name: {\n"
            "        inherit name;\n"
            "        hostPlatform = {\n"
            "          inherit system;\n"
            '          isLinux = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];\n'
            '          isDarwin = builtins.elem system [ "x86_64-darwin" "aarch64-darwin" ];\n'
            "        };\n"
            '        cc.cc.lib = "gcc-lib-${system}";\n'
            '        mkDerivation = attrs: (removeAttrs attrs [ "meta" ]) // { builder = name; };\n'
            "      };\n"
            "      pool = {\n"
            "        inherit lib;\n"
            "        fetchurl = { url, hash }: { inherit url hash; };\n"
            '        stdenv = mkStdenv "stdenv";\n'
            '        stdenvNoCC = mkStdenv "stdenvNoCC";\n'
            '        bintools = "bintools-${system}";\n'
            '        gnutar = "gnutar-${system}";\n'
            '        xz = "xz-${system}";\n'
            '        zstd = "zstd-${system}";\n'
            '        autoPatchelfHook = "autoPatchelfHook-${system}";\n'
            '        unzip = "unzip-${system}";\n'
            '        makeWrapper = "makeWrapper-${system}";\n'
            "      };\n"
            "    in\n"
            "    fn (builtins.intersectAttrs (builtins.functionArgs fn) pool);\n"
            "in\n"
            "{\n"
            + "".join(
                f'  {label} = evalInputs {path} "{sys_name}";\n'
                for label, path, sys_name in [
                    ("tar_solo_static", expr_files["tar_solo_static"], "x86_64-linux"),
                    ("tar_multi_static", expr_files["tar_multi_static"], "x86_64-linux"),
                    ("tar_solo_dyn", expr_files["tar_solo_dyn"], "x86_64-linux"),
                    ("tar_multi_dyn", expr_files["tar_multi_dyn"], "x86_64-linux"),
                    ("fb_solo_dyn", expr_files["fb_solo_dyn"], "x86_64-linux"),
                    ("fb_multi_dyn", expr_files["fb_multi_dyn"], "x86_64-linux"),
                    ("fb_solo_static", expr_files["fb_solo_static"], "x86_64-linux"),
                    ("fb_multi_static", expr_files["fb_multi_static"], "x86_64-linux"),
                    ("fb_solo_zip", expr_files["fb_solo_zip"], "aarch64-darwin"),
                    ("fb_multi_zip", expr_files["fb_multi_dyn"], "aarch64-darwin"),
                ]
            )
            + "}\n"
        )
        eval_res = runtime.run(
            ["nix-instantiate", "--readonly-mode", "--eval", "--strict", "--json", "-E", harness]
        )
        assert eval_res.returncode == 0, eval_res.stderr.decode(errors="replace")
        evaluated = json.loads(eval_res.stdout)

        assert evaluated["tar_solo_static"] == evaluated["tar_multi_static"]
        assert evaluated["tar_solo_static"]["builder"] == "stdenvNoCC"
        assert evaluated["tar_solo_static"]["nativeBuildInputs"] == []
        assert evaluated["tar_solo_static"]["buildInputs"] == []
        assert evaluated["tar_solo_static"]["dontFixup"] is True

        assert evaluated["tar_solo_dyn"] == evaluated["tar_multi_dyn"]
        assert evaluated["tar_solo_dyn"]["builder"] == "stdenv"
        assert evaluated["tar_solo_dyn"]["nativeBuildInputs"] == ["autoPatchelfHook-x86_64-linux"]
        assert evaluated["tar_solo_dyn"]["buildInputs"] == ["gcc-lib-x86_64-linux"]
        assert evaluated["tar_solo_dyn"]["dontFixup"] is False

        assert evaluated["fb_solo_dyn"] == evaluated["fb_multi_dyn"]
        assert evaluated["fb_solo_dyn"]["builder"] == "stdenv"
        assert evaluated["fb_solo_dyn"]["dontFixup"] is False
        assert evaluated["fb_solo_dyn"]["unpackPhase"] == (
            'bintools-x86_64-linux/bin/ar x "$src"\ntar xf data.tar.*\n'
        )
        assert 'target="$out/${dir#usr/}"' in evaluated["fb_solo_dyn"]["installPhase"]

        assert evaluated["fb_solo_static"] == evaluated["fb_multi_static"]
        assert evaluated["fb_solo_static"]["builder"] == "stdenvNoCC"
        assert evaluated["fb_solo_static"]["dontFixup"] is True
        assert (
            "autoPatchelfHook-x86_64-linux" not in evaluated["fb_solo_static"]["nativeBuildInputs"]
        )
        assert evaluated["fb_solo_static"]["buildInputs"] == []

        assert evaluated["fb_solo_zip"] == evaluated["fb_multi_zip"]
        assert evaluated["fb_solo_zip"]["builder"] == "stdenvNoCC"
        assert evaluated["fb_solo_zip"]["unpackPhase"] == 'unzip -q "$src"\n'

        if shutil.which("haberdasher-nixpkgs", path=tool_path) is None:
            return
        nixpkgs_raw = json.loads(runtime.run(["haberdasher-nixpkgs"]).stdout)
        store_path = nixpkgs_raw["store_path"]
        real_expr = (
            "let\n"
            f'  pkgsLinux = import {store_path} {{ system = "x86_64-linux"; }};\n'
            f'  pkgsDarwin = import {store_path} {{ system = "aarch64-darwin"; }};\n'
            "  pair = pkgs: file:\n"
            "    let drv = pkgs.callPackage file { }; in { inherit (drv) drvPath outPath; };\n"
            "in {\n"
            f"  tar_solo_static = pair pkgsLinux {expr_files['tar_solo_static']};\n"
            f"  tar_multi_static = pair pkgsLinux {expr_files['tar_multi_static']};\n"
            f"  tar_solo_dyn = pair pkgsLinux {expr_files['tar_solo_dyn']};\n"
            f"  tar_multi_dyn = pair pkgsLinux {expr_files['tar_multi_dyn']};\n"
            f"  fb_solo_dyn = pair pkgsLinux {expr_files['fb_solo_dyn']};\n"
            f"  fb_multi_dyn = pair pkgsLinux {expr_files['fb_multi_dyn']};\n"
            f"  fb_solo_static = pair pkgsLinux {expr_files['fb_solo_static']};\n"
            f"  fb_multi_static = pair pkgsLinux {expr_files['fb_multi_static']};\n"
            f"  fb_solo_zip = pair pkgsDarwin {expr_files['fb_solo_zip']};\n"
            f"  fb_multi_zip = pair pkgsDarwin {expr_files['fb_multi_dyn']};\n"
            "}\n"
        )
        real_res = runtime.run(
            ["nix-instantiate", "--readonly-mode", "--eval", "--strict", "--json", "-E", real_expr]
        )
        assert real_res.returncode == 0, real_res.stderr.decode(errors="replace")
        real_paths = json.loads(real_res.stdout)
        assert real_paths["tar_solo_static"] == real_paths["tar_multi_static"]
        assert real_paths["tar_solo_dyn"] == real_paths["tar_multi_dyn"]
        assert real_paths["fb_solo_dyn"] == real_paths["fb_multi_dyn"]
        assert real_paths["fb_solo_static"] == real_paths["fb_multi_static"]
        assert real_paths["fb_solo_zip"] == real_paths["fb_multi_zip"]


@pytest.mark.parametrize(
    "out_sigs",
    [
        ["host-1:hostsig=="],
        ["flakehub-1:thirdpartysig=="],
    ],
)
def test_prepare_exports_signed_out_path_and_stubs_only_upstream_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, out_sigs: list[str]
) -> None:
    flake_key_1 = f"{'1' * 32}-source"
    out_key_1 = f"{'2' * 32}-tailor-0.6.0"
    host_dep_key = f"{'3' * 32}-local-wrapper-1.0"
    third_party_dep_key = f"{'4' * 32}-flakehub-dep-1.0"
    unsigned_dep_key = f"{'5' * 32}-unsigned-dep-1.0"
    upstream_dep_key = f"{'6' * 32}-glibc-2.40"
    mixed_upstream_dep_key = f"{'7' * 32}-zlib-1.3.1"
    flake_key_2 = f"{'8' * 32}-source"
    out_key_2 = f"{'9' * 32}-other-1.0.0"

    def info_entry(refs: list[str], sigs: list[str]) -> dict[str, JSONValue]:
        return {
            "narHash": f"sha256-{'A' * 43}=",
            "narSize": 128,
            "references": list(refs),
            "signatures": list(sigs),
        }

    closures: dict[str, dict[str, JSONValue]] = {
        f"/nix/store/{out_key_1}": {
            out_key_1: info_entry(
                [
                    host_dep_key,
                    third_party_dep_key,
                    unsigned_dep_key,
                    upstream_dep_key,
                    mixed_upstream_dep_key,
                ],
                out_sigs,
            ),
            host_dep_key: info_entry([upstream_dep_key], ["host-1:depsig=="]),
            third_party_dep_key: info_entry([], ["flakehub-1:depsig=="]),
            unsigned_dep_key: info_entry([], []),
            upstream_dep_key: info_entry([], ["cache.nixos.org-1:upstreamsig=="]),
            mixed_upstream_dep_key: info_entry(
                [], ["host-1:mirrorsig==", "cache.nixos.org-1:upstreamsig=="]
            ),
        },
        f"/nix/store/{out_key_2}": {
            out_key_2: info_entry([host_dep_key, upstream_dep_key], out_sigs),
            host_dep_key: info_entry([upstream_dep_key], ["host-1:depsig=="]),
            upstream_dep_key: info_entry([], ["cache.nixos.org-1:upstreamsig=="]),
        },
    }

    with private_workspace(tmp_path) as runtime:
        orig_run = runtime.run
        current_flake = flake_key_1
        built_targets: list[str] = []
        copied_batches: list[tuple[tuple[str, ...], set[str]]] = []
        verified_batches: list[tuple[tuple[str, ...], set[str]]] = []

        def fake_run(
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            input: bytes | None = None,
            timeout: float = 120,
            env_kind: str = "native",
            progress: Callable[[str], None] | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            if argv[0] == "gpgconf":
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[0] == "haberdasher-nixpkgs":
                payload = {
                    "locked": {
                        "owner": "NixOS",
                        "repo": "nixpkgs",
                        "rev": "0" * 40,
                        "type": "github",
                    },
                    "original": {
                        "owner": "NixOS",
                        "ref": "nixos-unstable",
                        "repo": "nixpkgs",
                        "type": "github",
                    },
                }
                return subprocess.CompletedProcess(argv, 0, json.dumps(payload).encode(), b"")
            if argv[0] == "nixfmt":
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[0] != "nix":
                return orig_run(
                    argv,
                    cwd=cwd,
                    input=input,
                    timeout=timeout,
                    env_kind=env_kind,  # type: ignore[arg-type]
                    progress=progress,
                )
            args = list(argv[3:])
            if args[:2] == ["store", "add-file"]:
                return subprocess.CompletedProcess(
                    argv, 0, f"/nix/store/{'0' * 32}-seed\n".encode(), b""
                )
            if args[:2] == ["flake", "archive"]:
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps({"path": f"/nix/store/{current_flake}"}).encode(), b""
                )
            if args[:4] == ["eval", "--raw", "--impure", "--expr"]:
                return subprocess.CompletedProcess(argv, 0, b"x86_64-linux\n", b"")
            if args[:2] == ["eval", "--raw"]:
                expr = args[2]
                out_key = out_key_1 if expr.endswith(".tailor.outPath") else out_key_2
                return subprocess.CompletedProcess(argv, 0, f"/nix/store/{out_key}\n".encode(), b"")
            if args[0] == "build":
                built_targets.append(args[-1])
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if args[0] == "path-info":
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps({"info": closures[args[-1]]}).encode(), b""
                )
            if args[0] == "copy":
                to_uri = args[args.index("--to") + 1]
                cache_dir = Path(to_uri.removeprefix("file://").split("?", 1)[0])
                store_paths = tuple(arg for arg in args if arg.startswith("/nix/store/"))
                pre_narinfos = {p.name for p in cache_dir.glob("*.narinfo")}
                copied_batches.append((store_paths, pre_narinfos))
                for store_path in store_paths:
                    store_key = store_path.removeprefix("/nix/store/")
                    h32 = store_key.split("-", 1)[0]
                    nar_rel = f"nar/{h32}{'0' * 20}.nar.zst"
                    nar_target = cache_dir / nar_rel
                    nar_target.parent.mkdir(parents=True, exist_ok=True)
                    atomic_write(nar_target, f"nar-{store_key}".encode())
                    narinfo = (
                        f"StorePath: {store_path}\n"
                        f"URL: {nar_rel}\n"
                        "Compression: zstd\n"
                        f"Sig: {NIX_KEY_NAME}:sig==\n"
                    )
                    atomic_write(cache_dir / f"{h32}.narinfo", narinfo.encode("utf-8"))
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            assert args[:2] == ["store", "verify"]
            store_uri = args[args.index("--store") + 1]
            cache_dir = Path(store_uri.removeprefix("file://"))
            store_paths = tuple(arg for arg in args if arg.startswith("/nix/store/"))
            verified_batches.append((store_paths, {p.name for p in cache_dir.glob("*.narinfo")}))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        monkeypatch.setattr(runtime, "run", fake_run)
        secret_file = tmp_path / "nix.sec"
        public_file = tmp_path / "nix.pub"
        secret_file.write_text(f"{NIX_KEY_NAME}:{'B' * 86}==\n", encoding="utf-8")
        public_file.write_text(f"{PUB_VALUE}\n", encoding="utf-8")
        signer = SigningSession(runtime, tmp_path / "gnupg", FINGERPRINT)

        def make_admitted(name: str, version: str, asset_id: int) -> AdmittedAsset:
            v_asset = verified_asset(
                tmp_path,
                f"{name}_{version}_linux_x86_64.tar.gz",
                tar_gz((name, elf64(0x3E, dynamic=False))),
                repository=f"wimpysworld/{name}",
                tag=f"v{version}",
                asset_id=asset_id,
            )
            return AdmittedAsset(
                InspectedAsset(
                    v_asset,
                    NativeIdentity("nix", name, "x86_64-linux", version),
                    {"mode": "tarball", "binary": name, "dynamic_elf": False},
                    {},
                    "unsigned",
                ),
                "preserve",
                v_asset.sha256,
            )

        with patch.object(signer, "nix_key", return_value=(secret_file, public_file, PUB_VALUE)):
            prepared1 = nix.prepare(
                [make_admitted("tailor", "0.6.0", 70)],
                RetainedFormat("nix", (), (), {}, ()),
                policy=POLICY,
                runtime=runtime,
                signer=signer,
                now=datetime(2026, 1, 1, tzinfo=UTC),
                out=tmp_path / "prep1",
            )

            expected_export_1 = tuple(
                sorted(
                    f"/nix/store/{key}"
                    for key in (
                        flake_key_1,
                        out_key_1,
                        host_dep_key,
                        third_party_dep_key,
                        unsigned_dep_key,
                    )
                )
            )
            assert len(copied_batches) == 1 and len(verified_batches) == 1
            copied_1, stubs_before_copy_1 = copied_batches[0]
            verified_1, narinfos_before_verify_1 = verified_batches[0]
            assert copied_1 == expected_export_1
            assert verified_1 == expected_export_1
            assert stubs_before_copy_1 == {f"{'6' * 32}.narinfo", f"{'7' * 32}.narinfo"}
            assert f"{'6' * 32}.narinfo" not in narinfos_before_verify_1
            assert f"{'7' * 32}.narinfo" not in narinfos_before_verify_1

            gen1_keys = {ref.key for ref in prepared1.retained.objects}
            for exported_h32 in ("1" * 32, "2" * 32, "3" * 32, "4" * 32, "5" * 32):
                assert f"{exported_h32}.narinfo" in gen1_keys
            for stubbed_h32 in ("6" * 32, "7" * 32):
                assert f"{stubbed_h32}.narinfo" not in gen1_keys

            current_flake = flake_key_2
            retained1 = replace(
                prepared1.retained,
                metadata={
                    **prepared1.retained.metadata,
                    "etags": {entry: '"etag"' for entry in nix._ENTRIES},  # pyright: ignore[reportPrivateUsage]
                },
            )
            prepared2 = nix.prepare(
                [make_admitted("other", "1.0.0", 71)],
                retained1,
                policy=POLICY,
                runtime=runtime,
                signer=signer,
                now=datetime(2026, 1, 2, tzinfo=UTC),
                out=tmp_path / "prep2",
            )

            assert len(built_targets) == 2
            assert built_targets[1].endswith("#packages.x86_64-linux.other")
            expected_export_2 = tuple(
                sorted(f"/nix/store/{key}" for key in (flake_key_2, out_key_2))
            )
            copied_2, stubs_before_copy_2 = copied_batches[1]
            verified_2, narinfos_before_verify_2 = verified_batches[1]
            assert copied_2 == expected_export_2
            assert verified_2 == expected_export_2
            assert stubs_before_copy_2 == {f"{'3' * 32}.narinfo", f"{'6' * 32}.narinfo"}
            assert f"{'3' * 32}.narinfo" not in narinfos_before_verify_2
            assert f"{'6' * 32}.narinfo" not in narinfos_before_verify_2

            gen2_keys = {ref.key for ref in prepared2.retained.objects}
            assert f"{'8' * 32}.narinfo" in gen2_keys
            assert f"{'9' * 32}.narinfo" in gen2_keys
            assert f"{'3' * 32}.narinfo" in gen2_keys
            assert f"{'6' * 32}.narinfo" not in gen2_keys
