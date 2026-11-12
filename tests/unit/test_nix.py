from __future__ import annotations

import base64
import hashlib
import io
import plistlib
import struct
import subprocess
import tarfile
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import replace
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
from haberdasher.signing import NIX_KEY_NAME
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
        assert "stdenvNoCC" in static_expr and "autoPatchelfHook" not in static_expr

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
