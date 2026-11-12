"""Disposable ELF tarballs, upstream Nix release fixtures, and unprivileged Nix store clients."""

from __future__ import annotations

import base64
import io
import json
import shutil
import struct
import subprocess
import tarfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from haberdasher.core import (
    JSONValue,
    PreparedFormat,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
    atomic_write,
    safe_path,
    sha256_file,
)
from haberdasher.runtime import Runtime
from tests.support.http import set_generation_mtime


def _x86_64_linux_static_elf(text: str) -> bytes:
    """Build a minimal 64-bit x86_64 Linux static ELF executable that prints `text` and exits 0."""
    payload = text.encode("utf-8")
    load_vaddr = 0x400000
    ehdr_size = 64
    phdr_size = 56
    code_offset = ehdr_size + phdr_size
    msg_vaddr = load_vaddr + code_offset + 36
    code = (
        b"\xb8\x01\x00\x00\x00"  # mov eax, 1 (sys_write)
        b"\xbf\x01\x00\x00\x00"  # mov edi, 1 (stdout)
        + b"\x48\xbe"
        + struct.pack("<Q", msg_vaddr)  # movabs rsi, msg_vaddr
        + b"\xba"
        + struct.pack("<I", len(payload))  # mov edx, len(payload)
        + b"\x0f\x05"  # syscall
        + b"\xb8\x3c\x00\x00\x00"  # mov eax, 60 (sys_exit)
        + b"\x31\xff"  # xor edi, edi
        + b"\x0f\x05"  # syscall
    )
    assert len(code) == 36
    total_size = code_offset + len(code) + len(payload)
    e_ident = (
        b"\x7fELF"
        b"\x02"  # ELFCLASS64
        b"\x01"  # ELFDATA2LSB
        b"\x01"  # EV_CURRENT
        b"\x00" + b"\x00" * 8  # ELFOSABI_NONE
    )
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        0x3E,  # EM_X86_64
        1,  # EV_CURRENT
        load_vaddr + code_offset,  # e_entry
        ehdr_size,  # e_phoff
        0,  # e_shoff
        0,  # e_flags
        ehdr_size,  # e_ehsize
        phdr_size,  # e_phentsize
        1,  # e_phnum
        64,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        5,  # PF_R | PF_X
        0,  # p_offset
        load_vaddr,  # p_vaddr
        load_vaddr,  # p_paddr
        total_size,  # p_filesz
        total_size,  # p_memsz
        0x1000,  # p_align
    )
    return ehdr + phdr + code + payload


def tarball_asset(
    runtime: Runtime,
    name: str,
    version: str,
    payload: str,
    *,
    repository: str = "wimpysworld/fixture",
    release_id: int = 1,
    asset_id: int = 1,
    os_label: str = "linux",
    arch_label: str = "x86_64",
    subdir: str = "",
) -> VerifiedAsset:
    """Create a `.tar.gz` VerifiedAsset holding a runnable x86_64 Linux static ELF executable."""
    filename = f"{name}_{version}_{os_label}_{arch_label}.tar.gz"
    build_dir = safe_path(runtime.root, f"nix-fixture-{asset_id}-{filename}")
    build_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive_path = build_dir / filename
    elf = _x86_64_linux_static_elf(payload + "\n")
    member_name = f"{subdir.strip('/')}/{name}" if subdir else name
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=member_name)
        info.size = len(elf)
        info.mode = 0o755
        info.mtime = 1700000000
        tar.addfile(info, io.BytesIO(elf))
        readme = f"# {name} {version}\n".encode()
        rinfo = tarfile.TarInfo(name="README.md")
        rinfo.size = len(readme)
        rinfo.mode = 0o644
        rinfo.mtime = 1700000000
        tar.addfile(rinfo, io.BytesIO(readme))
    atomic_write(archive_path, buf.getvalue())
    sha, size = sha256_file(archive_path)
    source = SourceAsset(
        repository=repository,
        release_id=release_id,
        asset_id=asset_id,
        filename=filename,
        size=size,
        updated_at="2026-01-01T00:00:00Z",
        public_url=f"https://github.com/{repository}/releases/download/v{version}/{filename}",
        github_sha256=sha,
    )
    return VerifiedAsset(source, archive_path, sha, size, 999, "a" * 64)


def deb_executable_asset(
    runtime: Runtime,
    name: str,
    version: str,
    payload: str,
    *,
    repository: str = "wimpysworld/sidra",
    release_id: int = 1,
    asset_id: int = 10,
) -> VerifiedAsset:
    """Create a `.deb` VerifiedAsset holding `/usr/bin/<name>` as an x86_64 static ELF binary."""
    filename = f"{name}_{version}_linux_amd64.deb"
    build_dir = safe_path(runtime.root, f"nix-deb-{asset_id}-{filename}")
    root = build_dir / "root"
    control = root / "DEBIAN/control"
    control.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    control.write_text(
        f"Package: {name}\n"
        f"Version: {version}\n"
        "Architecture: amd64\n"
        "Maintainer: Synthetic test <test@invalid>\n"
        f"Description: {name} package for Nix upstream-nix proof\n"
    )
    bin_path = root / "usr/bin" / name
    bin_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    bin_path.write_bytes(_x86_64_linux_static_elf(payload + "\n"))
    for path in (root, *root.rglob("*")):
        if path.is_dir():
            path.chmod(0o755)
        elif path == bin_path:
            path.chmod(0o755)
        else:
            path.chmod(0o644)
    deb_path = build_dir / filename
    result = runtime.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(deb_path)])
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    sha, size = sha256_file(deb_path)
    source = SourceAsset(
        repository=repository,
        release_id=release_id,
        asset_id=asset_id,
        filename=filename,
        size=size,
        updated_at="2026-01-01T00:00:00Z",
        public_url=f"https://github.com/{repository}/releases/download/v{version}/{filename}",
        github_sha256=sha,
    )
    return VerifiedAsset(source, deb_path, sha, size, 999, "b" * 64)


def upstream_nix_files(
    name: str,
    *,
    repository: str = "wimpysworld/sidra",
    stale_hash: str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
) -> dict[str, str]:
    """Return upstream `flake.nix` and `nix/linux.nix` with a deliberately stale `fetchurl` hash."""
    flake_nix = '{\n  description = "Upstream fixture flake";\n  outputs = { self }: { };\n}\n'
    linux_nix = (
        "{\n"
        "  lib,\n"
        "  stdenvNoCC,\n"
        "  fetchurl,\n"
        "  dpkg,\n"
        f'  version ? "0.0.0",\n'
        "}:\n"
        "let\n"
        "  inherit (stdenvNoCC.hostPlatform) system;\n"
        "  sources = {\n"
        "    x86_64-linux = {\n"
        f'      url = "https://github.com/{repository}/releases/download/v${{version}}/{name}_${{version}}_linux_amd64.deb";\n'
        f'      hash = "{stale_hash}";\n'
        "    };\n"
        "  };\n"
        "in\n"
        "stdenvNoCC.mkDerivation {\n"
        f'  pname = "{name}";\n'
        "  inherit version;\n"
        "  src = fetchurl sources.${system};\n"
        "  nativeBuildInputs = [ dpkg ];\n"
        "  dontConfigure = true;\n"
        "  dontBuild = true;\n"
        "  dontFixup = true;\n"
        "  unpackPhase = ''\n"
        '    dpkg-deb -x "$src" .\n'
        "  '';\n"
        "  installPhase = ''\n"
        "    runHook preInstall\n"
        f'    install -Dm755 usr/bin/{name} "$out/bin/{name}"\n'
        "    runHook postInstall\n"
        "  '';\n"
        "  meta = {\n"
        f'    description = "Upstream {name} fixture";\n'
        f'    homepage = "https://github.com/{repository}";\n'
        "    license = lib.licenses.mit;\n"
        '    platforms = [ "x86_64-linux" ];\n'
        f'    mainProgram = "{name}";\n'
        "  };\n"
        "}\n"
    )
    return {"flake.nix": flake_nix, "nix/linux.nix": linux_nix}


@contextmanager
def bind_github_metadata(
    runtime: Runtime,
    *,
    tag: str = "v1.0.0",
    description: str = "Disposable Nix fixture",
    licence: str = "MIT",
    upstream_by_repo: Mapping[str, Mapping[str, str]] | None = None,
) -> Iterator[None]:
    """Intercept `gh api` calls for `release_details` and `tag_nix_files` while running native tools."""
    real_run: Callable[..., subprocess.CompletedProcess[bytes]] = runtime.run
    blobs: dict[tuple[str, str], bytes] = {}
    trees: dict[str, list[dict[str, object]]] = {}
    for repo, files in (upstream_by_repo or {}).items():
        entries: list[dict[str, object]] = []
        for idx, (rel_path, content) in enumerate(sorted(files.items()), 1):
            raw = content.encode("utf-8")
            sha = f"{idx:040x}"
            blobs[(repo, sha)] = raw
            entries.append(
                {
                    "path": rel_path,
                    "mode": "100644",
                    "type": "blob",
                    "sha": sha,
                    "size": len(raw),
                }
            )
        trees[repo] = entries

    def fake_run(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
        env_kind: str = "native",
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[0] != "gh":
            return real_run(argv, cwd=cwd, input=input, timeout=timeout, env_kind=env_kind)
        endpoint = argv[-1]
        if "/releases/" in endpoint:
            rel_id = int(endpoint.rsplit("/", 1)[1])
            doc: object = {
                "id": rel_id,
                "draft": False,
                "prerelease": False,
                "tag_name": tag,
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps(doc).encode(), b"")
        if "/git/trees/" in endpoint:
            repo = endpoint.removeprefix("repos/").split("/git/trees/", 1)[0]
            if repo not in trees:
                return subprocess.CompletedProcess(argv, 1, b"", b"gh: Not Found (HTTP 404)\n")
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({"tree": trees[repo]}).encode(), b""
            )
        if "/git/blobs/" in endpoint:
            repo, sha = endpoint.removeprefix("repos/").split("/git/blobs/", 1)
            raw = blobs[(repo, sha)]
            doc = {"encoding": "base64", "content": base64.b64encode(raw).decode("ascii")}
            return subprocess.CompletedProcess(argv, 0, json.dumps(doc).encode(), b"")
        if endpoint.startswith("repos/"):
            doc = {
                "description": description,
                "license": {"spdx_id": licence},
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps(doc).encode(), b"")
        raise AssertionError(f"Unexpected gh endpoint: {endpoint}")

    runtime.run = fake_run  # pyright: ignore[reportAttributeAccessIssue]
    try:
        yield
    finally:
        runtime.run = real_run  # pyright: ignore[reportAttributeAccessIssue]


def publish(prepared: PreparedFormat, root: Path, generation: int = 1) -> RetainedFormat:
    """Write prepared outputs into `root` and return updated `RetainedFormat` with synthetic ETags."""
    etags: dict[str, JSONValue] = dict(
        prepared.retained.metadata.get("etags", {})  # type: ignore[arg-type]
    )
    paths: list[Path] = []
    for output in prepared.outputs:
        target = root / output.ref.key
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output.local_path, target)
        assert sha256_file(target) == (output.ref.sha256, output.ref.size)
        etags[output.ref.key] = f'"synthetic-{generation}-{output.ordinal}"'
        paths.append(target)
    if paths:
        set_generation_mtime(paths, generation)
    return replace(
        prepared.retained,
        metadata={**prepared.retained.metadata, "etags": etags},
    )


class NixClient:
    """Isolated client store (`--store <root>`) that substitutes from a loopback HTTP binary cache."""

    def __init__(
        self,
        runtime: Runtime,
        name: str,
        cache_url: str,
        trusted_public_key: str,
    ) -> None:
        self.runtime = runtime
        self.base = safe_path(runtime.root, f"nix-clients/{name}")
        self.store = self.base / "store"
        self.home = self.base / "home"
        self.cache = self.base / "cache"
        for directory in (self.store, self.home, self.cache):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.cache_url = cache_url.rstrip("/")
        self.trusted_public_key = trusted_public_key

    def run_nix(
        self,
        *args: str,
        check: bool = True,
        substituters: str | None = None,
        trusted_keys: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        sub = self.cache_url if substituters is None else substituters
        keys = self.trusted_public_key if trusted_keys is None else trusted_keys
        argv = [
            "env",
            f"HOME={self.home}",
            f"XDG_CACHE_HOME={self.cache}",
            "nix",
            "--extra-experimental-features",
            "nix-command flakes",
            "--store",
            str(self.store),
            "--max-jobs",
            "0",
            "--option",
            "substituters",
            sub,
            "--option",
            "extra-substituters",
            "",
            "--option",
            "trusted-public-keys",
            keys,
            "--option",
            "extra-trusted-public-keys",
            "",
            "--option",
            "narinfo-cache-negative-ttl",
            "0",
            "--option",
            "narinfo-cache-positive-ttl",
            "0",
            "--option",
            "connect-timeout",
            "5",
            *args,
        ]
        try:
            result = self.runtime.run(argv, timeout=180)
        finally:
            self.make_writable()
        if check:
            assert result.returncode == 0, result.stdout.decode(
                errors="replace"
            ) + result.stderr.decode(errors="replace")
        return result

    def real_store_path(self, logical_store_path: str) -> Path:
        rel = logical_store_path.lstrip("/")
        return safe_path(self.store, rel)

    def substitute_and_run(
        self, logical_store_path: str, binary_name: str, expected_output: str
    ) -> None:
        self.run_nix("build", "--no-link", logical_store_path)
        exe = self.real_store_path(logical_store_path) / "bin" / binary_name
        assert exe.is_file(), f"Missing substituted executable {exe}"
        proc = self.runtime.run([str(exe)])
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        assert proc.stdout.decode("utf-8") == expected_output + "\n"

    def make_writable(self) -> None:
        for path in (self.base, *self.base.rglob("*")):
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            path.chmod(mode | 0o200)


def make_tree_writable(root: Path) -> None:
    if not root.exists():
        return
    for path in (root, *root.rglob("*")):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        path.chmod(mode | 0o200)
