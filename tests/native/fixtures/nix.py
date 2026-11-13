"""Disposable local flakes and unprivileged Nix store clients."""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from dataclasses import replace
from pathlib import Path

from haberdasher.core import (
    JSONValue,
    PreparedFormat,
    RetainedFormat,
    atomic_write,
    safe_path,
    sha256_file,
)
from haberdasher.runtime import Runtime
from tests.support.http import set_generation_mtime

# The project lock pins the nixpkgs that the development shell already holds in the store.
PROJECT_LOCK = Path(__file__).resolve().parents[3] / "flake.lock"


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


def flake(root: Path, name: str, version: str, payload: str, *, broken: str = "") -> Path:
    """Write a flake whose static executable prints `payload`, with an optional failing package.

    The default package duplicates the named package. The lock reuses the project nixpkgs, so
    evaluation and builds need no network.
    """
    root.mkdir(mode=0o700, parents=True)
    atomic_write(root / name, _x86_64_linux_static_elf(payload + "\n"))
    nixpkgs = json.loads(PROJECT_LOCK.read_text(encoding="utf-8"))["nodes"]["nixpkgs"]
    lock = {
        "nodes": {"nixpkgs": nixpkgs, "root": {"inputs": {"nixpkgs": "nixpkgs"}}},
        "root": "root",
        "version": 7,
    }
    atomic_write(root / "flake.lock", json.dumps(lock, indent=2).encode())
    failing = (
        f"""
        {broken} = pkgs.stdenvNoCC.mkDerivation {{
          pname = "{broken}";
          version = "{version}";
          dontUnpack = true;
          buildPhase = "exit 1";
        }};"""
        if broken
        else ""
    )
    atomic_write(
        root / "flake.nix",
        f"""{{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  outputs =
    {{ nixpkgs, ... }}:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      package = pkgs.stdenvNoCC.mkDerivation {{
        pname = "{name}";
        version = "{version}";
        src = ./{name};
        dontUnpack = true;
        dontFixup = true;
        installPhase = "install -Dm755 $src $out/bin/{name}";
        meta.description = "Disposable Nix fixture";
      }};
    in
    {{
      packages.x86_64-linux = {{
        default = package;
        {name} = package;{failing}
      }};
    }};
}}
""".encode(),
    )
    return root


def empty_flake(root: Path) -> Path:
    """Write a flake with packages for another system only."""
    root.mkdir(mode=0o700, parents=True)
    atomic_write(root / "flake.nix", b"{ outputs = _: { packages.aarch64-linux = { }; }; }\n")
    return root


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
        make_tree_writable(self.base)


def make_tree_writable(root: Path) -> None:
    if not root.exists():
        return
    for path in (root, *root.rglob("*")):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        path.chmod(mode | 0o200)
