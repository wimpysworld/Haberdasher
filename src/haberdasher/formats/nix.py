"""Nix flake repository over dumb HTTP and signed HTTP binary cache."""

from __future__ import annotations

import base64
import io
import json
import os
import plistlib
import posixpath
import re
import shutil
import struct
import tarfile
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import cast

from haberdasher import discovery
from haberdasher.config import PUBLIC, FormatPolicy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    JSONValue,
    NativeIdentity,
    ObjectRef,
    OutputObject,
    PreparedFormat,
    RetainedFormat,
    UnsupportedAsset,
    VerifiedAsset,
    atomic_write,
    safe_key,
    safe_path,
    sha256_file,
    stale_entries,
)
from haberdasher.formats import apt, brew, mirror, scoop
from haberdasher.runtime import Runtime, RuntimeFailure
from haberdasher.signing import NIX_KEY_NAME, SigningSession

REPO = "packages.git"
PUBKEY_KEY = "keys/haberdasher-nix.pub"
CACHE_INFO_KEY = "nix-cache-info"
CACHE_INFO = b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 41\n"
IMMUTABLE = "public, max-age=31536000, immutable"
SYSTEMS = ("x86_64-linux", "aarch64-linux", "x86_64-darwin", "aarch64-darwin")
MAX_TAR_MEMBERS = 10_000
MAX_TAR_BYTES = 1024 * 1024 * 1024
_NIX32 = "[0-9a-df-np-sv-z]"
_NAR = re.compile(rf"nar/{_NIX32}{{52}}\.nar\.zst")
_NARINFO = re.compile(rf"{_NIX32}{{32}}\.narinfo")
_GIT_OBJECT = re.compile(
    r"packages\.git/objects/(?:[0-9a-f]{2}/[0-9a-f]{38}|pack/pack-[0-9a-f]{40}\.(?:pack|idx))"
)
_GIT_TAG = re.compile(r"packages\.git/refs/tags/[0-9a-f]{40}")
_GIT_ENTRIES = tuple(f"{REPO}/{entry}" for entry in mirror.ENTRIES)
_ENTRIES = (CACHE_INFO_KEY, *_GIT_ENTRIES)
_TARBALL_VERSION = re.compile(
    r"[^/]+[-_]v?(\d[A-Za-z0-9._+-]*)[-_](?:linux|darwin|macos|mac|osx)[-_]"
    r"(?:x86_64|amd64|x64|aarch64|arm64)\.tar\.gz$",
    re.IGNORECASE,
)
_SKIP_SUFFIXES = (
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".bash",
    ".zsh",
    ".fish",
    ".png",
    ".svg",
    ".1",
    ".2",
    ".3",
    ".4",
    ".5",
    ".6",
    ".7",
    ".8",
    ".9",
    ".gz",
    ".so",
)
LICENCES = {
    "0BSD": "bsd0",
    "AGPL-3.0-only": "agpl3Only",
    "AGPL-3.0-or-later": "agpl3Plus",
    "Apache-2.0": "asl20",
    "Artistic-2.0": "artistic2",
    "BSD-2-Clause": "bsd2",
    "BSD-3-Clause": "bsd3",
    "BSL-1.0": "boost",
    "BlueOak-1.0.0": "blueOak100",
    "CC0-1.0": "cc0",
    "EPL-2.0": "epl20",
    "GPL-2.0-only": "gpl2Only",
    "GPL-2.0-or-later": "gpl2Plus",
    "GPL-3.0-only": "gpl3Only",
    "GPL-3.0-or-later": "gpl3Plus",
    "ISC": "isc",
    "LGPL-2.1-only": "lgpl21Only",
    "LGPL-2.1-or-later": "lgpl21Plus",
    "LGPL-3.0-only": "lgpl3Only",
    "LGPL-3.0-or-later": "lgpl3Plus",
    "MIT": "mit",
    "MPL-2.0": "mpl20",
    "Unlicense": "unlicense",
    "WTFPL": "wtfpl",
    "Zlib": "zlib",
}


class NixFailure(RuntimeFailure):
    pass


def _run(
    runtime: Runtime, argv: Sequence[str], *, cwd: Path | None = None, timeout: float = 300
) -> bytes:
    result = runtime.run(argv, cwd=cwd, timeout=timeout)
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise NixFailure(f"Native Nix command failed ({argv[0]}): {detail}")
    return result.stdout


def _nix(runtime: Runtime, *args: str, flakes: bool = False, timeout: float = 600) -> bytes:
    features = "nix-command flakes" if flakes else "nix-command"
    return _run(runtime, ["nix", "--extra-experimental-features", features, *args], timeout=timeout)


def _string(value: JSONValue, label: str = "metadata value") -> str:
    if not isinstance(value, str) or not value:
        raise NixFailure(f"Missing or invalid Nix {label}")
    return value


def _mapping(value: JSONValue, label: str = "metadata mapping") -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise NixFailure(f"Missing or invalid Nix {label}")
    return value


def _sri(sha256_hex: str) -> str:
    return "sha256-" + base64.b64encode(bytes.fromhex(sha256_hex)).decode("ascii")


def elf_binary(data: bytes) -> tuple[str, bool]:
    """Return `(system, dynamic_elf)` for a 64-bit Linux ELF executable, or `("", False)`."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return "", False
    (
        e_type,
        e_machine,
        _version,
        _entry,
        e_phoff,
        _shoff,
        _flags,
        _ehsize,
        e_phentsize,
        e_phnum,
        _shentsize,
        _shnum,
        _shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    system = {0x3E: "x86_64-linux", 0xB7: "aarch64-linux"}.get(e_machine, "")
    if not system or e_type not in {2, 3}:
        return "", False
    if e_phnum == 0 or e_phentsize < 56 or len(data) < e_phoff + e_phnum * e_phentsize:
        return system, False
    dynamic = any(
        struct.unpack_from("<I", data, e_phoff + index * e_phentsize)[0] == 3
        for index in range(e_phnum)
    )
    return system, dynamic


def darwin_systems(header: bytes) -> tuple[str, ...]:
    """Map Mach-O header architectures to Nix Darwin systems."""
    mapping = {"arm": "aarch64-darwin", "intel": "x86_64-darwin"}
    return tuple(mapping[arch] for arch in brew.macho_architectures(header) if arch in mapping)


def _clean_member(raw: str) -> str:
    cleaned = raw.removeprefix("./").strip("/")
    safe_key(cleaned)
    return cleaned


def _tarball_binary(path: Path, hint: str) -> tuple[str, str, bool, bool]:
    """Inspect a `.tar.gz` archive and return `(member, system, dynamic_elf, universal)`."""
    candidates: list[tuple[str, str, bool, bool, bool]] = []
    total = 0
    try:
        with tarfile.open(path, "r:gz") as archive:
            for count, member in enumerate(archive, 1):
                if count > MAX_TAR_MEMBERS:
                    raise NixFailure("Tarball exceeds member limit")
                if member.ischr() or member.isblk() or member.isfifo():
                    raise NixFailure("Tarball contains special device nodes")
                if not member.isfile() or member.size == 0:
                    continue
                rel = _clean_member(member.name)
                total += member.size
                if total > MAX_TAR_BYTES:
                    raise NixFailure("Tarball exceeds uncompressed byte limit")
                base = rel.rsplit("/", 1)[-1]
                lower = base.lower()
                if lower.endswith(_SKIP_SUFFIXES) or ".so." in lower:
                    continue
                if lower.startswith(("license", "readme", "changelog", "copying")):
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                data = extracted.read(min(member.size, 64 * 1024 * 1024))
                elf_sys, dynamic = elf_binary(data)
                if elf_sys:
                    candidates.append((rel, elf_sys, dynamic, False, lower == hint))
                    continue
                mac_sys = darwin_systems(data[:4096])
                if mac_sys:
                    universal = len(mac_sys) > 1
                    chosen = "aarch64-darwin" if universal else mac_sys[0]
                    candidates.append((rel, chosen, False, universal, lower == hint))
    except (tarfile.TarError, OSError, EOFError, ValueError) as error:
        if isinstance(error, NixFailure):
            raise
        raise UnsupportedAsset(f"{path.name}: invalid or unsupported tar.gz archive") from error
    named = [item for item in candidates if item[4]]
    selected = named if len(named) == 1 else candidates
    if len(selected) != 1:
        return "", "", False, False
    rel, system, dynamic, universal, _ = selected[0]
    return rel, system, dynamic, universal


def _brace_blocks(
    content: str, header_pattern: str
) -> list[tuple[re.Match[str], str, tuple[int, int]]]:
    blocks: list[tuple[re.Match[str], str, tuple[int, int]]] = []
    for match in re.finditer(header_pattern, content):
        open_idx = match.end() - 1
        depth = 1
        in_str = False
        idx = open_idx + 1
        while idx < len(content) and depth > 0:
            ch = content[idx]
            if in_str:
                if ch == "\\" and idx + 1 < len(content):
                    idx += 2
                    continue
                if ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
            idx += 1
        if depth == 0:
            inner = content[open_idx + 1 : idx - 1]
            blocks.append((match, inner, (open_idx + 1, idx - 1)))
    return blocks


def _mask_nix(content: str, *, mask_strings: bool = False) -> str:
    """Mask Nix comments and indented strings (and optionally `\"...\"` text) with spaces."""
    out: list[str] = []
    stack: list[tuple[str, int]] = [("code", 0)]
    idx = 0
    length = len(content)
    while idx < length:
        mode, depth = stack[-1]
        if mode in {"code", "interp_dquote", "interp_indented"}:
            if content[idx] == "#":
                end = content.find("\n", idx)
                stop = length if end == -1 else end
                out.append(" " * (stop - idx))
                idx = stop
                continue
            if content[idx : idx + 2] == "/*":
                end = content.find("*/", idx + 2)
                stop = length if end == -1 else end + 2
                out.extend("\n" if ch == "\n" else " " for ch in content[idx:stop])
                idx = stop
                continue
            if content[idx : idx + 2] == "''":
                out.append("  ")
                stack.append(("indented", 0))
                idx += 2
                continue
            if content[idx] == '"':
                out.append('"')
                stack.append(("dquote", 0))
                idx += 1
                continue
            if content[idx] == "{" and mode != "code":
                stack[-1] = (mode, depth + 1)
                out.append("{")
                idx += 1
                continue
            if content[idx] == "}" and mode != "code":
                if depth == 0:
                    stack.pop()
                    if mode == "interp_dquote":
                        out.append(" " if mask_strings else "}")
                    else:
                        out.append(" ")
                else:
                    stack[-1] = (mode, depth - 1)
                    out.append("}")
                idx += 1
                continue
            out.append(content[idx])
            idx += 1
            continue
        if mode == "dquote":
            if content[idx] == "\\":
                step = 2 if idx + 1 < length else 1
                if mask_strings:
                    out.extend("\n" if ch == "\n" else " " for ch in content[idx : idx + step])
                else:
                    out.append(content[idx : idx + step])
                idx += step
                continue
            if content[idx : idx + 2] == "${":
                out.append("  " if mask_strings else "${")
                stack.append(("interp_dquote", 0))
                idx += 2
                continue
            if content[idx] == '"':
                stack.pop()
                out.append('"')
                idx += 1
                continue
            ch = content[idx]
            out.append(("\n" if ch == "\n" else " ") if mask_strings else ch)
            idx += 1
            continue
        if content[idx : idx + 3] in {"'''", "''$"}:
            out.append("   ")
            idx += 3
            continue
        if content[idx : idx + 3] == "''\\" and idx + 3 < length:
            out.append("   " + ("\n" if content[idx + 3] == "\n" else " "))
            idx += 4
            continue
        if content[idx : idx + 2] == "''":
            stack.pop()
            out.append("  ")
            idx += 2
            continue
        if content[idx : idx + 2] == "${":
            out.append("  ")
            stack.append(("interp_indented", 0))
            idx += 2
            continue
        out.append("\n" if content[idx] == "\n" else " ")
        idx += 1
    return "".join(out)


_UPSTREAM_SYS_HEADER = (
    r'(?:"(x86_64-linux|aarch64-linux|x86_64-darwin|aarch64-darwin)"'
    r"|(?<![A-Za-z0-9_-])(x86_64-linux|aarch64-linux|x86_64-darwin|aarch64-darwin))"
    r"\s*=\s*(?:[A-Za-z0-9_.]*\bfetchurl\s*)?\{"
)
_SYSTEM_BLOCK_HEADER = (
    r'(?:"([A-Za-z0-9_]+-(?:linux|darwin))"|(?<![A-Za-z0-9_-])([A-Za-z0-9_]+-(?:linux|darwin)))'
    r"\s*=\s*(?:[A-Za-z0-9_.]*\bfetchurl\s*)?\{"
)


def _upstream_sources(
    nix_files: Mapping[str, str], ver: str
) -> tuple[str, list[tuple[str, str, str, bool]]]:
    pname = ""
    entries: list[tuple[str, str, str, bool]] = []
    for rel_path, content in sorted(nix_files.items()):
        if rel_path == "flake.nix":
            continue
        masked = _mask_nix(content)
        if not pname and (match := re.search(r'\bpname\s*=\s*"([^"]+)"\s*;', masked)):
            pname = mirror.name(match[1])
        matched_spans: list[tuple[int, int]] = []
        for match, inner, span in _brace_blocks(masked, _UPSTREAM_SYS_HEADER):
            urls = re.findall(r'\burl\s*=\s*"([^"]+)"\s*;', inner)
            hashes = re.findall(r'\b(?:hash|sha256)\s*=\s*"([^"]*)"\s*;', inner)
            if len(urls) == 1 and len(hashes) == 1:
                expanded = urls[0].replace("${version}", ver)
                if pname:
                    expanded = expanded.replace("${pname}", pname)
                entries.append((rel_path, match[1] or match[2], expanded, False))
                matched_spans.append(span)
        platforms = re.findall(
            r'"(x86_64-linux|aarch64-linux|x86_64-darwin|aarch64-darwin)"',
            next(iter(re.findall(r"\bplatforms\s*=\s*\[([^\]]*)\]", masked)), ""),
        )
        standalone_urls: list[str] = []
        for _match, inner, span in _brace_blocks(masked, r"\bfetchurl\s*\{"):
            if any(start <= span[0] < end for start, end in matched_spans):
                continue
            url_match = re.search(r'\burl\s*=\s*"([^"]+)"\s*;', inner)
            hash_match = re.search(r'\b(?:hash|sha256)\s*=\s*"([^"]*)"\s*;', inner)
            if not (url_match and hash_match):
                continue
            expanded = url_match[1].replace("${version}", ver)
            if pname:
                expanded = expanded.replace("${pname}", pname)
            standalone_urls.append(expanded)
        darwin_both = {"aarch64-darwin", "x86_64-darwin"}.issubset(platforms)
        for expanded in standalone_urls:
            if len(platforms) == 1:
                entries.append((rel_path, platforms[0], expanded, False))
                continue
            lower = expanded.lower()
            fname_lower = lower.rsplit("/", 1)[-1]
            is_mac = (
                "darwin" in rel_path
                or lower.endswith(".dmg")
                or (bool(platforms) and set(platforms) <= {"aarch64-darwin", "x86_64-darwin"})
                or any(k in lower for k in ("mac", "darwin", "osx"))
            )
            is_arm = any(k in lower for k in ("arm64", "aarch64"))
            is_x86 = any(k in fname_lower for k in ("x86_64", "x64", "amd64", "intel"))
            has_universal = "universal" in fname_lower or (
                "universal" in lower and not is_arm and not is_x86
            )
            if is_mac and (
                has_universal
                or (darwin_both and len(standalone_urls) == 1 and not is_arm and not is_x86)
            ):
                if not platforms or darwin_both:
                    entries.append((rel_path, "aarch64-darwin", expanded, True))
                elif "aarch64-darwin" in platforms:
                    entries.append((rel_path, "aarch64-darwin", expanded, False))
                elif "x86_64-darwin" in platforms:
                    entries.append((rel_path, "x86_64-darwin", expanded, False))
                continue
            inferred = (
                ("aarch64-darwin" if is_arm else "x86_64-darwin")
                if is_mac
                else ("aarch64-linux" if is_arm else "x86_64-linux")
            )
            if not platforms or inferred in platforms:
                entries.append((rel_path, inferred, expanded, False))
    return pname, entries


_DEB_NON_BIN_DIRS = frozenset(
    {
        "doc",
        "etc",
        "include",
        "lib",
        "lib32",
        "lib64",
        "locales",
        "man",
        "resources",
        "share",
        "var",
    }
)


def _is_shared_object(path: str) -> bool:
    lower = path.rsplit("/", 1)[-1].lower()
    return lower.endswith(".so") or ".so." in lower


def _in_deb_bin(rel: str) -> bool:
    if rel.startswith(("usr/bin/", "bin/")):
        return True
    if rel.startswith("opt/"):
        parts = rel.split("/")
        return len(parts) >= 2 and not any(
            part.lower() in _DEB_NON_BIN_DIRS for part in parts[1:-1]
        )
    return False


def _deb_inspect(asset: VerifiedAsset, runtime: Runtime) -> tuple[str, str, str, str, bool]:
    filename = asset.source.filename
    raw_control = _run(runtime, ["dpkg-deb", "-f", str(asset.local_path)]).decode("utf-8")
    control = apt._fields(raw_control)  # pyright: ignore[reportPrivateUsage]
    deb_arch = control.get("Architecture", "")
    system = {"amd64": "x86_64-linux", "arm64": "aarch64-linux"}.get(deb_arch, "")
    if not system:
        raise UnsupportedAsset(f"{filename}: unsupported Nix DEB architecture {deb_arch!r}")
    pkg = mirror.name(control.get("Package", ""))
    deb_ver = control.get("Version", "").partition(":")[2] or control.get("Version", "")
    desc = control.get("Description", "").splitlines()[0].strip()
    fsys = _run(runtime, ["dpkg-deb", "--fsys-tarfile", str(asset.local_path)])
    has_exec = False
    dynamic = False
    exec_files: set[str] = set()
    links: dict[str, str] = {}
    bin_links: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(fsys), mode="r|") as archive:
        for count, member in enumerate(archive, 1):
            if count > MAX_TAR_MEMBERS:
                raise NixFailure("DEB payload exceeds member limit")
            if not (member.isfile() or member.issym() or member.islnk()):
                continue
            rel = posixpath.normpath(member.name.removeprefix("./").lstrip("/"))
            if rel in {"", "."} or rel.startswith("../"):
                continue
            in_bin = _in_deb_bin(rel) and not _is_shared_object(rel)
            if member.issym() or member.islnk():
                if member.islnk() or member.linkname.startswith("/"):
                    target = posixpath.normpath(member.linkname.removeprefix("./").lstrip("/"))
                else:
                    target = posixpath.normpath(
                        posixpath.join(posixpath.dirname(rel), member.linkname)
                    )
                if target not in {"", "."} and not target.startswith("../"):
                    links[rel] = target
                    if in_bin:
                        bin_links.append(rel)
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            data = extracted.read(min(member.size, 16 * 1024 * 1024))
            elf_sys, elf_dyn = elf_binary(data)
            is_exec_mode = (member.mode & 0o111) != 0 and not _is_shared_object(rel)
            if elf_sys:
                if elf_sys != system:
                    raise NixFailure(f"{filename}: DEB header {deb_arch} disagrees with {elf_sys}")
                dynamic = dynamic or elf_dyn
                if is_exec_mode:
                    exec_files.add(rel)
                    if in_bin:
                        has_exec = True
            elif is_exec_mode and not data.startswith(b"\x7fELF") and member.size > 0:
                exec_files.add(rel)
                if in_bin:
                    has_exec = True
    if not has_exec:
        for link in bin_links:
            seen: set[str] = set()
            cur = link
            while cur in links and cur not in seen and len(seen) < 16:
                seen.add(cur)
                cur = links[cur]
            if cur in exec_files:
                has_exec = True
                break
    if not has_exec:
        raise UnsupportedAsset(f"{filename}: DEB contains no executable program")
    return pkg, deb_ver, system, desc, dynamic


def _zip_executable(path: Path, app: str) -> str:
    with zipfile.ZipFile(path) as archive:
        plist = archive.read(f"{app}/Contents/Info.plist")
    executable = plistlib.loads(plist).get("CFBundleExecutable")
    if not isinstance(executable, str) or not executable or "/" in executable:
        raise NixFailure(f"Missing CFBundleExecutable in {app}")
    return executable


def _effective_version(tag: str, fallback: str) -> str:
    cleaned = mirror.version(tag)
    if re.match(r"\d", cleaned) is not None:
        return cleaned
    return fallback or cleaned


def inspect(
    asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
) -> InspectedAsset:
    if policy.format != "nix":
        raise NixFailure("Expected the Nix format policy")
    mirror.check(asset)
    filename = asset.source.filename
    repo_tool = mirror.name(asset.source.repository.split("/")[1])
    tag, description, licence = discovery.release_details(asset.source, runtime)
    upstream = discovery.tag_nix_files(asset.source.repository, tag, runtime)
    if upstream is not None:
        ver = mirror.version(tag)
        pname, entries = _upstream_sources(upstream, ver)
        pname = pname or repo_tool
        matches = [
            (rel_path, system, url, universal)
            for rel_path, system, url, universal in entries
            if url == asset.source.public_url or url.rsplit("/", 1)[-1] == filename
        ]
        if not matches:
            raise UnsupportedAsset(
                f"{filename}: not referenced by {asset.source.repository} nix/ expressions"
            )
        if len({(system, universal) for _, system, _, universal in matches}) != 1:
            raise NixFailure(f"{filename}: ambiguous system mapping in nix/ expressions")
        _, system, _, universal = matches[0]
        for sys_name in ("aarch64-darwin", "x86_64-darwin") if universal else (system,):
            if sys_name not in policy.architectures:
                raise UnsupportedAsset(f"{filename}: unsupported Nix system {sys_name!r}")
        if not mirror.valid(pname, ver):
            raise UnsupportedAsset(f"{filename}: invalid Nix package name or version")
        metadata: dict[str, JSONValue] = {
            "mode": "upstream-nix",
            "desc": description,
            "license": licence,
            "tag": tag,
            "nix_files": dict(upstream),
        }
        if universal:
            metadata["universal"] = True
        return InspectedAsset(
            asset, NativeIdentity("nix", pname, system, ver), metadata, {}, "unsigned"
        )
    if filename.lower().endswith(".tar.gz"):
        _run(runtime, ["tar", "-tzf", str(asset.local_path)])
        tar_ver = match[1] if (match := _TARBALL_VERSION.fullmatch(filename)) else ""
        ver = _effective_version(tag, tar_ver)
        hint = scoop.tool(filename.removesuffix(".tar.gz") + ".zip") or repo_tool
        binary, system, dynamic, universal = _tarball_binary(asset.local_path, hint)
        if not binary or not system:
            raise UnsupportedAsset(f"{filename}: no single supported Linux or macOS executable")
        pname = mirror.name(binary.rsplit("/", 1)[-1])
        if not mirror.valid(pname, ver):
            raise UnsupportedAsset(f"{filename}: invalid Nix package name or version")
        if system not in policy.architectures:
            raise UnsupportedAsset(f"{filename}: unsupported Nix system {system!r}")
        metadata = {
            "mode": "tarball",
            "desc": description,
            "license": licence,
            "binary": binary,
            "dynamic_elf": dynamic,
        }
        if universal:
            metadata["universal"] = True
        return InspectedAsset(
            asset, NativeIdentity("nix", pname, system, ver), metadata, {}, "unsigned"
        )
    if filename.endswith(".deb"):
        pname, deb_ver, system, deb_desc, dynamic = _deb_inspect(asset, runtime)
        ver = _effective_version(tag, deb_ver)
        if not mirror.valid(pname, ver) or system not in policy.architectures:
            raise UnsupportedAsset(f"{filename}: invalid Nix DEB identity or system {system!r}")
        metadata = {
            "mode": "deb",
            "desc": description or deb_desc,
            "license": licence,
            "dynamic_elf": dynamic,
        }
        return InspectedAsset(
            asset, NativeIdentity("nix", pname, system, ver), metadata, {}, "unsigned"
        )
    if filename.endswith(".zip"):
        app, archs = brew.zip_app(asset.local_path)
        if not app or not archs:
            raise UnsupportedAsset(f"{filename}: not a zip file of one macOS app")
        executable = _zip_executable(asset.local_path, app)
        mac = tuple({"arm": "aarch64-darwin", "intel": "x86_64-darwin"}[a] for a in archs)
        universal = len(mac) > 1
        system = "aarch64-darwin" if universal else mac[0]
        pname = brew.token(filename, app)
        ver = mirror.version(tag)
        if not mirror.valid(pname, ver) or system not in policy.architectures:
            raise UnsupportedAsset(f"{filename}: invalid Nix app name, version, or system")
        metadata = {
            "mode": "zip",
            "desc": description,
            "license": licence,
            "app": app,
            "executable": executable,
        }
        if universal:
            metadata["universal"] = True
        return InspectedAsset(
            asset, NativeIdentity("nix", pname, system, ver), metadata, {}, "unsigned"
        )
    raise UnsupportedAsset(f"{filename}: macOS disk images require a nix/ package expression")


def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
    same = (left.format, left.name, left.architecture, left.version) == (
        right.format,
        right.name,
        right.architecture,
        right.version,
    )
    return 0 if same else None


def _classify(key: str) -> tuple[str, str, bool, int]:
    if _NAR.fullmatch(key):
        return "package", "application/x-nix-nar", False, 0
    if _NARINFO.fullmatch(key):
        return "dependency", "text/x-nix-narinfo", False, 1
    if key == PUBKEY_KEY or _GIT_TAG.fullmatch(key):
        return "dependency", "text/plain; charset=utf-8", False, 1
    if _GIT_OBJECT.fullmatch(key):
        return "dependency", "application/octet-stream", False, 1
    if key == CACHE_INFO_KEY:
        return "entry", "text/x-nix-cache-info", True, 2
    if key in _GIT_ENTRIES:
        return "entry", "text/plain; charset=utf-8", True, 3 + _GIT_ENTRIES.index(key)
    raise NixFailure(f"Unexpected public Nix object: {key}")


def validate_retained(retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    if policy.format != "nix" or retained.format != "nix":
        raise NixFailure("Expected Nix retained state")
    if not retained.accepted_history:
        if retained.metadata or retained.objects or retained.active_identities:
            raise NixFailure("Incomplete initial Nix retained state")
        return
    if retained.active_identities != tuple(
        item.inspected.identity for item in retained.accepted_history
    ):
        raise NixFailure("Retained Nix active identities differ from accepted history")
    refs = {ref.key: ref for ref in retained.objects}
    if len(refs) != len(retained.objects):
        raise NixFailure("Duplicate retained Nix object keys")
    head = _string(retained.metadata.get("head"), "Git head")
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise NixFailure("Invalid retained Nix Git head")
    pub_val = _string(retained.metadata.get("public_key"), "public key")
    if not pub_val.startswith(f"{NIX_KEY_NAME}:"):
        raise NixFailure("Unexpected retained Nix public key name")
    if re.fullmatch(r"[A-F0-9]{40}", _string(retained.metadata.get("fingerprint"))) is None:
        raise NixFailure("Invalid retained Nix signing fingerprint")
    _mapping(retained.metadata.get("flake_lock"), "flake lock")
    files = _mapping(retained.metadata.get("files"), "working-set files")
    stale = stale_entries(retained)
    expected_working = {
        key
        for key in refs
        if key == PUBKEY_KEY
        or key in _ENTRIES
        or _GIT_OBJECT.fullmatch(key) is not None
        or _GIT_TAG.fullmatch(key) is not None
    }
    if set(files) != expected_working or any(entry not in refs for entry in _ENTRIES):
        raise NixFailure("Retained Nix working set or entry closure is incomplete")
    if f"{REPO}/refs/tags/{head}" not in refs or PUBKEY_KEY not in refs:
        raise NixFailure("Retained Nix head tag or public key object is missing")
    for key, ref in refs.items():
        kind, content_type, mutable, _ = _classify(key)
        if ref.object_class != kind or ref.content_type != content_type:
            raise NixFailure(f"Retained Nix object metadata mismatch for {key}")
        if ref.cache_control != ("no-cache" if mutable else IMMUTABLE):
            raise NixFailure(f"Retained Nix cache policy mismatch for {key}")
        if key in files and key not in stale:
            local = Path(_string(files[key], "file path"))
            if sha256_file(local) != (ref.sha256, ref.size):
                raise NixFailure(f"Retained Nix file {key} is missing or corrupt")
    if CACHE_INFO_KEY not in stale:
        cache_info_path = Path(_string(files[CACHE_INFO_KEY], "nix-cache-info path"))
        if cache_info_path.read_bytes() != CACHE_INFO:
            raise NixFailure("Retained nix-cache-info differs from required cache settings")
    pub_path = Path(_string(files[PUBKEY_KEY], "public key path"))
    if pub_path.read_text(encoding="utf-8").strip() != pub_val:
        raise NixFailure("Retained keys/haberdasher-nix.pub differs from retained public_key")


def _nix_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("${", "\\${")
    return f'"{escaped}"'


def _meta_block(item: InspectedAsset, pname: str, systems: Sequence[str]) -> str:
    desc = item.metadata.get("desc")
    licence = item.metadata.get("license")
    lines = ["  meta = {"]
    if isinstance(desc, str) and desc:
        lines.append(f"    description = {_nix_str(desc)};")
    lines.append(
        f"    homepage = {_nix_str(f'https://github.com/{item.verified.source.repository}')};"
    )
    if isinstance(licence, str) and licence in LICENCES:
        lines.append(f"    license = lib.licenses.{LICENCES[licence]};")
    lines.append("    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];")
    platforms = " ".join(_nix_str(sys_name) for sys_name in systems)
    lines.append(f"    platforms = [ {platforms} ];")
    lines.append(f"    mainProgram = {_nix_str(pname)};")
    lines.append("  };")
    return "\n".join(lines)


def _item_systems(item: InspectedAsset) -> tuple[str, ...]:
    if item.metadata.get("universal") is True:
        return ("aarch64-darwin", "x86_64-darwin")
    return (item.identity.architecture,)


def _ordered_systems(systems: set[str]) -> tuple[str, ...]:
    return tuple(sys_name for sys_name in SYSTEMS if sys_name in systems)


@dataclass(frozen=True)
class _SourceBlock:
    system: str | None
    inner_span: tuple[int, int]
    remove_span: tuple[int, int] | None


def _find_source_blocks(content: str) -> list[_SourceBlock]:
    masked = _mask_nix(content)
    code_only = _mask_nix(content, mask_strings=True)
    blocks: list[_SourceBlock] = []
    sys_spans: list[tuple[int, int]] = []
    for match, inner, (inner_start, inner_end) in _brace_blocks(masked, _SYSTEM_BLOCK_HEADER):
        urls = re.findall(r'\burl\s*=\s*"[^"]+"\s*;', inner)
        hashes = re.findall(r'\b(?:hash|sha256)\s*=\s*"[^"]*"\s*;', inner)
        if len(urls) != 1 or len(hashes) != 1:
            continue
        semi = re.match(r"\s*;", masked[inner_end + 1 :])
        remove_span: tuple[int, int] | None = None
        if semi is not None:
            stmt_start = match.start()
            remove_start = stmt_start
            while remove_start > 0 and content[remove_start - 1] in {" ", "\t"}:
                remove_start -= 1
            after_semi = inner_end + 1 + semi.end()
            if remove_start == 0 or content[remove_start - 1] == "\n":
                nl = re.match(r"[ \t]*\r?\n", content[after_semi:])
                remove_end = after_semi + (nl.end() if nl else 0)
            else:
                remove_start = stmt_start
                ws = re.match(r"[ \t]*", content[after_semi:])
                remove_end = after_semi + (ws.end() if ws else 0)
            remove_span = (remove_start, remove_end)
        sys_spans.append((inner_start, inner_end))
        blocks.append(_SourceBlock(match[1] or match[2], (inner_start, inner_end), remove_span))
    for _match, _inner, (inner_start, inner_end) in _brace_blocks(
        masked, r"\b(?:fetchurl|fetchzip|fetchTarball)\s*\{"
    ):
        if any(start <= inner_start and inner_end <= end for start, end in sys_spans):
            continue
        inner_code = code_only[inner_start:inner_end]
        if re.search(r"\b(?:url|hash|sha256|outputHash)\s*=", inner_code):
            blocks.append(_SourceBlock(None, (inner_start, inner_end), None))
    return blocks


def _replace_fetchurl_block(
    body: str, pname: str, ver: str, pub_url: str, fname: str, sri: str
) -> tuple[str, bool]:
    masked = _mask_nix(body)
    url_ms = list(re.finditer(r'\burl\s*=\s*"([^"]+)"\s*;', masked))
    hash_ms = list(re.finditer(r'\b(?:hash|sha256)\s*=\s*"([^"]*)"\s*;', masked))
    if len(url_ms) != 1 or len(hash_ms) != 1:
        return body, False
    url_m, hash_m = url_ms[0], hash_ms[0]
    expanded = url_m[1].replace("${version}", ver).replace("${pname}", pname)
    if expanded != pub_url and expanded.rsplit("/", 1)[-1] != fname:
        return body, False
    edits = sorted(
        [
            (url_m.start(), url_m.end(), f"url = {_nix_str(pub_url)};"),
            (hash_m.start(), hash_m.end(), f"hash = {_nix_str(sri)};"),
        ]
    )
    new_body = body
    for start, end, replacement in reversed(edits):
        new_body = new_body[:start] + replacement + new_body[end:]
    return new_body, True


def _rewrite_upstream_nix(
    items: Sequence[InspectedAsset],
) -> tuple[dict[str, str], tuple[str, ...]]:
    first = items[0]
    pname, ver = first.identity.name, first.identity.version
    raw_files = _mapping(items[-1].metadata.get("nix_files"), "upstream nix_files")
    candidates = {
        rel: _string(text, "upstream nix content")
        for rel, text in sorted(raw_files.items())
        if rel != "flake.nix"
    }
    blocks_by_file = {rel: _find_source_blocks(content) for rel, content in candidates.items()}
    replacements: dict[tuple[str, int], str] = {}
    admitted_systems: set[str] = set()
    for item in items:
        item_sys = _item_systems(item)
        admitted_systems.update(item_sys)
        sri = _sri(item.verified.sha256)
        pub_url = item.verified.source.public_url
        fname = item.verified.source.filename
        updated = False
        for target_sys in item_sys:
            matched_sys = False
            for rel, blocks in blocks_by_file.items():
                content = candidates[rel]
                for idx, block in enumerate(blocks):
                    if block.system != target_sys or (rel, idx) in replacements:
                        continue
                    inner = content[block.inner_span[0] : block.inner_span[1]]
                    new_inner, hit = _replace_fetchurl_block(inner, pname, ver, pub_url, fname, sri)
                    if hit:
                        replacements[(rel, idx)] = new_inner
                        updated = True
                        matched_sys = True
                        break
                if matched_sys:
                    break
        if not updated:
            for rel, blocks in blocks_by_file.items():
                content = candidates[rel]
                for idx, block in enumerate(blocks):
                    if block.system is not None or (rel, idx) in replacements:
                        continue
                    inner = content[block.inner_span[0] : block.inner_span[1]]
                    new_inner, hit = _replace_fetchurl_block(inner, pname, ver, pub_url, fname, sri)
                    if hit:
                        replacements[(rel, idx)] = new_inner
                        updated = True
                        break
                if updated:
                    break
        if not updated:
            raise NixFailure(f"Could not bind verified hash for {fname} in {pname} nix/ files")
    pkg_files: dict[str, str] = {}
    for rel, content in candidates.items():
        blocks = blocks_by_file[rel]
        matched_idxs = {idx for idx in range(len(blocks)) if (rel, idx) in replacements}
        if not matched_idxs:
            continue
        edits: list[tuple[int, int, str]] = []
        for idx, block in enumerate(blocks):
            if idx in matched_idxs:
                edits.append((block.inner_span[0], block.inner_span[1], replacements[(rel, idx)]))
            elif block.remove_span is not None:
                edits.append((block.remove_span[0], block.remove_span[1], ""))
            else:
                raise NixFailure(f"Unmatched fetchurl block in {pname} {rel}")
        edits.sort(key=lambda item: (item[0], item[1]))
        if any(edits[i - 1][1] > edits[i][0] for i in range(1, len(edits))):
            raise NixFailure(f"Overlapping source blocks in {pname} {rel}")
        for start, end, replacement in reversed(edits):
            content = content[:start] + replacement + content[end:]
        code_only = _mask_nix(content, mask_strings=True)
        url_count = len(re.findall(r"\burl\s*=", code_only))
        hash_count = len(re.findall(r"\b(?:hash|sha256|outputHash)\s*=", code_only))
        bare_fetch = re.search(
            r'\b(?:fetchurl|fetchzip|fetchTarball|fetchGit|fetchTree)\s*"', code_only
        )
        if url_count != len(matched_idxs) or hash_count != len(matched_idxs) or bare_fetch:
            raise NixFailure(f"Unverified source attribute remains in {pname} {rel}")
        leaf = rel.removeprefix("nix/")
        target_leaf = "upstream.nix" if leaf == "default.nix" else leaf
        pkg_files[f"pkgs/{pname}/{target_leaf}"] = content
    has_darwin = f"pkgs/{pname}/darwin.nix" in pkg_files
    non_darwin = [
        f"./{leaf}"
        for leaf in ("linux.nix", "package.nix", "upstream.nix")
        if f"pkgs/{pname}/{leaf}" in pkg_files
    ]
    if len(non_darwin) > 1 or (not has_darwin and not non_darwin):
        raise NixFailure(f"Invalid matched Nix expression set for {pname}")
    if has_darwin and non_darwin:
        dispatch = (
            f"if stdenv.hostPlatform.isDarwin then call ./darwin.nix else call {non_darwin[0]}"
        )
    elif has_darwin:
        dispatch = "call ./darwin.nix"
    else:
        dispatch = f"call {non_darwin[0]}"
    ordered = _ordered_systems(admitted_systems)
    platforms = " ".join(_nix_str(sys_name) for sys_name in ordered)
    pkg_files[f"pkgs/{pname}/default.nix"] = (
        "{\n"
        "  lib,\n"
        "  stdenv,\n"
        "  callPackage,\n"
        "}:\n"
        "let\n"
        "  call =\n"
        "    file:\n"
        "    let\n"
        "      fn = import file;\n"
        "      args = lib.optionalAttrs ((builtins.functionArgs fn) ? version) {\n"
        f"        version = {_nix_str(ver)};\n"
        "      };\n"
        "    in\n"
        "    callPackage fn args;\n"
        "in\n"
        f"if builtins.elem stdenv.hostPlatform.system [ {platforms} ] then\n"
        f"  {dispatch}\n"
        "else\n"
        f'  throw "{pname} is not available on ${{stdenv.hostPlatform.system}}"\n'
    )
    return pkg_files, ordered


def _tarball_nix(items: Sequence[InspectedAsset]) -> tuple[str, tuple[str, ...]]:
    first = items[0]
    pname, ver = first.identity.name, first.identity.version
    by_system: dict[str, InspectedAsset] = {}
    for item in items:
        for sys_name in _item_systems(item):
            by_system[sys_name] = item
    systems = _ordered_systems(set(by_system))
    src_entries: list[str] = []
    for sys_name in systems:
        item = by_system[sys_name]
        binary = _string(item.metadata.get("binary"), "tarball binary")
        dynamic = "true" if item.metadata.get("dynamic_elf") else "false"
        src_entries.append(
            f"    {sys_name} = {{\n"
            f"      url = {_nix_str(item.verified.source.public_url)};\n"
            f"      hash = {_nix_str(_sri(item.verified.sha256))};\n"
            f"      bin = {_nix_str(binary)};\n"
            f"      dynamic = {dynamic};\n"
            "    };"
        )
    expr = (
        "{\n"
        "  lib,\n"
        "  fetchurl,\n"
        "  stdenv,\n"
        "  stdenvNoCC,\n"
        "  autoPatchelfHook,\n"
        "}:\n"
        "let\n"
        "  inherit (stdenvNoCC.hostPlatform) system;\n"
        "  sources = {\n" + "\n".join(src_entries) + "\n  };\n"
        "  source = sources.${system};\n"
        "in\n"
        "(if source.dynamic then stdenv else stdenvNoCC).mkDerivation {\n"
        f"  pname = {_nix_str(pname)};\n"
        f"  version = {_nix_str(ver)};\n"
        "  src = fetchurl {\n"
        "    inherit (source) url hash;\n"
        "  };\n"
        '  sourceRoot = ".";\n'
        "  nativeBuildInputs = lib.optionals source.dynamic [ autoPatchelfHook ];\n"
        "  buildInputs = lib.optionals source.dynamic [ stdenv.cc.cc.lib ];\n"
        "  dontConfigure = true;\n"
        "  dontBuild = true;\n"
        "  dontFixup = !source.dynamic;\n"
        "  installPhase = ''\n"
        "    runHook preInstall\n"
        f'    install -Dm755 -- ${{lib.escapeShellArg source.bin}} "$out/bin/{pname}"\n'
        "    runHook postInstall\n"
        "  '';\n" + _meta_block(first, pname, systems) + "\n}\n"
    )
    return expr, systems


def _fallback_nix(items: Sequence[InspectedAsset]) -> tuple[str, tuple[str, ...]]:
    first = items[0]
    pname, ver = first.identity.name, first.identity.version
    by_system: dict[str, InspectedAsset] = {}
    for item in items:
        for sys_name in _item_systems(item):
            by_system[sys_name] = item
    systems = _ordered_systems(set(by_system))
    src_entries: list[str] = []
    for sys_name in systems:
        item = by_system[sys_name]
        kind = _string(item.metadata.get("mode"), "fallback mode")
        if kind not in {"deb", "zip"}:
            raise NixFailure(f"Unsupported Nix fallback mode {kind!r}")
        dynamic = "true" if item.metadata.get("dynamic_elf") else "false"
        app = item.metadata.get("app")
        exe = item.metadata.get("executable")
        app_line = f"      app = {_nix_str(app)};\n" if isinstance(app, str) else ""
        exe_line = f"      exe = {_nix_str(exe)};\n" if isinstance(exe, str) else ""
        src_entries.append(
            f"    {sys_name} = {{\n"
            f"      url = {_nix_str(item.verified.source.public_url)};\n"
            f"      hash = {_nix_str(_sri(item.verified.sha256))};\n"
            f"      kind = {_nix_str(kind)};\n"
            f"      dynamic = {dynamic};\n" + app_line + exe_line + "    };"
        )
    expr = (
        "{\n"
        "  lib,\n"
        "  fetchurl,\n"
        "  stdenv,\n"
        "  stdenvNoCC,\n"
        "  bintools,\n"
        "  gnutar,\n"
        "  xz,\n"
        "  zstd,\n"
        "  autoPatchelfHook,\n"
        "  unzip,\n"
        "  makeWrapper,\n"
        "}:\n"
        "let\n"
        "  inherit (stdenvNoCC.hostPlatform) system;\n"
        "  sources = {\n" + "\n".join(src_entries) + "\n  };\n"
        "  source = sources.${system};\n"
        "in\n"
        "(if source.dynamic then stdenv else stdenvNoCC).mkDerivation {\n"
        f"  pname = {_nix_str(pname)};\n"
        f"  version = {_nix_str(ver)};\n"
        "  src = fetchurl {\n"
        "    inherit (source) url hash;\n"
        "  };\n"
        "  nativeBuildInputs =\n"
        '    lib.optionals (source.kind == "deb") (\n'
        "      [\n"
        "        bintools\n"
        "        gnutar\n"
        "        xz\n"
        "        zstd\n"
        "      ]\n"
        "      ++ lib.optionals source.dynamic [ autoPatchelfHook ]\n"
        "    )\n"
        '    ++ lib.optionals (source.kind == "zip") [\n'
        "      unzip\n"
        "      makeWrapper\n"
        "    ];\n"
        "  buildInputs = lib.optionals source.dynamic [ stdenv.cc.cc.lib ];\n"
        "  dontConfigure = true;\n"
        "  dontBuild = true;\n"
        "  dontFixup = !source.dynamic;\n"
        "  unpackPhase =\n"
        '    if source.kind == "deb" then\n'
        "      ''\n"
        '        ${lib.getExe\' bintools "ar"} x "$src"\n'
        "        tar xf data.tar.*\n"
        "      ''\n"
        "    else\n"
        "      ''\n"
        '        unzip -q "$src"\n'
        "      '';\n"
        "  installPhase =\n"
        '    if source.kind == "deb" then\n'
        "      ''\n"
        "        runHook preInstall\n"
        '        mkdir -p "$out"\n'
        "        for dir in usr/bin usr/share usr/lib usr/libexec; do\n"
        '          if [ -d "$dir" ]; then\n'
        "            target=\"$out/''${dir#usr/}\"\n"
        '            mkdir -p "$target"\n'
        '            cp -a "$dir"/. "$target"/\n'
        "          fi\n"
        "        done\n"
        "        for dir in bin lib opt etc; do\n"
        '          if [ -d "$dir" ]; then\n'
        '            mkdir -p "$out/$dir"\n'
        '            cp -a "$dir"/. "$out/$dir"/\n'
        "          fi\n"
        "        done\n"
        "        runHook postInstall\n"
        "      ''\n"
        "    else\n"
        "      ''\n"
        "        runHook preInstall\n"
        '        mkdir -p "$out/Applications" "$out/bin"\n'
        '        cp -R -- ${lib.escapeShellArg source.app} "$out/Applications/"\n'
        '        makeWrapper "$out/Applications/"'
        '${lib.escapeShellArg "${source.app}/Contents/MacOS/${source.exe}"} '
        f'"$out/bin/{pname}"\n'
        "        runHook postInstall\n"
        "      '';\n" + _meta_block(first, pname, systems) + "\n}\n"
    )
    return expr, systems


def _flake_nix(package_systems: Mapping[str, tuple[str, ...]], nixpkgs_url: str) -> str:
    all_systems = _ordered_systems(
        {sys_name for group in package_systems.values() for sys_name in group}
    )
    sys_blocks: list[str] = []
    for sys_name in all_systems:
        names = [name for name, group in sorted(package_systems.items()) if sys_name in group]
        attrs = [f"          {name} = pkgs.callPackage ./pkgs/{name} {{ }};" for name in names]
        if len(package_systems) == 1 and len(names) == 1:
            attrs.append(f"          default = pkgs.callPackage ./pkgs/{names[0]} {{ }};")
        body = "\n".join(attrs)
        sys_blocks.append(
            f"      {sys_name} =\n"
            f"        let\n"
            f"          pkgs = import nixpkgs {{ system = {_nix_str(sys_name)}; }};\n"
            f"        in\n"
            f"        {{\n{body}\n        }};"
        )
    overlay_parts: list[str] = []
    for name, group in sorted(package_systems.items()):
        platforms = " ".join(_nix_str(sys_name) for sys_name in group)
        overlay_parts.append(
            f"        prev.lib.optionalAttrs (builtins.elem system [ {platforms} ]) {{\n"
            f"          {name} = final.callPackage ./pkgs/{name} {{ }};\n"
            "        }"
        )
    if overlay_parts:
        joined = "\n        // ".join(
            part.lstrip() if idx else part for idx, part in enumerate(overlay_parts)
        )
        overlay_block = (
            "      overlays.default =\n"
            "        final: prev:\n"
            "        let\n"
            "          inherit (prev.stdenv.hostPlatform) system;\n"
            "        in\n" + joined + ";\n"
        )
    else:
        overlay_block = "      overlays.default = _final: _prev: { };\n"
    return (
        "{\n"
        '  description = "Nix packages published by Haberdasher";\n\n'
        "  inputs = {\n"
        f"    nixpkgs.url = {_nix_str(nixpkgs_url)};\n"
        "  };\n\n"
        "  outputs =\n"
        "    { nixpkgs, ... }:\n"
        "    {\n" + overlay_block + "      packages = {\n" + "\n".join(sys_blocks) + "\n      };\n"
        "    };\n"
        "}\n"
    )


def _flake_lock(retained: RetainedFormat, runtime: Runtime) -> tuple[dict[str, JSONValue], str]:
    existing = retained.metadata.get("flake_lock")
    if isinstance(existing, dict):
        nodes = _mapping(existing.get("nodes"), "flake.lock nodes")
        nixpkgs_node = _mapping(nodes.get("nixpkgs"), "flake.lock nixpkgs")
        orig = _mapping(nixpkgs_node.get("original"), "flake.lock original")
        ref = orig.get("ref")
        suffix = f"/{ref}" if isinstance(ref, str) and ref else ""
        url = f"github:{_string(orig.get('owner'))}/{_string(orig.get('repo'))}{suffix}"
        return existing, url
    raw = json.loads(_run(runtime, ["haberdasher-nixpkgs"]))
    if not isinstance(raw, dict):
        raise NixFailure("Invalid haberdasher-nixpkgs output")
    payload = cast(dict[str, JSONValue], raw)
    locked = _mapping(payload.get("locked"), "nixpkgs locked")
    original = _mapping(payload.get("original"), "nixpkgs original")
    ref = original.get("ref")
    suffix = f"/{ref}" if isinstance(ref, str) and ref else ""
    url = f"github:{_string(original.get('owner'))}/{_string(original.get('repo'))}{suffix}"
    lock_doc: dict[str, JSONValue] = {
        "nodes": {
            "nixpkgs": {"locked": locked, "original": original},
            "root": {"inputs": {"nixpkgs": "nixpkgs"}},
        },
        "root": "root",
        "version": 7,
    }
    return lock_doc, url


def readme(names: Sequence[str]) -> str:
    url = PUBLIC["nix"][1]
    installs = "\n".join(f"nix profile add 'git+{url}/{REPO}#{name}'" for name in names)
    return (
        "# Haberdasher Nix flake\n\n"
        "Nix packages and signed binary cache for projects by Martin Wimpress.\n"
        f"Haberdasher writes this repository. See {url}/ for details.\n\n"
        "```sh\n"
        f"{installs}\n"
        "```\n"
    )


def _repo_files(
    history: Sequence[AdmittedAsset],
    lock_doc: dict[str, JSONValue],
    nixpkgs_url: str,
    runtime: Runtime,
    work: Path,
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    grouped = mirror.latest(history)
    files: dict[str, str] = {}
    package_systems: dict[str, tuple[str, ...]] = {}
    for pname, items in grouped.items():
        modes = {_string(item.metadata.get("mode"), "package mode") for item in items}
        if "upstream-nix" in modes:
            if modes != {"upstream-nix"}:
                raise NixFailure(f"Conflicting Nix modes for {pname}")
            pkg_files, systems = _rewrite_upstream_nix(items)
            files.update(pkg_files)
            package_systems[pname] = systems
        elif "tarball" in modes:
            if modes != {"tarball"}:
                raise NixFailure(f"Conflicting Nix modes for {pname}")
            expr, systems = _tarball_nix(items)
            files[f"pkgs/{pname}/default.nix"] = expr
            package_systems[pname] = systems
        else:
            expr, systems = _fallback_nix(items)
            files[f"pkgs/{pname}/default.nix"] = expr
            package_systems[pname] = systems
    files["flake.nix"] = _flake_nix(package_systems, nixpkgs_url)
    fmt_dir = safe_path(work, "nixfmt")
    fmt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    nix_paths: list[str] = []
    for rel, content in sorted(files.items()):
        if not rel.endswith(".nix"):
            continue
        target = safe_path(fmt_dir, rel)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_write(target, content.encode("utf-8"))
        nix_paths.append(str(target))
    if nix_paths:
        _run(runtime, ["nixfmt", *nix_paths])
        for rel in sorted(files):
            if rel.endswith(".nix"):
                files[rel] = safe_path(fmt_dir, rel).read_text(encoding="utf-8")
    files["flake.lock"] = json.dumps(lock_doc, indent=2, sort_keys=True) + "\n"
    files["README.md"] = readme(list(grouped))
    return files, package_systems


def prepare(
    new: Sequence[AdmittedAsset],
    retained: RetainedFormat,
    *,
    policy: FormatPolicy,
    runtime: Runtime,
    signer: SigningSession,
    now: datetime,
    out: Path,
) -> PreparedFormat:
    validate_retained(retained, policy=policy, runtime=runtime)
    if retained.accepted_history and retained.metadata.get("fingerprint") != signer.fingerprint:
        raise NixFailure("Nix signing primary changed without a trust transition")
    history = list(retained.accepted_history)
    additions: list[AdmittedAsset] = []
    for candidate in new:
        if candidate in history:
            continue
        if candidate.transformation_policy != "preserve":
            raise NixFailure("Unexpected Nix transformation policy")
        mirror.check(candidate.inspected.verified)
        admitted = replace(candidate, published_sha256=candidate.inspected.verified.sha256)
        additions.append(admitted)
        history.append(admitted)
    stale = stale_entries(retained)
    if not additions and not stale:
        return PreparedFormat("nix", retained, (), retained.objects)
    if not history:
        return PreparedFormat("nix", retained, (), retained.objects)
    out = safe_path(out, "validation").parent
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret_key, public_key_file, public_value = signer.nix_key()
    if retained.accepted_history and retained.metadata.get("public_key") != public_value:
        raise NixFailure("Derived Nix public key changed without a trust transition")
    lock_doc, nixpkgs_url = _flake_lock(retained, runtime)
    repo_files, package_systems = _repo_files(history, lock_doc, nixpkgs_url, runtime, out)
    restored = _mapping(retained.metadata.get("files", {})) if retained.accepted_history else {}
    git_objects = {
        key.removeprefix(f"{REPO}/"): Path(_string(path))
        for key, path in restored.items()
        if _GIT_OBJECT.fullmatch(key) is not None or _GIT_TAG.fullmatch(key) is not None
    }
    head, repo = mirror.repository(
        git_objects,
        _string(retained.metadata["head"]) if retained.accepted_history else None,
        repo_files,
        runtime=runtime,
        out=out / "git",
        now=now,
        message="Update Nix packages",
        tag_head=True,
    )
    seed_root = safe_path(out, "seed")
    seed_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for index, item in enumerate(additions):
        verified = item.inspected.verified
        slot = safe_path(seed_root, f"{index}/{verified.source.filename}")
        slot.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.link(verified.local_path, slot)
        except OSError:
            shutil.copyfile(verified.local_path, slot)
        _nix(runtime, "store", "add-file", str(slot))
    old_refs = {ref.key: ref for ref in retained.objects}
    archive_raw = json.loads(
        _nix(runtime, "flake", "archive", "--json", f"git+file://{repo}", flakes=True)
    )
    flake_path = _string(_mapping(cast(JSONValue, archive_raw)).get("path"), "flake store path")
    flake_key = flake_path.removeprefix("/nix/store/")
    export_keys: set[str] = set()
    stub_entries: dict[str, dict[str, JSONValue]] = {}
    if f"{flake_key.split('-', 1)[0]}.narinfo" not in old_refs:
        export_keys.add(flake_key)
    host_system = (
        _nix(runtime, "eval", "--raw", "--impure", "--expr", "builtins.currentSystem")
        .decode("utf-8")
        .strip()
    )
    for pname, systems in sorted(package_systems.items()):
        if host_system not in systems:
            continue
        target = f"git+file://{repo}#packages.{host_system}.{pname}"
        out_path = _nix(runtime, "eval", "--raw", f"{target}.outPath", flakes=True).decode().strip()
        out_key = out_path.removeprefix("/nix/store/")
        out_hash = out_key.split("-", 1)[0]
        if f"{out_hash}.narinfo" in old_refs:
            continue
        _nix(runtime, "build", "--no-link", "--print-out-paths", target, flakes=True)
        info_doc = _mapping(
            cast(
                JSONValue,
                json.loads(
                    _nix(runtime, "path-info", "--json", "--json-format", "2", "-r", out_path)
                ),
            ),
            "path-info",
        )
        info_map = _mapping(info_doc.get("info"), "path-info map")
        export_keys.add(out_key)
        for store_key, raw_entry in info_map.items():
            entry = _mapping(raw_entry, "path-info entry")
            if store_key == out_key:
                continue
            h32 = store_key.split("-", 1)[0]
            sigs = entry.get("signatures", [])
            sigs_list = sigs if isinstance(sigs, list) else []
            is_upstream = any(
                isinstance(sig, str) and sig.startswith("cache.nixos.org-1:") for sig in sigs_list
            )
            if not is_upstream and f"{h32}.narinfo" not in old_refs:
                export_keys.add(store_key)
            else:
                stub_entries[store_key] = entry
    cache_dir = safe_path(out, "cache")
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if export_keys:
        stub_hashes: set[str] = set()
        for store_key, entry in stub_entries.items():
            if store_key in export_keys:
                continue
            h32 = store_key.split("-", 1)[0]
            stub_hashes.add(h32)
            raw_refs = entry.get("references", [])
            ref_list = [str(r) for r in raw_refs] if isinstance(raw_refs, list) else []
            stub = (
                f"StorePath: /nix/store/{store_key}\n"
                f"URL: nar/{'0' * 52}.nar.zst\n"
                "Compression: zstd\n"
                f"NarHash: {_string(entry.get('narHash'), 'narHash')}\n"
                f"NarSize: {entry.get('narSize')}\n"
                f"References: {' '.join(sorted(ref_list))}\n"
            )
            atomic_write(safe_path(cache_dir, f"{h32}.narinfo"), stub.encode("utf-8"))
        store_paths = [f"/nix/store/{store_key}" for store_key in sorted(export_keys)]
        _nix(
            runtime,
            "copy",
            "--no-recursive",
            "--to",
            f"file://{cache_dir}?compression=zstd&secret-key={secret_key}",
            *store_paths,
        )
        for h32 in stub_hashes:
            safe_path(cache_dir, f"{h32}.narinfo").unlink(missing_ok=True)
        _nix(
            runtime,
            "store",
            "verify",
            "--store",
            f"file://{cache_dir}",
            "--trusted-public-keys",
            public_value,
            *store_paths,
        )
    atomic_write(safe_path(cache_dir, CACHE_INFO_KEY), CACHE_INFO)
    staged: dict[str, Path] = {}
    for path in sorted(cache_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(cache_dir).as_posix()
        if rel == CACHE_INFO_KEY or _NAR.fullmatch(rel) or _NARINFO.fullmatch(rel):
            staged[rel] = path
    pub_target = safe_path(out, PUBKEY_KEY)
    pub_target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(public_key_file, pub_target)
    staged[PUBKEY_KEY] = pub_target
    for inner, path in mirror.published_files(repo).items():
        staged[f"{REPO}/{inner}"] = path
    etags = _mapping(retained.metadata.get("etags", {})) if retained.accepted_history else {}
    refs: list[ObjectRef] = []
    outputs: list[OutputObject] = []
    working_files: dict[str, JSONValue] = {}
    for key in sorted(old_refs.keys() | staged.keys(), key=lambda item: (_classify(item)[3], item)):
        kind, content_type, mutable, _ = _classify(key)
        is_working = (
            key == PUBKEY_KEY
            or key in _ENTRIES
            or _GIT_OBJECT.fullmatch(key) is not None
            or _GIT_TAG.fullmatch(key) is not None
        )
        if key not in staged:
            if is_working and key in restored:
                working_files[key] = restored[key]
            refs.append(old_refs[key])
            continue
        local_path = staged[key]
        sha, size = sha256_file(local_path)
        ref = ObjectRef(
            "nix",
            key,
            kind,
            size,
            sha,
            content_type,
            "no-cache" if mutable else IMMUTABLE,
        )
        if is_working:
            working_files[key] = str(local_path)
        refs.append(ref)
        prior = old_refs.get(key)
        if prior is not None and (prior.sha256, prior.size) == (sha, size) and key not in stale:
            continue
        if prior is not None and not mutable:
            raise NixFailure(f"Immutable Nix object {key} changed")
        etag = _string(etags.get(key), "entry ETag") if prior is not None else None
        outputs.append(
            OutputObject(ref, local_path, "replace" if prior else "create", etag, len(outputs))
        )
    result = RetainedFormat(
        "nix",
        tuple(history),
        tuple(item.inspected.identity for item in history),
        {
            "head": head,
            "files": working_files,
            "public_key": public_value,
            "fingerprint": signer.fingerprint,
            "flake_lock": lock_doc,
        },
        tuple(refs),
    )
    prepared = PreparedFormat("nix", result, tuple(outputs), result.objects)
    validate_prepared(prepared, policy=policy, runtime=runtime)
    return prepared


def validate_prepared(prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime) -> None:
    if prepared.format != "nix" or prepared.referenced_objects != prepared.retained.objects:
        raise NixFailure("Prepared Nix object closure differs from retained state")
    validate_retained(prepared.retained, policy=policy, runtime=runtime)
    if not prepared.retained.accepted_history:
        if prepared.outputs:
            raise NixFailure("Empty Nix state contains outputs")
        return
    refs = {ref.key: ref for ref in prepared.referenced_objects}
    previous_rank = -1
    for ordinal, output in enumerate(prepared.outputs):
        if refs.get(output.ref.key) != output.ref:
            raise NixFailure("Prepared Nix output differs from referenced objects")
        _kind, _ctype, mutable, rank = _classify(output.ref.key)
        if (
            output.ordinal != ordinal
            or rank < previous_rank
            or (not mutable and output.mode != "create")
            or sha256_file(output.local_path) != (output.ref.sha256, output.ref.size)
        ):
            raise NixFailure("Prepared Nix output bytes or publication order is invalid")
        previous_rank = rank
