"""Nix flake repository over dumb HTTP and signed HTTP binary cache."""

from __future__ import annotations

import base64
import io
import json
import os
import plistlib
import re
import shutil
import struct
import tarfile
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import replace
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


def _upstream_sources(
    nix_files: Mapping[str, str], ver: str
) -> tuple[str, list[tuple[str, str, str]]]:
    pname = ""
    entries: list[tuple[str, str, str]] = []
    for rel_path, content in sorted(nix_files.items()):
        if rel_path == "flake.nix":
            continue
        if not pname and (match := re.search(r'\bpname\s*=\s*"([^"]+)"\s*;', content)):
            pname = mirror.name(match[1])
        matched_spans: list[tuple[int, int]] = []
        for match, inner, span in _brace_blocks(
            content,
            r"(?<![A-Za-z0-9_-])(x86_64-linux|aarch64-linux|x86_64-darwin|aarch64-darwin)\s*=\s*\{",
        ):
            url_match = re.search(r'\burl\s*=\s*"([^"]+)"\s*;', inner)
            hash_match = re.search(r'\b(?:hash|sha256)\s*=\s*"([^"]*)"\s*;', inner)
            if url_match and hash_match:
                expanded = url_match[1].replace("${version}", ver)
                if pname:
                    expanded = expanded.replace("${pname}", pname)
                entries.append((rel_path, match[1], expanded))
                matched_spans.append(span)
        platforms = re.findall(
            r'"(x86_64-linux|aarch64-linux|x86_64-darwin|aarch64-darwin)"',
            next(iter(re.findall(r"\bplatforms\s*=\s*\[([^\]]*)\]", content)), ""),
        )
        for _match, inner, span in _brace_blocks(content, r"\bfetchurl\s*\{"):
            if any(start <= span[0] < end for start, end in matched_spans):
                continue
            url_match = re.search(r'\burl\s*=\s*"([^"]+)"\s*;', inner)
            hash_match = re.search(r'\b(?:hash|sha256)\s*=\s*"([^"]*)"\s*;', inner)
            if not (url_match and hash_match):
                continue
            expanded = url_match[1].replace("${version}", ver)
            if pname:
                expanded = expanded.replace("${pname}", pname)
            if len(platforms) == 1:
                entries.append((rel_path, platforms[0], expanded))
            else:
                lower = expanded.lower()
                is_mac = "darwin" in rel_path or any(k in lower for k in ("mac", "darwin", "osx"))
                is_arm = any(k in lower for k in ("arm64", "aarch64"))
                inferred = (
                    ("aarch64-darwin" if is_arm else "x86_64-darwin")
                    if is_mac
                    else ("aarch64-linux" if is_arm else "x86_64-linux")
                )
                if not platforms or inferred in platforms:
                    entries.append((rel_path, inferred, expanded))
    return pname, entries


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
    with tarfile.open(fileobj=io.BytesIO(fsys), mode="r|") as archive:
        for count, member in enumerate(archive, 1):
            if count > MAX_TAR_MEMBERS:
                raise NixFailure("DEB payload exceeds member limit")
            if not (member.isfile() or member.issym()):
                continue
            rel = member.name.removeprefix("./").lstrip("/")
            in_bin = rel.startswith(("usr/bin/", "bin/", "opt/"))
            if member.issym() and in_bin:
                has_exec = True
                continue
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            data = extracted.read(min(member.size, 16 * 1024 * 1024))
            elf_sys, elf_dyn = elf_binary(data)
            if elf_sys:
                if elf_sys != system:
                    raise NixFailure(f"{filename}: DEB header {deb_arch} disagrees with {elf_sys}")
                has_exec = True
                dynamic = dynamic or elf_dyn
            elif in_bin and (member.mode & 0o111):
                has_exec = True
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
            (rel_path, system, url)
            for rel_path, system, url in entries
            if url == asset.source.public_url or url.rsplit("/", 1)[-1] == filename
        ]
        if not matches:
            raise UnsupportedAsset(
                f"{filename}: not referenced by {asset.source.repository} nix/ expressions"
            )
        if len({system for _, system, _ in matches}) != 1:
            raise NixFailure(f"{filename}: ambiguous system mapping in nix/ expressions")
        system = matches[0][1]
        if system not in policy.architectures:
            raise UnsupportedAsset(f"{filename}: unsupported Nix system {system!r}")
        if not mirror.valid(pname, ver):
            raise UnsupportedAsset(f"{filename}: invalid Nix package name or version")
        metadata: dict[str, JSONValue] = {
            "mode": "upstream-nix",
            "desc": description,
            "license": licence,
            "tag": tag,
            "nix_files": dict(upstream),
        }
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


def _replace_fetchurl_block(
    body: str, pname: str, ver: str, pub_url: str, fname: str, sri: str
) -> tuple[str, bool]:
    url_m = re.search(r'\burl\s*=\s*"([^"]+)"\s*;', body)
    hash_m = re.search(r'\b(?:hash|sha256)\s*=\s*"([^"]*)"\s*;', body)
    if not (url_m and hash_m):
        return body, False
    expanded = url_m[1].replace("${version}", ver).replace("${pname}", pname)
    if expanded != pub_url and expanded.rsplit("/", 1)[-1] != fname:
        return body, False
    new_body = re.sub(r'\burl\s*=\s*"[^"]+"\s*;', f"url = {_nix_str(pub_url)};", body, count=1)
    new_body = re.sub(
        r'\b(?:hash|sha256)\s*=\s*"[^"]*"\s*;', f"hash = {_nix_str(sri)};", new_body, count=1
    )
    return new_body, True


def _rewrite_upstream_nix(
    items: Sequence[InspectedAsset],
) -> tuple[dict[str, str], tuple[str, ...]]:
    first = items[0]
    pname, ver = first.identity.name, first.identity.version
    raw_files = _mapping(items[-1].metadata.get("nix_files"), "upstream nix_files")
    rewritten = {
        rel: _string(text, "upstream nix content")
        for rel, text in raw_files.items()
        if rel != "flake.nix"
    }
    admitted_systems: set[str] = set()
    for item in items:
        admitted_systems.add(item.identity.architecture)
        sri = _sri(item.verified.sha256)
        pub_url = item.verified.source.public_url
        fname = item.verified.source.filename
        updated = False
        for rel in sorted(rewritten):
            content = rewritten[rel]
            sys_pat = rf"(?<![A-Za-z0-9_-]){re.escape(item.identity.architecture)}\s*=\s*\{{"
            for _match, inner, (inner_start, inner_end) in _brace_blocks(content, sys_pat):
                new_inner, hit = _replace_fetchurl_block(inner, pname, ver, pub_url, fname, sri)
                if hit:
                    content = content[:inner_start] + new_inner + content[inner_end:]
                    rewritten[rel] = content
                    updated = True
                    break
            if updated:
                break
            for _match, inner, (inner_start, inner_end) in _brace_blocks(
                content, r"\bfetchurl\s*\{"
            ):
                new_inner, hit = _replace_fetchurl_block(inner, pname, ver, pub_url, fname, sri)
                if hit:
                    content = content[:inner_start] + new_inner + content[inner_end:]
                    rewritten[rel] = content
                    updated = True
                    break
            if updated:
                break
        if not updated:
            raise NixFailure(f"Could not bind verified hash for {fname} in {pname} nix/ files")
    pkg_files: dict[str, str] = {}
    for rel, content in sorted(rewritten.items()):
        leaf = rel.removeprefix("nix/")
        target_leaf = "upstream.nix" if leaf == "default.nix" else leaf
        pkg_files[f"pkgs/{pname}/{target_leaf}"] = content
    has_darwin = f"pkgs/{pname}/darwin.nix" in pkg_files
    has_linux = f"pkgs/{pname}/linux.nix" in pkg_files
    if has_darwin and has_linux:
        dispatch = "if stdenv.hostPlatform.isDarwin then call ./darwin.nix else call ./linux.nix"
    elif has_darwin:
        dispatch = "call ./darwin.nix"
    elif has_linux:
        dispatch = "call ./linux.nix"
    elif f"pkgs/{pname}/package.nix" in pkg_files:
        dispatch = "call ./package.nix"
    else:
        dispatch = "call ./upstream.nix"
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
        f"{dispatch}\n"
    )
    return pkg_files, _ordered_systems(admitted_systems)


def _tarball_nix(items: Sequence[InspectedAsset]) -> tuple[str, tuple[str, ...]]:
    first = items[0]
    pname, ver = first.identity.name, first.identity.version
    by_system: dict[str, InspectedAsset] = {}
    for item in items:
        for sys_name in _item_systems(item):
            by_system[sys_name] = item
    systems = _ordered_systems(set(by_system))
    any_dynamic = any(bool(item.metadata.get("dynamic_elf")) for item in items)
    stdenv_arg = "stdenv" if any_dynamic else "stdenvNoCC"
    extra_args = ",\n  autoPatchelfHook" if any_dynamic else ""
    src_entries: list[str] = []
    for sys_name in systems:
        item = by_system[sys_name]
        binary = _string(item.metadata.get("binary"), "tarball binary")
        src_entries.append(
            f"    {sys_name} = {{\n"
            f"      url = {_nix_str(item.verified.source.public_url)};\n"
            f"      hash = {_nix_str(_sri(item.verified.sha256))};\n"
            f"      bin = {_nix_str(binary)};\n"
            "    };"
        )
    fixup_lines = (
        "  nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [ autoPatchelfHook ];\n"
        "  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [ stdenv.cc.cc.lib ];\n"
        "  dontFixup = stdenv.hostPlatform.isDarwin;\n"
        if any_dynamic
        else "  dontFixup = true;\n"
    )
    expr = (
        "{\n"
        "  lib,\n"
        "  fetchurl,\n"
        f"  {stdenv_arg}{extra_args},\n"
        "}:\n"
        "let\n"
        f"  inherit ({stdenv_arg}.hostPlatform) system;\n"
        "  sources = {\n" + "\n".join(src_entries) + "\n  };\n"
        "  source = sources.${system};\n"
        "in\n"
        f"{stdenv_arg}.mkDerivation {{\n"
        f"  pname = {_nix_str(pname)};\n"
        f"  version = {_nix_str(ver)};\n"
        "  src = fetchurl {\n"
        "    inherit (source) url hash;\n"
        "  };\n"
        '  sourceRoot = ".";\n'
        "  dontConfigure = true;\n"
        "  dontBuild = true;\n" + fixup_lines + "  installPhase = ''\n"
        "    runHook preInstall\n"
        f'    install -Dm755 "${{source.bin}}" "$out/bin/{pname}"\n'
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
    has_deb = any(item.metadata.get("mode") == "deb" for item in items)
    has_zip = any(item.metadata.get("mode") == "zip" for item in items)
    any_dynamic = any(bool(item.metadata.get("dynamic_elf")) for item in items)
    stdenv_arg = "stdenv" if any_dynamic else "stdenvNoCC"
    inputs = ["lib", "fetchurl", stdenv_arg]
    if has_deb:
        inputs += ["bintools", "gnutar", "xz", "zstd"]
        if any_dynamic:
            inputs.append("autoPatchelfHook")
    if has_zip:
        inputs += ["unzip", "makeWrapper"]
    src_entries: list[str] = []
    for sys_name in systems:
        item = by_system[sys_name]
        app = item.metadata.get("app")
        exe = item.metadata.get("executable")
        app_line = f"      app = {_nix_str(app)};\n" if isinstance(app, str) else ""
        exe_line = f"      exe = {_nix_str(exe)};\n" if isinstance(exe, str) else ""
        src_entries.append(
            f"    {sys_name} = {{\n"
            f"      url = {_nix_str(item.verified.source.public_url)};\n"
            f"      hash = {_nix_str(_sri(item.verified.sha256))};\n"
            + app_line
            + exe_line
            + "    };"
        )
    native_parts: list[str] = []
    if has_deb:
        deb_tools = "bintools gnutar xz zstd" + (" autoPatchelfHook" if any_dynamic else "")
        native_parts.append(f"lib.optionals {stdenv_arg}.hostPlatform.isLinux [ {deb_tools} ]")
    if has_zip:
        native_parts.append(
            f"lib.optionals {stdenv_arg}.hostPlatform.isDarwin [ unzip makeWrapper ]"
        )
    native_expr = " ++ ".join(native_parts) if native_parts else "[ ]"
    build_inputs = (
        "  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [ stdenv.cc.cc.lib ];\n"
        "  dontFixup = stdenv.hostPlatform.isDarwin;\n"
        if any_dynamic
        else "  dontFixup = true;\n"
    )
    deb_unpack = '${lib.getExe\' bintools "ar"} x "$src"\n      tar xf data.tar.*'
    zip_unpack = 'unzip -q "$src"'
    unpack_body = (
        f"if {stdenv_arg}.hostPlatform.isDarwin then ''\n      {zip_unpack}\n    '' else ''\n      {deb_unpack}\n    ''"
        if (has_deb and has_zip)
        else f"''\n    {zip_unpack}\n  ''"
        if has_zip
        else f"''\n    {deb_unpack}\n  ''"
    )
    deb_install = (
        "runHook preInstall\n"
        'mkdir -p "$out"\n'
        "for dir in usr/bin usr/share usr/lib usr/libexec; do\n"
        '  if [ -d "$dir" ]; then\n'
        '    target="$out/${dir#usr/}"\n'
        '    mkdir -p "$target"\n'
        '    cp -a "$dir"/. "$target"/\n'
        "  fi\n"
        "done\n"
        "for dir in bin lib opt etc; do\n"
        '  if [ -d "$dir" ]; then\n'
        '    mkdir -p "$out/$dir"\n'
        '    cp -a "$dir"/. "$out/$dir"/\n'
        "  fi\n"
        "done\n"
        "runHook postInstall"
    )
    zip_install = (
        "runHook preInstall\n"
        'mkdir -p "$out/Applications" "$out/bin"\n'
        'cp -R "${source.app}" "$out/Applications/"\n'
        f'makeWrapper "$out/Applications/${{source.app}}/Contents/MacOS/${{source.exe}}" "$out/bin/{pname}"\n'
        "runHook postInstall"
    )
    install_body = (
        f"if {stdenv_arg}.hostPlatform.isDarwin then ''\n{zip_install}\n  '' else ''\n{deb_install}\n  ''"
        if (has_deb and has_zip)
        else f"''\n{zip_install}\n  ''"
        if has_zip
        else f"''\n{deb_install}\n  ''"
    )
    args_header = ",\n  ".join(inputs)
    expr = (
        f"{{\n  {args_header},\n}}:\n"
        "let\n"
        f"  inherit ({stdenv_arg}.hostPlatform) system;\n"
        "  sources = {\n" + "\n".join(src_entries) + "\n  };\n"
        "  source = sources.${system};\n"
        "in\n"
        f"{stdenv_arg}.mkDerivation {{\n"
        f"  pname = {_nix_str(pname)};\n"
        f"  version = {_nix_str(ver)};\n"
        "  src = fetchurl {\n"
        "    inherit (source) url hash;\n"
        "  };\n"
        f"  nativeBuildInputs = {native_expr};\n" + build_inputs + "  dontConfigure = true;\n"
        "  dontBuild = true;\n"
        f"  unpackPhase = {unpack_body};\n"
        f"  installPhase = {install_body};\n" + _meta_block(first, pname, systems) + "\n}\n"
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
    overlay_attrs = "\n".join(
        f"        {name} = final.callPackage ./pkgs/{name} {{ }};"
        for name in sorted(package_systems)
    )
    return (
        "{\n"
        '  description = "Nix packages published by Haberdasher";\n\n'
        "  inputs = {\n"
        f"    nixpkgs.url = {_nix_str(nixpkgs_url)};\n"
        "  };\n\n"
        "  outputs =\n"
        "    { nixpkgs, ... }:\n"
        "    {\n"
        "      overlays.default = final: _prev: {\n" + overlay_attrs + "\n      };\n"
        "      packages = {\n" + "\n".join(sys_blocks) + "\n      };\n"
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
        out_hash = out_path.removeprefix("/nix/store/").split("-", 1)[0]
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
        for store_key, raw_entry in info_map.items():
            entry = _mapping(raw_entry, "path-info entry")
            h32 = store_key.split("-", 1)[0]
            sigs = entry.get("signatures", [])
            sigs_list = sigs if isinstance(sigs, list) else []
            is_local = all(
                isinstance(sig, str) and sig.startswith(f"{NIX_KEY_NAME}:") for sig in sigs_list
            )
            if is_local and f"{h32}.narinfo" not in old_refs:
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
