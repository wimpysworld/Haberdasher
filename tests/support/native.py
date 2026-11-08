"""Private roots and command evidence, without package-format policy.

Callers supply trusted native configuration and fixed root-selection prefixes.
The guard checks those prefixes and rejects later root or configuration overrides.
This helper is not a sandbox for untrusted programs or package scripts.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from haberdasher.core import safe_path
from haberdasher.runtime import Runtime


@dataclass(frozen=True)
class CommandRecord:
    argv: tuple[str, ...]
    returncode: int | None


class NativeClient:
    def __init__(self, runtime: Runtime, name: str) -> None:
        if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) is None:
            raise ValueError("Invalid private client name")
        self.runtime = runtime
        self.base = safe_path(runtime.root, f"clients/{name}")
        self.base.parent.mkdir(mode=0o700, exist_ok=True)
        self.base.mkdir(mode=0o700)
        self._identity = self.base.stat()
        self.root = self.path("root")
        for name in ("root", "config", "cache", "state", "log", "tmp"):
            self.path(name).mkdir(mode=0o700)
        self.command_log = self.path("log/commands.jsonl")
        self.command_log.touch(mode=0o600)
        self._commands: list[CommandRecord] = []
        self._log_bytes = 0

    def path(self, relative: str) -> Path:
        stat = self.base.stat(follow_symlinks=False)
        if self.base.is_symlink() or (stat.st_dev, stat.st_ino) != (
            self._identity.st_dev,
            self._identity.st_ino,
        ):
            raise ValueError("Private client root changed")
        return safe_path(self.base, relative)

    def guard_root(self, root: Path) -> Path:
        expected = self.path("root")
        if not root.is_absolute() or root != expected or root.is_symlink():
            raise ValueError("Refuse installation outside the private client root")
        safe_path(root, "validation")
        if not root.is_dir():
            raise ValueError("Private installation root is missing")
        return root

    def _guard_command(self, argv: Sequence[str], root: Path) -> None:
        error = "Native command must select only its private installation root"
        args = list(argv)
        setopts: set[str] = set()
        # Fixed prefixes keep option values and operands from posing as root selectors.
        match args:
            case ["apk", *_]:
                prefix = ["apk", "--root", str(root)]
                long_options, short_options = ("--root",), "p"
            case ["fakeroot", "pacman", *_]:
                prefix = [
                    "fakeroot",
                    "pacman",
                    "--config",
                    str(self.path("config/pacman.conf")),
                    "--root",
                    str(root),
                ]
                long_options = ("--root", "--sysroot", "--config", "--dbpath")
                short_options = "rb"
            case ["rpm", *_]:
                prefix = ["rpm", "--define", "_dbpath /var/lib/rpm", "--root", str(root)]
                long_options = ("--root", "--dbpath", "--rcfile", "--macros", "--define")
                short_options = "rD"
            case ["dpkg-query", *_]:
                prefix = ["dpkg-query", f"--admindir={self.path('root/var/lib/dpkg')}"]
                long_options, short_options = ("--admindir", "--root", "--instdir"), ""
            case ["env", _, "fakeroot", "apt-get", *_]:
                prefix = [
                    "env",
                    f"APT_CONFIG={self.path('config/apt.conf')}",
                    "fakeroot",
                    "apt-get",
                    "-o",
                    f"Dir::State::status={self.path('root/var/lib/dpkg/status')}",
                    f"-oDPkg::Options::=--root={root}",
                    f"-oDPkg::Options::=--admindir={self.path('root/var/lib/dpkg')}",
                ]
                long_options, short_options = ("--option", "--config-file"), "oc"
            case [
                "env",
                _,
                data_dirs,
                _,
                _,
                _,
                "flatpak",
                "--user",
                *_,
            ]:
                if not data_dirs.startswith("XDG_DATA_DIRS="):
                    raise ValueError(error)
                prefix = [
                    "env",
                    f"FLATPAK_USER_DIR={root}",
                    data_dirs,
                    f"HOME={self.path('config')}",
                    f"XDG_DATA_HOME={self.path('state')}",
                    f"XDG_CACHE_HOME={self.path('cache')}",
                    "flatpak",
                    "--user",
                ]
                long_options, short_options = ("--user", "--system", "--installation"), "u"
            case [
                "env",
                "FAKECHROOT_EXCLUDE_PATH=/nix/store",
                _,
                "fakechroot",
                "-e",
                "none",
                "fakeroot",
                "chroot",
                _,
                env,
                *inner,
            ]:
                local = "/" + str(self.base.relative_to(self.runtime.root))
                home = f"{local}/home"
                environment = [
                    f"HOME={home}",
                    f"GNUPGHOME={local}/gnupg",
                    "TMPDIR=/tmp",
                    f"XDG_CONFIG_HOME={home}/.config",
                    f"XDG_DATA_HOME={home}/.local/share",
                    f"XDG_CACHE_HOME={home}/.cache",
                    f"XDG_STATE_HOME={home}/.local/state",
                    "XDG_RUNTIME_DIR=/run",
                ]
                if (
                    not Path(env).is_absolute()
                    or Path(env).name != "env"
                    or len(inner) <= len(environment)
                    or not Path(inner[len(environment)]).is_absolute()
                    or Path(inner[len(environment)]).name != "dnf5"
                ):
                    raise ValueError(error)
                # The fake chroot maps logical paths through the workspace, not the install root.
                prefix = [
                    "env",
                    "FAKECHROOT_EXCLUDE_PATH=/nix/store",
                    f"HD_PRIVATE_INSTALL_ROOT={root}",
                    "fakechroot",
                    "-e",
                    "none",
                    "fakeroot",
                    "chroot",
                    str(self.runtime.root),
                    env,
                    *environment,
                    inner[len(environment)],
                    "--config",
                    f"{local}/config/dnf.conf",
                    "--installroot",
                    f"{local}/root",
                ]
                long_options, short_options = ("--installroot", "--config", "--setopt"), "c"
                setopts = {
                    f"--setopt={key}={local}/{value}"
                    for key, value in (
                        ("reposdir", "repos"),
                        ("varsdir", "vars"),
                        ("cachedir", "cache"),
                        ("system_cachedir", "cache"),
                        ("logdir", "log"),
                        ("persistdir", "state"),
                    )
                }
            case _:
                raise ValueError(error)
        if args[: len(prefix)] != prefix:
            raise ValueError(error)
        for arg in args[len(prefix) :]:
            if arg in setopts:
                continue
            option = arg.partition("=")[0]
            if (
                option.startswith("--")
                and len(option) > 2
                and any(name.startswith(option) for name in long_options)
            ) or (
                arg.startswith("-")
                and not arg.startswith("--")
                and any(letter in arg[1:] for letter in short_options)
            ):
                raise ValueError(error)

    @property
    def commands(self) -> tuple[CommandRecord, ...]:
        return tuple(self._commands)

    def count(self, executable: str | None = None) -> int:
        return sum(
            executable is None or Path(record.argv[0]).name == executable
            for record in self._commands
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        install_root: Path,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
    ) -> subprocess.CompletedProcess[bytes]:
        root = self.guard_root(install_root)
        if (
            isinstance(argv, (str, bytes))
            or not argv
            or any(not isinstance(arg, str) or "\0" in arg for arg in argv)
        ):
            raise ValueError("Expected an argument sequence")
        self._guard_command(argv, root)
        if cwd is not None:
            self.path(str(cwd.relative_to(self.base)))
        args = tuple(self.runtime.redact(arg.encode()).decode() for arg in argv)
        # Reserve the worst return-code width before the command can run.
        entry_size = len(json.dumps({"argv": args, "returncode": -(2**63)}).encode()) + 1
        if (
            len(self._commands) >= 10_000
            or entry_size > 32_768
            or self._log_bytes + entry_size > 2 * 1024 * 1024
        ):
            raise ValueError("Native command log limit exceeded")
        self.path("log/commands.jsonl")
        code: int | None = None
        try:
            result = self.runtime.run(argv, cwd=cwd or self.base, input=input, timeout=timeout)
            code = result.returncode
            return result
        finally:
            record = CommandRecord(args, code)
            self._commands.append(record)
            entry = json.dumps({"argv": args, "returncode": code}) + "\n"
            self._log_bytes += len(entry.encode())
            with self.path("log/commands.jsonl").open("a") as stream:
                stream.write(entry)
                stream.flush()
                os.fsync(stream.fileno())
