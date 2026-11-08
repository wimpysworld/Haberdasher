"""Private roots and command evidence, without package-format policy.

Callers supply native configuration and root options. The mandatory install_root
argument and an explicit path in argv reject accidental host-root invocations.
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
        if isinstance(argv, (str, bytes)) or not argv:
            raise ValueError("Expected an argument sequence")
        if not any(
            value == str(root) or value.startswith(str(root) + "/")
            for arg in argv
            for value in (arg, arg.partition("=")[2])
        ):
            raise ValueError("Native command must name its private installation root")
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
