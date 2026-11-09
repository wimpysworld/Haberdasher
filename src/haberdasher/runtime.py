"""Private workspaces and bounded native process groups."""

from __future__ import annotations

import contextlib
import math
import os
import selectors
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Generator, Mapping, Sequence
from pathlib import Path
from types import FrameType

from haberdasher.core import atomic_write, safe_path

GITHUB_VARIABLES = ("GH_TOKEN", "GITHUB_TOKEN")
STORAGE_VARIABLES = (
    "HD_CLOUDFLARE_S3_API_ENDPOINT",
    "HD_CLOUDFLARE_ACCESS_KEY_ID",
    "HD_CLOUDFLARE_SECRET_ACCESS_KEY",
)


class RuntimeFailure(RuntimeError):
    pass


def _gh_login_token(path: str) -> str | None:
    """Read the token of the operator's stored `gh` login, when one exists."""
    executable = shutil.which("gh", path=path)
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, "auth", "token", "--hostname", "github.com"],
            env={**os.environ, "PATH": path, "GH_PROMPT_DISABLED": "1"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except OSError, subprocess.SubprocessError:
        return None
    token = result.stdout.decode("ascii", "replace").strip()
    if result.returncode != 0 or not token or any(char.isspace() for char in token):
        return None
    return token


class Runtime:
    def __init__(
        self,
        root: Path,
        *,
        environ: Mapping[str, str] | None = None,
        max_output: int = 16 * 1024 * 1024,
    ) -> None:
        if type(max_output) is not int or max_output < 1:
            raise ValueError("Invalid output limit")
        root = root.absolute()
        self.root = root
        self.max_output = max_output
        source = os.environ if environ is None else environ
        self._path = source.get("HABERDASHER_TOOL_PATH", source.get("PATH", os.defpath))
        self._github = {key: source[key] for key in GITHUB_VARIABLES if key in source}
        self._github_login = environ is None and not self._github
        self._storage = {key: source[key] for key in STORAGE_VARIABLES if key in source}
        self._children: set[subprocess.Popen[bytes]] = set()
        self._closed = False
        self._base = {
            "PATH": self._path,
            "HOME": str(root / "home"),
            "GNUPGHOME": str(root / "gnupg"),
            "XDG_CONFIG_HOME": str(root / "home/.config"),
            "XDG_DATA_HOME": str(root / "home/.local/share"),
            "XDG_CACHE_HOME": str(root / "home/.cache"),
            "XDG_STATE_HOME": str(root / "home/.local/state"),
            "XDG_RUNTIME_DIR": str(root / "run"),
            "TMPDIR": str(root / "tmp"),
            "LC_ALL": "C",
            "TZ": "UTC",
        }
        for key, value in self._base.items():
            if key not in {"PATH", "LC_ALL", "TZ"}:
                path = safe_path(root, str(Path(value).relative_to(root)))
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.chmod(0o700)
        atomic_write(
            root / "gnupg/gpg.conf",
            b"digest-algo SHA256\ncert-digest-algo SHA256\npersonal-digest-preferences SHA256\n",
        )
        for name in ("aws-config", "aws-credentials", "rclone.conf"):
            atomic_write(root / name, b"")

    @property
    def environment(self) -> dict[str, str]:
        return self.environment_for("native")

    def environment_for(self, kind: str) -> dict[str, str]:
        env = dict(self._base)
        if kind == "github":
            if self._github_login and not self._closed:
                self._github_login = False
                token = _gh_login_token(self._path)
                if token:
                    self._github = {"GH_TOKEN": token}
            env.update(self._github)
            env.update(
                {
                    "GH_CONFIG_DIR": str(self.root / "home/.config/gh"),
                    "GH_PROMPT_DISABLED": "1",
                    "GH_NO_UPDATE_NOTIFIER": "1",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                }
            )
        elif kind == "storage":
            env.update(self._storage)
            env.update(
                {
                    "AWS_CONFIG_FILE": str(self.root / "aws-config"),
                    "AWS_SHARED_CREDENTIALS_FILE": str(self.root / "aws-credentials"),
                    "AWS_EC2_METADATA_DISABLED": "true",
                    "AWS_MAX_ATTEMPTS": "1",
                    "AWS_RETRY_MODE": "standard",
                    "AWS_DEFAULT_REGION": "auto",
                    "AWS_PAGER": "",
                    "RCLONE_CONFIG": str(self.root / "rclone.conf"),
                }
            )
            for source, target in (
                (STORAGE_VARIABLES[0], "AWS_ENDPOINT_URL_S3"),
                (STORAGE_VARIABLES[1], "AWS_ACCESS_KEY_ID"),
                (STORAGE_VARIABLES[2], "AWS_SECRET_ACCESS_KEY"),
            ):
                if source in self._storage:
                    env[target] = self._storage[source]
        elif kind != "native":
            raise ValueError("Unknown subprocess environment profile")
        return env

    def redact(self, value: bytes) -> bytes:
        secrets = sorted((*self._github.values(), *self._storage.values()), key=len, reverse=True)
        for secret in secrets:
            if secret:
                value = value.replace(secret.encode(), b"[REDACTED]")
        return value

    @staticmethod
    def _stop(process: subprocess.Popen[bytes]) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
        env_kind: str = "native",
    ) -> subprocess.CompletedProcess[bytes]:
        if self._closed:
            raise RuntimeFailure("Runtime is closed")
        if (
            isinstance(argv, (str, bytes))
            or not argv
            or any(not isinstance(arg, str) or "\0" in arg for arg in argv)
        ):
            raise ValueError("Expected a non-empty argument sequence")
        if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Expected a positive finite timeout")
        if input is not None and not isinstance(input, bytes):
            raise ValueError("Process input must be bytes")
        env = self.environment_for(env_kind)
        deadline = time.monotonic() + timeout
        try:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd or self.root,
                env=env,
                stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                umask=0o077,
            )
        except OSError:
            raise RuntimeFailure("Could not start native command") from None
        self._children.add(process)
        outputs = {"stdout": bytearray(), "stderr": bytearray()}
        total = sent = 0
        try:
            with selectors.DefaultSelector() as selector:
                for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                    if stream is None:
                        raise RuntimeFailure("Missing subprocess output pipe")
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                if process.stdin is not None:
                    os.set_blocking(process.stdin.fileno(), False)
                    if input:
                        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                    else:
                        process.stdin.close()
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeFailure("Native command timed out")
                    for key, _ in selector.select(remaining):
                        if key.data == "stdin":
                            try:
                                sent += os.write(key.fd, (input or b"")[sent : sent + 65536])
                            except BrokenPipeError:
                                sent = len(input or b"")
                            if sent == len(input or b""):
                                selector.unregister(key.fileobj)
                                if process.stdin is not None:
                                    process.stdin.close()
                        else:
                            block = os.read(key.fd, 65536)
                            if not block:
                                selector.unregister(key.fileobj)
                                continue
                            total += len(block)
                            if total > self.max_output:
                                raise RuntimeFailure("Native command exceeded the output limit")
                            outputs[key.data].extend(block)
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    raise RuntimeFailure("Native command timed out") from None
            return subprocess.CompletedProcess(
                [self.redact(arg.encode()).decode() for arg in argv],
                process.returncode,
                self.redact(bytes(outputs["stdout"])),
                self.redact(bytes(outputs["stderr"])),
            )
        finally:
            self._stop(process)
            self._children.discard(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def cleanup_gnupg(
        self, home: Path, *, timeout: float = 120
    ) -> subprocess.CompletedProcess[bytes]:
        command = ["gpgconf", "--homedir", str(home)]
        result = self.run([*command, "--kill", "all"], timeout=timeout)
        if result.returncode:
            return result
        result = self.run([*command, "--list-dirs", "socketdir"], timeout=timeout)
        if result.returncode:
            return result
        # Removal can fail on read-only /run even when sockets use the homedir.
        if Path(os.fsdecode(result.stdout).rstrip("\n")) != home:
            return self.run([*command, "--remove-socketdir"], timeout=timeout)
        return result

    def close(self) -> None:
        if self._closed:
            return
        for process in tuple(self._children):
            self._stop(process)
        self._children.clear()
        if shutil.which("gpgconf", path=self._path):
            with contextlib.suppress(RuntimeFailure):
                self.cleanup_gnupg(self.root / "gnupg", timeout=10)
        self._closed = True
        self._github.clear()
        self._storage.clear()


def _interrupt(signum: int, _frame: FrameType | None) -> None:
    raise SystemExit(128 + signum)


@contextlib.contextmanager
def private_workspace(parent: Path | None = None) -> Generator[Runtime]:
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeFailure("Private workspaces require the main thread for signal cleanup")
    base = (parent or Path(tempfile.gettempdir())).absolute()
    safe_path(base, "validation")
    if not base.is_dir() or base == Path("/nix/store") or Path("/nix/store") in base.parents:
        raise ValueError("Invalid private workspace parent")
    if any((ancestor / ".git").exists() for ancestor in (base, *base.parents)):
        raise ValueError("Private workspaces must be outside a checkout")
    socket = base / "haberdasher-XXXXXXXX" / "gnupg/S.gpg-agent.browser"
    if len(os.fsencode(socket)) >= 107:
        base = Path("/tmp")  # noqa: S108 - mkdtemp creates an exclusive private child.
    mask = os.umask(0o077)
    handlers = {
        sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    }
    root: Path | None = None
    identity: tuple[int, int] | None = None
    runtime: Runtime | None = None
    try:
        for sig in handlers:
            signal.signal(sig, _interrupt)
        root = Path(tempfile.mkdtemp(prefix="haberdasher-", dir=base))
        stat = root.stat()
        identity = stat.st_dev, stat.st_ino
        runtime = Runtime(root)
        yield runtime
    finally:
        try:
            if runtime is not None:
                runtime.close()
            if root is not None and root.exists() and not root.is_symlink():
                stat = root.stat()
                if (stat.st_dev, stat.st_ino) == identity:
                    shutil.rmtree(root)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            os.umask(mask)
