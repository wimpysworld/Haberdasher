"""Bounded loopback miniserve fixtures for native clients.

Miniserve 0.35.0 implements the required conditional and range requests. Its
port-zero choice uses a free-port probe before bind, so startup retries remain
necessary. A token response alone is not proof of listener ownership.
"""

from __future__ import annotations

import contextlib
import http.client
import os
import re
import secrets
import selectors
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Generator, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from urllib.parse import quote

from haberdasher.core import safe_key, safe_path

STARTUP_TIMEOUT = 6.0
STARTUP_ATTEMPTS = 3
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_REQUESTS = 10_000
_LOG = re.compile(rb'\[INFO\] 127\.0\.0\.1 "([A-Z]+) ([^"\r\n]+) HTTP/1\.[01]" (\d{3}) (\d+) ')
_PORT = re.compile(rb"Bound to 127\.0\.0\.1:(\d+)\n")


class HttpFixtureError(RuntimeError):
    pass


@dataclass(frozen=True)
class RequestRecord:
    method: str
    path: str
    status: int
    bytes_sent: int


def set_generation_mtime(paths: Sequence[Path], generation: int) -> None:
    """Use distinct whole seconds, before the clock, without a client cache reset."""
    if type(generation) is not int or not 0 <= generation <= 1_000_000:
        raise ValueError("Invalid fixture generation")
    stamp = 946684800 + 2 * generation
    if stamp >= int(time.time()) - 60:
        raise ValueError("Fixture generation mtime is not before the test clock")
    checked = [safe_path(path.absolute().parent, path.name) for path in paths]
    if any(not path.is_file() for path in checked):
        raise ValueError("Generation mtimes require regular files")
    for path in checked:
        os.utime(path, (stamp, stamp), follow_symlinks=False)


def owns_listener(pid: int, port: int) -> bool:
    """Match the child's open socket inode, not an unrelated loopback service."""
    proc = Path(f"/proc/{pid}")
    if not Path("/proc/self/fd").is_dir():
        raise HttpFixtureError("Listener ownership verification requires Linux /proc")
    try:
        inodes: set[str] = set()
        for entry in (proc / "fd").iterdir():
            # Descriptor directories can include a scanner's already closed FD.
            try:
                target = os.readlink(entry)
            except FileNotFoundError:
                continue
            if target.startswith("socket:["):
                inodes.add(target[8:-1])
        listeners: list[str] = []
        for table in ("tcp", "tcp6"):
            for line in (proc / "net" / table).read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == "0A" and fields[9] in inodes:
                    listeners.append(fields[1])
        return listeners == [f"0100007F:{port:04X}"]
    except FileNotFoundError, ProcessLookupError:
        return False


class HttpFixture:
    backend = "miniserve"

    def __init__(self, root: Path) -> None:
        self.root = root.absolute()
        safe_path(self.root, "validation")
        if not self.root.is_dir() or self.root == Path("/"):
            raise ValueError("Expected a non-root serving directory")
        self._token = secrets.token_hex(32)
        self._token_name = f"fixture-ready-{secrets.token_hex(16)}"
        self._token_path = safe_path(self.root, self._token_name)
        descriptor = os.open(self._token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(self._token)
        self._token_identity = self._token_path.stat()
        self._work = Path(tempfile.mkdtemp(prefix="haberdasher-http-"))
        self.request_log = self._work / "requests"
        self.request_log.touch(mode=0o600)
        self._condition = threading.Condition()
        self._records: list[RequestRecord] = []
        self._seen: set[str] = set()
        self._error: str | None = None
        self._tail = bytearray()
        self._total = 0
        self._port: int | None = None
        self._eof = False
        self._process: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._closed = False

    @property
    def pid(self) -> int:
        if self._process is None:
            raise HttpFixtureError("Server did not start")
        return self._process.pid

    @property
    def port(self) -> int:
        if self._port is None:
            raise HttpFixtureError("Server has no listener")
        return self._port

    @property
    def log_bytes(self) -> int:
        return self._total

    def _read_logs(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        pending = bytearray()
        try:
            with selectors.DefaultSelector() as selector, self.request_log.open("a") as log:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.select():
                    block = os.read(process.stdout.fileno(), 65536)
                    with self._condition:
                        if not block:
                            self._eof = True
                            self._condition.notify_all()
                            return
                        self._total += len(block)
                        self._tail.extend(block)
                        del self._tail[:-8192]
                        if self._total > MAX_LOG_BYTES:
                            raise HttpFixtureError("Server exceeded the log limit")
                        pending.extend(block)
                        while b"\n" in pending:
                            line, _, rest = pending.partition(b"\n")
                            pending = bytearray(rest)
                            if match := _PORT.search(line + b"\n"):
                                self._port = int(match[1])
                            if match := _LOG.search(line):
                                method, path = match[1].decode(), match[2].decode()
                                status, size = int(match[3]), int(match[4])
                                if path.startswith("/" + self._token_name):
                                    # Barrier tokens are bounded by the same log limit.
                                    self._seen.add(path)
                                else:
                                    if len(self._records) >= MAX_REQUESTS:
                                        raise HttpFixtureError("Server exceeded the request limit")
                                    self._records.append(
                                        RequestRecord(
                                            method,
                                            path,
                                            status,
                                            0 if method == "HEAD" or status == 304 else size,
                                        )
                                    )
                                    log.write(path + "\n")
                                    log.flush()
                            elif b'[INFO] 127.0.0.1 "' in line:
                                raise HttpFixtureError("Cannot parse the miniserve request log")
                        self._condition.notify_all()
        except Exception as error:
            with self._condition:
                self._error = str(error)
                self._condition.notify_all()
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)

    def _check(self) -> None:
        if self._error:
            raise HttpFixtureError(self._error)
        if self._process is None or self._process.poll() is not None or self._eof:
            raise HttpFixtureError("Server child exited before readiness or acquisition")

    def _get_token(self, path: str, deadline: float) -> None:
        self._check()
        if not owns_listener(self.pid, self.port):
            self._check()
            raise HttpFixtureError("Server does not own its loopback listener")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HttpFixtureError("Server readiness deadline expired")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=remaining)
        try:
            connection.request("GET", path, headers={"Connection": "close"})
            response = connection.getresponse()
            if (
                response.status != 200
                or response.getheader("X-Haberdasher-Fixture") != self._token
                or response.read(1024) != self._token.encode()
            ):
                raise HttpFixtureError("Server readiness token mismatch")
        except (OSError, http.client.HTTPException) as error:
            self._check()
            raise HttpFixtureError(f"Server token request failed: {error}") from error
        finally:
            connection.close()
        self._check()
        if not owns_listener(self.pid, self.port):
            self._check()
            raise HttpFixtureError("Server lost its owned listener")

    def _launch(self, executable: str) -> None:
        # Port zero is miniserve's free-port-before-bind selection, not atomic bind.
        self._process = subprocess.Popen(
            [
                executable,
                "--interfaces",
                "127.0.0.1",
                "--port",
                "0",
                "--workers",
                "1",
                "--no-symlinks",
                "--verbose",
                "--log-color",
                "never",
                "--disable-indexing",
                "--header",
                f"X-Haberdasher-Fixture:{self._token}",
                str(self.root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"PATH": os.environ.get("HABERDASHER_TOOL_PATH", os.defpath), "LC_ALL": "C"},
            start_new_session=True,
            umask=0o077,
        )
        self._reader = threading.Thread(
            target=self._read_logs, name="fixture-http-log", daemon=True
        )
        self._reader.start()

    def start(self) -> None:
        executable = shutil.which(
            "miniserve", path=os.environ.get("HABERDASHER_TOOL_PATH", os.environ.get("PATH"))
        )
        if executable is None:
            raise HttpFixtureError("Pinned miniserve is required in HABERDASHER_TOOL_PATH")
        deadline = time.monotonic() + STARTUP_TIMEOUT
        failure: Exception | None = None
        for _attempt in range(STARTUP_ATTEMPTS):
            try:
                self._launch(executable)
                with self._condition:
                    while self._port is None:
                        self._check()
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise HttpFixtureError("Server readiness deadline expired")
                        self._condition.wait(remaining)
                self._get_token("/" + self._token_name, deadline)
                return
            except (HttpFixtureError, OSError, http.client.HTTPException) as error:
                failure = error
                self._stop_child()
                # An explicit bind collision is the only retryable startup failure.
                collision = b"address already in use" in bytes(self._tail).lower()
                if not collision or time.monotonic() >= deadline:
                    break
                self._port = None
                self._eof = False
        raise HttpFixtureError(f"Loopback startup failed: {failure}") from failure

    def url(self, relative: str = "") -> str:
        if relative:
            safe_key(relative)
        return f"http://127.0.0.1:{self.port}/" + quote(relative, safe="/")

    def requests(self) -> tuple[RequestRecord, ...]:
        if not self._closed:
            deadline = time.monotonic() + STARTUP_TIMEOUT
            barrier = f"/{self._token_name}?barrier={secrets.token_hex(16)}"
            self._get_token(barrier, deadline)
            with self._condition:
                while barrier not in self._seen:
                    self._check()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise HttpFixtureError("Request log drain deadline expired")
                    self._condition.wait(remaining)
                self._seen.remove(barrier)
        if self._error:
            raise HttpFixtureError(self._error)
        return tuple(self._records)

    def set_generation_mtime(self, paths: Sequence[Path], generation: int) -> None:
        checked: list[Path] = []
        for path in paths:
            full = path if path.is_absolute() else self.root / path
            checked.append(safe_path(self.root, str(full.relative_to(self.root))))
        set_generation_mtime(checked, generation)

    def _stop_child(self) -> None:
        if self._process is not None:
            process = self._process
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            if self._reader is not None:
                self._reader.join(timeout=2)
                if self._reader.is_alive():
                    raise HttpFixtureError("Server log reader did not stop")
            if process.stdout is not None:
                process.stdout.close()

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._stop_child()
        finally:
            self._closed = True
            if self._token_path.is_file() and not self._token_path.is_symlink():
                stat = self._token_path.stat()
                if (stat.st_dev, stat.st_ino) == (
                    self._token_identity.st_dev,
                    self._token_identity.st_ino,
                ):
                    self._token_path.unlink()
            shutil.rmtree(self._work)
        if self._error:
            raise HttpFixtureError(self._error)


def _interrupt(signum: int, _frame: FrameType | None) -> None:
    raise SystemExit(128 + signum)


@contextlib.contextmanager
def serve(root: Path, *, backend: str = "auto") -> Generator[HttpFixture]:
    """Serve mutable disposable files. Symlinks, uploads and deletion stay disabled."""
    if backend not in {"auto", "miniserve"}:
        raise ValueError("Supported HTTP backends are auto and miniserve")
    if threading.current_thread() is not threading.main_thread():
        raise HttpFixtureError("HTTP fixtures require the main thread for signal cleanup")
    fixture = HttpFixture(root)
    handlers = {
        sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    }
    try:
        for sig in handlers:
            signal.signal(sig, _interrupt)
        fixture.start()
        yield fixture
        fixture.requests()
    finally:
        try:
            fixture.close()
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
