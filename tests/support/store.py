"""Inert storage fixtures. The HTTP double does not qualify R2 semantics."""

from __future__ import annotations

import contextlib
import hashlib
import threading
from collections.abc import Generator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from haberdasher.config import StoragePolicy
from haberdasher.core import ObjectRef


def local_policy(root: Path) -> StoragePolicy:
    return StoragePolicy(private=str(root / "private"), public={"apt": str(root / "public/apt")})


def remote_policy() -> StoragePolicy:
    return StoragePolicy("r2", "test-private", {"apt": "test-public"})


def object_ref(
    data: bytes = b"fixture", *, key: str = "nested/object", role: str = "apt"
) -> ObjectRef:
    return ObjectRef(
        role,
        key,
        "private" if role == "private" else "entry",
        len(data),
        hashlib.sha256(data).hexdigest(),
        "application/octet-stream",
        "no-cache",
    )


def synthetic_environment(endpoint: str, path: str) -> dict[str, str]:
    return {
        "PATH": path,
        "HD_CLOUDFLARE_S3_API_ENDPOINT": endpoint,
        "HD_CLOUDFLARE_ACCESS_KEY_ID": "inert-test-access",
        "HD_CLOUDFLARE_SECRET_ACCESS_KEY": "inert-test-secret",
    }


@dataclass
class StorageHTTP:
    endpoint: str = ""
    objects: dict[str, tuple[bytes, str]] = field(default_factory=dict)
    requests: list[tuple[str, str, str | None, str | None]] = field(default_factory=list)
    revision: int = 0
    put_error: int | None = None
    accept_then_error: bool = False
    truncate_get: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


@contextlib.contextmanager
def storage_http() -> Generator[StorageHTTP]:
    state = StorageHTTP()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def _record(self) -> str:
            key = unquote(urlsplit(self.path).path)
            state.requests.append(
                (self.command, key, self.headers.get("If-Match"), self.headers.get("If-None-Match"))
            )
            return key

        def _error(self, status: int) -> None:
            code = {
                404: "NoSuchKey",
                412: "PreconditionFailed",
                409: "ConditionalRequestConflict",
            }.get(status, "ServiceUnavailable")
            data = f"<Error><Code>{code}</Code><Message>Inert failure</Message></Error>".encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _read(self) -> None:
            with state.lock:
                key = self._record()
                item = state.objects.get(key)
            if item is None:
                self._error(404)
                return
            data, etag = item
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("ETag", etag)
            self.send_header("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            if self.command == "GET":
                self.wfile.write(data[:-1] if state.truncate_get else data)

        def do_HEAD(self) -> None:
            self._read()

        def do_GET(self) -> None:
            self._read()

        def do_PUT(self) -> None:
            data = self.rfile.read(int(self.headers["Content-Length"]))
            with state.lock:
                key = self._record()
                current = state.objects.get(key)
                if state.put_error is not None and not state.accept_then_error:
                    self._error(state.put_error)
                    return
                if (self.headers.get("If-None-Match") == "*" and current is not None) or (
                    self.headers.get("If-Match") is not None
                    and (current is None or current[1] != self.headers["If-Match"])
                ):
                    self._error(412)
                    return
                state.revision += 1
                etag = f'"revision-{state.revision}"'
                state.objects[key] = data, etag
                if state.put_error is not None:
                    self._error(state.put_error)
                    return
            self.send_response(200)
            self.send_header("ETag", etag)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.endpoint = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("Storage HTTP fixture did not stop")
