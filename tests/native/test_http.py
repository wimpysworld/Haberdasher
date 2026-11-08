"""Acceptance against pinned miniserve, without host installation or credentials."""

from __future__ import annotations

import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import time
from http.client import HTTPConnection
from pathlib import Path

import pytest

from tests.support import http


def _request(
    fixture: http.HttpFixture,
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = HTTPConnection("127.0.0.1", fixture.port, timeout=3)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


@pytest.mark.parametrize("backend", ["auto", "miniserve"])
def test_native_conditional_acquisition_and_request_evidence(tmp_path: Path, backend: str) -> None:
    source = tmp_path / "metadata"
    source.write_bytes(b"first-generation")
    with http.serve(tmp_path, backend=backend) as fixture:
        assert fixture.backend == "miniserve"
        assert fixture.url("metadata") == f"http://127.0.0.1:{fixture.port}/metadata"
        assert http.owns_listener(fixture.pid, fixture.port)
        fixture.set_generation_mtime([source], 1)
        status, headers, body = _request(fixture, "/metadata")
        assert (status, body) == (200, b"first-generation")
        modified = headers["last-modified"]
        etag = headers["etag"]
        assert _request(fixture, "/metadata", method="HEAD")[2] == b""
        assert _request(fixture, "/metadata", headers={"If-Modified-Since": modified})[::2] == (
            304,
            b"",
        )
        assert _request(fixture, "/metadata", method="HEAD", headers={"If-None-Match": etag})[
            ::2
        ] == (304, b"")
        source.write_bytes(b"next-generation!")
        fixture.set_generation_mtime([Path("metadata")], 2)
        status, changed, body = _request(
            fixture, "/metadata", headers={"If-Modified-Since": modified}
        )
        assert (status, body) == (200, b"next-generation!")
        assert changed["last-modified"] != modified
        assert changed["etag"] != etag
        assert _request(fixture, "/absent")[0] == 404
        assert _request(fixture, "/absent", method="HEAD")[::2] == (404, b"")
        records = fixture.requests()
        assert [(row.method, row.path, row.status) for row in records] == [
            ("GET", "/metadata", 200),
            ("HEAD", "/metadata", 200),
            ("GET", "/metadata", 304),
            ("HEAD", "/metadata", 304),
            ("GET", "/metadata", 200),
            ("GET", "/absent", 404),
            ("HEAD", "/absent", 404),
        ]
        assert [row.bytes_sent for row in records[:5]] == [16, 0, 0, 0, 16]
        assert fixture.request_log.read_text().splitlines() == [row.path for row in records]
        assert fixture.log_bytes < http.MAX_LOG_BYTES
        with pytest.raises(ValueError):
            fixture.set_generation_mtime([tmp_path.parent / "outside"], 3)
        for path in ("../outside", "/etc/passwd", "https://invalid/"):
            with pytest.raises(ValueError):
                fixture.url(path)
        pid, port, work = fixture.pid, fixture.port, fixture.request_log.parent
    assert fixture.requests() == records
    assert not work.exists()
    assert not list(tmp_path.glob("fixture-ready-*"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0


def test_native_ranges_and_read_only_tree(tmp_path: Path) -> None:
    root = tmp_path / "public"
    root.mkdir()
    (root / "file with space").write_bytes(b"0123456789")
    outside = tmp_path / "private"
    outside.write_bytes(b"private-state")
    (root / "escape").symlink_to(outside)
    (root / "alias").symlink_to(root / "file with space")
    (root / "directory").symlink_to(tmp_path, target_is_directory=True)
    with http.serve(root) as fixture:
        assert fixture.url("file with space").endswith("file%20with%20space")
        status, headers, body = _request(
            fixture, "/file%20with%20space", headers={"Range": "bytes=2-5"}
        )
        assert (status, body) == (206, b"2345")
        assert headers["content-range"] == "bytes 2-5/10"
        assert _request(fixture, "/file%20with%20space", headers={"Range": "bytes=8-"})[::2] == (
            206,
            b"89",
        )
        assert _request(fixture, "/file%20with%20space", headers={"Range": "bytes=99-"})[0] == 416
        for path in ("/escape", "/alias", "/directory/private", "/%2e%2e/private"):
            status, _, body = _request(fixture, path)
            assert status in {400, 404}
            assert b"private-state" not in body
        for method in ("PUT", "POST", "DELETE"):
            assert _request(fixture, "/file%20with%20space", method=method)[0] in {404, 405}
        assert (root / "file with space").read_bytes() == b"0123456789"
        assert outside.read_bytes() == b"private-state"
        assert fixture.requests()[0].bytes_sent == 4


def test_real_bind_collision_is_not_an_unrelated_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = http.shutil.which("miniserve", path=os.environ.get("HABERDASHER_TOOL_PATH"))
    assert executable is not None
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        port = occupied.getsockname()[1]
        shim = tmp_path / "miniserve"
        shim.write_text(
            f"#!{sys.executable}\nimport os, sys\nargs=sys.argv[1:]\n"
            f"args[args.index('--port')+1]={str(port)!r}\n"
            f"os.execv({executable!r}, [{executable!r}, *args])\n"
        )
        shim.chmod(0o700)
        monkeypatch.setenv("HABERDASHER_TOOL_PATH", str(tmp_path))
        started = time.monotonic()
        with pytest.raises(http.HttpFixtureError, match="startup failed"), http.serve(tmp_path):
            pass
        assert time.monotonic() - started < http.STARTUP_TIMEOUT + 2
        assert occupied.getsockname()[1] == port
        assert not list(tmp_path.glob("fixture-ready-*"))


@pytest.mark.parametrize("mode", ["exception", "INT", "TERM", "HUP"])
def test_native_signal_and_exception_cleanup(tmp_path: Path, mode: str) -> None:
    script = """import json, signal, sys
from pathlib import Path
from tests.support.http import serve
with serve(Path(sys.argv[1])) as fixture:
    print(json.dumps([fixture.pid, fixture.port, str(fixture.request_log.parent)]), flush=True)
    if sys.argv[2] == 'exception':
        raise ValueError('injected')
    signal.pause()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path), mode],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": os.environ.get("HABERDASHER_TOOL_PATH", os.defpath),
            "HABERDASHER_TOOL_PATH": os.environ.get("HABERDASHER_TOOL_PATH", os.defpath),
        },
    )
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(10), "No native readiness pipe response"
            line = process.stdout.readline()
        assert line, "Server exited before readiness"
        pid, port, work = json.loads(line)
        if mode != "exception":
            process.send_signal(getattr(signal, "SIG" + mode))
        _, error = process.communicate(timeout=10)
        expected = 1 if mode == "exception" else 128 + getattr(signal, "SIG" + mode)
        assert process.returncode == expected, error.decode()
        assert not Path(work).exists()
        assert not list(tmp_path.glob("fixture-ready-*"))
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        with socket.socket() as probe:
            assert probe.connect_ex(("127.0.0.1", port)) != 0
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


def test_wrong_readiness_token_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(http.HttpFixtureError, match="token mismatch"):
        with http.serve(tmp_path) as fixture:
            token = next(tmp_path.glob("fixture-ready-*"))
            token.write_text("unrelated response")
            fixture.requests()
    assert not list(tmp_path.glob("fixture-ready-*"))


def test_dead_server_and_log_overflow_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "file").write_bytes(b"fixture")
    with pytest.raises(http.HttpFixtureError, match="child exited"):
        with http.serve(tmp_path) as fixture:
            descriptor = os.pidfd_open(fixture.pid)
            try:
                os.kill(fixture.pid, signal.SIGKILL)
                with selectors.DefaultSelector() as selector:
                    selector.register(descriptor, selectors.EVENT_READ)
                    assert selector.select(3), "Server did not exit"
            finally:
                os.close(descriptor)
            fixture.requests()
    assert not list(tmp_path.glob("fixture-ready-*"))
    with pytest.raises(http.HttpFixtureError, match="log limit"):
        with http.serve(tmp_path) as fixture:
            monkeypatch.setattr(http, "MAX_LOG_BYTES", fixture.log_bytes + 1)
            _request(fixture, "/file")
            fixture.requests()
