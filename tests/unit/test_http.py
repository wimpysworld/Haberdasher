"""Failure paths for the HTTP process and the private native harness."""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path

import pytest

from haberdasher.runtime import RuntimeFailure, private_workspace
from tests.support import http
from tests.support.native import NativeClient


def _server_double(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    executable = tmp_path / "miniserve"
    executable.write_text(
        f"#!{sys.executable}\nimport os\nfrom pathlib import Path\n"
        f"Path({str(tmp_path / 'child-pid')!r}).write_text(str(os.getpid()))\n{body}\n"
    )
    executable.chmod(0o700)
    monkeypatch.setenv("HABERDASHER_TOOL_PATH", str(tmp_path))


def test_deterministic_mtimes_and_path_guards(tmp_path: Path) -> None:
    source = tmp_path / "metadata"
    source.write_bytes(b"one")
    http.set_generation_mtime([source], 1)
    first = source.stat().st_mtime_ns
    source.write_bytes(b"two")
    http.set_generation_mtime([source], 2)
    assert source.stat().st_mtime_ns == first + 2_000_000_000
    assert source.stat().st_mtime < time.time() - 60
    for generation in (-1, True, 1_000_001):
        with pytest.raises(ValueError, match="generation"):
            http.set_generation_mtime([source], generation)
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="Symlink"):
        http.set_generation_mtime([link], 3)
    with pytest.raises(ValueError, match="regular"):
        http.set_generation_mtime([tmp_path], 3)


def test_invalid_backend_and_missing_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="backends"), http.serve(tmp_path, backend="unknown"):
        pass
    monkeypatch.setenv("HABERDASHER_TOOL_PATH", str(tmp_path))
    with pytest.raises(http.HttpFixtureError, match="Pinned miniserve"), http.serve(tmp_path):
        pass
    assert not list(tmp_path.glob("fixture-ready-*"))


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("raise SystemExit(17)", "child exited"),
        ("import signal; signal.pause()", "deadline"),
        ("import os; os.write(1, b'x' * 65536)", "log limit"),
        ("print('[INFO] 127.0.0.1 \"BROKEN\"', flush=True)", "Cannot parse"),
    ],
)
def test_startup_failures_are_finite_and_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, message: str
) -> None:
    _server_double(tmp_path, monkeypatch, body)
    monkeypatch.setattr(http, "STARTUP_TIMEOUT", 0.3)
    monkeypatch.setattr(http, "MAX_LOG_BYTES", 1024)
    sentinel = tmp_path / "unrelated"
    sentinel.write_text("keep")
    start = time.monotonic()
    with pytest.raises(http.HttpFixtureError, match=message), http.serve(tmp_path):
        pytest.fail("Failed startup entered the context")
    assert time.monotonic() - start < 3
    with pytest.raises(ProcessLookupError):
        os.kill(int((tmp_path / "child-pid").read_text()), 0)
    assert sentinel.read_text() == "keep"
    assert not list(tmp_path.glob("fixture-ready-*"))


def test_bind_collision_has_three_attempts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = tmp_path / "attempts"
    _server_double(
        tmp_path,
        monkeypatch,
        "from pathlib import Path\n"
        f"with Path({str(attempts)!r}).open('a') as stream: stream.write('attempt\\n')\n"
        "import sys\nsys.stderr.write('Address already in use (os error 98)\\n')\n"
        "raise SystemExit(1)",
    )
    with pytest.raises(http.HttpFixtureError, match="startup failed"), http.serve(tmp_path):
        pass
    assert attempts.read_text().splitlines() == ["attempt"] * 3


def test_advertised_unrelated_listener_is_not_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        port = occupied.getsockname()[1]
        _server_double(
            tmp_path,
            monkeypatch,
            f"print('Bound to 127.0.0.1:{port}', flush=True)\nimport signal; signal.pause()",
        )
        assert http.owns_listener(os.getpid(), port)
        with pytest.raises(http.HttpFixtureError, match="does not own"), http.serve(tmp_path):
            pass
        assert occupied.getsockname()[1] == port


def test_native_private_paths_and_counters(tmp_path: Path) -> None:
    with private_workspace(tmp_path) as runtime:
        client = NativeClient(runtime, "client-one")
        assert client.root.stat().st_mode & 0o777 == 0o700
        assert client.command_log.stat().st_mode & 0o777 == 0o600
        for path in (Path("/"), tmp_path, Path("relative")):
            with pytest.raises(ValueError, match="outside"):
                client.guard_root(path)
        for relative in ("../outside", "/etc", "a/../b"):
            with pytest.raises(ValueError):
                client.path(relative)
        client.path("escape").symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(ValueError, match="Symlink"):
            client.path("escape/file")
        with pytest.raises(ValueError, match="name its private"):
            client.run([sys.executable, "--version"], install_root=client.root)
        assert client.count() == 0
        result = client.run(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", str(client.root)],
            install_root=client.root,
        )
        assert result.returncode == 0
        result = client.run(
            [sys.executable, "-c", "raise SystemExit(7)", str(client.root)],
            install_root=client.root,
        )
        assert result.returncode == 7
        with pytest.raises(RuntimeFailure, match="timed out"):
            client.run(
                [sys.executable, "-c", "import signal; signal.pause()", str(client.root)],
                install_root=client.root,
                timeout=0.1,
            )
        assert client.count() == client.count(Path(sys.executable).name) == 3
        records = [json.loads(line) for line in client.command_log.read_text().splitlines()]
        assert [record["returncode"] for record in records] == [0, 7, None]
        assert [record.returncode for record in client.commands] == [0, 7, None]
        with pytest.raises(FileExistsError):
            NativeClient(runtime, "client-one")
        base = client.base
    assert not base.exists()


def test_native_rejects_replaced_root(tmp_path: Path) -> None:
    with private_workspace(tmp_path) as runtime:
        client = NativeClient(runtime, "replaced")
        client.base.rename(runtime.root / "retained")
        client.base.symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(ValueError, match="root changed"):
            client.guard_root(client.root)


def test_listener_rejects_dead_pid() -> None:
    assert not http.owns_listener(2**30, 12345)
