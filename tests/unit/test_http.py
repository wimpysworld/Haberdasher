"""Failure paths for the HTTP process and the private native harness."""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock

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


def test_native_private_paths_and_counters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
        runner = Mock(
            side_effect=[
                CompletedProcess([], 0, b"", b""),
                CompletedProcess([], 7, b"", b""),
                RuntimeFailure("Native command timed out"),
            ]
        )
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "run", runner)
            with pytest.raises(ValueError, match="private installation root"):
                client.run([sys.executable, "--version"], install_root=client.root)
            runner.assert_not_called()
            assert client.count() == 0
            argv = ["apk", "--root", str(client.root), "info"]
            assert client.run(argv, install_root=client.root).returncode == 0
            assert client.run(argv, install_root=client.root).returncode == 7
            with pytest.raises(RuntimeFailure, match="timed out"):
                client.run(argv, install_root=client.root, timeout=0.1)
            runner.assert_called_with(argv, cwd=client.base, input=None, timeout=0.1)
        assert client.count() == client.count("apk") == 3
        records = [json.loads(line) for line in client.command_log.read_text().splitlines()]
        assert [record["returncode"] for record in records] == [0, 7, None]
        assert [record.returncode for record in client.commands] == [0, 7, None]
        with pytest.raises(FileExistsError):
            NativeClient(runtime, "client-one")
        base = client.base
    assert not base.exists()


def _native_argv(client: NativeClient, kind: str) -> list[str]:
    root = str(client.root)
    if kind == "apt":
        return [
            "env",
            f"APT_CONFIG={client.path('config/apt.conf')}",
            "fakeroot",
            "apt-get",
            "-o",
            f"Dir::State::status={root}/var/lib/dpkg/status",
            f"-oDPkg::Options::=--root={root}",
            f"-oDPkg::Options::=--admindir={root}/var/lib/dpkg",
            "update",
        ]
    if kind == "dpkg-query":
        return ["dpkg-query", f"--admindir={root}/var/lib/dpkg", "-W", "fixture"]
    if kind == "rpm":
        return ["rpm", "--define", "_dbpath /var/lib/rpm", "--root", root, "-q", "fixture"]
    if kind == "dnf":
        local = "/" + str(client.base.relative_to(client.runtime.root))
        home = f"{local}/home"
        return [
            "env",
            "FAKECHROOT_EXCLUDE_PATH=/nix/store",
            f"HD_PRIVATE_INSTALL_ROOT={root}",
            "fakechroot",
            "-e",
            "none",
            "fakeroot",
            "chroot",
            str(client.runtime.root),
            "/nix/store/fixture-coreutils/bin/env",
            f"HOME={home}",
            f"GNUPGHOME={local}/gnupg",
            "TMPDIR=/tmp",
            f"XDG_CONFIG_HOME={home}/.config",
            f"XDG_DATA_HOME={home}/.local/share",
            f"XDG_CACHE_HOME={home}/.cache",
            f"XDG_STATE_HOME={home}/.local/state",
            "XDG_RUNTIME_DIR=/run",
            "/nix/store/fixture-dnf5/bin/dnf5",
            "--config",
            f"{local}/config/dnf.conf",
            "--installroot",
            f"{local}/root",
            "--releasever",
            "1",
            "--no-plugins",
            "--repo",
            "proof",
            "--assumeyes",
            "--refresh",
            f"--setopt=cachedir={local}/cache",
            "install",
            "fixture",
        ]
    if kind == "arch":
        return [
            "fakeroot",
            "pacman",
            "--config",
            str(client.path("config/pacman.conf")),
            "--root",
            root,
            "--noconfirm",
            "-S",
            "fixture",
        ]
    if kind == "apk":
        return ["apk", "--root", root, "--cache-dir", str(client.path("cache")), "info"]
    assert kind == "flatpak"
    return [
        "env",
        f"FLATPAK_USER_DIR={root}",
        "XDG_DATA_DIRS=/nix/store/fixture/share",
        f"HOME={client.path('config')}",
        f"XDG_DATA_HOME={client.path('state')}",
        f"XDG_CACHE_HOME={client.path('cache')}",
        "flatpak",
        "--user",
        "list",
    ]


@pytest.mark.parametrize("kind", ["apt", "dpkg-query", "rpm", "dnf", "arch", "apk", "flatpak"])
def test_native_accepts_fixture_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    with private_workspace(tmp_path) as runtime:
        client = NativeClient(runtime, "valid")
        argv = _native_argv(client, kind)
        runner = Mock(return_value=CompletedProcess(argv, 0, b"", b""))
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "run", runner)
            assert client.run(argv, install_root=client.root).returncode == 0
            runner.assert_called_once_with(argv, cwd=client.base, input=None, timeout=120)
        assert client.count() == 1


@pytest.mark.parametrize(
    ("kind", "override"),
    [
        ("apk", ["--root", "/"]),
        ("apk", ["--root=/"]),
        ("apk", ["-p", "/"]),
        ("apk", ["-p/"]),
        ("apk", ["-p=/"]),
        ("arch", ["--root=/"]),
        ("arch", ["-r", "/"]),
        ("arch", ["-r/"]),
        ("arch", ["-Sr/"]),
        ("arch", ["--sysroot=/"]),
        ("arch", ["--config=/tmp/other.conf"]),
        ("rpm", ["--root=/"]),
        ("rpm", ["-r", "/"]),
        ("rpm", ["-r/"]),
        ("dpkg-query", ["--admindir=/var/lib/dpkg"]),
        ("dpkg-query", ["--root=/"]),
        ("dnf", ["--installroot", "/"]),
        ("dnf", ["--installroot=/"]),
        ("dnf", ["--setopt=installroot=/"]),
        ("dnf", ["--config=/other.conf"]),
        ("dnf", ["-c/other.conf"]),
        ("apt", ["-oDPkg::Options::=--root=/"]),
        ("apt", ["-o", "DPkg::Options::=--admindir=/var/lib/dpkg"]),
        ("apt", ["--option=DPkg::Options::=--instdir=/"]),
        ("apt", ["--option", "DPkg::Options::=-R/"]),
        ("apt", ["-odpkg::options::=--root=/"]),
        ("apt", ["-oDPkg::Options=--root=/"]),
        ("apt", ["-oDir::Bin::dpkg=/other"]),
        ("apt", ["-c", "/other.conf"]),
        ("apt", ["--config-file=/other.conf"]),
        ("flatpak", ["--system"]),
        ("flatpak", ["--installation=default"]),
        ("flatpak", ["--installation", "default"]),
        ("flatpak", ["--user", "--system"]),
    ],
)
def test_native_rejects_root_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, override: list[str]
) -> None:
    with private_workspace(tmp_path) as runtime:
        client = NativeClient(runtime, "overrides")
        runner = Mock(return_value=CompletedProcess([], 0, b"", b""))
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "run", runner)
            with pytest.raises(ValueError, match="private installation root"):
                client.run([*_native_argv(client, kind), *override], install_root=client.root)
            runner.assert_not_called()
        assert client.count() == 0
        assert client.command_log.read_bytes() == b""


@pytest.mark.parametrize(
    "case",
    [
        "unrelated",
        "missing",
        "traversal",
        "descendant",
        "symlink",
        "duplicate",
        "python",
        "apt-status-only",
        "apt-missing-admindir",
        "apt-wrong-root",
        "apt-wrong-admindir",
        "flatpak-wrong-root",
        "flatpak-no-user",
        "flatpak-duplicate-env",
        "dnf-marker-only",
        "dnf-logical-slash",
        "dnf-host-root",
        "dnf-traversal",
        "dnf-inner-env-override",
        "dnf-missing-wrapper",
        "dnf-outside-chroot",
        "dnf-chroot-is-install-root",
        "dnf-symlink-chroot",
        "dnf-unrelated-chroot",
        "root-as-option-value",
        "root-after-terminator",
    ],
)
def test_native_rejects_false_root_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    with private_workspace(tmp_path) as runtime:
        client = NativeClient(runtime, "false-root")
        root = str(client.root)
        argv = ["apk", "--root", "/", "--cache-dir", root]
        if case == "missing":
            argv = ["apk", "--cache-dir", root]
        elif case == "traversal":
            argv = ["apk", "--root", root + "/../../../../.."]
        elif case == "descendant":
            argv = ["apk", "--root", root + "/nested"]
        elif case == "symlink":
            client.path("root/link").symlink_to(tmp_path, target_is_directory=True)
            argv = ["apk", "--root", root + "/link"]
        elif case == "duplicate":
            argv = ["apk", "--root", root, "--root", root]
        elif case == "python":
            argv = [sys.executable, "-c", "pass", root]
        elif case.startswith("apt-"):
            argv = _native_argv(client, "apt")
            if case == "apt-status-only":
                argv = [arg for arg in argv if not arg.startswith("-oDPkg::Options")]
            elif case == "apt-missing-admindir":
                argv = [arg for arg in argv if "--admindir" not in arg]
            elif case == "apt-wrong-root":
                argv = [arg.replace(f"--root={root}", "--root=/") for arg in argv]
            else:
                argv = [
                    arg.replace(f"--admindir={root}/var/lib/dpkg", "--admindir=/var/lib/dpkg")
                    for arg in argv
                ]
        elif case.startswith("flatpak-"):
            argv = _native_argv(client, "flatpak")
            if case == "flatpak-no-user":
                argv.remove("--user")
            elif case == "flatpak-wrong-root":
                argv[1] = "FLATPAK_USER_DIR=/"
            else:
                argv.insert(2, "FLATPAK_USER_DIR=/")
        elif case.startswith("dnf-"):
            argv = _native_argv(client, "dnf")
            if case == "dnf-marker-only":
                index = argv.index("--installroot")
                del argv[index : index + 2]
            elif case == "dnf-logical-slash":
                argv[argv.index("--installroot") + 1] = "/"
            elif case == "dnf-host-root":
                argv[argv.index("--installroot") + 1] = root
            elif case == "dnf-traversal":
                argv[argv.index("--installroot") + 1] += "/../../../.."
            elif case == "dnf-inner-env-override":
                argv.insert(argv.index("TMPDIR=/tmp"), "FAKECHROOT_BASE=/")
            elif case == "dnf-missing-wrapper":
                argv.remove("fakechroot")
            elif case == "dnf-outside-chroot":
                argv[argv.index("chroot") + 1] = str(tmp_path)
            elif case == "dnf-chroot-is-install-root":
                argv[argv.index("chroot") + 1] = root
            elif case == "dnf-symlink-chroot":
                link = client.path("config/chroot")
                link.symlink_to(runtime.root, target_is_directory=True)
                argv[argv.index("chroot") + 1] = str(link)
            else:
                argv = ["apk", "--root", "/", "chroot", root]
        elif case == "root-as-option-value":
            argv = ["apk", "--cache-dir", "--root", root]
        elif case == "root-after-terminator":
            argv = ["apk", "--", "--root", root]
        runner = Mock(return_value=CompletedProcess([], 0, b"", b""))
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "run", runner)
            with pytest.raises(ValueError, match="private installation root"):
                client.run(argv, install_root=client.root)
            runner.assert_not_called()
        assert client.count() == 0


@pytest.mark.parametrize("relative", ["root", "root/var", "root/var/lib/dpkg"])
def test_native_rejects_symlinked_installation_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    with private_workspace(tmp_path) as runtime:
        client = NativeClient(runtime, "linked")
        argv = _native_argv(client, "dpkg-query")
        link = client.path(relative)
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.exists():
            link.rename(client.path("retained"))
        link.symlink_to(tmp_path, target_is_directory=True)
        runner = Mock(return_value=CompletedProcess([], 0, b"", b""))
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "run", runner)
            with pytest.raises(ValueError, match="Symlink"):
                client.run(argv, install_root=client.root)
            runner.assert_not_called()
        assert client.count() == 0


def test_native_rejects_replaced_root(tmp_path: Path) -> None:
    with private_workspace(tmp_path) as runtime:
        client = NativeClient(runtime, "replaced")
        client.base.rename(runtime.root / "retained")
        client.base.symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(ValueError, match="root changed"):
            client.guard_root(client.root)


def test_listener_rejects_dead_pid() -> None:
    assert not http.owns_listener(2**30, 12345)
