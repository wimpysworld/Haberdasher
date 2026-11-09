import json
import os
import select
import shutil
import signal
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from haberdasher.runtime import (
    STORAGE_VARIABLES,
    Runtime,
    RuntimeFailure,
    _gh_login_token,  # pyright: ignore[reportPrivateUsage]
    private_workspace,
)


@pytest.mark.parametrize("kind", ["native", "github", "storage"])
def test_environment_profiles(tmp_path: Path, kind: str) -> None:
    inherited = {
        "PATH": os.defpath,
        "GH_TOKEN": "synthetic-github-token",
        "GITHUB_TOKEN": "synthetic-second-github-token",
        "HD_SIGNING_KEY": "synthetic-signing-key",
        "HD_SIGNING_KEY_FILE": "/must/not/read/key",
        "HD_CLOUDFLARE_ACCESS_KEY_ID": "synthetic-storage-id",
        "HD_CLOUDFLARE_SECRET_ACCESS_KEY": "synthetic-storage-secret",
        "HD_CLOUDFLARE_S3_API_ENDPOINT": "https://synthetic-storage.invalid",
        "AWS_PROFILE": "do-not-inherit",
        "AWS_SESSION_TOKEN": "do-not-inherit",
        "RCLONE_CONFIG_OTHER_ACCESS_KEY_ID": "do-not-inherit",
        "HOME": "/must/not/read/home",
        "GNUPGHOME": "/must/not/read/gnupg",
        "PYTHONPATH": "/must/not/import",
        "LD_PRELOAD": "/must/not/load",
    }
    runtime = Runtime(tmp_path, environ=inherited)
    try:
        command = [sys.executable, "-c", "import os,json; print(json.dumps(dict(os.environ)))"]
        result = runtime.run(command, env_kind=kind)
        env = json.loads(result.stdout)
        assert result.returncode == 0
        assert env["HOME"] == str(tmp_path / "home")
        assert env["GNUPGHOME"] == str(tmp_path / "gnupg")
        assert "HD_SIGNING_KEY" not in env and "HD_SIGNING_KEY_FILE" not in env
        for name in (
            "AWS_PROFILE",
            "AWS_SESSION_TOKEN",
            "RCLONE_CONFIG_OTHER_ACCESS_KEY_ID",
            "PYTHONPATH",
            "LD_PRELOAD",
        ):
            assert name not in env
        assert ("GH_TOKEN" in env) == (kind == "github")
        assert ("GITHUB_TOKEN" in env) == (kind == "github")
        assert ("HD_CLOUDFLARE_ACCESS_KEY_ID" in env) == (kind == "storage")
        assert ("AWS_ACCESS_KEY_ID" in env) == (kind == "storage")
        if kind == "storage":
            assert env["AWS_MAX_ATTEMPTS"] == "1"
            assert env["AWS_EC2_METADATA_DISABLED"] == "true"
        assert b"synthetic-" not in result.stdout
    finally:
        runtime.close()


@pytest.mark.parametrize("kind", ["native", "github", "storage"])
@pytest.mark.parametrize("explicit_cwd", [False, True])
def test_relative_root_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, explicit_cwd: bool
) -> None:
    monkeypatch.chdir(tmp_path)
    runtime = Runtime(Path("work"), environ={"PATH": ""})
    cwd = tmp_path / "elsewhere" if explicit_cwd else None
    if cwd is not None:
        cwd.mkdir()
    try:
        result = runtime.run(
            [
                sys.executable,
                "-c",
                "import json,os; from pathlib import Path; "
                "(Path(os.environ['HOME']) / 'probe').write_text(str(Path.cwd())); "
                "print(json.dumps(dict(os.environ)))",
            ],
            cwd=cwd,
            env_kind=kind,
        )
        assert result.returncode == 0, result.stderr.decode()
        root = tmp_path / "work"
        assert runtime.root == root
        assert (root / "home/probe").read_text() == str(cwd or root)
        paths = {
            "HOME": "home",
            "GNUPGHOME": "gnupg",
            "XDG_CONFIG_HOME": "home/.config",
            "XDG_DATA_HOME": "home/.local/share",
            "XDG_CACHE_HOME": "home/.cache",
            "XDG_STATE_HOME": "home/.local/state",
            "XDG_RUNTIME_DIR": "run",
            "TMPDIR": "tmp",
        }
        if kind == "github":
            paths["GH_CONFIG_DIR"] = "home/.config/gh"
        elif kind == "storage":
            paths.update(
                {
                    "AWS_CONFIG_FILE": "aws-config",
                    "AWS_SHARED_CREDENTIALS_FILE": "aws-credentials",
                    "RCLONE_CONFIG": "rclone.conf",
                }
            )
        env = json.loads(result.stdout)
        for name, relative in paths.items():
            assert env[name] == str(root / relative)
    finally:
        runtime.close()


@pytest.mark.parametrize("link", ["work", "work/home"])
def test_relative_root_rejects_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, link: str
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    path = Path(link)
    path.parent.mkdir(exist_ok=True)
    path.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="Symlink in private"):
        Runtime(Path("work"), environ={"PATH": ""})
    assert not list(target.iterdir())


def test_run_input_nonzero_and_limits(tmp_path: Path) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": os.defpath}, max_output=300_000)
    try:
        result = runtime.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.exit(7)",
            ],
            input=b"x" * 200_000,
        )
        assert result.stdout == b"x" * 200_000
        assert result.returncode == 7
        with pytest.raises(RuntimeFailure, match="output limit"):
            runtime.run([sys.executable, "-c", "import os;\nwhile True: os.write(1, b'x' * 65536)"])
        with pytest.raises(RuntimeFailure, match="timed out"):
            runtime.run([sys.executable, "-c", "import signal; signal.pause()"], timeout=0.1)
        with pytest.raises(RuntimeFailure, match="start"):
            runtime.run([str(tmp_path / "missing-command")])
        with pytest.raises(ValueError):
            runtime.run([sys.executable], env_kind="unsafe")
        with pytest.raises(ValueError):
            runtime.run([sys.executable], timeout=float("nan"))
        runtime.close()
        runtime.close()
        with pytest.raises(RuntimeFailure, match="closed"):
            runtime.run([sys.executable])
    finally:
        runtime.close()


def test_redact_arguments_and_error_output(tmp_path: Path) -> None:
    runtime = Runtime(tmp_path, environ={"GH_TOKEN": "synthetic-private-value", "PATH": os.defpath})
    try:
        result = runtime.run(
            [
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1], file=sys.stderr)",
                "synthetic-private-value",
            ]
        )
        assert result.stderr == b"[REDACTED]\n"
        assert result.args[-1] == "[REDACTED]"
    finally:
        runtime.close()


@pytest.mark.parametrize("failure", [False, True])
def test_workspace_permissions_and_cleanup(tmp_path: Path, failure: bool) -> None:
    sentinel = tmp_path / "unrelated"
    sentinel.write_text("keep")
    previous_mask = os.umask(0o022)
    root: Path | None = None
    try:
        try:
            with private_workspace(tmp_path) as runtime:
                root = runtime.root
                assert root.stat().st_mode & 0o777 == 0o700
                for path in root.rglob("*"):
                    assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
                assert "SHA256" in (root / "gnupg/gpg.conf").read_text()
                result = runtime.run(
                    [
                        sys.executable,
                        "-c",
                        "from pathlib import Path; Path('child').write_text('private')",
                    ]
                )
                assert result.returncode == 0
                assert (root / "child").stat().st_mode & 0o777 == 0o600
                if failure:
                    raise ValueError("injected")
        except ValueError:
            if not failure:
                raise
        assert root is not None and not root.exists()
        assert sentinel.read_text() == "keep"
        assert os.umask(0o022) == 0o022
    finally:
        os.umask(previous_mask)


def test_long_parent_uses_short_socket_path(tmp_path: Path) -> None:
    base = tmp_path / ("a" * 100)
    base.mkdir()
    with private_workspace(base) as runtime:
        root = runtime.root
        assert root.parent == Path("/tmp")
        assert len(os.fsencode(root / "gnupg/S.gpg-agent.browser")) < 107
    assert not root.exists()
    assert base.exists()
    assert not list(base.iterdir())


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_signals_stop_children_before_cleanup(tmp_path: Path, sig: signal.Signals) -> None:
    marker = tmp_path / "workspace"
    pidfile = tmp_path / "pid"
    child = f"import os,signal; from pathlib import Path; Path({str(pidfile)!r}).write_text(str(os.getpid())); os.kill(os.getppid(), {int(sig)}); signal.pause()"
    script = f"""import sys
from pathlib import Path
from haberdasher.runtime import private_workspace
with private_workspace(Path({str(tmp_path)!r})) as runtime:
    Path({str(marker)!r}).write_text(str(runtime.root))
    runtime.run([sys.executable, '-c', {child!r}])
"""
    result = subprocess.run(
        [sys.executable, "-c", script], env={"PATH": os.defpath}, capture_output=True, timeout=15
    )
    assert result.returncode == 128 + sig, result.stderr.decode()
    assert not Path(marker.read_text()).exists()
    with pytest.raises(ProcessLookupError):
        os.kill(int(pidfile.read_text()), 0)


def test_success_stops_background_group(tmp_path: Path) -> None:
    pidfile = tmp_path / "descendant"
    command = f"""import os,signal
from pathlib import Path
pid = os.fork()
if pid == 0:
    os.close(1)
    os.close(2)
    signal.pause()
else:
    Path({str(pidfile)!r}).write_text(str(pid))
"""
    runtime = Runtime(tmp_path / "work", environ={"PATH": os.defpath})
    try:
        assert runtime.run([sys.executable, "-c", command]).returncode == 0
        pid = int(pidfile.read_text())
        status = Path(f"/proc/{pid}/status")
        if sys.platform == "linux" and status.exists():
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                return
            try:
                assert select.select([descriptor], [], [], 2)[0]
            finally:
                os.close(descriptor)
    finally:
        runtime.close()


@pytest.mark.parametrize("external", [False, True])
@pytest.mark.parametrize("failure", [None, "kill", "query", "remove", "start"])
def test_close_cleans_only_owned_socketdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, external: bool, failure: str | None
) -> None:
    runtime = Runtime(tmp_path / "owned", environ={"PATH": "", "GH_TOKEN": "synthetic"})
    home = runtime.root / "gnupg"
    socketdir = tmp_path / "owned-sockets" if external else home
    socketdir.mkdir(exist_ok=True)
    sentinel = tmp_path / "unrelated"
    sentinel.write_text("keep")
    commands: list[list[str]] = []

    def run(argv: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(list(argv))
        assert argv[:3] == ["gpgconf", "--homedir", str(home)]
        if failure == "start":
            raise RuntimeFailure("Could not start native command")
        stage = {"--kill": "kill", "--list-dirs": "query", "--remove-socketdir": "remove"}[argv[3]]
        code = int(stage == failure)
        if stage == "remove" and not code:
            socketdir.rmdir()
        return subprocess.CompletedProcess(argv, code, os.fsencode(socketdir) + b"\n", b"")

    def which(_command: str, *, path: str) -> str:
        return "/gpgconf"

    with monkeypatch.context() as patch:
        patch.setattr("haberdasher.runtime.shutil.which", which)
        patch.setattr(runtime, "run", run)
        runtime.close()
        runtime.close()
    expected = [["--kill", "all"]]
    if failure not in {"kill", "start"}:
        expected.append(["--list-dirs", "socketdir"])
        if failure != "query" and external:
            expected.append(["--remove-socketdir"])
    assert [command[3:] for command in commands] == expected
    assert socketdir.exists() == (not external or failure is not None)
    assert home.is_dir()
    assert sentinel.read_text() == "keep"
    assert "GH_TOKEN" not in runtime.environment_for("github")
    with pytest.raises(RuntimeFailure, match="closed"):
        runtime.run([sys.executable])


def test_private_parent_guards(tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError), private_workspace(link):
        pass
    with pytest.raises(ValueError), private_workspace(Path.cwd()):
        pass


def test_help_and_collection_need_no_credentials() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--help"],
        env={"PATH": os.defpath},
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0
    assert b"--collect-only" in result.stdout


def test_github_falls_back_to_stored_gh_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def login(path: str) -> str:
        calls.append(path)
        return "synthetic-login-token"

    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr("haberdasher.runtime._gh_login_token", login)
    runtime = Runtime(tmp_path / "workspace")
    try:
        assert "GH_TOKEN" not in runtime.environment_for("native")
        assert runtime.environment_for("github")["GH_TOKEN"] == "synthetic-login-token"
        assert runtime.environment_for("github")["GH_TOKEN"] == "synthetic-login-token"
        assert len(calls) == 1
    finally:
        runtime.close()


def test_gh_login_token_gets_only_login_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "bin"
    binary.mkdir()
    gh = binary / "gh"
    gh.write_text(
        f"#!{shutil.which('sh')}\n"
        f"{shutil.which('env')} -0 >'{tmp_path / 'env'}'\n"
        "echo synthetic-login-token\n"
    )
    gh.chmod(0o700)
    for key in (*STORAGE_VARIABLES, "HD_SIGNING_KEY", "HD_SIGNING_KEY_FILE", "UNRELATED"):
        monkeypatch.setenv(key, "do-not-inherit")
    for key in ("HOME", "GH_CONFIG_DIR", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
        monkeypatch.setenv(key, f"synthetic-{key}")
    assert _gh_login_token(str(binary)) == "synthetic-login-token"
    env = dict(line.split("=", 1) for line in (tmp_path / "env").read_text().split("\0") if line)
    assert "do-not-inherit" not in env.values()
    assert env["GH_CONFIG_DIR"] == "synthetic-GH_CONFIG_DIR"
    assert env["DBUS_SESSION_BUS_ADDRESS"] == "synthetic-DBUS_SESSION_BUS_ADDRESS"
    assert (env["PATH"], env["GH_PROMPT_DISABLED"]) == (str(binary), "1")


def test_explicit_environment_never_reads_gh_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def login(_path: str) -> str:
        raise AssertionError("stored login must not be read")

    monkeypatch.setattr("haberdasher.runtime._gh_login_token", login)
    runtime = Runtime(tmp_path / "workspace", environ={"PATH": os.defpath})
    try:
        assert "GH_TOKEN" not in runtime.environment_for("github")
    finally:
        runtime.close()


def test_progress_receives_redacted_stderr_lines_as_they_arrive(tmp_path: Path) -> None:
    runtime = Runtime(
        tmp_path, environ={"PATH": os.defpath, "HD_CLOUDFLARE_ACCESS_KEY_ID": "synthetic-id"}
    )
    lines: list[str] = []
    script = (
        "import sys, time\n"
        "sys.stderr.write('first synthetic-id\\nsec'); sys.stderr.flush(); time.sleep(0.1)\n"
        "sys.stderr.write('ond\\nunterminated'); print('stdout')\n"
    )
    try:
        result = runtime.run([sys.executable, "-c", script], progress=lines.append)
    finally:
        runtime.close()
    assert lines == ["first [REDACTED]", "second"]
    assert result.stderr == b"first [REDACTED]\nsecond\nunterminated"
    assert result.stdout == b"stdout\n"
