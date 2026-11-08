import json
import os
import select
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from haberdasher.runtime import Runtime, RuntimeFailure, private_workspace


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
