import json
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/publish.yml"
POLICY = "# synthetic policy: %s \\n $() `ignored`\napprovals: {}\nnote: 'café'\n\n"


@pytest.fixture
def workflow() -> dict[str, Any]:
    return cast(dict[str, Any], yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader))


def test_publish_gates_and_step_inputs(workflow: dict[str, Any]) -> None:
    job = workflow["jobs"]["publish"]
    assert workflow["on"] == {"workflow_dispatch": ""}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "haberdasher-publisher",
        "cancel-in-progress": "false",
    }
    assert job["if"] == (
        "vars.HD_PUBLISH_ENABLED == 'true' && "
        "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
    )
    assert job["environment"] == "publisher"
    assert "env" not in workflow and "env" not in job
    steps = job["steps"]
    assert steps[0]["with"]["persist-credentials"] == "false"
    assert all("env" not in step for step in steps[:-1])
    assert steps[-1]["shell"] == "bash"
    assert steps[-1]["env"] == {
        "HD_PUBLISH_POLICY": "${{ secrets.HD_PUBLISH_POLICY }}",
        "GH_TOKEN": "${{ github.token }}",
        "HD_SIGNING_KEY": "${{ secrets.HD_SIGNING_KEY }}",
        "HD_CLOUDFLARE_S3_API_ENDPOINT": "${{ secrets.HD_CLOUDFLARE_S3_API_ENDPOINT }}",
        "HD_CLOUDFLARE_ACCESS_KEY_ID": "${{ secrets.HD_CLOUDFLARE_ACCESS_KEY_ID }}",
        "HD_CLOUDFLARE_SECRET_ACCESS_KEY": "${{ secrets.HD_CLOUDFLARE_SECRET_ACCESS_KEY }}",
    }


@pytest.mark.parametrize(
    ("policy", "exit_code", "sig"),
    [
        (POLICY, 0, 0),
        (POLICY.rstrip("\n"), 0, 0),
        (POLICY, 7, 0),
        ("", 0, 0),
        (None, 0, 0),
        (POLICY, 0, signal.SIGHUP),
        (POLICY, 0, signal.SIGINT),
        (POLICY, 0, signal.SIGTERM),
    ],
)
def test_publish_policy_lifecycle(
    tmp_path: Path,
    workflow: dict[str, Any],
    policy: str | None,
    exit_code: int,
    sig: int,
) -> None:
    checkout = tmp_path / "checkout with spaces"
    checkout.mkdir()
    tools = tmp_path / "bin"
    tools.mkdir()
    for name in ("bash", "mktemp", "rm"):
        executable = shutil.which(name)
        assert executable is not None
        (tools / name).symlink_to(executable)
    record = tmp_path / "record.json"
    nix = tools / "nix"
    nix.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "assert sys.argv[1:4] == ['develop', '--no-write-lock-file', '--command']\n"
        "assert sys.argv[4] == 'just'\n"
        f"os.execv({str(tools / 'just')!r}, sys.argv[4:])\n"
    )
    nix.chmod(0o700)
    just = tools / "just"
    just.write_text(
        f"#!{sys.executable}\n"
        "import json, os, stat, sys\n"
        "from pathlib import Path\n"
        "assert sys.argv[1:5] == ['publish', '--apply', '--remote', '--policy-file']\n"
        "assert len(sys.argv) == 6\n"
        "policy = Path(sys.argv[5])\n"
        "record = {\n"
        "    'path': str(policy.resolve()),\n"
        "    'bytes': policy.read_bytes().hex(),\n"
        "    'mode': stat.S_IMODE(policy.stat().st_mode),\n"
        "    'umask': os.umask(0o077),\n"
        "    'policy_in_env': 'HD_PUBLISH_POLICY' in os.environ,\n"
        "}\n"
        f"Path({str(record)!r}).write_text(json.dumps(record))\n"
        f"if {int(sig)}: os.kill(os.getppid(), {int(sig)})\n"
        f"sys.exit({exit_code})\n"
    )
    just.chmod(0o700)
    env = {"PATH": str(tools), "TMPDIR": str(checkout), "HOME": str(tmp_path)}
    if policy is not None:
        env["HD_PUBLISH_POLICY"] = policy
    body = cast(str, workflow["jobs"]["publish"]["steps"][-1]["run"])
    result = subprocess.run(
        [str(tools / "bash"), "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", body],
        cwd=checkout,
        env=env,
        capture_output=True,
        timeout=10,
    )
    assert result.stdout == b""
    if not policy:
        assert result.returncode != 0
        assert result.stderr == b"HD_PUBLISH_POLICY requires an approved policy.\n"
        assert not record.exists()
    else:
        assert result.returncode == (128 + sig if sig else exit_code), result.stderr.decode()
        assert result.stderr == b""
        observed = json.loads(record.read_text())
        path = Path(observed["path"])
        assert path.is_absolute()
        assert path.parent == Path("/tmp")
        assert not path.is_relative_to(checkout)
        assert not path.is_relative_to(WORKFLOW.parents[2])
        assert not path.is_relative_to("/nix/store")
        assert observed["bytes"] == policy.encode().hex()
        assert observed["mode"] == 0o600
        assert observed["umask"] == 0o077
        assert observed["policy_in_env"] is False
        assert not path.exists()
    assert list(checkout.iterdir()) == []
