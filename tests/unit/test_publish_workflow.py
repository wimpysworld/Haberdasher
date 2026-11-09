import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/publish.yml"


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
        "GH_TOKEN": "${{ github.token }}",
        "HD_SIGNING_KEY": "${{ secrets.HD_SIGNING_KEY }}",
        "HD_CLOUDFLARE_S3_API_ENDPOINT": "${{ secrets.HD_CLOUDFLARE_S3_API_ENDPOINT }}",
        "HD_CLOUDFLARE_ACCESS_KEY_ID": "${{ secrets.HD_CLOUDFLARE_ACCESS_KEY_ID }}",
        "HD_CLOUDFLARE_SECRET_ACCESS_KEY": "${{ secrets.HD_CLOUDFLARE_SECRET_ACCESS_KEY }}",
    }


@pytest.mark.parametrize("exit_code", [0, 7])
def test_publish_command(tmp_path: Path, workflow: dict[str, Any], exit_code: int) -> None:
    tools = tmp_path / "bin"
    tools.mkdir()
    bash = shutil.which("bash")
    assert bash is not None
    (tools / "bash").symlink_to(bash)
    record = tmp_path / "record.json"
    nix = tools / "nix"
    nix.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "from pathlib import Path\n"
        f"Path({str(record)!r}).write_text(json.dumps(sys.argv[1:]))\n"
        f"sys.exit({exit_code})\n"
    )
    nix.chmod(0o700)
    body = cast(str, workflow["jobs"]["publish"]["steps"][-1]["run"])
    result = subprocess.run(
        [str(tools / "bash"), "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", body],
        cwd=tmp_path,
        env={"PATH": str(tools), "HOME": str(tmp_path)},
        capture_output=True,
        timeout=10,
    )
    assert result.stdout == b""
    assert result.returncode == exit_code
    assert json.loads(record.read_text()) == [
        "develop",
        "--no-write-lock-file",
        "--command",
        "just",
        "publish",
        "--apply",
        "--remote",
        "--format",
        "all",
    ]
