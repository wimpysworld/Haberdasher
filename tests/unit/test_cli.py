from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from haberdasher import cli, discovery, publish, state
from haberdasher.config import (
    PRODUCTION_FINGERPRINT,
    Config,
    FormatPolicy,
    Policy,
    StoragePolicy,
)
from haberdasher.core import FORMATS
from haberdasher.runtime import Runtime


def empty_scan(*args: object, **kwargs: object) -> discovery.CompleteScan:
    return discovery.CompleteScan(discovery.DiscoveryState(), (), (), (), ())


def configured(names: tuple[str, ...], buckets: tuple[str, ...] | None = None) -> Config:
    return Config(
        ("synthetic/test",),
        {name: FormatPolicy(name) for name in names},
        storage=StoragePolicy("r2", {name: f"test-{name}" for name in buckets or names}),
    )


def test_default_plan_never_opens_store_or_signer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("sources: [synthetic/test]\n")
    monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(tmp_path / "must-not-open"))
    with (
        patch.object(discovery, "scan_releases", side_effect=empty_scan) as scan,
        patch.object(cli, "LocalStore", side_effect=AssertionError("storage opened")),
        patch.object(cli, "R2Store", side_effect=AssertionError("storage opened")),
        patch.object(state, "acquire", side_effect=AssertionError("lock acquired")),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
        patch("haberdasher.signing.SigningSession", side_effect=AssertionError("key imported")),
    ):
        assert cli.main(["--config", str(config)]) == 0
        scan.assert_called_once()
    assert '"mode":"plan"' in capsys.readouterr().out


@pytest.mark.parametrize(
    "arguments",
    [
        ["--apply"],
        ["--remote"],
        ["--local-root", "/tmp/unused"],
        ["--break-lock"],
        ["--plan", "--local-root", "/tmp/unused"],
    ],
)
def test_invalid_modes_fail_before_runtime(arguments: list[str]) -> None:
    with patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")):
        assert cli.main(arguments) == 1


@pytest.mark.parametrize(
    "arguments",
    [
        ["--plan", "--apply"],
        ["--apply", "--break-lock"],
        ["--plan", "--break-lock"],
        ["--apply", "--remote", "--local-root", "/tmp/unused"],
    ],
)
def test_argparse_rejects_incompatible_modes(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 2


@pytest.mark.parametrize(
    "config",
    [
        "sources: [synthetic/test]\n",
        "sources: [synthetic/test]\nformats: {apt: {}}\nstorage: {public: {rpm: test-rpm}}\n",
    ],
    ids=["no-storage", "no-configured-bucket"],
)
def test_remote_denied_before_credentials_or_workspace(
    tmp_path: Path, config: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(config)
    with (
        patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")),
        patch.dict(os.environ, clear=True),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["--apply", "--remote", "--config", str(path)]) == 1
    assert "--remote needs a storage bucket" in capsys.readouterr().err


def test_signing_fingerprint_requires_local_root() -> None:
    with patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")):
        assert cli.main(["--apply", "--remote", "--signing-fingerprint", "A" * 40]) == 1


@pytest.mark.parametrize(
    "destination",
    [
        "ancestor",
        "grandparent",
        "checkout",
        "child",
        "sibling",
        "source",
        "source-child",
        "alias",
        "alias-child",
        "home",
        "root",
    ],
)
@pytest.mark.parametrize("marker_kind", ["file", "directory", "symlink"])
@pytest.mark.parametrize("mode", [["--apply"], ["--break-lock"]])
def test_local_root_denied_before_workspace_store_or_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    destination: str,
    marker_kind: str,
    mode: list[str],
) -> None:
    checkout = tmp_path / "parent/checkout"
    docs = checkout / "docs"
    docs.mkdir(parents=True)
    source_checkout = tmp_path / "source-checkout"
    module = source_checkout / "src/haberdasher/cli.py"
    module.parent.mkdir(parents=True)
    module.touch()
    module_alias = tmp_path / "module-alias.py"
    module_alias.symlink_to(module)
    monkeypatch.setattr(cli, "__file__", str(module_alias))
    for boundary in (checkout, source_checkout):
        marker = boundary / ".git"
        if marker_kind == "file":
            marker.write_text("gitdir: must-not-open\n")
        elif marker_kind == "directory":
            marker.mkdir()
        else:
            marker.symlink_to(tmp_path / "must-not-follow")
    home = tmp_path / "home"
    home.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(checkout, target_is_directory=True)
    monkeypatch.chdir(alias / "docs")
    monkeypatch.setenv("HOME", str(home))
    roots = {
        "ancestor": checkout.parent,
        "grandparent": tmp_path,
        "checkout": checkout,
        "child": docs / "store",
        "sibling": checkout / "store",
        "source": source_checkout,
        "source-child": source_checkout / "store",
        "alias": alias,
        "alias-child": alias / "store",
        "home": home,
        "root": Path("/"),
    }
    before = set(tmp_path.rglob("*"))
    with (
        patch.object(Path, "open", side_effect=AssertionError("file opened")),
        patch.object(state, "acquire", side_effect=AssertionError("lock acquired")),
        patch.object(state, "break_locks", side_effect=AssertionError("locks broken")),
        patch.object(cli, "load_config", side_effect=AssertionError("config opened")),
        patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")),
        patch.object(cli, "LocalStore", side_effect=AssertionError("storage opened")),
        patch.object(cli, "R2Store", side_effect=AssertionError("storage opened")),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main([*mode, "--local-root", str(roots[destination])]) == 1
    error = capsys.readouterr().err
    assert ("symlinks" if "alias" in destination else "disposable local root") in error
    assert set(tmp_path.rglob("*")) == before


@pytest.mark.parametrize("destination", ["cwd", "child", "sibling", "site-packages", "nearest"])
def test_local_root_uses_nearest_markers_or_packaged_cwd_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, destination: str
) -> None:
    working_path = tmp_path / "work"
    working_path.mkdir()
    site_packages = tmp_path / "installed/lib/python3.14/site-packages"
    module = site_packages / "haberdasher/cli.py"
    module.parent.mkdir(parents=True)
    module.touch()
    monkeypatch.chdir(working_path)
    monkeypatch.setattr(cli, "__file__", str(module))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    roots = {
        "cwd": working_path,
        "child": working_path / "store",
        "sibling": tmp_path / "store",
        "site-packages": site_packages / "store",
    }
    if destination == "nearest":
        (tmp_path / ".git").mkdir()
        (working_path / ".git").symlink_to(tmp_path / "must-not-follow")
        (site_packages / ".git").touch()
        roots["nearest"] = tmp_path / "store"
    root = roots[destination]
    before = set(tmp_path.rglob("*"))
    with (
        patch.object(Path, "open", side_effect=AssertionError("file opened")),
        patch.object(cli, "load_config", return_value=Config(("synthetic/test",))) as config,
        patch.object(cli, "private_workspace") as workspace,
        patch.object(cli, "LocalStore") as store,
        patch.object(publish, "reconcile", return_value=publish.RunResult(False, 0)) as run,
    ):
        result = cli.main(["--apply", "--local-root", str(root)])
    if destination in ("cwd", "child"):
        assert result == 1
        config.assert_not_called()
        workspace.assert_not_called()
        store.assert_not_called()
        run.assert_not_called()
    else:
        assert result == 0
        run.assert_called_once()
        assert run.call_args.args[1].storage.public == {
            name: str(root / "public" / name) for name in FORMATS
        }
    assert set(tmp_path.rglob("*")) == before


@pytest.mark.parametrize("backend", ["local", "r2"])
@pytest.mark.parametrize(
    "names, selected, message",
    [
        [("apt", "rpm"), "apt", "one publication"],
        [("apt", "rpm"), "arch", "not a configured public format"],
        [("apt",), "rpm", "not a configured public format"],
    ],
)
@pytest.mark.parametrize("mode", [["--apply"], ["--break-lock"]])
def test_format_selection_denied_before_workspace_store_or_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    backend: str,
    names: tuple[str, ...],
    selected: str,
    message: str,
    mode: list[str],
) -> None:
    root = tmp_path / "store"
    destination = ["--local-root", str(root)] if backend == "local" else ["--remote"]
    with (
        patch.object(cli, "load_config", return_value=configured(names)),
        patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")),
        patch.object(cli, "LocalStore", side_effect=AssertionError("storage opened")),
        patch.object(cli, "R2Store", side_effect=AssertionError("storage opened")),
        patch.object(state, "acquire", side_effect=AssertionError("lock acquired")),
        patch.object(state, "break_locks", side_effect=AssertionError("locks broken")),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main([*mode, *destination, "--format", selected]) == 1
    error = capsys.readouterr().err
    assert message in error
    assert "Use --format all" in error
    assert not root.exists()


@pytest.mark.parametrize("backend", ["local", "r2"])
@pytest.mark.parametrize(
    "names, selected",
    [(("apt",), "apt"), (("apt",), "all"), (("rpm", "apt"), "all")],
)
def test_policy_preserves_all_configured_roles(
    tmp_path: Path, backend: str, names: tuple[str, ...], selected: str
) -> None:
    root = tmp_path / "store"
    roles = tuple(sorted(names))
    expected = Policy(
        StoragePolicy(
            backend,
            {
                name: str(root / "public" / name) if backend == "local" else f"test-{name}"
                for name in roles
            },
        ),
        PRODUCTION_FINGERPRINT if backend == "r2" else None,
    )
    destination = ["--local-root", str(root)] if backend == "local" else ["--remote"]
    with (
        patch.object(cli, "load_config", return_value=configured(names, (*names, "flatpak"))),
        patch.object(cli, "LocalStore"),
        patch.object(cli, "R2Store"),
        patch.object(publish, "reconcile", return_value=publish.RunResult(False, 0)) as run,
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["--apply", *destination, "--format", selected]) == 0
    run.assert_called_once()
    assert run.call_args.args[1] == expected
    assert not root.exists()


def test_remote_uses_configured_buckets_and_production_key(
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = configured(("apk", "rpm"), ("apk", "apt", "rpm"))
    with (
        patch.object(cli, "load_config", return_value=config),
        patch.object(cli, "private_workspace") as workspace,
        patch.object(cli, "R2Store") as store,
        patch.object(publish, "reconcile", return_value=publish.RunResult(False, 0)) as run,
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["--apply", "--remote", "--format", "all"]) == 0
    policy = Policy(
        StoragePolicy("r2", {"apk": "test-apk", "rpm": "test-rpm"}),
        PRODUCTION_FINGERPRINT,
    )
    store.assert_called_once_with(
        policy.storage, runtime=workspace.return_value.__enter__.return_value
    )
    run.assert_called_once()
    assert run.call_args.args == (config, policy)
    assert run.call_args.kwargs["store"] is store.return_value
    assert not capsys.readouterr().err


@pytest.mark.parametrize("omit_from_config", [False, True])
def test_omitted_format_bucket_is_preserved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], omit_from_config: bool
) -> None:
    def write_config(names: tuple[str, ...]) -> None:
        config.write_text(
            yaml.safe_dump(
                {
                    "sources": ["synthetic/test"],
                    "formats": {name: {} for name in names},
                    "storage": {"public": {name: f"test-{name}" for name in names}},
                }
            )
        )

    config = tmp_path / "config.yaml"
    write_config(("apt", "rpm"))
    root = tmp_path / "store"
    args = ["--apply", "--local-root", str(root), "--config", str(config)]
    inventory = root / "public/rpm/haberdasher.json"
    inventory.parent.mkdir(parents=True)
    inventory.write_bytes(b"previously published rpm inventory")
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    if omit_from_config:
        write_config(("apt",))
    with (
        patch.object(discovery, "scan_releases", side_effect=empty_scan),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        result = cli.main([*args, "--format", "all" if omit_from_config else "apt"])
    output = capsys.readouterr()
    if omit_from_config:
        assert result == 0 and '"changed":false' in output.out
    else:
        assert result == 1 and "Use --format all" in output.err
    after = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    assert after == before
    assert not list(root.rglob(state.LOCK_KEY))


def test_format_help_explains_single_publication_constraint() -> None:
    help_text = " ".join(cli.parser().format_help().split())
    assert "all configured public formats form one publication" in help_text
    assert "only configured public format" in help_text
    assert "local bootstrap with no configured public destinations" in help_text


def test_publish_workflow_gates_and_github_command_environment(tmp_path: Path) -> None:
    workflow = state.mapping(
        yaml.load(Path(".github/workflows/publish.yml").read_text(), Loader=yaml.BaseLoader)
    )
    assert workflow["on"] == {"workflow_dispatch": ""}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "haberdasher-publisher",
        "cancel-in-progress": "false",
    }
    assert "env" not in workflow
    job = state.mapping(state.mapping(workflow["jobs"])["publish"])
    assert " ".join(str(job["if"]).split()) == (
        "vars.HD_PUBLISH_ENABLED == 'true' && "
        "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
    )
    assert job["environment"] == "publisher"
    assert "env" not in job and "permissions" not in job
    raw_steps = job["steps"]
    assert isinstance(raw_steps, list)
    steps = [state.mapping(step) for step in raw_steps]
    assert state.mapping(steps[0]["with"])["persist-credentials"] == "false"
    publishing = steps[-1]
    assert publishing["name"] == "Publish"
    assert str(publishing["run"]).endswith(
        "nix develop --no-write-lock-file --command \\\n"
        "  just publish --apply --remote --format all\n"
    )
    assert all("env" not in step for step in steps[:-1])
    env = state.mapping(publishing["env"])
    assert env["GH_TOKEN"] == "${{ github.token }}"
    assert "GITHUB_TOKEN" not in env
    assert {name for name in env if name.startswith("HD_")} == {
        "HD_SIGNING_KEY",
        "HD_CLOUDFLARE_S3_API_ENDPOINT",
        "HD_CLOUDFLARE_ACCESS_KEY_ID",
        "HD_CLOUDFLARE_SECRET_ACCESS_KEY",
    }
    binary = tmp_path / "bin"
    binary.mkdir()
    gh = binary / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "assert sys.argv[1:] == ['api', '--hostname', 'github.com', '--method', 'GET', "
        "'--header', 'Accept: application/vnd.github+json', '--header', "
        "'X-GitHub-Api-Version: 2022-11-28', 'repos/synthetic/test/releases?per_page=100&page=1']\n"
        "assert os.environ['GH_TOKEN'] == 'synthetic-workflow-token'\n"
        "assert os.environ['GH_CONFIG_DIR'] == os.environ['HOME'] + '/.config/gh'\n"
        "assert os.environ['GH_PROMPT_DISABLED'] == '1'\n"
        "assert not any(key.startswith(('HD_', 'AWS_')) for key in os.environ)\n"
        "print('[]')\n"
    )
    gh.chmod(0o700)
    runtime = Runtime(
        tmp_path / "runtime",
        environ={"PATH": str(binary), "GH_TOKEN": "synthetic-workflow-token"},
    )
    try:
        scan = discovery.scan_releases(
            Config(("synthetic/test",)), runtime=runtime, previous=discovery.DiscoveryState()
        )
        assert not scan.state.assets
        assert "GH_TOKEN" not in runtime.environment_for("native")
        assert "GH_TOKEN" not in runtime.environment_for("storage")
    finally:
        runtime.close()


def test_local_apply_without_key_or_assets_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("sources: [synthetic/test]\n")
    root = tmp_path / "store"
    args = ["--apply", "--local-root", str(root), "--config", str(config), "--format", "apt"]
    with patch.object(discovery, "scan_releases", side_effect=empty_scan):
        assert cli.main(args) == 0
    assert '"changed":false' in capsys.readouterr().out
    assert sorted(path.name for path in (root / "public").iterdir()) == ["apt"]
    assert not any((root / "public/apt").iterdir())
