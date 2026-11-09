from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from haberdasher import cli, discovery, publish, signing, state
from haberdasher.config import (
    PRODUCTION_FINGERPRINT,
    PUBLIC,
    Config,
    Policy,
    StoragePolicy,
)
from haberdasher.core import SourceAsset
from haberdasher.runtime import Runtime


def empty_scan(*args: object, **kwargs: object) -> discovery.CompleteScan:
    return discovery.CompleteScan(discovery.DiscoveryState(), (), (), (), ())


def scan_with(*filenames: str) -> discovery.CompleteScan:
    """A scan with one checksummed asset for each file name."""
    records: list[discovery.DiscoveredAsset] = []
    for index, filename in enumerate(filenames, 1):
        source = SourceAsset(
            "synthetic/test",
            1,
            index,
            filename,
            1,
            "2026-01-01T00:00:00Z",
            f"https://github.com/synthetic/test/{filename}",
            "a" * 64,
        )
        checksum = discovery.ChecksumEntry(source, filename, "a" * 64, "a" * 64)
        records.append(discovery.DiscoveredAsset(source, checksum, "b" * 64))
    state_ = discovery.DiscoveryState(
        tuple(records), tuple(record.source for record in records), ("synthetic/test",)
    )
    return discovery.CompleteScan(state_, tuple(records), (), (), ())


def unpublished(name: str, url: str) -> state.Published:
    return state.unpublished(name)


def work_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    config = work / "haberdasher.yaml"
    config.write_text(text)
    monkeypatch.chdir(work)
    return config


def test_plan_never_opens_store_or_signer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    work_config(tmp_path, monkeypatch, "sources: [synthetic/test]\n")
    monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(tmp_path / "must-not-open"))
    with (
        patch.object(discovery, "scan_releases", side_effect=empty_scan) as scan,
        patch.object(cli, "LocalStore", side_effect=AssertionError("storage opened")),
        patch.object(cli, "R2Store", side_effect=AssertionError("storage opened")),
        patch.object(cli, "read_published", side_effect=unpublished),
        patch.object(state, "acquire", side_effect=AssertionError("lock acquired")),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
        patch("haberdasher.signing.SigningSession", side_effect=AssertionError("key imported")),
    ):
        assert cli.main(["plan"]) == 0
        scan.assert_called_once()
    output = capsys.readouterr().out
    assert output.startswith("Reading haberdasher.yaml: 1 source\n")
    assert output.endswith("Nothing written.\n") and "{" not in output


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--plan"],
        ["plan", "--local-root", "/tmp/unused"],
        ["publish", "--apply"],
        ["publish", "--remote"],
        ["publish", "--format", "all"],
        ["publish", "--config", "haberdasher.yaml"],
        ["publish", "--signing-fingerprint", "A" * 40],
        ["unlock", "--break-lock"],
    ],
)
def test_argparse_rejects_removed_options(arguments: list[str]) -> None:
    with (
        patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")),
        pytest.raises(SystemExit) as error,
    ):
        cli.main(arguments)
    assert error.value.code == 2


def test_remote_publish_needs_credentials_before_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work_config(tmp_path, monkeypatch, "sources: [synthetic/test]\n")
    with (
        patch.dict(os.environ, {"PATH": os.environ["PATH"]}, clear=True),
        patch.object(discovery, "scan_releases", side_effect=AssertionError("scanned")),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["publish"]) == 1
    assert "storage environment variables are required" in capsys.readouterr().err


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
@pytest.mark.parametrize("mode", [["publish"], ["unlock"]])
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
        patch.object(discovery, "scan_releases", return_value=scan_with("app.deb")),
        patch.object(publish, "reconcile", return_value=publish.RunResult(False, 0)) as run,
    ):
        result = cli.main(["publish", "--local-root", str(root)])
    if destination in ("cwd", "child"):
        assert result == 1
        config.assert_not_called()
        workspace.assert_not_called()
        store.assert_not_called()
        run.assert_not_called()
    else:
        assert result == 0
        run.assert_called_once()
        assert run.call_args.args[1].storage.public == {"apt": str(root / "public" / "apt")}
    assert set(tmp_path.rglob("*")) == before


@pytest.mark.parametrize("backend", ["local", "r2"])
@pytest.mark.parametrize(
    "filenames,published,names",
    [
        (("a.deb",), (), ("apt",)),
        (("a.rpm", "b.deb", "c.pkg.tar.xz", "d.tar.gz"), (), ("apt", "rpm", "arch")),
        (("a.apk",), ("rpm",), ("rpm", "apk")),
    ],
)
def test_publication_covers_found_and_published_formats(
    tmp_path: Path,
    backend: str,
    filenames: tuple[str, ...],
    published: tuple[str, ...],
    names: tuple[str, ...],
) -> None:
    root = tmp_path / "store"
    for name in published if backend == "local" else ():
        inventory = root / "public" / name / state.INVENTORY_KEY
        inventory.parent.mkdir(parents=True)
        inventory.write_bytes(b"previously published inventory")

    def read(name: str, url: str) -> state.Published:
        assert url == PUBLIC[name][1]
        if name in published:
            return state.Published(name, None, "c" * 64, (), state.unpublished(name).retained)
        return state.unpublished(name)

    expected = Policy(
        StoragePolicy(
            backend,
            {
                name: str(root / "public" / name) if backend == "local" else PUBLIC[name][0]
                for name in names
            },
        ),
        PRODUCTION_FINGERPRINT if backend == "r2" else "A" * 40,
    )
    destination = ["--local-root", str(root)] if backend == "local" else []
    with (
        patch.object(cli, "load_config", return_value=Config(("synthetic/test",))),
        patch.object(discovery, "scan_releases", return_value=scan_with(*filenames)),
        patch.object(cli, "read_published", side_effect=read),
        patch.object(cli, "LocalStore") as local,
        patch.object(cli, "R2Store") as remote,
        patch.object(signing, "key_fingerprint", return_value="A" * 40),
        patch.object(publish, "reconcile", return_value=publish.RunResult(False, 0)) as run,
    ):
        assert cli.main(["publish", *destination]) == 0
    run.assert_called_once()
    assert run.call_args.args == (Config(("synthetic/test",)), expected)
    if backend == "r2":
        remote.assert_called_once_with(
            StoragePolicy("r2", {name: bucket for name, (bucket, _) in PUBLIC.items()}),
            runtime=remote.call_args.kwargs["runtime"],
        )
        assert run.call_args.kwargs["store"] is remote.return_value
        local.assert_not_called()
    else:
        local.assert_called_once_with(expected.storage)
        remote.assert_not_called()


def test_local_publish_without_packages_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work_config(tmp_path, monkeypatch, "sources: [synthetic/test]\n")
    root = tmp_path / "store"
    with (
        patch.object(discovery, "scan_releases", return_value=scan_with("tool.tar.gz")),
        patch.object(publish, "reconcile", side_effect=AssertionError("reconciled")),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["publish", "--local-root", str(root)]) == 0
    assert capsys.readouterr().out.endswith("No packages found. Nothing written.\n")
    assert not root.exists()


def test_help_lists_commands_and_hides_local_root(capsys: pytest.CaptureFixture[str]) -> None:
    assert "{plan,publish,unlock}" in cli.parser().format_help()
    for command in ("plan", "publish", "unlock"):
        with pytest.raises(SystemExit):
            cli.main([command, "--help"])
        assert "--local-root" not in capsys.readouterr().out


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
        "nix develop --no-write-lock-file --command just publish\n"
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


def test_plan_treats_404_as_unpublished_and_continues_past_an_unreachable_domain(
    capsys: pytest.CaptureFixture[str],
) -> None:
    urls = {"apt": "https://apt.example.invalid", "rpm": "https://127.0.0.1:1"}
    real = urllib.request.urlopen

    def answer(request: urllib.request.Request, timeout: float) -> object:
        if request.full_url.startswith("https://apt."):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", Message(), None)
        return real(request, timeout=timeout)

    with patch.object(urllib.request, "urlopen", side_effect=answer):
        cli.show_plan(scan_with("app.deb"), urls)
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "Reading published state from apt.example.invalid, 127.0.0.1"
    assert lines[1].startswith("rpm   cannot reach 127.0.0.1: ")
    assert lines[2:] == [
        "",
        "Format  Repository           Published  New",
        "apt     apt.example.invalid          0    1",
        "rpm     127.0.0.1                    ?    ?",
        "",
        "1 new package. Nothing written. Could not read rpm, so the plan is incomplete.",
    ]


def test_errors_print_one_line_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work_config(tmp_path, monkeypatch, "sources: [synthetic/test]\n")
    failure = discovery.DiscoveryFailure("synthetic/test v1, checksums.txt: Cosign failed")
    with patch.object(discovery, "scan_releases", side_effect=failure):
        assert cli.main(["plan"]) == 1
    captured = capsys.readouterr()
    assert captured.err == "Error: synthetic/test v1, checksums.txt: Cosign failed\n"
