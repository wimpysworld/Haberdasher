from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from haberdasher import cli, discovery, publish, state
from haberdasher.config import (
    APPROVAL_GATES,
    PRODUCTION_FINGERPRINT,
    Config,
    Policy,
    RuntimePolicy,
    StoragePolicy,
    TrustPolicy,
)
from haberdasher.core import canonical_json
from haberdasher.runtime import Runtime
from haberdasher.storage import LocalStore


def empty_scan(*args: object, **kwargs: object) -> discovery.CompleteScan:
    return discovery.CompleteScan(discovery.DiscoveryState(), (), (), (), ())


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
        patch.object(state, "acquire", side_effect=AssertionError("ownership acquired")),
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
        ["--plan", "--recover-owner", "nonce", "--recovery-evidence", "unused"],
        ["--apply", "--recover-owner", "nonce", "--recovery-evidence", "unused"],
        ["--recover-owner", "nonce", "--local-root", "/tmp/unused"],
        ["--replay", "../bad", "--local-root", "/tmp/unused"],
    ],
)
def test_invalid_modes_fail_before_runtime(arguments: list[str]) -> None:
    with patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")):
        assert cli.main(arguments) == 1


@pytest.mark.parametrize(
    "arguments",
    [
        ["--plan", "--apply"],
        ["--apply", "--replay", "generation"],
        ["--apply", "--remote", "--local-root", "/tmp/unused"],
    ],
)
def test_argparse_rejects_incompatible_modes(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 2


@pytest.mark.parametrize("policy", [[], ["--policy-file", "tests/fixtures/policy/denied.yaml"]])
def test_remote_denied_before_credentials_or_workspace(policy: list[str]) -> None:
    with (
        patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")),
        patch.object(cli.os, "environ", dict[str, str]()),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["--apply", "--remote", *policy]) == 1


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
@pytest.mark.parametrize(
    "mode",
    [
        ["--apply"],
        ["--replay", "generation"],
        ["--recover-owner", "nonce", "--recovery-evidence", "unopened.json"],
    ],
)
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
        patch.object(cli, "_evidence", side_effect=AssertionError("evidence opened")),
        patch.object(state, "acquire", side_effect=AssertionError("ownership acquired")),
        patch.object(state, "recover_owner", side_effect=AssertionError("ownership recovered")),
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
        patch.object(publish, "reconcile", return_value=publish.RunResult(None, False, 0)) as run,
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
        assert run.call_args.args[1].storage.private == str(root / "private")
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
@pytest.mark.parametrize(
    "mode",
    [
        ["--apply"],
        ["--replay", "generation"],
        ["--recover-owner", "nonce", "--recovery-evidence", "unopened.json"],
    ],
)
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
    policy = Policy(
        storage=StoragePolicy(
            backend,
            str(root / "private") if backend == "local" else "test-private",
            {
                name: str(root / "public" / name) if backend == "local" else f"test-{name}"
                for name in names
            },
        )
    )
    destination = ["--local-root", str(root)] if backend == "local" else ["--remote"]
    with (
        patch.object(cli, "load_policy", return_value=policy),
        patch.object(cli, "load_config", side_effect=AssertionError("config opened")),
        patch.object(cli, "_evidence", side_effect=AssertionError("evidence opened")),
        patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")),
        patch.object(cli, "LocalStore", side_effect=AssertionError("storage opened")),
        patch.object(cli, "R2Store", side_effect=AssertionError("storage opened")),
        patch.object(state, "acquire", side_effect=AssertionError("ownership acquired")),
        patch.object(state, "recover_owner", side_effect=AssertionError("ownership recovered")),
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
    policy = Policy(
        storage=StoragePolicy(
            backend,
            str(root / "private") if backend == "local" else "test-private",
            {
                name: str(root / "public" / name) if backend == "local" else f"test-{name}"
                for name in names
            },
        ),
        approved_formats=names,
        approval_references={gate: "synthetic approval" for gate in APPROVAL_GATES},
        expected_signing_fingerprint=PRODUCTION_FINGERPRINT,
        clients={name: TrustPolicy(True, "synthetic approval") for name in names},
    )
    destination = ["--local-root", str(root)] if backend == "local" else ["--remote"]
    with (
        patch.object(cli, "load_policy", return_value=policy),
        patch.object(cli, "load_config", return_value=Config(("synthetic/test",))),
        patch.object(cli, "LocalStore"),
        patch.object(cli, "R2Store"),
        patch.object(publish, "reconcile", return_value=publish.RunResult(None, False, 0)) as run,
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["--apply", *destination, "--format", selected]) == 0
    run.assert_called_once()
    result = run.call_args.args[1]
    assert result == policy
    if backend == "r2":
        assert result is policy
    assert not root.exists()


def test_remote_approval_checks_full_configured_set(capsys: pytest.CaptureFixture[str]) -> None:
    policy = Policy(
        storage=StoragePolicy("r2", "test-private", {"apt": "test-apt", "rpm": "test-rpm"}),
        approved_formats=("apt",),
        approval_references={gate: "synthetic approval" for gate in APPROVAL_GATES},
        expected_signing_fingerprint=PRODUCTION_FINGERPRINT,
        clients={"apt": TrustPolicy(True, "synthetic approval")},
    )
    with (
        patch.object(cli, "load_policy", return_value=policy),
        patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")),
        patch.object(cli, "R2Store", side_effect=AssertionError("storage opened")),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["--apply", "--remote"]) == 1
    assert "Format publication is not approved" in capsys.readouterr().err


def approved_remote_policy(name: str) -> Policy:
    trust = TrustPolicy(approved=True, approval_reference="synthetic-client-approval")
    if name == "flatpak":
        trust = replace(
            trust,
            source_owner="synthetic",
            refs=("app/org.example.App/x86_64/stable",),
            runtime=RuntimePolicy(
                url="http://127.0.0.1:12345/runtime",
                fingerprint="A" * 40,
                collection="",
                branch="stable",
                architecture="x86_64",
                remote="synthetic-runtime",
                refs=("runtime/org.example.Platform/x86_64/stable",),
            ),
        )
    return Policy(
        storage=StoragePolicy("r2", "synthetic-private", {name: f"synthetic-{name}"}),
        approved_formats=(name,),
        approval_references={gate: "synthetic-approval" for gate in APPROVAL_GATES},
        expected_signing_fingerprint=PRODUCTION_FINGERPRINT,
        clients={name: trust},
    )


@pytest.mark.parametrize("name", ["apk", "flatpak"])
def test_remote_accepts_approved_format(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    policy = approved_remote_policy(name)
    with (
        patch.object(cli, "load_policy", return_value=policy),
        patch.object(cli, "load_config", return_value=Config(("synthetic/test",))),
        patch.object(cli, "private_workspace") as workspace,
        patch.object(cli, "R2Store") as store,
        patch.object(publish, "reconcile", return_value=publish.RunResult(None, False, 0)) as run,
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["--apply", "--remote", "--format", name]) == 0
    workspace.assert_called_once()
    store.assert_called_once_with(
        policy.storage, runtime=workspace.return_value.__enter__.return_value
    )
    run.assert_called_once()
    assert run.call_args.args[1] is policy
    assert run.call_args.kwargs["store"] is store.return_value
    assert not capsys.readouterr().err


@pytest.mark.parametrize(
    "name, field, value, message",
    [
        ("apk", "apk_v2", None, "Remote publication is not approved"),
        ("apk", "approved", False, "Format publication is not approved"),
        ("apk", "approval_reference", None, "Format publication is not approved"),
        ("flatpak", "flatpak_runtime", None, "Remote publication is not approved"),
        ("flatpak", "approved", False, "Format publication is not approved"),
        ("flatpak", "approval_reference", None, "Format publication is not approved"),
        ("flatpak", "source_owner", None, "Flatpak source and runtime approval is incomplete"),
        ("flatpak", "refs", (), "Flatpak source and runtime approval is incomplete"),
        ("flatpak", "runtime", None, "Flatpak source and runtime approval is incomplete"),
    ],
    ids=[
        "apk-v2-approval",
        "apk-client-approved",
        "apk-client-reference",
        "flatpak-runtime-approval",
        "flatpak-client-approved",
        "flatpak-client-reference",
        "flatpak-source-owner",
        "flatpak-refs",
        "flatpak-runtime",
    ],
)
def test_remote_rejects_individual_format_approval_omissions_before_runtime(
    name: str, field: str, value: object, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = approved_remote_policy(name)
    if field in APPROVAL_GATES:
        policy = replace(
            policy,
            approval_references={
                gate: reference
                for gate, reference in policy.approval_references.items()
                if gate != field
            },
        )
    else:
        policy = replace(policy, clients={name: replace(policy.clients[name], **{field: value})})
    with (
        patch.object(cli, "load_policy", return_value=policy),
        patch.object(cli, "load_config", side_effect=AssertionError("config opened")),
        patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")),
        patch.object(cli, "LocalStore", side_effect=AssertionError("storage opened")),
        patch.object(cli, "R2Store", side_effect=AssertionError("storage opened")),
        patch.object(state, "acquire", side_effect=AssertionError("ownership acquired")),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main(["--apply", "--remote", "--format", name]) == 1
    captured = capsys.readouterr()
    assert captured.err == f"Error: {message}\n"
    assert not captured.out


@pytest.mark.parametrize("omit_from_policy", [False, True])
def test_previous_role_omission_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], omit_from_policy: bool
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("sources: [synthetic/test]\n")
    policy = tmp_path / "policy.yaml"
    root = tmp_path / "store"
    destinations = {name: str(root / "public" / name) for name in ("apt", "rpm")}
    policy.write_text(yaml.safe_dump({"storage": {"public": destinations}}))
    args = [
        "--apply",
        "--local-root",
        str(root),
        "--config",
        str(config),
        "--policy-file",
        str(policy),
    ]
    with patch.object(discovery, "scan_releases", side_effect=empty_scan):
        assert cli.main(args) == 0
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    assert (root / "public/rpm/haberdasher.json") in before
    if omit_from_policy:
        policy.write_text(yaml.safe_dump({"storage": {"public": {"apt": destinations["apt"]}}}))
    with (
        patch.object(discovery, "scan_releases", side_effect=empty_scan),
        patch.object(state, "freeze", side_effect=AssertionError("generation frozen")),
        patch("haberdasher.signing._input", side_effect=AssertionError("key input read")),
    ):
        assert cli.main([*args, "--format", "all" if omit_from_policy else "apt"]) == 1
    error = capsys.readouterr().err
    assert (
        "No destination for this bucket role" if omit_from_policy else "Use --format all"
    ) in error
    after = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    if omit_from_policy:
        ownership = root / "private/ownership.json"
        previous_owner = state.parse(before[ownership])
        failed_owner = state.parse(after[ownership])
        assert previous_owner["status"] == "idle"
        assert failed_owner["status"] == "active"
        nonce = failed_owner["nonce"]
        assert isinstance(nonce, str) and nonce
        assert nonce != previous_owner["nonce"]
        assert failed_owner["completion"] == previous_owner["completion"]
        store = LocalStore(StoragePolicy("local", str(root / "private"), destinations))
        with pytest.raises(state.StateError, match="An owner already holds publication rights"):
            state.acquire(store, owner="competing-test")
        assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == after
        before.pop(ownership)
        after.pop(ownership)
    assert after == before


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
    assert publishing["name"] == "Publish with explicit policy approval"
    assert str(publishing["run"]).endswith(
        "nix develop --no-write-lock-file --command \\\n"
        '  just publish --apply --remote --policy-file "$policy_file"\n'
    )
    assert all("env" not in step for step in steps[:-1])
    env = state.mapping(publishing["env"])
    assert env["GH_TOKEN"] == "${{ github.token }}"
    assert env["HD_PUBLISH_POLICY"] == "${{ secrets.HD_PUBLISH_POLICY }}"
    assert "GITHUB_TOKEN" not in env
    assert {name for name in env if name.startswith("HD_")} == {
        "HD_PUBLISH_POLICY",
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


def test_local_apply_uses_real_publication_and_noop(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("sources: [synthetic/test]\n")
    root = tmp_path / "store"
    args = ["--apply", "--local-root", str(root), "--config", str(config), "--format", "apt"]
    with patch.object(discovery, "scan_releases", side_effect=empty_scan):
        assert cli.main(args) == 0
        assert cli.main(args) == 0
    store = LocalStore(
        StoragePolicy("local", str(root / "private"), {"apt": str(root / "public/apt")})
    )
    assert state.read_control(store, "completed.json") is not None
    assert (root / "public/apt/haberdasher.json").is_file()
    assert not (root / "public/apt/ownership.json").exists()


def test_recovery_checks_evidence_and_releases_stopped_owner(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = LocalStore(
        StoragePolicy("local", str(root / "private"), {"apt": str(root / "public/apt")})
    )
    owner = state.acquire(store, owner="stopped-test")
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "stopped_owner": True,
                "requests_resolved": True,
                "reference": "synthetic stopped process",
                "runner_identity": "test",
                "writes": [],
            }
        )
    )
    args = [
        "--local-root",
        str(root),
        "--format",
        "apt",
        "--recover-owner",
        owner.owner_nonce,
        "--recovery-evidence",
        str(evidence),
    ]
    assert cli.main(args) == 0
    assert cli.main(args) == 1
    current = state.read_control(store, "ownership.json")
    assert current is not None and current[0]["status"] == "idle"


@pytest.mark.parametrize(
    "change", [{"stopped_owner": False}, {"requests_resolved": False}, {"force": True}]
)
def test_recovery_rejects_unsafe_evidence(tmp_path: Path, change: dict[str, bool]) -> None:
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "stopped_owner": True,
                "requests_resolved": True,
                "reference": "synthetic",
                "runner_identity": "test",
                "writes": [],
                **change,
            }
        )
    )
    with patch.object(cli, "private_workspace", side_effect=AssertionError("runtime opened")):
        assert (
            cli.main(
                [
                    "--recover-owner",
                    "nonce",
                    "--recovery-evidence",
                    str(evidence),
                    "--local-root",
                    str(tmp_path / "store"),
                ]
            )
            == 1
        )
