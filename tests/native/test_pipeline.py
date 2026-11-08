"""Recorded GitHub transport, real adapters, durable storage and HTTP clients."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Generator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch
from urllib.request import urlopen

import pytest

from haberdasher import cli, discovery, publish, state
from haberdasher.config import (
    Config,
    FormatPolicy,
    Policy,
    RuntimePolicy,
    StoragePolicy,
    TrustPolicy,
)
from haberdasher.core import (
    ObjectRef,
    ObjectStat,
    RetainedFormat,
    VerifiedAsset,
    WriteReceipt,
    canonical_json,
    json_value,
    sha256_file,
)
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import signing_session
from haberdasher.storage import LocalStore
from tests.native.fixtures import apk, apt, arch, flatpak, rpm
from tests.native.test_flatpak import add_remotes, client_run, installed
from tests.support.http import serve
from tests.support.keys import DisposableKey, disposable_key
from tests.support.native import NativeClient


class RecordedGitHub:
    def __init__(self, assets: Sequence[VerifiedAsset]) -> None:
        self.assets = tuple(
            replace(
                asset,
                source=replace(
                    asset.source, repository="wimpysworld/fixture", release_id=1, asset_id=index
                ),
            )
            for index, asset in enumerate(assets, 1)
        )
        self.contents = {
            asset.source.filename: asset.local_path.read_bytes() for asset in self.assets
        }
        self.visible = len(self.assets) - 1
        self.checksummed = self.visible
        self.downloads: list[str] = []
        self.native: list[tuple[str, ...]] = []
        self.inspected: set[str] = set()
        self.forbid_native = False
        self.runtime: Runtime | None = None
        self.real_run: Callable[..., CompletedProcess[bytes]] | None = None

    def bind(self, runtime: Runtime) -> None:
        self.runtime = runtime
        self.real_run = runtime.run
        runtime.run = self.run

    def rows(self) -> tuple[list[dict[str, object]], dict[str, bytes]]:
        contents = {
            asset.source.filename: self.contents[asset.source.filename]
            for asset in self.assets[: self.visible]
        }
        sums = "".join(
            f"{asset.sha256}  {asset.source.filename}\n"
            for asset in self.assets[: self.checksummed]
        ).encode()
        contents["SHA256SUMS"] = sums
        rows: list[dict[str, object]] = []
        for index, (name, data) in enumerate(contents.items(), 1):
            rows.append(
                {
                    "id": 999 if name == "SHA256SUMS" else index,
                    "name": name,
                    "size": len(data),
                    "state": "uploaded",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "browser_download_url": f"https://example.invalid/{name}",
                    "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                }
            )
        return rows, contents

    def record_native(self, argv: Sequence[str], input: bytes | None = None) -> None:
        if argv[0] == "gpgconf":
            return
        self.native.append(tuple(argv))
        assert not self.forbid_native, f"No-op ran native command: {argv}"
        self.inspected.update(arg for arg in argv if arg.endswith("-asset"))
        if argv[0] == "haberdasher-flatpak-metadata" and input is not None:
            bundle = json.loads(input).get("bundle")
            if bundle is not None:
                self.inspected.add(bundle)

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
        env_kind: str = "native",
    ) -> CompletedProcess[bytes]:
        if argv[0] != "gh":
            self.record_native(argv, input)
            assert self.real_run is not None
            return self.real_run(argv, cwd=cwd, input=input, timeout=timeout, env_kind=env_kind)
        assert env_kind == "github"
        rows, contents = self.rows()
        release = {"id": 1, "draft": False, "prerelease": False, "tag_name": "fixture"}
        if argv[1:3] == ["release", "download"]:
            name = argv[argv.index("--pattern") + 1]
            self.downloads.append(name)
            Path(argv[argv.index("--output") + 1]).write_bytes(contents[name])
            return CompletedProcess(argv, 0, b"", b"")
        assert argv[1] == "api"
        endpoint = argv[-1]
        if "?" in endpoint:
            value = (
                [] if endpoint.endswith("page=2") else rows if "/assets?" in endpoint else [release]
            )
        elif "/assets/" in endpoint:
            value = next(row for row in rows if row["id"] == int(endpoint.rsplit("/", 1)[1]))
        else:
            value = release
        return CompletedProcess(argv, 0, json.dumps(value).encode(), b"")


def apply_cli(
    recorded: RecordedGitHub, root: Path, key: DisposableKey, arguments: Sequence[str]
) -> publish.RunResult:
    shim = root / "bin"
    shim.mkdir(mode=0o700, exist_ok=True)

    def executable(name: str, script: str) -> None:
        path = shim / name
        path.write_text(f"#!{sys.executable}\n" + script)
        path.chmod(0o700)

    rows, contents = recorded.rows()
    (shim / "recorded.json").write_text(
        json.dumps(
            {
                "rows": rows,
                "contents": {
                    name: base64.b64encode(data).decode() for name, data in contents.items()
                },
            }
        )
    )
    (shim / "gh.jsonl").write_text("")
    (shim / "native.jsonl").write_text("")
    executable(
        "gh",
        """import base64,json,os,sys
from pathlib import Path
root=Path(__file__).parent
assert os.environ['GH_TOKEN']=='synthetic-pipeline-token'
assert not any(k.startswith(('HD_','AWS_','RCLONE_')) for k in os.environ)
data=json.loads((root/'recorded.json').read_text())
args=sys.argv[1:]
with (root/'gh.jsonl').open('a') as log: log.write(json.dumps(args)+'\\n')
release={'id':1,'draft':False,'prerelease':False,'tag_name':'fixture'}
if args[:2]==['release','download']:
    name=args[args.index('--pattern')+1]
    Path(args[args.index('--output')+1]).write_bytes(base64.b64decode(data['contents'][name]))
else:
    assert args[0]=='api'
    endpoint=args[-1]
    if '?' in endpoint:
        value=[] if endpoint.endswith('page=2') else data['rows'] if '/assets?' in endpoint else [release]
    elif '/assets/' in endpoint:
        value=next(row for row in data['rows'] if row['id']==int(endpoint.rsplit('/',1)[1]))
    else: value=release
    print(json.dumps(value))
""",
    )
    for command in (
        "gpg",
        "gpgsm",
        "gpgconf",
        "gpgv",
        "dpkg",
        "dpkg-deb",
        "apt-ftparchive",
        "rpm",
        "rpmsign",
        "rpmkeys",
        "createrepo_c",
        "pacman",
        "vercmp",
        "repo-add",
        "apk",
        "abuild-sign",
        "tar",
        "openssl",
        "flatpak",
        "ostree",
        "appstreamcli",
        "haberdasher-flatpak-metadata",
    ):
        target = shutil.which(command)
        assert target is not None
        executable(
            command,
            f"""import json,os,subprocess,sys
from pathlib import Path
assert not any(k.startswith(('HD_','GH_','GITHUB_','AWS_','RCLONE_')) for k in os.environ)
data=sys.stdin.buffer.read() if {command!r}=='haberdasher-flatpak-metadata' else None
with (Path(__file__).parent/'native.jsonl').open('a') as log:
    log.write(json.dumps({{'argv':[{command!r},*sys.argv[1:]],'input':data.decode() if data else None}})+'\\n')
if {recorded.forbid_native!r} and {command!r}!='gpgconf': sys.exit(88)
if data is not None:
    sys.exit(subprocess.run([{target!r},*sys.argv[1:]],input=data).returncode)
os.execv({target!r},[{target!r},*sys.argv[1:]])
""",
        )
    path = str(shim) + ":" + os.environ["HABERDASHER_TOOL_PATH"]
    result = subprocess.run(
        [sys.executable, "-m", "haberdasher", *arguments],
        env={
            "PATH": path,
            "HABERDASHER_TOOL_PATH": path,
            "HOME": str(root / "cli-home"),
            "TMPDIR": str(root / "tmp"),
            "LC_ALL": "C",
            "HD_SIGNING_KEY_FILE": str(key.key_file),
            "GH_TOKEN": "synthetic-pipeline-token",
        },
        capture_output=True,
        timeout=240,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    for line in (shim / "gh.jsonl").read_text().splitlines():
        argv = json.loads(line)
        if argv[:2] == ["release", "download"]:
            recorded.downloads.append(argv[argv.index("--pattern") + 1])
    for line in (shim / "native.jsonl").read_text().splitlines():
        event = json.loads(line)
        recorded.record_native(event["argv"], event["input"].encode() if event["input"] else None)
    return publish.RunResult(**json.loads(result.stdout))


class InterruptedStore(LocalStore):
    interrupt = False

    def __init__(self, policy: StoragePolicy) -> None:
        super().__init__(policy)
        self.downloads: list[ObjectRef] = []

    def download(self, ref: ObjectRef, destination: Path) -> ObjectStat:
        self.downloads.append(ref)
        return super().download(ref, destination)

    def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
        if self.interrupt and ref.bucket_role != "private":
            self.interrupt = False
            raise RuntimeError("synthetic interruption before public write")
        return super().create(ref, source)

    def replace(self, ref: ObjectRef, source: Path, *, expected_etag: str) -> WriteReceipt:
        if self.interrupt and ref.bucket_role != "private":
            self.interrupt = False
            raise RuntimeError("synthetic interruption before public write")
        return super().replace(ref, source, expected_etag=expected_etag)


def assets_for(name: str, runtime: Runtime) -> list[VerifiedAsset]:
    match name:
        case "apt":
            return [
                apt.build(runtime, "hd-dependency", "1.0", "dependency", arch="all", asset_id=1),
                apt.build(
                    runtime, "hd-application", "1.0", "first", depends="hd-dependency", asset_id=2
                ),
                apt.build(
                    runtime, "hd-application", "2.0", "second", depends="hd-dependency", asset_id=3
                ),
            ]
        case "rpm":
            return [
                rpm.build(runtime, "hd-proof-data", "1", "dependency-v1", number=1),
                rpm.build(runtime, "hd-proof-app", "1", "application-v1", number=2),
                rpm.build(runtime, "hd-proof-app", "2", "application-v2", number=3),
            ]
        case "arch":
            return [
                arch.fixture(runtime, "keeper", "1", dependency="updateable>=1"),
                arch.fixture(runtime, "updateable", "1"),
                arch.fixture(runtime, "updateable", "2"),
            ]
        case "apk":
            return [
                apk.fixture(runtime, "hd-dependency", "1.0-r0", payload="dependency"),
                apk.fixture(
                    runtime, "hd-application", "1.0-r0", payload="first", dependency="hd-dependency"
                ),
                apk.fixture(
                    runtime,
                    "hd-application",
                    "2.0-r0",
                    payload="second",
                    dependency="hd-dependency",
                ),
            ]
        case "flatpak":
            return [
                flatpak.bundle(runtime, runtime.root, "1", 1),
                flatpak.bundle(runtime, runtime.root, "2", 2),
            ]
        case _:
            raise ValueError(name)


def native_client(
    name: str,
    runtime: Runtime,
    label: str,
    url: str,
    key: DisposableKey,
    runtime_url: str,
    runtime_commits: tuple[str, str],
) -> Callable[[RetainedFormat, int], None]:
    trust = runtime.root / f"{label}-bootstrap"
    trust.mkdir(mode=0o700)
    gpg = [
        "gpg",
        "--no-options",
        "--homedir",
        str(runtime.root / "gnupg"),
        "--batch",
        "--no-autostart",
    ]
    listings: list[bytes] = []
    for suffix in ("asc", "gpg"):
        path = trust / f"haberdasher.{suffix}"
        with urlopen(url + f"/keys/{path.name}", timeout=10) as response:
            assert response.status == 200
            path.write_bytes(response.read())
        result = runtime.run([*gpg, "--with-colons", "--with-key-data", "--show-keys", str(path)])
        assert result.returncode == 0, result.stderr
        listings.append(result.stdout)
        rows = [line.split(b":") for line in result.stdout.splitlines()]
        assert [row[9].decode() for row in rows if row[0] == b"fpr"] == [key.fingerprint]
        assert [row[0] for row in rows if row[0] in {b"pub", b"sub", b"sec", b"ssb"}] == [b"pub"]
        packets = runtime.run([*gpg, "--list-packets", str(path)])
        assert packets.returncode == 0, packets.stderr
        assert b":public key packet:" in packets.stdout
        assert b":secret key packet:" not in packets.stdout
        assert b":secret sub key packet:" not in packets.stdout
    assert listings[0] == listings[1]
    key = replace(key, public_file=trust / "haberdasher.gpg", key_file=trust / "absent-private")
    match name:
        case "apt":
            apt_client = apt.Client(runtime, label, url, key.public_file)

            def check_apt(retained: RetainedFormat, version: int) -> None:
                apt_client.apt("update")
                apt_client.apt("install", "-y", "hd-application")
                apt_client.installed(
                    "hd-application", f"{version}.0", "first" if version == 1 else "second"
                )
                apt_client.installed("hd-dependency", "1.0", "dependency")

            return check_apt
        case "rpm":
            rpm_client = rpm.DnfClient(runtime, label, url, key.public_file)

            def check_rpm(retained: RetainedFormat, version: int) -> None:
                rpm_client.run("install", "hd-proof-app")
                rpm_client.state(str(version))

            return check_rpm
        case "arch":
            arch_client = arch.client(runtime, label, url + "/x86_64", key)

            def check_arch(retained: RetainedFormat, version: int) -> None:
                arch_client.checked("-Syu", "keeper")
                assert f"updateable {version}-1" in arch_client.checked("-Q", "updateable").decode()
                assert (
                    arch_client.client.path("root/usr/share/arch-test/updateable.txt").read_text()
                    == f"updateable-{version}\n"
                )

            return check_arch
        case "apk":
            public = trust / "haberdasher.rsa.pub"
            with urlopen(url + "/keys/haberdasher.rsa.pub", timeout=10) as response:
                assert response.status == 200
                public.write_bytes(response.read())
            assert public.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
            assert b"PRIVATE" not in public.read_bytes()
            modulus = runtime.run(
                ["openssl", "rsa", "-pubin", "-in", str(public), "-modulus", "-noout"]
            )
            assert modulus.returncode == 0, modulus.stderr
            numbers = [
                line.split(b":")[3] for line in listings[1].splitlines() if line.startswith(b"pkd:")
            ]
            assert len(numbers) == 2
            assert int(modulus.stdout.strip().split(b"=")[1], 16) == int(numbers[0], 16)
            apk_client = apk.Client(runtime, label, url, public)

            def check_apk(retained: RetainedFormat, version: int) -> None:
                apk_client.run("update")
                apk_client.add(f"hd-application={version}.0-r0")
                apk_client.installed(
                    "hd-application", f"{version}.0-r0", "first" if version == 1 else "second"
                )
                apk_client.installed("hd-dependency", "1.0-r0", "dependency")

            return check_apk
        case "flatpak":
            fp_client = NativeClient(runtime, label)
            add_remotes(fp_client, url, runtime_url, key.public_file)

            def check_flatpak(retained: RetainedFormat, version: int) -> None:
                client_run(
                    fp_client,
                    "install",
                    "--assumeyes",
                    "--noninteractive",
                    "publisher",
                    flatpak.APP,
                )
                client_run(
                    fp_client,
                    "update",
                    "--assumeyes",
                    "--noninteractive",
                    flatpak.APP,
                )
                commit = next(
                    identity.source_commit
                    for identity in retained.active_identities
                    if identity.name == flatpak.REF
                )
                assert commit is not None
                installed(fp_client, commit, str(version), runtime_commits)

            return check_flatpak
        case _:
            raise ValueError(name)


def committed(store: LocalStore, runtime: Runtime) -> RetainedFormat:
    owner = state.acquire(store, owner="test-read")
    result = state.load_committed(store, owner, out=runtime.root / "restored")
    state.release(store, owner)
    assert len(result.formats) == 1
    assert result.signing_fingerprint is not None
    assert {ref.key for ref in result.bootstrap_objects} == {
        "keys/haberdasher.asc",
        "keys/haberdasher.gpg",
    }
    for ref in (*result.formats[0].objects, *result.bootstrap_objects):
        store.download(ref, runtime.root / "checked-object")
    return result.formats[0]


@pytest.mark.parametrize("name", ["apt", "rpm", "arch", "apk", "flatpak"])
@pytest.mark.parametrize("interrupted", [False, True], ids=["cli", "recovery"])
def test_recorded_pipeline_and_frozen_recovery(
    name: str,
    interrupted: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with private_workspace() as fixtures, disposable_key() as key, ExitStack() as stack:
        now = datetime.now(UTC).replace(microsecond=0)
        assets = assets_for(name, fixtures)
        recorded = RecordedGitHub(assets)
        local_root = fixtures.root / "store"
        storage = StoragePolicy(
            "local", str(local_root / "private"), {name: str(local_root / "public" / name)}
        )
        store = InterruptedStore(storage)
        (fixtures.root / "http").mkdir()
        runtime_commits = ("", "")
        if name == "flatpak":
            with signing_session(
                fixtures, expected_fingerprint=key.fingerprint, key_file=key.key_file
            ) as signer:
                runtime_commits = flatpak.runtime_repo(
                    fixtures, fixtures.root / "http", signer.fingerprint, signer.gnupghome
                )
        http = stack.enter_context(serve(fixtures.root / "http"))
        format_policy = apt.policy() if name == "apt" else FormatPolicy(name)
        if name == "flatpak":
            format_policy = replace(
                format_policy,
                trust=TrustPolicy(
                    approved=True,
                    approval_reference="synthetic-only",
                    source_owner="wimpysworld",
                    refs=(flatpak.REF,),
                    runtime=RuntimePolicy(
                        http.url("runtime-repo"),
                        key.fingerprint,
                        "",
                        "stable",
                        "x86_64",
                        "provider",
                        (flatpak.RREF,),
                        (flatpak.EREF,),
                    ),
                ),
            )
        config = Config(
            ("wimpysworld/fixture",), {name: replace(format_policy, trust=TrustPolicy())}
        )
        policy = Policy(
            storage,
            expected_signing_fingerprint=key.fingerprint,
            clients={name: format_policy.trust},
        )
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key.key_file))
        config_file, policy_file = fixtures.root / "config.json", fixtures.root / "policy.json"
        configured = {"architectures": json_value(format_policy.architectures)}
        if name == "apt":
            configured["suite"] = format_policy.suite
        config_file.write_bytes(
            canonical_json({"sources": config.sources, "formats": {name: configured}})
        )
        client_policy = {
            key: value
            for key, value in state.mapping(json_value(format_policy.trust)).items()
            if value is not None
        }
        policy_file.write_bytes(
            canonical_json(
                {
                    "storage": storage,
                    "expected_signing_fingerprint": key.fingerprint,
                    "clients": {name: client_policy},
                }
            )
        )
        arguments = [
            "--local-root",
            str(local_root),
            "--format",
            name,
            "--policy-file",
            str(policy_file),
        ]

        @contextmanager
        def recorded_workspace() -> Generator[Runtime]:
            with private_workspace() as runtime:
                recorded.bind(runtime)
                yield runtime

        def reconcile() -> publish.RunResult:
            if not interrupted:
                return apply_cli(
                    recorded,
                    fixtures.root,
                    key,
                    ["--apply", "--config", str(config_file), *arguments],
                )
            with private_workspace() as runtime:
                recorded.bind(runtime)
                return publish.reconcile(config, policy, store=store, runtime=runtime, now=now)

        def serve_generation(number: int) -> None:
            public = fixtures.root / "http" / name
            shutil.copytree(Path(storage.public[name]), public, dirs_exist_ok=True)
            http.set_generation_mtime(
                [path for path in public.rglob("*") if path.is_file()], number
            )

        if interrupted:
            with patch.object(cli, "private_workspace", recorded_workspace):
                assert cli.main(["--apply", "--config", str(config_file), *arguments]) == 0
            first = publish.RunResult(**json.loads(capsys.readouterr().out))
        else:
            first = reconcile()
        assert first.changed and first.published_objects > 0
        bootstrap_paths = sorted((Path(storage.public[name]) / "keys").iterdir())
        bootstrap_stats = {path: (path.read_bytes(), path.stat()) for path in bootstrap_paths}
        assert recorded.downloads == [
            "SHA256SUMS",
            *[asset.source.filename for asset in assets[:-1]],
        ]
        assert len(recorded.inspected) == len(assets) - 1
        for asset in assets[:-1]:
            asset.local_path.unlink()
        serve_generation(1)
        with private_workspace() as runtime:
            retained = committed(store, runtime)
        check = native_client(
            name,
            fixtures,
            "existing",
            http.url(name),
            key,
            http.url("runtime-repo"),
            runtime_commits,
        )
        check(retained, 1)
        recorded.downloads.clear()
        recorded.native.clear()
        recorded.inspected.clear()
        recorded.forbid_native = True
        store.downloads.clear()
        unchanged = reconcile()
        assert not unchanged.changed and unchanged.published_objects == 0
        assert recorded.downloads == ["SHA256SUMS"] and not recorded.native
        package_hashes = {ref.sha256 for ref in retained.objects if ref.object_class == "package"}
        assert not any(ref.sha256 in package_hashes for ref in store.downloads)
        recorded.forbid_native = False
        recorded.visible += 1
        recorded.downloads.clear()
        pending = reconcile()
        assert pending.pending_assets == 1
        assert recorded.downloads == ["SHA256SUMS"] and not recorded.inspected
        recorded.checksummed += 1
        recorded.downloads.clear()
        recorded.native.clear()
        prior = state.read_control(store, "completed.json")
        if interrupted:
            store.interrupt = True
            with pytest.raises(RuntimeError, match="synthetic interruption"):
                reconcile()
            assert state.read_control(store, "completed.json") == prior
        else:
            second = reconcile()
            assert second.changed and second.pending_assets == 0
        assert recorded.downloads == ["SHA256SUMS", assets[-1].source.filename]
        assert len(recorded.inspected) == 1
        assert {Path(path).name for path in recorded.inspected} == {f"{name}-0-asset"}
        if not interrupted:
            with private_workspace() as runtime:
                restored = committed(store, runtime)
            assert restored.accepted_history[:-1] == retained.accepted_history
            assert all(
                not asset.inspected.verified.local_path.exists()
                for asset in restored.accepted_history
            )
            for path, (data, stat) in bootstrap_stats.items():
                assert (path.read_bytes(), path.stat()) == (data, stat)
            serve_generation(2)
            check(restored, 2)
            fresh = native_client(
                name,
                fixtures,
                "fresh",
                http.url(name),
                key,
                http.url("runtime-repo"),
                runtime_commits,
            )
            fresh(restored, 2)
            recorded.downloads.clear()
            recorded.native.clear()
            recorded.inspected.clear()
            recorded.forbid_native = True
            unchanged = reconcile()
            assert not unchanged.changed and unchanged.published_objects == 0
            assert recorded.downloads == ["SHA256SUMS"] and not recorded.native
            for ref in restored.objects:
                assert sha256_file(Path(storage.public[name]) / ref.key) == (ref.sha256, ref.size)
            return
        frozen = state.pending_generation(store)
        assert frozen is not None
        raw_manifest = store.read_private(
            f"generations/{frozen.id}/manifest.json", max_bytes=state.MAX_CONTROL_BYTES
        )
        assert raw_manifest is not None
        journal, _ = state.read_journal(store, frozen)
        outstanding = [
            int(index)
            for index, value in state.mapping(journal["writes"]).items()
            if state.mapping(value)["status"] == "intent"
        ]
        assert len(outstanding) == 1
        current = state.read_control(store, "ownership.json")
        assert current is not None
        nonce = str(current[0]["nonce"])
        for asset in assets:
            asset.local_path.unlink(missing_ok=True)
        monkeypatch.delenv("HD_SIGNING_KEY_FILE")
        with private_workspace() as runtime, ExitStack() as disabled:

            def forbidden(*args: object, **kwargs: object) -> None:
                raise AssertionError(
                    "Frozen replay called discovery, inspection, preparation or signing"
                )

            disabled.enter_context(patch.object(discovery, "scan_releases", forbidden))
            disabled.enter_context(patch.object(publish, "signing_session", forbidden))
            for operation in ("inspect", "prepare"):
                disabled.enter_context(patch(f"haberdasher.formats.{name}.{operation}", forbidden))
            store = InterruptedStore(storage)
            evidence = fixtures.root / "recovery.json"
            evidence.write_bytes(
                canonical_json(
                    {
                        "schema_version": 1,
                        **state.mapping(
                            json_value(
                                state.RecoveryEvidence(
                                    True,
                                    True,
                                    "test process stopped and public request was not sent",
                                    "fresh-test-runtime",
                                    tuple(
                                        state.WriteResolution(index, "not-written")
                                        for index in outstanding
                                    ),
                                )
                            )
                        ),
                    }
                )
            )
            assert (
                cli.main(
                    [
                        "--replay",
                        frozen.id,
                        "--recover-owner",
                        nonce,
                        "--recovery-evidence",
                        str(evidence),
                        *arguments,
                    ]
                )
                == 0
            )
            assert json.loads(capsys.readouterr().out)["generation_id"] == frozen.id
            assert (
                store.read_private(
                    f"generations/{frozen.id}/manifest.json", max_bytes=state.MAX_CONTROL_BYTES
                )
                == raw_manifest
            )
            restored = committed(store, runtime)
            assert len(restored.accepted_history) == len(assets)
            assert restored.accepted_history[:-1] == retained.accepted_history
            assert all(
                not asset.inspected.verified.local_path.exists()
                for asset in restored.accepted_history
            )
        for path, (data, stat) in bootstrap_stats.items():
            assert (path.read_bytes(), path.stat()) == (data, stat)
        serve_generation(2)
        check(restored, 2)
        fresh = native_client(
            name, fixtures, "fresh", http.url(name), key, http.url("runtime-repo"), runtime_commits
        )
        fresh(restored, 2)
        requests = http.requests()
        assert any(
            request.status == 200 and request.path.startswith(f"/{name}/") for request in requests
        )
        for ref in restored.objects:
            assert sha256_file(Path(storage.public[name]) / ref.key) == (ref.sha256, ref.size)
        assert not any(
            "private" in request.path or "generations" in request.path for request in requests
        )


@pytest.mark.parametrize("after", [False, True], ids=["before-key-write", "after-key-write"])
def test_public_bootstrap_interruption_replays_without_source_or_signer(
    after: bool, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with private_workspace() as fixtures, disposable_key() as key:
        assets = assets_for("apt", fixtures)
        recorded = RecordedGitHub(assets)
        local_root = fixtures.root / "store"
        storage = StoragePolicy(
            "local", str(local_root / "private"), {"apt": str(local_root / "public/apt")}
        )
        target = "keys/haberdasher.gpg" if after else "keys/haberdasher.asc"

        class KeyFailure(LocalStore):
            def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
                if ref.bucket_role == "apt" and ref.key == target:
                    if after:
                        super().create(ref, source)
                    raise RuntimeError("synthetic bootstrap interruption")
                return super().create(ref, source)

        store = KeyFailure(storage)
        config = Config(("wimpysworld/fixture",), {"apt": apt.policy()})
        policy = Policy(storage, expected_signing_fingerprint=key.fingerprint)
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key.key_file))
        with private_workspace() as runtime:
            recorded.bind(runtime)
            with pytest.raises(RuntimeError, match="bootstrap interruption"):
                publish.reconcile(
                    config, policy, store=store, runtime=runtime, now=datetime.now(UTC)
                )
        frozen = state.pending_generation(store)
        current = state.read_control(store, "ownership.json")
        assert frozen is not None and current is not None
        assert state.read_control(store, "completed.json") is None
        assert not (Path(storage.public["apt"]) / "dists").exists()
        manifest = store.read_private(
            f"generations/{frozen.id}/manifest.json", max_bytes=state.MAX_CONTROL_BYTES
        )
        assert manifest is not None
        assert hashlib.sha256(manifest[0]).hexdigest() == frozen.manifest_hash
        for forbidden_path in (str(key.key_file), str(key.runtime.root), "private-keys-v1.d"):
            assert forbidden_path.encode() not in manifest[0]
        with private_workspace() as runtime:
            generation, _ = state.load_frozen(store, frozen, out=runtime.root / "frozen")
            ordinal = 1 if after else 0
            output = generation.bootstrap_outputs[ordinal]
            assert output.ref.key == target
            observed = store.stat(output.ref)
            resolution = (
                state.WriteResolution(ordinal, "written", observed.etag)
                if after and observed
                else state.WriteResolution(ordinal, "not-written")
            )
        for asset in assets:
            asset.local_path.unlink()
        key.key_file.unlink()
        monkeypatch.delenv("HD_SIGNING_KEY_FILE")

        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("Bootstrap replay attempted discovery or signing")

        monkeypatch.setattr(discovery, "scan_releases", forbidden)
        monkeypatch.setattr(publish, "signing_session", forbidden)
        evidence = fixtures.root / "recovery.json"
        evidence.write_bytes(
            canonical_json(
                {
                    "schema_version": 1,
                    **state.mapping(
                        json_value(
                            state.RecoveryEvidence(
                                True,
                                True,
                                "synthetic request resolved",
                                "fresh-runtime",
                                (resolution,),
                            )
                        )
                    ),
                }
            )
        )
        assert (
            cli.main(
                [
                    "--replay",
                    frozen.id,
                    "--recover-owner",
                    str(current[0]["nonce"]),
                    "--recovery-evidence",
                    str(evidence),
                    "--local-root",
                    str(local_root),
                    "--format",
                    "apt",
                ]
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["generation_id"] == frozen.id
        store = LocalStore(storage)
        assert (
            store.read_private(
                f"generations/{frozen.id}/manifest.json", max_bytes=state.MAX_CONTROL_BYTES
            )
            == manifest
        )
        with private_workspace() as runtime:
            retained = committed(store, runtime)
        with serve(local_root / "public") as http:
            client = native_client("apt", fixtures, "recovered", http.url("apt"), key, "", ("", ""))
            client(retained, 1)
