"""Recorded GitHub transport, real adapters, locked storage and HTTP clients."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Generator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess
from typing import cast
from unittest.mock import patch
from urllib.request import urlopen

import pytest

from haberdasher import cli, publish, state
from haberdasher.config import (
    Config,
    Policy,
    StoragePolicy,
)
from haberdasher.core import (
    ObjectRef,
    ObjectStat,
    RetainedFormat,
    VerifiedAsset,
    WriteReceipt,
    sha256_file,
)
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import signing_session
from haberdasher.storage import LocalStore
from tests.native.fixtures import apk, apt, arch, flatpak, rpm
from tests.native.test_flatpak import (
    add_remotes,
    client_run,
    installed,
    payload_objects,
    published_remote,
)
from tests.support.http import serve
from tests.support.keys import DisposableKey, disposable_key, run
from tests.support.native import NativeClient


def printed_result(output: str) -> publish.RunResult:
    """Rebuild the run result from the publish progress lines and summary."""
    lines = output.splitlines()
    assert lines and "{" not in output
    objects = 0
    uploading = False
    for line in lines:
        words = line.split()
        if words[1:2] == ["uploading"]:
            uploading = True
        elif words[1:2] == ["uploaded"]:
            uploading = False
            objects += int(words[2])
        elif line.endswith(f"wrote {state.INVENTORY_KEY}"):
            uploading = False
            objects += 1
        elif not uploading and line.startswith(f"{words[0]:<5}   "):
            objects += 1
    pending = next((int(line.split()[1]) for line in lines if line.startswith("Skipped ")), 0)
    changed = lines[-1].startswith("Published ")
    assert changed or lines[-1].startswith("Nothing changed in ")
    return publish.RunResult(changed, objects, pending)


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
        self.extras: dict[str, bytes] = {}
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
        contents.update(self.extras)
        sums = "".join(
            f"{asset.sha256}  {asset.source.filename}\n"
            for asset in self.assets[: self.checksummed]
        ).encode()
        sums += "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in self.extras.items()
        ).encode()
        contents["SHA256SUMS"] = sums
        rows: list[dict[str, object]] = []
        for index, (name, data) in enumerate(contents.items(), 1):
            row: dict[str, object] = {
                "id": 999 if name == "SHA256SUMS" else index,
                "name": name,
                "size": len(data),
                "state": "uploaded",
                "updated_at": "2026-01-01T00:00:00Z",
                "browser_download_url": f"https://example.invalid/{name}",
            }
            # A late upload has neither a checksum entry nor a GitHub digest, so it stays pending.
            if name == "SHA256SUMS" or index <= self.checksummed:
                row["digest"] = "sha256:" + hashlib.sha256(data).hexdigest()
            rows.append(row)
        return rows, contents

    def record_native(self, argv: Sequence[str], input: bytes | None = None) -> None:
        if argv[0] == "gpgconf" or (argv[0] == "gpg" and "--show-keys" in argv):
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
if {recorded.forbid_native!r} and {command!r}!='gpgconf' and '--show-keys' not in sys.argv: sys.exit(88)
if data is not None:
    sys.exit(subprocess.run([{target!r},*sys.argv[1:]],input=data).returncode)
os.execv({target!r},[{target!r},*sys.argv[1:]])
""",
        )
    path = str(shim) + ":" + os.environ["HABERDASHER_TOOL_PATH"]
    result = subprocess.run(
        [sys.executable, "-m", "haberdasher", *arguments],
        cwd=root / "work",
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
    return printed_result(result.stdout.decode())


class InterruptedStore(LocalStore):
    """Fail a run after a set number of its entry writes, once packages are uploaded."""

    def __init__(self, policy: StoragePolicy) -> None:
        super().__init__(policy)
        self.downloads: list[ObjectRef] = []
        self.writes: list[ObjectRef] = []
        self.entries_before_failure: int | None = None
        self.entries = 0

    def interrupt_after(self, entries: int) -> None:
        self.entries_before_failure = entries
        self.entries = 0

    def download(self, ref: ObjectRef, destination: Path) -> ObjectStat:
        self.downloads.append(ref)
        return super().download(ref, destination)

    def _check(self, ref: ObjectRef) -> None:
        self.writes.append(ref)
        if ref.object_class != "entry":
            return
        if self.entries == self.entries_before_failure:
            self.entries_before_failure = None
            raise RuntimeError(f"synthetic interruption after {self.entries} entry writes")
        self.entries += 1

    def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
        self._check(ref)
        return super().create(ref, source)

    def replace(self, ref: ObjectRef, source: Path, *, expected_etag: str) -> WriteReceipt:
        self._check(ref)
        return super().replace(ref, source, expected_etag=expected_etag)


def snapshot(root: Path) -> dict[Path, tuple[bytes, int, int]]:
    return {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }


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


def strings(value: object) -> Generator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in cast(dict[str, object], value).values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in cast(list[object], value):
            yield from strings(item)


def committed(store: LocalStore, runtime: Runtime, name: str) -> RetainedFormat:
    current = store.read(name, state.INVENTORY_KEY, max_bytes=state.MAX_INVENTORY_BYTES)
    assert current is not None
    roots = (tempfile.gettempdir(), "/tmp/")
    assert not [item for item in strings(json.loads(current[0])) if any(r in item for r in roots)]
    published = state.read(store, name)
    assert {ref.key for ref in published.bootstrap} == set(state.BOOTSTRAP_KEYS)
    assert all(ref.key != state.LOCK_KEY for ref in published.objects)
    retained = state.materialise(store, published, out=runtime.root / "restored")
    for ref in published.objects:
        store.download(ref, runtime.root / "checked-object")
    return retained


@pytest.mark.parametrize("name", ["apt", "rpm", "arch", "apk", "flatpak"])
@pytest.mark.parametrize("interrupted", [False, True], ids=["cli", "rerun"])
def test_recorded_pipeline_and_full_rerun(
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
        storage = StoragePolicy("local", {name: str(local_root / "public" / name)})
        bucket = Path(storage.public[name])
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
        config = Config(("wimpysworld/fixture",))
        policy = Policy(storage, expected_signing_fingerprint=key.fingerprint)
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key.key_file))
        (fixtures.root / "work").mkdir()
        config_file = fixtures.root / "work/haberdasher.yaml"
        config_file.write_text("sources: [wimpysworld/fixture]\n")
        arguments = ["publish", "--local-root", str(local_root)]

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
                    arguments,
                )
            with private_workspace() as runtime:
                recorded.bind(runtime)
                return publish.reconcile(config, policy, store=store, runtime=runtime, now=now)

        def serve_generation(number: int) -> None:
            public = fixtures.root / "http" / name
            shutil.copytree(bucket, public, dirs_exist_ok=True)
            http.set_generation_mtime(
                [path for path in public.rglob("*") if path.is_file()], number
            )

        def unchanged_rerun() -> None:
            before = snapshot(bucket)
            recorded.downloads.clear()
            recorded.native.clear()
            recorded.inspected.clear()
            recorded.forbid_native = True
            store.downloads.clear()
            store.writes.clear()
            result = reconcile()
            assert not result.changed and result.published_objects == 0
            assert recorded.downloads == ["SHA256SUMS"] and not recorded.native
            assert not store.downloads
            if interrupted:
                assert [ref.key for ref in store.writes] == [state.LOCK_KEY]
            assert snapshot(bucket) == before
            recorded.forbid_native = False

        if interrupted:
            monkeypatch.chdir(fixtures.root / "work")
            with patch.object(cli, "private_workspace", recorded_workspace):
                assert cli.main(arguments) == 0
            first = printed_result(capsys.readouterr().out)
        else:
            first = reconcile()
        assert first.changed and first.published_objects > 0
        assert not (bucket / state.LOCK_KEY).exists()
        bootstrap_paths = sorted((bucket / "keys").iterdir())
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
            retained = committed(store, runtime, name)
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
        unchanged_rerun()
        recorded.visible += 1
        recorded.downloads.clear()
        pending = reconcile()
        assert pending.pending_assets == 1 and not pending.changed
        assert recorded.downloads == ["SHA256SUMS"] and not recorded.inspected
        recorded.checksummed += 1
        recorded.downloads.clear()
        recorded.native.clear()
        if interrupted:
            # Each rerun stops after one more entry write than the last, so that a full rerun
            # recovers from an interruption before and after every entry write of the run.
            entries = 0
            while True:
                inventory = (bucket / state.INVENTORY_KEY).read_bytes()
                store.writes.clear()
                store.interrupt_after(entries)
                try:
                    second = reconcile()
                    break
                except RuntimeError as error:
                    assert str(error) == f"synthetic interruption after {entries} entry writes"
                assert (bucket / state.INVENTORY_KEY).read_bytes() == inventory
                assert not (bucket / state.LOCK_KEY).exists()
                leftovers = {
                    ref.key for ref in store.writes if ref.object_class in {"package", "dependency"}
                }
                assert leftovers and all((bucket / key).exists() for key in leftovers)
                assert recorded.downloads == ["SHA256SUMS", assets[-1].source.filename]
                recorded.downloads.clear()
                recorded.inspected.clear()
                entries += 1
            store.entries_before_failure = None
            assert entries == sum(ref.object_class == "entry" for ref in store.writes) > 0
        else:
            second = reconcile()
        assert second.changed and second.pending_assets == 0
        assert recorded.downloads == ["SHA256SUMS", assets[-1].source.filename]
        assert {Path(path).name for path in recorded.inspected} == {f"{name}-0-asset"}
        assert not (bucket / state.LOCK_KEY).exists()
        with private_workspace() as runtime:
            restored = committed(store, runtime, name)
        assert len(restored.accepted_history) == len(assets)
        assert restored.accepted_history[:-1] == retained.accepted_history
        assert all(
            not asset.inspected.verified.local_path.exists() for asset in restored.accepted_history
        )
        for path, (data, stat) in bootstrap_stats.items():
            assert (path.read_bytes(), path.stat()) == (data, stat)
        serve_generation(2)
        check(restored, 2)
        fresh = native_client(
            name, fixtures, "fresh", http.url(name), key, http.url("runtime-repo"), runtime_commits
        )
        fresh(restored, 2)
        assets[-1].local_path.unlink()
        unchanged_rerun()
        for ref in restored.objects:
            assert sha256_file(bucket / ref.key) == (ref.sha256, ref.size)
        requests = http.requests()
        assert any(
            request.status == 200 and request.path.startswith(f"/{name}/") for request in requests
        )
        assert not any(state.LOCK_KEY in request.path for request in requests)


def signed_upstream_assets(
    name: str, runtime: Runtime, upstream: DisposableKey
) -> tuple[list[VerifiedAsset], dict[str, bytes]]:
    """Release assets that a separate upstream key signed, with a detached .sig for Arch."""
    with signing_session(
        upstream.runtime, expected_fingerprint=upstream.fingerprint, key_file=upstream.key_file
    ) as signer:
        match name:
            case "rpm":
                data = rpm.build(runtime, "hd-proof-data", "1", "dependency-v1", number=1)
                app = rpm.build(runtime, "hd-proof-app", "1", "application-v1", number=2)
                return [rpm.upstream_sign(runtime, asset, signer) for asset in (data, app)], {}
            case "apk":
                return [
                    apk.fixture(
                        runtime, "hd-dependency", "1.0-r0", payload="dependency", signer=signer
                    ),
                    apk.fixture(
                        runtime,
                        "hd-application",
                        "1.0-r0",
                        payload="first",
                        dependency="hd-dependency",
                        signer=signer,
                    ),
                ], {}
            case "arch":
                assets = [
                    arch.fixture(runtime, "keeper", "1", dependency="updateable>=1"),
                    arch.fixture(runtime, "updateable", "1"),
                ]
                signatures = {
                    asset.source.filename + ".sig": run(
                        runtime,
                        "gpg",
                        "--homedir",
                        str(signer.gnupghome),
                        "--batch",
                        "--local-user",
                        signer.fingerprint + "!",
                        "--detach-sign",
                        "--output",
                        "-",
                        str(asset.local_path),
                    )
                    for asset in assets
                }
                return assets, signatures
            case _:
                raise ValueError(name)


@pytest.mark.parametrize("name", ["rpm", "arch", "apk"])
def test_signed_upstream_publishes_installs_and_reruns(name: str) -> None:
    with (
        private_workspace() as fixtures,
        disposable_key() as key,
        disposable_key() as upstream,
        ExitStack() as stack,
    ):
        assert key.fingerprint != upstream.fingerprint
        assets, extras = signed_upstream_assets(name, fixtures, upstream)
        recorded = RecordedGitHub(assets)
        recorded.visible = recorded.checksummed = len(assets)
        recorded.extras = extras
        local_root = fixtures.root / "store"
        bucket = local_root / "public" / name
        (fixtures.root / "work").mkdir()
        (fixtures.root / "work/haberdasher.yaml").write_text("sources: [wimpysworld/fixture]\n")
        arguments = ["publish", "--local-root", str(local_root)]
        first = apply_cli(recorded, fixtures.root, key, arguments)
        assert first.changed and first.published_objects > 0
        assert recorded.downloads == ["SHA256SUMS", *(a.source.filename for a in assets)]
        public = fixtures.root / "http" / name
        shutil.copytree(bucket, public)
        http = stack.enter_context(serve(fixtures.root / "http"))
        http.set_generation_mtime([path for path in public.rglob("*") if path.is_file()], 1)
        storage = StoragePolicy("local", {name: str(bucket)})
        with private_workspace() as runtime:
            retained = committed(LocalStore(storage), runtime, name)
        for asset in retained.accepted_history:
            assert asset.inspected.verified.sha256 in {a.sha256 for a in assets}
            if name != "arch":
                assert asset.inspected.upstream_signature == "signed"
                assert asset.published_sha256 != asset.inspected.verified.sha256
        if name == "arch":
            assert not [
                path
                for path in public.rglob("*.pkg.tar.zst.sig")
                if path.read_bytes() in extras.values()
            ]
        check = native_client(name, fixtures, "signed", http.url(name), key, "", ("", ""))
        check(retained, 1)
        before = snapshot(bucket)
        recorded.downloads.clear()
        recorded.native.clear()
        recorded.forbid_native = True
        rerun = apply_cli(recorded, fixtures.root, key, arguments)
        assert not rerun.changed and rerun.published_objects == 0
        assert recorded.downloads == ["SHA256SUMS"] and not recorded.native
        assert snapshot(bucket) == before


@pytest.mark.parametrize("after", [False, True], ids=["before-key-write", "after-key-write"])
def test_public_bootstrap_interruption_converges_with_a_full_rerun(
    after: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    with private_workspace() as fixtures, disposable_key() as key:
        assets = assets_for("apt", fixtures)
        recorded = RecordedGitHub(assets)
        storage = StoragePolicy("local", {"apt": str(fixtures.root / "store/public/apt")})
        bucket = Path(storage.public["apt"])
        target = "keys/haberdasher.gpg" if after else "keys/haberdasher.asc"

        class KeyFailure(LocalStore):
            def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
                if ref.key == target:
                    if after:
                        super().create(ref, source)
                    raise RuntimeError("synthetic bootstrap interruption")
                return super().create(ref, source)

        config = Config(("wimpysworld/fixture",))
        assert config.format_policy("apt") == apt.policy()
        policy = Policy(storage, expected_signing_fingerprint=key.fingerprint)
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key.key_file))
        with private_workspace() as runtime:
            recorded.bind(runtime)
            with pytest.raises(RuntimeError, match="bootstrap interruption"):
                publish.reconcile(
                    config,
                    policy,
                    store=KeyFailure(storage),
                    runtime=runtime,
                    now=datetime.now(UTC),
                )
        assert not (bucket / "dists").exists()
        assert not (bucket / state.INVENTORY_KEY).exists()
        assert not (bucket / state.LOCK_KEY).exists()
        assert (bucket / "keys/haberdasher.asc").exists() == after
        store = LocalStore(storage)
        with private_workspace() as runtime:
            recorded.bind(runtime)
            result = publish.reconcile(
                config, policy, store=store, runtime=runtime, now=datetime.now(UTC)
            )
        assert result.changed
        with private_workspace() as runtime:
            retained = committed(store, runtime, "apt")
        with serve(fixtures.root / "store/public") as http:
            client = native_client("apt", fixtures, "rerun", http.url("apt"), key, "", ("", ""))
            client(retained, 1)


def test_flatpak_runs_download_only_the_working_set() -> None:
    """Three runs: an app, its second version, a second app. Later runs skip earlier payloads."""
    other = "world.wimpress.HaberdasherOther"
    with private_workspace() as fixtures, disposable_key() as key, ExitStack() as stack:
        assets = [
            flatpak.bundle(fixtures, fixtures.root, "1", 1),
            flatpak.bundle(fixtures, fixtures.root, "2", 2),
            flatpak.bundle(fixtures, fixtures.root, "1", 3, app=other),
        ]
        recorded = RecordedGitHub(assets)
        storage = StoragePolicy("local", {"flatpak": str(fixtures.root / "store/public/flatpak")})
        bucket = Path(storage.public["flatpak"])
        store = InterruptedStore(storage)
        (fixtures.root / "http").mkdir()
        with signing_session(
            fixtures, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer:
            runtime_commits = flatpak.runtime_repo(
                fixtures, fixtures.root / "http", signer.fingerprint, signer.gnupghome
            )
        http = stack.enter_context(serve(fixtures.root / "http"))
        config = Config(("wimpysworld/fixture",))
        policy = Policy(storage, expected_signing_fingerprint=key.fingerprint)
        client = NativeClient(fixtures, "incremental")
        downloads: list[tuple[int, int]] = []
        with patch.dict(os.environ, {"HD_SIGNING_KEY_FILE": str(key.key_file)}):
            for number in range(1, 4):
                heads = (
                    {
                        path.relative_to(bucket / "refs/heads").as_posix(): path.read_text().strip()
                        for path in (bucket / "refs/heads").rglob("*")
                        if path.is_file()
                    }
                    if bucket.exists()
                    else {}
                )
                earlier = set[str]().union(
                    *(
                        payload_objects(fixtures, bucket, ref)
                        for ref in heads
                        if ref.startswith("app/")
                    )
                )
                recorded.visible = recorded.checksummed = number
                store.downloads.clear()
                with private_workspace() as runtime:
                    recorded.bind(runtime)
                    result = publish.reconcile(
                        config, policy, store=store, runtime=runtime, now=datetime.now(UTC)
                    )
                assert result.changed
                keys = {ref.key for ref in store.downloads}
                assert len(keys) == len(store.downloads)
                assert not keys & earlier
                assert {key for key in keys if key.endswith(".commit")} == {
                    f"objects/{commit[:2]}/{commit[2:]}.commit" for commit in heads.values()
                }
                downloads.append((len(keys), sum(ref.size for ref in store.downloads)))
                public = fixtures.root / "http/flatpak"
                shutil.copytree(bucket, public, dirs_exist_ok=True)
                http.set_generation_mtime(
                    [path for path in public.rglob("*") if path.is_file()], number
                )
                if number == 1:
                    client_run(
                        client,
                        "remote-add",
                        f"--gpg-import={key.public_file}",
                        "provider",
                        http.url("runtime-repo"),
                    )
                    repofile = published_remote(
                        http.url("flatpak"), client.path("config/publisher.flatpakrepo")
                    )
                    client_run(client, "remote-add", "--from", "publisher", str(repofile))
                    assert (
                        "no-gpg-verify"
                        not in client_run(client, "remotes", "--columns=name,options").decode()
                    )
                    client_run(client, "install", "--noninteractive", "publisher", flatpak.APP)
                elif number == 2:
                    client_run(client, "update", "--noninteractive")
                else:
                    client_run(client, "install", "--noninteractive", "publisher", other)
                    client_run(client, "update", "--noninteractive")
                with private_workspace() as runtime:
                    retained = committed(store, runtime, "flatpak")
                commit = next(
                    identity.source_commit
                    for identity in retained.active_identities
                    if identity.name == flatpak.REF
                )
                assert commit is not None
                if number < 3:
                    installed(client, commit, str(number), runtime_commits)
                else:
                    assert (
                        client_run(client, "info", "--show-commit", flatpak.APP).strip().decode()
                        == commit
                    )
                    assert (
                        client_run(client, "info", "--show-origin", other).strip() == b"publisher"
                    )
                    assert {
                        f"{flatpak.APP}.flatpakref",
                        f"{other}.flatpakref",
                    } <= {path.name for path in bucket.glob("*.flatpakref")}
        assert downloads[0] == (0, 0)
        published = sum(path.stat().st_size for path in bucket.rglob("*") if path.is_file())
        for count, size in downloads[1:]:
            assert 0 < count < 100 and size < published / 2
        print(f"Flatpak working-set downloads per run (objects, bytes): {downloads}")
