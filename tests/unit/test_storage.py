from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import stat
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from haberdasher import storage
from haberdasher.core import ObjectStat, OutputObject, WriteReceipt
from haberdasher.runtime import Runtime, RuntimeFailure, transfer_timeout
from haberdasher.storage import (
    MAX_OBJECT_SIZE,
    LocalStore,
    PreconditionFailed,
    R2Store,
    StorageError,
    UnknownWrite,
)
from tests.support.store import local_policy, object_ref, remote_policy, synthetic_environment

if TYPE_CHECKING:
    from multiprocessing.queues import Queue
    from multiprocessing.synchronize import Event


class CommandRuntime(Runtime):
    def __init__(self, root: Path) -> None:
        super().__init__(root, environ=synthetic_environment("https://storage.invalid", os.defpath))
        self.calls: list[list[str]] = []
        self.timeouts: list[float] = []
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.failure = ""
        self.bad_download = False
        self.change_on_download = False
        self.head_error = False

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
        env_kind: str = "native",
        progress: Callable[[str], None] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        assert env_kind == "storage"
        command = list(argv)
        self.calls.append(command)
        self.timeouts.append(timeout)
        if command[0] == "rclone":
            key = command[2].split("/", 1)[1]
            data, etag = self.objects[key]
            Path(command[3]).write_bytes(data[:-1] if self.bad_download else data)
            if self.change_on_download:
                self.objects[key] = data, etag + "changed"
            return subprocess.CompletedProcess(command, 0, b"", b"")
        parameters = (
            {
                {"bucket": "Bucket", "key": "Key", "if-match": "IfMatch", "range": "Range"}[
                    name
                ]: value
                for argument in command
                if argument.startswith(("--bucket=", "--key=", "--if-match=", "--range="))
                for name, value in [argument[2:].split("=", 1)]
            }
            if command[2] == "get-object"
            else cast(dict[str, str], json.loads(command[command.index("--cli-input-json") + 1]))
        )
        key = parameters["Key"]
        if command[2] == "head-object":
            if self.head_error:
                return subprocess.CompletedProcess(command, 1, b"", b"Access denied (403)")
            if key not in self.objects:
                return subprocess.CompletedProcess(
                    command,
                    1,
                    b"",
                    b"An error occurred (404) when calling the HeadObject operation",
                )
            data, etag = self.objects[key]
            return subprocess.CompletedProcess(
                command, 0, json.dumps({"ETag": etag, "ContentLength": len(data)}).encode(), b""
            )
        if command[2] == "get-object":
            data, etag = self.objects[key]
            if parameters["IfMatch"] != etag:
                return subprocess.CompletedProcess(command, 1, b"", b"PreconditionFailed")
            assert parameters["Range"] == f"bytes=0-{len(data) - 1}"
            Path(command[-1]).write_bytes(data[:-1] if self.bad_download else data)
            if self.change_on_download:
                self.objects[key] = data, etag + "changed"
            return subprocess.CompletedProcess(
                command, 0, json.dumps({"ETag": etag, "ContentLength": len(data)}).encode(), b""
            )
        if command[2] == "delete-object":
            current = self.objects.get(key)
            if current is None or current[1] != parameters["IfMatch"]:
                return subprocess.CompletedProcess(
                    command,
                    1,
                    b"",
                    b"An error occurred (PreconditionFailed) when calling the DeleteObject operation",
                )
            del self.objects[key]
            return subprocess.CompletedProcess(command, 0, b"{}", b"")
        assert command[2] == "put-object"
        current = self.objects.get(key)
        if (parameters.get("IfNoneMatch") == "*" and current is not None) or (
            "IfMatch" in parameters and (current is None or current[1] != parameters["IfMatch"])
        ):
            return subprocess.CompletedProcess(
                command,
                1,
                b"",
                b"An error occurred (PreconditionFailed) when calling the PutObject operation",
            )
        timed_out = RuntimeFailure(f"Native command timed out after {timeout:.0f} seconds")
        if self.failure == "before":
            raise timed_out
        if self.failure == "unavailable":
            return subprocess.CompletedProcess(
                command,
                1,
                b"",
                b"An error occurred (ServiceUnavailable) when calling the PutObject operation",
            )
        data = Path(command[command.index("--body") + 1]).read_bytes()
        if self.failure in {"other", "corrupt"}:
            data = b"other bytes" if self.failure == "other" else data[:-1]
        etag = f'"{hashlib.md5(data, usedforsecurity=False).hexdigest()}"'
        self.objects[key] = data, etag
        if self.failure in {"after", "other"}:
            raise timed_out
        if self.failure == "nonzero":
            return subprocess.CompletedProcess(command, 1, b"", b"Lost response")
        if self.failure == "malformed":
            return subprocess.CompletedProcess(command, 0, b"{}", b"")
        if self.failure == "etag":
            etag = '"wrong-response"'
        return subprocess.CompletedProcess(command, 0, json.dumps({"ETag": etag}).encode(), b"")


@pytest.fixture
def command_runtime(tmp_path: Path) -> CommandRuntime:
    return CommandRuntime(tmp_path / "runtime")


def source_file(root: Path, data: bytes = b"fixture") -> Path:
    source = root / "source"
    source.write_bytes(data)
    return source


def fail_write_cleanup(monkeypatch: pytest.MonkeyPatch) -> PermissionError:
    original_mkstemp = tempfile.mkstemp
    original_unlink = Path.unlink
    target: Path | None = None
    failure = PermissionError("Injected temporary cleanup failure")

    def mkstemp(*, prefix: str, dir: Path) -> tuple[int, str]:
        nonlocal target
        descriptor, name = original_mkstemp(prefix=prefix, dir=dir)
        if target is None:
            target = Path(name)
        return descriptor, name

    def unlink(path: Path, missing_ok: bool = False) -> None:
        if path == target:
            raise failure
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(tempfile, "mkstemp", mkstemp)
    monkeypatch.setattr(Path, "unlink", unlink)
    return failure


@pytest.mark.parametrize("remote", [False, True])
@pytest.mark.parametrize("replacement", [False, True])
@pytest.mark.parametrize("role", ["apt", "rpm"])
def test_committed_cleanup_failure_retains_receipt_and_blocks_writes(
    tmp_path: Path,
    command_runtime: CommandRuntime,
    monkeypatch: pytest.MonkeyPatch,
    remote: bool,
    replacement: bool,
    role: str,
) -> None:
    policy = local_policy(tmp_path / "store")
    store = R2Store(remote_policy(), runtime=command_runtime) if remote else LocalStore(policy)
    source = source_file(tmp_path)
    first = store.create(object_ref(role=role), source) if replacement else None
    data = b"replacement" if replacement else b"fixture"
    source.write_bytes(data)
    ref = object_ref(data, role=role)
    cleanup = fail_write_cleanup(monkeypatch)
    with pytest.raises(UnknownWrite) as error:
        if first is None:
            store.create(ref, source)
        else:
            store.replace(ref, source, expected_etag=first.etag)
    assert error.value.__cause__ is cleanup
    current = store.stat(ref)
    assert current is not None
    assert error.value.observation == WriteReceipt(current.etag, ref.sha256, ref.size)
    if first is not None:
        assert current.etag != first.etag
    if remote:
        assert command_runtime.objects[ref.key] == (data, current.etag)
    else:
        root = Path(policy.public[role])
        assert (root / ref.key).read_bytes() == data
    calls = len(command_runtime.calls)
    next_ref = object_ref(data, key="next-object", role=role)
    with pytest.raises(UnknownWrite):
        store.create(next_ref, source)
    assert len(command_runtime.calls) == calls
    assert store.stat(next_ref) is None


@pytest.mark.parametrize("remote", [False, True])
@pytest.mark.parametrize("replacement", [False, True])
def test_cleanup_does_not_change_precondition_rejection(
    tmp_path: Path,
    command_runtime: CommandRuntime,
    monkeypatch: pytest.MonkeyPatch,
    remote: bool,
    replacement: bool,
) -> None:
    store = (
        R2Store(remote_policy(), runtime=command_runtime)
        if remote
        else LocalStore(local_policy(tmp_path / "store"))
    )
    source = source_file(tmp_path)
    ref = object_ref()
    first = store.create(ref, source)
    calls = len(command_runtime.calls)
    with monkeypatch.context() as patch:
        cleanup = fail_write_cleanup(patch)
        with pytest.raises(PreconditionFailed) as error:
            if replacement:
                store.replace(ref, source, expected_etag="stale")
            else:
                store.create(ref, source)
        assert error.value.__cause__ is (cleanup if remote else None)
    assert len(command_runtime.calls) == calls + int(remote)
    assert store.stat(ref) == ObjectStat(first.etag, ref.size)
    replaced = store.replace(ref, source, expected_etag=first.etag)
    assert (replaced.etag == first.etag) == remote


@pytest.mark.parametrize("remote", [False, True])
@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_snapshot_failure_does_not_mark_write_uncertain(
    tmp_path: Path,
    command_runtime: CommandRuntime,
    monkeypatch: pytest.MonkeyPatch,
    remote: bool,
    cleanup_failure: bool,
) -> None:
    store = (
        R2Store(remote_policy(), runtime=command_runtime)
        if remote
        else LocalStore(local_policy(tmp_path / "store"))
    )
    ref = object_ref()
    source = source_file(tmp_path, b"changed")
    with monkeypatch.context() as patch:
        if cleanup_failure:
            fail_write_cleanup(patch)
        with pytest.raises(PermissionError if cleanup_failure else StorageError):
            store.create(ref, source)
    assert not command_runtime.calls
    assert store.stat(ref) is None
    source.write_bytes(b"fixture")
    assert store.create(ref, source).sha256 == ref.sha256


def test_local_roundtrip_and_fresh_revision(tmp_path: Path) -> None:
    store = LocalStore(local_policy(tmp_path / "store"))
    source = source_file(tmp_path)
    ref = object_ref()
    assert store.stat(ref) is None
    first = store.create(ref, source)
    with pytest.raises(PreconditionFailed):
        store.create(ref, source)
    second = store.replace(ref, source, expected_etag=first.etag)
    assert second.etag != first.etag
    assert second.sha256 == first.sha256
    with pytest.raises(PreconditionFailed):
        store.replace(ref, source, expected_etag=first.etag)
    destination = tmp_path / "download"
    assert store.download(ref, destination) == ObjectStat(second.etag, ref.size)
    assert destination.read_bytes() == source.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o600
    assert LocalStore(local_policy(tmp_path / "store")).stat(ref) == ObjectStat(
        second.etag, ref.size
    )


def test_local_missing_and_conflicting_bytes(tmp_path: Path) -> None:
    store = LocalStore(local_policy(tmp_path / "store"))
    ref = object_ref()
    with pytest.raises(FileNotFoundError):
        store.download(ref, tmp_path / "absent")
    with pytest.raises(PreconditionFailed):
        store.replace(ref, source_file(tmp_path), expected_etag="absent")
    with pytest.raises(StorageError):
        store.create(ref, source_file(tmp_path, b"changed"))
    assert store.stat(ref) is None
    store.create(ref, source_file(tmp_path))
    destination = source_file(tmp_path, b"keep old destination")
    with pytest.raises(StorageError):
        store.download(object_ref(b"changed"), destination)
    assert destination.read_bytes() == b"keep old destination"


@pytest.mark.parametrize("where", ["source", "destination", "stored", "root"])
def test_local_symlinks_reject(tmp_path: Path, where: str) -> None:
    policy = local_policy(tmp_path / "store")
    source = source_file(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    if where == "root":
        (tmp_path / "store").symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError):
            LocalStore(policy)
        return
    store = LocalStore(policy)
    if where == "source":
        link = tmp_path / "link"
        link.symlink_to(source)
        with pytest.raises(ValueError):
            store.create(object_ref(), link)
    elif where == "stored":
        (Path(policy.public["apt"]) / "nested").symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError):
            store.create(object_ref(), source)
    else:
        store.create(object_ref(), source)
        link = tmp_path / "link"
        link.symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError):
            store.download(object_ref(), link / "object")


def test_local_download_write_bypass(tmp_path: Path) -> None:
    policy = local_policy(tmp_path / "store")
    store = LocalStore(policy)
    store.create(object_ref(), source_file(tmp_path))
    with pytest.raises(ValueError):
        store.download(object_ref(), Path(policy.public["apt"]) / "bypass")


def _contender(root: str, ready: Queue[str], start: Event, expected: str | None) -> None:
    store = LocalStore(local_policy(Path(root) / "store"))
    ready.put("ready")
    if not start.wait(10):
        raise RuntimeError("Contention test did not start")
    try:
        if expected is None:
            store.create(object_ref(), Path(root) / "source")
        else:
            store.replace(object_ref(), Path(root) / "source", expected_etag=expected)
        ready.put("written")
    except PreconditionFailed:
        ready.put("conflict")


@pytest.mark.parametrize("replacement", [False, True])
def test_local_process_contention(tmp_path: Path, replacement: bool) -> None:
    source = source_file(tmp_path)
    store = LocalStore(local_policy(tmp_path / "store"))
    expected = store.create(object_ref(), source).etag if replacement else None
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    start = context.Event()
    children = [
        context.Process(target=_contender, args=(str(tmp_path), queue, start, expected))
        for _ in range(6)
    ]
    try:
        for child in children:
            child.start()
        assert [queue.get(timeout=10) for _ in children] == ["ready"] * len(children)
        start.set()
        outcomes = [queue.get(timeout=10) for _ in children]
        assert outcomes.count("written") == 1
        assert outcomes.count("conflict") == 5
        for child in children:
            child.join(timeout=10)
            assert child.exitcode == 0
    finally:
        for child in children:
            if child.is_alive():
                child.kill()
                child.join(timeout=10)
        queue.close()
        queue.join_thread()


@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_local_fsync_and_uncertain_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cleanup_failure: bool
) -> None:
    store = LocalStore(local_policy(tmp_path / "store"))
    source = source_file(tmp_path)
    syncs: list[int] = []
    original = os.fsync

    def fsync(descriptor: int) -> None:
        syncs.append(os.fstat(descriptor).st_mode)
        original(descriptor)

    monkeypatch.setattr(os, "fsync", fsync)
    receipt = store.create(object_ref(), source)
    assert any(stat.S_ISREG(mode) for mode in syncs)
    assert any(stat.S_ISDIR(mode) for mode in syncs)

    def fail_sync(path: Path) -> None:
        raise OSError("Injected directory sync failure")

    with monkeypatch.context() as patch:
        patch.setattr(storage, "_sync_directory", fail_sync)
        cleanup = fail_write_cleanup(patch) if cleanup_failure else None
        with pytest.raises(UnknownWrite) as error:
            store.replace(object_ref(), source, expected_etag=receipt.etag)
        assert error.value.observation is None
        if cleanup is not None:
            assert error.value.__cause__ is cleanup
    with pytest.raises(UnknownWrite):
        store.create(object_ref(key="next"), source)
    assert store.stat(object_ref()) != ObjectStat(receipt.etag, len(b"fixture"))


def test_remote_missing_credentials_never_falls_back(tmp_path: Path) -> None:
    runtime = Runtime(tmp_path / "runtime", environ={"AWS_PROFILE": "unread"})
    with pytest.raises(ValueError, match="three HD_CLOUDFLARE"):
        R2Store(remote_policy(), runtime=runtime)


@pytest.mark.parametrize("remote", [False, True])
def test_size_limit_before_io(
    tmp_path: Path, command_runtime: CommandRuntime, remote: bool
) -> None:
    store = (
        R2Store(remote_policy(), runtime=command_runtime)
        if remote
        else LocalStore(local_policy(tmp_path / "store"))
    )
    ref = replace(object_ref(), size=MAX_OBJECT_SIZE)
    with pytest.raises(ValueError, match="5 GiB"):
        store.create(ref, tmp_path / "absent")
    assert not command_runtime.calls


def test_remote_roundtrip_and_arguments(tmp_path: Path, command_runtime: CommandRuntime) -> None:
    store = R2Store(remote_policy(), runtime=command_runtime)
    source = source_file(tmp_path)
    ref = replace(object_ref(), content_type="file://not-a-local-parameter")
    assert store.stat(ref) is None
    first = store.create(ref, source)
    second = store.replace(ref, source, expected_etag=first.etag)
    assert first.etag == second.etag == f'"{hashlib.md5(b"fixture").hexdigest()}"'
    assert not any(call[0] == "rclone" or "get-object" in call for call in command_runtime.calls)
    puts = [call for call in command_runtime.calls if call[0] == "aws" and call[2] == "put-object"]
    first_args = json.loads(puts[0][puts[0].index("--cli-input-json") + 1])
    second_args = json.loads(puts[1][puts[1].index("--cli-input-json") + 1])
    assert first_args["IfNoneMatch"] == "*"
    assert second_args["IfMatch"] == first.etag
    assert first_args["Key"] == ref.key
    assert first_args["ContentType"] == "file://not-a-local-parameter"
    assert first_args["ContentLength"] == ref.size
    assert first_args["CacheControl"] == ref.cache_control
    for call in command_runtime.calls:
        assert "sync" not in call and "delete" not in call
        assert "--no-verify-ssl" not in call and "--debug" not in call
        assert "inert-test-secret" not in " ".join(call)
        if call[0] == "rclone":
            assert "--retries=1" in call and "--low-level-retries=1" in call


@pytest.fixture(autouse=True)
def no_retry_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(storage, "WRITE_RETRY_SECONDS", 0)


def test_transfer_timeout_scales_with_size(tmp_path: Path, command_runtime: CommandRuntime) -> None:
    assert transfer_timeout(0) == 120
    assert transfer_timeout(105_000_000) == pytest.approx(1722.2, abs=0.1)
    store = R2Store(remote_policy(), runtime=command_runtime)
    store.create(object_ref(), source_file(tmp_path))
    store.download(object_ref(), tmp_path / "download")
    calls = list(zip(command_runtime.calls, command_runtime.timeouts, strict=True))
    puts = [timeout for call, timeout in calls if "put-object" in call]
    rclone = [timeout for call, timeout in calls if call[0] == "rclone"]
    assert puts == rclone == [transfer_timeout(7)]


@pytest.mark.parametrize(
    ("failure", "replacement", "puts"),
    [
        ("after", False, 2),
        ("nonzero", False, 2),
        ("malformed", False, 1),
        ("after", True, 1),
        ("nonzero", True, 1),
    ],
)
def test_committed_attempt_is_confirmed_by_head_and_md5(
    tmp_path: Path, command_runtime: CommandRuntime, failure: str, replacement: bool, puts: int
) -> None:
    store = R2Store(remote_policy(), runtime=command_runtime)
    source = source_file(tmp_path)
    ref = object_ref()
    first = store.create(ref, source) if replacement else None
    command_runtime.calls.clear()
    command_runtime.failure = failure
    if first is None:
        receipt = store.create(ref, source)
    else:
        receipt = store.replace(ref, source, expected_etag=first.etag)
    assert receipt == WriteReceipt(command_runtime.objects[ref.key][1], ref.sha256, ref.size)
    assert len([call for call in command_runtime.calls if "put-object" in call]) == puts
    command_runtime.failure = ""
    store.create(object_ref(key="next-object"), source)


@pytest.mark.parametrize(
    ("failure", "replacement", "puts", "cause"),
    [
        ("before", False, 3, "Native command timed out after 120 seconds"),
        ("unavailable", False, 3, "ServiceUnavailable"),
        ("other", False, 2, "PreconditionFailed on retry"),
        ("etag", False, 1, "stored object differs from the upload"),
        ("before", True, 1, "Native command timed out after 120 seconds"),
        ("other", True, 1, "Native command timed out after 120 seconds"),
    ],
)
@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_unconfirmed_write_is_unknown_and_blocks_writes(
    tmp_path: Path,
    command_runtime: CommandRuntime,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    replacement: bool,
    puts: int,
    cause: str,
    cleanup_failure: bool,
) -> None:
    store = R2Store(remote_policy(), runtime=command_runtime)
    old = object_ref(b"first")
    first = store.create(old, source_file(tmp_path, b"first")) if replacement else None
    source = source_file(tmp_path)
    ref = object_ref()
    command_runtime.calls.clear()
    command_runtime.failure = failure
    cleanup = fail_write_cleanup(monkeypatch) if cleanup_failure else None
    with pytest.raises(UnknownWrite) as error:
        if first is None:
            store.create(ref, source)
        else:
            store.replace(ref, source, expected_etag=first.etag)
    message = str(error.value)
    assert (
        message
        == f"Write outcome is unknown for apt object nested/object ({cause}); rerun the publication"
    )
    assert error.value.observation is None
    if cleanup is not None:
        assert error.value.__cause__ is cleanup
    assert len([call for call in command_runtime.calls if "put-object" in call]) == puts
    calls = len(command_runtime.calls)
    with pytest.raises(UnknownWrite, match=r"^Write outcome is unknown \(an earlier"):
        store.create(object_ref(key="next-object"), source)
    assert len(command_runtime.calls) == calls


def test_precondition_conflict_does_not_reconcile_equal_bytes(
    tmp_path: Path, command_runtime: CommandRuntime
) -> None:
    store = R2Store(remote_policy(), runtime=command_runtime)
    ref = object_ref()
    source = source_file(tmp_path)
    first = store.create(ref, source)
    for expected in (None, "stale"):
        before = len(command_runtime.calls)
        with pytest.raises(PreconditionFailed):
            if expected is None:
                store.create(ref, source)
            else:
                store.replace(ref, source, expected_etag=expected)
        assert len(command_runtime.calls) == before + 1
    assert store.stat(ref) == ObjectStat(first.etag, ref.size)


@pytest.mark.parametrize("changed", [False, True])
def test_remote_bad_reads_preserve_destination(
    tmp_path: Path, command_runtime: CommandRuntime, changed: bool
) -> None:
    store = R2Store(remote_policy(), runtime=command_runtime)
    store.create(object_ref(), source_file(tmp_path))
    command_runtime.bad_download = not changed
    command_runtime.change_on_download = changed
    destination = source_file(tmp_path, b"preserve")
    with pytest.raises(StorageError):
        store.download(object_ref(), destination)
    assert destination.read_bytes() == b"preserve"


@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_failed_write_verification_is_unknown(
    tmp_path: Path,
    command_runtime: CommandRuntime,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_failure: bool,
) -> None:
    command_runtime.failure = "corrupt"
    store = R2Store(remote_policy(), runtime=command_runtime)
    cleanup = fail_write_cleanup(monkeypatch) if cleanup_failure else None
    source = source_file(tmp_path)
    with pytest.raises(UnknownWrite) as error:
        store.create(object_ref(), source)
    assert error.value.observation is None
    if cleanup is not None:
        assert error.value.__cause__ is cleanup
    calls = len(command_runtime.calls)
    with pytest.raises(UnknownWrite):
        store.create(object_ref(key="next-object"), source)
    assert len(command_runtime.calls) == calls


def test_access_denied_is_not_absence(command_runtime: CommandRuntime) -> None:
    command_runtime.head_error = True
    with pytest.raises(StorageError):
        R2Store(remote_policy(), runtime=command_runtime).stat(object_ref())


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://storage.invalid",
        "https://user@storage.invalid",
        "https://storage.invalid/?x=y",
        "https://storage.invalid/path",
        "file:///tmp/object",
    ],
)
def test_unsafe_endpoints_reject(tmp_path: Path, endpoint: str) -> None:
    runtime = Runtime(tmp_path / "runtime", environ=synthetic_environment(endpoint, os.defpath))
    with pytest.raises(ValueError):
        R2Store(remote_policy(), runtime=runtime)


def test_storage_environment_has_no_inherited_authority(tmp_path: Path) -> None:
    hostile = {
        "AWS_PROFILE": "host-profile",
        "AWS_SESSION_TOKEN": "host-session",
        "AWS_WEB_IDENTITY_TOKEN_FILE": "/unread-token",
        "AWS_ROLE_ARN": "host-role",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://metadata.invalid",
        "AWS_CONFIG_FILE": "/unread-config",
        "AWS_SHARED_CREDENTIALS_FILE": "/unread-credentials",
        "AWS_ENDPOINT_URL": "http://wrong.invalid",
        "RCLONE_CONFIG": "/unread-rclone",
        "RCLONE_S3_ACCESS_KEY_ID": "host-access",
        "RCLONE_S3_SECRET_ACCESS_KEY": "host-secret",
        "RCLONE_NO_CHECK_CERTIFICATE": "true",
        "RCLONE_DUMP": "auth",
        "AWS_CA_BUNDLE": "/unread-ca",
        "HTTPS_PROXY": "http://proxy.invalid",
    }
    runtime = Runtime(
        tmp_path / "runtime",
        environ=hostile | synthetic_environment("https://storage.invalid", os.defpath),
    )
    environment = runtime.environment_for("storage")
    assert all(environment.get(name) != value for name, value in hostile.items())
    assert environment["AWS_ACCESS_KEY_ID"] == "inert-test-access"
    assert environment["AWS_SECRET_ACCESS_KEY"] == "inert-test-secret"
    assert environment["AWS_EC2_METADATA_DISABLED"] == "true"
    assert environment["AWS_MAX_ATTEMPTS"] == "1"
    for name in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "RCLONE_CONFIG"):
        assert Path(environment[name]).read_bytes() == b""
        assert Path(environment[name]).stat().st_mode & 0o777 == 0o600
    assert "AWS_ACCESS_KEY_ID" not in runtime.environment_for("native")
    assert "AWS_ACCESS_KEY_ID" not in runtime.environment_for("github")


@pytest.mark.parametrize("remote", [False, True])
@pytest.mark.parametrize("data", [b"", b"fixture", b"not JSON\x00\xff"])
def test_bounded_read_roundtrip(
    tmp_path: Path, command_runtime: CommandRuntime, remote: bool, data: bytes
) -> None:
    store = (
        R2Store(remote_policy(), runtime=command_runtime)
        if remote
        else LocalStore(local_policy(tmp_path / "store"))
    )
    ref = object_ref(data, role="rpm")
    assert store.read("rpm", ref.key, max_bytes=100) is None
    receipt = store.create(ref, source_file(tmp_path, data))
    command_runtime.calls.clear()
    expected = ObjectStat(receipt.etag, len(data))
    assert store.read("rpm", ref.key, max_bytes=max(1, len(data))) == (data, expected)
    assert all(
        "--bucket=test-rpm" in call
        if call[2] == "get-object"
        else json.loads(call[call.index("--cli-input-json") + 1])["Bucket"] == "test-rpm"
        for call in command_runtime.calls
    )
    assert store.stat(ref) == expected
    destination = tmp_path / "regular-download"
    assert store.download(ref, destination) == expected
    assert destination.read_bytes() == data


@pytest.mark.parametrize("remote", [False, True])
@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "1", MAX_OBJECT_SIZE])
def test_bounded_read_invalid_limit(
    tmp_path: Path, command_runtime: CommandRuntime, remote: bool, limit: object
) -> None:
    store = (
        R2Store(remote_policy(), runtime=command_runtime)
        if remote
        else LocalStore(local_policy(tmp_path / "store"))
    )
    with pytest.raises(ValueError):
        store.read("rpm", "control", max_bytes=cast(int, limit))
    assert not command_runtime.calls


@pytest.mark.parametrize("remote", [False, True])
@pytest.mark.parametrize("key", ["", "../escape", "/absolute", "a//b", "a/./b", r"a\b", "a\nb"])
def test_bounded_read_invalid_key(
    tmp_path: Path, command_runtime: CommandRuntime, remote: bool, key: str
) -> None:
    store = (
        R2Store(remote_policy(), runtime=command_runtime)
        if remote
        else LocalStore(local_policy(tmp_path / "store"))
    )
    with pytest.raises(ValueError):
        store.read("rpm", key, max_bytes=100)
    assert not command_runtime.calls


@pytest.mark.parametrize("remote", [False, True])
def test_bounded_read_oversize_before_download(
    tmp_path: Path, command_runtime: CommandRuntime, remote: bool
) -> None:
    store = (
        R2Store(remote_policy(), runtime=command_runtime)
        if remote
        else LocalStore(local_policy(tmp_path / "store"))
    )
    store.create(object_ref(role="rpm"), source_file(tmp_path))
    command_runtime.calls.clear()
    with pytest.raises(StorageError, match="read limit"):
        store.read("rpm", "nested/object", max_bytes=1)
    assert all(call[2] == "head-object" for call in command_runtime.calls)


def test_bounded_read_no_public_fallback(tmp_path: Path) -> None:
    store = LocalStore(local_policy(tmp_path / "store"))
    store.create(object_ref(), source_file(tmp_path))
    assert store.read("rpm", "nested/object", max_bytes=100) is None


@pytest.mark.parametrize("kind", ["file", "parent", "directory", "fifo"])
def test_local_bounded_read_unsafe_path(tmp_path: Path, kind: str) -> None:
    policy = local_policy(tmp_path / "store")
    store = LocalStore(policy)
    root = Path(policy.public["rpm"])
    outside = source_file(tmp_path)
    if kind == "file":
        (root / "control").symlink_to(outside)
    elif kind == "parent":
        (root / "control").symlink_to(tmp_path, target_is_directory=True)
    elif kind == "directory":
        (root / "control").mkdir()
    else:
        os.mkfifo(root / "control")
    key = "control/source" if kind == "parent" else "control"
    with pytest.raises((ValueError, OSError, StorageError)):
        store.read("rpm", key, max_bytes=100)


@pytest.mark.parametrize("change", ["truncate", "grow", "overwrite", "replace", "remove"])
def test_local_bounded_read_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    policy = local_policy(tmp_path / "store")
    store = LocalStore(policy)
    ref = object_ref(role="rpm")
    source = source_file(tmp_path)
    store.create(ref, source)
    path = Path(policy.public["rpm"]) / ref.key
    original = os.fstat
    changed = False

    def fstat(descriptor: int) -> os.stat_result:
        nonlocal changed
        info = original(descriptor)
        if not changed:
            changed = True
            if change == "replace":
                os.replace(source, path)
            elif change == "remove":
                path.unlink()
            else:
                path.write_bytes(
                    {"truncate": b"f", "grow": b"fixture!", "overwrite": b"changed"}[change]
                )
        return info

    monkeypatch.setattr(os, "fstat", fstat)
    with pytest.raises(StorageError, match="changed"):
        store.read("rpm", ref.key, max_bytes=ref.size)


@pytest.mark.parametrize("changed", [False, True])
def test_remote_bounded_read_bad_download(command_runtime: CommandRuntime, changed: bool) -> None:
    command_runtime.objects["control"] = b"fixture", '"original"'
    command_runtime.bad_download = not changed
    command_runtime.change_on_download = changed
    with pytest.raises(StorageError, match="changed"):
        R2Store(remote_policy(), runtime=command_runtime).read("rpm", "control", max_bytes=7)
    assert not list((command_runtime.root / "tmp").glob(".hd-store-*"))


@pytest.mark.parametrize("failure", ["replace", "remove", "access", "etag", "size", "oversize"])
def test_remote_bounded_read_failures_are_not_absence(
    command_runtime: CommandRuntime, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    command_runtime.objects["control"] = b"fixture", '"original"'
    original = command_runtime.run

    def run(
        argv: Sequence[str], *, timeout: float = 120, env_kind: str = "native"
    ) -> subprocess.CompletedProcess[bytes]:
        command = list(argv)
        if command[2] == "get-object":
            if failure == "replace":
                command_runtime.objects["control"] = b"changed", '"replacement"'
            elif failure in {"remove", "access"}:
                return subprocess.CompletedProcess(
                    command, 1, b"", b"404" if failure == "remove" else b"403"
                )
        result = original(argv, timeout=timeout, env_kind=env_kind)
        if command[2] == "get-object":
            if failure == "etag":
                result.stdout = b'{"ETag":"wrong","ContentLength":7}'
            elif failure == "size":
                result.stdout = b'{"ETag":"original","ContentLength":true}'
            elif failure == "oversize":
                Path(command[-1]).write_bytes(b"fixture!")
        return result

    monkeypatch.setattr(command_runtime, "run", run)
    with pytest.raises(StorageError):
        R2Store(remote_policy(), runtime=command_runtime).read("rpm", "control", max_bytes=7)
    assert not list((command_runtime.root / "tmp").glob(".hd-store-*"))


def test_remote_bounded_read_denied_head(command_runtime: CommandRuntime) -> None:
    command_runtime.head_error = True
    with pytest.raises(StorageError):
        R2Store(remote_policy(), runtime=command_runtime).read("rpm", "control", max_bytes=100)


@pytest.mark.parametrize("etag", ["*", '"one","two"', "bad\nvalue", ""])
def test_wildcard_or_unsafe_replacement_rejects(
    tmp_path: Path, command_runtime: CommandRuntime, etag: str
) -> None:
    source = source_file(tmp_path)
    stores = (
        LocalStore(local_policy(tmp_path / "store")),
        R2Store(remote_policy(), runtime=command_runtime),
    )
    for store in stores:
        with pytest.raises(ValueError):
            store.replace(object_ref(), source, expected_etag=etag)
    assert not command_runtime.calls


@pytest.mark.parametrize("remote", [False, True])
def test_conditional_delete(tmp_path: Path, command_runtime: CommandRuntime, remote: bool) -> None:
    store = (
        R2Store(remote_policy(), runtime=command_runtime)
        if remote
        else LocalStore(local_policy(tmp_path / "store"))
    )
    ref = object_ref(role="rpm", key="haberdasher.lock")
    first = store.create(ref, source_file(tmp_path))
    with pytest.raises(PreconditionFailed):
        store.delete("rpm", ref.key, expected_etag='"another-revision"')
    assert store.stat(ref) == ObjectStat(first.etag, ref.size)
    with pytest.raises(ValueError):
        store.delete("rpm", ref.key, expected_etag="*")
    store.delete("rpm", ref.key, expected_etag=first.etag)
    assert store.stat(ref) is None
    with pytest.raises(PreconditionFailed):
        store.delete("rpm", ref.key, expected_etag=first.etag)
    if remote:
        deletes = [call for call in command_runtime.calls if call[2] == "delete-object"]
        assert [json.loads(call[call.index("--cli-input-json") + 1]) for call in deletes] == [
            {"Bucket": "test-rpm", "Key": "haberdasher.lock", "IfMatch": first.etag}
        ]


def test_local_upload_overwrites_an_unreferenced_leftover(tmp_path: Path) -> None:
    store = LocalStore(local_policy(tmp_path))
    outputs: list[OutputObject] = []
    for index in range(2):
        data = f"package {index}".encode()
        ref = replace(object_ref(data, key=f"pool/package-{index}.deb"), object_class="package")
        path = tmp_path / f"source-{index}"
        path.write_bytes(data)
        outputs.append(OutputObject(ref, path, "create", None, index))
    store.create(outputs[0].ref, outputs[0].local_path)
    leftover = tmp_path / "public/apt/pool/package-0.deb"
    leftover.write_bytes(b"interrupted run")
    store.upload(outputs)
    assert leftover.read_bytes() == b"package 0"
    assert (tmp_path / "public/apt/pool/package-1.deb").read_bytes() == b"package 1"


def _recorded_stats(recorded: Sequence[str]) -> list[str]:
    lines: list[str] = []
    report = storage._stats(lines.append)  # pyright: ignore[reportPrivateUsage]
    report("2026/11/09 10:00:00 INFO  : pool/a.deb: Copied (new)")
    for line in recorded:
        report(f"2026/11/09 10:00:00 NOTICE: {line}\n")
    return lines


def test_rclone_stats_omit_a_fast_upload() -> None:
    assert _recorded_stats(["800 B / 800 B, 100%, 0 B/s, ETA -"]) == []
    assert _recorded_stats(["10.472 MiB / 10.472 MiB, 100%, 10.471 MiB/s, ETA 0s"]) == []


def test_rclone_stats_show_a_slow_upload_without_the_final_line() -> None:
    recorded = [
        "52.000 MiB / 204.513 MiB, 25%, 5.200 MiB/s, ETA 29s",
        "150.000 MiB / 204.513 MiB, 73%, 9.800 MiB/s, ETA 5s",
        "204.513 MiB / 204.513 MiB, 100%, 10.512 MiB/s, ETA 0s",
        "204.513 MiB / 204.513 MiB, 100%, 0 B/s, ETA -",
    ]
    assert _recorded_stats(recorded) == recorded[:2]


def test_rclone_stats_collapse_a_stall_and_resume() -> None:
    recorded = [
        "138.106 MiB / 204.513 MiB, 68%, 156.941 KiB/s, ETA 7m13s",
        "138.106 MiB / 204.513 MiB, 68%, 82.310 KiB/s, ETA 13m46s",
        "138.106 MiB / 204.513 MiB, 68%, 1.204 KiB/s, ETA 2y47w2d",
        "150.000 MiB / 204.513 MiB, 73%, 1.183 MiB/s, ETA 46s",
        "204.513 MiB / 204.513 MiB, 100%, 10.512 MiB/s, ETA 0s",
    ]
    assert _recorded_stats(recorded) == [
        recorded[0],
        "upload stalled, waiting",
        "upload resumed",
        recorded[3],
    ]
