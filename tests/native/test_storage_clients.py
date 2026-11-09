"""Native clients against loopback doubles, not live R2 acceptance."""

from __future__ import annotations

import os
import shutil
from collections.abc import Generator
from pathlib import Path

import pytest

from haberdasher.runtime import Runtime
from haberdasher.storage import PreconditionFailed, R2Store, StorageError, UnknownWrite
from tests.support.store import object_ref, remote_policy, storage_http, synthetic_environment


@pytest.fixture
def client_path() -> str:
    path = os.environ.get("HABERDASHER_TOOL_PATH", os.environ.get("PATH", os.defpath))
    for name in ("aws", "rclone"):
        if shutil.which(name, path=path) is None:
            pytest.skip(f"Native storage acceptance requires {name}")
    return path


@pytest.fixture
def isolated_root(tmp_path: Path) -> Generator[Path]:
    yield tmp_path / "runtime"


def test_native_conditional_writes_and_rclone_download(
    isolated_root: Path, tmp_path: Path, client_path: str
) -> None:
    with storage_http() as server:
        runtime = Runtime(
            isolated_root, environ=synthetic_environment(server.endpoint, client_path)
        )
        try:
            store = R2Store(remote_policy(), runtime=runtime)
            source = tmp_path / "source"
            data = b"Native storage fixture\n" * 200
            source.write_bytes(data)
            ref = object_ref(data, key="nested/object with space+percent%")
            assert store.stat(ref) is None
            first = store.create(ref, source)
            assert first.sha256 == ref.sha256
            with pytest.raises(PreconditionFailed):
                store.create(ref, source)
            changed = data + b"second generation\n"
            source.write_bytes(changed)
            changed_ref = object_ref(changed, key=ref.key)
            second = store.replace(changed_ref, source, expected_etag=first.etag)
            assert second.etag != first.etag
            with pytest.raises(PreconditionFailed):
                store.replace(changed_ref, source, expected_etag=first.etag)
            destination = tmp_path / "download"
            assert store.download(changed_ref, destination).etag == second.etag
            assert destination.read_bytes() == changed
            puts = [request for request in server.requests if request[0] == "PUT"]
            assert len(puts) == 4
            assert puts[0][2:] == (None, "*")
            assert puts[2][2:] == (first.etag, None)
            assert all(method in {"HEAD", "PUT", "GET"} for method, *_ in server.requests)
            assert any(request[0] == "GET" for request in server.requests)
        finally:
            runtime.close()


@pytest.mark.parametrize("accepted", [False, True])
def test_native_unknown_outcome_no_retry(
    isolated_root: Path, tmp_path: Path, client_path: str, accepted: bool
) -> None:
    with storage_http() as server:
        server.put_error = 503
        server.accept_then_error = accepted
        runtime = Runtime(
            isolated_root, environ=synthetic_environment(server.endpoint, client_path)
        )
        try:
            store = R2Store(remote_policy(), runtime=runtime)
            source = tmp_path / "source"
            source.write_bytes(b"fixture")
            with pytest.raises(UnknownWrite) as error:
                store.create(object_ref(), source)
            assert (error.value.observation is not None) == accepted
            with pytest.raises(UnknownWrite):
                store.create(object_ref(key="next"), source)
            assert len([request for request in server.requests if request[0] == "PUT"]) == 1
        finally:
            runtime.close()


@pytest.mark.parametrize("truncate", [False, True])
def test_native_bounded_read(isolated_root: Path, client_path: str, truncate: bool) -> None:
    with storage_http() as server:
        key = "control/object with space+percent%"
        data = b"inventory bytes\x00\xff"
        etag = '"rpm-revision"'
        server.objects[f"/test-rpm/{key}"] = data, etag
        server.objects[f"/test-public/{key}"] = b"other bucket bytes", '"apt-revision"'
        server.truncate_get = truncate
        runtime = Runtime(
            isolated_root, environ=synthetic_environment(server.endpoint, client_path)
        )
        try:
            store = R2Store(remote_policy(), runtime=runtime)
            assert store.read("rpm", "absent", max_bytes=10) is None
            with pytest.raises(StorageError, match="read limit"):
                store.read("rpm", key, max_bytes=len(data) - 1)
            assert not any(method == "GET" for method, *_ in server.requests)
            if truncate:
                with pytest.raises(StorageError):
                    store.read("rpm", key, max_bytes=len(data))
            else:
                result = store.read("rpm", key, max_bytes=len(data))
                assert result is not None
                assert result[0] == data
                assert result[1].etag == etag
                assert result[1].size == len(data)
            gets = [request for request in server.requests if request[0] == "GET"]
            assert gets == [("GET", f"/test-rpm/{key}", etag, None)]
            assert all(path.startswith("/test-rpm/") for _, path, *_ in server.requests)
            assert not list((runtime.root / "tmp").glob(".hd-store-*"))
        finally:
            runtime.close()


def test_native_conditional_delete(isolated_root: Path, client_path: str) -> None:
    with storage_http() as server:
        runtime = Runtime(
            isolated_root, environ=synthetic_environment(server.endpoint, client_path)
        )
        try:
            store = R2Store(remote_policy(), runtime=runtime)
            server.objects["/test-rpm/haberdasher.lock"] = b"lock", '"revision-2"'
            server.stale_delete = True
            with pytest.raises(PreconditionFailed):
                store.delete("rpm", "haberdasher.lock", expected_etag='"revision-2"')
            changed = '"revision-2-changed"'
            assert server.objects["/test-rpm/haberdasher.lock"] == (b"lock", changed)
            server.stale_delete = False
            store.delete("rpm", "haberdasher.lock", expected_etag=changed)
            assert "/test-rpm/haberdasher.lock" not in server.objects
            deletes = [request for request in server.requests if request[0] == "DELETE"]
            assert deletes == [
                ("DELETE", "/test-rpm/haberdasher.lock", '"revision-2"', None),
                ("DELETE", "/test-rpm/haberdasher.lock", changed, None),
            ]
        finally:
            runtime.close()


def test_native_truncated_download_preserves_destination(
    isolated_root: Path, tmp_path: Path, client_path: str
) -> None:
    with storage_http() as server:
        server.objects["/test-public/nested/object"] = b"fixture", '"revision-1"'
        server.truncate_get = True
        runtime = Runtime(
            isolated_root, environ=synthetic_environment(server.endpoint, client_path)
        )
        try:
            destination = tmp_path / "download"
            destination.write_bytes(b"preserve")
            with pytest.raises(StorageError):
                R2Store(remote_policy(), runtime=runtime).download(object_ref(), destination)
            assert destination.read_bytes() == b"preserve"
            assert len([request for request in server.requests if request[0] == "GET"]) == 1
        finally:
            runtime.close()
