"""Conditional local storage and single-request native R2 transport."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from collections.abc import Generator, Sequence
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from haberdasher.config import StoragePolicy
from haberdasher.core import (
    ObjectRef,
    ObjectStat,
    OutputObject,
    Report,
    WriteReceipt,
    atomic_write,
    canonical_json,
    integer,
    plural,
    quiet,
    safe_key,
    safe_path,
    sha256_file,
    text,
)
from haberdasher.runtime import STORAGE_VARIABLES, Runtime, RuntimeFailure, transfer_timeout

MAX_OBJECT_SIZE = 5368709120
UPLOAD_TRANSFERS = 16
WRITE_ATTEMPTS = 3
WRITE_RETRY_SECONDS = 5


class StorageError(RuntimeError):
    pass


class PreconditionFailed(StorageError):
    pass


class UnknownWrite(StorageError):
    """A write may or may not have committed. The run stops, and a full rerun converges."""

    def __init__(
        self,
        ref: ObjectRef | None = None,
        cause: str = "an earlier write failed",
        observation: WriteReceipt | None = None,
    ) -> None:
        target = f" for {ref.bucket_role} object {ref.key}" if ref is not None else ""
        super().__init__(f"Write outcome is unknown{target} ({cause}); rerun the publication")
        self.observation = observation


def _check_ref(ref: ObjectRef) -> None:
    if not isinstance(ref, ObjectRef):
        raise ValueError("Expected an object reference")
    ref.__post_init__()
    if ref.size >= MAX_OBJECT_SIZE:
        raise ValueError("Objects at or above 5 GiB are not supported")


def _check_read(key: str, max_bytes: int) -> None:
    safe_key(key)
    integer(max_bytes, "read limit", 1)
    if max_bytes >= MAX_OBJECT_SIZE:
        raise ValueError("Read limits at or above 5 GiB are not supported")


def _etag(value: str) -> str:
    text(value, "ETag")
    if "*" in value or "," in value:
        raise ValueError("Expected one exact ETag, not a wildcard or list")
    return value


def _verify(ref: ObjectRef, source: Path) -> None:
    if sha256_file(source) != (ref.sha256, ref.size):
        raise StorageError("Object bytes differ from the expected SHA256 or size")


def _stats(line: str, progress: Report) -> None:
    """Pass on the periodic `rclone` statistics line, without its log prefix."""
    _, marker, stats = line.partition(" NOTICE: ")
    if marker and " ETA " in stats:
        progress(stats.strip())


def _rclone_error(result: subprocess.CompletedProcess[bytes]) -> str:
    """Name the last `rclone` error line, or the exit status when it printed none."""
    errors = [
        line for line in result.stderr.decode(errors="replace").splitlines() if " ERROR : " in line
    ]
    if errors:
        return errors[-1].partition(" ERROR : ")[2]
    return f"rclone exited with {result.returncode}"


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir(path: Path) -> None:
    safe_path(path.parent, path.name)
    if not path.exists():
        _mkdir(path.parent)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            safe_path(path.parent, path.name)
        _sync_directory(path.parent)
    if not path.is_dir():
        raise ValueError("Storage parent must be a directory")


@contextlib.contextmanager
def _temporary(parent: Path) -> Generator[Path]:
    safe_path(parent, "validation")
    descriptor, name = tempfile.mkstemp(prefix=".hd-store-", dir=parent)
    os.close(descriptor)
    path = Path(name)
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def _snapshot(ref: ObjectRef, source: Path, destination: Path) -> None:
    source = safe_path(source.parent, source.name)
    if not source.is_file() or source.stat().st_size != ref.size:
        raise StorageError("Source size or file type differs from the expected object")
    with source.open("rb") as incoming, destination.open("wb") as outgoing:
        remaining = ref.size
        while remaining:
            block = incoming.read(min(remaining, 1024 * 1024))
            if not block:
                raise StorageError("Source was truncated")
            outgoing.write(block)
            remaining -= len(block)
        if incoming.read(1):
            raise StorageError("Source grew during the copy")
        outgoing.flush()
        os.fsync(outgoing.fileno())
    _verify(ref, destination)


def _install(source: Path, destination: Path) -> None:
    destination = safe_path(destination.parent, destination.name)
    if destination.exists() and not destination.is_file():
        raise ValueError("Destination must be a regular file")
    os.replace(source, destination)
    _sync_directory(destination.parent)


class LocalStore:
    """Directory storage for isolated execution, not an R2 emulator.

    A directory flock serialises each request. The inode revision changes
    with replacement, including identical bytes.
    """

    def __init__(self, storage: StoragePolicy) -> None:
        if storage.backend != "local":
            raise ValueError("Local storage requires a local destination")
        storage.__post_init__()
        self._roots = {role: Path(path) for role, path in storage.public.items()}
        for root in self._roots.values():
            _mkdir(root)
        self._uncertain = False

    def _path(self, ref: ObjectRef) -> Path:
        _check_ref(ref)
        try:
            return safe_path(self._roots[ref.bucket_role], ref.key)
        except KeyError:
            raise ValueError("No destination for this bucket role") from None

    def _root(self, role: str) -> Path:
        try:
            return self._roots[role]
        except KeyError:
            raise ValueError("No destination for this bucket role") from None

    @contextlib.contextmanager
    def _locked(self, ref: ObjectRef) -> Generator[Path]:
        self._path(ref)
        descriptor = os.open(
            self._roots[ref.bucket_role], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield self._path(ref)
        finally:
            os.close(descriptor)

    @staticmethod
    def _stat(path: Path) -> ObjectStat | None:
        if not path.exists():
            return None
        if not path.is_file():
            raise StorageError("Stored object is not a regular file")
        return LocalStore._revision(path.stat())

    @staticmethod
    def _revision(info: os.stat_result) -> ObjectStat:
        revision = canonical_json(
            [info.st_dev, info.st_ino, info.st_ctime_ns, info.st_mtime_ns, info.st_size]
        )
        return ObjectStat(hashlib.sha256(revision).hexdigest(), info.st_size)

    def stat(self, ref: ObjectRef) -> ObjectStat | None:
        with self._locked(ref) as path:
            return self._stat(path)

    def download(self, ref: ObjectRef, destination: Path) -> ObjectStat:
        destination = safe_path(destination.parent, destination.name).absolute()
        if any(destination == root or root in destination.parents for root in self._roots.values()):
            raise ValueError("Downloads must not bypass conditional storage writes")
        with self._locked(ref) as path:
            result = self._stat(path)
            if result is None:
                raise FileNotFoundError("Stored object is absent")
            with _temporary(destination.parent) as temporary:
                _snapshot(ref, path, temporary)
                _install(temporary, destination)
            return result

    def read(self, role: str, key: str, *, max_bytes: int) -> tuple[bytes, ObjectStat] | None:
        _check_read(key, max_bytes)
        root = self._root(role)
        path = safe_path(root, key)
        with contextlib.ExitStack() as stack:
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.callback(os.close, directory)
            fcntl.flock(directory, fcntl.LOCK_EX)
            try:
                for part in key.split("/")[:-1]:
                    directory = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                    )
                    stack.callback(os.close, directory)
                descriptor = os.open(
                    path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
                )
            except FileNotFoundError:
                return None
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise StorageError("Stored object is not a regular file")
                before = self._revision(info)
                if before.size > max_bytes:
                    raise StorageError("Stored object exceeds the read limit")
                data = stream.read(before.size + 1)
                after = self._revision(os.fstat(stream.fileno()))
            if (
                len(data) != before.size
                or after != before
                or self._stat(safe_path(root, key)) != before
            ):
                raise StorageError("Stored object changed during read")
            return data, before

    def delete(self, role: str, key: str, *, expected_etag: str) -> None:
        expected_etag = _etag(expected_etag)
        root = self._root(role)
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            path = safe_path(root, key)
            current = self._stat(path)
            if current is None or current.etag != expected_etag:
                raise PreconditionFailed("Local object precondition failed")
            path.unlink()
            _sync_directory(path.parent)
        finally:
            os.close(descriptor)

    def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
        return self._write(ref, source, None)

    def replace(self, ref: ObjectRef, source: Path, *, expected_etag: str) -> WriteReceipt:
        return self._write(ref, source, _etag(expected_etag))

    def upload(self, outputs: Sequence[OutputObject], *, progress: Report = quiet) -> None:
        """Write new immutable objects, and overwrite unreferenced leftovers of a failed run."""
        for output in outputs:
            current = self.stat(output.ref)
            if current is None:
                self.create(output.ref, output.local_path)
            else:
                self.replace(output.ref, output.local_path, expected_etag=current.etag)

    def _write(self, ref: ObjectRef, source: Path, expected: str | None) -> WriteReceipt:
        if self._uncertain:
            raise UnknownWrite()
        with self._locked(ref) as path:
            current = self._stat(path)
            if (
                current is not None
                if expected is None
                else current is None or current.etag != expected
            ):
                raise PreconditionFailed("Local object precondition failed")
            _mkdir(path.parent)
            started = False
            receipt: WriteReceipt | None = None
            try:
                with _temporary(path.parent) as temporary:
                    _snapshot(ref, source, temporary)
                    started = True
                    _install(temporary, path)
                    _verify(ref, path)
                    result = self._stat(path)
                    if result is None:
                        raise StorageError("Written object is absent")
                    receipt = WriteReceipt(result.etag, ref.sha256, ref.size)
            except (OSError, StorageError) as error:
                if not started:
                    raise
                self._uncertain = True
                raise UnknownWrite(ref, type(error).__name__, receipt) from error
            return receipt


class R2Store:
    def __init__(self, storage: StoragePolicy, *, runtime: Runtime) -> None:
        if storage.backend != "r2":
            raise ValueError("R2 storage requires R2 buckets")
        storage.__post_init__()
        self._buckets = dict(storage.public)
        self._runtime = runtime
        environment = runtime.environment_for("storage")
        if any(not environment.get(name) for name in STORAGE_VARIABLES):
            raise ValueError("The three approved storage environment variables are required")
        self._endpoint = text(environment[STORAGE_VARIABLES[0]], "storage endpoint")
        parsed = urlsplit(self._endpoint)
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or (
                parsed.scheme != "https"
                and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1"})
            )
        ):
            raise ValueError("Storage requires HTTPS, or numeric loopback for isolated tests")
        self._uncertain = False

    def _bucket(self, ref: ObjectRef) -> str:
        _check_ref(ref)
        return self._role(ref.bucket_role)

    def _role(self, role: str) -> str:
        try:
            return self._buckets[role]
        except KeyError:
            raise ValueError("No bucket for this role") from None

    def _aws(
        self, operation: str, parameters: dict[str, str | int] | None, *extra: str
    ) -> list[str]:
        return [
            "aws",
            "s3api",
            operation,
            *(["--cli-input-json", canonical_json(parameters).decode()] if parameters else []),
            "--endpoint-url",
            self._endpoint,
            "--region",
            "auto",
            "--output",
            "json",
            "--no-cli-pager",
            "--no-cli-auto-prompt",
            *extra,
        ]

    @staticmethod
    def _response(data: bytes) -> dict[str, object]:
        try:
            value: object = json.loads(data)
        except ValueError, UnicodeError:
            raise StorageError("Invalid native storage response") from None
        if not isinstance(value, dict):
            raise StorageError("Expected a native storage response object")
        return cast(dict[str, object], value)

    @staticmethod
    def _response_etag(value: dict[str, object]) -> str:
        try:
            return _etag(text(value.get("ETag"), "response ETag"))
        except ValueError:
            raise StorageError("Missing or invalid response ETag") from None

    def stat(self, ref: ObjectRef) -> ObjectStat | None:
        return self._head(self._bucket(ref), ref.key)

    def _head(self, bucket: str, key: str) -> ObjectStat | None:
        command = self._aws("head-object", {"Bucket": bucket, "Key": key})
        result = self._runtime.run(command, env_kind="storage")
        if result.returncode:
            if re.search(
                rb"\((?:404|NoSuchKey|NotFound)\) when calling the HeadObject operation",
                result.stderr,
            ):
                return None
            raise StorageError("Native object stat failed")
        value = self._response(result.stdout)
        size = value.get("ContentLength")
        if type(size) is not int or size < 0:
            raise StorageError("Missing or invalid object size")
        return ObjectStat(self._response_etag(value), size)

    def download(self, ref: ObjectRef, destination: Path) -> ObjectStat:
        bucket = self._bucket(ref)
        destination = safe_path(destination.parent, destination.name)
        before = self.stat(ref)
        if before is None:
            raise FileNotFoundError("Stored object is absent")
        if before.size != ref.size:
            raise StorageError("Stored object size differs from the expected size")
        with _temporary(destination.parent) as temporary:
            result = self._runtime.run(
                [
                    "rclone",
                    "copyto",
                    f":s3:{bucket}/{ref.key}",
                    str(temporary),
                    "--s3-provider=Cloudflare",
                    "--s3-env-auth",
                    "--s3-region=auto",
                    f"--s3-endpoint={self._endpoint}",
                    "--s3-no-check-bucket",
                    "--ignore-times",
                    "--no-traverse",
                    "--retries=1",
                    "--low-level-retries=1",
                ],
                env_kind="storage",
                timeout=transfer_timeout(ref.size),
            )
            if result.returncode:
                raise StorageError("Native object download failed")
            _verify(ref, temporary)
            if self.stat(ref) != before:
                raise StorageError("Object changed during download")
            with temporary.open("rb") as stream:
                os.fsync(stream.fileno())
            _install(temporary, destination)
        return before

    def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
        return self._write(ref, source, None)

    def replace(self, ref: ObjectRef, source: Path, *, expected_etag: str) -> WriteReceipt:
        return self._write(ref, source, _etag(expected_etag))

    def read(self, role: str, key: str, *, max_bytes: int) -> tuple[bytes, ObjectStat] | None:
        _check_read(key, max_bytes)
        bucket = self._role(role)
        before = self._head(bucket, key)
        if before is None:
            return None
        if before.size > max_bytes:
            raise StorageError("Stored object exceeds the read limit")
        data = b""
        if before.size:
            with _temporary(self._runtime.root / "tmp") as temporary:
                result = self._runtime.run(
                    self._aws(
                        "get-object",
                        None,
                        f"--bucket={bucket}",
                        f"--key={key}",
                        f"--if-match={before.etag}",
                        f"--range=bytes=0-{before.size - 1}",
                        str(temporary),
                    ),
                    env_kind="storage",
                    timeout=transfer_timeout(before.size),
                )
                if result.returncode:
                    raise StorageError("Native object read failed")
                value = self._response(result.stdout)
                if (
                    self._response_etag(value) != before.etag
                    or type(value.get("ContentLength")) is not int
                    or value["ContentLength"] != before.size
                    or temporary.stat().st_size != before.size
                ):
                    raise StorageError("Stored object changed during read")
                with temporary.open("rb") as stream:
                    data = stream.read(before.size + 1)
                if len(data) != before.size:
                    raise StorageError("Stored object changed during read")
        if self._head(bucket, key) != before:
            raise StorageError("Stored object changed during read")
        return data, before

    def delete(self, role: str, key: str, *, expected_etag: str) -> None:
        expected_etag = _etag(expected_etag)
        safe_key(key)
        bucket = self._role(role)
        current = self._head(bucket, key)
        if current is None or current.etag != expected_etag:
            raise PreconditionFailed("Remote object precondition failed")
        result = self._runtime.run(
            self._aws("delete-object", {"Bucket": bucket, "Key": key, "IfMatch": expected_etag}),
            env_kind="storage",
        )
        if result.returncode:
            if re.search(
                rb"\((?:412|PreconditionFailed)\) when calling the DeleteObject operation",
                result.stderr,
            ):
                raise PreconditionFailed("Remote object precondition failed")
            raise StorageError("Native object delete failed")

    def _rclone(self, *arguments: str) -> list[str]:
        return [
            "rclone",
            *arguments,
            "--s3-provider=Cloudflare",
            "--s3-env-auth",
            "--s3-region=auto",
            f"--s3-endpoint={self._endpoint}",
            "--s3-no-check-bucket",
        ]

    def upload(self, outputs: Sequence[OutputObject], *, progress: Report = quiet) -> None:
        """Copy new immutable objects of one bucket with one `rclone` run per header group.

        The caller passes only objects that the published inventory does not reference.
        `--checksum` skips identical leftovers of a failed run and overwrites changed ones.
        One listing then confirms the size and MD5 of every uploaded key.
        """
        if self._uncertain:
            raise UnknownWrite()
        if not outputs:
            return
        roles = {output.ref.bucket_role for output in outputs}
        if len(roles) != 1:
            raise ValueError("One upload covers one bucket")
        role = roles.pop()
        bucket = self._role(role)
        with tempfile.TemporaryDirectory(
            prefix="hd-upload-", dir=self._runtime.root / "tmp"
        ) as directory:
            root = Path(directory)
            staging = root / "objects"
            expected: dict[str, tuple[int, str]] = {}
            groups: dict[tuple[str, str], list[ObjectRef]] = {}
            for output in outputs:
                ref = output.ref
                _check_ref(ref)
                if ref.key in expected:
                    raise ValueError("Duplicate upload key")
                target = safe_path(staging, ref.key)
                _mkdir(target.parent)
                _snapshot(ref, output.local_path, target)
                with target.open("rb") as stream:
                    expected[ref.key] = ref.size, hashlib.file_digest(stream, "md5").hexdigest()
                groups.setdefault((ref.content_type, ref.cache_control), []).append(ref)
            keys = root / "all.list"
            atomic_write(keys, "".join(f"{key}\n" for key in expected).encode())
            try:
                for index, ((content_type, cache_control), refs) in enumerate(
                    sorted(groups.items())
                ):
                    listing = root / f"{index}.list"
                    atomic_write(listing, "".join(f"{ref.key}\n" for ref in refs).encode())
                    result = self._runtime.run(
                        self._rclone(
                            "copy",
                            str(staging),
                            f":s3:{bucket}",
                            f"--files-from-raw={listing}",
                            "--no-traverse",
                            "--checksum",
                            f"--transfers={UPLOAD_TRANSFERS}",
                            f"--checkers={UPLOAD_TRANSFERS}",
                            "--s3-upload-cutoff=16M",
                            "--s3-chunk-size=16M",
                            "--s3-upload-concurrency=4",
                            f"--header-upload=Content-Type: {content_type}",
                            f"--header-upload=Cache-Control: {cache_control}",
                            "--stats=10s",
                            "--stats-one-line",
                            "--stats-log-level=NOTICE",
                        ),
                        env_kind="storage",
                        timeout=transfer_timeout(sum(ref.size for ref in refs)),
                        progress=lambda line: _stats(line, progress),
                    )
                    if result.returncode:
                        raise UnknownWrite(None, f"{role} upload: {_rclone_error(result)}")
                result = self._runtime.run(
                    self._rclone(
                        "lsjson",
                        f":s3:{bucket}",
                        f"--files-from-raw={keys}",
                        "--no-traverse",
                        "--recursive",
                        "--files-only",
                        "--hash",
                        "--hash-type=md5",
                    ),
                    env_kind="storage",
                    timeout=transfer_timeout(0) + len(expected) / UPLOAD_TRANSFERS,
                )
                if result.returncode:
                    raise UnknownWrite(None, f"{role} upload: {_rclone_error(result)}")
                try:
                    listed = {
                        str(item["Path"]): (item["Size"], item.get("Hashes", {}).get("md5"))
                        for item in json.loads(result.stdout)
                    }
                except ValueError, TypeError, KeyError, AttributeError:
                    raise UnknownWrite(None, f"{role} upload: invalid rclone listing") from None
                differ = sorted(key for key, value in expected.items() if listed.get(key) != value)
                if differ:
                    raise UnknownWrite(
                        None,
                        f"{role} upload: {plural(len(differ), 'object')} differ after upload,"
                        f" first {differ[0]}",
                    )
            except (UnknownWrite, RuntimeFailure, OSError) as error:
                self._uncertain = True
                if isinstance(error, UnknownWrite):
                    raise
                raise UnknownWrite(None, f"{role} upload: {error}") from error

    def _matches(self, ref: ObjectRef, bucket: str, md5: str) -> ObjectStat | None:
        """Return the stored object when its size and single-part MD5 ETag match the upload."""
        try:
            current = self._head(bucket, ref.key)
        except StorageError, RuntimeFailure:
            return None
        if current is None or current.size != ref.size or current.etag.strip('"') != md5:
            return None
        return current

    def _put(
        self, ref: ObjectRef, bucket: str, command: list[str], md5: str, *, create: bool
    ) -> WriteReceipt:
        """Retry a create only. A precondition failure on a retry can be the earlier attempt."""
        timeout = transfer_timeout(ref.size)
        cause = ""
        for attempt in range(WRITE_ATTEMPTS if create else 1):
            if attempt:
                time.sleep(WRITE_RETRY_SECONDS)
            try:
                result = self._runtime.run(command, env_kind="storage", timeout=timeout)
            except RuntimeFailure as error:
                cause = str(error)
                continue
            if result.returncode:
                code = re.search(
                    rb"\(([A-Za-z0-9]+)\) when calling the PutObject operation", result.stderr
                )
                cause = code[1].decode() if code else f"aws exited with {result.returncode}"
                if cause in {"412", "PreconditionFailed", "409", "ConditionalRequestConflict"}:
                    if not attempt:
                        raise PreconditionFailed("Remote object precondition failed")
                    cause += " on retry"
                    break
                continue
            try:
                etag = self._response_etag(self._response(result.stdout))
            except StorageError as error:
                cause = str(error)
                break
            current = self._matches(ref, bucket, md5)
            if current is None or current.etag != etag:
                raise UnknownWrite(ref, "stored object differs from the upload")
            return WriteReceipt(etag, ref.sha256, ref.size)
        current = self._matches(ref, bucket, md5)
        if current is None:
            raise UnknownWrite(ref, cause)
        return WriteReceipt(current.etag, ref.sha256, ref.size)

    def _write(self, ref: ObjectRef, source: Path, expected: str | None) -> WriteReceipt:
        if self._uncertain:
            raise UnknownWrite()
        bucket = self._bucket(ref)
        parameters: dict[str, str | int] = {
            "Bucket": bucket,
            "Key": ref.key,
            "ContentLength": ref.size,
            "ContentType": ref.content_type,
            "CacheControl": ref.cache_control,
        }
        parameters["IfNoneMatch" if expected is None else "IfMatch"] = (
            "*" if expected is None else expected
        )
        started = False
        observed: WriteReceipt | None = None
        failure: PreconditionFailed | UnknownWrite | None = None
        try:
            with _temporary(self._runtime.root / "tmp") as temporary:
                _snapshot(ref, source, temporary)
                with temporary.open("rb") as stream:
                    md5 = hashlib.file_digest(stream, "md5").hexdigest()
                command = self._aws("put-object", parameters, "--body", str(temporary))
                started = True
                try:
                    observed = self._put(ref, bucket, command, md5, create=expected is None)
                except (PreconditionFailed, UnknownWrite) as error:
                    if isinstance(error, UnknownWrite):
                        self._uncertain = True
                    failure = error
                    raise
        except OSError as error:
            if failure is not None:
                raise failure from error
            if not started:
                raise
            self._uncertain = True
            raise UnknownWrite(ref, type(error).__name__, observed) from error
        return observed


type Store = LocalStore | R2Store
