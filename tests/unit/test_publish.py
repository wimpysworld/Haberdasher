from __future__ import annotations

import hashlib
import io
import json
import socket
import urllib.error
import urllib.request
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from haberdasher import cli, core, discovery, publish, site, state
from haberdasher.admission import AdmissionFailure
from haberdasher.config import Config, FormatPolicy, Policy, StoragePolicy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    NativeIdentity,
    ObjectRef,
    ObjectStat,
    OutputObject,
    PreparedFormat,
    RetainedFormat,
    SourceAsset,
    UnsupportedAsset,
    VerifiedAsset,
    WriteReceipt,
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession
from haberdasher.storage import LocalStore

NOW = datetime(2026, 1, 1, tzinfo=UTC)
FINGERPRINT = "A" * 40
EXPORT = b"synthetic public export"


class AdapterDouble:
    """Arch-shaped native metadata, with package bytes that change on every signing run."""

    def __init__(self) -> None:
        self.validations = 0
        self.prepares = 0
        self.inspections = 0

    def select(self, name: str) -> AdapterDouble:
        return self

    def inspect(
        self, asset: VerifiedAsset, *, policy: FormatPolicy, runtime: Runtime, out: Path
    ) -> InspectedAsset:
        self.inspections += 1
        name, version = asset.source.filename.removesuffix(".pkg.tar.zst").rsplit("-", 1)
        if version == "armhf":
            raise UnsupportedAsset(
                f"{asset.source.filename}: unsupported Arch architecture {version!r}"
            )
        return InspectedAsset(
            asset, NativeIdentity("arch", name, "x86_64", version), {}, {}, "unsigned"
        )

    def compare(
        self, left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime
    ) -> int | None:
        if (left.name, left.architecture) != (right.name, right.architecture):
            return None
        return (left.version > right.version) - (left.version < right.version)

    def validate_retained(
        self, retained: RetainedFormat, *, policy: FormatPolicy, runtime: Runtime
    ) -> None:
        self.validations += 1
        if not retained.metadata:
            return
        refs = {ref.key: ref for ref in retained.objects}
        stale = core.stale_entries(retained)
        for key, value in state.mapping(retained.metadata["paths"]).items():
            if key not in stale:
                assert core.sha256_file(Path(str(value))) == (refs[key].sha256, refs[key].size)
        assert Path(str(retained.metadata["public_key"])).read_bytes() == EXPORT

    def prepare(
        self,
        new: Sequence[AdmittedAsset],
        retained: RetainedFormat,
        *,
        policy: FormatPolicy,
        runtime: Runtime,
        signer: SigningSession,
        now: datetime,
        out: Path,
    ) -> PreparedFormat:
        self.prepares += 1
        out.mkdir(mode=0o700, parents=True)
        history = (*retained.accepted_history, *new)
        refs = {ref.key: ref for ref in retained.objects}
        etags = state.mapping(retained.metadata.get("etags", {}))
        outputs: list[OutputObject] = []

        def output(key: str, data: bytes, kind: str) -> Path:
            path = core.safe_path(out, key)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(data)
            sha, size = core.sha256_file(path)
            ref = ObjectRef("arch", key, kind, size, sha, "application/octet-stream", "no-cache")
            prior = refs.get(key)
            etag = str(etags[key]) if prior else None
            outputs.append(
                OutputObject(ref, path, "replace" if prior else "create", etag, len(outputs))
            )
            refs[key] = ref
            return path

        for asset in new:
            identity = asset.inspected.identity
            signature = f"\nsignature-{self.prepares}".encode()
            data = asset.inspected.verified.local_path.read_bytes() + signature
            output(f"x86_64/{identity.name}-{identity.version}.pkg", data, "package")
        names = sorted(
            f"{item.inspected.identity.name}-{item.inspected.identity.version}\n"
            for item in history
        )
        database = output("x86_64/db", "".join(names).encode(), "entry")
        public = out / "public.gpg"
        public.write_bytes(EXPORT)
        result = RetainedFormat(
            "arch",
            history,
            tuple(item.inspected.identity for item in history),
            {
                "paths": {"x86_64/db": str(database)},
                "public_key": str(public),
                "fingerprint": FINGERPRINT,
            },
            tuple(refs.values()),
        )
        return PreparedFormat("arch", result, tuple(outputs), result.objects)

    def validate_prepared(
        self, prepared: PreparedFormat, *, policy: FormatPolicy, runtime: Runtime
    ) -> None:
        self.validate_retained(prepared.retained, policy=policy, runtime=runtime)
        for output in prepared.outputs:
            assert core.sha256_file(output.local_path) == (output.ref.sha256, output.ref.size)


class CountingStore(LocalStore):
    interrupt = False
    interrupt_after_entry = False

    def __init__(self, storage: StoragePolicy) -> None:
        super().__init__(storage)
        self.writes: list[str] = []
        self.deletes: list[str] = []
        self.downloads: list[str] = []

    def create(self, ref: ObjectRef, source: Path) -> WriteReceipt:
        self._check(ref)
        self.writes.append(f"{ref.bucket_role}/{ref.key}")
        return self._after(ref, super().create(ref, source))

    def replace(self, ref: ObjectRef, source: Path, *, expected_etag: str) -> WriteReceipt:
        self._check(ref)
        self.writes.append(f"{ref.bucket_role}/{ref.key}")
        return self._after(ref, super().replace(ref, source, expected_etag=expected_etag))

    def delete(self, role: str, key: str, *, expected_etag: str) -> None:
        self.deletes.append(f"{role}/{key}")
        super().delete(role, key, expected_etag=expected_etag)

    def download(self, ref: ObjectRef, destination: Path) -> ObjectStat:
        self.downloads.append(f"{ref.bucket_role}/{ref.key}")
        return super().download(ref, destination)

    def _check(self, ref: ObjectRef) -> None:
        if self.interrupt and ref.object_class == "entry":
            self.interrupt = False
            raise RuntimeError("synthetic interruption after package upload")

    def _after(self, ref: ObjectRef, receipt: WriteReceipt) -> WriteReceipt:
        if self.interrupt_after_entry and ref.object_class == "entry":
            self.interrupt_after_entry = False
            raise RuntimeError("synthetic interruption after an entry write")
        return receipt


class Releases:
    """The GitHub "Latest" release of one source, as discovery returns it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir()
        self.assets: list[tuple[SourceAsset, Path]] = []
        self.release_id = 1
        self.next_id = 1
        self.fail = False

    def new_release(self) -> None:
        """Mark a new release as the latest, so that discovery no longer reads the old one."""
        self.release_id += 1
        self.assets.clear()

    def add(self, name: str, version: str, data: bytes | None = None) -> None:
        filename = f"{name}-{version}.pkg.tar.zst"
        path = self.root / f"{self.next_id}-{filename}"
        path.write_bytes(data or f"{name} {version}".encode())
        source = SourceAsset(
            "test/project",
            self.release_id,
            self.next_id,
            filename,
            path.stat().st_size,
            "2026-01-01T00:00:00Z",
            f"https://example.invalid/{filename}",
        )
        self.next_id += 1
        self.assets.append((source, path))

    def scan(
        self,
        config: Config,
        *,
        runtime: Runtime,
        report: core.Report = core.quiet,
    ) -> discovery.CompleteScan:
        if self.fail:
            raise discovery.DiscoveryFailure("synthetic discovery failure")
        sums = SourceAsset(
            "test/project",
            self.release_id,
            999,
            "SHA256SUMS",
            1,
            "2026-01-01T00:00:00Z",
            "https://example.invalid/s",
        )
        records = tuple(
            discovery.DiscoveredAsset(
                source,
                discovery.ChecksumEntry(sums, source.filename, core.sha256_file(path)[0], "c" * 64),
            )
            for source, path in self.assets
        )
        scanned = discovery.DiscoveryState(
            records, (*(source for source, _ in self.assets), sums), config.sources
        )
        return discovery.CompleteScan(scanned, records, ())

    def verify(
        self,
        source: SourceAsset,
        checksum: discovery.ChecksumEntry,
        *,
        runtime: Runtime,
        out: Path,
    ) -> VerifiedAsset:
        path = next(path for item, path in self.assets if item == source)
        sha, size = core.sha256_file(path)
        return VerifiedAsset(source, path, sha, size, 999, checksum.checksum_sha256)


class SignerDouble:
    fingerprint = FINGERPRINT

    def public_exports(self, out: Path) -> tuple[Path, Path, Path]:
        paths = tuple(
            out / name for name in ("haberdasher.asc", "haberdasher.gpg", "haberdasher.rsa.pub")
        )
        for path in paths:
            core.atomic_write(path, EXPORT)
        return paths[0], paths[1], paths[2]


@contextmanager
def signing(runtime: Runtime, *, expected_fingerprint: str) -> Generator[SigningSession]:
    yield cast(SigningSession, SignerDouble())


class Fixture:
    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch, names: tuple[str, ...]) -> None:
        self.storage = StoragePolicy("local", {name: str(root / "store" / name) for name in names})
        self.store = CountingStore(self.storage)
        self.policy = Policy(self.storage, FINGERPRINT)
        self.config = Config(("test/project",))
        self.runtime = Runtime(root / "runtime", environ={})
        self.adapter = AdapterDouble()
        self.releases = Releases(root / "releases")
        monkeypatch.setattr(publish, "_adapter", self.adapter.select)
        monkeypatch.setattr(publish, "signing_session", signing)
        monkeypatch.setattr(discovery, "scan_releases", self.releases.scan)
        monkeypatch.setattr(discovery, "verify_asset", self.releases.verify)

    def run(self, report: core.Report = core.quiet) -> publish.RunResult:
        self.store.writes.clear()
        self.store.deletes.clear()
        self.store.downloads.clear()
        return publish.reconcile(
            self.config, self.policy, store=self.store, runtime=self.runtime, now=NOW, report=report
        )

    def path(self, name: str, key: str) -> Path:
        return Path(self.storage.public[name]) / key

    def inventory(self, name: str = "arch") -> dict[str, object]:
        return json.loads(self.path(name, state.INVENTORY_KEY).read_bytes())

    def locks(self) -> list[str]:
        return [name for name in self.storage.public if self.path(name, state.LOCK_KEY).exists()]


def assert_published(fixture: Fixture, name: str = "arch") -> None:
    inventory = fixture.inventory(name)
    objects = cast(list[dict[str, object]], inventory["objects"])
    assert state.LOCK_KEY not in {item["key"] for item in objects}
    for item in objects:
        data = fixture.path(name, str(item["key"])).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item["sha256"]


def test_unchanged_rerun_writes_only_its_locks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    first = fixture.run()
    assert first.changed and first.published_objects == 7
    assert fixture.store.writes == [
        "arch/haberdasher.lock",
        "arch/keys/haberdasher.asc",
        "arch/keys/haberdasher.gpg",
        "arch/x86_64/tool-1.pkg",
        "arch/x86_64/db",
        "arch/haberdasher.json",
        "arch/og.png",
        "arch/index.html",
    ]
    assert fixture.store.deletes == ["arch/haberdasher.lock"] and not fixture.locks()
    assert_published(fixture)
    counts = (fixture.adapter.inspections, fixture.adapter.prepares)
    second = fixture.run()
    assert second == publish.RunResult(False, 0, 0)
    assert fixture.store.writes == ["arch/haberdasher.lock"]
    assert fixture.store.deletes == ["arch/haberdasher.lock"]
    assert not fixture.store.downloads
    assert (fixture.adapter.inspections, fixture.adapter.prepares) == counts


def test_asset_added_to_the_latest_release_publishes_only_the_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    fixture.run()
    package = fixture.path("arch", "x86_64/tool-1.pkg").read_bytes()
    fixture.releases.add("helper", "1")
    result = fixture.run()
    assert result.changed and result.published_objects == 4
    assert fixture.store.writes == [
        "arch/haberdasher.lock",
        "arch/x86_64/helper-1.pkg",
        "arch/x86_64/db",
        "arch/haberdasher.json",
        "arch/index.html",
    ]
    assert fixture.adapter.inspections == 2
    assert "arch/x86_64/tool-1.pkg" not in fixture.store.downloads
    assert fixture.path("arch", "x86_64/tool-1.pkg").read_bytes() == package
    assert fixture.path("arch", "x86_64/db").read_text() == "helper-1\ntool-1\n"
    assets = cast(list[dict[str, object]], fixture.inventory()["assets"])
    assert len(assets) == 2
    assert_published(fixture)


def test_new_latest_release_adds_packages_and_keeps_the_published_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    fixture.run()
    package = fixture.path("arch", "x86_64/tool-1.pkg").read_bytes()
    fixture.releases.new_release()
    fixture.releases.add("tool", "2")
    result = fixture.run()
    assert result.changed and result.packages == 1
    assert fixture.store.writes == [
        "arch/haberdasher.lock",
        "arch/x86_64/tool-2.pkg",
        "arch/x86_64/db",
        "arch/haberdasher.json",
        "arch/index.html",
    ]
    assert fixture.store.deletes == ["arch/haberdasher.lock"]
    assert fixture.path("arch", "x86_64/tool-1.pkg").read_bytes() == package
    assert fixture.path("arch", "x86_64/db").read_text() == "tool-1\ntool-2\n"
    assets = cast(list[dict[str, object]], fixture.inventory()["assets"])
    assert len(assets) == 2
    assert_published(fixture)
    assert fixture.run() == publish.RunResult(False, 0, 0)
    assert fixture.store.writes == ["arch/haberdasher.lock"]


def test_interrupted_run_converges_with_a_full_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    fixture.run()
    before = fixture.path("arch", state.INVENTORY_KEY).read_bytes()
    fixture.releases.add("tool", "2")
    fixture.store.interrupt = True
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        fixture.run()
    leftover = fixture.path("arch", "x86_64/tool-2.pkg").read_bytes()
    assert fixture.path("arch", state.INVENTORY_KEY).read_bytes() == before
    assert fixture.path("arch", "x86_64/db").read_text() == "tool-1\n"
    assert not fixture.locks()
    result = fixture.run()
    assert result.changed
    assert fixture.path("arch", "x86_64/tool-2.pkg").read_bytes() != leftover
    assert fixture.path("arch", "x86_64/db").read_text() == "tool-1\ntool-2\n"
    assert_published(fixture)
    assert fixture.run() == publish.RunResult(False, 0, 0)


def test_entry_interruption_converges_with_a_full_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    fixture.run()
    before = fixture.path("arch", state.INVENTORY_KEY).read_bytes()
    fixture.releases.add("tool", "2")
    fixture.store.interrupt_after_entry = True
    with pytest.raises(RuntimeError, match="after an entry write"):
        fixture.run()
    assert fixture.path("arch", state.INVENTORY_KEY).read_bytes() == before
    assert fixture.path("arch", "x86_64/db").read_text() == "tool-1\ntool-2\n"
    assert not fixture.locks()
    result = fixture.run()
    assert (result.changed, result.packages) == (True, 1)
    assert fixture.store.writes[-3:] == [
        "arch/x86_64/db",
        "arch/haberdasher.json",
        "arch/index.html",
    ]
    assert "arch/x86_64/tool-1.pkg" not in fixture.store.downloads
    assert fixture.path("arch", "x86_64/db").read_text() == "tool-1\ntool-2\n"
    assert_published(fixture)
    assert fixture.run() == publish.RunResult(False, 0, 0)
    assert fixture.store.writes == ["arch/haberdasher.lock"]
    fixture.releases.add("tool", "2", b"different bytes")
    with pytest.raises(AdmissionFailure, match="Changed bytes"):
        fixture.run()


def test_changed_bytes_for_a_published_identity_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    fixture.run()
    before = fixture.path("arch", state.INVENTORY_KEY).read_bytes()
    fixture.releases.add("tool", "1", b"different bytes")
    with pytest.raises(AdmissionFailure, match="Changed bytes"):
        fixture.run()
    assert fixture.path("arch", state.INVENTORY_KEY).read_bytes() == before
    assert not fixture.locks()


def test_second_publisher_fails_and_leaves_the_first_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch", "rpm"))
    fixture.releases.add("tool", "1")
    first = state.acquire(fixture.store, {"rpm": fixture.storage.public["rpm"]}, now=NOW)
    held = fixture.path("rpm", state.LOCK_KEY).read_bytes()
    with pytest.raises(state.StateError, match="is locked by another run") as error:
        fixture.run()
    assert fixture.storage.public["rpm"] in str(error.value)
    assert first.run_id in str(error.value)
    assert fixture.store.writes == ["arch/haberdasher.lock", "rpm/haberdasher.lock"]
    assert fixture.store.deletes == ["arch/haberdasher.lock"]
    assert fixture.locks() == ["rpm"]
    assert fixture.path("rpm", state.LOCK_KEY).read_bytes() == held
    assert not fixture.path("arch", state.INVENTORY_KEY).exists()
    state.release(fixture.store, first)
    assert fixture.run().changed


def test_handled_failure_releases_the_locks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch", "rpm"))
    fixture.releases.fail = True
    with pytest.raises(discovery.DiscoveryFailure):
        fixture.run()
    assert fixture.store.deletes == ["rpm/haberdasher.lock", "arch/haberdasher.lock"]
    assert not fixture.locks()


def test_lock_records_only_run_publisher_and_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_NAME", "runner-1")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "wimpysworld/Haberdasher")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("HD_SIGNING_KEY", "secret-sentinel")
    lock = state.acquire(fixture.store, fixture.storage.public, now=NOW)
    content = json.loads(fixture.path("arch", state.LOCK_KEY).read_bytes())
    assert content == {
        "publisher": "github-actions:runner-1",
        "run_id": lock.run_id,
        "run_url": "https://github.com/wimpysworld/Haberdasher/actions/runs/42",
        "started_at": NOW.isoformat(),
    }
    other = state.Lock("other", (("arch", "stale-etag"),))
    with pytest.raises(state.StateError, match="lock changed"):
        state.release(fixture.store, other)
    assert fixture.locks() == ["arch"]
    state.release(fixture.store, lock)
    assert not fixture.locks()


def test_unlock_deletes_existing_locks_only_on_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "local"
    work = tmp_path / "work"
    work.mkdir()
    (work / "haberdasher.yaml").write_text("sources: [test/project]\n")
    monkeypatch.chdir(work)
    monkeypatch.setenv("HD_SIGNING_KEY_FILE", "")
    storage = StoragePolicy("local", {name: str(root / "public" / name) for name in core.FORMATS})
    store = LocalStore(storage)
    state.acquire(store, {"arch": storage.public["arch"]}, now=NOW)
    releases = Releases(tmp_path / "releases")
    releases.add("tool", "1")
    monkeypatch.setattr(discovery, "scan_releases", releases.scan)
    assert cli.main(["publish", "--local-root", str(root)]) == 1
    error = capsys.readouterr().err
    assert "is locked by another run" in error and "Use just unlock only after" in error
    assert (root / "public/arch" / state.LOCK_KEY).exists()
    assert cli.main(["unlock", "--local-root", str(root)]) == 0
    lines = capsys.readouterr().out.splitlines()
    host = socket.gethostname()
    assert lines == [
        "apk   no lock",
        "apt   no lock",
        f"arch  removed lock from {host} started {NOW.isoformat()}",
        "brew  no lock",
        "flatpak no lock",
        "rpm   no lock",
        "scoop no lock",
        "Removed 1 lock.",
    ]
    assert not any((root / "public" / name / state.LOCK_KEY).exists() for name in core.FORMATS)
    assert not (root / "public/arch" / state.INVENTORY_KEY).exists()


def test_signing_fingerprint_change_fails_before_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    fixture.run()
    fixture.policy = replace(fixture.policy, expected_signing_fingerprint="B" * 40)
    fixture.releases.fail = True
    with pytest.raises(state.StateError, match="key rotation"):
        fixture.run()
    assert not fixture.locks()


@pytest.mark.parametrize("content", ["tampered\n", "tool-9\n"], ids=["size", "bytes"])
def test_changed_published_entry_is_rebuilt_from_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: str
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    fixture.run()
    fixture.path("arch", "x86_64/db").write_text(content)
    fixture.releases.add("tool", "2")
    assert fixture.run().changed
    assert fixture.path("arch", "x86_64/db").read_text() == "tool-1\ntool-2\n"
    assert_published(fixture)


def test_missing_published_entry_stops_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    fixture.run()
    fixture.path("arch", "x86_64/db").unlink()
    fixture.releases.add("tool", "2")
    with pytest.raises(state.StateError, match="x86_64/db is missing"):
        fixture.run()
    assert not fixture.path("arch", "x86_64/tool-2.pkg").exists()


def test_publish_reports_each_step_and_an_unchanged_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    clock = iter((10.0, 202.0))
    monkeypatch.setattr(publish.time, "monotonic", lambda: next(clock))
    lines: list[str] = []
    result = fixture.run(lines.append)
    assert (result.packages, result.repositories) == (1, ("arch",))
    assert result.published_objects == 7
    assert lines == [
        "arch  locked",
        "arch  preparing 1 new package",
        "arch  signed metadata",
        f"arch  uploading 3 objects ({2 * len(EXPORT) + 18} B)",
        f"arch    keys/haberdasher.asc ({len(EXPORT)} B)",
        f"arch    keys/haberdasher.gpg ({len(EXPORT)} B)",
        "arch    x86_64/tool-1.pkg (18 B)",
        "arch  uploaded 3 objects in 3m12s",
        "arch    x86_64/db (7 B)",
        "arch  wrote haberdasher.json",
        "arch  wrote og.png",
        "arch  wrote index.html",
        "arch  unlocked",
    ]
    lines.clear()
    assert not fixture.run(lines.append).changed
    assert lines == ["arch  locked", "arch  unchanged", "arch  unlocked"]


def test_publish_reports_batch_size_in_readable_units(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("big", "1", b"x" * 2_000_000)
    fixture.releases.add("mid", "1", b"x" * 4_000)
    lines: list[str] = []
    fixture.run(lines.append)
    assert [
        line.rsplit(" in ", 1)[0] for line in lines if "x86_64/" in line or "upload" in line
    ] == [
        "arch  uploading 4 objects (2 MB)",
        "arch    x86_64/big-1.pkg (2 MB)",
        "arch    x86_64/mid-1.pkg (4 KB)",
        "arch  uploaded 4 objects",
        "arch    x86_64/db (12 B)",
    ]


def test_flatpak_listing_summarises_objects() -> None:
    def ref(key: str, size: int) -> ObjectRef:
        return ObjectRef("flatpak", key, "package", size, "0" * 64, "a/b", "no-cache")

    refs = [
        ref("summary", 900),
        ref("objects/ab/cd.filez", 1_500_000),
        ref("deltas/x/superblock", 2_000),
        ref("objects/01/23.commit", 600_000),
        ref("refs/heads/app", 65),
    ]
    assert publish._listing("flatpak", refs) == [  # pyright: ignore[reportPrivateUsage]
        "  deltas/x/superblock (2 KB)",
        "  objects/ 2 files (2 MB)",
        "  refs/heads/app (65 B)",
        "  summary (900 B)",
    ]
    assert publish._listing("apt", refs[1:2]) == [  # pyright: ignore[reportPrivateUsage]
        "  objects/ab/cd.filez (2 MB)"
    ]


def test_plan_counts_published_and_new_packages_from_the_public_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("tool", "1")
    fixture.run()
    fixture.releases.add("tool", "2")
    inventory = fixture.path("arch", state.INVENTORY_KEY).read_bytes()
    urls = {"arch": "https://pkg.example.invalid", "apt": "https://apt.example.invalid"}
    requested: list[str] = []

    page = fixture.path("arch", site.PAGE_KEY).read_bytes()
    image = fixture.path("arch", site.IMAGE_KEY).read_bytes()

    def answer(request: urllib.request.Request, timeout: float) -> io.BytesIO:
        requested.append(request.full_url)
        if request.full_url.startswith("https://apt."):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", Message(), None)
        if request.full_url.endswith(site.IMAGE_KEY):
            return io.BytesIO(image)
        return io.BytesIO(page if request.full_url.endswith(site.PAGE_KEY) else inventory)

    scan = fixture.releases.scan(fixture.config, runtime=fixture.runtime)
    with patch.object(urllib.request, "urlopen", side_effect=answer):
        cli.show_plan(scan, fixture.config, fixture.runtime, urls, FINGERPRINT)
    assert requested == [
        "https://pkg.example.invalid/haberdasher.json",
        "https://apt.example.invalid/haberdasher.json",
        "https://pkg.example.invalid/og.png",
        "https://pkg.example.invalid/index.html",
    ]
    assert capsys.readouterr().out.splitlines() == [
        "Reading published state from pkg.example.invalid, apt.example.invalid",
        "",
        "Format  Repository           Published  New",
        "arch    pkg.example.invalid          1    1",
        "",
        "1 new package. Nothing written. Run `just publish` to publish them.",
    ]


def test_unsupported_asset_is_skipped_with_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    fixture.releases.add("other", "armhf")
    fixture.releases.add("tool", "1")
    skipped = "arch  skipped other-armhf.pkg.tar.zst: unsupported Arch architecture 'armhf'"
    lines: list[str] = []
    result = fixture.run(lines.append)
    assert (result.changed, result.packages) == (True, 1)
    assert lines.count(skipped) == 1
    assert lines.index(skipped) < lines.index("arch  preparing 1 new package")
    assert fixture.path("arch", "x86_64/db").read_text() == "tool-1\n"
    lines.clear()
    assert not fixture.run(lines.append).changed
    assert lines == ["arch  locked", skipped, "arch  unchanged", "arch  unlocked"]
    assert fixture.store.writes == ["arch/haberdasher.lock"]
    inventory = fixture.path("arch", state.INVENTORY_KEY).read_bytes()
    scan = fixture.releases.scan(fixture.config, runtime=fixture.runtime)
    fixture.path("arch", site.PAGE_KEY).unlink()
    fixture.path("arch", site.IMAGE_KEY).unlink()

    def answer(request: urllib.request.Request, timeout: float) -> io.BytesIO:
        if request.full_url.endswith((site.PAGE_KEY, site.IMAGE_KEY)):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", Message(), None)
        return io.BytesIO(inventory)

    with patch.object(urllib.request, "urlopen", side_effect=answer):
        cli.show_plan(scan, fixture.config, fixture.runtime, {"arch": "https://pkg.example"})
    output = capsys.readouterr().out.splitlines()
    assert output[1:] == [
        skipped,
        "arch  would write og.png",
        "arch  would write index.html",
        "",
        "Format  Repository   Published  New",
        "arch    pkg.example          1    0",
        "",
        "No new packages. 1 index page to write. 1 preview image to write. Nothing written. "
        "Run `just publish` to publish them.",
    ]
    lines.clear()
    result = fixture.run(lines.append)
    assert (result.changed, result.pages, result.published_objects, fixture.store.writes) == (
        True,
        ("arch",),
        2,
        ["arch/haberdasher.lock", "arch/og.png", "arch/index.html"],
    )
    assert lines == [
        "arch  locked",
        skipped,
        "arch  unchanged",
        "arch  wrote og.png",
        "arch  wrote index.html",
        "arch  unlocked",
    ]


def test_preview_image_is_written_only_when_missing_or_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path, monkeypatch, ("arch",))
    store = fixture.store
    lines: list[str] = []
    assert publish.write_image(store, "arch", report=lines.append) == 1
    assert store.writes == ["arch/og.png"] and lines == ["arch  wrote og.png"]
    assert fixture.path("arch", site.IMAGE_KEY).read_bytes() == site.image("arch")
    store.writes.clear()
    assert publish.write_image(store, "arch", report=lines.append) == 0
    assert store.writes == [] and len(lines) == 1
    fixture.path("arch", site.IMAGE_KEY).write_bytes(b"older image")
    assert publish.write_image(store, "arch") == 1
    assert store.writes == ["arch/og.png"]
    assert fixture.path("arch", site.IMAGE_KEY).read_bytes() == site.image("arch")
