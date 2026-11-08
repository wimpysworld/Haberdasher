import copy
import hashlib
import json
import subprocess
from collections.abc import Iterator, Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast
from urllib.parse import unquote

import pytest

from haberdasher import discovery
from haberdasher.config import Config
from haberdasher.core import SourceAsset, canonical_json
from haberdasher.discovery import (
    ChecksumEntry,
    CompleteScan,
    DiscoveryFailure,
    DiscoveryState,
    parse_checksums,
    scan_releases,
    verify_asset,
)
from haberdasher.runtime import Runtime, RuntimeFailure

FIXTURES = Path(__file__).parents[1] / "fixtures/github"
CONFIG = Config(("example/tool",))
RELEASES = "repos/example/tool/releases"


class RecordedGitHub(Runtime):
    def __init__(self, root: Path) -> None:
        super().__init__(root, environ={"PATH": ""})
        self.pages = cast(
            dict[str, list[dict[str, object]]], json.loads((FIXTURES / "pages.json").read_bytes())
        )
        bodies = cast(dict[str, str], json.loads((FIXTURES / "downloads.json").read_bytes()))
        self.bodies = {name: body.encode() for name, body in bodies.items()}
        self.calls: list[tuple[str, ...]] = []
        self.fail: str | None = None
        self.failure_mode = "nonzero"
        self.raw: bytes | None = None
        self.download_fault: str | None = None

    def rows(self, identifier: int) -> Iterator[dict[str, object]]:
        for page in self.pages.values():
            for row in page:
                if row["id"] == identifier:
                    yield row

    def update(self, identifier: int, **changes: object) -> None:
        for row in self.rows(identifier):
            row.update(changes)

    def body(self, name: str, data: bytes, identifier: int) -> None:
        self.bodies[name] = data
        self.update(identifier, size=len(data))

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
        env_kind: str = "native",
    ) -> subprocess.CompletedProcess[bytes]:
        assert cwd is None and input is None and timeout > 0
        assert env_kind == "github"
        assert argv[0] == "gh"
        self.calls.append(tuple(argv))
        if self.fail is not None and self.fail in argv:
            if self.failure_mode == "runtime":
                raise RuntimeFailure("injected launch, time or output failure")
            return subprocess.CompletedProcess(argv, 1, b"", b"injected error")
        if argv[1] == "api":
            assert "--hostname" in argv and "github.com" in argv
            assert "--method" in argv and "GET" in argv
            assert "--paginate" not in argv
            endpoint = argv[-1]
            if self.raw is not None:
                data = self.raw
            elif endpoint in self.pages:
                data = canonical_json(self.pages[endpoint])
            elif "/tags/" in endpoint:
                tag = unquote(endpoint.rsplit("/", 1)[1])
                release = next(
                    row
                    for page in self.pages.values()
                    for row in page
                    if row.get("tag_name") == tag
                )
                data = canonical_json(release)
            else:
                data = canonical_json(next(self.rows(int(endpoint.rsplit("/", 1)[1]))))
            return subprocess.CompletedProcess(argv, 0, data, b"")
        assert argv[1:3] == ["release", "download"]
        assert argv[argv.index("--repo") + 1] == "https://github.com/example/tool"
        assert argv[-2] == "--"
        pattern = argv[argv.index("--pattern") + 1]
        name = pattern.replace("\\", "")
        path = Path(argv[argv.index("--output") + 1])
        assert path.is_relative_to(self.root)
        assert path.parent.stat().st_mode & 0o777 == 0o700
        data = self.bodies[f"{argv[-1]}/{name}"]
        if self.download_fault == "missing":
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if self.download_fault == "symlink":
            path.symlink_to(self.root / "aws-config")
        else:
            if self.download_fault == "truncate":
                data = data[:-1]
            elif self.download_fault == "corrupt":
                data = b"x" * len(data)
            elif self.download_fault == "oversize":
                data += b"x"
            path.write_bytes(data)
        if self.download_fault == "replace":
            self.update(201, updated_at="2026-01-05T00:00:00Z")
        if self.download_fault == "retag":
            self.update(20, id=21)
        if self.download_fault == "partial-failure":
            return subprocess.CompletedProcess(argv, 1, b"", b"partial download")
        if self.download_fault == "timeout":
            raise RuntimeFailure("injected timeout")
        return subprocess.CompletedProcess(argv, 0, b"", b"")


@pytest.fixture
def github(tmp_path: Path) -> Iterator[RecordedGitHub]:
    runtime = RecordedGitHub(tmp_path / "runtime")
    try:
        yield runtime
    finally:
        runtime.close()


def scan(github: RecordedGitHub, previous: DiscoveryState | None = None) -> CompleteScan:
    return scan_releases(CONFIG, runtime=github, previous=previous or DiscoveryState())


def package(scan: CompleteScan, identifier: int = 201) -> tuple[SourceAsset, ChecksumEntry]:
    record = next(record for record in scan.state.records if record.source.asset_id == identifier)
    assert record.checksum is not None
    return record.source, record.checksum


def test_all_historical_pages_deduplication_and_unchanged(github: RecordedGitHub) -> None:
    first = scan(github)
    assert {item.source.asset_id for item in first.changed} == {101, 201}
    assert [item.source.asset_id for item in first.pending] == [203]
    assert len(first.state.assets) == 5
    assert not first.unchanged and not first.disappeared
    endpoints = [call[-1] for call in github.calls if call[1] == "api"]
    assert f"{RELEASES}?per_page=100&page=3" in endpoints
    assert f"{RELEASES}/20/assets?per_page=100&page=3" in endpoints
    assert not any("/30/assets" in endpoint or "/40/assets" in endpoint for endpoint in endpoints)
    github.calls.clear()
    second = scan(github, first.state)
    assert not second.changed
    assert len(second.unchanged) == 2 and len(second.pending) == 1
    assert second.state == first.state
    downloaded = [
        call[call.index("--pattern") + 1] for call in github.calls if call[1] == "release"
    ]
    assert downloaded == ["checksums.txt", "SHA256SUMS"]
    assert second.state.to_dict()["schema_version"] == 1


def test_late_checksum_and_package_upload(github: RecordedGitHub) -> None:
    first = scan(github)
    checksum = github.bodies["v2/checksums.txt"]
    checksum += f"{hashlib.sha256(b'later').hexdigest()}  late.rpm\n".encode()
    github.body("v2/checksums.txt", checksum, 202)
    late = scan(github, first.state)
    assert {record.source.asset_id for record in late.changed} == {203}
    assert {record.source.asset_id for record in late.unchanged} == {101, 201}
    assert package(late)[1].checksum_sha256 != package(first)[1].checksum_sha256
    assert not late.pending
    added = copy.deepcopy(next(github.rows(203)))
    added.update(id=204, name="new.apk", size=3)
    github.pages[f"{RELEASES}/20/assets?per_page=100&page=2"].append(added)
    uploaded = scan(github, late.state)
    assert [record.source.asset_id for record in uploaded.pending] == [204]
    assert not uploaded.changed


@pytest.mark.parametrize("change", ["timestamp", "digest", "new-id", "size", "url", "name"])
def test_replacement_fingerprints(github: RecordedGitHub, change: str) -> None:
    first = scan(github)
    if change == "timestamp":
        github.update(201, updated_at="2025-01-01T00:00:00Z")
    elif change == "digest":
        github.update(201, digest="sha256:" + hashlib.sha256(b"current-deb").hexdigest())
    elif change == "new-id":
        github.update(201, id=211)
    elif change == "size":
        github.update(201, size=12)
    elif change == "url":
        github.update(201, browser_download_url="https://example.invalid/replacement.deb")
    else:
        github.update(201, name="renamed.deb")
        body = github.bodies["v2/checksums.txt"].replace(b"app.deb", b"renamed.deb")
        github.body("v2/checksums.txt", body, 202)
    second = scan(github, first.state)
    assert len(second.changed) == 1
    assert second.changed[0].fingerprint != first.changed[0].fingerprint


@pytest.mark.parametrize("change", ["id", "bytes", "timestamp", "extra-document"])
def test_checksum_provenance_does_not_repeat_admission(github: RecordedGitHub, change: str) -> None:
    first = scan(github)
    before = canonical_json(first.state)
    if change == "id":
        github.update(202, id=212)
    elif change == "bytes":
        body = github.bodies["v2/checksums.txt"].replace(b"  app.deb", b" *app.deb")
        github.body("v2/checksums.txt", body, 202)
    elif change == "timestamp":
        github.update(202, updated_at="2026-02-01T00:00:00Z")
    else:
        extra = copy.deepcopy(next(github.rows(202)))
        body = f"{'a' * 64}  unrelated.txt\n".encode()
        extra.update(id=204, name="extra.sha256", size=len(body))
        github.pages[f"{RELEASES}/20/assets?per_page=100&page=2"].append(extra)
        github.bodies["v2/extra.sha256"] = body
    second = scan(github, first.state)
    assert not second.changed
    assert {record.source.asset_id for record in second.unchanged} == {101, 201}
    assert second.state != first.state
    assert [record.fingerprint for record in second.unchanged] == [
        record.fingerprint for record in first.changed
    ]
    assert canonical_json(first.state) == before


def test_legacy_document_fingerprint_does_not_repeat_admission(github: RecordedGitHub) -> None:
    first = scan(github)
    previous = replace(
        first.state,
        records=tuple(replace(record, fingerprint="f" * 64) for record in first.state.records),
    )
    second = scan(github, previous)
    assert not second.changed
    assert len(second.unchanged) == 2


def test_equal_size_backdated_bytes_are_detected_by_checksum(github: RecordedGitHub) -> None:
    first = scan(github)
    data = b"replacement"
    assert len(data) == len(github.bodies["v2/app.deb"])
    github.bodies["v2/app.deb"] = data
    github.body("v2/checksums.txt", f"{hashlib.sha256(data).hexdigest()}  app.deb\n".encode(), 202)
    second = scan(github, first.state)
    assert len(second.changed) == 1
    source, checksum = package(second)
    verified = verify_asset(source, checksum, runtime=github, out=github.root / "verified")
    assert verified.local_path.read_bytes() == data


def test_disappearance_never_changes_previous(github: RecordedGitHub) -> None:
    first = scan(github)
    before = canonical_json(first.state)
    for page in github.pages.values():
        page[:] = [row for row in page if row["id"] != 101]
    second = scan(github, first.state)
    assert [asset.asset_id for asset in second.disappeared] == [101]
    assert canonical_json(first.state) == before
    assert len(first.state.records) == 3


def test_disappeared_checksum_keeps_package_pending(github: RecordedGitHub) -> None:
    first = scan(github)
    for page in github.pages.values():
        page[:] = [row for row in page if row["id"] != 202]
    second = scan(github, first.state)
    assert {item.source.asset_id for item in second.pending} == {201, 203}
    assert [item.asset_id for item in second.disappeared] == [202]


@pytest.mark.parametrize(
    "endpoint",
    [
        f"{RELEASES}?per_page=100&page=3",
        f"{RELEASES}/10/assets?per_page=100&page=2",
        f"{RELEASES}/assets/102",
    ],
)
@pytest.mark.parametrize("mode", ["nonzero", "runtime"])
def test_failed_scan_preserves_previous(github: RecordedGitHub, endpoint: str, mode: str) -> None:
    first = scan(github)
    before = canonical_json(first.state)
    github.fail, github.failure_mode = endpoint, mode
    with pytest.raises((DiscoveryFailure, RuntimeFailure)):
        scan(github, first.state)
    assert canonical_json(first.state) == before
    assert not list((github.root / "downloads").iterdir())


def test_second_source_failure_does_not_return_partial_scan(github: RecordedGitHub) -> None:
    github.fail = "repos/example/second/releases?per_page=100&page=1"
    with pytest.raises(DiscoveryFailure):
        scan_releases(
            Config(("example/tool", "example/second")), runtime=github, previous=DiscoveryState()
        )
    assert not any(call[1] == "release" for call in github.calls)


@pytest.mark.parametrize("kind", ["release", "asset", "loop", "names", "cross-release-id"])
def test_conflicting_ids_names_and_pagination_loops(github: RecordedGitHub, kind: str) -> None:
    if kind == "release":
        github.pages[f"{RELEASES}?per_page=100&page=2"][0]["draft"] = True
    elif kind == "asset":
        github.pages[f"{RELEASES}/20/assets?per_page=100&page=2"][0]["size"] = 12
    elif kind == "loop":
        github.pages[f"{RELEASES}?per_page=100&page=2"] = copy.deepcopy(
            github.pages[f"{RELEASES}?per_page=100&page=1"]
        )
    elif kind == "names":
        github.update(203, name="app.deb")
    else:
        github.update(101, id=201)
    with pytest.raises(DiscoveryFailure):
        scan(github)


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"null",
        b"{",
        b'[{"id":1,"id":2}]',
        b"[NaN]",
        b"[[[]]]",
        b'[{"id":true}]',
        b'[{"id":1,"draft":"false","prerelease":false}]',
        b"[" * 40 + b"0" + b"]" * 40,
        b"\xff",
    ],
)
def test_malformed_api_responses(github: RecordedGitHub, raw: bytes) -> None:
    github.raw = raw
    with pytest.raises(ValueError):
        scan(github)


@pytest.mark.parametrize(
    "field,value",
    [
        ("digest", "sha512:" + "a" * 64),
        ("digest", "sha256:" + "a" * 63),
        ("name", "../app.deb"),
        ("name", " app.deb"),
        ("size", True),
        ("state", "new"),
        ("updated_at", "2026-01-01"),
        ("browser_download_url", "http://github.com/app.deb"),
    ],
)
def test_malformed_assets(github: RecordedGitHub, field: str, value: object) -> None:
    github.update(201, **{field: value})
    with pytest.raises(ValueError):
        scan(github)


def test_discovery_limits(github: RecordedGitHub, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery, "MAX_PAGES", 1)
    with pytest.raises(DiscoveryFailure, match="page limit"):
        scan(github)
    monkeypatch.setattr(discovery, "MAX_PAGES", 10_000)
    monkeypatch.setattr(discovery, "MAX_PAGE_BYTES", 1)
    with pytest.raises(DiscoveryFailure, match="byte limit"):
        scan(github)


def test_ambiguous_checksum_sources(github: RecordedGitHub) -> None:
    previous = scan(github).state
    before = canonical_json(previous)
    extra = copy.deepcopy(next(github.rows(202)))
    extra.update(id=204, name="SHA256SUMS")
    github.pages[f"{RELEASES}/20/assets?per_page=100&page=2"].append(extra)
    github.bodies["v2/SHA256SUMS"] = github.bodies["v2/checksums.txt"]
    with pytest.raises(DiscoveryFailure, match="Ambiguous checksum"):
        scan(github, previous)
    assert canonical_json(previous) == before


def test_github_package_digest_must_match_checksum(github: RecordedGitHub) -> None:
    previous = scan(github).state
    github.update(201, digest="sha256:" + "f" * 64)
    with pytest.raises(DiscoveryFailure, match="differs from GitHub"):
        scan(github, previous)


def checksum_source(data: bytes) -> SourceAsset:
    return SourceAsset(
        "example/tool",
        20,
        202,
        "checksums.txt",
        len(data),
        "2026-01-02T00:00:00Z",
        "https://github.com/example/tool/checksums.txt",
    )


@pytest.mark.parametrize(
    "line",
    [
        "a" * 64 + "  app.deb\n",
        "A" * 64 + " *app.deb\r\n",
        "SHA256 (app.deb) = " + "a" * 64 + "\n",
    ],
)
def test_exact_checksum_syntax(line: str) -> None:
    data = line.encode()
    entries = parse_checksums(data, checksum_source(data))
    assert len(entries) == 1
    assert entries[0].filename == "app.deb" and entries[0].sha256 == "a" * 64
    assert entries[0].checksum_sha256 == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize(
    "line",
    [
        "",
        "a" * 63 + "  app.deb",
        "g" * 64 + "  app.deb",
        "a" * 64 + " app.deb",
        "a" * 64 + "  ../app.deb",
        "a" * 64 + "  dir/app.deb",
        "a" * 64 + "  /app.deb",
        "a" * 64 + "  app\\.deb",
        "a" * 64 + "  app.deb\x00",
        "a" * 64 + "  app.deb ",
        "a" * 64 + "   app.deb",
        "\\" + "a" * 64 + "  app.deb",
        "# comment",
        "\ufeff" + "a" * 64 + "  app.deb",
        ("a" * 64 + "  app.deb\n") * 2,
        "a" * 64 + "  .",
        "a" * 64 + "  ..",
    ],
)
def test_reject_invalid_checksum_syntax(line: str) -> None:
    data = line.encode()
    with pytest.raises(ValueError):
        parse_checksums(data, checksum_source(data))


def test_checksum_bounds_and_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    data = ("a" * 64 + "  app.deb\n").encode()
    with pytest.raises(DiscoveryFailure, match="GitHub digest"):
        parse_checksums(data, replace(checksum_source(data), github_sha256="b" * 64))
    with pytest.raises(DiscoveryFailure, match="size"):
        parse_checksums(data, replace(checksum_source(data), size=1))
    with pytest.raises(DiscoveryFailure, match="UTF-8"):
        parse_checksums(b"\xff", checksum_source(b"\xff"))
    monkeypatch.setattr(discovery, "MAX_CHECKSUM_BYTES", 1)
    with pytest.raises(DiscoveryFailure, match="size"):
        parse_checksums(data, checksum_source(data))
    monkeypatch.setattr(discovery, "MAX_CHECKSUM_BYTES", 1024 * 1024)
    monkeypatch.setattr(discovery, "MAX_CHECKSUM_ENTRIES", 1)
    data += ("a" * 64 + "  second.deb\n").encode()
    with pytest.raises(DiscoveryFailure, match="Too many"):
        parse_checksums(data, checksum_source(data))


def test_verify_private_bytes_and_provenance(github: RecordedGitHub) -> None:
    source, checksum = package(scan(github))
    out = github.root / "verified.deb"
    verified = verify_asset(source, checksum, runtime=github, out=out)
    assert out.read_bytes() == b"current-deb"
    assert out.stat().st_mode & 0o777 == 0o600
    assert verified.sha256 == hashlib.sha256(out.read_bytes()).hexdigest()
    assert verified.checksum_asset_id == 202
    assert verified.checksum_sha256 == hashlib.sha256(github.bodies["v2/checksums.txt"]).hexdigest()
    assert not list((github.root / "downloads").iterdir())
    with pytest.raises(DiscoveryFailure, match="already exists"):
        verify_asset(source, checksum, runtime=github, out=out)
    assert out.read_bytes() == b"current-deb"


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "truncate",
        "oversize",
        "corrupt",
        "replace",
        "retag",
        "symlink",
        "partial-failure",
        "timeout",
    ],
)
def test_download_failure_is_not_verified(github: RecordedGitHub, fault: str) -> None:
    source, checksum = package(scan(github))
    github.download_fault = fault
    out = github.root / "verified"
    with pytest.raises((ValueError, RuntimeFailure)):
        verify_asset(source, checksum, runtime=github, out=out)
    assert not out.exists()
    assert not list((github.root / "downloads").iterdir())


def test_verification_guards_before_download(github: RecordedGitHub, tmp_path: Path) -> None:
    source, checksum = package(scan(github))
    github.calls.clear()
    for bad in (
        replace(checksum, filename="other.deb"),
        replace(checksum, source=replace(checksum.source, release_id=999)),
        replace(checksum, source=replace(checksum.source, repository="another/tool")),
    ):
        with pytest.raises(DiscoveryFailure):
            verify_asset(source, bad, runtime=github, out=github.root / "verified")
    with pytest.raises(ValueError):
        verify_asset(source, checksum, runtime=github, out=tmp_path / "escape")
    (github.root / "link").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        verify_asset(source, checksum, runtime=github, out=github.root / "link/escape")
    with pytest.raises(DiscoveryFailure, match="size limit"):
        verify_asset(
            replace(source, size=5 * 1024**3),
            checksum,
            runtime=github,
            out=github.root / "verified",
        )
    assert not github.calls


def test_literal_glob_filename_and_option_like_tag(github: RecordedGitHub) -> None:
    name = "app[1]*?.deb"
    github.update(201, name=name)
    github.update(20, tag_name="--option")
    github.bodies[f"--option/{name}"] = b"current-deb"
    body = f"{hashlib.sha256(b'current-deb').hexdigest()}  {name}\n".encode()
    github.body("--option/checksums.txt", body, 202)
    source, checksum = package(scan(github))
    verify_asset(source, checksum, runtime=github, out=github.root / "verified")
    command = next(call for call in reversed(github.calls) if call[1] == "release")
    assert command[command.index("--pattern") + 1] == r"app\[1\]\*\?.deb"
    assert command[-2:] == ("--", "--option")


def test_state_validation(github: RecordedGitHub) -> None:
    state = scan(github).state
    with pytest.raises(ValueError):
        replace(state, assets=state.assets + (state.assets[0],))
    with pytest.raises(ValueError):
        replace(state, records=state.records + (state.records[0],))
    with pytest.raises(ValueError):
        replace(state, sources=())
    with pytest.raises(ValueError):
        replace(state, assets=tuple(asset for asset in state.assets if asset.asset_id != 202))
