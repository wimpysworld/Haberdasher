import copy
import hashlib
import json
import re
import subprocess
from collections.abc import Callable, Iterator, Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast
from urllib.parse import unquote

import pytest

from haberdasher import discovery, publish
from haberdasher.config import Config
from haberdasher.core import SourceAsset, canonical_json
from haberdasher.discovery import (
    ChecksumEntry,
    CompleteScan,
    DiscoveryFailure,
    cosign_identity,
    parse_checksums,
    scan_releases,
    verify_asset,
)
from haberdasher.runtime import Runtime, RuntimeFailure

FIXTURES = Path(__file__).parents[1] / "fixtures/github"
CONFIG = Config(("example/tool",))
RELEASES = "repos/example/tool/releases"


class RecordedGitHub(Runtime):
    repository = "example/tool"

    def __init__(self, root: Path) -> None:
        super().__init__(root, environ={"PATH": ""})
        self.pages = cast(
            dict[str, list[dict[str, object]]], json.loads((FIXTURES / "pages.json").read_bytes())
        )
        bodies = cast(dict[str, str], json.loads((FIXTURES / "downloads.json").read_bytes()))
        self.bodies = {name: body.encode() for name, body in bodies.items()}
        self.latest: dict[str, int] = {self.repository: 20}
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
        progress: Callable[[str], None] | None = None,
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
            elif endpoint.endswith("/releases/latest"):
                repository = endpoint.removeprefix("repos/").removesuffix("/releases/latest")
                if repository not in self.latest:
                    body = b'{"message":"Not Found","status":"404"}'
                    return subprocess.CompletedProcess(argv, 1, body, b"gh: Not Found (HTTP 404)\n")
                data = canonical_json(next(self.rows(self.latest[repository])))
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
        assert argv[argv.index("--repo") + 1] == f"https://github.com/{self.repository}"
        assert argv[-2] == "--"
        pattern = argv[argv.index("--pattern") + 1]
        name = pattern.replace("\\", "")
        path = Path(argv[argv.index("--output") + 1])
        assert path.is_relative_to(self.root)
        assert path.parent.stat().st_mode & 0o777 == 0o700
        data = self.bodies[f"{argv[-1]}/{name}"]
        if self.download_fault == "transient":
            self.download_fault = None
            path.write_bytes(data[:1])
            return subprocess.CompletedProcess(argv, 1, b"", b"connection reset")
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


@pytest.fixture(autouse=True)
def no_retry_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    def sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("haberdasher.discovery.time.sleep", sleep)


@pytest.fixture
def github(tmp_path: Path) -> Iterator[RecordedGitHub]:
    runtime = RecordedGitHub(tmp_path / "runtime")
    try:
        yield runtime
    finally:
        runtime.close()


def scan(github: RecordedGitHub) -> CompleteScan:
    return scan_releases(CONFIG, runtime=github)


def package(scan: CompleteScan, identifier: int = 201) -> tuple[SourceAsset, ChecksumEntry]:
    record = next(record for record in scan.state.records if record.source.asset_id == identifier)
    assert record.checksum is not None
    return record.source, record.checksum


def test_only_the_latest_release_is_read(github: RecordedGitHub) -> None:
    lines: list[str] = []
    first = scan_releases(CONFIG, runtime=github, report=lines.append)
    assert {item.source.asset_id for item in first.checksummed} == {201}
    assert [item.source.asset_id for item in first.pending] == [203]
    assert {asset.asset_id for asset in first.state.assets} == {201, 202, 203}
    assert lines == [
        "example/tool: latest release v2",
        "  v2  checksums OK  no cosign bundle  2 packages, 1 without a checksum (skipped)",
    ]
    endpoints = [call[-1] for call in github.calls if call[1] == "api"]
    assert endpoints[0] == f"{RELEASES}/latest"
    assert f"{RELEASES}/20/assets?per_page=100&page=3" in endpoints
    assert not any(endpoint.startswith(f"{RELEASES}?") for endpoint in endpoints)
    assert not any(f"{RELEASES}/10" in endpoint for endpoint in endpoints)
    github.calls.clear()
    second = scan(github)
    assert second == first
    downloaded = [
        call[call.index("--pattern") + 1] for call in github.calls if call[1] == "release"
    ]
    assert downloaded == ["checksums.txt"]
    assert second.state.to_dict()["schema_version"] == 1


def test_older_unpublished_release_is_not_backfilled(github: RecordedGitHub) -> None:
    github.latest["example/tool"] = 10
    older = scan(github)
    assert {item.source.filename for item in older.checksummed} == {"old.deb"}
    github.latest["example/tool"] = 20
    latest = scan(github)
    assert "old.deb" not in {asset.filename for asset in latest.state.assets}
    assert {item.source.filename for item in latest.checksummed} == {"app.deb"}


def test_source_without_a_latest_release(github: RecordedGitHub) -> None:
    lines: list[str] = []
    result = scan_releases(
        Config(("example/second", "example/tool")), runtime=github, report=lines.append
    )
    assert lines[0] == "example/second: no latest release"
    assert lines[1] == "example/tool: latest release v2"
    assert {item.source.repository for item in result.state.records} == {"example/tool"}
    github.fail = f"{RELEASES}/latest"
    with pytest.raises(DiscoveryFailure, match="request failed"):
        scan(github)


@pytest.mark.parametrize("flag", ["draft", "prerelease"])
def test_latest_release_must_be_eligible(github: RecordedGitHub, flag: str) -> None:
    github.update(20, **{flag: True})
    with pytest.raises(DiscoveryFailure, match="draft or pre-release"):
        scan(github)


def test_late_checksum_and_package_upload(github: RecordedGitHub) -> None:
    first = scan(github)
    checksum = github.bodies["v2/checksums.txt"]
    checksum += f"{hashlib.sha256(b'later').hexdigest()}  late.rpm\n".encode()
    github.body("v2/checksums.txt", checksum, 202)
    late = scan(github)
    assert {record.source.asset_id for record in late.checksummed} == {201, 203}
    assert package(late)[1].checksum_sha256 != package(first)[1].checksum_sha256
    assert not late.pending
    added = copy.deepcopy(next(github.rows(203)))
    added.update(id=204, name="new.apk", size=3)
    github.pages[f"{RELEASES}/20/assets?per_page=100&page=2"].append(added)
    uploaded = scan(github)
    assert [record.source.asset_id for record in uploaded.pending] == [204]
    assert {record.source.asset_id for record in uploaded.checksummed} == {201, 203}


@pytest.mark.parametrize("change", ["id", "bytes", "timestamp", "extra-document"])
def test_checksum_provenance_keeps_the_package_checksum(
    github: RecordedGitHub, change: str
) -> None:
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
    second = scan(github)
    assert {record.source.asset_id for record in second.checksummed} == {201}
    assert second.state != first.state
    assert [record.checksum.sha256 for record in second.checksummed if record.checksum] == [
        record.checksum.sha256 for record in first.checksummed if record.checksum
    ]
    assert canonical_json(first.state) == before


def test_equal_size_backdated_bytes_are_detected_by_checksum(github: RecordedGitHub) -> None:
    data = b"replacement"
    assert len(data) == len(github.bodies["v2/app.deb"])
    github.bodies["v2/app.deb"] = data
    github.body("v2/checksums.txt", f"{hashlib.sha256(data).hexdigest()}  app.deb\n".encode(), 202)
    second = scan(github)
    assert len(second.checksummed) == 1
    source, checksum = package(second)
    verified = verify_asset(source, checksum, runtime=github, out=github.root / "verified")
    assert verified.local_path.read_bytes() == data


def test_disappeared_checksum_keeps_package_pending(github: RecordedGitHub) -> None:
    for page in github.pages.values():
        page[:] = [row for row in page if row["id"] != 202]
    second = scan(github)
    assert {item.source.asset_id for item in second.pending} == {201, 203}
    assert not second.checksummed


@pytest.mark.parametrize(
    "endpoint",
    [
        f"{RELEASES}/latest",
        f"{RELEASES}/20/assets?per_page=100&page=2",
        f"{RELEASES}/assets/202",
    ],
)
@pytest.mark.parametrize("mode", ["nonzero", "runtime"])
def test_failed_scan_leaves_no_downloads(github: RecordedGitHub, endpoint: str, mode: str) -> None:
    github.fail, github.failure_mode = endpoint, mode
    with pytest.raises((DiscoveryFailure, RuntimeFailure)):
        scan(github)
    downloads = github.root / "downloads"
    assert not downloads.exists() or not list(downloads.iterdir())


def test_second_source_failure_does_not_return_partial_scan(github: RecordedGitHub) -> None:
    github.latest["example/second"] = 20
    github.fail = "repos/example/second/releases/latest"
    with pytest.raises(DiscoveryFailure):
        scan_releases(Config(("example/tool", "example/second")), runtime=github)
    assert not any(call[1] == "release" for call in github.calls)


@pytest.mark.parametrize("kind", ["asset", "loop", "names"])
def test_conflicting_ids_names_and_pagination_loops(github: RecordedGitHub, kind: str) -> None:
    if kind == "asset":
        github.pages[f"{RELEASES}/20/assets?per_page=100&page=2"][0]["size"] = 12
    elif kind == "loop":
        github.pages[f"{RELEASES}/20/assets?per_page=100&page=2"] = copy.deepcopy(
            github.pages[f"{RELEASES}/20/assets?per_page=100&page=1"]
        )
    else:
        github.update(203, name="app.deb")
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


def add_checksum(github: RecordedGitHub, identifier: int, name: str, body: bytes) -> None:
    extra = copy.deepcopy(next(github.rows(202)))
    extra.update(id=identifier, name=name, size=len(body))
    github.pages[f"{RELEASES}/20/assets?per_page=100&page=2"].append(extra)
    github.bodies[f"v2/{name}"] = body


def test_agreeing_checksum_sources(github: RecordedGitHub) -> None:
    add_checksum(github, 204, "SHA256SUMS", github.bodies["v2/checksums.txt"])
    digest = github.bodies["v2/checksums.txt"].split()[0]
    add_checksum(github, 205, "app.deb.sha256", digest + b"\n")
    assert {item.source.asset_id for item in scan(github).checksummed} == {201}


def test_conflicting_checksum_sources(github: RecordedGitHub) -> None:
    add_checksum(github, 204, "app.deb.sha256", ("f" * 64 + "  app.deb\n").encode())
    with pytest.raises(DiscoveryFailure, match="disagree about app.deb"):
        scan(github)


def test_github_package_digest_must_match_checksum(github: RecordedGitHub) -> None:
    github.update(201, digest="sha256:" + "f" * 64)
    with pytest.raises(DiscoveryFailure, match="differs from GitHub"):
        scan(github)


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


def test_transient_download_failure_is_retried(github: RecordedGitHub) -> None:
    source, checksum = package(scan(github))
    github.download_fault = "transient"
    out = github.root / "verified.deb"
    verify_asset(source, checksum, runtime=github, out=out)
    assert out.read_bytes() == b"current-deb"
    downloads = [call for call in github.calls if call[1:3] == ("release", "download")]
    assert len(downloads) >= 2


def test_repeated_download_failure_names_the_attempts(github: RecordedGitHub) -> None:
    source, checksum = package(scan(github))
    github.download_fault = "partial-failure"
    with pytest.raises(DiscoveryFailure, match="after 3 attempts"):
        verify_asset(source, checksum, runtime=github, out=github.root / "verified")


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


class CosignGitHub(RecordedGitHub):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.cosign: list[tuple[tuple[str, ...], bytes, bytes]] = []
        self.signers = {
            tag: f"https://github.com/example/tool/.github/workflows/release.yml@refs/tags/{tag}"
            for tag in ("v1", "v2")
        }
        for release, checksum, identifier in ((20, "checksums.txt", 204), (10, "SHA256SUMS", 103)):
            tag = "v2" if release == 20 else "v1"
            row = copy.deepcopy(next(self.rows(202)))
            name = checksum + ".sigstore.json"
            body = f'{{"bundle":"{tag}"}}'.encode()
            row.update(id=identifier, name=name, size=len(body))
            self.pages[f"{RELEASES}/{release}/assets?per_page=100&page=1"].append(row)
            self.bodies[f"{tag}/{name}"] = body

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
        if argv[0] != "cosign":
            return super().run(argv, cwd=cwd, input=input, timeout=timeout, env_kind=env_kind)
        assert env_kind == "native" and cwd is None and input is None
        bundle = Path(argv[argv.index("--bundle") + 1])
        self.cosign.append((tuple(argv), bundle.read_bytes(), Path(argv[-1]).read_bytes()))
        signer = self.signers[json.loads(bundle.read_bytes())["bundle"]]
        pattern = argv[argv.index("--certificate-identity-regexp") + 1]
        status = 0 if re.search(pattern, signer) else 1
        return subprocess.CompletedProcess(argv, status, b"", b"")


@pytest.fixture
def signed(tmp_path: Path) -> Iterator[CosignGitHub]:
    runtime = CosignGitHub(tmp_path / "runtime")
    try:
        yield runtime
    finally:
        runtime.close()


def test_cosign_verifies_each_checksum_with_its_release_identity(signed: CosignGitHub) -> None:
    lines: list[str] = []
    result = scan_releases(CONFIG, runtime=signed, report=lines.append)
    assert {item.source.asset_id for item in result.checksummed} == {201}
    verified = {
        argv[argv.index("--certificate-identity-regexp") + 1]: (argv, bundle, blob)
        for argv, bundle, blob in signed.cosign
    }
    assert set(verified) == {cosign_identity("example/tool", "v2")}
    argv, bundle, blob = verified[cosign_identity("example/tool", "v2")]
    assert argv[:2] == ("cosign", "verify-blob")
    assert argv[argv.index("--certificate-oidc-issuer") + 1] == discovery.COSIGN_ISSUER
    assert bundle == b'{"bundle":"v2"}'
    assert blob == signed.bodies["v2/checksums.txt"]
    assert all("cosign OK" in line for line in lines[1:])
    assert not list((signed.root / "downloads").iterdir())


@pytest.mark.parametrize(
    "identity,matches",
    [
        ("https://github.com/example/tool/.github/workflows/release.yml@refs/tags/v1.0", True),
        ("https://github.com/example/tool/.github/workflows/builder.yml@refs/tags/v1.0", True),
        ("https://github.com/example/other/.github/workflows/release.yml@refs/tags/v1.0", False),
        ("https://github.com/attacker/tool/.github/workflows/release.yml@refs/tags/v1.0", False),
        ("https://github.com/example/tool/.github/workflows/release.yml@refs/tags/v1.01", False),
        ("https://github.com/example/tool/.github/workflows/release.yml@refs/tags/v1x0", False),
        ("https://github.com/example/tool/.github/workflows/release.yml@refs/heads/v1.0", False),
        ("https://github.com/example/tool/.github/workflows/a@b@refs/tags/v1.0", False),
        ("https://github.com/example/toolx/.github/workflows/release.yml@refs/tags/v1.0", False),
    ],
)
def test_cosign_identity_pins_repository_and_tag(identity: str, matches: bool) -> None:
    pattern = cosign_identity("example/tool", "v1.0")
    assert pattern.startswith("^") and pattern.endswith("$")
    assert (re.search(pattern, identity) is not None) is matches


def test_missing_cosign_bundle_is_allowed_and_shown(signed: CosignGitHub) -> None:
    for page in signed.pages.values():
        page[:] = [row for row in page if row["id"] != 204]
    lines: list[str] = []
    result = scan_releases(CONFIG, runtime=signed, report=lines.append)
    assert {item.source.asset_id for item in result.checksummed} == {201}
    assert "no cosign bundle" in lines[1]
    assert not signed.cosign


@pytest.mark.parametrize(
    "signer",
    [
        "https://github.com/example/other/.github/workflows/release.yml@refs/tags/v2",
        "https://github.com/example/tool/.github/workflows/release.yml@refs/tags/v1",
    ],
    ids=["wrong-repository", "wrong-tag"],
)
def test_failed_cosign_verification_fails_before_import(signed: CosignGitHub, signer: str) -> None:
    signed.signers["v2"] = signer
    with pytest.raises(DiscoveryFailure, match="does not verify for example/tool at tag v2"):
        scan_releases(CONFIG, runtime=signed)
    assert len(signed.cosign) == 1
    assert not list((signed.root / "downloads").iterdir())


OTHER = "repos/example/other/releases"


def asset_row(identifier: int, name: str, data: bytes, digest: bool = False) -> dict[str, object]:
    row: dict[str, object] = {
        "id": identifier,
        "name": name,
        "size": len(data),
        "state": "uploaded",
        "updated_at": "2026-03-01T00:00:00Z",
        "browser_download_url": f"https://github.com/example/other/releases/download/{name}",
    }
    if digest:
        row["digest"] = "sha256:" + hashlib.sha256(data).hexdigest()
    return row


class OtherLayout(RecordedGitHub):
    """A second project: no tag prefix, per-asset and SHA256SUMS checksums, no cosign bundles,
    architecture-independent packages, a Flatpak bundle, and releases without checksum files."""

    repository = "example/other"

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        packages = {
            "other_1.2.3_all.deb": b"deb-all",
            "other-1.2.3-1.noarch.rpm": b"rpm-noarch",
            "other-1.2.3-1-any.pkg.tar.xz": b"arch-any",
            "other-1.2.3-r0.apk": b"apk-noarch",
        }
        assets: dict[str, bytes] = {
            **packages,
            "other_1.2.3_linux.tar.gz": b"tarball",
            "other-linux-amd64": b"binary",
            "org.example.Other.flatpak": b"flatpak",
            "other_1.2.3_all.deb.sha256": hashlib.sha256(b"deb-all").hexdigest().encode() + b"\n",
            "other-1.2.3-1.noarch.rpm.sha256": (
                f"{hashlib.sha256(b'rpm-noarch').hexdigest()}  other-1.2.3-1.noarch.rpm\n"
            ).encode(),
            "SHA256SUMS": "".join(
                f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                for name, data in (
                    ("other-1.2.3-1-any.pkg.tar.xz", packages["other-1.2.3-1-any.pkg.tar.xz"]),
                    ("other-1.2.3-r0.apk", packages["other-1.2.3-r0.apk"]),
                    ("org.example.Other.flatpak", b"flatpak"),
                )
            ).encode(),
        }
        self.latest = {self.repository: 70}
        self.pages = {
            "releases": [
                {"id": 70, "tag_name": "1.2.3", "draft": False, "prerelease": False},
                {"id": 60, "tag_name": "1.2.2", "draft": False, "prerelease": False},
                {"id": 50, "tag_name": "1.2.1", "draft": False, "prerelease": False},
            ],
            f"{OTHER}/70/assets?per_page=100&page=1": [
                asset_row(700 + index, name, data)
                for index, (name, data) in enumerate(assets.items())
            ],
            f"{OTHER}/70/assets?per_page=100&page=2": [],
            f"{OTHER}/60/assets?per_page=100&page=1": [
                asset_row(600, "other_1.2.2_amd64.deb", b"no-checksum"),
                asset_row(601, "other-1.2.2-1.x86_64.rpm", b"no-checksum-rpm"),
            ],
            f"{OTHER}/60/assets?per_page=100&page=2": [],
            f"{OTHER}/50/assets?per_page=100&page=1": [
                asset_row(500, "other_1.2.1_arm64.deb", b"digest-only", digest=True),
            ],
            f"{OTHER}/50/assets?per_page=100&page=2": [],
        }
        self.bodies = {f"1.2.3/{name}": data for name, data in assets.items()}
        self.bodies["1.2.1/other_1.2.1_arm64.deb"] = b"digest-only"


def test_second_source_with_a_different_release_layout(tmp_path: Path) -> None:
    runtime = OtherLayout(tmp_path / "runtime")
    config = Config(("example/other",))
    lines: list[str] = []
    try:
        result = scan_releases(config, runtime=runtime, report=lines.append)
        checksummed = {item.source.filename: item for item in result.checksummed}
        assert set(checksummed) == {
            "other_1.2.3_all.deb",
            "other-1.2.3-1.noarch.rpm",
            "other-1.2.3-1-any.pkg.tar.xz",
            "other-1.2.3-r0.apk",
            "org.example.Other.flatpak",
        }
        assert not result.pending
        assert publish.provided(result) == {"apt", "rpm", "arch", "apk", "flatpak"}
        assert lines == [
            "example/other: latest release 1.2.3",
            "  1.2.3  checksums OK  no cosign bundle  5 packages",
        ]
        for item in checksummed.values():
            assert item.checksum is not None
            data = runtime.bodies[f"1.2.3/{item.source.filename}"]
            out = runtime.root / f"verified-{item.source.asset_id}"
            verified = verify_asset(item.source, item.checksum, runtime=runtime, out=out)
            assert verified.sha256 == hashlib.sha256(data).hexdigest()
        lines.clear()
        runtime.latest[runtime.repository] = 60
        result = scan_releases(config, runtime=runtime, report=lines.append)
        assert not result.checksummed
        assert {item.source.filename for item in result.pending} == {
            "other_1.2.2_amd64.deb",
            "other-1.2.2-1.x86_64.rpm",
        }
        assert lines[1] == (
            "  1.2.2  no checksums  no cosign bundle  2 packages, 2 without a checksum (skipped)"
        )
        lines.clear()
        runtime.latest[runtime.repository] = 50
        result = scan_releases(config, runtime=runtime, report=lines.append)
        assert lines[1] == "  1.2.1  GitHub digests OK  no cosign bundle  1 package"
        (digest_only,) = result.checksummed
        assert digest_only.checksum is not None
        assert digest_only.checksum.source == digest_only.source
        out = runtime.root / "verified-digest-only"
        verify_asset(digest_only.source, digest_only.checksum, runtime=runtime, out=out)
        assert out.read_bytes() == b"digest-only"
        assert not any(call[0] == "cosign" for call in runtime.calls)
    finally:
        runtime.close()


def test_digest_cross_checks_a_checksum_file(tmp_path: Path) -> None:
    runtime = OtherLayout(tmp_path / "runtime")
    try:
        for row in runtime.pages[f"{OTHER}/70/assets?per_page=100&page=1"]:
            if row["name"] == "other-1.2.3-r0.apk":
                row["digest"] = "sha256:" + "f" * 64
        with pytest.raises(DiscoveryFailure, match="differs from GitHub digest"):
            scan_releases(Config(("example/other",)), runtime=runtime)
    finally:
        runtime.close()


def test_bare_digest_needs_a_per_asset_checksum_file() -> None:
    data = ("a" * 64 + "\n").encode()
    source = replace(checksum_source(data), filename="app.deb.sha256")
    assert parse_checksums(data, source)[0].filename == "app.deb"
    with pytest.raises(DiscoveryFailure, match="Malformed"):
        parse_checksums(data, checksum_source(data))
