"""Homebrew publication to a local root, a tap clone over loopback dumb HTTP, and Ruby syntax."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from haberdasher import publish, state
from haberdasher.config import Config, Policy, StoragePolicy
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.storage import LocalStore
from tests.support.http import serve
from tests.support.keys import disposable_key
from tests.unit.test_brew import ARM, INTEL, app_zip, thin

REPOSITORY = "wimpysworld/fixture"
RELEASE: dict[str, object] = {"id": 1, "draft": False, "prerelease": False, "tag_name": "v1.0.0"}


class GitHub:
    """Answer the gh requests of one latest release, and run every other command natively."""

    def __init__(self, contents: dict[str, bytes]) -> None:
        self.contents = contents
        self.downloads: list[str] = []

    def rows(self) -> list[dict[str, object]]:
        files = dict(self.contents)
        files["checksums.txt"] = "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in self.contents.items()
        ).encode()
        return [
            {
                "id": index,
                "name": name,
                "size": len(data),
                "state": "uploaded",
                "updated_at": "2026-01-01T00:00:00Z",
                "browser_download_url": f"https://example.invalid/{name}",
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                "data": data.hex(),
            }
            for index, (name, data) in enumerate(files.items(), 1)
        ]

    def bind(self, runtime: Runtime) -> None:
        native: Callable[..., subprocess.CompletedProcess[bytes]] = runtime.run

        def run(argv: Sequence[str], **options: object) -> subprocess.CompletedProcess[bytes]:
            if argv[0] != "gh":
                return native(argv, **options)
            rows = self.rows()
            if argv[1:3] == ["release", "download"]:
                name = argv[argv.index("--pattern") + 1]
                self.downloads.append(name)
                row = next(row for row in rows if row["name"] == name)
                Path(argv[argv.index("--output") + 1]).write_bytes(bytes.fromhex(str(row["data"])))
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            endpoint = argv[-1]
            public = [{k: v for k, v in row.items() if k != "data"} for row in rows]
            value: object
            if endpoint == f"repos/{REPOSITORY}":
                value = {"description": "A fixture tool", "html_url": "https://github.invalid"}
            elif "/assets?" in endpoint:
                value = [] if endpoint.endswith("page=2") else public
            elif "/assets/" in endpoint:
                value = next(row for row in public if row["id"] == int(endpoint.rsplit("/", 1)[1]))
            else:
                value = RELEASE
            return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")

        runtime.run = run  # pyright: ignore[reportAttributeAccessIssue]


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def test_publish_serves_a_tap_that_git_clones_over_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with disposable_key() as key, private_workspace() as fixtures:
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key.key_file))
        app = app_zip(fixtures.root / "app.zip", header=thin(ARM)).read_bytes()
        github = GitHub(
            {
                "tool-darwin-arm64": thin(ARM),
                "tool-darwin-amd64": thin(INTEL),
                "tool-linux-amd64": b"\x7fELF" + bytes(60),
                "Sidra-1.0.0-mac-arm64.zip": app,
            }
        )
        root = fixtures.root / "store"
        storage = StoragePolicy("local", {"brew": str(root / "public/brew")})
        store = LocalStore(storage)
        bucket = Path(storage.public["brew"])
        config = Config((REPOSITORY,))
        policy = Policy(storage, key.fingerprint)

        def reconcile(now: datetime) -> publish.RunResult:
            with private_workspace() as runtime:
                github.bind(runtime)
                return publish.reconcile(config, policy, store=store, runtime=runtime, now=now)

        result = reconcile(datetime(2026, 11, 11, tzinfo=UTC))
        assert result.packages == 3 and result.repositories == ("brew",)
        assert "tool-linux-amd64" not in github.downloads
        assert (bucket / "tool/1.0.0/tool-darwin-arm64").read_bytes() == thin(ARM)
        assert (bucket / "sidra/1.0.0/Sidra-1.0.0-mac-arm64.zip").read_bytes() == app
        assert not (bucket / "keys").exists()
        assert {"index.html", "og.png", "logo.svg", state.INVENTORY_KEY} <= {
            p.name for p in bucket.iterdir()
        }

        before = {path: path.read_bytes() for path in bucket.rglob("*") if path.is_file()}
        unchanged = reconcile(datetime(2026, 11, 12, tzinfo=UTC))
        assert not unchanged.changed
        assert {path: path.read_bytes() for path in bucket.rglob("*") if path.is_file()} == before

        clone = tmp_path / "clone"
        with serve(root / "public") as http:
            git("clone", "--quiet", http.url("brew/tap.git"), str(clone), cwd=tmp_path)
        assert git("log", "--format=%an <%ae>", cwd=clone) == "Wimpy's World <code@wimpress.io>"
        assert git("rev-parse", "--abbrev-ref", "HEAD", cwd=clone) == "main"
        casks = sorted(path.name for path in (clone / "Casks").iterdir())
        assert casks == ["sidra.rb", "tool.rb"]
        tool = (clone / "Casks/tool.rb").read_text()
        assert '    url "https://brew.wimpys.world/tool/1.0.0/tool-darwin-arm64"\n' in tool
        assert '  desc "A fixture tool"\n' in tool and "depends_on" not in tool
        sidra = (clone / "Casks/sidra.rb").read_text()
        assert '  app "Sidra.app"\n' in sidra and "  depends_on arch: :arm64\n" in sidra
        assert "brew tap wimpysworld/tap" in (clone / "README.md").read_text()
        ruby = shutil.which("ruby")
        assert ruby is not None
        for path in (clone / "Casks").iterdir():
            subprocess.run([ruby, "-c", str(path)], check=True, capture_output=True)

        github.contents["tool-darwin-arm64"] = thin(ARM) + b"v2"
        github.contents["tool-darwin-amd64"] = thin(INTEL) + b"v2"
        RELEASE["tag_name"] = "v1.1.0"
        try:
            later = reconcile(datetime(2026, 11, 13, tzinfo=UTC))
        finally:
            RELEASE["tag_name"] = "v1.0.0"
        assert later.packages == 2
        assert (bucket / "tool/1.0.0/tool-darwin-arm64").read_bytes() == thin(ARM)
        with serve(root / "public") as http:
            git("pull", "--quiet", "--ff-only", http.url("brew/tap.git"), "main", cwd=clone)
        assert git("rev-list", "--count", "main", cwd=clone) == "2"
        tool = (clone / "Casks/tool.rb").read_text()
        assert '  version "1.1.0"\n' in tool and "on_intel" in tool
        assert '    url "https://brew.wimpys.world/tool/1.1.0/tool-darwin-amd64"\n' in tool
