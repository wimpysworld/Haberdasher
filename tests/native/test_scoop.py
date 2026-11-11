"""Scoop publication to a local root, and a bucket clone over loopback dumb HTTP."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from haberdasher import publish, state
from haberdasher.config import Config, Policy, StoragePolicy
from haberdasher.runtime import private_workspace
from haberdasher.storage import LocalStore
from tests.native.test_brew import RELEASE, REPOSITORY, GitHub, git
from tests.support.http import serve
from tests.support.keys import disposable_key
from tests.unit.test_scoop import AMD64, ARM64, exe_zip, pe


def test_publish_serves_a_bucket_that_git_clones_over_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with disposable_key() as key, private_workspace() as fixtures:
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key.key_file))
        packed = exe_zip(("viewer-1.0.0/viewer.exe", pe(AMD64)), ("viewer-1.0.0/README", b"x"))
        github = GitHub(
            {
                "tool-windows-amd64.exe": pe(AMD64),
                "tool-windows-arm64.exe": pe(ARM64),
                "viewer-1.0.0-windows-x64.zip": packed,
                "Setup-1.0.0-win-x64.exe": pe(AMD64, tail=b"\xef\xbe\xad\xdeNullsoftInst"),
            }
        )
        root = fixtures.root / "store"
        storage = StoragePolicy("local", {"scoop": str(root / "public/scoop")})
        store = LocalStore(storage)
        bucket = Path(storage.public["scoop"])
        config = Config((REPOSITORY,))
        policy = Policy(storage, key.fingerprint)

        def reconcile(now: datetime) -> publish.RunResult:
            with private_workspace() as runtime:
                github.bind(runtime)
                return publish.reconcile(config, policy, store=store, runtime=runtime, now=now)

        result = reconcile(datetime(2026, 11, 11, tzinfo=UTC))
        assert result.packages == 3 and result.repositories == ("scoop",)
        assert (bucket / "tool/1.0.0/tool-windows-amd64.exe").read_bytes() == pe(AMD64)
        assert (bucket / "viewer/1.0.0/viewer-1.0.0-windows-x64.zip").read_bytes() == packed
        assert not (bucket / "setup").exists() and not (bucket / "keys").exists()
        assert {"index.html", "og.png", state.INVENTORY_KEY} <= {p.name for p in bucket.iterdir()}

        before = {path: path.read_bytes() for path in bucket.rglob("*") if path.is_file()}
        unchanged = reconcile(datetime(2026, 11, 12, tzinfo=UTC))
        assert not unchanged.changed
        assert {path: path.read_bytes() for path in bucket.rglob("*") if path.is_file()} == before

        clone = tmp_path / "clone"
        with serve(root / "public") as http:
            url = http.url("scoop/wimpysworld/haberdasher.git")
            git("ls-remote", url, cwd=tmp_path)
            git("clone", "--quiet", url, str(clone), cwd=tmp_path)
        assert git("log", "--format=%an <%ae>", cwd=clone) == "Haberdasher <code@wimpress.io>"
        assert sorted(path.name for path in (clone / "bucket").iterdir()) == [
            "tool.json",
            "viewer.json",
        ]
        for path in (clone / "bucket").iterdir():
            data = json.loads(path.read_text())
            assert {"version", "description", "homepage", "license", "architecture"} <= set(data)
            assert data["version"] == "1.0.0" and data["license"] == "Unknown"
            assert data["homepage"] == f"https://github.com/{REPOSITORY}"
        tool = json.loads((clone / "bucket/tool.json").read_text())
        assert tool["architecture"]["arm64"] == {
            "url": "https://scoop.wimpys.world/tool/1.0.0/tool-windows-arm64.exe",
            "hash": hashlib.sha256(pe(ARM64)).hexdigest(),
            "bin": [["tool-windows-arm64.exe", "tool"]],
        }
        viewer = json.loads((clone / "bucket/viewer.json").read_text())
        assert viewer["architecture"]["64bit"]["bin"] == [["viewer-1.0.0/viewer.exe", "viewer"]]
        assert "scoop bucket add haberdasher" in (clone / "README.md").read_text()

        github.contents["tool-windows-amd64.exe"] = pe(AMD64, tail=b"v2")
        github.contents["tool-windows-arm64.exe"] = pe(ARM64, tail=b"v2")
        github.contents["viewer-1.0.0-windows-x64.zip"] = packed
        RELEASE["tag_name"] = "v1.1.0"
        try:
            later = reconcile(datetime(2026, 11, 13, tzinfo=UTC))
        finally:
            RELEASE["tag_name"] = "v1.0.0"
        assert later.packages == 2
        with serve(root / "public") as http:
            url = http.url("scoop/wimpysworld/haberdasher.git")
            git("pull", "--quiet", "--ff-only", url, "main", cwd=clone)
        assert git("rev-list", "--count", "main", cwd=clone) == "2"
        assert json.loads((clone / "bucket/tool.json").read_text())["version"] == "1.1.0"
