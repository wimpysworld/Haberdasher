"""Flake packages in a signed HTTP binary cache, with loopback clients that only substitute."""

from __future__ import annotations

import html
import json
import re
import shutil
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from haberdasher import discovery, publish, site, state
from haberdasher.config import Config, Policy, StoragePolicy
from haberdasher.core import atomic_write
from haberdasher.formats import nix
from haberdasher.runtime import private_workspace
from haberdasher.signing import NIX_KEY_NAME, signing_session
from haberdasher.storage import LocalStore
from tests.native.fixtures.nix import NixClient, empty_flake, flake
from tests.support.http import serve
from tests.support.keys import disposable_key, run

NOW = datetime(2026, 11, 13, tzinfo=UTC)
TOOL = "wimpysworld/hd-tool"
SOURCES = (TOOL, "wimpysworld/bare", "wimpysworld/empty")
UNTRUSTED = "not signed by any of the keys in 'trusted-public-keys'"


def scan(tool_tag: str) -> discovery.CompleteScan:
    releases = ((TOOL, tool_tag), ("wimpysworld/bare", "v1"), ("wimpysworld/empty", "v1"))
    return discovery.CompleteScan(discovery.DiscoveryState(sources=SOURCES), (), (), releases)


def narinfo(bucket: Path, path: str) -> Path:
    return bucket / nix.Package(TOOL, "t", "f", "a", "n", "v", "s", path).narinfo


def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        item.relative_to(root).as_posix(): (item.read_bytes(), item.stat().st_mtime_ns)
        for item in sorted(root.rglob("*"))
        if item.is_file()
    }


def test_flake_packages_substitute_from_the_signed_cache_and_reruns_do_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with private_workspace() as fixtures, disposable_key() as key, disposable_key() as wrong:
        print(run(fixtures, "nix", "--version").decode().strip())
        root = fixtures.root
        bare = root / "bare"
        bare.mkdir()
        flakes = {
            (TOOL, "v1.0.0"): flake(
                root / "tool-v1", "hd-tool", "1.0.0", "hd-tool-v1", broken="hd-broken"
            ),
            (TOOL, "v2.0.0"): flake(root / "tool-v2", "hd-tool", "0.0.0-abc1234", "hd-tool-v2"),
            ("wimpysworld/bare", "v1"): bare,
            ("wimpysworld/empty", "v1"): empty_flake(root / "empty"),
        }

        def local(repository: str, tag: str) -> str:
            return f"path:{flakes[(repository, tag)]}"

        monkeypatch.setattr(nix, "flake_ref", local)
        moved = {"latest": True}

        def flake_input(repository: str, tag: str, runtime: object) -> str:
            return f"github:{repository}/latest" if moved["latest"] else f"github:{repository}"

        monkeypatch.setattr(nix, "flake_input", flake_input)
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key.key_file))
        storage = StoragePolicy("local", {"nix": str(root / "public/nix")})
        bucket = Path(storage.public["nix"])
        store = LocalStore(storage)
        config = Config(SOURCES)
        policy = Policy(storage, expected_signing_fingerprint=key.fingerprint)

        def reconcile(tag: str) -> tuple[publish.RunResult, list[str], list[list[str]]]:
            lines: list[str] = []
            calls: list[list[str]] = []
            with private_workspace() as runtime:
                real = runtime.run

                def recorded(
                    argv: Sequence[str], **kwargs: object
                ) -> subprocess.CompletedProcess[bytes]:
                    calls.append(list(argv))
                    return real(argv, **kwargs)  # type: ignore[arg-type]

                runtime.run = recorded  # pyright: ignore[reportAttributeAccessIssue]
                result = publish.reconcile(
                    config,
                    policy,
                    store=store,
                    runtime=runtime,
                    now=NOW,
                    report=lines.append,
                    scan=scan(tag),
                )
            return result, lines, calls

        # 1. Publish the named package once, and skip a failed build and sources without packages.
        first, lines, _ = reconcile("v1.0.0")
        assert first.changed and first.packages == 1
        for line in (
            "nix   skipped wimpysworld/bare v1: no flake",
            "nix   skipped wimpysworld/empty v1: no packages for x86_64-linux",
            "nix   skipped wimpysworld/hd-tool v1.0.0 hd-broken: the build failed",
        ):
            assert line in lines
        published = state.read(store, "nix")
        [tool_v1] = nix.published(published.retained)
        assert (tool_v1.attribute, tool_v1.name, tool_v1.version) == ("hd-tool", "hd-tool", "1.0.0")
        assert tool_v1.tag == "v1.0.0" and tool_v1.flake == f"path:{flakes[(TOOL, 'v1.0.0')]}"
        assert (bucket / nix.CACHE_INFO_KEY).read_bytes() == nix.CACHE_INFO
        nix_pub = (bucket / nix.PUBKEY_KEY).read_text(encoding="ascii").strip()
        assert nix_pub.startswith(f"{NIX_KEY_NAME}:")
        assert re.search(rf"^Sig: {NIX_KEY_NAME}:", narinfo(bucket, tool_v1.path).read_text(), re.M)
        inventory = (bucket / state.INVENTORY_KEY).read_text()
        assert "packages.git" not in inventory and json.loads(inventory)["assets"] == []
        page = html.unescape(re.sub(r"<[^>]+>", "", (bucket / site.PAGE_KEY).read_text()))
        assert f"nix profile add github:{TOOL}/latest#hd-tool" in page

        # 2. An unchanged rerun evaluates no published tag, builds nothing, and writes nothing.
        before = snapshot(bucket)
        rerun, _, calls = reconcile("v1.0.0")
        assert not rerun.changed and rerun.published_objects == 0
        assert snapshot(bucket) == before
        assert not any(str(flakes[(TOOL, "v1.0.0")]) in " ".join(call) for call in calls)
        assert not any("build" in call for call in calls)

        # 3. A moved latest tag rewrites only the inventory and the page.
        moved["latest"] = False
        retag, _, calls = reconcile("v1.0.0")
        assert retag.changed and retag.packages == 0
        assert not any("build" in call for call in calls)
        changed = {key for key, value in snapshot(bucket).items() if before.get(key) != value}
        assert changed == {state.INVENTORY_KEY, site.PAGE_KEY}
        page = html.unescape(re.sub(r"<[^>]+>", "", (bucket / site.PAGE_KEY).read_text()))
        assert f"nix profile add github:{TOOL}#hd-tool" in page
        assert "the default branch matches the release" in page

        # 4. A new release tag adds its package and keeps the earlier one.
        second, _, _ = reconcile("v2.0.0")
        assert second.changed and second.packages == 1
        tool_v2 = nix.published(state.read(store, "nix").retained)[-1]
        assert (tool_v2.version, tool_v2.tag) == ("2.0.0", "v2.0.0")
        assert tool_v2.derivation_version == "0.0.0-abc1234"

        with serve(root / "public") as http:
            client = NixClient(fixtures, "trusted", http.url("nix"), nix_pub)
            client.substitute_and_run(tool_v1.path, "hd-tool", "hd-tool-v1")
            client.substitute_and_run(tool_v2.path, "hd-tool", "hd-tool-v2")
            requests = http.requests()
            for suffix in ("/nix/nix-cache-info", ".narinfo", ".nar.zst"):
                assert any(
                    item.path.endswith(suffix) and item.status == 200 and item.bytes_sent > 0
                    for item in requests
                )

            # 5. A client without the key, or with another key, rejects every narinfo.
            with signing_session(
                fixtures, expected_fingerprint=wrong.fingerprint, key_file=wrong.key_file
            ) as other:
                wrong_pub = other.nix_key()[2]
            for name, trusted in (("missing-key", ""), ("wrong-key", wrong_pub)):
                denied = NixClient(fixtures, name, http.url("nix"), trusted)
                result = denied.run_nix("build", "--no-link", tool_v2.path, check=False)
                assert result.returncode != 0 and UNTRUSTED in result.stderr.decode()
                assert not denied.real_store_path(tool_v2.path).exists()

        # 6. Unsigned, re-signed, resized, and corrupted cache objects fail closed.
        for kind in ("unsigned", "sig", "narsize", "nar"):
            bad = root / f"bad-{kind}"
            shutil.copytree(bucket, bad / "nix")
            info = narinfo(bad / "nix", tool_v2.path)
            body = info.read_text(encoding="utf-8")
            if kind == "unsigned":
                info.write_text(re.sub(r"^Sig: .*\n", "", body, flags=re.M), encoding="utf-8")
            elif kind == "sig":
                forged = f"Sig: {NIX_KEY_NAME}:{'A' * 86}=="
                info.write_text(re.sub(r"^Sig: .*$", forged, body, flags=re.M), encoding="utf-8")
            elif kind == "narsize":
                size = int(re.findall(r"^NarSize: (\d+)$", body, re.M)[0]) + 1
                info.write_text(
                    re.sub(r"^NarSize: \d+$", f"NarSize: {size}", body, flags=re.M),
                    encoding="utf-8",
                )
            else:
                nar = bad / "nix" / re.findall(r"^URL: (.+)$", body, re.M)[0]
                data = bytearray(nar.read_bytes())
                data[-1] ^= 0xFF
                atomic_write(nar, bytes(data))
            with serve(bad) as bad_http:
                client = NixClient(fixtures, f"bad-{kind}", bad_http.url("nix"), nix_pub)
                result = client.run_nix("build", "--no-link", tool_v2.path, check=False)
                assert result.returncode != 0
                stderr = result.stderr.decode(errors="replace")
                if kind == "nar":
                    assert "Failed to open archive" in stderr
                else:
                    assert UNTRUSTED in stderr
                assert not client.real_store_path(tool_v2.path).exists()
