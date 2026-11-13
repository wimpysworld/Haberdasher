from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from haberdasher.core import JSONValue, ObjectRef, RetainedFormat, atomic_write
from haberdasher.formats import nix
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import NIX_KEY_NAME, SigningSession

PUBLIC_KEY = f"{NIX_KEY_NAME}:{'A' * 43}="
FINGERPRINT = "A" * 40
TOOL = f"/nix/store/{'1' * 32}-tool-1.0.0"
OTHER = f"/nix/store/{'2' * 32}-other-2.0.0"
GLIBC = f"{'3' * 32}-glibc-2.40"
HELPER = f"{'4' * 32}-helper-1.0"

type Handler = Callable[[Sequence[str]], subprocess.CompletedProcess[bytes] | None]


def done(argv: Sequence[str], stdout: bytes = b"", code: int = 0, stderr: bytes = b""):
    return subprocess.CompletedProcess(list(argv), code, stdout, stderr)


def fake(runtime: Runtime, handler: Handler) -> list[list[str]]:
    """Answer each nix command from the handler, and record it."""
    calls: list[list[str]] = []
    real = runtime.run

    def run(argv: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if argv[0] != "nix":
            return real(argv, **kwargs)  # type: ignore[arg-type]
        calls.append(list(argv[3:]))
        if "builtins.currentSystem" in argv:
            return done(argv, b"x86_64-linux")
        result = handler(argv[3:])
        if result is None:
            raise AssertionError(f"Unexpected nix command: {argv}")
        return result

    runtime.run = run  # pyright: ignore[reportAttributeAccessIssue]
    return calls


def evaluation(
    platforms: list[str | None] | None = None, **packages: tuple[str, str, str]
) -> bytes:
    return json.dumps(
        {
            attribute: {
                "name": name,
                "version": version,
                "path": path,
                "description": " A  tool ",
                "platforms": platforms,
            }
            for attribute, (name, version, path) in packages.items()
        }
    ).encode()


def package(path: str = TOOL, tag: str = "v1.0.0", name: str = "tool") -> nix.Package:
    return nix.Package(
        "wimpysworld/tool",
        tag,
        f"github:wimpysworld/tool/{tag}",
        name,
        name,
        "1.0.0",
        "x86_64-linux",
        path,
        "A tool",
    )


def ref(key: str, data: bytes = b"x") -> ObjectRef:
    kind, content_type, mutable, _ = nix._classify(key)  # pyright: ignore[reportPrivateUsage]
    return ObjectRef(
        "nix",
        key,
        kind,
        len(data),
        hashlib.sha256(data).hexdigest(),
        content_type,
        "no-cache" if mutable else nix.IMMUTABLE,
    )


def retained(*items: nix.Package, extra: tuple[ObjectRef, ...] = ()) -> RetainedFormat:
    objects = (
        ref(nix.CACHE_INFO_KEY, nix.CACHE_INFO),
        ref(nix.PUBKEY_KEY, f"{PUBLIC_KEY}\n".encode()),
        *(ref(item.narinfo) for item in items),
        *extra,
    )
    metadata: dict[str, JSONValue] = {
        "public_key": PUBLIC_KEY,
        "fingerprint": FINGERPRINT,
        "packages": [item.record() for item in items],
    }
    return RetainedFormat("nix", (), tuple(item.identity for item in items), metadata, objects)


def test_pending_evaluates_new_tags_and_skips_sources_without_packages(tmp_path: Path) -> None:
    published = package(tag="v0.9.0")
    answers = {
        "github:wimpysworld/tool/v1.0.0#packages.x86_64-linux": done(
            [], evaluation(default=("tool", "1.0.0", OTHER), tool=("tool", "1.0.0", OTHER))
        ),
        "github:wimpysworld/new/v2.0.0#packages.x86_64-linux": done(
            [],
            evaluation(
                ["x86_64-linux", None],
                default=("other", "0.0.0-abc1234", OTHER),
                helper=("helper", "1.0", f"/nix/store/{HELPER}"),
            ),
        ),
        "github:wimpysworld/arm/v3#packages.x86_64-linux": done(
            [], evaluation(["aarch64-linux"], arm=("arm", "3", OTHER))
        ),
        "github:wimpysworld/empty/v1#packages.x86_64-linux": done([], b"{}"),
        "github:wimpysworld/bare/v1#packages.x86_64-linux": done(
            [], code=1, stderr=b"error: path '/nix/store/x-source/flake.nix' does not exist\n"
        ),
        "github:wimpysworld/linux/v1#packages.x86_64-linux": done(
            [], code=1, stderr=b"error: flake 'github:x' does not provide attribute 'packages'\n"
        ),
    }
    lines: list[str] = []
    with private_workspace(tmp_path) as runtime:
        calls = fake(runtime, lambda argv: answers.get(argv[2]))
        found = nix.pending(
            (
                ("wimpysworld/tool", "v0.9.0"),
                ("wimpysworld/tool", "v1.0.0"),
                ("wimpysworld/new", "v2.0.0"),
                ("wimpysworld/arm", "v3"),
                ("wimpysworld/empty", "v1"),
                ("wimpysworld/bare", "v1"),
                ("wimpysworld/linux", "v1"),
            ),
            retained(replace(published, path=TOOL)),
            runtime=runtime,
            report=lines.append,
        )
    assert [item.attribute for item in found] == ["default", "helper"]
    assert found[0].flake == "github:wimpysworld/new/v2.0.0" and found[0].description == "A tool"
    assert (found[0].version, found[0].derivation_version) == ("2.0.0", "0.0.0-abc1234")
    assert lines == [
        "nix   skipped wimpysworld/tool v1.0.0 tool: tool 1.0.0 is already published from "
        "another store path. Release a new version",
        "nix   skipped wimpysworld/arm v3 arm: meta.platforms excludes x86_64-linux",
        "nix   skipped wimpysworld/empty v1: no packages for x86_64-linux",
        "nix   skipped wimpysworld/bare v1: no flake",
        "nix   skipped wimpysworld/linux v1: no packages for x86_64-linux",
    ]
    assert not any("v0.9.0" in " ".join(call) for call in calls)


def test_pending_does_nothing_when_every_tag_is_published(tmp_path: Path) -> None:
    with private_workspace(tmp_path) as runtime:
        calls = fake(runtime, lambda argv: None)
        state = retained(package())
        assert nix.pending((("wimpysworld/tool", "v1.0.0"),), state, runtime=runtime) == []
    assert calls == []


def test_legacy_flake_repository_state_keeps_only_the_cache() -> None:
    narinfo = ref(f"{'5' * 32}.narinfo")
    legacy = RetainedFormat(
        "nix",
        (),
        (),
        {
            "head": "0" * 40,
            "files": {},
            "flake_lock": {},
            "public_key": PUBLIC_KEY,
            "fingerprint": FINGERPRINT,
            "rejected": ["0" * 64],
            "stale": ["packages.git/HEAD"],
        },
        (
            *retained().objects,
            narinfo,
            ObjectRef("nix", "packages.git/HEAD", "entry", 1, "0" * 64, "text/plain", "no-cache"),
        ),
    )
    current = nix.current(legacy)
    assert current.metadata == {
        "public_key": PUBLIC_KEY,
        "fingerprint": FINGERPRINT,
        "packages": [],
        "stale": [],
    }
    assert [item.key for item in current.objects] == [
        nix.CACHE_INFO_KEY,
        nix.PUBKEY_KEY,
        narinfo.key,
    ]
    nix.validate_retained(current)
    assert nix.current(current) is current


def test_validate_retained_rejects_incomplete_or_foreign_state() -> None:
    good = retained(package())
    nix.validate_retained(good)
    nix.validate_retained(RetainedFormat("nix", (), (), {}, ()))
    with pytest.raises(nix.NixFailure, match="no narinfo"):
        nix.validate_retained(replace(good, objects=good.objects[:2]))
    with pytest.raises(nix.NixFailure, match="nix-cache-info"):
        nix.validate_retained(replace(good, objects=(ref(nix.CACHE_INFO_KEY), *good.objects[1:])))
    with pytest.raises(nix.NixFailure, match="Unexpected public Nix object"):
        nix.validate_retained(replace(good, objects=(*good.objects, ref("nar/../x"))))
    with pytest.raises(nix.NixFailure, match="active identities"):
        nix.validate_retained(replace(good, active_identities=()))
    with pytest.raises(nix.NixFailure, match="schema version 1"):
        nix.validate_retained(
            replace(good, metadata={**good.metadata, "packages": [{"name": "tool"}]})
        )
    with pytest.raises(nix.NixFailure, match="store path"):
        package(path="/nix/store/short-tool")


@pytest.mark.parametrize(
    ("commits", "expected"),
    [
        ({"v1.0.0": "a" * 40, "latest": "a" * 40}, "github:wimpysworld/tool/latest"),
        ({"v1.0.0": "a" * 40, "latest": "b" * 40}, "github:wimpysworld/tool"),
        ({"v1.0.0": "a" * 40}, "github:wimpysworld/tool"),
    ],
    ids=["latest-at-release", "latest-elsewhere", "latest-missing"],
)
def test_flake_reference_follows_latest_only_at_the_release_commit(
    monkeypatch: pytest.MonkeyPatch, commits: dict[str, str], expected: str
) -> None:
    def tag_commit(repository: str, tag: str, runtime: object) -> str | None:
        assert repository == "wimpysworld/tool"
        return commits.get(tag)

    monkeypatch.setattr(nix.discovery, "tag_commit", tag_commit)
    releases = [("wimpysworld/tool", "v1.0.0"), ("wimpysworld/bare", "v1")]
    found = nix.references(releases, retained(package()), [], runtime=cast(Runtime, None))
    assert found == {"wimpysworld/tool": expected}
    recorded = nix.with_references(retained(package()), found)
    nix.validate_retained(recorded)
    assert nix.flake_references(recorded) == found
    assert nix.with_references(recorded, found) is recorded
    assert nix.with_references(retained(), found) == retained()


def test_validate_retained_rejects_a_foreign_flake_reference() -> None:
    good = retained(package())
    for value in ({"wimpysworld/tool": "github:other/tool"}, {"wimpysworld/other": "github:x"}):
        with pytest.raises(nix.NixFailure, match="flake reference"):
            nix.validate_retained(replace(good, metadata={**good.metadata, "references": value}))


class Signer:
    fingerprint = FINGERPRINT

    def __init__(self, root: Path) -> None:
        self.secret = root / "haberdasher.nix.sec"
        self.public = root / "haberdasher.nix.pub"
        atomic_write(self.secret, b"secret")
        atomic_write(self.public, f"{PUBLIC_KEY}\n".encode())

    def nix_key(self) -> tuple[Path, Path, str]:
        return self.secret, self.public, PUBLIC_KEY


def test_prepare_skips_failed_builds_and_uploads_only_own_store_paths(tmp_path: Path) -> None:
    def entry(signatures: list[str]) -> dict[str, JSONValue]:
        return {
            "narHash": f"sha256-{'A' * 43}=",
            "narSize": 128,
            "references": [GLIBC],
            "signatures": list[JSONValue](signatures),
        }

    copied: list[str] = []
    lines: list[str] = []

    def handler(argv: Sequence[str]) -> subprocess.CompletedProcess[bytes] | None:
        match argv[0]:
            case "build" if argv[-1].endswith(".broken"):
                return done(argv, code=1, stderr=b"error: hash mismatch\n")
            case "build":
                return done(argv, f"{TOOL}\n".encode())
            case "path-info":
                info = {
                    TOOL.removeprefix("/nix/store/"): entry([]),
                    HELPER: entry(["host-1:sig"]),
                    GLIBC: entry(["cache.nixos.org-1:sig"]),
                }
                return done(argv, json.dumps({"info": info}).encode())
            case "copy":
                cache = Path(argv[3].removeprefix("file://").split("?", 1)[0])
                assert (cache / f"{GLIBC[:32]}.narinfo").is_file()
                copied.extend(argv[4:])
                for path in argv[4:]:
                    name = path.removeprefix("/nix/store/")[:32]
                    atomic_write(cache / f"{name}.narinfo", f"StorePath: {path}\n".encode())
                    (cache / "nar").mkdir(exist_ok=True)
                    atomic_write(cache / "nar" / f"{(name * 2)[:52]}.nar.zst", name.encode())
                atomic_write(cache / "nix-cache-info", b"StoreDir: /nix/store\n")
                return done(argv)
            case "store":
                return done(argv)
            case _:
                return None

    with private_workspace(tmp_path) as runtime:
        fake(runtime, handler)
        signer = Signer(runtime.root)
        empty = RetainedFormat("nix", (), (), {}, ())
        broken = replace(package(), attribute="broken", path=OTHER)
        unchanged = nix.prepare(
            [broken],
            empty,
            runtime=runtime,
            signer=cast(SigningSession, signer),
            out=runtime.root / "first",
            report=lines.append,
        )
        assert unchanged.retained is empty and not unchanged.outputs
        prepared = nix.prepare(
            [broken, package()],
            empty,
            runtime=runtime,
            signer=cast(SigningSession, signer),
            out=runtime.root / "second",
            report=lines.append,
        )
        nix.validate_prepared(prepared)
    assert lines == ["nix   skipped wimpysworld/tool v1.0.0 broken: the build failed"] * 2
    assert sorted(copied) == [TOOL, f"/nix/store/{HELPER}"]
    keys = [output.ref.key for output in prepared.outputs]
    assert keys[-1] == nix.CACHE_INFO_KEY and keys[0].startswith("nar/")
    assert f"{GLIBC[:32]}.narinfo" not in keys
    assert prepared.retained.metadata["packages"] == [package().record()]
    assert prepared.retained.active_identities == (package().identity,)
