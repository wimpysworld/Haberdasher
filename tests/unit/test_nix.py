from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from haberdasher import site
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


def releases(*items: tuple[str, str]) -> list[nix.Target]:
    return [nix.Target(repo, tag, f"github:{repo}/{tag}", False) for repo, tag in items]


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
            releases(
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
        assert nix.pending(releases(("wimpysworld/tool", "v1.0.0")), state, runtime=runtime) == []
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


RELEASE = "a" * 40
CHILD = "b" * 40


@pytest.mark.parametrize(
    ("latest", "status", "flake", "reference"),
    [
        (RELEASE, "identical", "github:wimpysworld/tool/v1.0.0", "github:wimpysworld/tool/latest"),
        (CHILD, "ahead", f"github:wimpysworld/tool/{CHILD}", "github:wimpysworld/tool/latest"),
        (CHILD, "behind", "github:wimpysworld/tool/v1.0.0", "github:wimpysworld/tool"),
        (CHILD, "diverged", "github:wimpysworld/tool/v1.0.0", "github:wimpysworld/tool"),
        (None, None, "github:wimpysworld/tool/v1.0.0", "github:wimpysworld/tool"),
    ],
    ids=["latest-identical", "latest-ahead", "latest-behind", "latest-diverged", "latest-missing"],
)
def test_target_builds_latest_at_or_after_the_release_and_the_page_follows_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    latest: str | None,
    status: str | None,
    flake: str,
    reference: str,
) -> None:
    compared: list[tuple[str, str]] = []

    def tag_commit(repository: str, tag: str, runtime: object) -> str | None:
        assert (repository, tag) == ("wimpysworld/tool", "latest")
        return latest

    def compare_status(repository: str, base: str, head: str, runtime: object) -> str:
        compared.append((base, head))
        assert status is not None
        return status

    monkeypatch.setattr(nix.discovery, "tag_commit", tag_commit)
    monkeypatch.setattr(nix.discovery, "compare_status", compare_status)
    found = nix.targets([("wimpysworld/tool", "v1.0.0")], runtime=cast(Runtime, None))
    assert found == [nix.Target("wimpysworld/tool", "v1.0.0", flake, reference.endswith("/latest"))]
    assert compared == ([] if latest is None else [("v1.0.0", latest)])

    with private_workspace(tmp_path) as runtime:
        calls = fake(
            runtime,
            lambda argv: (
                done(argv, evaluation(tool=("tool", "1.0.0", TOOL)))
                if argv[2] == f"{flake}#packages.x86_64-linux"
                else None
            ),
        )
        [built] = nix.pending(found, retained(), runtime=runtime)
        assert (built.flake, built.version, built.tag) == (flake, "1.0.0", "v1.0.0")
        assert nix.pending(found, retained(built), runtime=runtime) == []
    assert len(calls) == 2

    recorded = nix.with_references(retained(built), found)
    nix.validate_retained(recorded)
    assert nix.flake_references(recorded) == {"wimpysworld/tool": reference}
    assert site.nix_projects(recorded, {})[0].flake == reference
    assert nix.with_references(recorded, found) is recorded
    assert nix.with_references(retained(), found) == retained()


def test_page_follows_latest_only_when_the_release_is_built_from_its_commit() -> None:
    ahead = nix.Target("wimpysworld/tool", "v1.0.0", f"github:wimpysworld/tool/{CHILD}", True)
    older = package()
    references = nix.flake_references(nix.with_references(retained(older), [ahead]))
    assert references == {"wimpysworld/tool": "github:wimpysworld/tool"}


def test_a_moved_latest_tag_replaces_the_package_of_the_same_release(tmp_path: Path) -> None:
    old = replace(package(), flake=f"github:wimpysworld/tool/{RELEASE}")
    moved = [nix.Target("wimpysworld/tool", "v1.0.0", f"github:wimpysworld/tool/{CHILD}", True)]
    lines: list[str] = []
    with private_workspace(tmp_path) as runtime:
        for path in (OTHER, TOOL):
            fake(
                runtime, lambda argv, path=path: done(argv, evaluation(tool=("tool", "1.0", path)))
            )
            [found] = nix.pending(moved, retained(old), runtime=runtime)
            assert (found.flake, found.path) == (moved[0].flake, path)
        calls = fake(runtime, lambda argv: None)
        state = retained(old)
        prepared = nix.prepare(
            [found],
            state,
            runtime=runtime,
            signer=cast(SigningSession, Signer(runtime.root)),
            out=runtime.root / "out",
            report=lines.append,
        )
    assert calls == [] and lines == [] and not prepared.outputs
    assert prepared.retained.metadata["packages"] == [found.record()]
    assert set(prepared.retained.objects) == set(state.objects)


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
