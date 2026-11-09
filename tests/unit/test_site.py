from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from haberdasher import site, state
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    JSONValue,
    NativeIdentity,
    ObjectRef,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
)

FINGERPRINT = "B39939A127C7A8D338F53A3AE132098A87DB88E0"
NOW = datetime(2026, 11, 9, 12, tzinfo=UTC)


def asset(
    name: str,
    package: str,
    architecture: str,
    version: str,
    metadata: dict[str, JSONValue],
    *,
    repository: str = "wimpysworld/tool",
    release: int = 1,
    evidence: dict[str, JSONValue] | None = None,
) -> AdmittedAsset:
    source = SourceAsset(
        repository,
        release,
        release * 100 + len(architecture),
        f"{package.replace('/', '-')}-{version}-{architecture}.bin",
        1,
        "2026-01-01T00:00:00Z",
        "https://example.invalid/asset",
    )
    verified = VerifiedAsset(source, Path("unavailable"), "a" * 64, 1, 2, "b" * 64)
    identity = NativeIdentity(name, package, architecture, version)
    inspected = InspectedAsset(verified, identity, metadata, evidence or {}, "unsigned")
    return AdmittedAsset(inspected, "preserve", f"{package}-{architecture}-{version}")


def ref(name: str, key: str, size: int) -> ObjectRef:
    return ObjectRef(name, key, "package", size, "c" * 64, "application/octet-stream", "no-cache")


def published(
    name: str, history: tuple[AdmittedAsset, ...], objects: tuple[ObjectRef, ...] = ()
) -> state.Published:
    retained = RetainedFormat(name, history, (), {}, objects)
    return state.Published(name, None, "d" * 64, objects, retained, None, b"x" * 1500)


def apt(description: str, version: str = "1.0", release: int = 1) -> tuple[AdmittedAsset, ...]:
    record = f"Package: tool\nVersion: {version}\nDescription: {description}\n More text.\n"
    return tuple(
        asset("apt", "tool", arch, version, {"record": record}, release=release)
        for arch in ("amd64", "arm64")
    )


def test_page_escapes_every_package_value() -> None:
    hostile = '<script>alert("x")</script> & more'
    item = published("apt", apt(hostile), (ref("apt", 'pool/a "b"/<c>.deb', 10),))
    page = site.page("apt", item, fingerprint=FINGERPRINT, fallback={}, now=NOW)[0].decode()
    assert "<script>alert" not in page
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; more" in page
    assert 'href="pool/a%20%22b%22/%3Cc%3E.deb"' in page
    assert "&lt;c&gt;.deb" in page


def test_tree_nests_directories_and_folds_flatpak_objects() -> None:
    objects = (
        ref("flatpak", "objects/ab/one.filez", 1_500_000),
        ref("flatpak", "objects/cd/two.dirtree", 500_000),
        ref("flatpak", "refs/heads/app/world.wimpys.tool/x86_64/stable", 65),
        ref("flatpak", "summary", 900),
    )
    tree = site.tree("flatpak", objects, 1500)
    assert '<li><span class="folder">objects/</span> 2 files (2 MB)</li>' in tree
    assert "one.filez" not in tree
    assert "<summary>refs/ <small>1 file (65 B)</small></summary>" in tree
    assert 'href="refs/heads/app/world.wimpys.tool/x86_64/stable"' in tree
    assert '<a href="summary">summary</a> <small>900 B</small>' in tree
    assert '<a href="haberdasher.json">haberdasher.json</a> <small>2 KB</small>' in tree
    apt_tree = site.tree("apt", (ref("apt", "objects/a", 1),), 1)
    assert "<summary>objects/ <small>1 file (1 B)</small></summary>" in apt_tree


def test_projects_show_the_newest_release_with_its_architectures_and_command() -> None:
    history = (*apt("Old text", "1.0", 1), *apt("New text", "2.0", 2))
    other = asset(
        "apt", "helper", "all", "3.0", {"record": "Package: helper\n"}, repository="w/Helper"
    )
    entries = site.projects((*history, other), {"w/Helper": "From another format"})
    assert [(p.repository, p.description, p.packages) for p in entries] == [
        ("w/Helper", "From another format", (("helper", "3.0", ("all",)),)),
        ("wimpysworld/tool", "New text", (("tool", "2.0", ("amd64", "arm64")),)),
    ]
    page = site.page(
        "apt", published("apt", (*history, other)), fingerprint=FINGERPRINT, fallback={}, now=NOW
    )[0].decode()
    assert "<code>sudo apt-get install tool</code>" in page
    assert '<a href="https://github.com/wimpysworld/tool">wimpysworld/tool on GitHub</a>' in page


def test_descriptions_come_from_native_metadata() -> None:
    rpm = asset(
        "rpm",
        "tool",
        "x86_64",
        "1",
        {"header_xml": '<rpmTag name="Summary">\n\t<string>A &amp; B</string>'},
    )
    arch = asset("arch", "tool", "x86_64", "1-1", {"desc": "%NAME%\ntool\n\n%DESC%\nArch text\n"})
    apk = asset("apk", "tool", "x86_64", "1", {"stanza": "P:tool\nT:Alpine text\n"})
    flatpak = asset(
        "flatpak", "app/world.wimpys.tool/x86_64/stable", "x86_64", "1", {"summary": "Flat"}
    )
    assert [site.description(item) for item in (rpm, arch, apk, flatpak)] == [
        "A & B",
        "Arch text",
        "Alpine text",
        "Flat",
    ]
    assert site.description(apt("APT text")[0]) == "APT text"
    entries = site.projects((flatpak,), {})
    assert entries[0].packages == (("world.wimpys.tool", "1", ("x86_64",)),)
    commands = site.install("flatpak", ["world.wimpys.tool"])
    assert commands == [("", "flatpak --user install wimpysworld world.wimpys.tool")]


def test_content_hash_ignores_only_the_publication_date() -> None:
    item = published("rpm", ())
    first, digest = site.page("rpm", item, fingerprint=FINGERPRINT, fallback={}, now=NOW)
    later, same = site.page(
        "rpm", item, fingerprint=FINGERPRINT, fallback={}, now=datetime(2027, 1, 2, tzinfo=UTC)
    )
    assert digest == same and first != later
    assert site.content_hash(first) == digest
    assert '<time datetime="2026-11-09">9 November 2026</time>' in first.decode()
    changed = site.page("rpm", item, fingerprint="A" * 40, fallback={}, now=NOW)[1]
    assert changed != digest
    assert site.content_hash(b"<html></html>") is None and site.content_hash(None) is None


def test_every_format_loads_pinned_assets_with_integrity() -> None:
    for name, theme in site.THEMES.items():
        page = site.page(name, published(name, ()), fingerprint=FINGERPRINT, fallback={}, now=NOW)[
            0
        ].decode()
        links = re.findall(r'<link rel="stylesheet" href="([^"]+)" integrity="([^"]+)"', page)
        assert [url for url, _ in links] == [
            f"https://cdn.jsdelivr.net/npm/{path}" for path in theme.styles
        ]
        assert all(re.search(r"@\d+\.\d+\.\d+/", url) for url, _ in links)
        assert all(value.startswith("sha384-") for _, value in links)
        assert all(
            re.fullmatch(
                r"https://cdn\.jsdelivr\.net/npm/simple-icons@\d+\.\d+\.\d+/icons/\w+\.svg", url
            )
            for url in re.findall(r'<img src="([^"]+)"', page)
        )
        assert f"<title>Wimpy&#x27;s World {theme.label} repository</title>" in page
        assert "fonts.googleapis" not in page
    assert site.ref("apt", b"page").cache_control == "public, max-age=300"
