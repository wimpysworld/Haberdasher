from __future__ import annotations

import html
import re
import struct
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

from haberdasher import site, state
from haberdasher.config import PUBLIC
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
    return state.Published(name, None, "d" * 64, objects, retained, None)


def apt(
    description: str,
    version: str = "1.0",
    release: int = 1,
    *,
    package: str = "tool",
    repository: str = "wimpysworld/tool",
    name: str = "apt",
) -> tuple[AdmittedAsset, ...]:
    record = f"Package: {package}\nVersion: {version}\nDescription: {description}\n More text.\n"
    return tuple(
        asset(
            name,
            package,
            arch,
            version,
            {"record": record},
            release=release,
            repository=repository,
        )
        for arch in ("amd64", "arm64")
    )


def render(name: str, item: state.Published, now: datetime = NOW) -> str:
    return site.page(name, item, fingerprint=FINGERPRINT, fallback={}, now=now)[0].decode()


def commands(page: str) -> list[str]:
    """The text of every code block, as a browser shows and copies it."""
    blocks = re.findall(r'<code translate="no">(.*?)</code>', page, re.S)
    return [html.unescape(re.sub(r"<[^>]+>", "", block)) for block in blocks]


def test_page_escapes_every_package_value() -> None:
    hostile = '<script>alert("x")</script> & more'
    item = published("apt", apt(hostile), (ref("apt", 'pool/a "b"/<c>.deb', 10),))
    page = render("apt", item)
    assert "<script>alert" not in page
    assert (
        '<p class="desc">&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; more</p>' in page
    )
    assert 'href="pool/a%20%22b%22/%3Cc%3E.deb"' in page
    assert '<span class="name">a &quot;b&quot;/<span class="meta">' in page
    assert '<span class="name">&lt;c&gt;.deb</span>' in page


def test_tree_nests_directories_and_folds_flatpak_objects() -> None:
    objects = (
        ref("flatpak", "objects/ab/one.filez", 1_500_000),
        ref("flatpak", "objects/cd/two.dirtree", 500_000),
        ref("flatpak", "refs/heads/app/world.wimpys.tool/x86_64/stable", 65),
        ref("flatpak", "summary", 900),
        ref("flatpak", "keys/haberdasher.asc", 3000),
        ref("flatpak", "keys/haberdasher.gpg", 2000),
        ref("flatpak", "keys/haberdasher.rsa.pub", 800),
        ref("flatpak", "haberdasher.json", 1500),
        ref("flatpak", "index.html", 4000),
        ref("flatpak", "og.png", 40_000),
    )
    tree = site.tree("flatpak", site.files(objects))
    assert tree.startswith('<ul class="tree">')
    assert (
        '<span class="name">objects/<span class="meta">2 OSTree objects, content-addressed'
        '</span></span><span class="size">2 MB</span></div>'
    ) in tree
    assert "one.filez" not in tree
    assert '<span class="name">refs/<span class="meta">1 file</span></span>' in tree
    assert 'href="refs/heads/app/world.wimpys.tool/x86_64/stable"' in tree
    assert '<a href="summary">' in tree and '<span class="size">900 B</span>' in tree
    assert state.INVENTORY_KEY not in site.files(objects) and site.PAGE_KEY not in tree
    assert site.IMAGE_KEY not in site.files(objects) and site.IMAGE_KEY not in tree
    assert "haberdasher.<wbr>json" not in tree
    assert '<li class="aux"><a href="keys/haberdasher.asc">' in tree
    apt_tree = site.tree("apt", site.files((ref("apt", "objects/a", 1),)))
    assert "<details><summary>" in apt_tree and 'objects/<span class="meta">1 file' in apt_tree
    assert "content-addressed" not in apt_tree


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
    page = render("apt", published("apt", (*history, other)))
    assert "sudo apt-get install tool" in commands(page)
    assert '<a class="gh" href="https://github.com/wimpysworld/tool">' in page
    assert "wimpysworld/tool on GitHub</a>" in page


def test_one_project_renders_one_panel_without_tabs() -> None:
    page = render("apt", published("apt", apt("Text")))
    assert 'class="tablist"' not in page
    assert '<section class="panel" id="tool" aria-labelledby="tool-title">' in page
    assert '<h3 id="tool-title">Tool</h3>' in page


def test_several_projects_render_tabs_with_the_first_selected() -> None:
    history = (
        *apt("Zed text", "2.0", 2, package="zed", repository="someone/zed", name="rpm"),
        *apt("Alpha text", "1.5", 1, package="alpha", repository="other/alpha", name="rpm"),
    )
    page = render("rpm", published("rpm", history))
    assert '<ul class="tablist" aria-label="Projects">' in page
    assert (
        '<a id="alpha-tab" href="#alpha" class="is-selected" data-panel="alpha">'
        '<span class="t-name">Alpha</span><span class="t-ver">1.5</span></a>'
    ) in page
    assert '<a id="zed-tab" href="#zed" class="" data-panel="zed">' in page
    assert '<section class="panel" id="alpha"' in page
    assert '<section class="panel is-hidden" id="zed"' in page
    assert 'name="pm-alpha"' in page and 'name="pm-zed"' in page


def test_hero_card_counts_the_published_package_files() -> None:
    history = (
        *apt("Zed text", package="zed", repository="someone/zed"),
        asset("apt", "alpha", "all", "1", {"record": "Package: alpha\n"}, repository="o/alpha"),
    )
    objects = (
        ref("apt", "pool/a.deb", 2_000),
        ref("apt", "dists/Release", 500),
        ref("apt", "haberdasher.json", 9_000),
        ref("apt", "index.html", 9_000),
        ref("apt", "og.png", 40_000),
    )
    page = render("apt", published("apt", history, objects))
    card = page[page.index('<aside class="hero-card"') : page.index("</aside>")]
    assert "<dt>Projects</dt><dd>2</dd>" in card
    assert "<dt>Packages</dt><dd>2 <small>all, amd64, arm64</small></dd>" in card
    assert "<dt>Files</dt><dd>2 <small>2 KB</small></dd>" in card
    assert '<time datetime="2026-11-09">9 November</time> <small>2026</small>' in card
    assert card.endswith("</dl>") and "<a " not in card and commands(card) == []
    assert "<strong>2 files</strong> in this repository" in page
    assert "<strong>2 KB</strong> total" in page
    assert "haberdasher.json" not in page and 'href="index.html"' not in page
    assert 'href="og.png"' not in page


def test_every_hero_links_the_maintainer() -> None:
    for name in site.THEMES:
        page = render(name, published(name, ()))
        assert (
            '<p class="lead">Packages for projects managed and maintained by '
            '<a href="https://github.com/flexiondotorg">Martin Wimpress</a>.</p>'
        ) in page
        assert 'content="Wimpy&#x27;s World' in page and "maintained by Martin Wimpress." in page
        assert "nofficial" not in page and "affiliated" not in page


def test_pages_show_the_shared_client_configuration() -> None:
    fingerprint = FINGERPRINT
    apt_page = commands(render("apt", published("apt", apt("Text"))))
    sources = site.apt_sources(
        "https://apt.wimpys.world", site.APT_KEYRING, "$(dpkg --print-architecture)"
    )
    assert any(sources in command for command in apt_page)
    rpm_page = commands(render("rpm", published("rpm", apt("Text", name="rpm"))))
    repo = site.rpm_repo(
        "https://rpm.wimpys.world", "https://rpm.wimpys.world/keys/haberdasher.asc"
    )
    assert any(repo in command for command in rpm_page)
    assert "sudo dnf install tool" in rpm_page and "sudo zypper install tool" in rpm_page
    arch_page = commands(render("arch", published("arch", apt("Text", name="arch"))))
    assert any(site.pacman_repo("https://pkg.wimpys.world/$arch") in c for c in arch_page)
    assert any(f"--lsign-key {fingerprint}" in command for command in arch_page)
    flatpak = asset(
        "flatpak", "app/world.wimpys.tool/x86_64/stable", "x86_64", "1", {"summary": "Flat"}
    )
    item = published("flatpak", (flatpak,), (ref("flatpak", "world.wimpys.tool.flatpakref", 1),))
    flatpak_page = commands(render("flatpak", item))
    assert (
        "flatpak --user install https://flatpak.wimpys.world/world.wimpys.tool.flatpakref"
        in flatpak_page
    )
    assert "flatpak --user install wimpysworld world.wimpys.tool" in flatpak_page
    assert "flatpak --user remote-delete wimpysworld" in flatpak_page


def test_long_tokens_break_only_before_slashes() -> None:
    page = render("apt", published("apt", apt("Text")))
    assert (
        '<span class="tok br"><span class="tok">https://apt.wimpys.world</span><wbr>'
        '<span class="tok">/keys</span><wbr><span class="tok">/haberdasher.gpg</span></span>'
    ) in page
    assert '<span class="tok">--print-architecture)</span>' in page


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
    assert site.install("flatpak", ["world.wimpys.tool"]) == [
        (None, "flatpak --user install wimpysworld world.wimpys.tool")
    ]


def test_content_hash_ignores_only_the_publication_date() -> None:
    item = published("rpm", apt("Text", name="rpm"))
    first, digest = site.page("rpm", item, fingerprint=FINGERPRINT, fallback={}, now=NOW)
    later, same = site.page(
        "rpm", item, fingerprint=FINGERPRINT, fallback={}, now=datetime(2027, 1, 2, tzinfo=UTC)
    )
    assert digest == same and first != later
    assert site.content_hash(first) == digest
    assert '<p>Last published <time datetime="2026-11-09">9 November 2026</time>.</p>' in (
        first.decode()
    )
    assert '<time datetime="2027-01-02">2 January</time> <small>2027</small>' in later.decode()
    changed = site.page("rpm", item, fingerprint="A" * 40, fallback={}, now=NOW)[1]
    assert changed != digest
    assert site.content_hash(b"<html></html>") is None and site.content_hash(None) is None


def test_no_project_is_hard_coded() -> None:
    source = (Path(site.__file__).parent / "site.py").read_text()
    source += (Path(site.__file__).parent / "site_style.py").read_text()
    assert not re.search(r"tailor|sidra", source, re.I)
    page = render("apt", published("apt", ()))
    assert "<p>This repository has no packages yet.</p>" in page
    assert "<dt>Projects</dt><dd>0</dd>" in page


def test_every_format_loads_pinned_assets_with_integrity() -> None:
    packages = dict.fromkeys(site.THEMES, "tool") | {
        "flatpak": "app/world.wimpys.tool/x86_64/stable"
    }
    for name, theme in site.THEMES.items():
        page = render(name, published(name, apt("Text", package=packages[name], name=name)))
        links = re.findall(r'<link rel="stylesheet" href="([^"]+)" integrity="([^"]+)"', page)
        assert [url for url, _ in links] == [
            f"https://cdn.jsdelivr.net/npm/{path}" for path in theme.styles
        ]
        assert all(re.search(r"@\d+\.\d+\.\d+/", url) for url, _ in links)
        assert [value for _, value in links] == [site.STYLES[path] for path in theme.styles]
        assert all(value.startswith("sha384-") for _, value in links)
        assert all(
            re.fullmatch(
                r"https://cdn\.jsdelivr\.net/npm/simple-icons@\d+\.\d+\.\d+/icons/\w+\.svg", url
            )
            for url in re.findall(r"--m:url\(&quot;([^&]+)&quot;\)", page)
        )
        assert f"<title>Wimpy&#x27;s World {theme.label} repository</title>" in page
        assert '<html lang="en" class="no-js">' in page and "<script>" in page
        assert page.count('aria-current="page"') == 1
        assert "fonts.googleapis" not in page
    assert site.ref("apt", b"page").cache_control == "public, max-age=300"


class _Head(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        key = values.get("property") or values.get("name")
        if tag == "meta" and key is not None:
            self.meta[key] = values.get("content") or ""


def head(page: str) -> dict[str, str]:
    parser = _Head()
    parser.feed(page[: page.index("</head>")])
    return parser.meta


def test_every_page_has_absolute_preview_tags_for_its_host() -> None:
    lead = "Packages for projects managed and maintained by Martin Wimpress."
    for name, (_, url) in PUBLIC.items():
        meta = head(render(name, published(name, ())))
        title = f"Wimpy's World {site.THEMES[name].label} repository"
        assert meta["og:url"] == f"{url}/" and url.startswith("https://")
        assert meta["og:image"] == meta["twitter:image"] == f"{url}/og.png"
        assert meta["og:title"] == meta["twitter:title"] == title
        assert meta["description"] == meta["og:description"] == meta["twitter:description"] == lead
        assert meta["og:image:alt"] == f"{title}. {lead}"
        assert (meta["og:type"], meta["og:site_name"]) == ("website", "Wimpy's World")
        assert (meta["og:image:width"], meta["og:image:height"]) == ("1200", "630")
        assert (meta["og:image:type"], meta["twitter:card"]) == ("image/png", "summary_large_image")
    page = render("apt", published("apt", ()))
    assert '<meta property="og:site_name" content="Wimpy&#x27;s World">' in page
    assert "pkg.wimpys.world/og.png" in render("arch", published("arch", ()))


def test_package_ships_one_preview_image_per_format() -> None:
    for name in PUBLIC:
        data = site.image(name)
        assert data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) < site.MAX_IMAGE_BYTES
        assert struct.unpack(">II", data[16:24]) == (1200, 630)
        ref = site.image_ref(name, data)
        assert (ref.key, ref.content_type, ref.cache_control) == (
            "og.png",
            "image/png",
            "public, max-age=86400",
        )


def test_nix_page_renders_binary_cache_flake_and_folded_tree() -> None:
    nix_asset = asset("nix", "tailor", "x86_64-linux", "0.6.0", {"desc": "Nix tool"})
    objects = (
        ref("nix", "packages.git/objects/aa/bb", 1200),
        ref("nix", "packages.git/HEAD", 23),
        ref("nix", "nar/0000000000000000000000000000000000000000000000000000.nar.zst", 8000),
        ref("nix", "00000000000000000000000000000000.narinfo", 420),
        ref("nix", "keys/haberdasher-nix.pub", 64),
        ref("nix", "nix-cache-info", 48),
    )
    retained = RetainedFormat(
        "nix",
        (nix_asset,),
        (nix_asset.inspected.identity,),
        {"public_key": "nix.wimpys.world-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
        objects,
    )
    item = state.Published("nix", None, "d" * 64, objects, retained, None)
    page = render("nix", item)
    cmds = commands(page)
    assert site.description(nix_asset) == "Nix tool"
    assert any('extra-substituters = [ "https://nix.wimpys.world" ];' in c for c in cmds)
    assert any(
        'extra-trusted-public-keys = [ "nix.wimpys.world-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ];'
        in c
        for c in cmds
    )
    assert 'inputs.haberdasher.url = "git+https://nix.wimpys.world/packages.git";' in cmds
    assert "nix profile add 'git+https://nix.wimpys.world/packages.git#tailor'" in cmds
    assert "sudo sed -i '/nix\\.wimpys\\.world/d' /etc/nix/nix.conf" in cmds
    assert (
        '<span class="name">packages.git/<span class="meta">2 files, Git repository</span></span>'
        in page
    )
    assert (
        '<span class="name">nar/<span class="meta">1 NAR archive, content-addressed</span></span>'
        in page
    )
