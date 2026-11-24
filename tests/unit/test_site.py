from __future__ import annotations

import html
import re
import struct
import types
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from xml.etree import ElementTree

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
from haberdasher.formats import nix
from haberdasher.site_style import THEMES

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
    name: str,
    history: tuple[AdmittedAsset, ...],
    objects: tuple[ObjectRef, ...] = (),
    homepages: Mapping[str, str] | None = None,
    descriptions: Mapping[str, str] | None = None,
    icons: Mapping[str, str] | None = None,
) -> state.Published:
    retained = RetainedFormat(name, history, (), {}, objects)
    return state.Published(
        name,
        None,
        "d" * 64,
        objects,
        retained,
        None,
        homepages=types.MappingProxyType(dict(homepages or {})),
        descriptions=types.MappingProxyType(dict(descriptions or {})),
        icons=types.MappingProxyType(dict(icons or {})),
    )


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
    return site.page(name, item, fingerprint=FINGERPRINT, now=now)[0].decode()


def commands(page: str) -> list[str]:
    """The text of every code block, as a browser shows and copies it."""
    blocks = re.findall(r'<code translate="no">(.*?)</code>', page, re.S)
    return [html.unescape(re.sub(r"<[^>]+>", "", block)) for block in blocks]


def test_page_escapes_every_package_value() -> None:
    hostile = '<script>alert("x")</script> & more'
    item = published(
        "apt",
        apt("Package metadata ignored"),
        (ref("apt", 'pool/a "b"/<c>.deb', 10),),
        descriptions={"wimpysworld/tool": hostile},
    )
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
        ref("flatpak", "keys/wimpysworld.asc", 3000),
        ref("flatpak", "keys/wimpysworld.gpg", 2000),
        ref("flatpak", "keys/wimpysworld.rsa.pub", 800),
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
    assert '<li class="aux"><a href="keys/wimpysworld.asc">' in tree
    apt_tree = site.tree("apt", site.files((ref("apt", "objects/a", 1),)))
    assert "<details><summary>" in apt_tree and 'objects/<span class="meta">1 file' in apt_tree
    assert "content-addressed" not in apt_tree


def test_projects_show_the_newest_release_with_its_architectures_and_command() -> None:
    history = (*apt("Old text", "1.0", 1), *apt("New text", "2.0", 2))
    other = asset(
        "apt", "helper", "all", "3.0", {"record": "Package: helper\n"}, repository="w/Helper"
    )
    entries = site.projects((*history, other), {"w/Helper": "From GitHub"})
    assert [(p.repository, p.description, p.packages) for p in entries] == [
        ("w/Helper", "From GitHub", (("helper", "3.0", ("all",)),)),
        ("wimpysworld/tool", "", (("tool", "2.0", ("amd64", "arm64")),)),
    ]
    page = render("apt", published("apt", (*history, other)))
    assert "sudo apt-get install tool" in commands(page)
    assert '<a class="gh" href="https://github.com/wimpysworld/tool">' in page
    assert "wimpysworld/tool on GitHub</a>" in page


def test_one_project_renders_one_panel_without_tabs() -> None:
    page = render("apt", published("apt", apt("Text")))
    assert 'class="tablist"' not in page
    assert 'class="install-grid"' not in page
    assert "<select" not in page
    assert '<section class="panel" id="tool" aria-labelledby="tool-title">' in page
    assert '<h3 id="tool-title">Tool</h3>' in page


def test_several_projects_render_tabs_with_the_first_selected() -> None:
    history = (
        *apt("Zed text", "2.0", 2, package="zed", repository="someone/zed", name="rpm"),
        *apt("Alpha text", "1.5", 1, package="alpha", repository="other/alpha", name="rpm"),
    )
    page = render("rpm", published("rpm", history))
    assert (
        '<div class="install-grid"><div class="install-nav"><h2 id="install-h">Install</h2>' in page
    )
    assert '<div class="install-main"><div class="panels">' in page
    assert '</div><details class="fold"><summary id="remove-h">' in page
    assert '<select id="project-select" class="project-select" aria-label="Project">' in page
    assert '<option value="alpha" selected>Alpha (1.5)</option>' in page
    assert '<option value="zed">Zed (2.0)</option>' in page
    assert '<ul class="tablist" aria-label="Projects">' in page
    assert (
        '<a id="alpha-tab" href="#alpha" class="is-selected" data-panel="alpha">'
        '<span class="t-name">Alpha</span><span class="t-ver">1.5</span></a>'
    ) in page
    assert '<a id="zed-tab" href="#zed" class="" data-panel="zed">' in page
    assert '<div class="panels"><section class="panel" id="alpha"' in page
    assert '<section class="panel is-hidden" id="zed"' in page
    assert 'name="pm-alpha"' in page and 'name="pm-zed"' in page
    assert "aria-orientation','vertical'" in page and "scrollIntoView" in page


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
        ref("apt", "logo.svg", 1_000),
    )
    page = render("apt", published("apt", history, objects))
    card = page[page.index('<aside class="hero-card"') : page.index("</aside>")]
    assert '<span class="hero-pill">OpenPGP</span>' in card
    assert "<dt>Projects</dt><dd>2</dd>" in card
    assert "<dt>Architectures</dt><dd>3</dd>" in card
    assert "<dt>Packages</dt>" not in card and "<small>" not in card
    assert "<dt>Files</dt><dd>2</dd>" in card
    assert "<dt>Size</dt><dd>2 KB</dd>" in card
    assert (
        '<p class="hero-foot">Published <time datetime="2026-11-09">9 November 2026</time></p>'
        in card
    )
    assert card.endswith("</p>") and "<a " not in card and commands(card) == []
    assert "<strong>2 files</strong> in this repository" in page
    assert "<strong>2 KB</strong> total" in page
    assert "haberdasher.json" not in page and 'href="index.html"' not in page
    assert 'href="og.png"' not in page
    assert 'href="logo.svg"' not in page


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
        "https://rpm.wimpys.world", "https://rpm.wimpys.world/keys/wimpysworld.asc"
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
        '<span class="tok">/keys</span><wbr><span class="tok">/wimpysworld.gpg</span></span>'
    ) in page
    assert '<span class="tok">--print-architecture)</span>' in page


def test_descriptions_come_strictly_from_github_metadata() -> None:
    rpm = asset(
        "rpm",
        "tool",
        "x86_64",
        "1",
        {"header_xml": '<rpmTag name="Summary">\n\t<string>RPM text</string>'},
    )
    arch = asset("arch", "tool", "x86_64", "1-1", {"desc": "%NAME%\ntool\n\n%DESC%\nArch text\n"})
    apk = asset("apk", "tool", "x86_64", "1", {"stanza": "P:tool\nT:Alpine text\n"})
    flatpak = asset(
        "flatpak", "app/world.wimpys.tool/x86_64/stable", "x86_64", "1", {"summary": "Flat"}
    )
    github_desc = "GitHub summary \U0001f9d1\u200d\U0001f4bb"
    for item in (apt("APT text")[0], rpm, arch, apk, flatpak):
        without = site.projects((item,), {})
        assert without[0].description == ""
        page_without = render(
            item.inspected.identity.format, published(item.inspected.identity.format, (item,))
        )
        assert '<p class="desc">' not in page_without
        with_desc = site.projects((item,), {"wimpysworld/tool": github_desc})
        assert with_desc[0].description == github_desc
        page_with = render(
            item.inspected.identity.format,
            published(
                item.inspected.identity.format,
                (item,),
                descriptions={"wimpysworld/tool": github_desc},
            ),
        )
        assert f'<p class="desc">{github_desc}</p>' in page_with
    entries = site.projects((flatpak,), {})
    assert entries[0].packages == (("world.wimpys.tool", "1", ("x86_64",)),)
    assert site.install("flatpak", ["world.wimpys.tool"]) == [
        (None, "flatpak --user install wimpysworld world.wimpys.tool")
    ]


def test_content_hash_ignores_only_the_publication_date() -> None:
    item = published("rpm", apt("Text", name="rpm"))
    first, digest = site.page("rpm", item, fingerprint=FINGERPRINT, now=NOW)
    later, same = site.page(
        "rpm", item, fingerprint=FINGERPRINT, now=datetime(2027, 1, 2, tzinfo=UTC)
    )
    assert digest == same and first != later
    assert site.content_hash(first) == digest
    assert '<p>Last published <time datetime="2026-11-09">9 November 2026</time>.</p>' in (
        first.decode()
    )
    assert (
        '<p class="hero-foot">Published <time datetime="2027-01-02">2 January 2027</time></p>'
        in later.decode()
    )
    changed = site.page("rpm", item, fingerprint="A" * 40, now=NOW)[1]
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
        ref, stored = site.images(name)[0]
        assert stored == data
        assert (ref.key, ref.content_type, ref.cache_control) == (
            "og.png",
            "image/png",
            "public, max-age=86400",
        )


def _luminance(colour: str) -> float:
    channels = [int(colour[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    red, green, blue = (
        value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4
        for value in channels
    )
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(first: str, second: str) -> float:
    high, low = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def test_each_format_has_one_logo_that_reads_on_light_and_dark_backgrounds() -> None:
    namespace = "{http://www.w3.org/2000/svg}"
    for name in PUBLIC:
        ref, data = site.images(name)[1]
        assert data == site.logo(name) and 300 < len(data) < 4096
        assert (ref.key, ref.object_class, ref.content_type, ref.cache_control) == (
            "logo.svg",
            "page",
            "image/svg+xml",
            "public, max-age=86400",
        )
        root = ElementTree.fromstring(data)
        assert root.tag == f"{namespace}svg" and root.get("viewBox") == "0 0 24 24"
        assert [child.tag.removeprefix(namespace) for child in root] == ["title", "style", "path"]
        title, style, path = root
        theme = THEMES[name]
        assert title.text == theme.label and path.get("d") == theme.icon
        light, dark = theme.logo
        assert style.text == (
            f"path{{fill:{light}}}@media (prefers-color-scheme:dark){{path{{fill:{dark}}}}}"
        )
        assert _contrast(light, "#ffffff") >= 3 and _contrast(dark, "#0d1117") >= 3
        text = data.decode()
        assert not re.search(
            r"href|url\(|<script|<text|<image|@import|https?://(?!www\.w3\.org/2000/svg\")", text
        )


def test_nix_page_trusts_the_cache_once_and_installs_from_each_flake() -> None:
    store = "/nix/store/" + "0" * 32
    packages = [
        nix.Package(
            "wimpysworld/tailor",
            "v0.5.0",
            "github:wimpysworld/tailor/v0.5.0",
            "tailor",
            "tailor",
            "0.5.0",
            "x86_64-linux",
            f"{store}-tailor-0.5.0",
            "Old tool",
        ),
        nix.Package(
            "wimpysworld/tailor",
            "v0.6.0",
            "github:wimpysworld/tailor/v0.6.0",
            "tailor",
            "tailor",
            "0.6.0",
            "x86_64-linux",
            f"{store}-tailor-0.6.0",
            "Nix tool",
        ),
    ]
    objects = (
        ref("nix", "nar/0000000000000000000000000000000000000000000000000000.nar.zst", 8000),
        ref("nix", "00000000000000000000000000000000.narinfo", 420),
        ref("nix", "keys/haberdasher-nix.pub", 64),
        ref("nix", "nix-cache-info", 48),
    )
    retained = RetainedFormat(
        "nix",
        (),
        tuple(item.identity for item in packages),
        {
            "public_key": "nix.wimpys.world-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "packages": [item.record() for item in packages],
        },
        objects,
    )
    item = state.Published(
        "nix",
        None,
        "d" * 64,
        objects,
        retained,
        None,
        descriptions=types.MappingProxyType({"wimpysworld/tailor": "GitHub Tailor description"}),
    )
    page = render("nix", item)
    cmds = commands(page)
    assert '<p class="desc">GitHub Tailor description</p>' in page and "0.5.0" not in page
    assert "Nix tool" not in page
    assert '<p class="desc">' not in render(
        "nix", state.Published("nix", None, "d" * 64, objects, retained, None)
    )
    assert any('extra-substituters = [ "https://nix.wimpys.world" ];' in c for c in cmds)
    assert any(
        'extra-trusted-public-keys = [ "nix.wimpys.world-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ];'
        in c
        for c in cmds
    )
    assert any("extra-substituters = https://nix.wimpys.world\n" in c for c in cmds)
    assert "nix run github:wimpysworld/tailor" in cmds
    assert "nix profile add github:wimpysworld/tailor#tailor" in cmds
    assert 'inputs.tailor.url = "github:wimpysworld/tailor";' in cmds
    assert "inputs.tailor.packages.${pkgs.stdenv.hostPlatform.system}.tailor" in cmds
    assert page.count("inputs.tailor.inputs.nixpkgs.follows") == 1
    assert "sudo sed -i '/nix\\.wimpys\\.world/d' /etc/nix/nix.conf" in cmds
    assert "packages.git" not in page
    card = page[page.index('<aside class="hero-card"') : page.index("</aside>")]
    assert '<span class="hero-pill">Ed25519</span>' in card
    assert "<dt>Projects</dt><dd>1</dd>" in card
    assert "<dt>Architectures</dt><dd>1</dd>" in card
    assert "<dt>Files</dt><dd>4</dd>" in card
    assert "<dt>Size</dt><dd>9 KB</dd>" in card
    assert 'id="files-h"' not in page and "nar/" not in page
    assert page.count("only while the default branch matches the release") == 1

    latest = "github:wimpysworld/tailor/latest"
    metadata = {**retained.metadata, "references": {"wimpysworld/tailor": latest}}
    retained = replace(retained, metadata=metadata)
    page = render("nix", state.Published("nix", None, "d" * 64, objects, retained, None))
    cmds = commands(page)
    assert f"nix run {latest}" in cmds
    assert f"nix profile add {latest}#tailor" in cmds
    assert f'inputs.tailor.url = "{latest}";' in cmds
    assert page.count("inputs.tailor.inputs.nixpkgs.follows") == 1
    assert "default branch" not in page


def test_nix_page_of_the_generated_flake_inventory_has_no_packages() -> None:
    nix_asset = asset("nix", "tailor", "x86_64-linux", "0.6.0", {"desc": "Nix tool"})
    retained = RetainedFormat("nix", (nix_asset,), (nix_asset.inspected.identity,), {}, ())
    page = render("nix", state.Published("nix", None, "d" * 64, (), retained, None))
    assert "This repository has no packages yet." in page
    assert site.nix_projects(retained, {}) == []


def test_project_titles_capitalise_each_hyphenated_word_and_keep_the_anchor() -> None:
    assert site.project_title("linuxmatters/jive-vocals") == ("Jive Vocals", "jive-vocals")
    assert site.project_title("wimpysworld/WonKey") == ("WonKey", "wonkey")
    assert site.project_title("wimpysworld/tailor") == ("Tailor", "tailor")
    assert site.project_title("wimpysworld/ia-get") == ("ia-get", "ia-get")


def test_brew_pages_name_mac_processors_and_other_pages_keep_architectures() -> None:
    assert site.architecture_labels("brew", ("arm", "intel")) == "Apple Silicon, Intel"
    assert site.architecture_labels("brew", ("universal",)) == "Apple Silicon, Intel"
    assert site.architecture_labels("brew", ("intel",)) == "Intel"
    assert site.architecture_labels("scoop", ("arm64", "x64")) == "arm64, x64"
    history = (
        asset("brew", "tailor", "arm", "1", {"desc": "Tool"}, repository="o/tailor"),
        asset("brew", "tailor", "intel", "1", {"desc": "Tool"}, repository="o/tailor"),
    )
    page = render("brew", published("brew", history, (ref("brew", "Casks/tailor.rb", 900),)))
    assert "<dt>Architectures</dt><dd>Apple Silicon, Intel</dd>" in page
    card = page[page.index('<aside class="hero-card"') : page.index("</aside>")]
    assert '<span class="hero-pill">SHA-256</span>' in card
    assert "<dt>Architectures</dt><dd>2</dd>" in card
    assert "<small>" not in card and 'id="files-h"' in page
    universal = (
        asset("brew", "tailor", "universal", "1", {"desc": "Tool"}, repository="o/tailor"),
    )
    uni_page = render("brew", published("brew", universal))
    uni_card = uni_page[uni_page.index('<aside class="hero-card"') : uni_page.index("</aside>")]
    assert "<dt>Architectures</dt><dd>2</dd>" in uni_card


def test_project_links_prioritise_homepage_and_fall_back_to_github() -> None:
    history = (
        *apt("Vocals", "1.0", 1, package="jive-vocals", repository="linuxmatters/jive-vocals"),
        *apt("Other", "1.0", 1, package="other", repository="example/other"),
    )
    item = published(
        "apt",
        history,
        homepages={
            "linuxmatters/jive-vocals": "https://linuxmatters.sh/jive/vocals/",
            "example/other": "https://github.com/example/other/",
        },
    )
    page = render("apt", item)
    assert (
        '<div class="project-links">'
        '<a class="home" href="https://linuxmatters.sh/jive/vocals/">'
        'linuxmatters.sh/jive/vocals<svg class="ext"'
    ) in page
    assert (
        '<a class="gh" href="https://github.com/linuxmatters/jive-vocals" '
        'aria-label="linuxmatters/jive-vocals on GitHub">'
    ) in page
    assert "GitHub</a></div>" in page
    assert (
        '<div class="project-links"><a class="gh" href="https://github.com/example/other">'
    ) in page
    assert "example/other on GitHub</a></div>" in page
    plain_digest = site.page("apt", published("apt", history), fingerprint=FINGERPRINT, now=NOW)[1]
    with_home_digest = site.page("apt", item, fingerprint=FINGERPRINT, now=NOW)[1]
    assert plain_digest != with_home_digest


def test_themes_match_vendor_link_and_focus_colours_and_avoid_panel_tabindex() -> None:
    expected = {
        "apt": ("#C34113", "#E95420", "#F99B78"),
        "rpm": ("#A60000", "#EE0000", "#FF7A7A"),
        "scoop": ("#B52B6E", "#D9488F", "#F77FB5"),
        "brew": ("#745626", "#A8700F", "#F7C96C"),
        "arch": ("#005F96", "#1793D1", "#00B6F9"),
        "apk": ("#0D597F", "#3D92C9", "#7FC0E3"),
        "flatpak": ("#1A5FB4", "#4A90D9", "#99C1F1"),
        "nix": ("#2D5299", "#5277C3", "#7EBAE4"),
    }
    for name, tokens in expected.items():
        page = render(name, published(name, ()))
        for token in tokens:
            assert token.lower() in page.lower(), (name, token)
        assert "tabIndex=0" not in page
        assert ".panel{scroll-margin-top:1rem}" in page
        assert "minmax(11.5rem,1.35fr) minmax(5.5rem,.65fr) minmax(11rem,1.2fr)" in page
        if name == "flatpak":
            assert "--hd-header-bg:var(--hd-bg)" in page
            assert "--hd-header-bg:#1a1622" in page


def test_project_icons_render_in_project_head_and_stay_out_of_file_tree() -> None:
    history = (
        *apt("Tool text", "1.0", 1, package="tool", repository="wimpysworld/tool"),
        *apt("Other text", "1.0", 1, package="other", repository="example/other"),
    )
    objects = (
        ref("apt", "pool/tool.deb", 2_000),
        ref("apt", "icons/tool.svg", 512),
        ref("apt", "icons/other.png", 4_096),
    )
    assert site.files(objects) == {"pool/tool.deb": 2_000}
    item = published(
        "apt",
        history,
        objects,
        descriptions={"wimpysworld/tool": "Tool summary"},
        icons={"wimpysworld/tool": "icons/tool.svg"},
    )
    page = render("apt", item)
    assert (
        '<div class="project"><div class="project-head">'
        '<h3 id="tool-title">Tool</h3><p class="desc">Tool summary</p>'
        '<div class="project-links"><a class="gh" href="https://github.com/wimpysworld/tool">'
    ) in page
    assert (
        "wimpysworld/tool on GitHub</a></div>"
        '<img class="project-icon" src="icons/tool.svg" alt="" width="124" height="124" '
        'decoding="async"></div><dl class="pkg">'
    ) in page
    assert (
        '<div class="project"><div class="project-head"><h3 id="other-title">Other</h3>'
    ) in page
    assert page.count('class="project-icon"') == 1
    assert 'href="icons/tool.svg"' not in page
    assert "<strong>1 file</strong> in this repository" in page
    plain_digest = site.page(
        "apt", published("apt", history, objects), fingerprint=FINGERPRINT, now=NOW
    )[1]
    icon_digest = site.page("apt", item, fingerprint=FINGERPRINT, now=NOW)[1]
    assert plain_digest != icon_digest

    store = "/nix/store/" + "0" * 32
    pkg = nix.Package(
        "wimpysworld/tailor",
        "v0.6.0",
        "github:wimpysworld/tailor/v0.6.0",
        "tailor",
        "tailor",
        "0.6.0",
        "x86_64-linux",
        f"{store}-tailor-0.6.0",
        "Nix tool",
    )
    retained = RetainedFormat("nix", (), (pkg.identity,), {"packages": [pkg.record()]}, ())
    nix_item = state.Published(
        "nix",
        None,
        "d" * 64,
        (),
        retained,
        None,
        icons=types.MappingProxyType({"wimpysworld/tailor": "icons/tailor.png"}),
    )
    nix_page = render("nix", nix_item)
    assert (
        '<img class="project-icon" src="icons/tailor.png" alt="" width="124" height="124" '
        'decoding="async">'
    ) in nix_page


def test_hero_card_verification_pills_formatting_and_responsive_dossier() -> None:
    expected_pills = {
        "apt": "OpenPGP",
        "rpm": "OpenPGP",
        "arch": "OpenPGP",
        "flatpak": "OpenPGP",
        "apk": "RSA-256",
        "nix": "Ed25519",
        "brew": "SHA-256",
        "scoop": "SHA-256",
    }
    for name, pill in expected_pills.items():
        page = render(name, published(name, ()))
        card = page[page.index('<aside class="hero-card"') : page.index("</aside>")]
        assert f'<span class="hero-pill">{pill}</span>' in card
        assert "box-shadow:var(--hd-card-shadow" in page
        assert "@media (max-width:480px){" in page
        assert ".hero-card{display:none}" not in page
    many = tuple(ref("nix", f"nar/{i:04d}.nar.zst", 1_500_000) for i in range(1_234))
    nix_page = render("nix", published("nix", (), many))
    nix_card = nix_page[nix_page.index('<aside class="hero-card"') : nix_page.index("</aside>")]
    assert "<dt>Files</dt><dd>1,234</dd>" in nix_card
    assert "<dt>Size</dt><dd>1.9 GB</dd>" in nix_card
    assert 'id="files-h"' not in nix_page and "nar/" not in nix_page
