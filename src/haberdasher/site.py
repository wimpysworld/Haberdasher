"""The public index.html page of each repository bucket, built from its inventory."""

from __future__ import annotations

import hashlib
import html
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from urllib.parse import quote, urlsplit

from haberdasher import state
from haberdasher.config import PUBLIC
from haberdasher.core import AdmittedAsset, ObjectRef, plural, size_text
from haberdasher.formats.apt import COMPONENT, SUITE
from haberdasher.formats.flatpak import FLATHUB, FLATPAKREPO, REMOTE, TITLE

PAGE_KEY = "index.html"
MAX_PAGE_BYTES = 4 * 1024 * 1024
OWNER = "Martin Wimpress"
SOURCE = "https://github.com/wimpysworld/Haberdasher"
APT_KEYRING = "/etc/apt/keyrings/haberdasher.gpg"
_HASH = re.compile(rb'<meta name="haberdasher-content" content="([0-9a-f]{64})">')
_CDN = "https://cdn.jsdelivr.net/npm/"
_ICONS = _CDN + "simple-icons@16.37.0/icons/"
# Exact jsDelivr paths and the SRI digests of their served bytes.
STYLES = {
    "@digicreon/mucss@1.4.9/dist/mu.orange.css": (
        "sha384-RWjv5U5P9qrGA/d0BeUQffNMBO0uWgdz6pOWxLoZkWXfLENNQJXKt7dr7g8Khb1C"
    ),
    "@digicreon/mucss@1.4.9/dist/mu.red.css": (
        "sha384-T8B/jJxtffli4kRoMnNnM9r6sTPwB//d2IyD27RoJ8s/GKBtbB9NzOj326GthqyJ"
    ),
    "@digicreon/mucss@1.4.9/dist/mu.azure.css": (
        "sha384-YjTpibR/F7FR3aIGG2zomRYyj5iVUC8YZMDXyEpUjoYzvnA+xRlC57sqqdhse4si"
    ),
    "@fontsource/ubuntu@5.3.0/latin-400.css": (
        "sha384-Hmj8OALUB6aIikG4YVYkzbyKw1t3gdv7IYgzpt+5zEAmMwYM05vjN5KqGgXRudKz"
    ),
    "@fontsource/ubuntu@5.3.0/latin-500.css": (
        "sha384-2XRgRUz0XLG8Db6rua4zUxXUcvMtPOHp8NTrP0m2txLuzoF2jJauRxRzyDzLBIpv"
    ),
    "@fontsource/red-hat-display@5.3.0/latin-700.css": (
        "sha384-+5KZTNIZygIXY/HKL9IMr8E8KXyHWLcLXq20QErBF6HFBp1rCUKoYYwTRMus5J2n"
    ),
    "@fontsource/red-hat-text@5.3.0/latin-400.css": (
        "sha384-tp/ewtWBoD+TTx4nbbBgWqUxB7pAGpx2dDIWhUB7RAAZQfVsOZE9BJQ/+2ocys8v"
    ),
    "@fontsource/red-hat-text@5.3.0/latin-500.css": (
        "sha384-7/1FKLV8SzgEjbxZi00WTSdfok5BobgjT41ugDfDlruA4nOC5bB9xqUuR4j98Fkx"
    ),
    "@fontsource/inter@5.3.0/latin-400.css": (
        "sha384-zc+mzApNgdFM05uzzG/c/4wVZ4LHLa0ZrZyeZYh4tq7GukSAQ2T6xYGTgE+mssl6"
    ),
    "@fontsource/inter@5.3.0/latin-600.css": (
        "sha384-sIxfdbMxNyRS8ALLKQtuDA2c/167yRmp3egSBaxjFVG167V3b1JFy7HPQdrxziBJ"
    ),
}
_SANS = "var(--mu-font-family-sans-serif)"


@dataclass(frozen=True)
class Theme:
    """Colours are heading, accent, and action for light mode, then for dark mode.

    Action is the link and button colour. Button text is white in light mode and dark in dark
    mode, so each action colour keeps 4.5:1 against both the page and the button text.
    """

    label: str
    styles: tuple[str, ...]
    body: str
    display: str
    light: tuple[str, str, str]
    dark: tuple[str, str, str]
    works: tuple[tuple[str, str], ...]
    vendors: str


THEMES: dict[str, Theme] = {
    "apt": Theme(
        "APT",
        (
            "@digicreon/mucss@1.4.9/dist/mu.orange.css",
            "@fontsource/ubuntu@5.3.0/latin-400.css",
            "@fontsource/ubuntu@5.3.0/latin-500.css",
        ),
        f"Ubuntu, {_SANS}",
        f"Ubuntu, {_SANS}",
        ("#77216F", "#E95420", "#C34113"),
        ("#F99B78", "#E95420", "#F47B4F"),
        (
            ("ubuntu", "Ubuntu"),
            ("debian", "Debian"),
            ("linuxmint", "Linux Mint"),
            ("popos", "Pop!_OS"),
        ),
        "Canonical or the Debian Project",
    ),
    "rpm": Theme(
        "RPM",
        (
            "@digicreon/mucss@1.4.9/dist/mu.red.css",
            "@fontsource/red-hat-display@5.3.0/latin-700.css",
            "@fontsource/red-hat-text@5.3.0/latin-400.css",
            "@fontsource/red-hat-text@5.3.0/latin-500.css",
        ),
        f'"Red Hat Text", {_SANS}',
        f'"Red Hat Display", {_SANS}',
        ("#A60000", "#EE0000", "#C9190B"),
        ("#FF8C8C", "#EE0000", "#F56E6E"),
        (
            ("fedora", "Fedora"),
            ("redhat", "Red Hat Enterprise Linux"),
            ("opensuse", "openSUSE"),
            ("suse", "SUSE"),
        ),
        "Red Hat, the Fedora Project, or SUSE",
    ),
    "arch": Theme(
        "Arch Linux",
        ("@digicreon/mucss@1.4.9/dist/mu.azure.css",),
        _SANS,
        _SANS,
        ("#0B5F8A", "#1793D1", "#0F6A99"),
        ("#7DC4EB", "#1793D1", "#4DB0E6"),
        (
            ("archlinux", "Arch Linux"),
            ("manjaro", "Manjaro"),
            ("endeavouros", "EndeavourOS"),
        ),
        "Arch Linux",
    ),
    "apk": Theme(
        "Alpine Linux",
        ("@digicreon/mucss@1.4.9/dist/mu.azure.css",),
        _SANS,
        _SANS,
        ("#0D597F", "#1078A8", "#0D597F"),
        ("#6FB9E1", "#2D8EC4", "#5BB0DD"),
        (("alpinelinux", "Alpine Linux"),),
        "Alpine Linux",
    ),
    "flatpak": Theme(
        "Flatpak",
        (
            "@digicreon/mucss@1.4.9/dist/mu.azure.css",
            "@fontsource/inter@5.3.0/latin-400.css",
            "@fontsource/inter@5.3.0/latin-600.css",
        ),
        f"Inter, {_SANS}",
        f"Inter, {_SANS}",
        ("#1F5EA8", "#4A90D9", "#2B65A8"),
        ("#8FBDEE", "#4A90D9", "#6FA8E6"),
        (
            ("flatpak", "Flatpak"),
            ("flathub", "Flathub"),
            ("fedora", "Fedora"),
            ("ubuntu", "Ubuntu"),
            ("linuxmint", "Linux Mint"),
        ),
        "the Flatpak project or Flathub",
    ),
}


def apt_sources(url: str, keyring: str, architecture: str) -> str:
    """The deb822 source that the page shows and the APT client test uses."""
    return (
        f"Types: deb\nURIs: {url}\nSuites: {SUITE}\nComponents: {COMPONENT}\n"
        f"Architectures: {architecture}\nSigned-By: {keyring}\n"
    )


def rpm_repo(url: str, gpgkey: str) -> str:
    """The repository definition that the page shows and the DNF client test uses."""
    return (
        f"[haberdasher]\nname=Haberdasher\nbaseurl={url}\nenabled=1\ngpgcheck=1\n"
        f"repo_gpgcheck=1\ngpgkey={gpgkey}\nskip_if_unavailable=0\n"
    )


def pacman_repo(server: str) -> str:
    """The pacman.conf section that the page shows and the pacman client test uses."""
    return f"[haberdasher]\nSigLevel = Required\nServer = {server}\n"


def _heredoc(command: str, path: str, body: str, *, expand: bool = False) -> str:
    marker = "EOF" if expand else "'EOF'"
    return f"{command} {path} > /dev/null <<{marker}\n{body}EOF"


def _runtime_remotes(history: Sequence[AdmittedAsset]) -> list[str]:
    repos = {
        value
        for asset in history
        if isinstance(value := asset.inspected.evidence.get("runtime_repo"), str)
    } or {FLATHUB}
    return [
        f"flatpak --user remote-add --if-not-exists {PurePosixPath(urlsplit(repo).path).stem} {repo}"
        for repo in sorted(repos)
    ]


def setup(name: str, history: Sequence[AdmittedAsset]) -> list[tuple[str, str]]:
    """The common setup steps of one format, as a caption and a command."""
    url = PUBLIC[name][1]
    key = f"{url}/keys/haberdasher.asc"
    match name:
        case "apt":
            return [
                (
                    "Install the signing key.",
                    "sudo install -d -m 0755 /etc/apt/keyrings\n"
                    f"curl -fsSL {url}/keys/haberdasher.gpg | sudo tee {APT_KEYRING} > /dev/null",
                ),
                (
                    "Add the repository, then update the package lists.",
                    _heredoc(
                        "sudo tee",
                        "/etc/apt/sources.list.d/haberdasher.sources",
                        apt_sources(url, APT_KEYRING, "$(dpkg --print-architecture)"),
                        expand=True,
                    )
                    + "\nsudo apt-get update",
                ),
            ]
        case "rpm":
            return [
                (
                    "Fedora, Red Hat Enterprise Linux, and other systems with DNF:",
                    f"sudo rpm --import {key}\n"
                    + _heredoc("sudo tee", "/etc/yum.repos.d/haberdasher.repo", rpm_repo(url, key)),
                ),
                (
                    "openSUSE and SUSE Linux Enterprise, with zypper:",
                    f"sudo rpm --import {key}\n"
                    f"sudo zypper addrepo --gpgcheck --refresh {url} haberdasher\n"
                    "sudo zypper refresh",
                ),
            ]
        case "arch":
            return [
                (
                    "Add the signing key to the pacman keyring, and sign it locally.",
                    f"curl -fsSL {key} | sudo pacman-key --add -\n"
                    "sudo pacman-key --lsign-key {fingerprint}",
                ),
                (
                    "Add the repository to /etc/pacman.conf.",
                    _heredoc("sudo tee -a", "/etc/pacman.conf", "\n" + pacman_repo(url + "/$arch")),
                ),
            ]
        case "apk":
            return [
                (
                    "Run these commands as root.",
                    f"wget -qO /etc/apk/keys/haberdasher.rsa.pub {url}/keys/haberdasher.rsa.pub\n"
                    f"echo {url} >> /etc/apk/repositories\napk update",
                ),
            ]
        case _:
            return [
                (
                    "Add Flathub for the runtime, then add this repository.",
                    "\n".join(
                        [
                            *_runtime_remotes(history),
                            f"flatpak --user remote-add --if-not-exists {REMOTE} {url}/{FLATPAKREPO}",
                        ]
                    ),
                ),
            ]


def remove(name: str) -> list[tuple[str, str]]:
    url = PUBLIC[name][1]
    match name:
        case "apt":
            return [
                (
                    "",
                    "sudo rm /etc/apt/sources.list.d/haberdasher.sources " + APT_KEYRING + "\n"
                    "sudo apt-get update",
                )
            ]
        case "rpm":
            return [
                ("DNF:", "sudo rm /etc/yum.repos.d/haberdasher.repo\nsudo rpm -e {keyid}"),
                ("zypper:", "sudo zypper removerepo haberdasher\nsudo rpm -e {keyid}"),
            ]
        case "arch":
            return [
                (
                    "",
                    "sudo sed -i '/^\\[haberdasher\\]$/,/^Server = /d' /etc/pacman.conf\n"
                    "sudo pacman-key --delete {fingerprint}",
                )
            ]
        case "apk":
            return [
                (
                    "Run these commands as root.",
                    f"sed -i '\\|^{url}$|d' /etc/apk/repositories\n"
                    "rm /etc/apk/keys/haberdasher.rsa.pub",
                )
            ]
        case _:
            return [("Uninstall its applications first.", f"flatpak --user remote-delete {REMOTE}")]


def install(name: str, packages: Sequence[str]) -> list[tuple[str, str]]:
    names = " ".join(packages)
    match name:
        case "apt":
            return [("", f"sudo apt-get install {names}")]
        case "rpm":
            return [
                ("DNF:", f"sudo dnf install {names}"),
                ("zypper:", f"sudo zypper install {names}"),
            ]
        case "arch":
            return [("", f"sudo pacman -Syu {names}")]
        case "apk":
            return [("As root:", f"apk add {names}")]
        case _:
            return [("", f"flatpak --user install {REMOTE} {app}") for app in packages]


def _field(pattern: str, value: object) -> str:
    match = re.search(pattern, value, re.MULTILINE) if isinstance(value, str) else None
    return " ".join(html.unescape(match[1]).split()) if match else ""


def description(asset: AdmittedAsset) -> str:
    """The one-line package description from native package metadata."""
    metadata = asset.inspected.metadata
    match asset.inspected.identity.format:
        case "apt":
            return _field(r"^Description: ?(.*)$", metadata.get("record"))
        case "rpm":
            return _field(r'<rpmTag name="Summary">\s*<string>([^<]*)', metadata.get("header_xml"))
        case "arch":
            return _field(r"^%DESC%\n(.*)$", metadata.get("desc"))
        case "apk":
            return _field(r"^T:(.*)$", metadata.get("stanza"))
        case _:
            return _field(r"(.+)", metadata.get("summary"))


def descriptions(histories: Iterable[Sequence[AdmittedAsset]]) -> dict[str, str]:
    """The newest description of each source repository, from the first history that has one."""
    result: dict[str, str] = {}
    for history in histories:
        for asset in reversed(history):
            text = description(asset)
            if text:
                result.setdefault(asset.inspected.verified.source.repository, text)
    return result


@dataclass(frozen=True)
class Project:
    repository: str
    description: str
    packages: tuple[tuple[str, str, tuple[str, ...]], ...]


def _package(asset: AdmittedAsset) -> tuple[str, str]:
    identity = asset.inspected.identity
    if identity.format == "flatpak":
        return identity.name.split("/")[1], identity.version
    version = f"{identity.version}-{identity.release}" if identity.release else identity.version
    return identity.name, (f"{identity.epoch}:{version}" if identity.epoch else version)


def projects(history: Sequence[AdmittedAsset], fallback: Mapping[str, str]) -> list[Project]:
    """One entry per source repository, with the packages of its newest published release."""
    own = descriptions([history])
    releases: dict[str, int] = {}
    for asset in history:
        source = asset.inspected.verified.source
        releases[source.repository] = max(releases.get(source.repository, 0), source.release_id)
    result: list[Project] = []
    for repository in sorted(releases, key=str.lower):
        packages: dict[tuple[str, str], set[str]] = {}
        for asset in history:
            source = asset.inspected.verified.source
            if (source.repository, source.release_id) == (repository, releases[repository]):
                packages.setdefault(_package(asset), set()).add(
                    asset.inspected.identity.architecture
                )
        result.append(
            Project(
                repository,
                own.get(repository) or fallback.get(repository, ""),
                tuple(
                    (name, version, tuple(sorted(architectures)))
                    for (name, version), architectures in sorted(packages.items())
                ),
            )
        )
    return result


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _commands(steps: Sequence[tuple[str, str]], values: Mapping[str, str]) -> str:
    parts: list[str] = []
    for caption, command in steps:
        if caption:
            parts.append(f"<p>{_e(caption)}</p>")
        text = command.replace("{fingerprint}", values["fingerprint"]).replace(
            "{keyid}", values["keyid"]
        )
        parts.append(
            f'<div class="command"><pre><code>{_e(text)}</code></pre>'
            '<button type="button" class="copy" hidden>Copy</button></div>'
        )
    return "\n".join(parts)


def _tree(files: Mapping[str, int], prefix: str, fold: bool) -> str:
    directories: dict[str, dict[str, int]] = {}
    leaves: list[tuple[str, int]] = []
    for key, size in files.items():
        head, separator, rest = key.partition("/")
        if separator:
            directories.setdefault(head, {})[rest] = size
        else:
            leaves.append((key, size))
    items: list[str] = []
    for directory in sorted(directories):
        inner = directories[directory]
        label = f"{_e(directory)}/"
        detail = f"{plural(len(inner), 'file')} ({size_text(sum(inner.values()))})"
        if fold and not prefix and directory == "objects":
            items.append(f'<li><span class="folder">{label}</span> {detail}</li>')
            continue
        items.append(
            f"<li><details><summary>{label} <small>{detail}</small></summary>"
            f"{_tree(inner, f'{prefix}{directory}/', fold)}</details></li>"
        )
    for name, size in sorted(leaves):
        href = quote(prefix + name)
        items.append(
            f'<li><a href="{_e(href)}">{_e(name)}</a> <small>{size_text(size)}</small></li>'
        )
    return f"<ul>{''.join(items)}</ul>"


def tree(name: str, objects: Sequence[ObjectRef], inventory_size: int) -> str:
    """Nested disclosures of the published files, with Flatpak objects/ on one line."""
    files = {ref.key: ref.size for ref in objects}
    files[state.INVENTORY_KEY] = inventory_size
    return _tree(files, "", name == "flatpak")


_CSS = """body{--mu-font-family:var(--hd-body);--mu-primary:var(--hd-action);\
--mu-primary-hover:var(--hd-heading);--mu-primary-underline:var(--hd-accent);\
--mu-primary-background:var(--hd-action);--mu-primary-border:var(--hd-action);\
--mu-primary-hover-background:var(--hd-heading);--mu-primary-hover-border:var(--hd-heading);\
--mu-primary-inverse:var(--hd-on-action);--mu-primary-focus:var(--hd-accent);\
--mu-h1-color:var(--hd-heading);--mu-h2-color:var(--hd-heading);--mu-h3-color:var(--hd-heading);\
--mu-accordion-active-summary-color:var(--hd-action);--mu-code-color:var(--mu-color);\
--hd-on-action:#fff}
@media (prefers-color-scheme:dark){body{--hd-on-action:#13171f}.works img{filter:invert(1)}}
body{font-family:var(--hd-body)}h1,h2,h3{font-family:var(--hd-display);text-wrap:balance}
pre,code{font-family:var(--mu-font-family-monospace)}
body>header{border-top:.5rem solid var(--hd-accent);padding-top:1.5rem}
body>main{padding-top:0}h2{margin-top:2rem;padding-bottom:.25rem;border-bottom:.125rem solid var(--hd-accent)}
.skip{position:absolute;left:-100vw}.skip:focus{left:1rem;top:1rem;z-index:1;padding:.5rem 1rem;\
background:var(--mu-background-color)}
.visually-hidden{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);\
white-space:nowrap}
.sites{display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;margin:0 0 1.5rem;padding:0;list-style:none}
.sites li{margin:0;padding:0;list-style:none}.sites [aria-current]{font-weight:600;\
text-decoration:underline;text-decoration-thickness:.15em;text-decoration-color:var(--hd-accent)}
.lead{font-size:1.125rem}
.works{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1.25rem;margin-bottom:1rem}
.works ul{display:contents}.works li{display:flex;align-items:center;gap:.4rem;margin:0;\
list-style:none}.works img{width:1.25rem;height:1.25rem;opacity:.75}
.note{color:var(--mu-muted-color)}
.fingerprint{font-size:1rem;word-break:break-all}
.command{position:relative;margin-bottom:var(--mu-spacing)}
.command pre{margin:0;padding:2.75rem 1rem 1rem}.command code{padding:0;background:none}
.command .copy{position:absolute;top:.5rem;right:.5rem;width:auto;margin:0;padding:.25rem .75rem;\
font-size:.875rem}
article{border-top:.25rem solid var(--hd-accent)}article h3{margin-bottom:.5rem}
.scroll{overflow-x:auto}.scroll table{font-size:.875rem}
.tree ul{margin:0;padding-left:1.25rem}.tree>ul{padding-left:0}
.tree li{margin:.2rem 0;list-style:none}.tree details{margin:0;padding:0;border:0}
.tree summary{display:inline;cursor:pointer}.tree summary::after{display:none}
.tree summary::before{content:"\\25B8" / "";display:inline-block;width:1rem}
.tree details[open]>summary::before{content:"\\25BE" / ""}
.folder{font-weight:500}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""

_JS = """const s=document.getElementById("copy-status");\
for(const b of document.querySelectorAll(".copy")){b.hidden=false;\
b.addEventListener("click",async()=>{try{\
await navigator.clipboard.writeText(b.previousElementSibling.textContent);\
b.textContent="Copied";s.textContent="Command copied to the clipboard."}catch{\
b.textContent="Copy failed";s.textContent="Copy failed. Select the command and copy it."}\
setTimeout(()=>{b.textContent="Copy"},2000)})}"""


def _favicon(colour: str) -> str:
    svg = (
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
        f"<rect width='32' height='32' rx='6' fill='{colour}'/>"
        "<path d='M8 11l8-4 8 4v10l-8 4-8-4zM8 11l8 4 8-4M16 15v10' fill='none' "
        "stroke='white' stroke-width='2.5' stroke-linejoin='round'/></svg>"
    )
    return "data:image/svg+xml," + quote(svg)


def _project(name: str, project: Project, refs: set[str], values: Mapping[str, str]) -> str:
    short = project.repository.split("/")[1]
    title = short[:1].upper() + short[1:]
    rows = "".join(
        f"<tr><td><code>{_e(package)}</code></td><td>{_e(version)}</td>"
        f"<td>{_e(', '.join(architectures))}</td></tr>"
        for package, version, architectures in project.packages
    )
    names = list(dict.fromkeys(package for package, _, _ in project.packages))
    extra = ""
    if name == "flatpak":
        files = [f"{app}.flatpakref" for app in names if f"{app}.flatpakref" in refs]
        if files:
            links = ", ".join(f'<a href="{_e(quote(file))}">{_e(file)}</a>' for file in files)
            extra = f"<p>Or open {links} in a software centre.</p>"
    about = f"<p>{_e(project.description)}</p>" if project.description else ""
    return (
        f'<article id="{_e(short.lower())}"><h3>{_e(title)}</h3>{about}'
        f'<p><a href="https://github.com/{_e(project.repository)}">'
        f"{_e(project.repository)} on GitHub</a></p>"
        '<div class="scroll"><table><thead><tr><th scope="col">Package</th>'
        '<th scope="col">Version</th><th scope="col">Architectures</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></div>"
        f"{_commands(install(name, names), values)}{extra}</article>"
    )


def _document(
    name: str,
    published: state.Published,
    *,
    fingerprint: str,
    fallback: Mapping[str, str],
    digest: str,
    now: datetime | None,
) -> str:
    theme = THEMES[name]
    url = PUBLIC[name][1]
    title = f"{TITLE} {theme.label} repository"
    lead = f"This is the {theme.label} repository for packages from projects that {OWNER} manages."
    values = {"fingerprint": fingerprint, "keyid": f"gpg-pubkey-{fingerprint[-8:].lower()}"}
    styles = "\n".join(
        f'<link rel="stylesheet" href="{_e(_CDN + path)}" integrity="{_e(STYLES[path])}" '
        'crossorigin="anonymous">'
        for path in theme.styles
    )
    light, dark = theme.light, theme.dark
    tokens = (
        f"body{{--hd-body:{theme.body};--hd-display:{theme.display};--hd-heading:{light[0]};"
        f"--hd-accent:{light[1]};--hd-action:{light[2]}}}\n"
        f"@media (prefers-color-scheme:dark){{body{{--hd-heading:{dark[0]};"
        f"--hd-accent:{dark[1]};--hd-action:{dark[2]}}}}}\n"
    )
    sites = "".join(
        f'<li><a href="{_e(PUBLIC[other][1])}/"{current}>{_e(THEMES[other].label)}</a></li>'
        for other in PUBLIC
        for current in (' aria-current="page"' if other == name else "",)
    )
    works = "".join(
        f'<li><img src="{_e(_ICONS + slug)}.svg" alt="" width="20" height="20">{_e(label)}</li>'
        for slug, label in theme.works
    )
    history = published.retained.accepted_history
    entries = projects(history, fallback)
    refs = {ref.key for ref in published.objects}
    sections = (
        "\n".join(_project(name, project, refs, values) for project in entries)
        or "<p>This repository has no packages yet.</p>"
    )
    check = f"{'wget -qO-' if name == 'apk' else 'curl -fsSL'} {url}/keys/haberdasher.asc"
    key_note = (
        "<p>APK uses the same RSA key, as the PEM file "
        '<a href="keys/haberdasher.rsa.pub">keys/haberdasher.rsa.pub</a>.</p>'
        if name == "apk"
        else ""
    )
    if now is None:
        date = ""
    else:
        date = f'<time datetime="{now.date().isoformat()}">{now.day} {now:%B %Y}</time>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="haberdasher-content" content="{digest}">
<meta name="description" content="{_e(lead)}">
<title>{_e(title)}</title>
<link rel="icon" href="{_e(_favicon(light[1]))}">
{styles}
<style>
{tokens}{_CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to the main content</a>
<header class="container">
<nav aria-label="Repositories"><ul class="sites">{sites}</ul></nav>
<h1>{_e(title)}</h1>
<p class="lead">{_e(lead)}</p>
<div class="works"><span>Works with</span><ul>{works}</ul></div>
<p class="note"><small>Unofficial repository. Not affiliated with or endorsed by \
{_e(theme.vendors)}.</small></p>
</header>
<main id="main" class="container">
<section aria-labelledby="key">
<h2 id="key">Check the signing key</h2>
<p>One OpenPGP key signs this repository. Its full fingerprint is:</p>
<p><code class="fingerprint">{_e(fingerprint)}</code></p>
<p>Check that this command prints the same fingerprint:</p>
{_commands([("", f"{check} | gpg --show-keys")], values)}
{key_note}</section>
<section aria-labelledby="setup">
<h2 id="setup">Set up the repository</h2>
{_commands(setup(name, history), values)}
</section>
<section aria-labelledby="projects">
<h2 id="projects">Install packages</h2>
{sections}
</section>
<section aria-labelledby="remove">
<h2 id="remove">Remove this repository</h2>
{_commands(remove(name), values)}
</section>
<section aria-labelledby="files">
<h2 id="files">Published files</h2>
<div class="tree">{tree(name, published.objects, len(published.data))}</div>
</section>
</main>
<footer class="container">
<p><small>Last published {date}. Published with <a href="{SOURCE}">Haberdasher</a>.</small></p>
</footer>
<p id="copy-status" class="visually-hidden" aria-live="polite"></p>
<script>{_JS}</script>
</body>
</html>
"""


def page(
    name: str,
    published: state.Published,
    *,
    fingerprint: str,
    fallback: Mapping[str, str],
    now: datetime,
) -> tuple[bytes, str]:
    """Return the page and the hash of its content without the publication date."""

    def document(digest: str, date: datetime | None) -> bytes:
        return _document(
            name, published, fingerprint=fingerprint, fallback=fallback, digest=digest, now=date
        ).encode()

    digest = hashlib.sha256(document("", None)).hexdigest()
    return document(digest, now), digest


def content_hash(data: bytes | None) -> str | None:
    """The content hash that a published page embeds, or None."""
    match = _HASH.search(data) if data is not None else None
    return match[1].decode() if match else None


def ref(name: str, data: bytes) -> ObjectRef:
    return ObjectRef(
        name,
        PAGE_KEY,
        "page",
        len(data),
        hashlib.sha256(data).hexdigest(),
        "text/html; charset=utf-8",
        "public, max-age=300",
    )
