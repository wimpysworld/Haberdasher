"""The public index.html page of each repository bucket, built from its inventory."""

from __future__ import annotations

import hashlib
import html
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files as resources
from pathlib import PurePosixPath
from urllib.parse import quote, urlsplit

from haberdasher import state
from haberdasher.config import PUBLIC
from haberdasher.core import AdmittedAsset, ObjectRef, plural, size_text
from haberdasher.formats.apt import COMPONENT, SUITE
from haberdasher.formats.brew import TAP, TAP_NAME
from haberdasher.formats.flatpak import FLATHUB, FLATPAKREPO, REMOTE, TITLE
from haberdasher.formats.scoop import BUCKET, REPO
from haberdasher.site_style import (
    BASE_CSS,
    BRAND_MARK,
    CHEVRON,
    COPY_ICON,
    FILE_ICON,
    FOLDER_CLOSED,
    FOLDER_OPEN,
    GITHUB_ICON,
    JS,
    STYLES,
    THEMES,
)

PAGE_KEY = "index.html"
MAX_PAGE_BYTES = 4 * 1024 * 1024
IMAGE_KEY = "og.png"
MAX_IMAGE_BYTES = 1024 * 1024
OWNER = "Martin Wimpress"
OWNER_URL = "https://github.com/flexiondotorg"
SOURCE = "https://github.com/wimpysworld/Haberdasher"
APT_KEYRING = "/etc/apt/keyrings/haberdasher.gpg"
NIX_REPO = "packages.git"
_HASH = re.compile(rb'<meta name="haberdasher-content" content="([0-9a-f]{64})">')
_CDN = "https://cdn.jsdelivr.net/npm/"
_ICONS = _CDN + "simple-icons@16.37.0/icons/"
_PM = {"dnf": "DNF", "zypper": "zypper"}


def _url(name: str) -> str:
    return PUBLIC[name][1] if name in PUBLIC else f"https://{name}.wimpys.world"


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


def nix_settings(url: str, public_key: str) -> str:
    """The NixOS binary cache configuration that the page shows."""
    return (
        "nix.settings = {\n"
        f'  extra-substituters = [ "{url}" ];\n'
        f'  extra-trusted-public-keys = [ "{public_key}" ];\n'
        "};"
    )


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
        "flatpak --user remote-add --if-not-exists "
        f"{shlex.quote(PurePosixPath(urlsplit(repo).path).stem)} {shlex.quote(repo)}"
        for repo in sorted(repos)
    ]


type Command = tuple[str | None, str]
"""A package manager variant, or None for every client, and the command text."""


@dataclass(frozen=True)
class Step:
    """One numbered install step. The note is trusted markup from this module."""

    title: str
    note: str
    commands: tuple[Command, ...]
    check: bool = False
    check_note: bool = True
    switch: bool = False


def check_command(name: str) -> str:
    """The command that prints the fingerprint of the published signing key."""
    fetch = "wget -qO-" if name == "apk" else "curl -fsSL"
    return f"{fetch} {_url(name)}/keys/haberdasher.asc | gpg --show-keys"


def install(name: str, packages: Sequence[str]) -> list[Command]:
    """The install commands for the packages of one project."""
    names = " ".join(packages)
    match name:
        case "apt":
            return [(None, f"sudo apt-get install {names}")]
        case "rpm":
            return [
                ("dnf", f"sudo dnf install {names}"),
                ("zypper", f"sudo zypper install {names}"),
            ]
        case "arch":
            return [(None, f"sudo pacman -Syu {names}")]
        case "apk":
            return [(None, f"apk add {names}")]
        case "brew":
            return [(None, "\n".join(f"brew install --cask {TAP_NAME}/{p}" for p in packages))]
        case "scoop":
            return [(None, "\n".join(f"scoop install {BUCKET}/{p}" for p in packages))]
        case "nix":
            repo = f"git+{_url('nix')}/{NIX_REPO}"
            return [(None, "\n".join(f"nix profile add '{repo}#{p}'" for p in packages))]
        case _:
            return [(None, f"flatpak --user install {REMOTE} {app}") for app in packages]


def scoop_step() -> Step:
    """Add the Scoop bucket, which Scoop clones with Git."""
    return Step(
        "Add the bucket",
        "Scoop clones the bucket over HTTPS with Git and checks the SHA-256 of each download.",
        ((None, f"scoop bucket add {BUCKET} {_url('scoop')}/{REPO}"),),
    )


def steps(
    name: str,
    history: Sequence[AdmittedAsset],
    packages: Sequence[str],
    fingerprint: str,
    *,
    public_key: str | None = None,
) -> list[Step]:
    """Trust the key, add the repository, and install the packages of one project."""
    url = _url(name)
    key = f"{url}/keys/haberdasher.asc"
    trust = "Trust the signing key"
    add = "Add the repository"
    last = Step(f"Install {' '.join(packages)}", "", tuple(install(name, packages)))
    match name:
        case "scoop":
            return [scoop_step(), last]
        case "brew":
            return [
                Step(
                    "Add the tap",
                    "Homebrew clones the tap over HTTPS and checks the SHA-256 of each download.",
                    ((None, f"brew tap {TAP_NAME} {url}/{TAP}"),),
                ),
                Step(
                    last.title,
                    "These apps are not yet signed by Apple, so each cask removes the quarantine "
                    "flag after install.",
                    last.commands,
                ),
            ]
        case "nix":
            conf_key = public_key or f"$(curl -fsSL {url}/keys/haberdasher-nix.pub)"
            conf = _heredoc(
                "sudo tee -a",
                "/etc/nix/nix.conf",
                f"extra-substituters = {url}\nextra-trusted-public-keys = {conf_key}\n",
                expand=public_key is None,
            )
            cache_commands = (
                ((None, nix_settings(url, public_key)), (None, conf))
                if public_key
                else ((None, conf),)
            )
            return [
                Step(
                    "Trust the binary cache",
                    'Haberdasher signs store paths with <a href="keys/haberdasher-nix.pub">'
                    '<code class="nw">keys/haberdasher-nix.pub</code></a>, derived from the '
                    "OpenPGP signing key. Add the cache in NixOS, or append it to "
                    '<code class="nw">/etc/nix/nix.conf</code>.',
                    cache_commands,
                    check=True,
                ),
                Step(
                    "Add the flake input",
                    'Add this input in <code class="nw">flake.nix</code> for NixOS or Home '
                    "Manager, or skip to step 3.",
                    ((None, f'inputs.haberdasher.url = "git+{url}/{NIX_REPO}";'),),
                ),
                last,
            ]
        case "apt":
            sources = _heredoc(
                "sudo tee",
                "/etc/apt/sources.list.d/haberdasher.sources",
                apt_sources(url, APT_KEYRING, "$(dpkg --print-architecture)"),
                expand=True,
            )
            return [
                Step(
                    trust,
                    "Install the key into the APT keyring, then check that the fingerprint "
                    "matches.",
                    (
                        (
                            None,
                            "sudo install -d -m 0755 /etc/apt/keyrings\n"
                            f"curl -fsSL {url}/keys/haberdasher.gpg | sudo tee {APT_KEYRING} "
                            "> /dev/null",
                        ),
                    ),
                    check=True,
                ),
                Step(
                    add,
                    "Write the deb822 source for your architecture, then update the package lists.",
                    ((None, f"{sources}\nsudo apt-get update"),),
                ),
                last,
            ]
        case "rpm":
            repo = _heredoc("sudo tee", "/etc/yum.repos.d/haberdasher.repo", rpm_repo(url, key))
            return [
                Step(
                    trust,
                    "Import the key into RPM, then check that the fingerprint matches.",
                    ((None, f"sudo rpm --import {key}"),),
                    check=True,
                ),
                Step(
                    add,
                    "The switch also changes the install and remove commands.",
                    (
                        ("dnf", repo),
                        (
                            "zypper",
                            f"sudo zypper addrepo --gpgcheck --refresh {url} haberdasher\n"
                            "sudo zypper refresh",
                        ),
                    ),
                    switch=True,
                ),
                last,
            ]
        case "arch":
            section = _heredoc(
                "sudo tee -a", "/etc/pacman.conf", "\n" + pacman_repo(url + "/$arch")
            )
            return [
                Step(
                    trust,
                    "Add the key to the pacman keyring and sign it locally, then check that the "
                    "fingerprint matches.",
                    (
                        (
                            None,
                            f"curl -fsSL {key} | sudo pacman-key --add -\n"
                            f"sudo pacman-key --lsign-key {fingerprint}",
                        ),
                    ),
                    check=True,
                ),
                Step(
                    add,
                    "Append the section to /etc/pacman.conf. SigLevel = Required keeps signature "
                    "checks on.",
                    ((None, section),),
                ),
                last,
            ]
        case "apk":
            return [
                Step(
                    trust,
                    'Run these commands as root. APK trusts the PEM file <a href="keys/'
                    'haberdasher.rsa.pub"><code class="nw">keys/haberdasher.rsa.pub</code></a>, '
                    "the same RSA key.",
                    (
                        (
                            None,
                            "wget -qO /etc/apk/keys/haberdasher.rsa.pub "
                            f"{url}/keys/haberdasher.rsa.pub",
                        ),
                    ),
                    check=True,
                ),
                Step(
                    add,
                    "Append the repository URL and refresh the index.",
                    ((None, f"echo {url} >> /etc/apk/repositories\napk update"),),
                ),
                last,
            ]
        case _:
            remotes = [
                *_runtime_remotes(history),
                f"flatpak --user remote-add --if-not-exists {REMOTE} {url}/{FLATPAKREPO}",
            ]
            return [
                Step(
                    trust,
                    "The .flatpakrepo file carries the signing key, so Flatpak checks every "
                    "commit and summary. This command prints the fingerprint to compare.",
                    (),
                    check=True,
                    check_note=False,
                ),
                Step(
                    add,
                    "Add Flathub for the runtime, then add this repository. Both are user remotes.",
                    ((None, "\n".join(remotes)),),
                ),
                last,
            ]


def remove(name: str, fingerprint: str) -> tuple[str, list[Command]]:
    """A caption and the commands that undo the setup steps."""
    url = _url(name)
    keyid = f"gpg-pubkey-{fingerprint[-8:].lower()}"
    match name:
        case "apt":
            return (
                "",
                [
                    (
                        None,
                        f"sudo rm /etc/apt/sources.list.d/haberdasher.sources {APT_KEYRING}\n"
                        "sudo apt-get update",
                    )
                ],
            )
        case "rpm":
            return (
                "",
                [
                    ("dnf", f"sudo rm /etc/yum.repos.d/haberdasher.repo\nsudo rpm -e {keyid}"),
                    ("zypper", f"sudo zypper removerepo haberdasher\nsudo rpm -e {keyid}"),
                ],
            )
        case "arch":
            return (
                "",
                [
                    (
                        None,
                        "sudo sed -i '/^\\[haberdasher\\]$/,/^Server = /d' /etc/pacman.conf\n"
                        f"sudo pacman-key --delete {fingerprint}",
                    )
                ],
            )
        case "brew":
            return ("Uninstall its casks first.", [(None, f"brew untap {TAP_NAME}")])
        case "scoop":
            return ("Uninstall its apps first.", [(None, f"scoop bucket rm {BUCKET}")])
        case "nix":
            host = (urlsplit(url).hostname or "nix.wimpys.world").replace(".", r"\.")
            return (
                "Remove installed packages from your profile first. "
                "On NixOS, delete the flake input and cache settings instead.",
                [(None, f"sudo sed -i '/{host}/d' /etc/nix/nix.conf")],
            )
        case "apk":
            return (
                "Run these commands as root.",
                [
                    (
                        None,
                        f"sed -i '\\|^{url}$|d' /etc/apk/repositories\n"
                        "rm /etc/apk/keys/haberdasher.rsa.pub",
                    )
                ],
            )
        case _:
            return (
                "Uninstall its applications first.",
                [(None, f"flatpak --user remote-delete {REMOTE}")],
            )


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
        case "brew" | "scoop" | "nix":
            return _field(r"(.+)", metadata.get("desc"))
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


def _copy_button(label: str, data: str | None = None) -> str:
    extra = f' data-copy="{_e(data)}"' if data else ""
    return (
        f'<button type="button" class="copy"{extra} aria-label="{_e(label)}">'
        f"{COPY_ICON}<span>Copy</span></button>"
    )


def _token(token: str) -> str:
    """Keep a token whole. Long paths and URLs may break before each / outside ://."""
    if token.startswith("-") or len(token) < 28 or "/" not in token:
        return f'<span class="tok">{token}</span>'
    parts = re.split(r"(?<![/:])(?=/)", token)
    inner = "<wbr>".join(f'<span class="tok">{part}</span>' for part in parts if part)
    return f'<span class="tok br">{inner}</span>'


def _code(command: str, variant: str | None = None, label: str = "Copy command") -> str:
    tag = f'<span class="pm-tag" aria-hidden="true">{_PM[variant]}</span>' if variant else ""
    classes = "code" + (f" tagged for-{variant}" if variant else "")
    name = f"{label} ({_PM[variant]})" if variant else label
    text = re.sub(r"(\S+)", lambda match: _token(match[1]), _e(command))
    return (
        f'<div class="{classes}">{tag}<pre><code translate="no">{text}</code></pre>'
        f"{_copy_button(name)}</div>"
    )


def _fingerprint(fingerprint: str) -> str:
    groups = [fingerprint[i : i + 4] for i in range(0, len(fingerprint), 4)]
    spans = "".join(
        f'<span class="tail">{_e(group)}</span>'
        if i >= len(groups) - 2
        else f"<span>{_e(group)}</span>"
        for i, group in enumerate(groups)
    )
    return (
        '<div class="fp"><div><p class="fp-label">Expected fingerprint</p>'
        f'<p class="groups" translate="no" aria-hidden="true">{spans}</p>'
        f'<span class="vh">{_e(" ".join(groups))}</span>'
        '<p class="fp-note">The last eight characters are the key ID.</p></div>'
        f"{_copy_button('Copy fingerprint', fingerprint)}</div>"
    )


def _switch(slug: str) -> str:
    slug = _e(slug)
    return (
        '<fieldset class="pm"><legend>Package manager</legend>'
        f'<input type="radio" name="pm-{slug}" id="pm-{slug}-dnf" value="dnf" checked>'
        f'<label for="pm-{slug}-dnf">DNF</label>'
        f'<input type="radio" name="pm-{slug}" id="pm-{slug}-zypper" value="zypper">'
        f'<label for="pm-{slug}-zypper">zypper</label></fieldset>'
    )


def _breakable(name: str) -> str:
    """Break hashes every 16 characters and long names after . _ or -."""
    if re.fullmatch(r"[0-9a-f]{40,}", name):
        return "<wbr>".join(_e(name[i : i + 16]) for i in range(0, len(name), 16))
    return re.sub(r"([._-])(?=.)", r"\1<wbr>", _e(name)) if len(name) > 14 else _e(name)


def files(objects: Sequence[ObjectRef]) -> dict[str, int]:
    """The size of every published package repository file, without the inventory, page, or image."""
    hidden = (state.INVENTORY_KEY, PAGE_KEY, IMAGE_KEY)
    return {ref.key: ref.size for ref in objects if ref.key not in hidden}


# The top-level directories that each format shows on one row, and the description of their files.
FOLDS: dict[str, dict[str, tuple[str, str]]] = {
    "flatpak": {"objects": ("OSTree object", "content-addressed")},
    "brew": {TAP: ("file", "Git repository")},
    "scoop": {REPO.split("/")[0]: ("file", "Git repository")},
    "nix": {
        NIX_REPO: ("file", "Git repository"),
        "nar": ("NAR archive", "content-addressed"),
    },
}


def _tree(sizes: Mapping[str, int], prefix: str, folds: Mapping[str, tuple[str, str]]) -> str:
    directories: dict[str, dict[str, int]] = {}
    leaves: list[tuple[str, int]] = []
    for key, size in sizes.items():
        head, separator, rest = key.partition("/")
        if separator:
            directories.setdefault(head, {})[rest] = size
        else:
            leaves.append((key, size))
    items: list[str] = []
    for directory in sorted(directories):
        inner = directories[directory]
        total = size_text(sum(inner.values()))
        if not prefix and directory in folds:
            noun, note = folds[directory]
            items.append(
                f'<li><div class="frow"><span></span>{FOLDER_CLOSED}<span class="name">'
                f'{_e(directory)}/<span class="meta">{plural(len(inner), noun)}, '
                f'{note}</span></span><span class="size">{total}</span></div></li>'
            )
            continue
        items.append(
            f"<li><details><summary>{CHEVRON}{FOLDER_CLOSED}{FOLDER_OPEN}"
            f'<span class="name">{_e(directory)}/<span class="meta">'
            f'{plural(len(inner), "file")}</span></span><span class="size">{total}</span>'
            f"</summary>{_tree(inner, f'{prefix}{directory}/', folds)}</details></li>"
        )
    for name, size in sorted(leaves):
        aux = ' class="aux"' if name.endswith((".sig", ".asc")) and len(leaves) > 2 else ""
        items.append(
            f'<li{aux}><a href="{_e(quote(prefix + name))}"><span></span>{FILE_ICON}'
            f'<span class="name">{_breakable(name)}</span>'
            f'<span class="size">{size_text(size)}</span></a></li>'
        )
    body = "".join(items)
    return f"<ul>{body}</ul>" if prefix else f'<ul class="tree">{body}</ul>'


def tree(name: str, sizes: Mapping[str, int]) -> str:
    """Nested disclosures of the published files, with large object and Git trees on one row."""
    return _tree(sizes, "", FOLDS.get(name, {}))


def _favicon(colour: str) -> str:
    svg = (
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
        f"<rect width='32' height='32' rx='6' fill='{colour}'/>"
        "<path d='M8 11l8-4 8 4v10l-8 4-8-4zM8 11l8 4 8-4M16 15v10' fill='none' "
        "stroke='white' stroke-width='2.5' stroke-linejoin='round'/></svg>"
    )
    return "data:image/svg+xml," + quote(svg)


def _mark(path: str, classes: str = "") -> str:
    attrs = f' class="{classes}"' if classes else ""
    return (
        f'<svg{attrs} viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
        f'<path d="{path}"/></svg>'
    )


def _title(project: Project) -> tuple[str, str]:
    """The display name and the fragment id of a project, from its repository name."""
    short = project.repository.split("/")[1]
    return short[:1].upper() + short[1:], short.lower()


def _names(project: Project) -> list[str]:
    return list(dict.fromkeys(package for package, _, _ in project.packages))


def _panel(
    name: str,
    project: Project,
    history: Sequence[AdmittedAsset],
    refs: set[str],
    fingerprint: str,
    *,
    hidden: bool,
    public_key: str | None = None,
) -> str:
    title, slug = _title(project)
    names = _names(project)
    tiles = "".join(
        f"<div><dt>Package</dt><dd>{_e(package)}</dd></div>"
        f"<div><dt>Version</dt><dd>{_e(version)}</dd></div>"
        f"<div><dt>Architectures</dt><dd>{_e(', '.join(architectures))}</dd></div>"
        for package, version, architectures in project.packages
    )
    quick = ""
    flatpakrefs = [f"{app}.flatpakref" for app in names if f"{app}.flatpakref" in refs]
    if name == "flatpak" and flatpakrefs:
        flatpakref = flatpakrefs[0]
        quick = (
            '<div class="lead-install"><h4>Quick install</h4>'
            f'<p class="note">One command installs {_e(names[0])} with the repository and its '
            f'runtime. Or open <a href="{_e(quote(flatpakref))}">{_e(flatpakref)}</a> in a '
            "software centre.</p>"
            f"{_code(f'flatpak --user install {_url(name)}/{flatpakref}')}</div>"
            '<h4 class="alt">Or add the repository by hand</h4>'
        )
    items: list[str] = []
    for step in steps(name, history, names, fingerprint, public_key=public_key):
        blocks = "".join(_code(command, variant) for variant, command in step.commands)
        check = ""
        if step.check:
            intro = (
                '<p class="note">Check that this command prints the same fingerprint.</p>'
                if step.check_note
                else ""
            )
            check = (
                f"{intro}{_code(check_command(name), label='Copy check command')}"
                f"{_fingerprint(fingerprint)}"
            )
        note = f'<p class="note">{step.note}</p>' if step.note else ""
        head = f"<h4>{_e(step.title)}</h4>"
        if step.switch:
            head = f'<div class="step-head">{head}{_switch(slug)}</div>'
        items.append(f"<li>{head}{note}{blocks}{check}</li>")
    about = f'<p class="desc">{_e(project.description)}</p>' if project.description else ""
    return (
        f'<section class="panel{" is-hidden" if hidden else ""}" id="{_e(slug)}" '
        f'aria-labelledby="{_e(slug)}-title">'
        f'<div class="project"><div><h3 id="{_e(slug)}-title">{_e(title)}</h3>{about}'
        f'<a class="gh" href="https://github.com/{_e(project.repository)}">{GITHUB_ICON}'
        f"{_e(project.repository)} on GitHub</a></div>"
        f'<dl class="pkg">{tiles}</dl></div>'
        f'{quick}<ol class="steps">{"".join(items)}</ol></section>'
    )


def _empty(name: str) -> str:
    if name != "scoop":
        return "<p>This repository has no packages yet.</p>"
    step = scoop_step()
    blocks = "".join(_code(command, variant) for variant, command in step.commands)
    return (
        '<section class="panel"><p class="desc">No Windows packages are published yet.</p>'
        f'<ol class="steps"><li><h4>{_e(step.title)}</h4><p class="note">{step.note}</p>'
        f"{blocks}</li></ol></section>"
    )


def _tab(project: Project, *, selected: bool) -> str:
    title, slug = _title(project)
    versions = ", ".join(dict.fromkeys(version for _, version, _ in project.packages))
    return (
        f'<li><a id="{_e(slug)}-tab" href="#{_e(slug)}" '
        f'class="{"is-selected" if selected else ""}" data-panel="{_e(slug)}">'
        f'<span class="t-name">{_e(title)}</span><span class="t-ver">{_e(versions)}</span></a></li>'
    )


def _hero_card(entries: Sequence[Project], sizes: Mapping[str, int], now: datetime | None) -> str:
    architectures = sorted({a for p in entries for _, _, items in p.packages for a in items})
    packages = sum(len(project.packages) for project in entries)
    date = (
        ""
        if now is None
        else f'<time datetime="{now.date().isoformat()}">{now.day} {now:%B}</time> '
        f"<small>{now.year}</small>"
    )
    return (
        '<aside class="hero-card" aria-labelledby="hero-card-h">'
        '<h2 id="hero-card-h">In this repository</h2>'
        f"<dl><div><dt>Projects</dt><dd>{len(entries)}</dd></div>"
        f"<div><dt>Packages</dt><dd>{packages} <small>{_e(', '.join(architectures))}</small>"
        "</dd></div>"
        f"<div><dt>Files</dt><dd>{len(sizes)} <small>{size_text(sum(sizes.values()))}</small>"
        "</dd></div>"
        f"<div><dt>Published</dt><dd>{date}</dd></div></dl></aside>"
    )


def _meta(url: str, title: str, lead: str) -> str:
    """The description, OpenGraph, and Twitter card tags for the page and its preview image."""
    image = f"{url}/{IMAGE_KEY}"
    tags = (
        ("name", "description", lead),
        ("property", "og:type", "website"),
        ("property", "og:site_name", TITLE),
        ("property", "og:title", title),
        ("property", "og:description", lead),
        ("property", "og:url", f"{url}/"),
        ("property", "og:image", image),
        ("property", "og:image:width", "1200"),
        ("property", "og:image:height", "630"),
        ("property", "og:image:type", "image/png"),
        ("property", "og:image:alt", f"{title}. {lead}"),
        ("name", "twitter:card", "summary_large_image"),
        ("name", "twitter:title", title),
        ("name", "twitter:description", lead),
        ("name", "twitter:image", image),
    )
    return "\n".join(f'<meta {kind}="{key}" content="{_e(value)}">' for kind, key, value in tags)


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
    url = _url(name)
    title = f"{TITLE} {theme.label} repository"
    lead = f"Packages for projects managed and maintained by {OWNER}."
    lead_html = _e(lead).replace(_e(OWNER), f'<a href="{OWNER_URL}">{_e(OWNER)}</a>')
    links = "\n".join(
        f'<link rel="stylesheet" href="{_e(_CDN + path)}" integrity="{_e(STYLES[path])}" '
        'crossorigin="anonymous">'
        for path in theme.styles
    )
    sites = "".join(
        f'<li><a href="{_e(PUBLIC[other][1])}/"{current}>{_mark(THEMES[other].icon)}'
        f'<span class="full">{_e(THEMES[other].label)}</span>'
        f'<span class="short" aria-hidden="true">{_e(THEMES[other].short)}</span></a></li>'
        for other in PUBLIC
        for current in (' aria-current="page"' if other == name else "",)
    )
    works = "".join(
        f'<li><i style="--m:url(&quot;{_ICONS}{slug}.svg&quot;)"></i>{_e(label)}</li>'
        if slug
        else f'<li><b class="txt">{_e(label)}</b></li>'
        for slug, label in theme.works
    )
    history = published.retained.accepted_history
    entries = projects(history, fallback)
    refs = {ref.key for ref in published.objects}
    sizes = files(published.objects)
    tabs = (
        '<ul class="tablist" aria-label="Projects">'
        + "".join(_tab(project, selected=i == 0) for i, project in enumerate(entries))
        + "</ul>"
        if len(entries) > 1
        else ""
    )
    raw_key = published.retained.metadata.get("public_key")
    public_key = raw_key if isinstance(raw_key, str) and raw_key else None
    panels = "".join(
        _panel(name, project, history, refs, fingerprint, hidden=i > 0, public_key=public_key)
        for i, project in enumerate(entries)
    ) or _empty(name)
    caption, commands = remove(name, fingerprint)
    removal = (f"<p>{_e(caption)}</p>" if caption else "") + "".join(
        _code(command, variant) for variant, command in commands
    )
    published_on = (
        ""
        if now is None
        else f'<time datetime="{now.date().isoformat()}">{now.day} {now:%B %Y}</time>'
    )
    total = sum(sizes.values())
    return f"""<!doctype html>
<html lang="en" class="no-js">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="haberdasher-content" content="{digest}">
{_meta(url, title, lead)}
<title>{_e(title)}</title>
<link rel="icon" href="{_e(_favicon(theme.favicon))}">
{links}
<style>
/* ---- shared base ---- */{BASE_CSS}
/* ---- theme: {name} ---- */{theme.css}</style>
</head>
<body>
<a class="skip" href="#main">Skip to the main content</a>
<header>
<div class="bar"><div class="wrap">
<a class="brand" href="{_e(url)}/">{BRAND_MARK}<span>{_e(TITLE)}</span></a>
<nav aria-label="Repositories"><ul class="sites">{sites}</ul></nav>
</div></div>
<div class="masthead"><div class="wrap">
{_mark(theme.icon, "mark")}
<div>
<h1><span>{_e(TITLE)}</span> <span>{_e(theme.label)} repository</span></h1>
<p class="lead">{lead_html}</p>
<ul class="works" aria-label="Works with"><li class="label">Works with</li>{works}</ul>
</div>
{_hero_card(entries, sizes, now)}
</div></div>
</header>
<main id="main">
<section class="section" aria-labelledby="install-h">
<div class="wrap">
<h2 id="install-h">Install</h2>
{tabs}
{panels}
<details class="fold"><summary id="remove-h">{CHEVRON}Remove this repository\
<span class="sub">Undo the steps above</span></summary>
<div class="body">{removal}</div></details>
</div>
</section>
<section class="section" aria-labelledby="files-h">
<div class="wrap">
<h2 id="files-h">Published files</h2>
<div class="tree-wrap">
<div class="tree-sum"><span><strong>{plural(len(sizes), "file")}</strong> in this repository\
</span><span><strong>{size_text(total)}</strong> total</span></div>
{tree(name, sizes)}
</div>
</div>
</section>
</main>
<footer class="foot"><div class="wrap">
<p>Last published {published_on}.</p>
<p>Published with <a href="{SOURCE}">Haberdasher</a>.</p>
</div></footer>
<p id="copy-status" class="vh" aria-live="polite"></p>
<script>{JS}</script>
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


def image(name: str) -> bytes:
    """The OpenGraph preview image that the package ships for one format."""
    return (resources("haberdasher") / "og" / f"{name}.png").read_bytes()


def image_ref(name: str, data: bytes) -> ObjectRef:
    return ObjectRef(
        name,
        IMAGE_KEY,
        "page",
        len(data),
        hashlib.sha256(data).hexdigest(),
        "image/png",
        "public, max-age=86400",
    )
