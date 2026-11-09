"""Plan, publish, and unlock commands for haberdasher.yaml."""

from __future__ import annotations

import argparse
import stat
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from haberdasher import discovery, publish, signing, state
from haberdasher.config import (
    PRODUCTION_FINGERPRINT,
    PUBLIC,
    Config,
    Policy,
    StoragePolicy,
    load_config,
)
from haberdasher.core import plural, step, utc_now
from haberdasher.runtime import private_workspace
from haberdasher.storage import LocalStore, R2Store, Store

CONFIG = Path("haberdasher.yaml")
HTTP_TIMEOUT = 30


@dataclass
class Arguments:
    command: str = ""
    local_root: Path | None = None


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="haberdasher",
        description="Publish the release assets in haberdasher.yaml to package repositories.",
        epilog=(
            "Rerun publish to recover from an interrupted run. "
            "Use HD_SIGNING_KEY_FILE locally or HD_SIGNING_KEY in CI."
        ),
    )
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("plan", help="discover releases without storage or signing")
    for name, text in (
        ("publish", "publish every configured format to its R2 bucket"),
        ("unlock", "delete existing haberdasher.lock objects after a stopped run, then exit"),
    ):
        command = commands.add_parser(name, help=text)
        command.add_argument("--local-root", type=Path, help=argparse.SUPPRESS)
    return result


def _checkout_root(path: Path) -> Path | None:
    for directory in (path, *path.parents):
        try:
            mode = (directory / ".git").lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            return directory
    return None


def _local_root(path: Path) -> Path:
    root = path.absolute()
    for parent in (root, *root.parents):
        if parent.is_symlink():
            raise ValueError("Local storage must not use symlinks")
    root = root.resolve()
    working_path = Path.cwd().resolve()
    caller_checkout = _checkout_root(working_path) or working_path
    source_checkout = _checkout_root(Path(__file__).resolve().parent)
    if (
        root == Path.home()
        or root in Path.home().parents
        or root.is_relative_to(caller_checkout)
        or (source_checkout is not None and root.is_relative_to(source_checkout))
        or working_path.is_relative_to(root)
    ):
        raise ValueError("Use a disposable local root outside the checkout and home root")
    return root


def _storage(names: Sequence[str], root: Path | None) -> StoragePolicy:
    if root is not None:
        return StoragePolicy("local", {name: str(root / "public" / name) for name in names})
    return StoragePolicy("r2", {name: PUBLIC[name][0] for name in names})


def _published(name: str, root: Path | None) -> bool:
    """Whether a format already has a public inventory to preserve."""
    if root is not None:
        return (root / "public" / name / state.INVENTORY_KEY).is_file()
    return read_published(name, PUBLIC[name][1]).sha256 is not None


def say(line: str) -> None:
    print(line, flush=True)


def _repositories(count: int) -> str:
    return f"{count} {'repository' if count == 1 else 'repositories'}"


def read_published(name: str, url: str) -> state.Published:
    """Read one format's public haberdasher.json without credentials. HTTP 404 is empty."""
    request = urllib.request.Request(
        f"{url.rstrip('/')}/{state.INVENTORY_KEY}", headers={"User-Agent": "haberdasher"}
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            data = response.read(state.MAX_INVENTORY_BYTES + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return state.unpublished(name)
        raise
    if len(data) > state.MAX_INVENTORY_BYTES:
        raise ValueError(f"{state.INVENTORY_KEY} exceeds its size limit")
    return state.decode_published(name, data, None)


def _urls() -> dict[str, str]:
    return {name: url for name, (_, url) in PUBLIC.items()}


def show_plan(scan: discovery.CompleteScan, urls: Mapping[str, str] | None = None) -> None:
    """Print published and new package counts for each format found or already published."""
    urls = _urls() if urls is None else urls
    hosts = {name: urlsplit(url).hostname or url for name, url in urls.items()}
    say(f"Reading published state from {', '.join(hosts.values())}")
    published: dict[str, state.Published] = {}
    for name, url in urls.items():
        try:
            published[name] = read_published(name, url)
        except urllib.error.HTTPError as error:
            step(say, name, f"cannot read {hosts[name]}: HTTP {error.code}")
        except urllib.error.URLError as error:
            step(say, name, f"cannot reach {hosts[name]}: {error.reason}")
        except (OSError, ValueError, RuntimeError) as error:
            step(say, name, f"cannot read {hosts[name]}: {error}")
    found = publish.provided(scan)
    names = [
        name
        for name in urls
        if name in found or name not in published or published[name].sha256 is not None
    ]
    new = publish.new_assets(scan, {name: published[name] for name in names if name in published})
    if not names:
        say("")
        say("No packages found. Nothing written.")
        return
    rows = [("Format", "Repository", "Published", "New")]
    for name in names:
        if name in published:
            history = published[name].retained.accepted_history
            count = str(len({asset.inspected.identity for asset in history}))
            rows.append((name, hosts[name], count, str(len(new[name]))))
        else:
            rows.append((name, hosts[name], "?", "?"))
    widths = [max(len(row[column]) for row in rows) for column in range(4)]
    say("")
    for row in rows:
        say(
            f"{row[0]:<{widths[0]}}  {row[1]:<{widths[1]}}  "
            f"{row[2]:>{widths[2]}}  {row[3]:>{widths[3]}}"
        )
    say("")
    total = sum(len(items) for items in new.values())
    missing = [name for name in names if name not in published]
    stale = [name for name in names if name in published and publish.has_expiry(published[name])]
    for name in stale:
        step(say, name, "pending: refresh metadata without Valid-Until")
    if total:
        summary = f"{plural(total, 'new package')}. Nothing written."
    elif stale:
        summary = f"No new packages. {', '.join(stale)} metadata needs a refresh. Nothing written."
    else:
        summary = "No new packages. Nothing written."
    if missing:
        summary += f" Could not read {', '.join(missing)}, so the plan is incomplete."
    elif total:
        summary += " Run `just publish` to publish them."
    elif stale:
        summary += " Run `just publish` to refresh it."
    say(summary)


def main(argv: Sequence[str] | None = None) -> int:
    command = parser()
    args = Arguments()
    command.parse_args(argv, namespace=args)
    try:
        root = _local_root(args.local_root) if args.local_root is not None else None
        config = load_config(CONFIG)
        if args.command == "unlock":
            storage = _storage(tuple(PUBLIC), root)
            with private_workspace() as runtime:
                store: Store = (
                    LocalStore(storage) if root is not None else R2Store(storage, runtime=runtime)
                )
                broken = state.break_locks(store, tuple(storage.public), report=say)
            say(f"Removed {plural(len(broken), 'lock')}." if broken else "No locks found.")
            return 0
        _reading(config)
        with private_workspace() as runtime:
            remote = (
                R2Store(_storage(tuple(PUBLIC), None), runtime=runtime)
                if args.command == "publish" and root is None
                else None
            )
            scan = discovery.scan_releases(config, runtime=runtime, report=say)
            if args.command == "plan":
                show_plan(scan)
                return 0
            found = publish.provided(scan)
            names = tuple(name for name in PUBLIC if name in found or _published(name, root))
            if not names:
                say("No packages found. Nothing written.")
                return 0
            storage = _storage(names, root)
            store = remote or LocalStore(storage)
            fingerprint = (
                signing.key_fingerprint(runtime) if root is not None else PRODUCTION_FINGERPRINT
            )
            result = publish.reconcile(
                config,
                Policy(storage, fingerprint),
                store=store,
                runtime=runtime,
                now=utc_now(),
                report=say,
                scan=scan,
            )
            if result.pending_assets:
                say(f"Skipped {plural(result.pending_assets, 'package')} without a checksum.")
            if result.changed:
                say(
                    f"Published {plural(result.packages, 'package')} to "
                    f"{_repositories(result.repositories)}."
                )
            else:
                say(f"Nothing changed in {_repositories(len(storage.public))}.")
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr, flush=True)
        return 1


def _reading(config: Config) -> None:
    say(f"Reading {CONFIG}: {plural(len(config.sources), 'source')}")
