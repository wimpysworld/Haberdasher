"""Plan, publish, and unlock commands for haberdasher.yaml."""

from __future__ import annotations

import argparse
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from haberdasher import discovery, publish, signing, state
from haberdasher.config import PRODUCTION_FINGERPRINT, Config, Policy, StoragePolicy, load_config
from haberdasher.core import FORMATS, canonical_json, utc_now
from haberdasher.runtime import private_workspace
from haberdasher.storage import LocalStore, R2Store, Store

CONFIG = Path("haberdasher.yaml")


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


def _formats(config: Config) -> tuple[str, ...]:
    return config.public_formats() or tuple(sorted(config.formats)) or tuple(sorted(FORMATS))


def _storage(config: Config, root: Path | None) -> StoragePolicy:
    if root is not None:
        return StoragePolicy(
            "local", {name: str(root / "public" / name) for name in _formats(config)}
        )
    configured = config.public_formats()
    if config.storage is None or not configured:
        raise ValueError("Publication needs a storage bucket for a configured format")
    return StoragePolicy("r2", {name: config.storage.public[name] for name in configured})


def main(argv: Sequence[str] | None = None) -> int:
    command = parser()
    args = Arguments()
    command.parse_args(argv, namespace=args)
    try:
        root = _local_root(args.local_root) if args.local_root is not None else None
        config = load_config(CONFIG)
        if args.command == "plan":
            with private_workspace() as runtime:
                scan = discovery.scan_releases(
                    config, runtime=runtime, previous=discovery.DiscoveryState()
                )
            print(
                canonical_json(
                    {
                        "mode": "plan",
                        "formats": _formats(config),
                        "sources": config.sources,
                        "assets": len(scan.state.records),
                        "pending_assets": len(scan.pending),
                        "storage_changed": False,
                    }
                ).decode()
            )
            return 0
        storage = _storage(config, root)
        if root is None:
            Policy(storage, PRODUCTION_FINGERPRINT).require_remote()
        with private_workspace() as runtime:
            store: Store = (
                LocalStore(storage) if root is not None else R2Store(storage, runtime=runtime)
            )
            if args.command == "unlock":
                broken = state.break_locks(store, tuple(storage.public))
                print(canonical_json({"mode": "unlock", "broken": broken}).decode())
                return 0
            fingerprint = (
                signing.key_fingerprint(runtime) if root is not None else PRODUCTION_FINGERPRINT
            )
            policy = Policy(storage, fingerprint)
            result = publish.reconcile(config, policy, store=store, runtime=runtime, now=utc_now())
            print(canonical_json(result).decode())
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
