"""Read-only planning, explicit publication, and explicit lock release."""

from __future__ import annotations

import argparse
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from haberdasher import discovery, publish, state
from haberdasher.config import PRODUCTION_FINGERPRINT, Config, Policy, StoragePolicy, load_config
from haberdasher.core import FORMATS, canonical_json, utc_now
from haberdasher.runtime import private_workspace
from haberdasher.storage import LocalStore, R2Store


@dataclass
class Arguments:
    config: Path = Path("haberdasher.yaml")
    format: str = "all"
    plan: bool = False
    apply: bool = False
    local_root: Path | None = None
    signing_fingerprint: str | None = None
    remote: bool = False
    break_lock: bool = False


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Plan by default. Publication requires an explicit mode and destination.",
        epilog=(
            "Rerun --apply to recover from an interrupted run. "
            "Use HD_SIGNING_KEY_FILE locally or HD_SIGNING_KEY in CI."
        ),
    )
    result.add_argument("--config", type=Path, default=Path("haberdasher.yaml"))
    result.add_argument(
        "--format",
        choices=("all", *sorted(FORMATS)),
        default="all",
        help=(
            "all configured public formats form one publication (default: all). "
            "A single format must be the only configured public format, "
            "or define a local bootstrap with no configured public destinations"
        ),
    )
    modes = result.add_mutually_exclusive_group()
    modes.add_argument("--plan", action="store_true", help="discover without storage or signing")
    modes.add_argument("--apply", action="store_true", help="publish changes under bucket locks")
    modes.add_argument(
        "--break-lock",
        action="store_true",
        help="delete existing haberdasher.lock objects after a stopped run, then exit",
    )
    destination = result.add_mutually_exclusive_group()
    destination.add_argument("--local-root", type=Path, help="explicit disposable storage root")
    destination.add_argument(
        "--remote", action="store_true", help="publish to the R2 buckets in the configuration"
    )
    result.add_argument(
        "--signing-fingerprint",
        metavar="FINGERPRINT",
        help="signing key fingerprint for --local-root; --remote always uses the production key",
    )
    return result


def _validate(args: Arguments) -> None:
    if (args.apply or args.break_lock) != bool(args.local_root is not None or args.remote):
        raise ValueError("Write modes require exactly one of --local-root or --remote")
    if args.signing_fingerprint is not None and args.local_root is None:
        raise ValueError("--signing-fingerprint requires --local-root")


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


def _policy(args: Arguments, config: Config, root: Path | None) -> Policy:
    configured = config.public_formats()
    if args.format != "all" and configured:
        if args.format not in configured:
            raise ValueError(
                f"--format {args.format} is not a configured public format. Use --format all"
            )
        if set(configured) != {args.format}:
            raise ValueError("Configured public formats form one publication. Use --format all")
    names = configured or ((args.format,) if args.format != "all" else tuple(sorted(FORMATS)))
    if root is not None:
        return Policy(
            StoragePolicy("local", {name: str(root / "public" / name) for name in names}),
            args.signing_fingerprint,
        )
    if args.remote:
        if config.storage is None or not configured:
            raise ValueError("--remote needs a storage bucket for a configured format")
        policy = Policy(
            StoragePolicy("r2", {name: config.storage.public[name] for name in configured}),
            PRODUCTION_FINGERPRINT,
        )
        policy.require_remote()
        return policy
    return Policy()


def main(argv: Sequence[str] | None = None) -> int:
    command = parser()
    args = Arguments()
    command.parse_args(argv, namespace=args)
    try:
        _validate(args)
        root = _local_root(args.local_root) if args.local_root is not None else None
        config = load_config(args.config)
        policy = _policy(args, config, root)
        with private_workspace() as runtime:
            if not (args.apply or args.break_lock):
                scan = discovery.scan_releases(
                    config, runtime=runtime, previous=discovery.DiscoveryState()
                )
                selected = config.public_formats() or (
                    tuple(sorted(FORMATS)) if args.format == "all" else (args.format,)
                )
                print(
                    canonical_json(
                        {
                            "mode": "plan",
                            "formats": selected,
                            "sources": config.sources,
                            "assets": len(scan.state.records),
                            "pending_assets": len(scan.pending),
                            "storage_changed": False,
                        }
                    ).decode()
                )
                return 0
            store = (
                R2Store(policy.storage, runtime=runtime)
                if args.remote
                else LocalStore(policy.storage)
            )
            if args.break_lock:
                broken = state.break_locks(store, tuple(policy.storage.public))
                print(canonical_json({"mode": "break-lock", "broken": broken}).decode())
                return 0
            result = publish.reconcile(config, policy, store=store, runtime=runtime, now=utc_now())
            print(canonical_json(result).decode())
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
