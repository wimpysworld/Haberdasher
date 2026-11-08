"""Read-only planning and explicit publication and recovery commands."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from haberdasher import discovery, publish, state
from haberdasher.config import Policy, StoragePolicy, load_config, load_policy
from haberdasher.core import FORMATS, canonical_json, safe_key, utc_now
from haberdasher.runtime import private_workspace
from haberdasher.storage import LocalStore, R2Store


@dataclass
class Arguments:
    config: Path = Path("haberdasher.yaml")
    policy_file: Path | None = None
    format: str = "all"
    plan: bool = False
    apply: bool = False
    local_root: Path | None = None
    remote: bool = False
    replay: str | None = None
    recover_owner: str | None = None
    recovery_evidence: Path | None = None


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Plan by default. Publication requires an explicit mode and destination.",
        epilog=(
            "Interrupted replay requires --recover-owner NONCE --recovery-evidence PATH. "
            "Evidence is schema-version-1 JSON with stopped_owner, requests_resolved, "
            "reference, runner_identity and writes (ordinal, outcome, etag). "
            "Use HD_SIGNING_KEY_FILE locally or HD_SIGNING_KEY in CI."
        ),
    )
    result.add_argument("--config", type=Path, default=Path("haberdasher.yaml"))
    result.add_argument("--policy-file", type=Path)
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
    modes.add_argument("--apply", action="store_true", help="prepare and publish a generation")
    modes.add_argument("--replay", metavar="GENERATION", help="publish exact pending frozen bytes")
    destination = result.add_mutually_exclusive_group()
    destination.add_argument("--local-root", type=Path, help="explicit disposable storage root")
    destination.add_argument("--remote", action="store_true", help="require approved R2 policy")
    result.add_argument(
        "--recover-owner", metavar="NONCE", help="recover only the named stopped owner"
    )
    result.add_argument(
        "--recovery-evidence", type=Path, help="strict JSON evidence, not a force unlock"
    )
    return result


def _validate(args: Arguments) -> None:
    if bool(args.recover_owner) != bool(args.recovery_evidence):
        raise ValueError("Recovery requires both --recover-owner and --recovery-evidence")
    if args.recover_owner and (args.plan or args.apply):
        raise ValueError("Recovery cannot be combined with --plan or --apply")
    mutation = args.apply or args.replay is not None or args.recover_owner is not None
    if mutation != bool(args.local_root is not None or args.remote):
        raise ValueError("Write modes require exactly one of --local-root or --remote")
    if args.replay is not None and "/" in safe_key(args.replay):
        raise ValueError("Generation ID must be one path component")


def _checkout_root(path: Path) -> Path | None:
    for directory in (path, *path.parents):
        try:
            mode = (directory / ".git").lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            return directory
    return None


def _policy(args: Arguments) -> Policy:
    policy = load_policy(args.policy_file)
    if args.format != "all" and policy.storage.public:
        if args.format not in policy.storage.public:
            raise ValueError(
                f"--format {args.format} is not a configured public format. Use --format all"
            )
        if set(policy.storage.public) != {args.format}:
            raise ValueError("Configured public formats form one publication. Use --format all")
    names = tuple(sorted(policy.storage.public)) or (
        (args.format,) if args.format != "all" else tuple(sorted(FORMATS))
    )
    if args.local_root is not None:
        if policy.storage.backend != "local":
            raise ValueError("--local-root cannot override remote storage policy")
        root = args.local_root.absolute()
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
        policy = replace(
            policy,
            storage=StoragePolicy(
                "local",
                str(root / "private"),
                {name: str(root / "public" / name) for name in names},
            ),
        )
    elif args.remote:
        policy.require_remote(names)
    return policy


def _evidence(path: Path) -> state.RecoveryEvidence:
    with path.open("rb") as stream:
        data = state.parse(stream.read(state.MAX_CONTROL_BYTES + 1))
    del data["schema_version"]
    return state.decode_record(state.RecoveryEvidence, data)


def main(argv: Sequence[str] | None = None) -> int:
    command = parser()
    args = Arguments()
    command.parse_args(argv, namespace=args)
    try:
        _validate(args)
        policy = _policy(args)
        evidence = _evidence(args.recovery_evidence) if args.recovery_evidence else None
        config = load_config(args.config) if args.replay is None and evidence is None else None
        with private_workspace() as runtime:
            if not (args.apply or args.replay or evidence):
                if config is None:
                    raise ValueError("Plan requires configuration")
                scan = discovery.scan_releases(
                    config, runtime=runtime, previous=discovery.DiscoveryState()
                )
                selected = tuple(sorted(FORMATS)) if args.format == "all" else (args.format,)
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
            if args.apply:
                if config is None:
                    raise ValueError("Apply requires configuration")
                result = publish.reconcile(
                    config, policy, store=store, runtime=runtime, now=utc_now()
                )
                print(canonical_json(result).decode())
                return 0
            frozen = state.pending_generation(store)
            if args.replay is not None and (frozen is None or frozen.id != args.replay):
                raise ValueError("Replay must name the pending private generation")
            if args.replay is None and frozen is not None:
                completed = state.read_control(store, "completed.json")
                if (
                    completed is None
                    or state.decode_record(state.FrozenGeneration, completed[0].get("generation"))
                    != frozen
                ):
                    raise ValueError("Pending output requires --replay GENERATION with recovery")
            ownership = (
                state.recover_owner(
                    store, expected_nonce=args.recover_owner or "", evidence=evidence
                )
                if evidence is not None
                else state.acquire(store, owner=f"cli:{os.getpid()}:{uuid.uuid4().hex}")
            )
            if args.replay is not None and frozen is not None:
                result = publish.replay(
                    frozen, store=store, ownership=ownership, runtime=runtime, now=utc_now()
                )
                print(canonical_json(result).decode())
            else:
                state.release(store, ownership)
                print(canonical_json({"recovered": True, "released": True}).decode())
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
