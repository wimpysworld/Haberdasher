"""Bounded configuration and fail-closed operational policy."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import yaml
from yaml.events import (
    AliasEvent,
    Event,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode, Node

from haberdasher.core import (
    FORMATS,
    Record,
    format_name,
    integer,
    repository_name,
    safe_key,
    text,
)

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 10_000
PRODUCTION_FINGERPRINT = "B39939A127C7A8D338F53A3AE132098A87DB88E0"
APPROVAL_GATES = frozenset(
    {
        "private_storage",
        "signing",
        "repository_policy",
        "live_r2",
        "hosted_publication",
        "public_delivery",
        "apk_v2",
        "flatpak_runtime",
    }
)

if not getattr(yaml, "__with_libyaml__", False) or not hasattr(yaml, "CSafeLoader"):
    raise RuntimeError("Haberdasher requires PyYAML CSafeLoader and LibYAML")


class StrictLoader(yaml.CSafeLoader):
    def unique_mapping(self, node: MappingNode, deep: bool = False) -> dict[str, object]:
        result: dict[str, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)  # pyright: ignore[reportUnknownMemberType]
            if not isinstance(key, str) or key == "<<" or key in result:
                raise ValueError("YAML keys must be unique strings without merges")
            result[key] = self.construct_object(value_node, deep=deep)  # pyright: ignore[reportUnknownMemberType]
        return result


def _mapping(loader: StrictLoader, node: Node) -> dict[str, object]:
    if not isinstance(node, MappingNode):
        raise ValueError("Expected a YAML mapping")
    return loader.unique_mapping(node, deep=True)


StrictLoader.add_constructor("tag:yaml.org,2002:map", _mapping)


def _load(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("YAML exceeds 1 MiB")
    depth = nodes = 0
    try:
        events = cast(Iterator[Event], yaml.parse(data, Loader=StrictLoader))  # pyright: ignore[reportUnknownMemberType]
        for event in events:
            if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
                raise ValueError("YAML anchors and aliases are forbidden")
            if isinstance(event, (MappingStartEvent, SequenceStartEvent, ScalarEvent)):
                nodes += 1
                if nodes > MAX_NODES:
                    raise ValueError("YAML exceeds 10,000 nodes")
                if depth + 1 > MAX_DEPTH:
                    raise ValueError("YAML exceeds depth 32")
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                depth -= 1
        loader = StrictLoader(data)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
    except (yaml.YAMLError, UnicodeError) as error:
        raise ValueError("Invalid YAML document") from error
    return _keys(value, None)


def _keys(value: object, allowed: set[str] | frozenset[str] | None) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Expected a mapping")
    if any(not isinstance(key, str) for key in cast(dict[object, object], value)):
        raise ValueError("Expected string mapping keys")
    result = cast(dict[str, object], value)
    if allowed is not None and result.keys() - allowed:
        raise ValueError("Unknown configuration key")
    return result


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("Expected a list of strings")
    result = tuple(text(item, "list item") for item in cast(list[object], value))
    if len(set(result)) != len(result):
        raise ValueError("Duplicate list item")
    return result


def _bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("Expected a Boolean")
    return value


def _token(value: object) -> str:
    value = text(value, "policy token")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", value) is None:
        raise ValueError("Unsafe policy token")
    return value


@dataclass(frozen=True)
class RuntimePolicy(Record):
    url: str
    fingerprint: str
    collection: str
    branch: str
    architecture: str
    remote: str
    refs: tuple[str, ...]
    extensions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        parsed = urlsplit(text(self.url, "runtime URL"))
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError("Invalid runtime URL")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("HTTP runtime URLs must use loopback")
        _fingerprint(self.fingerprint)
        if not isinstance(self.collection, str):
            raise ValueError("Invalid runtime collection")
        if self.collection:
            text(self.collection, "runtime collection")
        for value in (self.branch, self.architecture, self.remote):
            _token(value)
        if not self.refs:
            raise ValueError("Runtime refs are required")
        for ref in (*self.refs, *self.extensions):
            safe_key(ref)


@dataclass(frozen=True)
class TrustPolicy(Record):
    approved: bool = False
    approval_reference: str | None = None
    allow_signed_upstream: bool = False
    upstream_fingerprints: tuple[str, ...] = ()
    source_owner: str | None = None
    refs: tuple[str, ...] = ()
    runtime: RuntimePolicy | None = None

    def __post_init__(self) -> None:
        _bool(self.approved)
        _bool(self.allow_signed_upstream)
        if self.approval_reference is not None:
            text(self.approval_reference, "approval reference")
        for fingerprint in self.upstream_fingerprints:
            _fingerprint(fingerprint)
        if self.source_owner is not None:
            repository_name(f"{self.source_owner}/validation")
        for ref in self.refs:
            safe_key(ref)
        if self.runtime is not None and not isinstance(self.runtime, RuntimePolicy):
            raise ValueError("Invalid runtime policy")


@dataclass(frozen=True)
class FormatPolicy(Record):
    format: str
    architectures: tuple[str, ...] = ("x86_64",)
    suite: str = "stable"
    component: str = "main"
    validity_seconds: int = 604800
    renewal_seconds: int = 172800
    trust: TrustPolicy = field(default_factory=TrustPolicy)

    def __post_init__(self) -> None:
        format_name(self.format)
        if not self.architectures or len(set(self.architectures)) != len(self.architectures):
            raise ValueError("Architectures must be non-empty and unique")
        for architecture in self.architectures:
            _token(architecture)
        _token(self.suite)
        _token(self.component)
        integer(self.validity_seconds, "validity", 1)
        integer(self.renewal_seconds, "renewal", 1)
        if self.validity_seconds > 31 * 86400 or self.renewal_seconds >= self.validity_seconds:
            raise ValueError("Invalid validity or renewal window")
        if not isinstance(self.trust, TrustPolicy):
            raise ValueError("Invalid trust policy")


@dataclass(frozen=True)
class Config(Record):
    sources: tuple[str, ...]
    formats: dict[str, FormatPolicy] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.sources or len({source.lower() for source in self.sources}) != len(
            self.sources
        ):
            raise ValueError("Sources must be non-empty and unique")
        for source in self.sources:
            repository_name(source)
        for name, policy in self.formats.items():
            if not isinstance(policy, FormatPolicy) or name != policy.format:
                raise ValueError("Invalid format policy")

    def format_policy(self, name: str) -> FormatPolicy:
        format_name(name)
        architectures = ("amd64", "arm64") if name == "apt" else ("x86_64",)
        return self.formats.get(name, FormatPolicy(name, architectures=architectures))


@dataclass(frozen=True)
class StoragePolicy(Record):
    backend: str = "local"
    private: str | None = None
    public: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.backend not in {"local", "r2"}:
            raise ValueError("Invalid storage backend")
        locations: list[str] = []
        for name, location in self.public.items():
            format_name(name)
            locations.append(text(location, "public destination"))
        if self.private is not None:
            locations.append(text(self.private, "private destination"))
        if self.backend == "r2":
            for location in locations:
                if re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", location) is None:
                    raise ValueError("Invalid R2 bucket name")
        else:
            paths = [Path(location) for location in locations]
            if any(not path.is_absolute() for path in paths):
                raise ValueError("Local destinations must be absolute")
            resolved = [path.resolve() for path in paths]
            if any(
                left == right or left in right.parents or right in left.parents
                for index, left in enumerate(resolved)
                for right in resolved[index + 1 :]
            ):
                raise ValueError("Storage destinations must not overlap")
        if len(set(locations)) != len(locations):
            raise ValueError("Storage destinations must be distinct")


def _fingerprint(value: object) -> str:
    value = text(value, "fingerprint")
    if re.fullmatch(r"[A-F0-9]{40}", value) is None:
        raise ValueError("Expected an uppercase primary fingerprint")
    return value


@dataclass(frozen=True)
class Policy(Record):
    storage: StoragePolicy = field(default_factory=StoragePolicy)
    approved_formats: tuple[str, ...] = ()
    approval_references: dict[str, str] = field(default_factory=dict)
    expected_signing_fingerprint: str | None = None
    clients: dict[str, TrustPolicy] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.storage, StoragePolicy):
            raise ValueError("Invalid storage policy")
        if len(set(self.approved_formats)) != len(self.approved_formats):
            raise ValueError("Duplicate approved format")
        for name in self.approved_formats:
            format_name(name)
        for name, value in self.approval_references.items():
            if name not in APPROVAL_GATES:
                raise ValueError("Unknown approval gate")
            text(value, "approval reference")
        if self.expected_signing_fingerprint is not None:
            _fingerprint(self.expected_signing_fingerprint)
        for name, policy in self.clients.items():
            format_name(name)
            if not isinstance(policy, TrustPolicy):
                raise ValueError("Invalid client policy")

    def format_policy(self, config: Config, name: str) -> FormatPolicy:
        return replace(config.format_policy(name), trust=self.clients.get(name, TrustPolicy()))

    def require_remote(self, formats: tuple[str, ...]) -> None:
        required = APPROVAL_GATES - {"apk_v2", "flatpak_runtime"}
        if "apk" in formats:
            required |= {"apk_v2"}
        if "flatpak" in formats:
            required |= {"flatpak_runtime"}
        if (
            not formats
            or self.storage.backend != "r2"
            or not self.storage.private
            or self.expected_signing_fingerprint != PRODUCTION_FINGERPRINT
            or not required <= self.approval_references.keys()
        ):
            raise ValueError("Remote publication is not approved")
        for name in formats:
            format_name(name)
            trust = self.clients.get(name, TrustPolicy())
            if (
                name not in self.approved_formats
                or name not in self.storage.public
                or not trust.approved
                or not trust.approval_reference
            ):
                raise ValueError("Format publication is not approved")
            if name == "flatpak" and (
                not trust.source_owner or not trust.refs or not trust.runtime
            ):
                raise ValueError("Flatpak source and runtime approval is incomplete")


def load_config(path: Path) -> Config:
    data = _keys(_load(path), {"sources", "formats"})
    sources = _strings(data.get("sources"))
    policies: dict[str, FormatPolicy] = {}
    for name, value in _keys(data.get("formats", {}), FORMATS).items():
        allowed = {"architectures"}
        if name == "apt":
            allowed |= {"suite", "component", "validity_seconds", "renewal_seconds"}
        values = _keys(value, allowed)
        architectures = _strings(
            values.get("architectures", ["amd64", "arm64"] if name == "apt" else ["x86_64"])
        )
        policies[name] = FormatPolicy(
            name,
            architectures,
            text(values.get("suite", "stable"), "suite"),
            text(values.get("component", "main"), "component"),
            integer(values.get("validity_seconds", 604800), "validity", 1),
            integer(values.get("renewal_seconds", 172800), "renewal", 1),
        )
    return Config(sources, policies)


def _trust(value: object) -> TrustPolicy:
    data = _keys(
        value,
        {
            "approved",
            "approval_reference",
            "allow_signed_upstream",
            "upstream_fingerprints",
            "source_owner",
            "refs",
            "runtime",
        },
    )
    runtime = None
    if "runtime" in data:
        values = _keys(
            data["runtime"],
            {
                "url",
                "fingerprint",
                "collection",
                "branch",
                "architecture",
                "remote",
                "refs",
                "extensions",
            },
        )
        collection = values.get("collection", "")
        if not isinstance(collection, str):
            raise ValueError("Runtime collection must be a string")
        runtime = RuntimePolicy(
            text(values.get("url"), "runtime URL"),
            _fingerprint(values.get("fingerprint")),
            collection,
            _token(values.get("branch")),
            _token(values.get("architecture")),
            _token(values.get("remote")),
            _strings(values.get("refs")),
            _strings(values.get("extensions", [])),
        )
    return TrustPolicy(
        _bool(data.get("approved", False)),
        text(data["approval_reference"], "approval reference")
        if "approval_reference" in data
        else None,
        _bool(data.get("allow_signed_upstream", False)),
        _strings(data.get("upstream_fingerprints", [])),
        text(data["source_owner"], "source owner") if "source_owner" in data else None,
        _strings(data.get("refs", [])),
        runtime,
    )


def load_policy(path: Path | None) -> Policy:
    if path is None:
        return Policy()
    data = _keys(
        _load(path),
        {
            "storage",
            "approved_formats",
            "approval_references",
            "expected_signing_fingerprint",
            "clients",
        },
    )
    values = _keys(data.get("storage", {}), {"backend", "private", "public"})
    public = {
        name: text(value, "public destination")
        for name, value in _keys(values.get("public", {}), FORMATS).items()
    }
    storage = StoragePolicy(
        text(values.get("backend", "local"), "backend"),
        text(values["private"], "private destination") if "private" in values else None,
        public,
    )
    approvals = {
        name: text(value, "approval reference")
        for name, value in _keys(data.get("approval_references", {}), APPROVAL_GATES).items()
    }
    clients = {
        name: _trust(value) for name, value in _keys(data.get("clients", {}), FORMATS).items()
    }
    return Policy(
        storage,
        _strings(data.get("approved_formats", [])),
        approvals,
        _fingerprint(data["expected_signing_fingerprint"])
        if "expected_signing_fingerprint" in data
        else None,
        clients,
    )
