"""Read Flatpak and GLib metadata through the pinned introspection libraries."""

from __future__ import annotations

import base64
import json
import sys
from importlib import import_module
from pathlib import Path
from typing import Any

gi = import_module("gi")
gi.require_version("Flatpak", "1.0")
gi.require_version("OSTree", "1.0")
Flatpak: Any = import_module("gi.repository.Flatpak")
Gio: Any = import_module("gi.repository.Gio")
GLib: Any = import_module("gi.repository.GLib")
OSTree: Any = import_module("gi.repository.OSTree")


def inspect_native(request: dict[str, str]) -> dict[str, object]:
    result: dict[str, object] = {}
    if "bundle" in request:
        bundle = Flatpak.BundleRef.new(Gio.File.new_for_path(request["bundle"]))
        result["bundle"] = {
            "ref": bundle.format_ref(),
            "commit": bundle.get_commit(),
            "collection": bundle.get_collection_id() or "",
            "origin": bundle.get_origin(),
            "runtime_repo": bundle.get_runtime_repo_url(),
            "metadata": bytes(bundle.get_metadata().get_data()).decode(),
        }
    if "metadata" in request:
        keyfile = GLib.KeyFile.new()
        data = request["metadata"]
        keyfile.load_from_data(data, len(data.encode()), GLib.KeyFileFlags.NONE)
        result["keyfile"] = {
            group: {key: keyfile.get_string(group, key) for key in keyfile.get_keys(group)[0]}
            for group in keyfile.get_groups()[0]
        }
    if "repository" in request:
        repo = OSTree.Repo.new(Gio.File.new_for_path(request["repository"]))
        repo.open(None)
        commit = request["commit"]
        _, variant, _ = repo.load_commit(commit)
        metadata = variant.get_child_value(0)
        result["commit"] = {
            key: metadata.lookup_value(key, None).unpack()
            for key in ("ostree.ref-binding", "ostree.collection-binding", "xa.metadata")
            if metadata.lookup_value(key, None) is not None
        }
        extra = metadata.lookup_value("xa.extra-data-sources", None)
        result["extra_data"] = extra is not None
        _, detached = repo.read_commit_detached_metadata(commit, None)
        signatures = detached.lookup_value("ostree.gpgsigs", None) if detached else None
        result["signatures"] = (
            [base64.b64encode(bytes(sig)).decode() for sig in signatures.unpack()]
            if signatures
            else []
        )
    if "summary_signature" in request:
        data = Path(request["summary_signature"]).read_bytes()
        if len(data) > 1024 * 1024:
            raise ValueError("Signature metadata exceeds 1 MiB")
        variant = GLib.Variant.new_from_bytes(
            GLib.VariantType.new("a{sv}"), GLib.Bytes.new(data), False
        )
        if not variant.is_normal_form():
            raise ValueError("Invalid signature metadata")
        signatures = variant.lookup_value("ostree.gpgsigs", GLib.VariantType.new("aay"))
        result["signatures"] = (
            [base64.b64encode(bytes(sig)).decode() for sig in signatures.unpack()]
            if signatures
            else []
        )
    return result


if __name__ == "__main__":
    raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Metadata request exceeds 2 MiB")
    print(json.dumps(inspect_native(json.loads(raw))))
