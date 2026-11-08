from dataclasses import replace
from pathlib import Path

import pytest

from haberdasher.admission import AdmissionFailure, admit
from haberdasher.config import FormatPolicy, TrustPolicy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    NativeIdentity,
    SourceAsset,
    VerifiedAsset,
    canonical_json,
)
from haberdasher.runtime import Runtime, RuntimeFailure


def inspected(
    root: Path,
    *,
    format: str = "apt",
    version: str = "1.0",
    sha256: str = "a" * 64,
    commit: str | None = None,
) -> InspectedAsset:
    source = SourceAsset(
        "example/tool",
        1,
        2,
        "input",
        12,
        "2026-01-01T00:00:00Z",
        "https://github.com/example/tool/input",
    )
    verified = VerifiedAsset(source, root / "input", sha256, 12, 3, "c" * 64)
    identity = NativeIdentity(format, "tool", "x86_64", version, source_commit=commit)
    return InspectedAsset(verified, identity, {"complete": True}, {"dependencies": []}, "unsigned")


class NativeDouble:
    def __init__(self, result: int | None = 0) -> None:
        self.result = result
        self.calls: list[tuple[NativeIdentity, NativeIdentity, Runtime]] = []

    def __call__(
        self, left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime
    ) -> int | None:
        self.calls.append((left, right, runtime))
        return self.result


@pytest.mark.parametrize(
    "format,transformation",
    [
        ("apt", "preserve"),
        ("rpm", "rpm-sign"),
        ("arch", "preserve"),
        ("apk", "preserve"),
        ("flatpak", "flatpak-sign"),
    ],
)
def test_new_admission_does_not_mutate_history(
    tmp_path: Path,
    format: str,
    transformation: str,
) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = inspected(tmp_path, format=format, commit="f" * 64 if format == "flatpak" else None)
    compare = NativeDouble()
    history: list[AdmittedAsset] = []
    accepted = admit(item, history, compare=compare, policy=FormatPolicy(format), runtime=runtime)
    assert accepted.inspected is item
    assert accepted.transformation_policy == transformation
    assert accepted.published_sha256 is None
    assert len(accepted.history_key) == 64
    assert not history and not compare.calls
    assert (
        admit(item, (), compare=compare, policy=FormatPolicy(format), runtime=runtime) == accepted
    )


@pytest.mark.parametrize(
    "format,left,right",
    [
        ("apt", "1.0", "1.0-0"),
        ("rpm", "1.01", "1.1"),
        ("arch", "1-1", "1-01"),
        ("apk", "1.0-r1", "1.0-r01"),
        ("flatpak", "1.0", "1.0.0"),
    ],
)
def test_native_equivalence_reuses_the_accepted_record(
    tmp_path: Path,
    format: str,
    left: str,
    right: str,
) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    original = inspected(
        tmp_path, format=format, version=left, commit="f" * 64 if format == "flatpak" else None
    )
    accepted = AdmittedAsset(original, "recorded-transformation", "accepted-history", "d" * 64)
    incoming = replace(original, identity=replace(original.identity, version=right))
    incoming = replace(
        incoming,
        verified=replace(
            incoming.verified,
            source=replace(incoming.verified.source, asset_id=200),
            local_path=tmp_path / "redownload",
        ),
    )
    compare = NativeDouble(0)
    result = admit(
        incoming, (accepted,), compare=compare, policy=FormatPolicy(format), runtime=runtime
    )
    assert result is accepted
    assert compare.calls == [(incoming.identity, original.identity, runtime)]


@pytest.mark.parametrize("format", ["apt", "rpm", "arch", "apk", "flatpak"])
def test_equivalent_identity_with_new_bytes_is_rejected(tmp_path: Path, format: str) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    original = inspected(tmp_path, format=format, commit="f" * 64 if format == "flatpak" else None)
    accepted = AdmittedAsset(original, "preserve", "original")
    changed = replace(original, verified=replace(original.verified, sha256="b" * 64))
    history = [accepted]
    before = canonical_json(history)
    with pytest.raises(AdmissionFailure, match="Changed bytes"):
        admit(
            changed, history, compare=NativeDouble(0), policy=FormatPolicy(format), runtime=runtime
        )
    assert canonical_json(history) == before


def test_all_equivalent_history_is_checked_before_reuse(tmp_path: Path) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = inspected(tmp_path)
    matching = AdmittedAsset(item, "preserve", "matching")
    conflicting = AdmittedAsset(
        replace(item, verified=replace(item.verified, sha256="b" * 64)), "preserve", "conflicting"
    )
    for history in ((matching, conflicting), (conflicting, matching)):
        with pytest.raises(AdmissionFailure, match="Changed bytes"):
            admit(
                item, history, compare=NativeDouble(0), policy=FormatPolicy("apt"), runtime=runtime
            )


@pytest.mark.parametrize("order", [None, -1, 1])
def test_native_slots_and_older_package_versions_are_distinct(
    tmp_path: Path, order: int | None
) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = inspected(tmp_path)
    old = AdmittedAsset(inspected(tmp_path, version="2.0", sha256="b" * 64), "preserve", "old")
    accepted = admit(
        item, (old,), compare=NativeDouble(order), policy=FormatPolicy("apt"), runtime=runtime
    )
    assert accepted.inspected is item and accepted is not old


def test_rpm_epoch_and_release_are_passed_intact(tmp_path: Path) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = inspected(tmp_path, format="rpm")
    item = replace(item, identity=replace(item.identity, epoch=2, release="3"))
    old = replace(item, identity=replace(item.identity, epoch=1, release="99"))
    compare = NativeDouble(1)
    admit(
        item,
        (AdmittedAsset(old, "rpm-sign", "old"),),
        compare=compare,
        policy=FormatPolicy("rpm"),
        runtime=runtime,
    )
    assert compare.calls[0][:2] == (item.identity, old.identity)


@pytest.mark.parametrize("result", [2, -2, True])
def test_invalid_native_comparator_result(tmp_path: Path, result: int) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = inspected(tmp_path)
    with pytest.raises(AdmissionFailure, match="invalid result"):
        admit(
            item,
            (AdmittedAsset(item, "preserve", "old"),),
            compare=NativeDouble(result),
            policy=FormatPolicy("apt"),
            runtime=runtime,
        )


def test_comparator_failure_preserves_history(tmp_path: Path) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = inspected(tmp_path)
    history = [AdmittedAsset(item, "preserve", "old")]
    before = canonical_json(history)

    def fail(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
        del left, right, runtime
        raise RuntimeFailure("native comparator failed")

    with pytest.raises(RuntimeFailure):
        admit(item, history, compare=fail, policy=FormatPolicy("apt"), runtime=runtime)
    assert canonical_json(history) == before


@pytest.mark.parametrize("status", ["unknown", "invalid"])
def test_untrusted_signatures_reject(tmp_path: Path, status: str) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = replace(inspected(tmp_path), upstream_signature=status)
    with pytest.raises(AdmissionFailure, match="not trusted"):
        admit(item, (), compare=NativeDouble(), policy=FormatPolicy("apt"), runtime=runtime)


@pytest.mark.parametrize("format", ["rpm", "apk"])
def test_signed_inputs_need_explicit_trust(tmp_path: Path, format: str) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = replace(inspected(tmp_path, format=format), upstream_signature="verified")
    policy = FormatPolicy(format)
    with pytest.raises(AdmissionFailure, match="explicit trust"):
        admit(item, (), compare=NativeDouble(), policy=policy, runtime=runtime)
    trust = TrustPolicy(True, "synthetic approval", True, ("A" * 40,))
    accepted = admit(
        item, (), compare=NativeDouble(), policy=replace(policy, trust=trust), runtime=runtime
    )
    assert accepted.inspected is item
    for changes in (
        {"approved": False},
        {"approval_reference": None},
        {"allow_signed_upstream": False},
        {"upstream_fingerprints": ()},
    ):
        incomplete = replace(trust, **changes)
        with pytest.raises(AdmissionFailure):
            admit(
                item,
                (),
                compare=NativeDouble(),
                policy=replace(policy, trust=incomplete),
                runtime=runtime,
            )


def test_policy_format_and_cross_format_history(tmp_path: Path) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = inspected(tmp_path)
    with pytest.raises(AdmissionFailure, match="formats differ"):
        admit(item, (), compare=NativeDouble(), policy=FormatPolicy("rpm"), runtime=runtime)
    compare = NativeDouble()
    other = AdmittedAsset(inspected(tmp_path, format="rpm"), "rpm-sign", "rpm")
    assert (
        admit(
            item, (other,), compare=compare, policy=FormatPolicy("apt"), runtime=runtime
        ).inspected
        is item
    )
    assert not compare.calls


def test_flatpak_commit_and_backward_head(tmp_path: Path) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    policy = FormatPolicy("flatpak")
    item = inspected(tmp_path, format="flatpak")
    with pytest.raises(AdmissionFailure, match="exact source commit"):
        admit(item, (), compare=NativeDouble(), policy=policy, runtime=runtime)
    item = replace(item, identity=replace(item.identity, source_commit="e" * 64))
    old = replace(item, identity=replace(item.identity, source_commit="f" * 64))
    history = (AdmittedAsset(old, "flatpak-sign", "old"),)
    with pytest.raises(AdmissionFailure, match="Conflicting commits"):
        admit(item, history, compare=NativeDouble(0), policy=policy, runtime=runtime)
    with pytest.raises(AdmissionFailure, match="backwards"):
        admit(item, history, compare=NativeDouble(-1), policy=policy, runtime=runtime)
    assert (
        admit(item, history, compare=NativeDouble(1), policy=policy, runtime=runtime).inspected
        is item
    )
    assert (
        admit(item, history, compare=NativeDouble(None), policy=policy, runtime=runtime).inspected
        is item
    )


def test_flatpak_repeated_historical_input_reuses_record(tmp_path: Path) -> None:
    runtime = Runtime(tmp_path, environ={"PATH": ""})
    item = inspected(tmp_path, format="flatpak", commit="e" * 64)
    old = AdmittedAsset(item, "flatpak-sign", "old")
    head = AdmittedAsset(
        replace(item, identity=replace(item.identity, version="2.0")), "flatpak-sign", "head"
    )

    def compare(left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime) -> int | None:
        del runtime
        return 0 if left.version == right.version else -1

    assert (
        admit(item, (head, old), compare=compare, policy=FormatPolicy("flatpak"), runtime=runtime)
        is old
    )
