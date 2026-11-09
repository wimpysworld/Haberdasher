"""Native-identity admission without changes to committed history."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Protocol

from haberdasher.config import FormatPolicy
from haberdasher.core import AdmittedAsset, InspectedAsset, NativeIdentity, canonical_json
from haberdasher.runtime import Runtime


class AdmissionFailure(ValueError):
    pass


class NativeCompare(Protocol):
    def __call__(
        self, left: NativeIdentity, right: NativeIdentity, *, runtime: Runtime
    ) -> int | None: ...


def admit(
    inspected: InspectedAsset,
    history: Sequence[AdmittedAsset],
    *,
    compare: NativeCompare,
    policy: FormatPolicy,
    runtime: Runtime,
) -> AdmittedAsset:
    identity = inspected.identity
    if identity.format != policy.format:
        raise AdmissionFailure("Inspection and policy formats differ")
    if inspected.upstream_signature in {"unknown", "invalid"}:
        raise AdmissionFailure("Upstream signature is not trusted")
    if identity.format == "flatpak" and identity.source_commit is None:
        raise AdmissionFailure("Flatpak admission requires an exact source commit")
    equivalent: AdmittedAsset | None = None
    backwards = False
    for accepted in history:
        prior = accepted.inspected
        if prior.identity.format != identity.format:
            continue
        order = compare(identity, prior.identity, runtime=runtime)
        if order is not None and (type(order) is not int or order not in {-1, 0, 1}):
            raise AdmissionFailure("Native comparator returned an invalid result")
        if order == 0:
            if inspected.verified.sha256 != prior.verified.sha256:
                raise AdmissionFailure("Changed bytes for an accepted native identity")
            if identity.source_commit != prior.identity.source_commit:
                raise AdmissionFailure("Conflicting commits for an equivalent native identity")
            if equivalent is None:
                equivalent = accepted
        elif order == -1 and identity.format == "flatpak":
            backwards = True
    if equivalent is not None:
        return equivalent
    if backwards:
        raise AdmissionFailure("Flatpak head cannot move backwards")
    transformation = {"rpm": "rpm-sign", "flatpak": "flatpak-sign"}.get(identity.format, "preserve")
    if identity.format == "apk" and inspected.upstream_signature == "signed":
        transformation = "apk-unsign"
    history_key = hashlib.sha256(canonical_json(identity)).hexdigest()
    return AdmittedAsset(inspected, transformation, history_key)
