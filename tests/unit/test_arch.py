"""Fail-closed Arch adapter checks without native client dependencies."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from haberdasher.config import FormatPolicy
from haberdasher.core import NativeIdentity, RetainedFormat
from haberdasher.formats import arch
from haberdasher.runtime import Runtime, private_workspace


@pytest.mark.parametrize("reply,expected", [(b"-1\n", -1), (b"0\n", 0), (b"1\n", 1)])
def test_native_comparison(reply: bytes, expected: int, monkeypatch: pytest.MonkeyPatch) -> None:
    def run(self: Runtime, argv: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        if argv[0] != "gpgconf":
            assert tuple(argv) == ("vercmp", "1-1", "1-01")
        return CompletedProcess(argv, 0, reply, b"")

    monkeypatch.setattr(Runtime, "run", run)
    with private_workspace() as runtime:
        assert (
            arch.compare(
                NativeIdentity("arch", "demo", "x86_64", "1-1"),
                NativeIdentity("arch", "demo", "x86_64", "1-01"),
                runtime=runtime,
            )
            == expected
        )


@pytest.mark.parametrize("code,reply", [(1, b"0"), (0, b""), (0, b"2"), (0, b"0\n1")])
def test_failed_comparison(code: int, reply: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    def run(self: Runtime, argv: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        return CompletedProcess(argv, code, reply, b"")

    monkeypatch.setattr(Runtime, "run", run)
    identity = NativeIdentity("arch", "demo", "x86_64", "1-1")
    with private_workspace() as runtime, pytest.raises(arch.ArchFailure):
        arch.compare(identity, identity, runtime=runtime)


def test_distinct_slots_do_not_compare() -> None:
    with private_workspace() as runtime:
        assert (
            arch.compare(
                NativeIdentity("arch", "one", "x86_64", "1-1"),
                NativeIdentity("arch", "two", "x86_64", "1-1"),
                runtime=runtime,
            )
            is None
        )


@pytest.mark.parametrize("architecture", ["any", "aarch64"])
def test_unqualified_placement(architecture: str) -> None:
    with private_workspace() as runtime, pytest.raises(arch.ArchFailure, match="qualified"):
        arch.validate_retained(
            RetainedFormat("arch", None, (), (), {}, ()),
            policy=FormatPolicy("arch", (architecture,)),
            runtime=runtime,
        )


@pytest.mark.parametrize("metadata,prior", [({}, "previous"), ({"paths": {}}, None)])
def test_incomplete_retained(metadata: dict[str, object], prior: str | None) -> None:
    state = RetainedFormat("arch", prior, (), (), {}, ())
    if metadata:
        state.metadata["paths"] = {}
    with private_workspace() as runtime, pytest.raises(arch.ArchFailure, match="Incomplete"):
        arch.validate_retained(state, policy=FormatPolicy("arch"), runtime=runtime)


def test_empty_retained() -> None:
    with private_workspace() as runtime:
        arch.validate_retained(
            RetainedFormat("arch", None, (), (), {}, ()),
            policy=FormatPolicy("arch"),
            runtime=runtime,
        )


def test_no_shell_proof_dependency() -> None:
    assert "tests.proofs" not in Path(arch.__file__).read_text()
    assert "arch.sh" not in Path(arch.__file__).read_text()
