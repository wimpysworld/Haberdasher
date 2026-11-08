import os
import subprocess
from pathlib import Path

import pytest

from haberdasher.core import atomic_write, safe_path
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import (
    MAX_KEY_BYTES,
    SigningFailure,
    SigningSession,
    _checked,  # pyright: ignore[reportPrivateUsage]
    _input,  # pyright: ignore[reportPrivateUsage]
    _validate,  # pyright: ignore[reportPrivateUsage]
    signing_session,
)

FINGERPRINT = "A" * 40
GRIP = "B" * 40


def listing(*, secret: bool = True) -> bytes:
    fields = [
        "sec" if secret else "pub",
        "u",
        "4096",
        "1",
        "1234",
        "1",
        "",
        "",
        "",
        "",
        "",
        "scSC",
        "",
        "",
        "+",
    ]
    return (":".join(fields) + f":\nfpr:::::::::{FINGERPRINT}:\ngrp:::::::::{GRIP}:\n").encode()


@pytest.mark.parametrize("secret", [True, False])
def test_primary_validation(secret: bool) -> None:
    assert _validate(listing(secret=secret), FINGERPRINT, secret=secret) == GRIP


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        listing() + listing(),
        listing() + b"ssb:u:2048:1:\n",
        listing().replace(b"4096", b"2048"),
        listing().replace(b":1:1234", b":22:1234"),
        listing().replace(b"scSC", b"scESC"),
        listing().replace(b"scSC", b"cC"),
        listing().replace(b"sec:u", b"sec:r"),
        listing().replace(b"sec:u", b"sec:e"),
        listing().replace(b"sec:u", b"sec:d"),
        listing().replace(b"sec:u", b"sec:i"),
        listing().replace(b":1::", b":1:1:"),
        listing().replace(b":1::", b":1:invalid:"),
        listing().replace(b"+", b"#"),
        listing().replace(FINGERPRINT.encode(), b"C" * 40),
        listing().replace(GRIP.encode(), b"invalid"),
        b"\xff",
    ],
)
def test_invalid_primary_rejects(bad: bytes) -> None:
    with pytest.raises(SigningFailure):
        _validate(bad, FINGERPRINT, secret=True)


def test_input_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    with private_workspace() as runtime:
        key = runtime.root / "synthetic"
        atomic_write(key, b"synthetic-key")
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key))
        monkeypatch.delenv("HD_SIGNING_KEY", raising=False)
        assert _input(None, None) == b"synthetic-key"
        monkeypatch.delenv("HD_SIGNING_KEY_FILE")
        monkeypatch.setenv("HD_SIGNING_KEY", "synthetic-ci-key")
        assert _input(None, None) == b"synthetic-ci-key"
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key))
        with pytest.raises(SigningFailure, match="exactly one"):
            _input(None, None)
        assert _input(None, b"explicit-synthetic") == b"explicit-synthetic"
        with pytest.raises(SigningFailure, match="exactly one"):
            _input(key, b"ambiguous")
        key.chmod(0o644)
        with pytest.raises(SigningFailure, match="private regular"):
            _input(key, None)
        key.chmod(0o600)
        link = runtime.root / "link"
        link.symlink_to(key)
        assert _input(link, None) == b"synthetic-key"
        for data in (b"", b"x" * (MAX_KEY_BYTES + 1)):
            with pytest.raises(SigningFailure, match="empty or exceeds"):
                _input(None, data)
        monkeypatch.delenv("HD_SIGNING_KEY")
        monkeypatch.delenv("HD_SIGNING_KEY_FILE")
        with pytest.raises(SigningFailure):
            _input(None, None)


@pytest.mark.parametrize("mode", [0o400, 0o600])
@pytest.mark.parametrize("links", ["direct", "directory", "file", "both"])
def test_private_key_file_links(mode: int, links: str, monkeypatch: pytest.MonkeyPatch) -> None:
    with private_workspace() as runtime:
        generation = runtime.root / "generation"
        generation.mkdir(mode=0o700)
        key = generation / "key"
        atomic_write(key, b"fake")
        key.chmod(mode)
        directory = runtime.root / "current"
        directory.symlink_to(generation, target_is_directory=True)
        path = directory / key.name if links in {"directory", "both"} else key
        if links in {"file", "both"}:
            link = runtime.root / "key-link"
            link.symlink_to(path)
            path = link
        assert _input(path, None) == b"fake"
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(path))
        assert _input(None, None) == b"fake"
        assert key.stat().st_mode & 0o777 == mode


@pytest.mark.parametrize("kind", ["missing", "dangling", "loop", "directory", "fifo"])
def test_invalid_key_file_targets(kind: str) -> None:
    with private_workspace() as runtime:
        target = runtime.root / "target"
        link = runtime.root / "key-link"
        link.symlink_to(target)
        if kind == "loop":
            target.symlink_to(link)
        elif kind == "directory":
            target.mkdir(mode=0o700)
        elif kind == "fifo":
            os.mkfifo(target, mode=0o600)
        with pytest.raises(SigningFailure):
            _input(target if kind == "missing" else link, None)


@pytest.mark.parametrize(
    "mode",
    [0o500, 0o700, 0o1400, 0o1600, 0o2400, 0o2600, 0o4400, 0o4600, 0o4700, 0o640, 0o604, 0o644],
)
def test_linked_key_rejects_invalid_permissions(mode: int) -> None:
    with private_workspace() as runtime:
        key = runtime.root / "key"
        atomic_write(key, b"fake")
        key.chmod(mode)
        link = runtime.root / "key-link"
        link.symlink_to(key)
        with pytest.raises(SigningFailure, match="private regular"):
            _input(link, None)


def test_key_file_rejects_other_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    with private_workspace() as runtime:
        key = runtime.root / "key"
        atomic_write(key, b"fake")
        other_uid = os.getuid() + 1
        monkeypatch.setattr(os, "getuid", lambda: other_uid)
        with pytest.raises(SigningFailure, match="owned by the current user"):
            _input(key, None)


@pytest.mark.parametrize("size", [0, MAX_KEY_BYTES, MAX_KEY_BYTES + 1])
def test_key_file_size_limit(size: int) -> None:
    with private_workspace() as runtime:
        key = runtime.root / "key"
        atomic_write(key, b"x" * size)
        link = runtime.root / "key-link"
        link.symlink_to(key)
        if size == MAX_KEY_BYTES:
            assert len(_input(link, None)) == size
        else:
            with pytest.raises(SigningFailure, match="empty or exceeds"):
                _input(link, None)


def test_ambiguous_inputs_reject_before_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_resolve(_path: Path, *, strict: bool = False) -> Path:
        raise AssertionError("Ambiguous input reached file resolution")

    monkeypatch.setattr(Path, "resolve", unexpected_resolve)
    monkeypatch.setenv("HD_SIGNING_KEY_FILE", "/synthetic-unread-key")
    monkeypatch.setenv("HD_SIGNING_KEY", "synthetic-ci-key")
    with pytest.raises(SigningFailure, match="exactly one"):
        _input(None, None)
    with pytest.raises(SigningFailure, match="exactly one"):
        _input(Path("/synthetic-unread-key"), b"synthetic")
    assert _input(None, b"\x00\xffsynthetic\n") == b"\x00\xffsynthetic\n"


@pytest.mark.parametrize("swap", ["missing", "symlink", "public", "fifo", "oversize", "rotation"])
def test_key_file_race_after_resolution(swap: str, monkeypatch: pytest.MonkeyPatch) -> None:
    with private_workspace() as runtime:
        key = runtime.root / "key"
        replacement = runtime.root / "replacement"
        link = runtime.root / "key-link"
        atomic_write(key, b"original")
        atomic_write(replacement, b"replacement")
        link.symlink_to(key)
        actual_resolve = Path.resolve

        def resolve(path: Path, *, strict: bool = False) -> Path:
            resolved = actual_resolve(path, strict=strict)
            if path == link:
                if swap == "rotation":
                    link.unlink()
                    link.symlink_to(replacement)
                else:
                    key.unlink()
                    if swap == "symlink":
                        key.symlink_to(replacement)
                    elif swap == "public":
                        key.write_bytes(b"public")
                        key.chmod(0o644)
                    elif swap == "fifo":
                        os.mkfifo(key, mode=0o600)
                    elif swap == "oversize":
                        key.write_bytes(b"x" * (MAX_KEY_BYTES + 1))
            return resolved

        monkeypatch.setattr(Path, "resolve", resolve)
        if swap == "rotation":
            assert _input(link, None) == b"original"
        else:
            with pytest.raises(SigningFailure):
                _input(link, None)


def test_key_file_growth_after_fstat_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    with private_workspace() as runtime:
        key = runtime.root / "key"
        atomic_write(key, b"fake")
        actual_fstat = os.fstat

        def fstat(descriptor: int) -> os.stat_result:
            info = actual_fstat(descriptor)
            key.write_bytes(b"x" * (MAX_KEY_BYTES + 1))
            return info

        with monkeypatch.context() as patch:
            patch.setattr(os, "fstat", fstat)
            with pytest.raises(SigningFailure, match="empty or exceeds"):
                _input(key, None)


def test_workspace_and_export_symlinks_still_reject() -> None:
    with private_workspace() as runtime:
        destination = runtime.root / "destination"
        destination.mkdir(mode=0o700)
        link = runtime.root / "link"
        link.symlink_to(destination, target_is_directory=True)
        source = runtime.root / "source"
        atomic_write(source, b"fake")
        session = SigningSession(runtime, runtime.root / "gnupg", FINGERPRINT)
        with pytest.raises(ValueError, match="Symlink"):
            safe_path(link, "key")
        with pytest.raises(ValueError, match="Symlink"), private_workspace(link):
            pass
        with pytest.raises(ValueError, match="Symlink"):
            session.public_exports(link)
        with pytest.raises(ValueError, match="Symlink"):
            session.sign_file(source, link / "signature")
        file_link = destination / "haberdasher.asc"
        file_link.symlink_to(source)
        with pytest.raises(ValueError, match="Symlink"):
            session.public_exports(destination)
        with pytest.raises(ValueError, match="Symlink"):
            session.sign_file(file_link, destination / "signature")
        assert not list(destination.glob("signature*"))


def test_environment_is_read_only_and_scoped() -> None:
    with private_workspace() as workspace:
        runtime = Runtime(
            workspace.root,
            environ={
                "PATH": os.defpath,
                "HD_CLOUDFLARE_ACCESS_KEY_ID": "synthetic-storage",
                "GH_TOKEN": "synthetic-github",
                "HD_SIGNING_KEY": "synthetic-private",
            },
        )
        try:
            session = SigningSession(runtime, workspace.root / "gnupg", FINGERPRINT)
            assert session.fingerprint == FINGERPRINT
            assert session.gnupghome == workspace.root / "gnupg"
            assert session.environment["GNUPGHOME"] == str(session.gnupghome)
            assert not any(name.startswith(("HD_", "AWS_", "GH_")) for name in session.environment)
            with pytest.raises(AttributeError):
                session.fingerprint = "C" * 40  # pyright: ignore[reportAttributeAccessIssue]
            with pytest.raises(AttributeError):
                session.gnupghome = Path("/bad")  # pyright: ignore[reportAttributeAccessIssue]
            with pytest.raises(AttributeError):
                session.environment = {}  # pyright: ignore[reportAttributeAccessIssue]
            assert not hasattr(session.environment, "__setitem__")
        finally:
            runtime.close()


def test_command_failure_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    with private_workspace() as runtime:

        def failed(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess(["gpg"], 2, b"", b"private diagnostic")

        monkeypatch.setattr(runtime, "run", failed)
        with pytest.raises(SigningFailure, match="Native signing command failed"):
            _checked(runtime, ["gpg"])


@pytest.mark.parametrize("result", [b"", b"not a signature"])
def test_missing_or_invalid_signature_preserves_output(
    monkeypatch: pytest.MonkeyPatch,
    result: bytes,
) -> None:
    with private_workspace() as runtime:
        session = SigningSession(runtime, runtime.root / "gnupg", FINGERPRINT)
        source, output = runtime.root / "source", runtime.root / "output"
        atomic_write(source, b"input")
        atomic_write(output, b"previous")
        monkeypatch.setattr(session, "_validate", lambda: None)

        def fake(*args: str, data: bytes | None = None) -> bytes:
            if "--output" in args and result:
                atomic_write(Path(args[args.index("--output") + 1]), result)
            return b""

        monkeypatch.setattr(session, "_gpg", fake)
        with pytest.raises(SigningFailure):
            session.sign_file(source, output)
        assert output.read_bytes() == b"previous"
        assert not list(runtime.root.glob("signature-*"))
        with pytest.raises(ValueError, match="armour"):
            session.sign_file(source, output, clear=True, armour=False)


def test_reject_invalid_fingerprint_before_import() -> None:
    with private_workspace() as runtime:
        with (
            pytest.raises(ValueError),
            signing_session(runtime, expected_fingerprint="bad", key_data=b"synthetic"),
        ):
            pass
