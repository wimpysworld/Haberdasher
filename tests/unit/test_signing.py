import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from haberdasher.core import atomic_write, safe_path
from haberdasher.runtime import Runtime, RuntimeFailure, private_workspace
from haberdasher.signing import (
    MAX_KEY_BYTES,
    NIX_KEY_NAME,
    SigningFailure,
    SigningSession,
    _checked,  # pyright: ignore[reportPrivateUsage]
    _input,  # pyright: ignore[reportPrivateUsage]
    _mpint,  # pyright: ignore[reportPrivateUsage]
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


@pytest.mark.parametrize("failure", [None, "kill", "query", "remove", "start"])
@pytest.mark.parametrize("fallback_fails", [False, True])
def test_session_socket_cleanup_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None, fallback_fails: bool
) -> None:
    with private_workspace() as runtime:
        socketdir = tmp_path / "owned-sockets"
        socketdir.mkdir()
        commands: list[tuple[Path, list[str]]] = []
        home: Path | None = None
        signer: SigningSession | None = None

        def run(
            runner: Runtime, argv: Sequence[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            commands.append((runner.root, list(argv)))
            assert home is not None and argv[:3] == ["gpgconf", "--homedir", str(home)]
            stage = {"--kill": "kill", "--list-dirs": "query", "--remove-socketdir": "remove"}[
                argv[3]
            ]
            fail = (runner is runtime or fallback_fails) and failure in {stage, "start"}
            if fail and failure == "start":
                raise RuntimeFailure("Could not start native command")
            if stage == "remove" and not fail and socketdir.exists():
                socketdir.rmdir()
            return subprocess.CompletedProcess(argv, int(fail), os.fsencode(socketdir) + b"\n", b"")

        def gpg(_session: SigningSession, *args: str, data: bytes | None = None) -> bytes:
            if "--list-keys" in args or "--list-secret-keys" in args:
                return listing(secret="--list-secret-keys" in args)
            return b""

        with monkeypatch.context() as patch:
            patch.setattr(Runtime, "run", run)
            patch.setattr(SigningSession, "_gpg", gpg)
            error = RuntimeFailure if failure == "start" else SigningFailure
            try:
                with signing_session(
                    runtime, expected_fingerprint=FINGERPRINT, key_data=b"synthetic"
                ) as signer:
                    home = signer.gnupghome
            except error:
                assert failure is not None and fallback_fails
            else:
                assert failure is None or not fallback_fails
        assert home is not None and not home.parent.exists()
        assert socketdir.exists() == (failure is not None and fallback_fails)
        expected = ["--kill"]
        if failure not in {"kill", "start"}:
            expected.append("--list-dirs")
            if failure != "query":
                expected.append("--remove-socketdir")
        assert [argv[3] for root, argv in commands if root == runtime.root] == expected
        if failure is not None:
            fallback = [argv[3] for root, argv in commands if root == home.parent]
            assert fallback[: len(expected)] == expected
        assert signer is not None
        with pytest.raises(SigningFailure, match="closed"):
            signer.alpine_key()


def test_reject_invalid_fingerprint_before_import() -> None:
    with private_workspace() as runtime:
        with (
            pytest.raises(ValueError),
            signing_session(runtime, expected_fingerprint="bad", key_data=b"synthetic"),
        ):
            pass


def _asn1_output(
    *,
    version: int = 0,
    n: int | None = None,
    e: int = 65537,
    d: int | None = None,
    p: int = (1 << 2048) - 1,
    q: int = (1 << 2047) + 1,
) -> bytes:
    if n is None:
        n = p * q
    if d is None:
        d = pow(e, -1, (p - 1) * (q - 1))
    values = (version, n, e, d, p, q, d % max(p - 1, 1), d % max(q - 1, 1), 1)
    return "".join(
        f"    0:d=1  hl=2 l=   1 prim: INTEGER           :{value:X}\n" for value in values
    ).encode("ascii")


def test_nix_key_deterministic_hkdf_derivation_and_swapped_primes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SigningFailure, match="positive"):
        _mpint(0)
    assert _mpint(0x0102) == b"\x00\x00\x00\x02\x01\x02"
    pub_bytes = bytes(range(1, 33))
    spki = bytes.fromhex("302a300506032b6570032100") + pub_bytes
    p_a = (1 << 2048) - 1
    q_a = (1 << 2047) + 1
    asn1_a = _asn1_output(p=p_a, q=q_a)
    asn1_swapped = _asn1_output(p=q_a, q=p_a)
    p_b = (1 << 2048) - 1
    q_b = (1 << 2047) + 3
    asn1_b = _asn1_output(p=p_b, q=q_b)

    def fake_which(_cmd: str, *, path: str | None = None) -> str:
        return "/bin/nix"

    def derive(asn1_bytes: bytes) -> tuple[bytes, bytes, str, list[bytes]]:
        seeds: list[bytes] = []
        with private_workspace() as runtime:
            session = SigningSession(runtime, runtime.root / "gnupg", FINGERPRINT)
            priv_pem = runtime.root / "haberdasher.rsa"
            pub_pem = runtime.root / "haberdasher.rsa.pub"
            atomic_write(priv_pem, b"pem")
            atomic_write(pub_pem, b"pub")
            monkeypatch.setattr(session, "_validate", lambda: None)
            monkeypatch.setattr(session, "alpine_key", lambda: (priv_pem, pub_pem))
            monkeypatch.setattr("haberdasher.signing.shutil.which", fake_which)

            def fake_run(argv: Sequence[str], *, data: bytes | None = None) -> bytes:
                if argv[:2] == ["openssl", "rsa"]:
                    return b"der"
                if argv[:2] == ["openssl", "asn1parse"]:
                    return asn1_bytes
                if argv[:2] == ["openssl", "pkey"]:
                    assert data is not None and len(data) == 48
                    seeds.append(data[-32:])
                    return spki
                assert argv[0] == "nix" and data is not None
                raw = data.decode("ascii").strip().split(":", 1)[1]
                import base64

                decoded = base64.b64decode(raw)
                return f"{NIX_KEY_NAME}:{base64.b64encode(decoded[32:]).decode('ascii')}\n".encode()

            monkeypatch.setattr(session, "_run", fake_run)
            sec_path, pub_path, pub_val = session.nix_key()
            assert session.nix_key() == (sec_path, pub_path, pub_val)
            assert sec_path.stat().st_mode & 0o777 == 0o600
            assert pub_path.stat().st_mode & 0o777 == 0o600
            return sec_path.read_bytes(), pub_path.read_bytes(), pub_val, seeds

    sec1, pub1, val1, seeds1 = derive(asn1_a)
    sec2, pub2, val2, seeds2 = derive(asn1_swapped)
    _, _, _, seeds_b = derive(asn1_b)
    assert (sec1, pub1, val1, seeds1) == (sec2, pub2, val2, seeds2)
    assert seeds1 != seeds_b
    assert val1.startswith(f"{NIX_KEY_NAME}:") and pub1 == f"{val1}\n".encode("ascii")


@pytest.mark.parametrize(
    ("fault", "match"),
    [
        ("non-ascii-asn1", "Invalid PKCS#1 ASN.1 output"),
        ("short-asn1", "Invalid PKCS#1 RSA private structure"),
        ("bad-version", "Invalid PKCS#1 RSA private structure"),
        ("bad-bits", "Invalid RSA secret numbers"),
        ("bad-product", "Invalid RSA secret numbers"),
        ("equal-primes", "Invalid RSA secret numbers"),
        ("bad-ed25519-spki", "Invalid derived Ed25519 public key"),
        ("non-ascii-nix", "Invalid native Nix key output"),
        ("nix-mismatch", "Derived Nix key disagrees with native Nix key conversion"),
    ],
)
def test_nix_key_validation_errors(monkeypatch: pytest.MonkeyPatch, fault: str, match: str) -> None:
    p = (1 << 2048) - 1
    q = (1 << 2047) + 1
    asn1 = _asn1_output(p=p, q=q)
    if fault == "non-ascii-asn1":
        asn1 = b"\xff\xfe"
    elif fault == "short-asn1":
        asn1 = b"    0:d=1  hl=2 l=   1 prim: INTEGER           :00\n"
    elif fault == "bad-version":
        asn1 = _asn1_output(version=1, p=p, q=q)
    elif fault == "bad-bits":
        asn1 = _asn1_output(n=61 * 53, e=17, d=413, p=61, q=53)
    elif fault == "bad-product":
        asn1 = _asn1_output(n=p * q + 2, p=p, q=q)
    elif fault == "equal-primes":
        p_eq = (1 << 2047) + (1 << 2046) + 1
        asn1 = _asn1_output(n=p_eq * p_eq, e=3, d=1, p=p_eq, q=p_eq)
    spki = (
        b"bad-spki"
        if fault == "bad-ed25519-spki"
        else bytes.fromhex("302a300506032b6570032100") + bytes(32)
    )
    with private_workspace() as runtime:
        session = SigningSession(runtime, runtime.root / "gnupg", FINGERPRINT)
        priv_pem = runtime.root / "haberdasher.rsa"
        pub_pem = runtime.root / "haberdasher.rsa.pub"
        atomic_write(priv_pem, b"pem")
        atomic_write(pub_pem, b"pub")

        def fake_which(_cmd: str, *, path: str | None = None) -> str:
            return "/bin/nix"

        monkeypatch.setattr(session, "_validate", lambda: None)
        monkeypatch.setattr(session, "alpine_key", lambda: (priv_pem, pub_pem))
        monkeypatch.setattr("haberdasher.signing.shutil.which", fake_which)

        def fake_run(argv: Sequence[str], *, data: bytes | None = None) -> bytes:
            if argv[:2] == ["openssl", "rsa"]:
                return b"der"
            if argv[:2] == ["openssl", "asn1parse"]:
                return asn1
            if argv[:2] == ["openssl", "pkey"]:
                return spki
            if fault == "non-ascii-nix":
                return b"\xff"
            return f"{NIX_KEY_NAME}:wrong\n".encode("ascii")

        monkeypatch.setattr(session, "_run", fake_run)
        with pytest.raises(SigningFailure, match=match):
            session.nix_key()
