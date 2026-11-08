import json
import os
import select
import signal
import subprocess
import sys
from collections.abc import Generator, Sequence
from pathlib import Path

import pytest

from haberdasher.core import atomic_write
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import ALPINE_SIGNATURE_MEMBER, SigningFailure, signing_session
from tests.support.keys import DisposableKey, disposable_key, run


@pytest.fixture(scope="module")
def key() -> Generator[DisposableKey]:
    with disposable_key() as synthetic:
        yield synthetic


def agent_pid(runtime: Runtime, home: Path) -> int:
    response = run(runtime, "gpg-connect-agent", "--homedir", str(home), "GETINFO pid", "/bye")
    return int(next(line[2:] for line in response.splitlines() if line.startswith(b"D ")))


def stopped(pid: int) -> None:
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        assert select.select([descriptor], [], [], 5)[0], "Owned agent did not stop"
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("link_kind,mode", [("directory", 0o400), ("file", 0o600)])
def test_native_signatures_exports_and_same_rsa(
    key: DisposableKey, link_kind: str, mode: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    with private_workspace() as runtime:
        generation = runtime.root / "generation"
        generation.mkdir(mode=0o700)
        secret = generation / "key"
        atomic_write(secret, key.key_file.read_bytes())
        secret.chmod(mode)
        current = runtime.root / "current"
        current.symlink_to(generation, target_is_directory=True)
        key_path = current / "key"
        if link_kind == "file":
            key_path = runtime.root / "key-link"
            key_path.symlink_to(current / "key")
        monkeypatch.setenv("HD_SIGNING_KEY_FILE", str(key_path))
        payload = runtime.root / "payload"
        atomic_write(payload, b"Native signing test\n")
        with signing_session(runtime, expected_fingerprint=key.fingerprint) as signer:
            assert signer.fingerprint == key.fingerprint
            assert secret.stat().st_mode & 0o777 == mode
            assert generation.stat().st_mode & 0o777 == 0o700
            home = signer.gnupghome
            assert not list((runtime.root / "gnupg").glob("private-keys-v1.d/*.key"))
            for clear, armour in ((False, False), (False, True), (True, True)):
                signature = runtime.root / f"signature-{clear}-{armour}"
                signer.sign_file(payload, signature, clear=clear, armour=armour)
                run(runtime, "gpg", "--batch", "--import", str(key.public_file))
                status = run(
                    runtime,
                    "gpg",
                    "--batch",
                    "--status-fd",
                    "1",
                    "--verify",
                    str(signature),
                    *([] if clear else [str(payload)]),
                )
                assert b"VALIDSIG " + key.fingerprint.encode() in status
                assert b" 1 8 " in status
            private, public = signer.alpine_key()
            assert signer.alpine_key() == (private, public)
            assert public.name == "haberdasher.rsa.pub"
            assert ALPINE_SIGNATURE_MEMBER == ".SIGN.RSA256.haberdasher.rsa.pub"
            rsa_signature = runtime.root / "signature.rsa"
            run(
                runtime,
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private),
                "-out",
                str(rsa_signature),
                str(payload),
            )
            assert b"Verified OK" in run(
                runtime,
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public),
                "-signature",
                str(rsa_signature),
                str(payload),
            )
            exports = runtime.root / "keys"
            exports.mkdir(mode=0o700)
            asc, binary, pem = signer.public_exports(exports)
            assert asc.name == "haberdasher.asc" and binary.name == "haberdasher.gpg"
            assert pem.read_bytes() == public.read_bytes()
            assert b"PRIVATE" not in asc.read_bytes() + pem.read_bytes()
            run(runtime, "gpg", "--batch", "--import", str(asc), str(binary))
            assert b"sec:" not in run(
                runtime, "gpg", "--batch", "--with-colons", "--list-secret-keys"
            )
            for path in (home.parent, *home.parent.rglob("*")):
                if path.is_file() or path.is_dir():
                    assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600), path
            pid = agent_pid(runtime, home)
        assert not home.parent.exists()
        stopped(pid)
        with pytest.raises(SigningFailure, match="closed"):
            signer.alpine_key()
    assert not runtime.root.exists()


def test_native_unsigned_and_wrong_key_reject(key: DisposableKey) -> None:
    with disposable_key(algorithm="rsa2048") as wrong_key, private_workspace() as runtime:
        payload, signature = runtime.root / "payload", runtime.root / "signature"
        atomic_write(payload, b"Native verification controls\n")
        with signing_session(
            runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer:
            signer.sign_file(payload, signature)
        run(runtime, "gpg", "--batch", "--import", str(wrong_key.public_file))
        for candidate in (payload, signature):
            result = runtime.run(["gpg", "--batch", "--verify", str(candidate), str(payload)])
            assert result.returncode != 0
        run(runtime, "gpg", "--batch", "--import", str(key.public_file))
        status = run(
            runtime, "gpg", "--batch", "--status-fd", "1", "--verify", str(signature), str(payload)
        )
        assert b"VALIDSIG " + key.fingerprint.encode() in status


@pytest.mark.parametrize("mode", ["fingerprint", "public-only", "bad-data"])
def test_reject_wrong_inputs(key: DisposableKey, mode: str) -> None:
    with private_workspace() as runtime:
        fingerprint = "A" * 40 if mode == "fingerprint" else key.fingerprint
        data = key.public_file.read_bytes() if mode == "public-only" else key.key_file.read_bytes()
        if mode == "bad-data":
            data = b"not a private key"
        before = set(runtime.root.rglob("*"))
        with (
            pytest.raises(SigningFailure),
            signing_session(runtime, expected_fingerprint=fingerprint, key_data=data),
        ):
            pass
        assert set(runtime.root.rglob("*")) == before


@pytest.mark.parametrize(
    "algorithm,usage,subkey",
    [
        ("rsa2048", "sign,cert", False),
        ("ed25519", "sign,cert", False),
        ("rsa4096", "cert", False),
        ("rsa4096", "sign,cert", True),
    ],
)
def test_reject_wrong_native_key_shape(algorithm: str, usage: str, subkey: bool) -> None:
    with disposable_key(algorithm=algorithm, usage=usage, subkey=subkey) as synthetic:
        with private_workspace() as runtime:
            with (
                pytest.raises(SigningFailure),
                signing_session(
                    runtime, expected_fingerprint=synthetic.fingerprint, key_file=synthetic.key_file
                ),
            ):
                pass


def test_long_socket_path_and_exception_cleanup(key: DisposableKey) -> None:
    with private_workspace() as runtime:
        long_parent = runtime.root / ("long" * 30)
        long_parent.mkdir(mode=0o700)
        with private_workspace(long_parent) as nested:
            home: Path | None = None
            pid: int | None = None
            with pytest.raises(ValueError, match="injected"):
                with signing_session(
                    nested, expected_fingerprint=key.fingerprint, key_file=key.key_file
                ) as signer:
                    home = signer.gnupghome
                    assert len(os.fsencode(home / "S.gpg-agent.browser")) < 107
                    pid = agent_pid(runtime, home)
                    raise ValueError("injected")
            assert home is not None and pid is not None
            assert not home.parent.exists()
            stopped(pid)
            assert long_parent.exists()


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_signals_clean_only_owned_agents(key: DisposableKey, sig: signal.Signals) -> None:
    unrelated_pid = agent_pid(key.runtime, Path(key.runtime.environment["GNUPGHOME"]))
    script = f"""import json, signal
from pathlib import Path
from haberdasher.runtime import private_workspace
from haberdasher.signing import signing_session
with private_workspace() as runtime:
    with signing_session(runtime, expected_fingerprint={key.fingerprint!r}, key_file=Path({str(key.key_file)!r})) as signer:
        result = runtime.run(["gpg-connect-agent", "--homedir", str(signer.gnupghome), "GETINFO pid", "/bye"])
        if result.returncode: raise RuntimeError("agent query failed")
        pid = int(next(line[2:] for line in result.stdout.splitlines() if line.startswith(b"D ")))
        print(json.dumps([str(runtime.root), str(signer.gnupghome.parent), pid]), flush=True)
        signal.pause()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        env={"PATH": key.runtime.environment["PATH"]},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.stdout is not None
        assert select.select([process.stdout], [], [], 30)[0], "No signing readiness"
        root, signing_root, pid = json.loads(process.stdout.readline())
        process.send_signal(sig)
        _, stderr = process.communicate(timeout=15)
        assert process.returncode == 128 + sig, stderr.decode()
        assert not Path(root).exists() and not Path(signing_root).exists()
        stopped(pid)
        os.kill(unrelated_pid, 0)
        assert key.key_file.exists()
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


@pytest.mark.parametrize("returncode", [0, 2])
def test_native_missing_output_signer(
    key: DisposableKey, monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    with private_workspace() as runtime:
        source = runtime.root / "source"
        output = runtime.root / "output"
        atomic_write(source, b"input")
        with signing_session(
            runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer:
            actual_run = runtime.run

            def fake(
                argv: Sequence[str],
                *,
                cwd: Path | None = None,
                input: bytes | None = None,
                timeout: float = 120,
                env_kind: str = "native",
            ) -> subprocess.CompletedProcess[bytes]:
                if "--detach-sign" in argv:
                    return subprocess.CompletedProcess(["gpg"], returncode, b"", b"")
                return actual_run(argv, cwd=cwd, input=input, timeout=timeout, env_kind=env_kind)

            monkeypatch.setattr(runtime, "run", fake)
            with pytest.raises(SigningFailure):
                signer.sign_file(source, output)
            assert not output.exists()
