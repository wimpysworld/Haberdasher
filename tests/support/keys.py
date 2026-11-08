"""Disposable native keys for tests, never production identities."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from haberdasher.core import atomic_write
from haberdasher.runtime import Runtime, private_workspace


@dataclass(frozen=True)
class DisposableKey:
    fingerprint: str
    key_file: Path
    public_file: Path
    runtime: Runtime


def run(runtime: Runtime, *argv: str, data: bytes | None = None) -> bytes:
    result = runtime.run(argv, input=data)
    if result.returncode:
        raise RuntimeError(f"Synthetic key command failed: {argv[0]}: {result.stderr.decode()}")
    return result.stdout


@contextmanager
def disposable_key(
    *, algorithm: str = "rsa4096", usage: str = "sign,cert", subkey: bool = False
) -> Generator[DisposableKey]:
    with private_workspace() as runtime:
        gpg = ("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "")
        run(
            runtime,
            *gpg,
            "--quick-generate-key",
            "Haberdasher test <test@invalid>",
            algorithm,
            usage,
            "1d",
        )
        listing = run(runtime, *gpg, "--with-colons", "--list-keys")
        fingerprints = [
            line.split(b":")[9].decode()
            for line in listing.splitlines()
            if line.startswith(b"fpr:")
        ]
        if len(fingerprints) != 1:
            raise RuntimeError("Expected one disposable primary")
        fingerprint = fingerprints[0]
        if subkey:
            run(runtime, *gpg, "--quick-add-key", fingerprint, "rsa2048", "sign", "1d")
        secret = runtime.root / "synthetic-secret.gpg"
        public = runtime.root / "synthetic-public.gpg"
        atomic_write(secret, run(runtime, *gpg, "--export-secret-keys", fingerprint))
        atomic_write(public, run(runtime, *gpg, "--export", fingerprint))
        yield DisposableKey(fingerprint, secret, public, runtime)
