"""Script-free data packages and private pacman clients."""

from __future__ import annotations

import shutil
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from subprocess import CompletedProcess

from haberdasher.core import SourceAsset, VerifiedAsset, safe_path, sha256_file
from haberdasher.runtime import Runtime
from tests.support.keys import DisposableKey, run
from tests.support.native import NativeClient


def fixture(
    runtime: Runtime,
    name: str,
    version: str,
    *,
    release: str = "1",
    content: str | None = None,
    architecture: str = "x86_64",
    dependency: str | None = None,
    label: str = "normal",
) -> VerifiedAsset:
    directory = runtime.root / f"build-{name}-{version}-{release}-{label}"
    directory.mkdir()
    executable = shutil.which("makepkg", path=runtime.environment["PATH"])
    if executable is None:
        raise RuntimeError("Missing makepkg")
    config = directory / "makepkg.conf"
    config.write_text(
        (Path(executable).parent.parent / "etc/makepkg.conf").read_text() + "\n"
        "BUILDENV=(!distcc !color !ccache !check !sign)\n"
        "OPTIONS=(!strip docs libtool staticlibs emptydirs !zipman !purge !debug !lto !autodeps)\n"
        "PKGEXT='.pkg.tar.zst'\n" + (f"CARCH='{architecture}'\n" if architecture != "any" else "")
    )
    (directory / "PKGBUILD").write_text(
        f"pkgname={name}\npkgver={version}\npkgrel={release}\n"
        "pkgdesc='Disposable data package'\nlicense=('MIT')\n"
        f"arch=('{architecture}')\n"
        + (f"depends=('{dependency}')\n" if dependency else "")
        + "package() {\n"
        + f' install -Dm644 /dev/null "$pkgdir/usr/share/arch-test/{name}.txt"\n'
        + f' printf "%s\\n" "{content or name + "-" + version}" >"$pkgdir/usr/share/arch-test/{name}.txt"\n'
        + "}\n"
    )
    result = runtime.run(["makepkg", "--nodeps", "--config", str(config)], cwd=directory)
    if result.returncode:
        raise RuntimeError(result.stderr.decode() + result.stdout.decode())
    package = directory / f"{name}-{version}-{release}-{architecture}.pkg.tar.zst"
    members = run(runtime, "bsdtar", "-tf", str(package)).splitlines()
    if b".INSTALL" in members:
        raise RuntimeError("Fixture contains an install script")
    digest, size = sha256_file(package)
    source = SourceAsset(
        "test/arch",
        1,
        1,
        package.name,
        size,
        "2026-01-01T00:00:00Z",
        "https://example.invalid/" + package.name,
    )
    return VerifiedAsset(source, package, digest, size, 2, "a" * 64)


@contextmanager
def client_keyring(runtime: Runtime, home: Path | None = None) -> Generator[Path]:
    if home is None:
        # Match the five-byte "gnupg" component reserved by private_workspace.
        for number in range(0x10000):
            home = safe_path(runtime.root, f"p{number:04x}")
            try:
                home.mkdir(mode=0o700)
                break
            except FileExistsError:
                continue
        else:
            raise RuntimeError("No private client keyring slot available")
    home = safe_path(runtime.root, str(home.relative_to(runtime.root)))
    try:
        yield home
    finally:
        safe_path(runtime.root, str(home.relative_to(runtime.root)))
        result = runtime.cleanup_gnupg(home)
        if result.returncode:
            raise RuntimeError(f"Synthetic keyring cleanup failed: {result.stderr.decode()}")


@dataclass
class Pacman:
    client: NativeClient
    config: Path
    keyring: Path

    def run(self, *arguments: str) -> CompletedProcess[bytes]:
        with client_keyring(self.client.runtime, self.keyring):
            return self.client.run(
                [
                    "fakeroot",
                    "pacman",
                    "--config",
                    str(self.config),
                    "--root",
                    str(self.client.root),
                    "--noconfirm",
                    *arguments,
                ],
                install_root=self.client.root,
            )

    def checked(self, *arguments: str) -> bytes:
        result = self.run(*arguments)
        if result.returncode:
            raise RuntimeError(result.stdout.decode() + result.stderr.decode())
        return result.stdout


def client(
    runtime: Runtime,
    name: str,
    url: str,
    key: DisposableKey,
    *,
    trusted: bool = True,
    architecture: str = "x86_64",
) -> Pacman:
    private = NativeClient(runtime, name)
    for directory in ("db", "hooks"):
        private.path(directory).mkdir()
    with client_keyring(runtime) as home:
        run(
            runtime,
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--no-autostart",
            "--no-default-keyring",
            "--keyring",
            str(home / "pubring.gpg"),
            "--import",
            str(key.public_file),
        )
        if trusted:
            run(
                runtime,
                "gpg",
                "--homedir",
                str(home),
                "--batch",
                "--no-autostart",
                "--import-ownertrust",
                data=f"{key.fingerprint}:6:\n".encode(),
            )
    config = private.path("config/pacman.conf")
    config.write_text(
        "[options]\n"
        f"RootDir = {private.root}\nDBPath = {private.path('db')}\n"
        f"CacheDir = {private.path('cache')}\nLogFile = {private.path('log/pacman.log')}\n"
        f"GPGDir = {home}\nHookDir = {private.path('hooks')}\n"
        f"Architecture = {architecture}\nSigLevel = Required TrustedOnly\n"
        "LocalFileSigLevel = Required TrustedOnly\nRemoteFileSigLevel = Required TrustedOnly\n"
        f"[haberdasher]\nServer = {url}\n"
    )
    return Pacman(private, config, home)
