"""Isolated canonical primary-key signing and public-key conversion."""

from __future__ import annotations

import base64
import contextlib
import hmac
import math
import os
import re
import shutil
import stat
import tempfile
import time
from collections.abc import Generator, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

from haberdasher.core import atomic_write, safe_path
from haberdasher.runtime import Runtime, RuntimeFailure, private_workspace

MAX_KEY_BYTES = 1024 * 1024
ALPINE_SIGNATURE_MEMBER = ".SIGN.RSA256.haberdasher.rsa.pub"
NIX_KEY_NAME = "nix.wimpys.world-1"
_NIX_HKDF_SALT = b"haberdasher-nix-ed25519-v1"
_ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class SigningFailure(RuntimeError):
    pass


def _mpint(value: int) -> bytes:
    if value <= 0:
        raise SigningFailure("Expected positive RSA integer")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return len(raw).to_bytes(4, "big") + raw


def _checked(runtime: Runtime, argv: Sequence[str], *, data: bytes | None = None) -> bytes:
    result = runtime.run(argv, input=data, env_kind="native")
    if result.returncode:
        raise SigningFailure("Native signing command failed")
    return result.stdout


def _records(data: bytes) -> list[list[str]]:
    try:
        return [line.split(":") for line in data.decode("ascii").splitlines()]
    except UnicodeError:
        raise SigningFailure("Invalid native key listing") from None


def _field(records: list[list[str]], kind: str, index: int) -> str:
    matches = [record for record in records if record[0] == kind]
    if len(matches) != 1 or len(matches[0]) <= index or not matches[0][index]:
        raise SigningFailure("Expected one complete primary key")
    return matches[0][index]


def _validate(data: bytes, fingerprint: str, *, secret: bool) -> str:
    records = _records(data)
    kind = "sec" if secret else "pub"
    if any(record[0] in {"sub", "ssb"} for record in records):
        raise SigningFailure("Signing key must not contain subkeys")
    validity = _field(records, kind, 1)
    if (
        validity in {"r", "e", "d", "i"}
        or _field(records, kind, 2) != "4096"
        or _field(records, kind, 3) != "1"
        or _field(records, "fpr", 9) != fingerprint
        or set(_field(records, kind, 11)) != set("scSC")
    ):
        raise SigningFailure("Expected the Haberdasher RSA4096 signing and certification primary")
    primary = next(record for record in records if record[0] == kind)
    try:
        if primary[6] and int(primary[6]) <= time.time():
            raise SigningFailure("Signing key expired")
    except ValueError:
        raise SigningFailure("Invalid signing key expiry") from None
    if secret and (len(primary) <= 14 or primary[14] != "+"):
        raise SigningFailure("Signing key requires local private material")
    grip = _field(records, "grp", 9)
    if re.fullmatch(r"[A-F0-9]{40}", grip) is None:
        raise SigningFailure("Invalid signing keygrip")
    return grip


def _input(key_file: Path | None, key_data: bytes | None) -> bytes:
    if key_file is None and key_data is None:
        filename = os.environ.get("HD_SIGNING_KEY_FILE")
        value = os.environ.get("HD_SIGNING_KEY")
        key_file = Path(filename) if filename else None
        key_data = value.encode() if value else None
    if (key_file is None) == (key_data is None):
        raise SigningFailure("Provide exactly one signing key input")
    if key_file is not None:
        try:
            path = key_file.resolve(strict=True)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
                    or info.st_uid != os.getuid()
                ):
                    raise SigningFailure(
                        "Signing key input must be a private regular file owned by the current user"
                    )
                if not 0 < info.st_size <= MAX_KEY_BYTES:
                    raise SigningFailure("Signing key input is empty or exceeds 1 MiB")
                key_data = stream.read(MAX_KEY_BYTES + 1)
        except OSError, ValueError:
            raise SigningFailure("Could not read signing key input") from None
    if not isinstance(key_data, bytes) or not 0 < len(key_data) <= MAX_KEY_BYTES:
        raise SigningFailure("Signing key input is empty or exceeds 1 MiB")
    return key_data


class SigningSession:
    def __init__(self, runtime: Runtime, home: Path, fingerprint: str) -> None:
        self._runtime = runtime
        self._home = home
        self._fingerprint = fingerprint
        self._grip = ""
        self._active = True
        self._alpine: tuple[Path, Path] | None = None
        self._nix: tuple[Path, Path, str] | None = None

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def gnupghome(self) -> Path:
        return self._home

    @property
    def environment(self) -> Mapping[str, str]:
        return MappingProxyType({**self._runtime.environment, "GNUPGHOME": str(self._home)})

    def _run(self, argv: Sequence[str], *, data: bytes | None = None) -> bytes:
        if not self._active:
            raise SigningFailure("Signing session is closed")
        return _checked(self._runtime, argv, data=data)

    def _gpg(self, *args: str, data: bytes | None = None) -> bytes:
        return self._run(
            [
                "gpg",
                "--no-options",
                "--homedir",
                str(self._home),
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--no-auto-key-retrieve",
                "--digest-algo",
                "SHA256",
                "--cert-digest-algo",
                "SHA256",
                *args,
            ],
            data=data,
        )

    def _sm(self, *args: str) -> bytes:
        return self._run(
            [
                "gpgsm",
                "--no-options",
                "--homedir",
                str(self._home),
                "--no-common-certs-import",
                "--disable-dirmngr",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                *args,
            ]
        )

    def _validate(self) -> None:
        grips = {
            _validate(
                self._gpg("--with-colons", "--with-keygrip", command),
                self.fingerprint,
                secret=secret,
            )
            for command, secret in (("--list-keys", False), ("--list-secret-keys", True))
        }
        if len(grips) != 1:
            raise SigningFailure("Public and private keygrips differ")
        self._grip = grips.pop()

    def sign_file(
        self, source: Path, output: Path, *, clear: bool = False, armour: bool = True
    ) -> None:
        if type(clear) is not bool or type(armour) is not bool or (clear and not armour):
            raise ValueError("Clear signatures require armour")
        source = safe_path(source.parent, source.name)
        output = safe_path(output.parent, output.name)
        if not source.is_file() or source == output:
            raise ValueError("Signing requires distinct source and output files")
        self._validate()
        with tempfile.TemporaryDirectory(prefix="signature-", dir=self._home.parent) as directory:
            temporary = Path(directory) / "signature"
            self._gpg(
                "--local-user",
                self.fingerprint + "!",
                *(["--armor"] if armour else []),
                "--output",
                str(temporary),
                "--clearsign" if clear else "--detach-sign",
                "--",
                str(source),
            )
            if not temporary.is_file() or not temporary.stat().st_size:
                raise SigningFailure("Signer produced no signature")
            status = self._gpg(
                "--status-fd",
                "1",
                "--verify",
                str(temporary),
                *([] if clear else [str(source)]),
            )
            signatures = [
                line.split()
                for line in status.splitlines()
                if line.startswith(b"[GNUPG:] VALIDSIG ")
            ]
            if (
                len(signatures) != 1
                or len(signatures[0]) < 12
                or signatures[0][2] != self.fingerprint.encode()
                or signatures[0][8:10] != [b"1", b"8"]
                or signatures[0][11] != self.fingerprint.encode()
            ):
                raise SigningFailure(
                    "Signature must use the Haberdasher signing primary and SHA256"
                )
            atomic_write(output, temporary.read_bytes())

    def alpine_key(self) -> tuple[Path, Path]:
        self._validate()
        if self._alpine is not None:
            return self._alpine
        root = self._home.parent
        batch = root / "conversion.batch"
        cert = root / "conversion.der"
        atomic_write(
            batch,
            (
                f"Key-Type: RSA\nKey-Grip: {self._grip}\nKey-Usage: sign\n"
                "Name-DN: CN=Haberdasher Key Conversion\nSerial: 01\nHash-Algo: sha256\n%commit\n"
            ).encode(),
        )
        self._sm("--output", str(cert), "--generate-key", str(batch))
        if not cert.is_file() or not cert.stat().st_size:
            raise SigningFailure("Key conversion produced no certificate")
        self._sm("--import", str(cert))
        listing = _records(self._sm("--with-colons", "--with-keygrip", "--list-secret-keys"))
        if _field(listing, "grp", 9) != self._grip:
            raise SigningFailure("Conversion changed the keygrip")
        private = root / "haberdasher.rsa"
        public = root / "haberdasher.rsa.pub"
        pem = self._sm("--armor", "--export-secret-key-p8", _field(listing, "fpr", 9))
        if not pem:
            raise SigningFailure("Key conversion produced no private key")
        atomic_write(private, pem)
        self._run(["openssl", "pkey", "-in", str(private), "-check", "-noout"])
        records = _records(
            self._gpg("--with-colons", "--with-key-data", "--list-keys", self.fingerprint)
        )
        numbers = [record[3] for record in records if record[0] == "pkd" and len(record) > 3]
        if len(numbers) != 2 or any(re.fullmatch(r"[0-9A-Fa-f]+", n) is None for n in numbers):
            raise SigningFailure("Invalid OpenPGP RSA public numbers")
        asn1 = root / "public.asn1"
        rsa = root / "public.der"
        atomic_write(
            asn1,
            (
                f"asn1=SEQUENCE:rsakey\n[rsakey]\nn=INTEGER:0x{numbers[0]}\ne=INTEGER:0x{numbers[1]}\n"
            ).encode(),
        )
        self._run(["openssl", "asn1parse", "-genconf", str(asn1), "-out", str(rsa), "-noout"])
        pgp_der = self._run(
            [
                "openssl",
                "rsa",
                "-RSAPublicKey_in",
                "-inform",
                "DER",
                "-in",
                str(rsa),
                "-pubout",
                "-outform",
                "DER",
            ]
        )
        cert_public = self._run(
            ["openssl", "x509", "-inform", "DER", "-in", str(cert), "-pubkey", "-noout"]
        )
        cert_der = self._run(["openssl", "pkey", "-pubin", "-outform", "DER"], data=cert_public)
        pem_der = self._run(["openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER"])
        if not pgp_der or pgp_der != cert_der or pgp_der != pem_der:
            raise SigningFailure("Conversion changed the RSA public numbers")
        private_keys = list((self._home / "private-keys-v1.d").glob("*.key"))
        if len(private_keys) != 1 or private_keys[0].stem != self._grip:
            raise SigningFailure("Conversion must retain exactly one private primary")
        exported = self._run(["openssl", "pkey", "-in", str(private), "-pubout"])
        if not exported:
            raise SigningFailure("Key conversion produced no public key")
        atomic_write(public, exported)
        self._alpine = private, public
        return self._alpine

    def nix_key(self) -> tuple[Path, Path, str]:
        self._validate()
        if self._nix is not None:
            return self._nix
        private_pem, _ = self.alpine_key()
        rsa_der = self._run(
            ["openssl", "rsa", "-traditional", "-in", str(private_pem), "-outform", "DER"]
        )
        try:
            asn1 = self._run(["openssl", "asn1parse", "-inform", "DER"], data=rsa_der).decode(
                "ascii"
            )
        except UnicodeError:
            raise SigningFailure("Invalid PKCS#1 ASN.1 output") from None
        integers = [
            int(match[1], 16)
            for line in asn1.splitlines()
            if (
                match := re.search(
                    r"d=1\s+hl=\d+\s+l=\s*\d+\s+prim:\s+INTEGER\s+:([0-9A-F]+)$", line
                )
            )
        ]
        if len(integers) != 9 or integers[0] != 0:
            raise SigningFailure("Invalid PKCS#1 RSA private structure")
        _, n, e, d, p, q, _, _, _ = integers
        if (
            n.bit_length() != 4096
            or e <= 1
            or p <= 1
            or q <= 1
            or p == q
            or p * q != n
            or (e * d) % math.lcm(p - 1, q - 1) != 1
        ):
            raise SigningFailure("Invalid RSA secret numbers")
        p_hi, p_lo = (p, q) if p > q else (q, p)
        d_canon = pow(e, -1, (p_hi - 1) * (p_lo - 1))
        ikm = b"".join(_mpint(x) for x in (n, e, d_canon, p_hi, p_lo))
        prk = hmac.digest(_NIX_HKDF_SALT, ikm, "sha256")
        seed = hmac.digest(prk, NIX_KEY_NAME.encode("ascii") + b"\x01", "sha256")
        spki = self._run(
            ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
            data=_ED25519_PKCS8_PREFIX + seed,
        )
        if len(spki) != 44 or not spki.startswith(_ED25519_SPKI_PREFIX):
            raise SigningFailure("Invalid derived Ed25519 public key")
        pubkey = spki[12:]
        secret_text = f"{NIX_KEY_NAME}:{base64.b64encode(seed + pubkey).decode('ascii')}\n".encode()
        public_value = f"{NIX_KEY_NAME}:{base64.b64encode(pubkey).decode('ascii')}"
        public_text = f"{public_value}\n".encode()
        if shutil.which("nix", path=self._runtime.environment["PATH"]) is not None:
            try:
                converted = (
                    self._run(
                        [
                            "nix",
                            "--extra-experimental-features",
                            "nix-command",
                            "key",
                            "convert-secret-to-public",
                        ],
                        data=secret_text,
                    )
                    .decode("ascii")
                    .strip()
                )
            except UnicodeError:
                raise SigningFailure("Invalid native Nix key output") from None
            if converted != public_value:
                raise SigningFailure("Derived Nix key disagrees with native Nix key conversion")
        root = self._home.parent
        secret = root / "haberdasher.nix.sec"
        public = root / "haberdasher.nix.pub"
        atomic_write(secret, secret_text)
        atomic_write(public, public_text)
        self._nix = secret, public, public_value
        return self._nix

    def public_exports(self, out: Path) -> tuple[Path, Path, Path]:
        paths = tuple(
            safe_path(out, name)
            for name in ("haberdasher.asc", "haberdasher.gpg", "haberdasher.rsa.pub")
        )
        _, public = self.alpine_key()
        armoured = self._gpg("--armor", "--export", self.fingerprint)
        binary = self._gpg("--export", self.fingerprint)
        if not armoured or not binary:
            raise SigningFailure("Signer produced no public export")
        for path, data in zip(paths, (armoured, binary, public.read_bytes()), strict=True):
            atomic_write(path, data)
        return paths[0], paths[1], paths[2]


def key_fingerprint(runtime: Runtime) -> str | None:
    """Primary fingerprint of the signing key in the environment, or None without a key."""
    if not (os.environ.get("HD_SIGNING_KEY_FILE") or os.environ.get("HD_SIGNING_KEY")):
        return None
    data = _input(None, None)
    with private_workspace(runtime.root / "tmp") as workspace:
        home = str(workspace.root / "gnupg")
        listing = _checked(
            workspace,
            ["gpg", "--no-options", "--homedir", home, "--batch", "--with-colons", "--show-keys"],
            data=data,
        )
    return _field(_records(listing), "fpr", 9)


@contextlib.contextmanager
def signing_session(
    runtime: Runtime,
    *,
    expected_fingerprint: str,
    key_file: Path | None = None,
    key_data: bytes | None = None,
) -> Generator[SigningSession]:
    if re.fullmatch(r"[A-F0-9]{40}", expected_fingerprint) is None:
        raise ValueError("Expected an uppercase primary fingerprint")
    data = _input(key_file, key_data)
    with private_workspace(runtime.root / "tmp") as workspace:
        session = SigningSession(runtime, workspace.root / "gnupg", expected_fingerprint)
        try:
            session._gpg("--import", data=data)  # pyright: ignore[reportPrivateUsage]
            session._validate()  # pyright: ignore[reportPrivateUsage]
            atomic_write(
                session.gnupghome / "gpg.conf",
                (
                    "digest-algo SHA256\ncert-digest-algo SHA256\npersonal-digest-preferences SHA256\n"
                    f"default-key {session.fingerprint}!\nno-auto-key-retrieve\n"
                ).encode(),
            )
            yield session
        finally:
            session._active = False  # pyright: ignore[reportPrivateUsage]
            try:
                if runtime.cleanup_gnupg(session.gnupghome).returncode:
                    raise SigningFailure("Native signing command failed")
            except RuntimeFailure, SigningFailure:
                if workspace.cleanup_gnupg(session.gnupghome).returncode:
                    raise SigningFailure("Native signing command failed") from None
