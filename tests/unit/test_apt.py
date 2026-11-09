from __future__ import annotations

import gzip
import hashlib
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from functools import partial
from pathlib import Path
from unittest.mock import patch

import pytest

from haberdasher.config import FormatPolicy
from haberdasher.core import (
    AdmittedAsset,
    InspectedAsset,
    JSONValue,
    NativeIdentity,
    ObjectRef,
    PreparedFormat,
    RetainedFormat,
    SourceAsset,
    VerifiedAsset,
    sha256_file,
)
from haberdasher.formats import apt
from haberdasher.formats.apt import (
    _check_names,  # pyright: ignore[reportPrivateUsage]
    _indexes,  # pyright: ignore[reportPrivateUsage]
    _policy,  # pyright: ignore[reportPrivateUsage]
    _pool_key,  # pyright: ignore[reportPrivateUsage]
    _verify_signatures,  # pyright: ignore[reportPrivateUsage]
)
from haberdasher.runtime import Runtime
from haberdasher.signing import SigningSession


class Commands(Runtime):
    def __init__(self, root: Path, replies: list[tuple[int, bytes]]) -> None:
        super().__init__(root, environ={"PATH": ""})
        self.replies = list(replies)
        self.commands: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        input: bytes | None = None,
        timeout: float = 120,
        env_kind: str = "native",
        progress: Callable[[str], None] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(tuple(argv))
        if not self.replies:
            raise AssertionError("Unexpected native call")
        code, data = self.replies.pop(0)
        return subprocess.CompletedProcess(argv, code, data, b"native failure" if code else b"")


def asset(root: Path) -> VerifiedAsset:
    path = root / "fixture.deb"
    path.write_bytes(b"synthetic bytes for mocked inspection")
    sha, size = sha256_file(path)
    source = SourceAsset(
        "synthetic/apt",
        1,
        2,
        path.name,
        size,
        "2026-01-01T00:00:00Z",
        "https://example.invalid/fixture.deb",
    )
    return VerifiedAsset(source, path, sha, size, 3, "0" * 64)


def control(arch: str = "amd64", name: str = "hd-test", version: str = "1.0") -> bytes:
    return f"Package: {name}\nVersion: {version}\nArchitecture: {arch}\n".encode()


def pool(
    arch: str = "amd64", name: str = "hd-test", version: str = "1.0", source: str | None = None
) -> str:
    source = source or name
    return f"pool/main/h/{source}/{name}_{version.partition(':')[2] or version}_{arch}.deb"


def record(
    verified: VerifiedAsset,
    arch: str = "amd64",
    name: str = "hd-test",
    version: str = "1.0",
    source: str | None = None,
) -> bytes:
    return (
        control(arch, name, version)
        + (f"Source: {source}\n" if source else "").encode()
        + (
            f"Filename: {pool(arch, name, version, source)}\nSize: {verified.size}\nSHA256: {verified.sha256}\n"
            "Depends: hd-one (>= 1),\n hd-two\nDescription: Test\n Full description.\n"
            "X-Custom: retained\n\n"
        ).encode()
    )


@pytest.mark.parametrize("codes,expected", [([0], 0), ([1, 0], -1), ([1, 1, 0], 1)])
def test_native_version_comparison(tmp_path: Path, codes: list[int], expected: int) -> None:
    runtime = Commands(tmp_path, [(code, b"") for code in codes])
    left = NativeIdentity("apt", "hd-test", "amd64", "1.0")
    right = replace(left, version="1.0-0")
    assert apt.compare(left, right, runtime=runtime) == expected
    assert runtime.commands[0] == ("dpkg", "--compare-versions", "1.0", "eq", "1.0-0")


@pytest.mark.parametrize("codes", [[2], [1, 2], [1, 1, 2], [1, 1, 1], [-9]])
def test_native_comparison_errors_fail_closed(tmp_path: Path, codes: list[int]) -> None:
    runtime = Commands(tmp_path, [(code, b"") for code in codes])
    identity = NativeIdentity("apt", "hd-test", "amd64", "1.0")
    with pytest.raises(apt.AptFailure):
        apt.compare(identity, identity, runtime=runtime)


@pytest.mark.parametrize(
    "other",
    [
        NativeIdentity("apt", "hd-other", "amd64", "1.0"),
        NativeIdentity("apt", "hd-test", "arm64", "1.0"),
        NativeIdentity("rpm", "hd-test", "amd64", "1.0"),
    ],
)
def test_different_slots_do_not_call_native_comparison(
    tmp_path: Path, other: NativeIdentity
) -> None:
    runtime = Commands(tmp_path, [])
    assert (
        apt.compare(NativeIdentity("apt", "hd-test", "amd64", "1.0"), other, runtime=runtime)
        is None
    )
    assert not runtime.commands


def test_complete_record_and_multiline_dependencies_are_preserved(tmp_path: Path) -> None:
    verified = asset(tmp_path)
    raw = record(verified)
    runtime = Commands(tmp_path, [(0, control()), (0, raw)])
    inspected = apt.inspect(
        verified,
        policy=FormatPolicy("apt", ("amd64",)),
        runtime=runtime,
        out=tmp_path / "inspection",
    )
    assert inspected.metadata == {"record": raw.decode()}
    assert inspected.evidence == {"dependencies": {"Depends": "hd-one (>= 1),\n hd-two"}}
    assert inspected.verified == verified
    assert sha256_file(tmp_path / "inspection" / pool()) == (
        verified.sha256,
        verified.size,
    )
    assert runtime.commands == [
        ("dpkg-deb", "-f", str(verified.local_path)),
        ("apt-ftparchive", "packages", pool()),
    ]


@pytest.mark.parametrize("arch", ["amd64", "arm64", "all"])
def test_approved_architectures_and_all(tmp_path: Path, arch: str) -> None:
    verified = asset(tmp_path)
    runtime = Commands(tmp_path, [(0, control(arch)), (0, record(verified, arch))])
    inspected = apt.inspect(
        verified,
        policy=FormatPolicy("apt", ("amd64", "arm64")),
        runtime=runtime,
        out=tmp_path / "inspection",
    )
    assert inspected.identity.architecture == arch


@pytest.mark.parametrize(
    "native_control",
    [
        control("i386"),
        b"",
        control() + b"Package: duplicate\n",
        control() + b"\nPackage: extra\n",
        control().replace(b"hd-test", b"../unsafe"),
        control().replace(b"1.0", b"bad version"),
        control() + b"Broken\n",
        control() + b"X-Test: value\r\n",
    ],
)
def test_invalid_native_control_is_rejected(tmp_path: Path, native_control: bytes) -> None:
    verified = asset(tmp_path)
    runtime = Commands(tmp_path, [(0, native_control)])
    with pytest.raises(apt.AptFailure):
        apt.inspect(
            verified,
            policy=FormatPolicy("apt", ("amd64",)),
            runtime=runtime,
            out=tmp_path / "inspection",
        )


@pytest.mark.parametrize("mode", ["empty", "duplicate", "digest", "size", "filename", "identity"])
def test_index_records_must_bind_the_exact_verified_asset(tmp_path: Path, mode: str) -> None:
    verified = asset(tmp_path)
    raw = record(verified)
    replacements = {
        "empty": b"",
        "duplicate": raw + raw,
        "digest": raw.replace(verified.sha256.encode(), b"a" * 64),
        "size": raw.replace(f"Size: {verified.size}".encode(), b"Size: 0"),
        "filename": raw.replace(b"Filename: pool/", b"Filename: ../"),
        "identity": raw.replace(b"Version: 1.0", b"Version: 2.0"),
    }
    runtime = Commands(tmp_path, [(0, control()), (0, replacements[mode])])
    with pytest.raises(apt.AptFailure):
        apt.inspect(
            verified,
            policy=FormatPolicy("apt", ("amd64",)),
            runtime=runtime,
            out=tmp_path / "inspection",
        )


@pytest.mark.parametrize("command", ["dpkg-deb", "apt-ftparchive"])
def test_inspection_checks_native_exit_status(tmp_path: Path, command: str) -> None:
    verified = asset(tmp_path)
    replies = [(2, control())] if command == "dpkg-deb" else [(0, control()), (2, record(verified))]
    runtime = Commands(tmp_path, replies)
    with pytest.raises(apt.AptFailure, match="native command failed"):
        apt.inspect(
            verified,
            policy=FormatPolicy("apt", ("amd64",)),
            runtime=runtime,
            out=tmp_path / "inspection",
        )


def test_verified_bytes_are_checked_before_any_native_call(tmp_path: Path) -> None:
    verified = asset(tmp_path)
    verified.local_path.write_bytes(b"changed")
    runtime = Commands(tmp_path, [])
    with pytest.raises(apt.AptFailure, match="changed"):
        apt.inspect(
            verified,
            policy=FormatPolicy("apt", ("amd64",)),
            runtime=runtime,
            out=tmp_path / "inspection",
        )
    assert not runtime.commands


def test_empty_bootstrap_needs_no_native_commands_or_signer(tmp_path: Path) -> None:
    runtime = Commands(tmp_path, [])
    config = FormatPolicy("apt", ("amd64",))
    empty = RetainedFormat("apt", None, (), (), {}, ())
    signer = SigningSession(runtime, tmp_path / "gnupg", "A" * 40)
    prepared = apt.prepare(
        [],
        empty,
        policy=config,
        runtime=runtime,
        signer=signer,
        now=datetime.now(UTC),
        out=tmp_path / "output",
    )
    assert prepared == PreparedFormat("apt", empty, (), ())
    apt.validate_prepared(prepared, policy=config, runtime=runtime, now=datetime.now(UTC))
    assert not runtime.commands


@pytest.mark.parametrize(
    "broken",
    [
        RetainedFormat("apt", "prior", (), (), {}, ()),
        RetainedFormat("apt", None, (), (), {"files": {}}, ()),
        RetainedFormat(
            "apt", None, (), (NativeIdentity("apt", "hd-test", "amd64", "1.0"),), {}, ()
        ),
    ],
)
def test_incomplete_retained_state_cannot_bootstrap(tmp_path: Path, broken: RetainedFormat) -> None:
    runtime = Commands(tmp_path, [])
    with pytest.raises(apt.AptFailure, match="Incomplete"):
        apt.validate_retained(broken, policy=FormatPolicy("apt", ("amd64",)), runtime=runtime)


def test_changed_admitted_bytes_do_not_produce_outputs(tmp_path: Path) -> None:
    verified = asset(tmp_path)
    runtime = Commands(tmp_path, [(0, control()), (0, record(verified))])
    config = FormatPolicy("apt", ("amd64",))
    inspected = apt.inspect(verified, policy=config, runtime=runtime, out=tmp_path / "inspection")
    verified.local_path.write_bytes(b"changed")
    signer = SigningSession(runtime, tmp_path / "gnupg", "A" * 40)
    with patch.object(signer, "sign_file", side_effect=AssertionError("Signer must not run")):
        with pytest.raises(apt.AptFailure, match="bytes changed"):
            apt.prepare(
                [AdmittedAsset(inspected, "preserve", "history")],
                RetainedFormat("apt", None, (), (), {}, ()),
                policy=config,
                runtime=runtime,
                signer=signer,
                now=datetime.now(UTC),
                out=tmp_path / "output",
            )


@pytest.mark.parametrize("inline", [False, True])
@pytest.mark.parametrize(
    "fault", [None, "missing", "duplicate", "truncated", "signer", "primary", "algorithm", "digest"]
)
def test_release_verification_requires_one_scoped_sha256_primary(
    tmp_path: Path, inline: bool, fault: str | None
) -> None:
    fingerprint = "A" * 40
    valid = f"[GNUPG:] VALIDSIG {fingerprint} 2026-01-01 1 0 4 0 1 8 00 {fingerprint}\n".encode()
    statuses = {
        "missing": b"[GNUPG:] GOODSIG untrusted\n",
        "duplicate": valid + valid,
        "truncated": b"[GNUPG:] VALIDSIG A\n",
        "signer": valid.replace(fingerprint.encode(), b"B" * 40, 1),
        "primary": valid.rsplit(fingerprint.encode(), 1)[0] + b"B" * 40 + b"\n",
        "algorithm": valid.replace(b" 1 8 00 ", b" 19 8 00 "),
        "digest": valid.replace(b" 1 8 00 ", b" 1 10 00 "),
    }
    replies = [(0, valid), (0, valid)]
    if fault is not None:
        replies[int(inline)] = (0, statuses[fault])
    runtime = Commands(tmp_path / "runtime", replies)
    release = tmp_path / "Release"
    release.write_bytes(b"Suite: stable\n")
    retained = RetainedFormat(
        "apt",
        None,
        (),
        (),
        {
            "files": {
                "dists/stable/Release": str(release),
                "dists/stable/Release.gpg": str(tmp_path / "Release.gpg"),
                "dists/stable/InRelease": str(tmp_path / "InRelease"),
            },
            "keyring": str(tmp_path / "trust.gpg"),
            "fingerprint": fingerprint,
        },
        (),
    )

    def verify(
        argv: Sequence[str], *, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        if "--output" in argv:
            extracted = Path(argv[argv.index("--output") + 1])
            assert extracted.is_relative_to(runtime.root / "tmp")
            extracted.write_bytes(release.read_bytes())
        return Commands.run(runtime, argv, cwd=cwd)

    with patch.object(runtime, "run", side_effect=verify):
        if fault is None:
            _verify_signatures(retained, policy=FormatPolicy("apt", ("amd64",)), runtime=runtime)
        else:
            with pytest.raises(apt.AptFailure, match="scoped SHA256 primary"):
                _verify_signatures(
                    retained, policy=FormatPolicy("apt", ("amd64",)), runtime=runtime
                )
    assert len(runtime.commands) == (1 if fault is not None and not inline else 2)
    assert all(command[0] == "gpgv" for command in runtime.commands)
    assert not list((runtime.root / "tmp").iterdir())


def retained_history(
    root: Path, identities: tuple[NativeIdentity, ...], config: FormatPolicy
) -> RetainedFormat:
    verified = asset(root)
    history: list[AdmittedAsset] = []
    refs: list[ObjectRef] = []

    def reference(key: str, data: bytes, kind: str) -> None:
        refs.append(
            ObjectRef(
                "apt",
                key,
                kind,
                len(data),
                hashlib.sha256(data).hexdigest(),
                "application/octet-stream",
                "no-cache",
            )
        )

    for index, identity in enumerate(identities):
        data = f"distinct synthetic DEB {index}".encode()
        current = replace(
            verified,
            source=replace(verified.source, asset_id=index + 1, size=len(data)),
            local_path=root / f"absent-{index}.deb",
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
        )
        source = f"hd-source-{index}"
        raw = record(
            current, identity.architecture, identity.name, identity.version, source
        ).decode()
        history.append(
            AdmittedAsset(
                InspectedAsset(current, identity, {"record": raw}, {}, "unsigned"),
                "preserve",
                f"unique-history-{index}",
                current.sha256,
            )
        )
        reference(
            pool(identity.architecture, identity.name, identity.version, source), data, "package"
        )
    indexes = _indexes(history, config)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    expiry = now + timedelta(seconds=config.validity_seconds)
    release = (
        f"Suite: {config.suite}\nCodename: {config.suite}\nComponents: {config.component}\n"
        f"Architectures: {' '.join(config.architectures)}\nAcquire-By-Hash: yes\n"
        f"Date: {format_datetime(now, usegmt=True)}\n"
        f"Valid-Until: {format_datetime(expiry, usegmt=True)}\nSHA256:\n"
    )
    for key, data in indexes.items():
        sha = hashlib.sha256(data).hexdigest()
        release += f" {sha} {len(data)} {key.removeprefix(f'dists/{config.suite}/')}\n"
        reference(key.rsplit("/", 1)[0] + "/by-hash/SHA256/" + sha, data, "dependency")
    files: dict[str, JSONValue] = {}
    for key, data in {
        **indexes,
        f"dists/{config.suite}/Release": release.encode(),
        f"dists/{config.suite}/Release.gpg": b"mock detached signature",
        f"dists/{config.suite}/InRelease": b"mock inline signature",
    }.items():
        path = root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        files[key] = str(path)
        reference(key, data, "entry")
    keyring = root / "trust.gpg"
    keyring.write_bytes(b"mock public keyring")
    return RetainedFormat(
        "apt",
        "prior",
        tuple(history),
        identities,
        {
            "policy": _policy(config),
            "files": files,
            "etags": {},
            "keyring": str(keyring),
            "keyring_sha256": sha256_file(keyring)[0],
            "fingerprint": "A" * 40,
            "expires_at": expiry.isoformat(),
        },
        tuple(refs),
    )


def test_indexes_are_deterministic_across_roots_and_times(tmp_path: Path) -> None:
    config = FormatPolicy("apt", ("amd64", "arm64"))
    identities = tuple(
        NativeIdentity("apt", f"hd-{arch}", arch, "1.0") for arch in ("amd64", "arm64", "all")
    )
    # Python 3.14 defaults to mtime=0. Require the adapter's explicit setting instead.
    compress = gzip.compress
    roots = (tmp_path / "first", tmp_path / "second")
    for root, clock in zip(roots, (1_800_000_000, 1_800_000_100), strict=True):
        root.mkdir()
        with (
            patch.object(apt.gzip, "compress", partial(compress, mtime=clock)),
            patch("gzip.time.time", return_value=clock),
        ):
            retained = retained_history(root, identities, config)
            expected = _indexes(retained.accepted_history, config)
        for key, data in expected.items():
            assert (root / key).read_bytes() == data
    for arch in config.architectures:
        key = f"dists/{config.suite}/{config.component}/binary-{arch}/Packages"
        plain = (roots[0] / key).read_bytes()
        left = (roots[0] / (key + ".gz")).read_bytes()
        right = (roots[1] / (key + ".gz")).read_bytes()
        assert left == right
        assert gzip.decompress(left) == gzip.decompress(right) == plain
        assert plain == (roots[1] / key).read_bytes()
        assert f"Package: hd-{arch}\n".encode() in plain
        assert b"Package: hd-all\n" in plain
        other = "arm64" if arch == "amd64" else "amd64"
        assert f"Package: hd-{other}\n".encode() not in plain
        assert b"X-Custom: retained\n" in plain


@pytest.mark.parametrize("version", ["1.0", "0:1.0", "1.0-0"])
def test_retained_rejects_semantically_duplicate_identities(tmp_path: Path, version: str) -> None:
    config = FormatPolicy("apt", ("amd64",))
    left = NativeIdentity("apt", "hd-test", "amd64", "1.0")
    retained = retained_history(tmp_path, (left, replace(left, version=version)), config)
    runtime = Commands(tmp_path / "runtime", [(0, b"")] * 2)
    with (
        patch.object(apt, "_indexes", side_effect=AssertionError("Indexes must not run")),
        patch.object(apt, "_verify_signatures", side_effect=AssertionError("No verification")),
        pytest.raises(apt.AptFailure, match="Duplicate retained Debian identity"),
    ):
        apt.validate_retained(retained, policy=config, runtime=runtime)
    assert runtime.commands == [
        ("dpkg", "--compare-versions", version, "eq", "1.0"),
        ("dpkg", "--compare-versions", "1.0", "eq", version),
    ]


@pytest.mark.parametrize("difference", ["version", "name", "architecture"])
def test_retained_preserves_distinct_identities(tmp_path: Path, difference: str) -> None:
    config = FormatPolicy("apt", ("amd64", "arm64"))
    left = NativeIdentity("apt", "hd-test", "amd64", "1.0")
    right = replace(
        left,
        version="2.0" if difference == "version" else left.version,
        name="hd-other" if difference == "name" else left.name,
        architecture="arm64" if difference == "architecture" else left.architecture,
    )
    retained = retained_history(tmp_path, (right, left), config)
    runtime = Commands(
        tmp_path / "runtime",
        [(code, b"") for code in [1, 0, 1, 0]] if difference == "version" else [],
    )
    with patch.object(apt, "_verify_signatures") as signatures:
        apt.validate_retained(retained, policy=config, runtime=runtime)
    signatures.assert_called_once_with(retained, policy=config, runtime=runtime)
    assert not runtime.replies
    assert all(command[0] == "dpkg" for command in runtime.commands)


def test_all_is_not_a_concrete_index_architecture(tmp_path: Path) -> None:
    runtime = Commands(tmp_path, [])
    with pytest.raises(apt.AptFailure, match="concrete"):
        apt.validate_retained(
            RetainedFormat("apt", None, (), (), {}, ()),
            policy=FormatPolicy("apt", ("all",)),
            runtime=runtime,
        )


@pytest.mark.parametrize(
    "fields,expected",
    [
        (
            {"Package": "sidra", "Version": "1.3.0", "Architecture": "amd64"},
            "pool/main/s/sidra/sidra_1.3.0_amd64.deb",
        ),
        (
            {"Package": "hd-tool", "Version": "1:2.0-1", "Architecture": "all"},
            "pool/main/h/hd-tool/hd-tool_2.0-1_all.deb",
        ),
        (
            {
                "Package": "libhd-data",
                "Source": "libhd (1.0)",
                "Version": "1.0",
                "Architecture": "arm64",
            },
            "pool/main/libh/libhd/libhd-data_1.0_arm64.deb",
        ),
        (
            {"Package": "lib", "Version": "1.0", "Architecture": "amd64"},
            "pool/main/lib/lib/lib_1.0_amd64.deb",
        ),
    ],
)
def test_pool_names_follow_debian_layout(fields: dict[str, str], expected: str) -> None:
    assert _pool_key(fields, FormatPolicy("apt", ("amd64",))) == expected


def test_two_sources_with_one_pool_name_fail_with_one_line(tmp_path: Path) -> None:
    config = FormatPolicy("apt", ("amd64",))
    verified = asset(tmp_path)
    history: list[AdmittedAsset] = []
    for index, (repository, version) in enumerate((("one/tool", "1.0"), ("two/tool", "1:1.0"))):
        data = f"different bytes {index}".encode()
        current = replace(
            verified,
            source=replace(
                verified.source, repository=repository, asset_id=index + 1, size=len(data)
            ),
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
        )
        identity = NativeIdentity("apt", "hd-test", "amd64", version)
        raw = record(current, version=version).decode()
        history.append(
            AdmittedAsset(
                InspectedAsset(current, identity, {"record": raw}, {}, "unsigned"),
                "preserve",
                f"history-{index}",
            )
        )
    with pytest.raises(apt.AptFailure) as error:
        _check_names(history, config)
    assert str(error.value) == (
        "pool/main/h/hd-test/hd-test_1.0_amd64.deb comes from both one/tool (fixture.deb)"
        " and two/tool (fixture.deb); publish one of them"
    )
    _check_names(history[:1] * 2, config)
