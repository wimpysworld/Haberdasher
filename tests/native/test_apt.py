"""Production APT preparation and actual HTTP installations in private dpkg roots."""

from __future__ import annotations

import gzip
import hashlib
import shutil
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from haberdasher.admission import AdmissionFailure, admit
from haberdasher.core import AdmittedAsset, RetainedFormat, sha256_file
from haberdasher.formats import apt
from haberdasher.runtime import private_workspace
from haberdasher.signing import SigningFailure, signing_session
from tests.native.fixtures.apt import Client, build, policy, publish
from tests.support.http import serve
from tests.support.keys import disposable_key


def test_client_configures_runtime_gpgv(monkeypatch: pytest.MonkeyPatch) -> None:
    with private_workspace() as runtime:
        gpgv = shutil.which("gpgv", path=runtime.environment["PATH"])
        assert gpgv is not None and Path(gpgv).is_absolute()
        monkeypatch.setenv("PATH", str(runtime.root / "absent-bin"))
        client = Client(runtime, "verifier", "http://127.0.0.1:9", runtime.root / "public.gpg")
        result = runtime.run(
            [
                "env",
                f"APT_CONFIG={client.config}",
                "apt-config",
                "shell",
                "verifier",
                "Apt::Key::gpgvcommand",
            ]
        )
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout.decode() == f"verifier='{gpgv}'\n"


def test_production_apt_install_update_and_rejections() -> None:
    with private_workspace() as runtime, disposable_key() as key:
        config = policy()
        now = datetime.now(UTC).replace(microsecond=0)
        empty = RetainedFormat("apt", None, (), (), {}, ())
        apt.validate_retained(empty, policy=config, runtime=runtime)
        dep = build(runtime, "hd-dependency", "1.0", "dependency", arch="all", asset_id=1)
        second_dep = build(runtime, "hd-extra", "1.0", "extra", arch="all", asset_id=2)
        first = build(
            runtime,
            "hd-application",
            "1.0",
            "first",
            depends="hd-dependency (>= 1.0),\n hd-extra",
            asset_id=3,
        )
        second = build(
            runtime,
            "hd-application",
            "2.0",
            "second",
            depends="hd-dependency (>= 1.0), hd-extra",
            asset_id=4,
        )
        equivalent = build(runtime, "hd-application", "1.0-0", "conflict", asset_id=5)
        history: list[AdmittedAsset] = []
        for asset in (dep, second_dep, first):
            inspected = apt.inspect(
                asset,
                policy=config,
                runtime=runtime,
                out=runtime.root / f"inspect-{asset.source.asset_id}",
            )
            history.append(
                admit(inspected, history, compare=apt.compare, policy=config, runtime=runtime)
            )
        assert "hd-extra" in str(history[-1].inspected.evidence["dependencies"])
        raw_record = str(history[-1].inspected.metadata["record"])
        assert " Complete multiline description." in raw_record
        assert "X-Haberdasher-Fixture: preserved-extension" in raw_record
        conflict = apt.inspect(
            equivalent, policy=config, runtime=runtime, out=runtime.root / "conflict"
        )
        with pytest.raises(AdmissionFailure, match="Changed bytes"):
            admit(conflict, history, compare=apt.compare, policy=config, runtime=runtime)
        assert (
            admit(
                history[-1].inspected, history, compare=apt.compare, policy=config, runtime=runtime
            )
            is history[-1]
        )
        with signing_session(
            runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer:
            initial = apt.prepare(
                history,
                empty,
                policy=config,
                runtime=runtime,
                signer=signer,
                now=now,
                out=runtime.root / "generation-one",
            )
            apt.validate_prepared(initial, policy=config, runtime=runtime, now=now)
            assert all(
                item.published_sha256 == item.inspected.verified.sha256
                for item in initial.retained.accepted_history
            )
            arm = (
                runtime.root / "generation-one/dists/proof/main/binary-arm64/Packages"
            ).read_text()
            assert "Package: hd-dependency" in arm and "Package: hd-extra" in arm
            assert "Package: hd-application" not in arm
            http_root = runtime.root / "http"
            live = http_root / "live"
            retained = publish(initial, live, 1)
            apt.validate_retained(retained, policy=config, runtime=runtime)
            with patch.object(
                runtime, "run", side_effect=AssertionError("Fresh no-op called a native command")
            ):
                unchanged = apt.prepare(
                    [],
                    retained,
                    policy=config,
                    runtime=runtime,
                    signer=signer,
                    now=now + timedelta(seconds=1),
                    out=runtime.root / "unused",
                )
            assert not unchanged.outputs and unchanged.retained is retained
            assert not (runtime.root / "unused").exists()
            renewal_time = now + timedelta(seconds=config.validity_seconds - config.renewal_seconds)
            with patch.object(runtime, "run", wraps=runtime.run) as commands:
                renewed = apt.prepare(
                    [],
                    retained,
                    policy=config,
                    runtime=runtime,
                    signer=signer,
                    now=renewal_time,
                    out=runtime.root / "renewal",
                )
            assert [item.ref.key for item in renewed.outputs] == [
                "dists/proof/Release",
                "dists/proof/Release.gpg",
                "dists/proof/InRelease",
            ]
            assert not any(
                call.args[0][0] in {"dpkg", "dpkg-deb", "apt-ftparchive"}
                for call in commands.call_args_list
            )
            with pytest.raises(apt.AptFailure, match="regeneration is required"):
                apt.validate_prepared(
                    initial,
                    policy=config,
                    runtime=runtime,
                    now=now + timedelta(seconds=config.validity_seconds),
                )
            with serve(http_root) as server:
                client = Client(runtime, "normal", server.url("live"), key.public_file)
                client.apt("update")
                client.apt("install", "-y", "hd-application=1.0")
                client.installed("hd-application", "1.0", "first")
                client.installed("hd-dependency", "1.0", "dependency")
                client.installed("hd-extra", "1.0", "extra")
                client.apt("update")
                assert any(
                    record.status == 304 and record.path.endswith("/InRelease")
                    for record in server.requests()
                )
                for asset in (dep, second_dep, first):
                    asset.local_path.unlink()
                inspected = apt.inspect(
                    second, policy=config, runtime=runtime, out=runtime.root / "inspect-second"
                )
                accepted = admit(
                    inspected,
                    retained.accepted_history,
                    compare=apt.compare,
                    policy=config,
                    runtime=runtime,
                )
                updated = apt.prepare(
                    [accepted],
                    retained,
                    policy=config,
                    runtime=runtime,
                    signer=signer,
                    now=now,
                    out=runtime.root / "generation-two",
                )
                assert (
                    raw_record == updated.retained.accepted_history[2].inspected.metadata["record"]
                )
                assert (
                    len([item for item in updated.outputs if item.ref.object_class == "package"])
                    == 1
                )
                assert len(updated.retained.accepted_history) == 4
                for item in initial.retained.objects:
                    if item.object_class in {"package", "dependency"}:
                        assert item in updated.referenced_objects
                retained_two = publish(updated, live, 2)
                client.apt("update")
                client.apt("upgrade", "-y")
                client.installed("hd-application", "2.0", "second")
                client.installed("hd-dependency", "1.0", "dependency")
                assert sha256_file(live / f"pool/{first.sha256}.deb") == (first.sha256, first.size)
                assert sha256_file(live / f"pool/{second.sha256}.deb") == (
                    second.sha256,
                    second.size,
                )
                delayed = http_root / "delayed"
                shutil.copytree(live, delayed)
                shutil.copyfile(
                    runtime.root / "generation-one/dists/proof/InRelease",
                    delayed / "dists/proof/InRelease",
                )
                server.set_generation_mtime([delayed / "dists/proof/InRelease"], 1)
                old = Client(runtime, "delayed", server.url("delayed"), key.public_file)
                old.apt("update")
                old_hash = sha256_file(
                    runtime.root / "generation-one/dists/proof/main/binary-amd64/Packages.gz"
                )[0]
                assert any(
                    record.path
                    == f"/delayed/dists/proof/main/binary-amd64/by-hash/SHA256/{old_hash}"
                    and record.status == 200
                    for record in server.requests()
                )
                old.apt("install", "-y", "hd-application")
                old.installed("hd-application", "1.0", "first")
                old.installed("hd-extra", "1.0", "extra")
                detached = http_root / "detached"
                shutil.copytree(live, detached)
                (detached / "dists/proof/InRelease").unlink()
                fallback = Client(runtime, "detached", server.url("detached"), key.public_file)
                fallback.apt("update")
                fallback.apt("install", "-y", "hd-application")
                fallback.installed("hd-application", "2.0", "second")
                assert any(
                    record.path == "/detached/dists/proof/Release.gpg" and record.status == 200
                    for record in server.requests()
                )
                with disposable_key() as wrong:
                    negative = Client(runtime, "wrong-key", server.url("live"), wrong.public_file)
                    negative.apt("update", succeeds=False)
                    negative.apt("install", "-y", "hd-application", succeeds=False)
                    negative.not_installed("hd-application")
                missing = Client(
                    runtime, "missing-key", server.url("live"), runtime.root / "absent.gpg"
                )
                missing.apt("update", succeeds=False)
                missing.apt("install", "-y", "hd-application", succeeds=False)
                missing.not_installed("hd-application")
                new_hash = sha256_file(
                    runtime.root / "generation-two/dists/proof/main/binary-amd64/Packages.gz"
                )[0]
                for name, target in (
                    ("signature", "dists/proof/InRelease"),
                    ("index", f"dists/proof/main/binary-amd64/by-hash/SHA256/{new_hash}"),
                    ("package", f"pool/{second.sha256}.deb"),
                ):
                    damaged = http_root / name
                    shutil.copytree(live, damaged)
                    path = damaged / target
                    data = path.read_bytes()
                    path.write_bytes(
                        data.replace(b"Suite: proof", b"Suite: wrong")
                        if name == "signature"
                        else b"X" + data[1:]
                    )
                    bad = Client(runtime, name, server.url(name), key.public_file)
                    bad.apt("update", succeeds=name == "package")
                    bad.apt("install", "-y", "hd-application", succeeds=False)
                    bad.not_installed("hd-application")
                expired = apt.prepare(
                    [accepted],
                    empty,
                    policy=config,
                    runtime=runtime,
                    signer=signer,
                    now=now - timedelta(days=8),
                    out=runtime.root / "expired-generation",
                )
                publish(expired, http_root / "expired", 3)
                bad = Client(runtime, "expired", server.url("expired"), key.public_file)
                assert b"expired" in bad.apt("update", succeeds=False)
                bad.apt("install", "-y", "hd-application", succeeds=False)
                bad.not_installed("hd-application")
                with patch.object(
                    signer, "sign_file", side_effect=SigningFailure("injected failure")
                ):
                    with pytest.raises(SigningFailure):
                        apt.prepare(
                            [],
                            retained_two,
                            policy=config,
                            runtime=runtime,
                            signer=signer,
                            now=renewal_time,
                            out=runtime.root / "failed-signing",
                        )
                with patch.object(signer, "sign_file", return_value=None):
                    with pytest.raises((ValueError, OSError)):
                        apt.prepare(
                            [],
                            retained_two,
                            policy=config,
                            runtime=runtime,
                            signer=signer,
                            now=renewal_time,
                            out=runtime.root / "missing-signature",
                        )
                fetched = server.requests()
                assert any(
                    record.path == f"/live/pool/{second.sha256}.deb"
                    and record.bytes_sent == second.size
                    for record in fetched
                )
                print(
                    f"Installed: 1.0 -> 2.0; delayed=1.0; dependencies=hd-dependency,hd-extra; HTTP requests={len(fetched)}"
                )
        apt.validate_prepared(updated, policy=config, runtime=runtime, now=now)
        broken = replace(
            updated.retained,
            objects=tuple(
                ref for ref in updated.retained.objects if ref.object_class != "dependency"
            ),
        )
        with pytest.raises(apt.AptFailure, match="incomplete"):
            apt.validate_retained(broken, policy=config, runtime=runtime)
        frozen = runtime.root / "generation-two/dists/proof/InRelease"
        frozen.write_bytes(frozen.read_bytes() + b"corruption")
        with pytest.raises(apt.AptFailure, match="changed"):
            apt.validate_prepared(updated, policy=config, runtime=runtime, now=now)
        print(client.apt("--version").decode().splitlines()[0])
        for command in (["dpkg-query", "--version"], ["gpg", "--version"]):
            result = runtime.run(command)
            assert result.returncode == 0
            print(result.stdout.decode().splitlines()[0])


def test_deterministic_gzip() -> None:
    data = b"Package: hd-test\nVersion: 1.0\n\n"
    left = gzip.compress(data, mtime=0)
    assert left == gzip.compress(data, mtime=0)
    assert gzip.decompress(left) == data
    assert (
        hashlib.sha256(left).hexdigest() == hashlib.sha256(gzip.compress(data, mtime=0)).hexdigest()
    )
