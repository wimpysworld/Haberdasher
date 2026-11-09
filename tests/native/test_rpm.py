from __future__ import annotations

import gzip
import hashlib
import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from haberdasher.admission import AdmissionFailure, admit
from haberdasher.config import FormatPolicy
from haberdasher.core import (
    NativeIdentity,
    RetainedFormat,
    canonical_json,
    sha256_file,
)
from haberdasher.formats import rpm
from haberdasher.runtime import private_workspace
from haberdasher.signing import SigningFailure, signing_session
from tests.native.fixtures.rpm import NOW, DnfClient, build, checked, publish
from tests.support.http import serve
from tests.support.keys import disposable_key

POLICY = FormatPolicy("rpm")


def test_rpm_adapter_http_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    with (
        disposable_key() as key,
        private_workspace() as runtime,
        signing_session(
            runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer,
    ):
        calls: list[tuple[str, ...]] = []
        original_run = runtime.run

        def traced(
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            input: bytes | None = None,
            timeout: float = 120,
            env_kind: str = "native",
        ) -> subprocess.CompletedProcess[bytes]:
            calls.append(tuple(argv))
            return original_run(argv, cwd=cwd, input=input, timeout=timeout, env_kind=env_kind)

        monkeypatch.setattr(runtime, "run", traced)
        data = build(runtime, "hd-proof-data", "1", "dependency-v1", number=1)
        app = build(runtime, "hd-proof-app", "1", "application-v1", number=2)
        update = build(runtime, "hd-proof-app", "2", "application-v2", epoch=0, number=3)
        empty = RetainedFormat("rpm", None, (), (), {}, ())
        admissions = [
            admit(
                rpm.inspect(asset, policy=POLICY, runtime=runtime, out=runtime.root),
                (),
                compare=rpm.compare,
                policy=POLICY,
                runtime=runtime,
            )
            for asset in (data, app)
        ]
        first = rpm.prepare(
            admissions,
            empty,
            policy=POLICY,
            runtime=runtime,
            signer=signer,
            now=NOW,
            out=runtime.root / "one",
        )
        first_hash = hashlib.sha256(canonical_json(first)).hexdigest()
        assert len(first.retained.accepted_history) == 2
        assert all(
            asset.published_sha256 != asset.inspected.verified.sha256
            for asset in first.retained.accepted_history
        )
        assert first.outputs[-2].ref.key == "repodata/repomd.xml"
        assert first.outputs[-1].ref.key == "repodata/repomd.xml.asc"
        first_root = runtime.root / "one"
        ring = first_root / "public.gpg"
        for asset in first.retained.accepted_history:
            records = asset.inspected.metadata["rpm_records"]
            assert isinstance(records, dict)
            assert set(records) == {"primary", "filelists", "other"}
            assert b"/opt/hd-proof/" in canonical_json(records["filelists"])
            assert b"Fixture payload" in canonical_json(records["other"])
            if asset.inspected.identity.name == "hd-proof-app":
                assert b"hd-proof-data" in canonical_json(records["primary"])
        installed = runtime.root / "published"
        installed.mkdir()
        with serve(installed) as server:
            publish(first, installed, server, 1)
            client = DnfClient(runtime, "positive", server.url(), ring)
            client.run("install", "hd-proof-app")
            client.state("1")
            providers = client.run("repoquery", "--whatprovides", "/opt/hd-proof/hd-proof-data")
            assert b"hd-proof-data-0:1-1.noarch" in providers
            cached = list(client.base.glob("cache/**/packages/*.rpm"))
            expected = {
                item.ref.sha256 for item in first.outputs if item.ref.object_class == "package"
            }
            assert {sha256_file(path)[0] for path in cached} == expected
            equivalent = build(
                runtime, "hd-proof-app", "1", "conflicting-payload", epoch=0, number=4
            )
            inspected = rpm.inspect(equivalent, policy=POLICY, runtime=runtime, out=runtime.root)
            with pytest.raises(AdmissionFailure, match="Changed bytes"):
                admit(
                    inspected,
                    first.retained.accepted_history,
                    compare=rpm.compare,
                    policy=POLICY,
                    runtime=runtime,
                )
            left = NativeIdentity("rpm", "app", "noarch", "1.01", release="1")
            assert rpm.compare(left, replace(left, version="1.1"), runtime=runtime) == 0
            assert rpm.compare(left, replace(left, epoch=1), runtime=runtime) == -1
            for output in first.outputs:
                if output.ref.object_class == "package":
                    signed = replace(
                        app,
                        local_path=output.local_path,
                        sha256=output.ref.sha256,
                        size=output.ref.size,
                        source=replace(app.source, size=output.ref.size),
                    )
                    with pytest.raises(rpm.RpmFailure, match="Signed upstream"):
                        rpm.inspect(signed, policy=POLICY, runtime=runtime, out=runtime.root)
            retained = replace(
                first.retained,
                prior_generation="one",
                metadata={
                    **first.retained.metadata,
                    "etags": {key: "first-etag" for key in rpm.ENTRIES},
                },
            )
            accepted = admit(
                rpm.inspect(update, policy=POLICY, runtime=runtime, out=runtime.root),
                retained.accepted_history,
                compare=rpm.compare,
                policy=POLICY,
                runtime=runtime,
            )
            # Remove only fixture-owned bytes after publication. Preparation has metadata only.
            for asset in (data, app):
                asset.local_path.unlink()
            for output in first.outputs:
                if output.ref.object_class == "package":
                    output.local_path.unlink()
            before = len(calls)
            second = rpm.prepare(
                [accepted],
                retained,
                policy=POLICY,
                runtime=runtime,
                signer=signer,
                now=NOW,
                out=runtime.root / "two",
            )
            second_calls = calls[before:]
            assert len([call for call in second_calls if "rpmsign" in call]) == 1
            assert len([call for call in second_calls if call[0] == "createrepo_c"]) == 1
            assert not any(
                str(app.local_path) in call or str(data.local_path) in call for call in second_calls
            )
            reads = (runtime.root / "two/read.list").read_text().splitlines()
            assert reads == [
                item.ref.key for item in second.outputs if item.ref.object_class == "package"
            ]
            for old, current in zip(
                first.retained.accepted_history, second.retained.accepted_history, strict=False
            ):
                assert old == current
            assert len(second.retained.accepted_history) == 3
            frozen = {item.ref.key: item.local_path.read_bytes() for item in second.outputs}
            publish(second, installed, server, 2)
            client.run("upgrade", "hd-proof-app")
            client.state("2")
            assert any(
                record.path.endswith(".rpm") and record.status == 200
                for record in server.requests()
            )
            for output in second.outputs:
                if output.ref.object_class == "package":
                    assert any(
                        sha256_file(path)[0] == output.ref.sha256
                        for path in client.base.glob("cache/**/packages/*.rpm")
                    )
            for mode in (
                "missing-metadata",
                "old-entry-new-signature",
                "new-entry-old-signature",
                "unsigned-package",
            ):
                negative_root = installed / mode
                negative_root.mkdir()
                for path in installed.glob("packages/**/*.rpm"):
                    target = negative_root / path.relative_to(installed)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
                # Frozen generation one package outputs are unavailable, but their published bytes remain.
                for output in first.outputs:
                    if output.ref.object_class != "package":
                        target = negative_root / output.ref.key
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(output.local_path, target)
                server.set_generation_mtime(list(negative_root.rglob("*.*")), 10)
                negative = DnfClient(runtime, mode, server.url(mode) + "/", ring)
                negative.run("install", "hd-proof-app")
                negative.state("1")
                publish(second, negative_root, server, 11)
                if mode == "missing-metadata":
                    (negative_root / rpm.ENTRIES[1]).unlink()
                elif mode == "old-entry-new-signature":
                    shutil.copyfile(first_root / rpm.ENTRIES[0], negative_root / rpm.ENTRIES[0])
                elif mode == "new-entry-old-signature":
                    shutil.copyfile(first_root / rpm.ENTRIES[1], negative_root / rpm.ENTRIES[1])
                else:
                    package = next(
                        item for item in second.outputs if item.ref.object_class == "package"
                    )
                    shutil.copyfile(update.local_path, negative_root / package.ref.key)
                    checked(
                        runtime,
                        "createrepo_c",
                        "--general-compress-type",
                        "gz",
                        "--checksum",
                        "sha256",
                        "--no-database",
                        str(negative_root),
                    )
                    signer.sign_file(negative_root / rpm.ENTRIES[0], negative_root / rpm.ENTRIES[1])
                server.set_generation_mtime(
                    [path for path in negative_root.rglob("*") if path.is_file()], 12
                )
                failure = negative.run("upgrade", "hd-proof-app", success=False).lower()
                assert (
                    b"signature" in failure
                    or b"not signed" in failure
                    or b"repomd.xml.asc" in failure
                )
                negative.state("1")
                publish(second, negative_root, server, 13)
                negative.run("upgrade", "hd-proof-app")
                negative.state("2")
            assert frozen == {item.ref.key: item.local_path.read_bytes() for item in second.outputs}
            assert first_hash == hashlib.sha256(canonical_json(first)).hexdigest()
            original_sign = signer.sign_file

            def forbidden(*args: object, **kwargs: object) -> None:
                raise AssertionError("Frozen validation called a signer")

            monkeypatch.setattr(signer, "sign_file", forbidden)
            rpm.validate_prepared(second, policy=POLICY, runtime=runtime, now=NOW)
            monkeypatch.setattr(signer, "sign_file", original_sign)
            print(
                "RPM STATE: same-client app 1 -> 2; dependency 1; both payloads; file provider; HTTP package hashes"
            )
            print(
                "RPM TRUST: package and repomd rejection; both split orders recover without cache deletion"
            )
        for kind in rpm.NAMESPACES:
            for mode in ("missing", "corrupt", "incomplete", "malformed"):
                root = runtime.root / f"damaged-{kind}-{mode}"
                shutil.copytree(first_root / "repodata", root / "repodata")
                retained_bad = replace(
                    first.retained, metadata={**first.retained.metadata, "root": str(root)}
                )
                document = ET.parse(root / rpm.ENTRIES[0])
                entry = next(node for node in document.getroot() if node.attrib.get("type") == kind)
                location = entry.find(rpm.REPO + "location")
                assert location is not None
                path = root / location.attrib["href"]
                if mode == "missing":
                    path.unlink()
                elif mode == "corrupt":
                    path.write_bytes(b"corrupt")
                else:
                    if mode == "malformed":
                        opened = b"<broken>"
                    else:
                        packages = ET.fromstring(gzip.decompress(path.read_bytes()))
                        packages.remove(packages[0])
                        packages.set("packages", str(len(packages)))
                        opened = ET.tostring(packages)
                    compressed = gzip.compress(opened)
                    path.write_bytes(compressed)
                    for field, value in (
                        ("checksum", hashlib.sha256(compressed).hexdigest()),
                        ("open-checksum", hashlib.sha256(opened).hexdigest()),
                        ("size", str(len(compressed))),
                        ("open-size", str(len(opened))),
                    ):
                        element = entry.find(rpm.REPO + field)
                        assert element is not None
                        element.text = value
                    document.write(root / rpm.ENTRIES[0], encoding="utf-8", xml_declaration=True)
                    signer.sign_file(root / rpm.ENTRIES[0], root / rpm.ENTRIES[1])
                with pytest.raises((ValueError, OSError)):
                    rpm.validate_retained(retained_bad, policy=POLICY, runtime=runtime)
        with disposable_key() as wrong:
            wrong_trust = replace(
                second.retained,
                metadata={
                    **second.retained.metadata,
                    "keyring": str(wrong.public_file),
                    "keyring_sha256": sha256_file(wrong.public_file)[0],
                    "fingerprint": wrong.fingerprint,
                },
            )
            with pytest.raises(rpm.RpmFailure):
                rpm.validate_retained(wrong_trust, policy=POLICY, runtime=runtime)
            package = next(item for item in second.outputs if item.ref.object_class == "package")
            with pytest.raises(rpm.RpmFailure):
                rpm._verify_package(package.local_path, wrong.public_file, runtime)
        second_package = next(item for item in second.outputs if item.ref.object_class == "package")
        second_package.local_path.write_bytes(b"changed frozen bytes")
        with pytest.raises(rpm.RpmFailure, match="Prepared"):
            rpm.validate_prepared(second, policy=POLICY, runtime=runtime, now=NOW)


def test_signer_failure_does_not_produce_prepared_state(monkeypatch: pytest.MonkeyPatch) -> None:
    with (
        disposable_key() as key,
        private_workspace() as runtime,
        signing_session(
            runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer,
    ):
        asset = build(runtime, "hd-proof-data", "1", "dependency-v1")
        accepted = admit(
            rpm.inspect(asset, policy=POLICY, runtime=runtime, out=runtime.root),
            (),
            compare=rpm.compare,
            policy=POLICY,
            runtime=runtime,
        )
        empty = RetainedFormat("rpm", None, (), (), {}, ())
        before = canonical_json(empty)

        def fail(source: Path, output: Path, *, clear: bool = False, armour: bool = True) -> None:
            raise SigningFailure("injected signer failure")

        monkeypatch.setattr(signer, "sign_file", fail)
        with pytest.raises(SigningFailure):
            rpm.prepare(
                [accepted],
                empty,
                policy=POLICY,
                runtime=runtime,
                signer=signer,
                now=NOW,
                out=runtime.root / "failed",
            )
        assert canonical_json(empty) == before
        assert sha256_file(asset.local_path) == (asset.sha256, asset.size)
