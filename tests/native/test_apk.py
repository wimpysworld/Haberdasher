# pyright: reportPrivateUsage=false

"""Production APK adapter acceptance with disposable loopback clients."""

import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from haberdasher.admission import AdmissionFailure, admit
from haberdasher.config import FormatPolicy
from haberdasher.core import (
    AdmittedAsset,
    JSONValue,
    PreparedFormat,
    RetainedFormat,
    UnsupportedAsset,
    VerifiedAsset,
    atomic_write,
    canonical_json,
    sha256_file,
)
from haberdasher.formats import apk
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import signing_session
from tests.native.fixtures.apk import (
    Client,
    archive,
    committed,
    fixture,
    tamper,
    verified,
    wrong_public_key,
)
from tests.support.http import serve
from tests.support.keys import disposable_key, run

NOW = datetime(2026, 1, 1, tzinfo=UTC)
POLICY = FormatPolicy("apk")
EMPTY = RetainedFormat("apk", (), (), {}, ())


def publish(prepared: PreparedFormat, root: Path) -> list[Path]:
    paths: list[Path] = []
    for output in prepared.outputs:
        path = root / output.ref.key
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output.local_path, path)
        assert sha256_file(path) == (output.ref.sha256, output.ref.size)
        paths.append(path)
    return paths


def accept(
    asset: VerifiedAsset,
    runtime: Runtime,
    history: Sequence[AdmittedAsset] = (),
    policy: FormatPolicy = POLICY,
) -> AdmittedAsset:
    item = apk.inspect(asset, policy=policy, runtime=runtime, out=runtime.root / "inspection")
    return admit(item, history, compare=apk.compare, policy=policy, runtime=runtime)


def test_unsigned_two_generations_http_and_rejections() -> None:
    with (
        private_workspace() as runtime,
        disposable_key() as key,
        signing_session(
            runtime,
            expected_fingerprint=key.fingerprint,
            key_file=key.key_file,
        ) as signer,
    ):
        print(run(runtime, "apk", "--version").decode().strip())
        dep = fixture(runtime, "hd-dependency", "1.0-r0", payload="dependency-data")
        first = fixture(
            runtime, "hd-main", "1.0-r1", payload="version-one", dependency="hd-dependency>=1.0-r0"
        )
        second = fixture(
            runtime, "hd-main", "2.0-r0", payload="version-two", dependency="hd-dependency>=1.0-r0"
        )
        accepted = [accept(asset, runtime) for asset in (dep, first)]
        assert all(item.inspected.upstream_signature == "unsigned" for item in accepted)
        assert (
            apk.compare(
                accepted[1].inspected.identity,
                replace(accepted[1].inspected.identity, version="1.0-r01"),
                runtime=runtime,
            )
            == 0
        )
        assert (
            admit(
                accepted[1].inspected, accepted, compare=apk.compare, policy=POLICY, runtime=runtime
            )
            == accepted[1]
        )
        equivalent = fixture(
            runtime, "hd-main", "1.0-r01", payload="changed", dependency="hd-dependency>=1.0-r0"
        )
        with pytest.raises(AdmissionFailure, match="Changed bytes"):
            accept(equivalent, runtime, accepted)
        generation1 = apk.prepare(
            accepted,
            EMPTY,
            policy=POLICY,
            runtime=runtime,
            signer=signer,
            now=NOW,
            out=runtime.root / "generation1",
        )
        apk.validate_retained(generation1.retained, policy=POLICY, runtime=runtime)
        public = runtime.root / "public"
        public.mkdir()
        with serve(public) as http:
            http.set_generation_mtime(publish(generation1, public), 1)
            client = Client(runtime, "trusted", http.url(), public / "keys/wimpysworld.rsa.pub")
            standalone = client.run("verify", str(first.local_path), check=False)
            assert standalone.returncode != 0
            client.add("hd-main=1.0-r1")
            client.installed("hd-main", "1.0-r1", "version-one")
            client.installed("hd-dependency", "1.0-r0", "dependency-data")
            downloaded1 = client.fetch("downloads-one", "hd-main=1.0-r1")
            assert {p.name for p in downloaded1.iterdir()} == {
                "hd-main-1.0-r1.apk",
                "hd-dependency-1.0-r0.apk",
            }
            for asset, filename in (
                (first, "hd-main-1.0-r1.apk"),
                (dep, "hd-dependency-1.0-r0.apk"),
            ):
                assert sha256_file(downloaded1 / filename) == (asset.sha256, asset.size)
                assert sha256_file(public / "x86_64" / filename) == (asset.sha256, asset.size)
            state = committed(generation1)
            # Preparation needs retained records, not historical source packages.
            first.local_path.rename(first.local_path.with_suffix(".unavailable"))
            dep.local_path.rename(dep.local_path.with_suffix(".unavailable"))
            addition = accept(second, runtime, state.accepted_history)
            generation2 = apk.prepare(
                [addition],
                state,
                policy=POLICY,
                runtime=runtime,
                signer=signer,
                now=NOW,
                out=runtime.root / "generation2",
            )
            assert [output.ref.object_class for output in generation2.outputs] == [
                "package",
                "entry",
            ]
            assert generation2.outputs[-1].expected_etag == '"synthetic-etag"'
            assert len(generation2.retained.accepted_history) == 3
            records = apk._records(
                run(
                    runtime, "tar", "-xOzf", str(generation2.outputs[-1].local_path), "APKINDEX"
                ).decode()
            )
            expected: dict[tuple[str, str, str], str] = {}
            for item in generation2.retained.accepted_history:
                expected.update(apk._records(cast(str, item.inspected.metadata["stanza"])))
                assert item.published_sha256 == item.inspected.verified.sha256
            assert records == expected
            assert all(
                "D:hd-dependency>=1.0-r0\n" in text
                for identity, text in records.items()
                if identity[0] == "hd-main"
            )
            before = canonical_json(generation2)
            with (
                patch.object(apk, "prepare", side_effect=AssertionError("No retry preparation")),
                patch.object(
                    type(signer), "alpine_key", side_effect=AssertionError("No retry signing")
                ),
            ):
                apk.validate_prepared(generation2, policy=POLICY, runtime=runtime)
                http.set_generation_mtime(publish(generation2, public), 2)
                apk.validate_prepared(generation2, policy=POLICY, runtime=runtime)
            assert canonical_json(generation2) == before
            client.run("update")
            client.add("hd-main=2.0-r0")
            client.installed("hd-main", "2.0-r0", "version-two")
            client.installed("hd-dependency", "1.0-r0", "dependency-data")
            downloaded2 = client.fetch("downloads-two", "hd-main=2.0-r0")
            assert {p.name for p in downloaded2.iterdir()} == {
                "hd-main-2.0-r0.apk",
                "hd-dependency-1.0-r0.apk",
            }
            assert sha256_file(downloaded2 / "hd-main-2.0-r0.apk") == (second.sha256, second.size)
            assert sha256_file(downloaded2 / "hd-dependency-1.0-r0.apk") == (dep.sha256, dep.size)
            assert (public / "x86_64/hd-main-1.0-r1.apk").is_file()
            assert not any(
                "--allow-untrusted" in command.argv for command in client.native.commands
            )
            requests = http.requests()
            for path in (
                "/x86_64/APKINDEX.tar.gz",
                "/x86_64/hd-main-1.0-r1.apk",
                "/x86_64/hd-main-2.0-r0.apk",
                "/x86_64/hd-dependency-1.0-r0.apk",
            ):
                assert any(
                    record.path == path and record.status == 200 and record.bytes_sent > 0
                    for record in requests
                )
            for name, trust in (
                ("missing-key", None),
                ("bad-key", public / "keys/wimpysworld.rsa.pub"),
            ):
                negative = Client(runtime, name, http.url(), trust)
                if name == "bad-key":
                    wrong_public_key(
                        runtime,
                        public / "keys/wimpysworld.rsa.pub",
                        negative.keys / "wimpysworld.rsa.pub",
                    )
                assert (
                    negative.run(
                        "verify", str(public / "x86_64/APKINDEX.tar.gz"), check=False
                    ).returncode
                    != 0
                )
                assert negative.add("hd-main=2.0-r0", check=False).returncode != 0
                fetched = negative.fetch("downloads", "hd-main=2.0-r0", check=False)
                assert not list(fetched.iterdir())
                assert not (negative.root / "usr/share/hd-main/payload").exists()
                assert negative.run("info", "--installed", "hd-main", check=False).returncode != 0
        # Use fresh clients and unmodified signed indexes for both package corruptions.
        for kind in ("control", "payload", "index"):
            root = runtime.root / f"bad-{kind}"
            publish(generation1, root)
            if kind != "index":
                changed = tamper(runtime, first, kind, root / "x86_64/hd-main-1.0-r1.apk")
                if kind == "payload":
                    with pytest.raises(apk.ApkFailure, match="datahash"):
                        accept(changed, runtime)
                else:
                    with pytest.raises(AdmissionFailure, match="Changed bytes"):
                        accept(changed, runtime, state.accepted_history)
            else:
                work = runtime.root / "index-corruption"
                work.mkdir()
                parts = apk._parts(root / "x86_64/APKINDEX.tar.gz", work)
                content = work / "content"
                content.mkdir()
                run(runtime, "tar", "-xzf", str(parts[1]), "-C", str(content))
                atomic_write(content / "DESCRIPTION", b"changed\n")
                atomic_write(
                    root / "x86_64/APKINDEX.tar.gz",
                    parts[0].read_bytes() + archive(runtime, content, "DESCRIPTION", "APKINDEX"),
                )
            with serve(root) as http:
                negative = Client(
                    runtime, f"bad-{kind}", http.url(), root / "keys/wimpysworld.rsa.pub"
                )
                assert (
                    negative.run(
                        "verify", str(root / "x86_64/APKINDEX.tar.gz"), check=False
                    ).returncode
                    == 0
                ) == (kind != "index")
                assert negative.add("hd-main=1.0-r1", check=False).returncode != 0
                assert not (negative.root / "usr/share/hd-main/payload").exists()
                assert negative.run("info", "--installed", "hd-main", check=False).returncode != 0
                fetched = negative.fetch("downloads", "hd-main=1.0-r1", check=False)
                assert not (fetched / "hd-main-1.0-r1.apk").exists()
                assert all(
                    path.name == "hd-dependency-1.0-r0.apk"
                    and sha256_file(path) == (dep.sha256, dep.size)
                    for path in fetched.iterdir()
                )
        # Missing native inputs must fail before a prepared generation can exist.
        old_indexes = cast(dict[str, dict[str, JSONValue]], state.metadata["indexes"])
        broken = replace(
            state,
            metadata={
                **state.metadata,
                "indexes": {
                    "x86_64": {**old_indexes["x86_64"], "local_path": str(runtime.root / "absent")}
                },
            },
        )
        with pytest.raises(ValueError):
            apk.prepare(
                [addition],
                broken,
                policy=POLICY,
                runtime=runtime,
                signer=signer,
                now=NOW,
                out=runtime.root / "missing-index",
            )
        missing = replace(
            addition,
            inspected=replace(
                addition.inspected, verified=replace(second, local_path=runtime.root / "absent.apk")
            ),
        )
        with pytest.raises(ValueError):
            apk.prepare(
                [missing],
                state,
                policy=POLICY,
                runtime=runtime,
                signer=signer,
                now=NOW,
                out=runtime.root / "missing-input",
            )
        with patch.object(
            type(signer),
            "alpine_key",
            return_value=(runtime.root / "absent-key", public / "keys/wimpysworld.rsa.pub"),
        ):
            with pytest.raises(apk.ApkFailure, match="Missing APK signing"):
                apk.prepare(
                    [addition],
                    state,
                    policy=POLICY,
                    runtime=runtime,
                    signer=signer,
                    now=NOW,
                    out=runtime.root / "missing-signer",
                )
        original_run = runtime.run
        for signer_exit in (0, 1):

            def failed_signer(
                argv: Sequence[str],
                *,
                input: bytes | None = None,
                env_kind: str = "native",
                exit_code: int = signer_exit,
            ) -> subprocess.CompletedProcess[bytes]:
                if "abuild-sign" in argv:
                    return subprocess.CompletedProcess(
                        argv, exit_code, b"", b"synthetic signer failure"
                    )
                return original_run(argv, input=input, env_kind=env_kind)

            with patch.object(runtime, "run", side_effect=failed_signer):
                with pytest.raises(apk.ApkFailure):
                    apk.prepare(
                        [addition],
                        state,
                        policy=POLICY,
                        runtime=runtime,
                        signer=signer,
                        now=NOW,
                        out=runtime.root / f"failed-signer-{signer_exit}",
                    )
        native_missing = runtime.root / "native-missing.tar.gz"
        run(
            runtime,
            "apk",
            "--no-network",
            "--repositories-file",
            "/dev/null",
            "index",
            "--merge",
            "--index",
            str(generation1.outputs[-1].local_path),
            "--output",
            str(native_missing),
            "--keys-dir",
            str(public / "keys"),
            str(runtime.root / "absent.apk"),
        )
        assert apk._records(
            run(runtime, "tar", "-xOzf", str(native_missing), "APKINDEX").decode()
        ) == apk._records(
            run(
                runtime, "tar", "-xOzf", str(generation1.outputs[-1].local_path), "APKINDEX"
            ).decode()
        )
        reversed_outputs = tuple(
            replace(output, ordinal=ordinal)
            for ordinal, output in enumerate(reversed(generation2.outputs))
        )
        with pytest.raises(apk.ApkFailure, match="precede"):
            apk.validate_prepared(
                replace(generation2, outputs=reversed_outputs),
                policy=POLICY,
                runtime=runtime,
            )
        incomplete = replace(
            state.accepted_history[0],
            inspected=replace(
                state.accepted_history[0].inspected,
                metadata={"stanza": state.accepted_history[0].inspected.metadata["stanza"]},
            ),
        )
        with pytest.raises(apk.ApkFailure):
            apk.validate_retained(
                replace(state, accepted_history=(incomplete, *state.accepted_history[1:])),
                policy=POLICY,
                runtime=runtime,
            )
        for metadata in ({}, {**state.metadata, "indexes": {}}):
            with pytest.raises(apk.ApkFailure):
                apk.validate_retained(
                    replace(state, metadata=metadata), policy=POLICY, runtime=runtime
                )
        with patch.object(
            type(signer), "alpine_key", side_effect=AssertionError("No no-op signing")
        ):
            unchanged = apk.prepare(
                [],
                state,
                policy=POLICY,
                runtime=runtime,
                signer=signer,
                now=NOW,
                out=runtime.root / "unchanged",
            )
        assert unchanged.outputs == () and unchanged.retained == state
        print(
            "Observed: two unsigned HTTP generations, dependency payloads, exact fetched SHA256, complete records, prepared validation, and trust/corruption rejection."
        )


@pytest.mark.parametrize("mixed_order", [None, "signed-first", "unsigned-first"])
def test_signed_upstream_loses_its_signature(mixed_order: str | None) -> None:
    with (
        private_workspace() as runtime,
        disposable_key() as key,
        disposable_key() as upstream_key,
        signing_session(
            runtime,
            expected_fingerprint=key.fingerprint,
            key_file=key.key_file,
        ) as signer,
        signing_session(
            upstream_key.runtime,
            expected_fingerprint=upstream_key.fingerprint,
            key_file=upstream_key.key_file,
        ) as upstream_signer,
    ):
        assert key.fingerprint != upstream_key.fingerprint
        publisher_public = signer.alpine_key()[1]
        upstream_public = upstream_signer.alpine_key()[1]
        assert publisher_public.name == upstream_public.name == "wimpysworld.rsa.pub"
        assert sha256_file(publisher_public) != sha256_file(upstream_public)
        dependency = "hd-mixed-dependency>=1.0-r0" if mixed_order else ""
        signed = fixture(
            runtime,
            "hd-signed",
            "1.0-r0",
            payload="signed-payload",
            dependency=dependency,
            signer=upstream_signer,
        )
        second = fixture(
            runtime,
            "hd-signed",
            "2.0-r0",
            payload="signed-update",
            dependency=dependency,
            signer=upstream_signer,
        )
        policy = POLICY
        # The same package without the upstream signature stream, as abuild builds it unsigned.
        plain = fixture(
            runtime,
            "hd-signed",
            "1.0-r0",
            payload="signed-payload",
            dependency=dependency,
            suffix="-unsigned",
        )
        plain_second = fixture(
            runtime,
            "hd-signed",
            "2.0-r0",
            payload="signed-update",
            dependency=dependency,
            suffix="-unsigned",
        )
        accepted = accept(signed, runtime)
        assert accepted.inspected.upstream_signature == "signed"
        assert accepted.transformation_policy == "apk-unsign"
        unsigned_view = accept(plain, runtime)
        assert accepted.inspected.identity == unsigned_view.inspected.identity
        assert (
            accepted.inspected.evidence["control_identity"]
            == unsigned_view.inspected.evidence["control_identity"]
        )
        assert accepted.inspected.metadata["stanza"] == unsigned_view.inspected.metadata["stanza"]
        assert accepted.inspected.metadata["published_sha256"] == plain.sha256
        inputs = [accepted]
        assets = {"hd-signed-1.0-r0.apk": plain}
        if mixed_order:
            dep = fixture(runtime, "hd-mixed-dependency", "1.0-r0", payload="mixed-dependency")
            unsigned_dep = accept(dep, runtime, policy=policy)
            assert unsigned_dep.inspected.upstream_signature == "unsigned"
            inputs.insert(0 if mixed_order == "unsigned-first" else 1, unsigned_dep)
            assets["hd-mixed-dependency-1.0-r0.apk"] = dep
        generation = apk.prepare(
            inputs,
            EMPTY,
            policy=policy,
            runtime=runtime,
            signer=signer,
            now=NOW,
            out=runtime.root / "signed-generation",
        )
        root = runtime.root / "signed-public"
        publish(generation, root)
        with serve(root) as http:
            http.set_generation_mtime([root / "x86_64/APKINDEX.tar.gz"], 1)
            client = Client(runtime, "signed", http.url(), root / "keys/wimpysworld.rsa.pub")
            upstream_client = Client(runtime, "upstream-only", http.url(), upstream_public)
            upstream_client.run("verify", str(signed.local_path))
            assert client.run("verify", str(signed.local_path), check=False).returncode != 0
            published = root / "x86_64/hd-signed-1.0-r0.apk"
            assert sha256_file(published) == (plain.sha256, plain.size)
            assert ".SIGN.RSA256.wimpysworld.rsa.pub" not in apk._members(published, runtime)
            client.run("verify", str(root / "x86_64/APKINDEX.tar.gz"))
            assert (
                upstream_client.run(
                    "verify", str(root / "x86_64/APKINDEX.tar.gz"), check=False
                ).returncode
                != 0
            )
            assert upstream_client.add("hd-signed=1.0-r0", check=False).returncode != 0
            client.add("hd-signed=1.0-r0")
            client.installed("hd-signed", "1.0-r0", "signed-payload")
            fetched = client.fetch("downloads", "hd-signed=1.0-r0")
            assert {path.name for path in fetched.iterdir()} == assets.keys()
            for filename, asset in assets.items():
                assert sha256_file(fetched / filename) == (asset.sha256, asset.size)
                assert sha256_file(root / "x86_64" / filename) == (asset.sha256, asset.size)
            state = committed(generation)
            rerun = accept(signed, runtime, state.accepted_history)
            assert rerun in state.accepted_history
            unchanged = apk.prepare(
                [rerun],
                state,
                policy=policy,
                runtime=runtime,
                signer=signer,
                now=NOW,
                out=runtime.root / "signed-rerun",
            )
            assert unchanged.outputs == () and unchanged.retained == state
            signed.local_path.rename(signed.local_path.with_suffix(".unavailable"))
            prior_hash = sha256_file(generation.outputs[-1].local_path)
            addition = accept(second, runtime, state.accepted_history, policy)
            generation2 = apk.prepare(
                [addition],
                state,
                policy=policy,
                runtime=runtime,
                signer=signer,
                now=NOW,
                out=runtime.root / "signed-generation2",
            )
            assert sha256_file(generation.outputs[-1].local_path) == prior_hash
            assert generation2.outputs[-1].expected_etag == '"synthetic-etag"'
            assert generation2.outputs[-1].mode == "replace"
            assert [output.ref.key for output in generation2.outputs] == [
                "x86_64/hd-signed-2.0-r0.apk",
                "x86_64/APKINDEX.tar.gz",
            ]
            apk.validate_retained(generation2.retained, policy=policy, runtime=runtime)
            apk.validate_prepared(generation2, policy=policy, runtime=runtime)
            assert len(generation2.retained.accepted_history) == len(inputs) + 1
            http.set_generation_mtime(publish(generation2, root), 2)
            client.run("update")
            client.add("hd-signed=2.0-r0")
            client.installed("hd-signed", "2.0-r0", "signed-update")
            if mixed_order:
                client.installed("hd-mixed-dependency", "1.0-r0", "mixed-dependency")
            fetched = client.fetch("downloads-two", "hd-signed=2.0-r0")
            assets.pop("hd-signed-1.0-r0.apk")
            assets["hd-signed-2.0-r0.apk"] = plain_second
            assert {path.name for path in fetched.iterdir()} == assets.keys()
            for filename, asset in assets.items():
                assert sha256_file(fetched / filename) == (asset.sha256, asset.size)
                assert sha256_file(root / "x86_64" / filename) == (asset.sha256, asset.size)
            assert (root / "x86_64/hd-signed-1.0-r0.apk").is_file()
            assert not any(
                "--allow-untrusted" in command.argv for command in client.native.commands
            )
            for filename in (*assets, "hd-signed-1.0-r0.apk", "APKINDEX.tar.gz"):
                assert any(
                    request.path == f"/x86_64/{filename}"
                    and request.status == 200
                    and request.bytes_sent > 0
                    for request in http.requests()
                )
        signed.local_path.with_suffix(".unavailable").rename(signed.local_path)
        work = runtime.root / "invalid-signature"
        work.mkdir()
        parts = apk._parts(signed.local_path, work)
        signature = work / "signature"
        signature.mkdir()
        run(runtime, "tar", "-xzf", str(parts[0]), "-C", str(signature))
        member = signature / ".SIGN.RSA256.wimpysworld.rsa.pub"
        raw = bytearray(member.read_bytes())
        raw[0] ^= 1
        atomic_write(member, bytes(raw))
        invalid = work / "invalid.apk"
        atomic_write(
            invalid,
            archive(runtime, signature, member.name)
            + parts[1].read_bytes()
            + parts[2].read_bytes(),
        )
        # A corrupt upstream signature is removed like a valid one. Only the package remains.
        corrupt = accept(verified(invalid), runtime)
        assert corrupt.inspected.metadata["published_sha256"] == plain.sha256
        assert corrupt.inspected.identity == accepted.inspected.identity
        twice = work / "twice.apk"
        atomic_write(twice, parts[0].read_bytes() + signed.local_path.read_bytes())
        with pytest.raises(apk.ApkFailure, match="gzip member"):
            accept(verified(twice), runtime)
        unsigned = fixture(runtime, "hd-unsigned", "1.0-r0", payload="unsigned")
        with pytest.raises(apk.ApkFailure):
            apk.inspect(
                replace(
                    unsigned, sha256="0" * 64, source=replace(unsigned.source, github_sha256=None)
                ),
                policy=POLICY,
                runtime=runtime,
                out=runtime.root / "bad-sha",
            )
        armv7 = fixture(runtime, "hd-armv7", "1.0-r0", payload="unqualified", arch="armv7")
        with pytest.raises(UnsupportedAsset, match="unsupported APK architecture 'armv7'"):
            accept(armv7, runtime)
        v3 = runtime.root / "v3.apk"
        empty = runtime.root / "empty-v3"
        empty.mkdir()
        run(
            runtime,
            "apk",
            "--no-network",
            "--repositories-file",
            "/dev/null",
            "mkpkg",
            "--info",
            "name:hd-v3",
            "--info",
            "version:1.0-r0",
            "--info",
            "arch:x86_64",
            "--files",
            str(empty),
            "--output",
            str(v3),
        )
        with pytest.raises(apk.ApkFailure, match="v3"):
            accept(verified(v3), runtime)
        print(
            f"Observed: distinct upstream/publisher keys, mixed order {mixed_order}, "
            "two HTTP generations, fetched bytes equal to unsigned builds, and no-op reruns. "
            "APK v2 C:Q1 remains a SHA1 boundary."
        )


def test_unsigned_multiarch_without_release_suffix() -> None:
    policy = replace(POLICY, architectures=("x86_64", "aarch64"))
    with (
        private_workspace() as runtime,
        disposable_key() as key,
        signing_session(
            runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer,
    ):
        assets = {
            arch: fixture(
                runtime, "hd-multi", "1.0", payload=f"multi-{arch}", arch=arch, suffix=f"-{arch}"
            )
            for arch in ("x86_64", "aarch64")
        }
        accepted: list[AdmittedAsset] = []
        for arch, asset in assets.items():
            item = accept(asset, runtime, accepted, policy)
            assert item.inspected.identity.architecture == arch
            assert item.inspected.identity.version == "1.0"
            accepted.append(item)
        with pytest.raises(UnsupportedAsset, match="unsupported APK architecture 'aarch64'"):
            accept(assets["aarch64"], runtime)
        generation1 = apk.prepare(
            accepted,
            EMPTY,
            policy=policy,
            runtime=runtime,
            signer=signer,
            now=NOW,
            out=runtime.root / "multi-generation1",
        )
        assert [output.ref.key for output in generation1.outputs] == [
            "keys/wimpysworld.rsa.pub",
            "x86_64/hd-multi-1.0.apk",
            "aarch64/hd-multi-1.0.apk",
            "aarch64/APKINDEX.tar.gz",
            "x86_64/APKINDEX.tar.gz",
        ]
        state = committed(generation1)
        update = fixture(runtime, "hd-multi", "1.1", payload="multi-aarch64-update", arch="aarch64")
        generation2 = apk.prepare(
            [accept(update, runtime, state.accepted_history, policy)],
            state,
            policy=policy,
            runtime=runtime,
            signer=signer,
            now=NOW,
            out=runtime.root / "multi-generation2",
        )
        assert [output.ref.key for output in generation2.outputs] == [
            "aarch64/hd-multi-1.1.apk",
            "aarch64/APKINDEX.tar.gz",
        ]
        public = runtime.root / "multi-public"
        public.mkdir()
        publish(generation1, public)
        publish(generation2, public)
        with serve(public) as http:
            http.set_generation_mtime([public / arch / "APKINDEX.tar.gz" for arch in assets], 1)
            for arch, version, source in (
                ("x86_64", "1.0", assets["x86_64"]),
                ("aarch64", "1.1", update),
            ):
                index = public / arch / "APKINDEX.tar.gz"
                client = Client(
                    runtime,
                    f"multi-{arch.replace('_', '-')}",
                    http.url(),
                    public / "keys/wimpysworld.rsa.pub",
                    arch,
                )
                client.run("verify", str(index))
                client.run("update")
                listing = client.run("search", "--exact", "hd-multi").stdout.decode()
                assert listing.split() == [f"hd-multi-{version}"]
                client.add(f"hd-multi={version}")
                payload = "multi-x86_64" if arch == "x86_64" else "multi-aarch64-update"
                client.installed("hd-multi", version, payload)
                fetched = client.fetch("downloads", f"hd-multi={version}")
                assert {path.name for path in fetched.iterdir()} == {f"hd-multi-{version}.apk"}
                assert sha256_file(fetched / f"hd-multi-{version}.apk") == (
                    source.sha256,
                    source.size,
                )
            assert sha256_file(public / "aarch64/hd-multi-1.0.apk") == (
                assets["aarch64"].sha256,
                assets["aarch64"].size,
            )
            requests = http.requests()
            for path in ("/x86_64/hd-multi-1.0.apk", "/aarch64/hd-multi-1.1.apk"):
                assert any(
                    record.path == path and record.status == 200 and record.bytes_sent > 0
                    for record in requests
                )


def test_noarch_package_in_every_architecture_index() -> None:
    policy = replace(POLICY, architectures=("x86_64", "aarch64"))
    with (
        private_workspace() as runtime,
        disposable_key() as key,
        signing_session(
            runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer,
    ):
        noarch = fixture(runtime, "hd-noarch", "1.0-r0", payload="shared", arch="noarch")
        item = accept(noarch, runtime, (), policy)
        assert item.inspected.identity.architecture == "noarch"
        prepared = apk.prepare(
            [item],
            EMPTY,
            policy=policy,
            runtime=runtime,
            signer=signer,
            now=NOW,
            out=runtime.root / "noarch-generation1",
        )
        assert [output.ref.key for output in prepared.outputs] == [
            "keys/wimpysworld.rsa.pub",
            "noarch/hd-noarch-1.0-r0.apk",
            "aarch64/APKINDEX.tar.gz",
            "x86_64/APKINDEX.tar.gz",
        ]
        apk.validate_retained(committed(prepared), policy=policy, runtime=runtime)
        public = runtime.root / "noarch-public"
        public.mkdir()
        publish(prepared, public)
        with serve(public) as http:
            for arch in ("x86_64", "aarch64"):
                http.set_generation_mtime([public / arch / "APKINDEX.tar.gz"], 1)
                client = Client(
                    runtime,
                    f"noarch-{arch.replace('_', '-')}",
                    http.url(),
                    public / "keys/wimpysworld.rsa.pub",
                    arch,
                )
                client.run("verify", str(public / arch / "APKINDEX.tar.gz"))
                client.run("update")
                client.add("hd-noarch=1.0-r0")
                client.installed("hd-noarch", "1.0-r0", "shared")
                fetched = client.fetch("downloads", "hd-noarch=1.0-r0")
                assert sha256_file(fetched / "hd-noarch-1.0-r0.apk") == (noarch.sha256, noarch.size)
