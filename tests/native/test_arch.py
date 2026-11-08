"""Production Arch adapter acceptance with Nix pacman over loopback HTTP."""

from __future__ import annotations

import base64
import os
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from haberdasher.admission import AdmissionFailure, admit
from haberdasher.config import FormatPolicy
from haberdasher.core import AdmittedAsset, PreparedFormat, RetainedFormat, sha256_file
from haberdasher.formats import arch
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import signing_session
from tests.native.fixtures.arch import client, client_keyring, fixture
from tests.native.test_signing import agent_pid, agent_socketdir, stopped
from tests.support.http import serve
from tests.support.keys import disposable_key, run

POLICY = FormatPolicy("arch")
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def publish(prepared: PreparedFormat, root: Path) -> None:
    for output in prepared.outputs:
        target = root / output.ref.key
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output.local_path, target)
        assert sha256_file(target) == (output.ref.sha256, output.ref.size)


@pytest.mark.parametrize("socket_bytes", [None, 106, 107])
def test_client_keyring_socket_paths(socket_bytes: int | None) -> None:
    with disposable_key() as key, tempfile.TemporaryDirectory(prefix="arch-", dir="/tmp") as short:
        unrelated = Path(short) / "unrelated"
        unrelated.write_text("keep")
        parent = Path(tempfile.gettempdir())
        if socket_bytes is not None:
            suffix = "/haberdasher-XXXXXXXX/gnupg/S.gpg-agent.browser"
            padding = socket_bytes - len(os.fsencode(short + "/" + suffix))
            parent = Path(short) / ("é" * (padding // 2) + "a" * (padding % 2))
            parent.mkdir(mode=0o700)
            assert len(os.fsencode(str(parent) + suffix)) == socket_bytes
        unrelated_pid = agent_pid(key.runtime, Path(key.runtime.environment["GNUPGHOME"]))
        with private_workspace(parent) as runtime:
            root = runtime.root
            if socket_bytes is not None:
                assert root.parent == (parent if socket_bytes == 106 else Path("/tmp"))
            reserved = root / "p0000"
            reserved.mkdir(mode=0o700)
            (reserved / "sentinel").write_text("keep")
            trusted = client(runtime, "existing", "http://127.0.0.1:1", key)
            untrusted = client(runtime, "u" * 64, "http://127.0.0.1:1", key, trusted=False)
            homes = [trusted.keyring, untrusted.keyring]
            assert len(set(homes)) == 2
            assert (reserved / "sentinel").read_text() == "keep"
            for pacman in (trusted, untrusted):
                home = pacman.keyring
                assert home.parent == root and len(os.fsencode(home.name)) == 5
                assert len(os.fsencode(home / "S.gpg-agent.browser")) < 107
                assert home.stat().st_mode & 0o777 == 0o700
                assert (home / "pubring.gpg").stat().st_mode & 0o777 == 0o600
                config = pacman.config.read_text()
                assert f"GPGDir = {home}\n" in config
                assert config.count("Required TrustedOnly") == 3
                listing = run(
                    runtime, "gpg", "--homedir", str(home), "--with-colons", "--list-keys"
                )
                assert key.fingerprint.encode() in listing
                trust = run(runtime, "gpg", "--homedir", str(home), "--export-ownertrust")
                assert (f"{key.fingerprint}:6:".encode() in trust) == (pacman is trusted)
            for failure in (False, True):
                pid = agent_pid(runtime, trusted.keyring)
                socketdir = agent_socketdir(runtime, trusted.keyring)
                assert (socketdir / "S.gpg-agent.browser").is_socket()
                if failure:
                    with pytest.raises(RuntimeError):
                        trusted.checked("-Q", "not-installed")
                else:
                    trusted.checked("--version")
                stopped(pid)
                assert not (socketdir / "S.gpg-agent.browser").exists()
                if socketdir != trusted.keyring:
                    assert not socketdir.exists()
                assert (trusted.keyring / "pubring.gpg").is_file()
                os.kill(unrelated_pid, 0)
            for error in (ValueError, SystemExit):
                with pytest.raises(error, match="injected"):
                    with client_keyring(runtime, trusted.keyring):
                        pid = agent_pid(runtime, trusted.keyring)
                        socketdir = agent_socketdir(runtime, trusted.keyring)
                        raise error("injected")
                stopped(pid)
                assert not (socketdir / "S.gpg-agent.browser").exists()
                if socketdir != trusted.keyring:
                    assert not socketdir.exists()
            alias = root / "alias"
            alias.symlink_to(Path(short), target_is_directory=True)
            with pytest.raises(ValueError), client_keyring(runtime, alias):
                pass
        assert not root.exists()
        assert all(not home.exists() for home in homes)
        assert unrelated.read_text() == "keep"
        os.kill(unrelated_pid, 0)


@pytest.mark.parametrize("failure", [None, "kill", "query", "remove"])
@pytest.mark.parametrize("body_fails", [False, True])
def test_client_keyring_external_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None, body_fails: bool
) -> None:
    runtime = Runtime(tmp_path / "owned", environ={"PATH": ""})
    home = runtime.root / "p0000"
    home.mkdir(mode=0o700)
    keyring = home / "pubring.gpg"
    keyring.write_bytes(b"synthetic")
    socketdir = tmp_path / "owned-sockets"
    socketdir.mkdir()
    sentinel = tmp_path / "unrelated"
    sentinel.write_text("keep")
    commands: list[list[str]] = []

    def fake(argv: Sequence[str], **_kwargs: object) -> CompletedProcess[bytes]:
        commands.append(list(argv))
        assert list(argv[:3]) == ["gpgconf", "--homedir", str(home)]
        stage = {"--kill": "kill", "--list-dirs": "query", "--remove-socketdir": "remove"}[argv[3]]
        if stage == "remove" and failure != stage:
            socketdir.rmdir()
        return CompletedProcess(argv, int(stage == failure), os.fsencode(socketdir) + b"\n", b"")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "run", fake)
            try:
                with client_keyring(runtime, home):
                    if body_fails:
                        raise ValueError("injected")
            except RuntimeError:
                assert failure is not None
            except ValueError:
                assert body_fails and failure is None
            else:
                assert failure is None and not body_fails
        expected = ["--kill"]
        if failure != "kill":
            expected.append("--list-dirs")
            if failure != "query":
                expected.append("--remove-socketdir")
        assert [argv[3] for argv in commands] == expected
        assert socketdir.exists() == (failure is not None)
        assert keyring.read_bytes() == b"synthetic"
        assert sentinel.read_text() == "keep"
    finally:
        runtime.close()


def test_arch_native(monkeypatch: pytest.MonkeyPatch) -> None:
    with (
        disposable_key() as key,
        private_workspace(Path("/tmp")) as runtime,
        signing_session(
            runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer,
    ):
        print(run(runtime, "pacman", "--version").decode())
        print(run(runtime, "repo-add", "--version").decode())
        print("pacman:", shutil.which("pacman", path=runtime.environment["PATH"]))
        empty = RetainedFormat("arch", None, (), (), {}, ())
        arch.validate_retained(empty, policy=POLICY, runtime=runtime)
        assets = [
            fixture(runtime, "keeper", "1", dependency="updateable>=1"),
            fixture(runtime, "updateable", "1"),
            fixture(runtime, "updateable", "2"),
        ]
        accepted: list[AdmittedAsset] = []
        for index, asset in enumerate(assets):
            inspected = arch.inspect(
                asset, policy=POLICY, runtime=runtime, out=runtime.root / f"inspect-{index}"
            )
            accepted.append(
                admit(inspected, accepted, compare=arch.compare, policy=POLICY, runtime=runtime)
            )
        equivalent = fixture(runtime, "keeper", "1", release="01", content="changed")
        inspected = arch.inspect(
            equivalent, policy=POLICY, runtime=runtime, out=runtime.root / "equivalent"
        )
        assert (
            arch.compare(inspected.identity, accepted[0].inspected.identity, runtime=runtime) == 0
        )
        with pytest.raises(AdmissionFailure, match="Changed bytes"):
            admit(inspected, accepted, compare=arch.compare, policy=POLICY, runtime=runtime)
        unqualified = fixture(runtime, "unqualified", "1", architecture="any")
        with pytest.raises(arch.ArchFailure, match="qualified"):
            arch.inspect(
                unqualified, policy=POLICY, runtime=runtime, out=runtime.root / "unqualified"
            )
        first = arch.prepare(
            accepted[:2],
            empty,
            policy=POLICY,
            runtime=runtime,
            signer=signer,
            now=NOW,
            out=runtime.root / "generation1",
        )
        state = replace(
            first.retained,
            prior_generation="one",
            metadata={
                **first.retained.metadata,
                "etags": {output.ref.key: "opaque-one" for output in first.outputs},
            },
        )
        for item in accepted[:2]:
            item.inspected.verified.local_path.rename(
                item.inspected.verified.local_path.with_suffix(".hidden")
            )
        for output in first.outputs:
            if output.ref.object_class == "package":
                output.local_path.rename(output.local_path.with_suffix(".hidden"))
        arch.validate_retained(state, policy=POLICY, runtime=runtime)
        second = arch.prepare(
            accepted[2:],
            state,
            policy=POLICY,
            runtime=runtime,
            signer=signer,
            now=NOW,
            out=runtime.root / "generation2",
        )
        arch.validate_prepared(second, policy=POLICY, runtime=runtime, now=NOW)
        assert len(second.retained.accepted_history) == 3
        assert len(second.retained.active_identities) == 2
        assert [
            output.ref.key for output in second.outputs if output.ref.object_class == "entry"
        ] == list(arch.ENTRIES)
        assert all(not output.local_path.is_symlink() for output in second.outputs)
        assert all(
            output.expected_etag == "opaque-one"
            for output in second.outputs
            if output.mode == "replace"
        )
        assert not (runtime.root / "generation2/x86_64/keeper-1-1-x86_64.pkg.tar.zst").exists()
        for output in first.outputs:
            if output.ref.object_class == "package":
                output.local_path.with_suffix(".hidden").rename(output.local_path)
        noop = arch.prepare(
            accepted[:2],
            state,
            policy=POLICY,
            runtime=runtime,
            signer=signer,
            now=NOW,
            out=runtime.root / "noop",
        )
        assert noop.outputs == ()
        assert not (runtime.root / "noop").exists()
        for kind in ("db", "files"):
            assert run(
                runtime,
                "bsdtar",
                "-xOf",
                str(runtime.root / f"generation1/x86_64/haberdasher.{kind}.tar.gz"),
                "keeper-1-1/desc",
            ) == run(
                runtime,
                "bsdtar",
                "-xOf",
                str(runtime.root / f"generation2/x86_64/haberdasher.{kind}.tar.gz"),
                "keeper-1-1/desc",
            )
        live = runtime.root / "live"
        live.mkdir()
        publish(first, live)
        with serve(live) as http:
            pacman = client(runtime, "update", http.url("x86_64"), key)
            http.set_generation_mtime(list((live / "x86_64").iterdir()), 1)
            pacman.checked("-Sy")
            pacman.checked("-S", "keeper")
            assert pacman.checked("-Q", "keeper").strip() == b"keeper 1-1"
            assert pacman.checked("-Q", "updateable").strip() == b"updateable 1-1"
            assert (
                pacman.client.path("root/usr/share/arch-test/keeper.txt").read_text()
                == "keeper-1\n"
            )
            assert (
                pacman.client.path("root/usr/share/arch-test/updateable.txt").read_text()
                == "updateable-1\n"
            )
            pacman.checked("-Fy")
            assert b"keeper 1-1" in pacman.checked("-F", "usr/share/arch-test/keeper.txt")
            publish(second, live)
            http.set_generation_mtime(list((live / "x86_64").iterdir()), 2)
            pacman.checked("-Syu")
            pacman.checked("-Fy")
            assert pacman.checked("-Q", "updateable").strip() == b"updateable 2-1"
            assert (
                pacman.client.path("root/usr/share/arch-test/updateable.txt").read_text()
                == "updateable-2\n"
            )
            assert b"updateable 2-1" in pacman.checked("-F", "usr/share/arch-test/updateable.txt")
            for output in (*first.outputs, *second.outputs):
                if output.ref.object_class == "package":
                    cached = pacman.client.path("cache/" + output.local_path.name)
                    assert sha256_file(cached) == (output.ref.sha256, output.ref.size)
            old_package = live / "x86_64/updateable-1-1-x86_64.pkg.tar.zst"
            assert old_package.is_file()
            generation = 3
            for kind, operation in (("db", "-Sy"), ("files", "-Fy")):
                for data_generation, signature_generation in ((1, 2), (2, 1)):
                    negative = client(
                        runtime, f"split-{kind}-{data_generation}", http.url("x86_64"), key
                    )
                    archive = live / f"x86_64/haberdasher.{kind}"
                    signature = archive.with_name(archive.name + ".sig")
                    archive.write_bytes(
                        (
                            runtime.root
                            / f"generation{data_generation}/x86_64/haberdasher.{kind}.tar.gz"
                        ).read_bytes()
                    )
                    signature.write_bytes(
                        (
                            runtime.root
                            / f"generation{signature_generation}/x86_64/haberdasher.{kind}.tar.gz.sig"
                        ).read_bytes()
                    )
                    http.set_generation_mtime([archive, signature], generation)
                    generation += 1
                    assert negative.run(operation).returncode != 0
                    publish(second, live)
                    http.set_generation_mtime(list((live / "x86_64").iterdir()), generation)
                    generation += 1
                    negative.checked(operation)
                    assert (
                        negative.client.path(f"db/sync/haberdasher.{kind}").read_bytes()
                        == archive.read_bytes()
                    )
            untrusted = client(runtime, "untrusted", http.url("x86_64"), key, trusted=False)
            assert untrusted.run("-Sy").returncode != 0
            for fault in ("invalid", "missing"):
                publish(second, live)
                extracted = runtime.root / f"bad-{fault}"
                extracted.mkdir()
                archive = runtime.root / "generation2/x86_64/haberdasher.db.tar.gz"
                run(runtime, "bsdtar", "-xf", str(archive), "-C", str(extracted))
                record = extracted / "updateable-2-1/desc"
                desc = record.read_text()
                before, marker, rest = desc.partition("%PGPSIG%\n")
                assert marker
                _, _, after = rest.partition("\n\n")
                package_signature = live / "x86_64/updateable-2-1-x86_64.pkg.tar.zst.sig"
                if fault == "invalid":
                    wrong = (live / "x86_64/keeper-1-1-x86_64.pkg.tar.zst.sig").read_bytes()
                    record.write_text(
                        before + marker + base64.b64encode(wrong).decode() + "\n\n" + after
                    )
                    package_signature.write_bytes(wrong)
                else:
                    record.write_text(before + after)
                    package_signature.unlink()
                bad = live / "x86_64/haberdasher.db"
                run(
                    runtime,
                    "bsdtar",
                    "-czf",
                    str(bad),
                    "-C",
                    str(extracted),
                    "keeper-1-1",
                    "updateable-2-1",
                )
                signer.sign_file(bad, bad.with_name(bad.name + ".sig"), armour=False)
                generation += 1
                http.set_generation_mtime(list((live / "x86_64").iterdir()), generation)
                negative = client(runtime, f"bad-package-{fault}", http.url("x86_64"), key)
                negative.checked("-Sy")
                result = negative.run("-S", "updateable")
                assert result.returncode != 0
                assert b"signature" in result.stderr or b".sig" in result.stderr
                assert negative.run("-Q", "updateable").returncode != 0
                assert not negative.client.path("root/usr/share/arch-test/updateable.txt").exists()
            requests = http.requests()
            assert any(
                record.path.endswith("updateable-2-1-x86_64.pkg.tar.zst") and record.status == 200
                for record in requests
            )
            assert any(
                record.path.endswith("haberdasher.files") and record.status == 200
                for record in requests
            )
        for missing in (
            "haberdasher.db.tar.gz.sig",
            "haberdasher.files.tar.gz",
            "haberdasher.files.tar.gz.sig",
        ):
            path = runtime.root / "generation2/x86_64" / missing
            saved = path.read_bytes()
            path.write_bytes(b"")
            with pytest.raises((arch.ArchFailure, ValueError)):
                arch.validate_prepared(second, policy=POLICY, runtime=runtime, now=NOW)
            path.write_bytes(saved)
        reordered = replace(
            second,
            outputs=tuple(
                replace(output, ordinal=index)
                for index, output in enumerate(reversed(second.outputs))
            ),
        )
        with pytest.raises(arch.ArchFailure):
            arch.validate_prepared(reordered, policy=POLICY, runtime=runtime, now=NOW)
        real_run = runtime.run
        real_gpg = shutil.which("gpg", path=runtime.environment["PATH"])
        shell = shutil.which("bash", path=runtime.environment["PATH"])
        assert real_gpg and shell
        for fault, code in (("sign-failure", 1), ("zero-output", 0)):
            bindir = runtime.root / fault
            bindir.mkdir()
            marker = bindir / "called"
            wrapper = bindir / "gpg"
            wrapper.write_text(
                f'#!{shell}\nfor arg in "$@"; do\n'
                f" if [[ $arg == --detach-sign ]]; then echo yes >>'{marker}'; exit {code}; fi\n"
                f"done\nexec '{real_gpg}' \"$@\"\n"
            )
            wrapper.chmod(0o700)

            def fault_run(
                argv: Sequence[str],
                *,
                cwd: Path | None = None,
                input: bytes | None = None,
                timeout: float = 120,
                env_kind: str = "native",
                bindir: Path = bindir,
            ) -> CompletedProcess[bytes]:
                if "repo-add" in argv:
                    argv = ["env", f"PATH={bindir}:{runtime.environment['PATH']}", *argv]
                return real_run(argv, cwd=cwd, input=input, timeout=timeout, env_kind=env_kind)

            with monkeypatch.context() as patch:
                patch.setattr(runtime, "run", fault_run)
                with pytest.raises((arch.ArchFailure, ValueError)):
                    arch.prepare(
                        accepted[2:],
                        empty,
                        policy=POLICY,
                        runtime=runtime,
                        signer=signer,
                        now=NOW,
                        out=runtime.root / f"failed-{fault}",
                    )
            assert marker.is_file()

        def no_signature(source: Path, output: Path, *, armour: bool = True) -> None:
            return None

        with monkeypatch.context() as patch:
            patch.setattr(signer, "sign_file", no_signature)
            with pytest.raises((arch.ArchFailure, ValueError)):
                arch.prepare(
                    accepted[2:],
                    empty,
                    policy=POLICY,
                    runtime=runtime,
                    signer=signer,
                    now=NOW,
                    out=runtime.root / "failed-package-signature",
                )
