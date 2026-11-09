"""Exercise the production adapter and private Flatpak clients over loopback HTTP."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import base64
import shutil
import struct
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from urllib.request import urlopen

import pytest

from haberdasher.admission import AdmissionFailure, admit
from haberdasher.config import PUBLIC, Config
from haberdasher.core import (
    OutputObject,
    PreparedFormat,
    RetainedFormat,
    canonical_json,
    sha256_file,
)
from haberdasher.formats import flatpak
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import SigningSession, signing_session
from tests.native.fixtures.flatpak import (
    APP,
    ARCH,
    EREF,
    EXTENSION,
    REF,
    RREF,
    RUNTIME,
    bundle,
    mime_directory,
    run,
    runtime_repo,
)
from tests.support.http import serve
from tests.support.keys import disposable_key
from tests.support.native import NativeClient

NOW = datetime(2026, 1, 1, tzinfo=UTC)
POLICY = Config(("wimpysworld/fixture",)).format_policy("flatpak")


def client_run(client: NativeClient, *args: str, success: bool = True) -> bytes:
    result = client.run(
        [
            "env",
            f"FLATPAK_USER_DIR={client.root}",
            f"XDG_DATA_DIRS={mime_directory()}",
            f"HOME={client.path('config')}",
            f"XDG_DATA_HOME={client.path('state')}",
            f"XDG_CACHE_HOME={client.path('cache')}",
            "flatpak",
            "--user",
            *args,
        ],
        install_root=client.root,
    )
    if success:
        assert result.returncode == 0, result.stderr.decode()
    else:
        assert result.returncode != 0, result.stdout.decode()
    return result.stdout + (result.stderr if not success else b"")


def published_remote(url: str, target: Path) -> Path:
    """Copy the published remote description, with the loopback URL in place of the public one."""
    with urlopen(f"{url.rstrip('/')}/{flatpak.FLATPAKREPO}", timeout=10) as response:
        text = response.read().decode()
    public_url = f"Url={PUBLIC['flatpak'][1]}/\n"
    assert public_url in text
    target.write_text(text.replace(public_url, f"Url={url.rstrip('/')}/\n"))
    return target


def add_remotes(
    client: NativeClient,
    url: str,
    runtime_url: str,
    public: Path,
    runtime_public: Path | None = None,
) -> None:
    """Add the runtime provider and the publisher remote from its published flatpakrepo file."""
    runtime_public = runtime_public or public
    runtime_filter = client.path("config/runtime.filter")
    runtime_filter.write_text(f"deny *\nallow {RREF}\nallow {EREF}\n")
    app_filter = client.path("config/app.filter")
    app_filter.write_text(f"deny *\nallow {REF}\n")
    client_run(
        client,
        "remote-add",
        f"--gpg-import={runtime_public}",
        f"--filter={runtime_filter}",
        "provider",
        runtime_url,
    )
    repofile = published_remote(url, client.path("config/publisher.flatpakrepo"))
    client_run(client, "remote-add", "--from", f"--filter={app_filter}", "publisher", str(repofile))
    listing = client_run(client, "remotes", "--columns=name,url,options").decode()
    assert runtime_url in listing and url in listing
    assert "no-gpg-verify" not in listing
    config = flatpak._mapping(
        flatpak._native(client.runtime, metadata=(client.root / "repo/config").read_text())[
            "keyfile"
        ]
    )
    assert {group for group in config if group.startswith("remote ")} == {
        'remote "provider"',
        'remote "publisher"',
    }

    def fingerprints(path: Path) -> set[bytes]:
        keys = run(client.runtime, "gpg", "--batch", "--with-colons", "--show-keys", str(path))
        return {line.split(b":")[9] for line in keys.splitlines() if line.startswith(b"fpr:")}

    for name, expected_url, filter_path, key in (
        ("provider", runtime_url, runtime_filter, runtime_public),
        ("publisher", url, app_filter, public),
    ):
        remote = flatpak._mapping(config[f'remote "{name}"'])
        assert flatpak._string(remote["url"]).rstrip("/") == expected_url.rstrip("/")
        assert remote["gpg-verify"] == "true"
        assert remote["gpg-verify-summary"] == "true"
        assert remote.get("collection-id", "") == ""
        assert remote["xa.filter"] == str(filter_path)
        assert fingerprints(client.root / "repo" / f"{name}.trustedkeys.gpg") == fingerprints(key)
    publisher = flatpak._mapping(config['remote "publisher"'])
    assert publisher["xa.title"] == flatpak.TITLE


def installed(
    client: NativeClient, commit: str, version: str, runtime_commits: tuple[str, str]
) -> None:
    runtime_commit, extension_commit = runtime_commits
    assert client_run(client, "info", "--show-ref", APP).strip().decode() == REF
    assert client_run(client, "info", "--show-commit", APP).strip().decode() == commit
    assert client_run(client, "info", "--show-runtime", APP).strip().decode() == RREF.removeprefix(
        "runtime/"
    )
    assert client_run(client, "info", "--show-origin", APP).strip() == b"publisher"
    assert client_run(client, "info", "--show-origin", RUNTIME).strip() == b"provider"
    assert client_run(client, "info", "--show-commit", RUNTIME).strip().decode() == runtime_commit
    location = Path(client_run(client, "info", "--show-location", APP).decode().strip())
    assert location.is_relative_to(client.root)
    assert (location / "files/version").read_text() == version + "\n"
    location = Path(client_run(client, "info", "--show-location", RUNTIME).decode().strip())
    assert (location / "files/runtime-version").read_text() == "1\n"
    assert client_run(client, "info", "--show-origin", EXTENSION).strip() == b"provider"
    assert (
        client_run(client, "info", "--show-commit", EXTENSION).strip().decode() == extension_commit
    )
    location = Path(client_run(client, "info", "--show-location", EXTENSION).decode().strip())
    assert location.is_relative_to(client.root)
    assert (location / "files/extension-version").read_text() == "1\n"
    assert set(client_run(client, "list", "--columns=ref").decode().splitlines()) == {
        ref.split("/", 1)[1] for ref in (REF, RREF, EREF)
    }


def publish(prepared: PreparedFormat, root: Path) -> RetainedFormat:
    for output in prepared.outputs:
        destination = root / output.ref.key
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output.local_path, destination)
    return replace(
        prepared.retained,
        prior_generation="synthetic",
        metadata={
            **prepared.retained.metadata,
            "etags": {ref.key: f"etag-{ref.sha256}" for ref in prepared.referenced_objects},
        },
    )


def catalogue(runtime: Runtime, prepared: PreparedFormat, version: str, target: Path) -> None:
    files = flatpak._mapping(prepared.retained.metadata["files"])
    repo = Path(flatpak._string(files["config"])).parent
    run(
        runtime,
        "ostree",
        f"--repo={repo}",
        "checkout",
        "--user-mode",
        f"appstream/{ARCH}",
        str(target),
    )
    assert flatpak._version(target / "appstream.xml.gz", REF, runtime) == version
    for size in (64, 128):
        data = (target / f"icons/{size}x{size}/{APP}.png").read_bytes()
        assert struct.unpack(">II", data[16:24]) == (size, size)


def test_native_publication_cold_restore_and_clients() -> None:
    with private_workspace() as runtime, disposable_key() as key:
        root = runtime.root
        public_tree = root / "http"
        public_tree.mkdir()
        with signing_session(
            runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
        ) as signer:
            runtime_commit = runtime_repo(
                runtime, public_tree, signer.fingerprint, signer.gnupghome
            )
            with serve(public_tree) as http:
                policy = POLICY
                first = bundle(runtime, root, "1", 1)
                inspected = flatpak.inspect(
                    first, policy=policy, runtime=runtime, out=root / "inspect-1"
                )
                assert inspected.identity.version == "1"
                assert inspected.identity.source_commit is not None
                admitted = admit(
                    inspected, (), compare=flatpak.compare, policy=policy, runtime=runtime
                )
                empty = RetainedFormat("flatpak", None, (), (), {}, ())
                prepared1 = flatpak.prepare(
                    (admitted,),
                    empty,
                    policy=policy,
                    runtime=runtime,
                    signer=signer,
                    now=NOW,
                    out=root / "generation-1",
                )
                relocated_outputs: list[OutputObject] = []
                for output in prepared1.outputs:
                    destination = root / "frozen-outputs" / str(output.ordinal)
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copyfile(output.local_path, destination)
                    relocated_outputs.append(replace(output, local_path=destination))
                prepared1 = replace(prepared1, outputs=tuple(relocated_outputs))
                flatpak.validate_prepared(prepared1, policy=policy, runtime=runtime, now=NOW)
                catalogue(runtime, prepared1, "1", root / "catalogue-1")
                retained1 = publish(prepared1, public_tree / "publisher")
                delayed_tree = public_tree / "delayed"
                for ref in prepared1.referenced_objects:
                    if ref.object_class == "entry":
                        destination = delayed_tree / ref.key
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(public_tree / "publisher" / ref.key, destination)
                http.set_generation_mtime(
                    [path for path in (public_tree / "publisher").rglob("*") if path.is_file()], 1
                )
                client = NativeClient(runtime, "normal")
                add_remotes(
                    client, http.url("publisher"), http.url("runtime-repo"), key.public_file
                )
                client_run(client, "update", "--appstream", "--noninteractive", "publisher")
                assert APP.encode() in client_run(
                    client, "search", "--columns=application,version", "Haberdasher"
                )
                client_run(client, "install", "--noninteractive", "publisher", REF)
                installed(client, inspected.identity.source_commit, "1", runtime_commit)
                assert any(
                    record.path.startswith("/runtime-repo/objects/") for record in http.requests()
                )

                # Only restored objects and the new bundle remain available to preparation.
                duplicate_path = root / "duplicate.flatpak"
                shutil.copyfile(first.local_path, duplicate_path)
                first.local_path.unlink()
                shutil.rmtree(root / "source")
                restored_files = {}
                before = len(http.requests())
                for ref in retained1.objects:
                    destination = root / "cold" / ref.key
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with urlopen(http.url("publisher/" + ref.key), timeout=10) as response:
                        destination.write_bytes(response.read())
                    assert sha256_file(destination) == (ref.sha256, ref.size)
                    restored_files[ref.key] = str(destination)
                requests = http.requests()[before:]
                assert sum(record.bytes_sent for record in requests) == sum(
                    ref.size for ref in retained1.objects
                )
                assert any(record.path.endswith(".filez") for record in requests)
                retained1 = replace(
                    retained1, metadata={**retained1.metadata, "files": restored_files}
                )
                shutil.rmtree(root / "generation-1")
                flatpak.validate_retained(retained1, policy=policy, runtime=runtime)
                duplicate = flatpak.inspect(
                    replace(first, local_path=duplicate_path),
                    policy=policy,
                    runtime=runtime,
                    out=root / "inspect-duplicate",
                )
                canonical = admit(
                    duplicate,
                    retained1.accepted_history,
                    compare=flatpak.compare,
                    policy=policy,
                    runtime=runtime,
                )
                assert canonical == admitted
                assert not canonical.inspected.verified.local_path.exists()
                second = bundle(runtime, root, "2", 2)
                inspected2 = flatpak.inspect(
                    second, policy=policy, runtime=runtime, out=root / "inspect-2"
                )
                assert inspected2.identity.source_commit is not None
                admitted2 = admit(
                    inspected2,
                    retained1.accepted_history,
                    compare=flatpak.compare,
                    policy=policy,
                    runtime=runtime,
                )
                before_failure = canonical_json(retained1)
                public_before = {
                    path.relative_to(public_tree): sha256_file(path)
                    for path in public_tree.rglob("*")
                    if path.is_file()
                }
                unavailable = SigningSession(runtime, root / "gnupg", signer.fingerprint)
                with pytest.raises(flatpak.FlatpakFailure, match="Native Flatpak command failed"):
                    flatpak.prepare(
                        (admitted2,),
                        retained1,
                        policy=policy,
                        runtime=runtime,
                        signer=unavailable,
                        now=NOW,
                        out=root / "signer-failure",
                    )
                assert canonical_json(retained1) == before_failure
                assert {
                    path.relative_to(public_tree): sha256_file(path)
                    for path in public_tree.rglob("*")
                    if path.is_file()
                } == public_before
                conflict = flatpak.inspect(
                    bundle(runtime, root, "2", 20),
                    policy=policy,
                    runtime=runtime,
                    out=root / "inspect-conflict",
                )
                assert conflict.identity.source_commit != inspected2.identity.source_commit
                with pytest.raises(AdmissionFailure, match="Changed bytes|Conflicting commits"):
                    admit(
                        conflict,
                        (*retained1.accepted_history, admitted2),
                        compare=flatpak.compare,
                        policy=policy,
                        runtime=runtime,
                    )
                with patch.object(runtime, "run", wraps=runtime.run) as native:
                    prepared2 = flatpak.prepare(
                        (canonical, admitted2, canonical, admitted2),
                        retained1,
                        policy=policy,
                        runtime=runtime,
                        signer=signer,
                        now=NOW,
                        out=root / "generation-2",
                    )
                imports = [
                    call.args[0]
                    for call in native.call_args_list
                    if call.args[0][:2] == ("flatpak", "build-import-bundle")
                ]
                assert len(imports) == 2
                assert all(command[-1] == str(second.local_path) for command in imports)
                assert prepared2.retained.accepted_history == (admitted, admitted2)
                assert prepared2.retained.active_identities == (inspected2.identity,)
                old_commit = inspected.identity.source_commit
                old_signature = next(
                    ref
                    for ref in retained1.objects
                    if ref.key == f"objects/{old_commit[:2]}/{old_commit[2:]}.commitmeta"
                )
                assert old_signature in prepared2.referenced_objects
                assert all(output.ref.key != old_signature.key for output in prepared2.outputs)
                catalogue(runtime, prepared2, "2", root / "catalogue-2")
                frozen = canonical_json(prepared2)
                retained2 = publish(prepared2, public_tree / "publisher")
                http.set_generation_mtime(
                    [path for path in (public_tree / "publisher").rglob("*") if path.is_file()], 2
                )
                client_run(
                    client,
                    "update",
                    "--noninteractive",
                    f"--commit={inspected2.identity.source_commit}",
                    APP,
                )
                installed(client, inspected2.identity.source_commit, "2", runtime_commit)
                fresh = NativeClient(runtime, "fresh")
                add_remotes(fresh, http.url("publisher"), http.url("runtime-repo"), key.public_file)
                client_run(fresh, "install", "--noninteractive", "publisher", REF)
                installed(fresh, inspected2.identity.source_commit, "2", runtime_commit)
                flatpak.validate_prepared(prepared2, policy=policy, runtime=runtime, now=NOW)
                assert canonical_json(prepared2) == frozen
                replay = root / "replay"
                publish(prepared2, replay)
                publish(prepared2, replay)
                for output in prepared2.outputs:
                    assert sha256_file(replay / output.ref.key) == (
                        output.ref.sha256,
                        output.ref.size,
                    )
                third = bundle(runtime, root, "3", 3)
                inspected3 = flatpak.inspect(
                    third, policy=policy, runtime=runtime, out=root / "inspect-3"
                )
                assert inspected3.identity.source_commit is not None
                admitted3 = admit(
                    inspected3,
                    retained2.accepted_history,
                    compare=flatpak.compare,
                    policy=policy,
                    runtime=runtime,
                )
                prepared3 = flatpak.prepare(
                    (admitted3,),
                    retained2,
                    policy=policy,
                    runtime=runtime,
                    signer=signer,
                    now=NOW,
                    out=root / "generation-3",
                )
                retained3 = publish(prepared3, public_tree / "publisher")
                catalogue(runtime, prepared3, "3", root / "catalogue-3")
                http.set_generation_mtime(
                    [path for path in (public_tree / "publisher").rglob("*") if path.is_file()], 3
                )
                assert (
                    len(
                        {
                            inspected.identity.source_commit,
                            inspected2.identity.source_commit,
                            inspected3.identity.source_commit,
                        }
                    )
                    == 3
                )
                client_run(
                    client,
                    "update",
                    "--noninteractive",
                    f"--commit={inspected3.identity.source_commit}",
                    APP,
                )
                installed(client, inspected3.identity.source_commit, "3", runtime_commit)
                for ref in retained3.objects:
                    if ref.object_class == "dependency":
                        destination = delayed_tree / ref.key
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(public_tree / "publisher" / ref.key, destination)
                before = len(http.requests())
                delayed = NativeClient(runtime, "delayed")
                add_remotes(delayed, http.url("delayed"), http.url("runtime-repo"), key.public_file)
                client_run(delayed, "install", "--noninteractive", "publisher", REF)
                installed(delayed, inspected.identity.source_commit, "1", runtime_commit)
                old_summaries = {
                    "/delayed/" + ref.key
                    for ref in retained1.objects
                    if ref.key.startswith("summaries/") and ref.key.endswith(".gz")
                }
                assert any(
                    record.path in old_summaries and record.status == 200
                    for record in http.requests()[before:]
                )
                for prior in (retained1, retained2):
                    for ref in prior.objects:
                        if ref.key.startswith("summaries/"):
                            assert sha256_file(public_tree / "publisher" / ref.key) == (
                                ref.sha256,
                                ref.size,
                            )
                with pytest.raises(AdmissionFailure, match="backwards"):
                    admit(
                        replace(
                            inspected,
                            verified=second,
                            identity=replace(inspected.identity, version="0"),
                        ),
                        retained2.accepted_history,
                        compare=flatpak.compare,
                        policy=policy,
                        runtime=runtime,
                    )

                for label, relative, replacement in (
                    ("tampered", "summary.idx", b"altered"),
                    (
                        "missing",
                        f"objects/{inspected3.identity.source_commit[:2]}/{inspected3.identity.source_commit[2:]}.commitmeta",
                        None,
                    ),
                ):
                    broken = public_tree / label
                    shutil.copytree(public_tree / "publisher", broken)
                    if replacement is None:
                        (broken / relative).unlink()
                    else:
                        (broken / relative).write_bytes(replacement)
                    negative = NativeClient(runtime, label)
                    if label == "tampered":
                        failure = client_run(
                            negative,
                            "remote-add",
                            f"--gpg-import={key.public_file}",
                            "publisher",
                            http.url(label),
                            success=False,
                        )
                    else:
                        add_remotes(
                            negative, http.url(label), http.url("runtime-repo"), key.public_file
                        )
                        failure = client_run(
                            negative, "install", "--noninteractive", "publisher", REF, success=False
                        )
                    assert any(
                        word in failure.lower()
                        for word in (b"signature", b"gpg", b"invalid", b"summary")
                    )
                    client_run(negative, "info", APP, success=False)
                repofile = (public_tree / "publisher" / flatpak.FLATPAKREPO).read_text()
                assert f"RuntimeRepo={flatpak.FLATHUB}\n" in repofile
                assert not any(
                    record.path.endswith("flathub.flatpakrepo") for record in http.requests()
                )
                config_ref = next(ref for ref in retained3.objects if ref.key == "config")
                files = flatpak._mapping(retained3.metadata["files"])
                original_config = Path(flatpak._string(files["config"])).read_text()
                for index, extra in enumerate(
                    (
                        "[core]\nrepo_version=1\nmode=bare-user\n",
                        original_config + "collection-id=world.example.Unapproved\n",
                        original_config + '[remote "unapproved"]\nurl=https://unknown.invalid\n',
                    )
                ):
                    config_path = root / f"invalid-config-{index}"
                    config_path.write_text(extra)
                    sha, size = sha256_file(config_path)
                    invalid = replace(
                        retained3,
                        metadata={
                            **retained3.metadata,
                            "files": {**files, "config": str(config_path)},
                        },
                        objects=tuple(
                            replace(ref, sha256=sha, size=size) if ref == config_ref else ref
                            for ref in retained3.objects
                        ),
                    )
                    with pytest.raises(flatpak.FlatpakFailure, match="configuration"):
                        flatpak.validate_retained(invalid, policy=policy, runtime=runtime)
                payload = next(
                    ref for ref in prepared2.referenced_objects if ref.key.endswith(".filez")
                )
                path = Path(
                    flatpak._string(
                        flatpak._mapping(prepared2.retained.metadata["files"])[payload.key]
                    )
                )
                saved = path.read_bytes()
                path.write_bytes(b"altered")
                with pytest.raises(flatpak.FlatpakFailure, match="corrupt"):
                    flatpak.validate_retained(prepared2.retained, policy=policy, runtime=runtime)
                path.write_bytes(saved)
                path.unlink()
                with pytest.raises(ValueError):
                    flatpak.validate_retained(prepared2.retained, policy=policy, runtime=runtime)


def test_signed_upstream_apps_and_architectures_share_one_repository() -> None:
    """Two apps, a second architecture and an upstream-signed bundle in one signed repository."""
    other = "world.wimpress.HaberdasherOther"
    with (
        private_workspace() as runtime,
        disposable_key() as key,
        disposable_key() as provider_key,
        disposable_key() as upstream_key,
    ):
        root = runtime.root
        public_tree = root / "http"
        public_tree.mkdir()
        with (
            signing_session(
                runtime,
                expected_fingerprint=provider_key.fingerprint,
                key_file=provider_key.key_file,
            ) as provider,
            signing_session(
                runtime,
                expected_fingerprint=upstream_key.fingerprint,
                key_file=upstream_key.key_file,
            ) as upstream,
        ):
            runtime_commits = runtime_repo(
                runtime, public_tree, provider.fingerprint, provider.gnupghome
            )
            upstream_signer = (upstream.fingerprint, upstream.gnupghome, upstream_key.public_file)
            with serve(public_tree) as http:
                runtime_repofile = http.url("runtime.flatpakrepo")
                (public_tree / "runtime.flatpakrepo").write_bytes(
                    b"[Flatpak Repo]\nTitle=Runtime provider\nUrl="
                    + http.url("runtime-repo").encode()
                    + b"\nGPGKey="
                    + base64.b64encode(provider_key.public_file.read_bytes())
                    + b"\n"
                )
                assets = (
                    bundle(
                        runtime,
                        root,
                        "1",
                        1,
                        runtime_repo=runtime_repofile,
                        upstream=upstream_signer,
                    ),
                    bundle(runtime, root, "1", 2, app=other, runtime_repo=runtime_repofile),
                    bundle(
                        runtime,
                        root,
                        "1",
                        3,
                        arch="aarch64",
                        runtime_repo=runtime_repofile,
                        upstream=upstream_signer,
                    ),
                )
                admitted = []
                for index, asset in enumerate(assets):
                    inspected = flatpak.inspect(
                        asset, policy=POLICY, runtime=runtime, out=root / f"inspect-{index}"
                    )
                    assert inspected.evidence["runtime_repo"] == runtime_repofile
                    assert "signatures" not in flatpak._mapping(inspected.metadata["native"])
                    assert inspected.upstream_signature == ("unsigned" if index == 1 else "signed")
                    admitted.append(
                        admit(
                            inspected,
                            tuple(admitted),
                            compare=flatpak.compare,
                            policy=POLICY,
                            runtime=runtime,
                        )
                    )
                assert {item.transformation_policy for item in admitted} == {"flatpak-sign"}
                with signing_session(
                    runtime, expected_fingerprint=key.fingerprint, key_file=key.key_file
                ) as signer:
                    prepared = flatpak.prepare(
                        tuple(admitted),
                        RetainedFormat("flatpak", None, (), (), {}, ()),
                        policy=POLICY,
                        runtime=runtime,
                        signer=signer,
                        now=NOW,
                        out=root / "generation-1",
                    )
                    mixed = bundle(
                        runtime, root, "2", 4, app=other, runtime_repo=http.url("other.flatpakrepo")
                    )
                    inspected = flatpak.inspect(
                        mixed, policy=POLICY, runtime=runtime, out=root / "inspect-mixed"
                    )
                    retained = publish(prepared, public_tree / "publisher")
                    with pytest.raises(flatpak.FlatpakFailure, match="different runtime"):
                        flatpak.prepare(
                            (
                                admit(
                                    inspected,
                                    retained.accepted_history,
                                    compare=flatpak.compare,
                                    policy=POLICY,
                                    runtime=runtime,
                                ),
                            ),
                            retained,
                            policy=POLICY,
                            runtime=runtime,
                            signer=signer,
                            now=NOW,
                            out=root / "generation-mixed",
                        )
                # Validation accepts exactly one signature per commit, by the publisher key.
                flatpak.validate_retained(retained, policy=POLICY, runtime=runtime)
                heads = flatpak._mapping(retained.metadata["heads"])
                assert {ref for ref in heads if ref.startswith("app/")} == {
                    REF,
                    f"app/{other}/{ARCH}/stable",
                    f"app/{APP}/aarch64/stable",
                }
                repofile = (public_tree / "publisher" / flatpak.FLATPAKREPO).read_text()
                assert f"RuntimeRepo={runtime_repofile}\n" in repofile

                client = NativeClient(runtime, "multi")
                client_run(client, "remote-add", "--from", "provider", runtime_repofile)
                repo = published_remote(
                    http.url("publisher"), client.path("config/publisher.flatpakrepo")
                )
                client_run(client, "remote-add", "--from", "publisher", str(repo))
                assert (
                    "no-gpg-verify"
                    not in client_run(client, "remotes", "--columns=name,options").decode()
                )
                listing = client_run(
                    client, "remote-ls", "--arch=*", "--columns=ref", "publisher"
                ).decode()
                assert f"{APP}/aarch64/stable" in listing and f"{other}/x86_64/stable" in listing
                for app in (APP, other):
                    client_run(client, "install", "--noninteractive", "publisher", app)
                    assert client_run(client, "info", "--show-origin", app).strip() == b"publisher"
                installed_refs = set(client_run(client, "list", "--columns=ref").decode().split())
                assert installed_refs == {
                    ref.split("/", 1)[1] for ref in (REF, f"app/{other}/{ARCH}/stable", RREF, EREF)
                }
                assert (
                    client_run(client, "info", "--show-commit", RUNTIME).strip().decode()
                    == runtime_commits[0]
                )
