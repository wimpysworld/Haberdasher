from dataclasses import replace
from pathlib import Path

import pytest

from haberdasher.config import (
    MAX_BYTES,
    PRODUCTION_FINGERPRINT,
    Config,
    FormatPolicy,
    Policy,
    RuntimePolicy,
    StoragePolicy,
    load_config,
)


def document(tmp_path: Path, value: str) -> Path:
    path = tmp_path / "input.yaml"
    path.write_text(value)
    return path


def test_existing_config_and_defaults() -> None:
    config = load_config(Path("haberdasher.yaml"))
    assert config.sources == ("wimpysworld/tailor",)
    for name in ("arch", "apk"):
        assert config.format_policy(name).architectures == ("x86_64", "aarch64")
    assert config.format_policy("rpm").architectures == ("x86_64", "aarch64")
    assert "flatpak" not in config.formats
    signer = config.cosign["wimpysworld/tailor"]
    assert signer.bundle_suffix == ".sigstore.json"
    assert signer.issuer == "https://token.actions.githubusercontent.com"
    assert signer.certificate_identity("v0.6.0") == (
        "https://github.com/wimpysworld/tailor/.github/workflows/builder.yml@refs/tags/v0.6.0"
    )
    apt = config.format_policy("apt")
    assert (apt.suite, apt.component, apt.validity_seconds, apt.renewal_seconds) == (
        "stable",
        "main",
        604800,
        172800,
    )
    assert apt.architectures == ("amd64", "arm64")
    assert config.storage == StoragePolicy(
        "r2",
        {
            "apt": "haberdasher-apt",
            "rpm": "haberdasher-rpm",
            "apk": "haberdasher-apk",
            "arch": "haberdasher-pkg",
            "flatpak": "haberdasher-flatpak",
        },
        {
            "apt": "https://apt.wimpys.world",
            "rpm": "https://rpm.wimpys.world",
            "apk": "https://apk.wimpys.world",
            "arch": "https://pkg.wimpys.world",
            "flatpak": "https://flatpak.wimpys.world",
        },
    )
    assert config.public_formats() == ("apk", "apt", "arch", "rpm")
    with pytest.raises(ValueError):
        Policy().require_remote()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "null",
        "[]",
        "sources: wrong",
        "sources: [true]",
        "sources: [yes]",
        "sources: [123]",
        "sources: [owner/repo]\nunknown: true",
        "sources: [owner/repo, owner/repo]",
        "sources: [Owner/Repo, owner/repo]",
        "sources: [owner/../repo]",
        "sources: [owner/..]",
        "sources: []",
        "sources: [owner/repo]\nsources: [other/repo]",
        "sources: &s [owner/repo]\nother: *s",
        "sources: [owner/repo]\n<<: {}",
        "sources: !!python/object:os.system {}",
        "sources: [owner/repo]\n---\nsources: [other/repo]",
        "sources: [owner/repo]\nformats: {unknown: {}}",
        "sources: [owner/repo]\nformats: {apt: {unknown: true}}",
        "sources: [owner/repo]\nformats: {apt: {suite: true}}",
        "sources: [owner/repo]\nformats: {apt: {validity_seconds: true}}",
        "sources: [owner/repo]\nformats: {apt: {renewal_seconds: '123'}}",
        "sources: [owner/repo]\nformats: {apt: {renewal_seconds: 604800}}",
        "sources: [owner/repo]\nformats: {apt: {suite: '../escape'}}",
        "sources: [owner/repo]\nformats: {rpm: {suite: stable}}",
        "sources: [owner/repo]\nformats: {apt: {architectures: [amd64, amd64]}}",
        "{true: value}",
        "{? [complex, key]: value}",
        "sources: [{repository: owner/repo, unknown: true}]",
        "sources: [{cosign: {}}]",
        "sources: [owner/repo, {repository: owner/repo}]",
        "sources: [{repository: owner/repo, cosign: {issuer: 'https://issuer.invalid'}}]",
        *(
            "sources: [{repository: owner/repo, cosign: {" + cosign + "}}]"
            for cosign in (
                "bundle_suffix: .sigstore.json, issuer: 'https://i.invalid', identity: "
                "'https://i.invalid/x@{tag}', extra: true",
                "bundle_suffix: sigstore.json, issuer: 'https://i.invalid', identity: "
                "'https://i.invalid/x@{tag}'",
                "bundle_suffix: ./x, issuer: 'https://i.invalid', identity: 'https://i.invalid/x'",
                "bundle_suffix: .sig, issuer: 'http://i.invalid', identity: 'https://i.invalid/x'",
                "bundle_suffix: .sig, issuer: 'https://i.invalid', identity: 'i.invalid/x'",
                "bundle_suffix: .sig, issuer: 'https://i.invalid', identity: "
                "'https://i.invalid/x@{ref}'",
            )
        ),
    ],
)
def test_reject_configuration(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError):
        load_config(document(tmp_path, value))


@pytest.mark.parametrize(
    "value",
    [
        "#" * (MAX_BYTES + 1),
        "sources: " + "[" * 33 + "owner/repo" + "]" * 33,
        "sources: [" + ",".join("owner/repo" for _ in range(10_001)) + "]",
    ],
)
def test_resource_bounds(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError, match="exceeds"):
        load_config(document(tmp_path, value))


def test_duplicate_nested_keys(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unique"):
        load_config(
            document(
                tmp_path, "sources: [owner/repo]\nformats: {apt: {suite: stable, suite: testing}}"
            )
        )


def test_config_format_trust(tmp_path: Path) -> None:
    config = load_config(
        document(
            tmp_path,
            "sources: [owner/repo]\nformats: {rpm: {trust: {allow_signed_upstream: true, "
            f"upstream_fingerprints: ['{'A' * 40}']}}}}}}",
        )
    )
    rpm = config.format_policy("rpm")
    assert rpm.trust.allow_signed_upstream
    assert rpm.trust.upstream_fingerprints == ("A" * 40,)
    assert not config.format_policy("apt").trust.allow_signed_upstream


@pytest.mark.parametrize(
    "value",
    [
        "storage: {}",
        "storage: {backend: r2, public: {apt: {bucket: apt-bucket, url: 'https://a.invalid'}}}",
        "storage: {private: state, public: {apt: {bucket: apt-bucket, url: 'https://a.invalid'}}}",
        "storage: {public: {}}",
        "storage: {public: {apt: apt-bucket}}",
        "storage: {public: {apt: {bucket: apt-bucket}}}",
        "storage: {public: {apt: {url: 'https://a.invalid'}}}",
        "storage: {public: {apt: {bucket: true, url: 'https://a.invalid'}}}",
        "storage: {public: {apt: {bucket: apt-bucket, url: 'http://a.invalid'}}}",
        "storage: {public: {apt: {bucket: apt-bucket, url: 'https://a.invalid/path'}}}",
        "storage: {public: {apt: {bucket: apt-bucket, url: 'https://a.invalid', other: 1}}}",
        "storage: {public: {unknown: {bucket: bucket, url: 'https://a.invalid'}}}",
        "storage: {public: {apt: {bucket: shared, url: 'https://a.invalid'}, "
        "rpm: {bucket: shared, url: 'https://b.invalid'}}}",
        "storage: {public: {apt: {bucket: 'https://example.invalid/bucket', "
        "url: 'https://a.invalid'}}}",
        "formats: {rpm: {trust: {allow_signed_upstream: 'false'}}}",
        "formats: {rpm: {trust: {unknown: true}}}",
        "formats: {flatpak: {trust: {runtime: {unknown: true}}}}",
        "expected_signing_fingerprint: '" + "A" * 40 + "'",
        "HD_SIGNING_KEY: forbidden",
    ],
)
def test_reject_storage_and_trust(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError):
        load_config(document(tmp_path, f"sources: [owner/repo]\n{value}"))


@pytest.mark.parametrize(
    ("apt", "rpm"),
    [
        ("/tmp/public", "/tmp/public"),
        ("/tmp/public/rpm", "/tmp/public"),
        ("/tmp/apt", "/tmp/apt/public"),
        ("relative", "/tmp/public"),
    ],
)
def test_reject_local_storage(apt: str, rpm: str) -> None:
    with pytest.raises(ValueError):
        StoragePolicy("local", {"apt": apt, "rpm": rpm})


def test_public_formats_need_configured_format_and_bucket(tmp_path: Path) -> None:
    config = load_config(
        document(
            tmp_path,
            "sources: [owner/repo]\nformats: {apt: {}, rpm: {}}\n"
            "storage: {public: {rpm: {bucket: rpm-bucket, url: 'https://rpm.invalid'}, "
            "apk: {bucket: apk-bucket, url: 'https://apk.invalid'}}}",
        )
    )
    assert config.public_formats() == ("rpm",)
    assert load_config(document(tmp_path, "sources: [owner/repo]")).public_formats() == ()


def test_remote_needs_r2_and_production_key(tmp_path: Path) -> None:
    storage = StoragePolicy("r2", {"apt": "public-apt"})
    Policy(storage, PRODUCTION_FINGERPRINT).require_remote()
    for policy in (
        Policy(storage, "A" * 40),
        Policy(storage),
        Policy(StoragePolicy("r2"), PRODUCTION_FINGERPRINT),
        Policy(StoragePolicy("local", {"apt": str(tmp_path / "apt")}), PRODUCTION_FINGERPRINT),
    ):
        with pytest.raises(ValueError, match="production signing key"):
            policy.require_remote()


def flatpak_runtime() -> RuntimePolicy:
    return RuntimePolicy(
        url="http://127.0.0.1:12345/runtime",
        fingerprint="A" * 40,
        collection="",
        branch="stable",
        architecture="x86_64",
        remote="synthetic-runtime",
        refs=("runtime/org.example.Platform/x86_64/stable",),
    )


@pytest.mark.parametrize("collection", ["", "world.example.Runtime", " "])
def test_flatpak_runtime_policy(tmp_path: Path, collection: str) -> None:
    value = f"""sources: [owner/repo]
formats:
  flatpak:
    trust:
      source_owner: example
      refs: [app/org.example.App/x86_64/stable]
      runtime:
        url: http://127.0.0.1:12345/runtime
        fingerprint: '{"A" * 40}'
        collection: '{collection}'
        branch: stable
        architecture: x86_64
        remote: test-runtime
        refs: [runtime/org.example.Platform/x86_64/stable]
        extensions: []
"""
    if collection:
        with pytest.raises(ValueError, match="External runtime collection must be empty"):
            load_config(document(tmp_path, value))
        return
    config = load_config(document(tmp_path, value))
    trust = config.format_policy("flatpak").trust
    assert trust.runtime is not None
    assert trust.runtime.collection == ""
    assert load_config(document(tmp_path, value.replace("        collection: ''\n", ""))) == config
    with pytest.raises(ValueError):
        load_config(document(tmp_path, value.replace("127.0.0.1", "example.invalid")))


@pytest.mark.parametrize("collection", ["", "world.example.Runtime", " "])
def test_direct_runtime_collection_policy(collection: str) -> None:
    runtime = flatpak_runtime()
    if collection:
        with pytest.raises(ValueError, match="External runtime collection must be empty"):
            replace(runtime, collection=collection)
    else:
        assert replace(runtime, collection=collection).collection == ""


def test_direct_policy_validation() -> None:
    with pytest.raises(ValueError):
        FormatPolicy("apt", validity_seconds=True)
    with pytest.raises(ValueError):
        Config(("owner/repo", "OWNER/REPO"))
