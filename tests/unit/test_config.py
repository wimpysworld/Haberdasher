from pathlib import Path

import pytest

from haberdasher.config import (
    MAX_BYTES,
    PRODUCTION_FINGERPRINT,
    PUBLIC,
    Config,
    FormatPolicy,
    Policy,
    StoragePolicy,
    load_config,
)


def document(tmp_path: Path, value: str) -> Path:
    path = tmp_path / "input.yaml"
    path.write_text(value)
    return path


def test_existing_config_is_one_line_and_settings_are_code_defaults() -> None:
    assert (
        Path("haberdasher.yaml").read_text() == "sources: [wimpysworld/tailor, wimpysworld/sidra]\n"
    )
    config = load_config(Path("haberdasher.yaml"))
    assert config == Config(("wimpysworld/tailor", "wimpysworld/sidra"))
    assert config.format_policy("apt").architectures == ("amd64", "arm64")
    for name in ("rpm", "arch", "apk", "flatpak"):
        assert config.format_policy(name).architectures == ("x86_64", "aarch64")
    apt = config.format_policy("apt")
    assert (apt.suite, apt.component, apt.validity_seconds, apt.renewal_seconds) == (
        "stable",
        "main",
        604800,
        172800,
    )
    assert PUBLIC == {
        "apt": ("haberdasher-apt", "https://apt.wimpys.world"),
        "rpm": ("haberdasher-rpm", "https://rpm.wimpys.world"),
        "arch": ("haberdasher-pkg", "https://pkg.wimpys.world"),
        "apk": ("haberdasher-apk", "https://apk.wimpys.world"),
        "flatpak": ("haberdasher-flatpak", "https://flatpak.wimpys.world"),
    }
    StoragePolicy("r2", {name: bucket for name, (bucket, _) in PUBLIC.items()})
    with pytest.raises(ValueError):
        Policy().require_remote()


@pytest.mark.parametrize(
    "value",
    [
        "sources:\n  - wimpysworld/tailor\n  - example/other\n",
        "sources: [wimpysworld/tailor, example/other]\n",
    ],
)
def test_sources_list_is_the_whole_configuration(tmp_path: Path, value: str) -> None:
    config = load_config(document(tmp_path, value))
    assert config.sources == ("wimpysworld/tailor", "example/other")


@pytest.mark.parametrize("key", ["formats", "storage", "cosign", "trust"])
def test_unknown_key_is_one_clear_line(tmp_path: Path, key: str) -> None:
    with pytest.raises(ValueError) as error:
        load_config(document(tmp_path, f"sources: [owner/repo]\n{key}: {{}}\n"))
    message = str(error.value)
    assert message == (
        f"Unknown key '{key}' in input.yaml. Only 'sources' is allowed, "
        "for example sources: [owner/repo]"
    )
    assert "\n" not in message


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


def test_direct_policy_validation() -> None:
    with pytest.raises(ValueError):
        FormatPolicy("apt", validity_seconds=True)
    with pytest.raises(ValueError):
        Config(("owner/repo", "OWNER/REPO"))
