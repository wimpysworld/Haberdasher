from pathlib import Path

import pytest

from haberdasher.config import (
    APPROVAL_GATES,
    MAX_BYTES,
    PRODUCTION_FINGERPRINT,
    Config,
    FormatPolicy,
    Policy,
    StoragePolicy,
    TrustPolicy,
    load_config,
    load_policy,
)


def document(tmp_path: Path, value: str) -> Path:
    path = tmp_path / "input.yaml"
    path.write_text(value)
    return path


def test_existing_config_and_defaults() -> None:
    config = load_config(Path("haberdasher.yaml"))
    assert config.sources == ("wimpysworld/tailor",)
    assert not config.formats
    apt = config.format_policy("apt")
    assert (apt.suite, apt.component, apt.validity_seconds, apt.renewal_seconds) == (
        "stable",
        "main",
        604800,
        172800,
    )
    assert apt.architectures == ("amd64", "arm64")
    assert not load_policy(None).approved_formats
    with pytest.raises(ValueError):
        load_policy(None).require_remote(("apt",))


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
        "sources: [owner/repo]\nformats: {apt: {trust: {approved: true}}}",
        "{true: value}",
        "{? [complex, key]: value}",
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


def test_config_policy_merge(tmp_path: Path) -> None:
    config = load_config(
        document(
            tmp_path,
            "sources: [owner/repo]\nformats: {apt: {architectures: [amd64], suite: testing}}",
        )
    )
    policy = Policy(clients={"apt": TrustPolicy(approved=True, approval_reference="local-test")})
    apt = policy.format_policy(config, "apt")
    assert apt.suite == "testing"
    assert apt.trust.approved
    assert not config.formats["apt"].trust.approved


@pytest.mark.parametrize(
    "value",
    [
        "unknown: true",
        "storage: {backend: s3}",
        "storage: {private: true}",
        "storage: {backend: r2, private: same-bucket, public: {apt: same-bucket}}",
        "storage: {backend: r2, private: 'https://example.invalid/bucket'}",
        "storage: {private: /tmp/private, public: {apt: /tmp/private/public}}",
        "storage: {private: relative}",
        "approved_formats: [true]",
        "approved_formats: [unknown]",
        "approval_references: {unknown: reference}",
        "approval_references: {signing: true}",
        "expected_signing_fingerprint: 123",
        "HD_SIGNING_KEY: forbidden",
        "clients: {apt: {approved: 'true'}}",
        "clients: {rpm: {allow_signed_upstream: 'false'}}",
        "clients: {apt: {unknown: true}}",
        "clients: {unknown: {}}",
        "clients: {flatpak: {runtime: {unknown: true}}}",
    ],
)
def test_reject_policy(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError):
        load_policy(document(tmp_path, value))


def test_local_policy(tmp_path: Path) -> None:
    value = f"""storage:
  backend: local
  private: {tmp_path}/private
  public:
    apt: {tmp_path}/apt
approved_formats: [apt]
expected_signing_fingerprint: '{"A" * 40}'
clients:
  apt:
    approved: true
    approval_reference: synthetic-local-test
"""
    policy = load_policy(document(tmp_path, value))
    assert policy.expected_signing_fingerprint == "A" * 40
    assert policy.clients["apt"].approved
    with pytest.raises(ValueError):
        policy.require_remote(("apt",))


def test_remote_requires_every_gate() -> None:
    references = {name: "reviewed-reference" for name in APPROVAL_GATES}
    storage = StoragePolicy("r2", "private-state", {"apt": "public-apt"})
    clients = {"apt": TrustPolicy(True, "apt-reference")}
    policy = Policy(storage, ("apt",), references, PRODUCTION_FINGERPRINT, clients)
    policy.require_remote(("apt",))
    for name in APPROVAL_GATES - {"apk_v2", "flatpak_runtime"}:
        missing = Policy(
            storage,
            ("apt",),
            {key: value for key, value in references.items() if key != name},
            PRODUCTION_FINGERPRINT,
            clients,
        )
        with pytest.raises(ValueError):
            missing.require_remote(("apt",))
    with pytest.raises(ValueError):
        policy.require_remote(())
    with pytest.raises(ValueError):
        policy.require_remote(("flatpak",))


def test_flatpak_runtime_policy(tmp_path: Path) -> None:
    value = f"""clients:
  flatpak:
    source_owner: example
    refs: [app/org.example.App/x86_64/stable]
    runtime:
      url: http://127.0.0.1:12345/runtime
      fingerprint: '{"A" * 40}'
      collection: ''
      branch: stable
      architecture: x86_64
      remote: test-runtime
      refs: [runtime/org.example.Platform/x86_64/stable]
      extensions: []
"""
    policy = load_policy(document(tmp_path, value))
    assert policy.clients["flatpak"].runtime is not None
    with pytest.raises(ValueError):
        load_policy(document(tmp_path, value.replace("127.0.0.1", "example.invalid")))


def test_direct_policy_validation() -> None:
    with pytest.raises(ValueError):
        FormatPolicy("apt", validity_seconds=True)
    with pytest.raises(ValueError):
        Config(("owner/repo", "OWNER/REPO"))
