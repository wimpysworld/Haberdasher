# Publisher operations

Haberdasher defaults to a read-only plan. Write modes require an explicit destination and preserve a private recovery record.

## Configuration

`haberdasher.yaml` contains public source and format settings. Operational policy belongs in a separate file selected by `--policy-file`. Keep operator attestations private.

Both files use the strict loader in `src/haberdasher/config.py`. It rejects unknown fields, duplicate keys, merges, anchors, aliases, and invalid types. Limits are 1 MiB, depth 32, and 10,000 nodes. PyYAML must provide LibYAML `CSafeLoader`.

This policy is a non-secret local example. Its fingerprint is a placeholder, not a signing identity:

```yaml
storage:
  backend: local
  private: /tmp/haberdasher-example/private
  public:
    apt: /tmp/haberdasher-example/public/apt
approved_formats: []
approval_references: {}
expected_signing_fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
clients:
  apt:
    approved: false
```

Replace the fingerprint with the independently verified disposable key fingerprint before an authorised local apply. `--local-root` replaces the local destination paths with `<root>/private` and `<root>/public/<format>`.

A local root must be disposable, outside the checkout, and distinct from the home root. Symlink paths reject. Local storage cannot override an R2 policy.

### Format selection

All public destinations in `storage.public` share one discovery and completion state. With multiple configured public formats, `--format all` is mandatory before any writes.

`--format NAME` is allowed only when NAME is the sole configured public format. A fresh local bootstrap without configured public destinations can also select NAME. This constraint deliberately prevents partial global-state updates. A completed format cannot disappear from later publications.

## Commands

After `just setup`, inspect the exact interface:

```sh
just publish --help
just publish --plan --config haberdasher.yaml
```

The plan requires runtime `GH_TOKEN` or `GITHUB_TOKEN`. GitHub subprocesses use an isolated configuration, not a stored personal login. Native subprocesses receive neither GitHub nor storage credentials.

These write examples are templates for approved operations, not activation instructions:

```sh
env -u HD_SIGNING_KEY HD_SIGNING_KEY_FILE=/private/disposable-test-key.asc \
  just publish --apply --local-root /tmp/haberdasher-example \
    --format apt --config haberdasher.yaml --policy-file local-policy.yaml
just publish --apply --remote --format all \
  --config haberdasher.yaml --policy-file publisher-policy.yaml
```

The local example requires a disposable test key outside the checkout, in a private file with mode `0400` or `0600`. Its independently verified full fingerprint must match `local-policy.yaml`. Do not copy or decrypt the canonical SOPS key for this fixture.

Production local signing reads the existing SOPS-managed path through `HD_SIGNING_KEY_FILE`. CI reads `HD_SIGNING_KEY`. Supply only one signing source. Keep the local SOPS convention. Do not copy, decrypt, or export the production key as a setup workaround. Signing requires the expected RSA4096 primary with signing and certification capabilities, without subkeys. Temporary keyrings and Alpine PKCS#8 conversion stay outside the checkout and Nix store. Cleanup stops owned agents and removes private exports.

### Remote policy

Remote policy requires `storage.backend: r2`, a separate private bucket, and public destinations by format. It requires the production fingerprint declared in `config.py`, approved formats, and per-format client approval references.

`approval_references` requires `private_storage`, `signing`, `repository_policy`, `live_r2`, `hosted_publication`, and `public_delivery`. APK also requires `apk_v2`. Flatpak also requires `flatpak_runtime`, an approved source owner, application refs, and runtime policy.

Runtime policy specifies URL, full fingerprint, collection, branch, architecture, remote, refs, and optional extensions. The current Flatpak adapter requires an empty collection. It rejects arbitrary runtime repository selection and signed upstream bundles. It does not add a source automatically.

These fields record operator attestations. They do not automatically validate cloud permissions, environment protection, HTTPS, or cache behaviour.

Storage subprocesses receive only the three documented `HD_CLOUDFLARE_*` storage variables through an isolated AWS configuration. Conditional create requires absence. Conditional replace requires the exact observed ETag. An ETag identifies a revision, not a SHA256 digest.

## Publication and state

`discovery.py` scans configured releases and assets, including additions to existing releases. Assets without a matching release checksum remain pending. Admission verifies source SHA256 before native import and rejects changed bytes under equivalent native identities.

Native adapters retain metadata and accepted history. Unchanged runs avoid package downloads, inspection, indexing, and signing. APT renews metadata within its configured renewal window. Flatpak restoration also requires current-head payload, not only metadata.

The private store contains ownership, frozen files/manifests, write journals, pending state, and completion. Public buckets contain packages, repository metadata, public keys, and `haberdasher.json`, not private control state.

The generation freezes exact public-key bytes before public writes. Both OpenPGP exports appear in every configured public role, including empty roles. The native APK public key appears only with the first APK index. An empty APK bucket does not claim native APK trust.

Publication writes bootstrap keys first, then native outputs in dependency-before-entry order. Each format's inventory follows its native outputs. Private completion follows all writes. Each write requires a durable intent, a conditional request, downloaded verification, and acknowledgement.

The frozen manifest binds bootstrap references, fingerprint, hashes, sizes, and order. Reuse verifies stored references and exact prior ETags. Changed public export bytes reject even when the fingerprint stays unchanged. Key rotation requires separate approval.

There is no multi-object atomicity. Split entry/signature pairs can temporarily fail client verification. The publisher retains older referenced objects and performs no deletion or retention change.

## Recovery

Ownership is non-expiring. There is no time-to-live takeover or force-unlock flag. A failed run can leave ownership active even before it creates a pending generation.

Stop the exact owner and resolve every outstanding request before recovery. Unknown write outcomes block further writes. A later read or apparent absence alone does not prove that a delayed request cannot commit.

Recovery evidence is schema-version-1 JSON. This example describes one confirmed request that did not write:

```json
{
  "schema_version": 1,
  "stopped_owner": true,
  "requests_resolved": true,
  "reference": "operator-record-of-stopped-run-and-request-resolution",
  "runner_identity": "replacement-runner",
  "writes": [
    {"ordinal": 0, "outcome": "not-written", "etag": null}
  ]
}
```

Use actual outstanding ordinals from the private journal. A `written` outcome requires its exact ETag. Do not copy these assertions without evidence. Recovery rejects missing resolutions, extra ordinals, and conflicting observations.

For a pending generation, name both the generation and stopped owner's nonce:

```sh
just publish --replay GENERATION --recover-owner NONCE \
  --recovery-evidence /private/recovery.json \
  --local-root /tmp/haberdasher-example --format apt \
  --policy-file local-policy.yaml
```

Use `--remote` instead of `--local-root` only with approved remote policy. If no pending output requires replay, omit `--replay` to recover and release ownership. `--recover-owner` always requires `--recovery-evidence`.

Replay uses exact frozen bytes. It requires no source packages, GitHub discovery, or private signing key. It still validates frozen native output and storage preconditions.

Expired frozen APT metadata rejects replay. Explicit new preparation requires a separate operator decision. There is no automatic re-sign, expiry bypass, or documented discard command. Do not delete pending state to bypass this gate.

See `src/haberdasher/{cli,core,state,publish,storage,signing}.py` and `tests/unit/test_recovery.py` for the exact records and transitions.
