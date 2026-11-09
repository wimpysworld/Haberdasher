# Publisher operations

Haberdasher defaults to a read-only plan. Write modes require an explicit destination. A run takes a lock in each bucket that it writes. A full rerun is the only recovery.

## Configuration

`haberdasher.yaml` holds all publisher configuration: sources, formats, and storage buckets. There is no separate policy file.

The file uses the strict loader in `src/haberdasher/config.py`. It rejects unknown fields, duplicate keys, merges, anchors, aliases, and invalid types. Limits are 1 MiB, depth 32, and 10,000 nodes. PyYAML must provide LibYAML `CSafeLoader`.

A source is a repository name, or a mapping with `repository` and optional `cosign`. With `cosign`, discovery runs `cosign verify-blob` on each release checksum document before it reads the document. The bundle is the release asset named with the checksum filename plus `bundle_suffix`. Verification requires the exact `issuer` and the `identity`, with `{tag}` replaced by the release tag. A missing bundle or a failed verification stops the scan before import:

```yaml
sources:
  - repository: wimpysworld/tailor
    cosign:
      bundle_suffix: .sigstore.json
      issuer: https://token.actions.githubusercontent.com
      identity: https://github.com/wimpysworld/tailor/.github/workflows/builder.yml@refs/tags/{tag}
```

Cosign gets the Sigstore trust root through its normal online update in the private workspace.

The `storage` section names one public R2 bucket for each format:

```yaml
storage:
  public:
    apt: haberdasher-apt
    rpm: haberdasher-rpm
    apk: haberdasher-apk
    arch: haberdasher-pkg
    flatpak: haberdasher-flatpak
```

Each public bucket must be distinct. Bucket names must be valid R2 names. A format publishes only when it is under `formats` and has a public bucket. The committed configuration lists `apt`, `rpm`, `arch`, and `apk` under `formats`, so it publishes those four and not Flatpak.

Each format can have a `trust` mapping. RPM and APK use `allow_signed_upstream` and `upstream_fingerprints` to admit already-signed upstream packages. Flatpak needs `source_owner`, application `refs`, and a `runtime` with URL, full fingerprint, collection, branch, architecture, remote, refs, and optional extensions. The current Flatpak adapter requires an empty collection. It rejects arbitrary runtime repository selection and signed upstream bundles. It does not add a source automatically.

All configured public formats form one publication from one discovery scan. A run never changes the bucket of a format that is not configured.

## Commands

After `just setup`, use the three recipes. None takes arguments. Each reads `haberdasher.yaml` in the working directory:

```sh
just plan
just publish
just unlock
```

`just plan` needs runtime `GH_TOKEN` or `GITHUB_TOKEN` and uses no storage or signing. GitHub subprocesses use an isolated configuration, not a stored personal login. Native subprocesses receive neither GitHub nor storage credentials.

`just publish` publishes every configured format to its R2 bucket. `just unlock` deletes stale locks, as described in [Locks](#locks).

### Local test root

Tests and proofs use a hidden `--local-root PATH` option on `python -m haberdasher publish` and `unlock`. It ignores the R2 buckets and writes to `<root>/public/<format>`. A local root must be disposable, outside the checkout, and distinct from the home root. Symlink paths reject. A local run publishes the formats with a public bucket, otherwise the formats under `formats`, otherwise all formats.

A local run takes its signing fingerprint from the key in `HD_SIGNING_KEY_FILE` or `HD_SIGNING_KEY`. Use a disposable test key outside the checkout, in a private file with mode `0400` or `0600`. Without a key, a local run can publish only output that needs no signature. Do not copy or decrypt the canonical SOPS key for this fixture.

Production local signing reads the existing SOPS-managed path through `HD_SIGNING_KEY_FILE`. CI reads `HD_SIGNING_KEY`. Supply only one signing source. Keep the local SOPS convention. Do not copy, decrypt, or export the production key as a setup workaround. Signing requires the expected RSA4096 primary with signing and certification capabilities, without subkeys. Temporary keyrings and Alpine PKCS#8 conversion stay outside the checkout and Nix store. Cleanup stops owned agents and removes private exports.

### Remote publication

`just publish` needs the `storage` section and at least one configured format with a public bucket. It always signs with the production fingerprint `PRODUCTION_FINGERPRINT` in `src/haberdasher/config.py`. The signing key must match that fingerprint.

Storage subprocesses receive only the three documented `HD_CLOUDFLARE_*` storage variables through an isolated AWS configuration. Conditional create requires absence. Conditional replace requires the exact observed ETag. An ETag identifies a revision, not a SHA256 digest.

## Publication and state

`discovery.py` scans configured releases and assets, including additions to existing releases. Assets without a matching release checksum remain pending. Admission verifies source SHA256 before native import and rejects changed bytes under equivalent native identities.

Each bucket's public `haberdasher.json` is the publication state for its format. It holds the inventory allow-list (package identity, source, published digests, and referenced objects) and the accepted history and metadata keys that the native adapter needs. There is no private state bucket. A run reads each inventory first. An asset whose bytes are already in the inventory needs no download. When a format changes, the run downloads only the published metadata that the inventory references, not the package pool. Unchanged runs avoid package downloads, inspection, indexing, and signing, and write nothing except the locks. APT renews metadata within its configured renewal window. Flatpak restoration downloads every object of its OSTree repository.

Both OpenPGP exports appear in every configured public bucket, including empty ones. The native APK public key appears only with the first APK index. An empty APK bucket does not claim native APK trust. Changed public export bytes reject even when the fingerprint stays unchanged. Key rotation is not supported.

For each format, a run writes the bootstrap keys and packages, then dependency metadata, then entry metadata, then `haberdasher.json`. A run replaces published entries only on the exact ETag that it read. Objects that the published inventory references never change. A run can overwrite an object that the published inventory does not reference, because an interrupted run can leave one with other signature bytes. RPM and Arch package signatures are not deterministic.

There is no multi-object atomicity. Split entry/signature pairs can temporarily fail client verification. The publisher retains older referenced objects and performs no deletion or retention change.

## Locks

Before it writes, `just publish` creates `haberdasher.lock` in each configured bucket, in sorted format order, with a conditional create. The lock holds a random run identifier, the host name or GitHub runner and run URL, and the UTC start time. It never appears in `haberdasher.json`. A local test root holds the same file in each format directory.

When a lock already exists, the run deletes the locks that it created and fails. The error names the bucket and shows the existing lock. At the end of a run, and after a handled error, the run deletes only its own locks, conditionally on the ETags that it created.

A run that stops without cleanup, for example after a killed process, leaves its locks. When you know that the run has stopped, delete them explicitly:

```sh
just unlock
```

`just unlock` deletes the existing locks in the configured buckets, prints what it deleted, and exits without publishing.

## Recovery

Recover from an interrupted run with a full rerun of `just publish`. The rerun reads the last complete `haberdasher.json`, prepares and signs again, overwrites leftover unreferenced objects, and publishes new metadata. There is no replay, write journal, or crash-recovery state.

An unknown write outcome stops the run. Delete a stale lock with `just unlock` first when the run could not release it.

See `src/haberdasher/{cli,state,publish,storage}.py` and `tests/unit/test_publish.py` for the exact behaviour.
