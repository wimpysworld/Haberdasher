# Publisher operations

Haberdasher defaults to a read-only plan. Write modes require an explicit destination. A run takes a lock in each bucket that it writes. A full rerun is the only recovery.

## Configuration

`haberdasher.yaml` is a list of GitHub repositories. It has no per-project settings and there is no separate policy file:

```yaml
sources: [wimpysworld/tailor]
```

The file uses the strict loader in `src/haberdasher/config.py`. Any key other than `sources` stops the run with one line that names the key. The loader also rejects duplicate keys, merges, anchors, aliases, and invalid types. Limits are 1 MiB, depth 32, and 10,000 nodes. PyYAML must provide LibYAML `CSafeLoader`.

### Derived settings

Haberdasher derives every other setting:

| Setting | Source |
| --- | --- |
| Format | Asset suffix: `.deb` APT, `.rpm` RPM, `.pkg.tar.zst` and `.pkg.tar.xz` Arch, `.apk` Alpine. Native inspection confirms the type. Other assets are ignored. |
| Architecture | Package metadata, never the file name |
| Bucket and public URL | The `PUBLIC` table in `src/haberdasher/config.py` |
| APT suite, component, and validity | Code defaults: `stable`, `main`, seven days, renewal within two days |
| Upstream signatures | Not checked. RPM inputs lose upstream signatures before Haberdasher signs them. APK inputs lose their `.SIGN.*` stream. Arch ignores release `.sig` assets. APT publishes `.deb` packages unchanged. |

A `.flatpak` asset prints `Flatpak not supported yet, skipped`, and the run continues. The Flatpak adapter needs per-project runtime and application settings, which `haberdasher.yaml` does not allow.

### Architectures

Each format accepts these architectures:

| Format | Architectures | Architecture-independent placement |
| --- | --- | --- |
| APT | `amd64`, `arm64`, `all` | `all` packages appear in every `binary-<arch>/Packages` index |
| RPM | `x86_64`, `aarch64`, `noarch` | One repository holds every architecture |
| Arch | `x86_64`, `aarch64`, `any` | `any` packages appear in every `<arch>/` directory and database |
| Alpine | `x86_64`, `aarch64`, `noarch` | `noarch/` holds the package, and every `<arch>/APKINDEX.tar.gz` lists it, because `apk` fetches from the directory of the package architecture |

Another architecture stops the run with one line that names the package and the architecture.

### Checksums and cosign

Each release needs a checksum before import. Discovery reads combined checksum files (`SHA256SUMS`, `checksums.txt`, `*_checksums.txt`, `*.sha256sum`) and per-asset `<asset>.sha256` files. A per-asset file can hold a bare digest. When two checksum files list the same asset, their digests must agree.

GitHub reports a `sha256:` digest for each release asset. Discovery checks each checksum file and listed asset against it. When a release has no checksum file entry for a package, the GitHub digest is the checksum. A package without any checksum stays pending, and the plan line counts it as skipped.

When a checksum file has a sibling `<checksum file>.sigstore.json`, discovery runs `cosign verify-blob --bundle` before it reads the file. The issuer must be `https://token.actions.githubusercontent.com`. The certificate identity must match `^https://github\.com/<owner>/<repo>/\.github/workflows/[^@]+@refs/tags/<tag>$`, for any workflow file. A failed bundle stops the run. A release without a bundle shows `no cosign bundle` instead of `cosign OK`.

Cosign gets the Sigstore trust root through its normal online update in the private workspace.

### Publication scope

One publication covers every format that any source provides, plus every format that is already published. One discovery scan feeds it. A format without packages gets no writes, not even a lock.

## Commands

After `just setup`, use the three recipes. None takes arguments. Each reads `haberdasher.yaml` in the working directory:

```sh
just plan
just publish
just unlock
```

`just plan` needs runtime `GH_TOKEN` or `GITHUB_TOKEN` and uses no storage credentials or signing. GitHub subprocesses use an isolated configuration, not a stored personal login. Native subprocesses receive neither GitHub nor storage credentials.

`just publish` publishes each format in the publication scope to its R2 bucket. `just unlock` deletes stale locks, as described in [Locks](#locks).

Each command prints plain text lines to stdout as each step starts or ends, then a short summary. An error prints one `Error:` line to stderr and exits with status 1.

`just plan` checks the checksums and cosign bundle of each release. Then it reads the public `haberdasher.json` of every format over HTTPS without credentials. HTTP 404 means that nothing is published. The table shows each format that the sources provide or that is already published. A repository that cannot be read shows `?` and the plan continues:

```text
Reading haberdasher.yaml: 1 source
wimpysworld/tailor: 9 releases
  v0.6.0  checksums OK  cosign OK  8 packages
  v0.5.0  checksums OK  cosign OK  8 packages
  ...
Reading published state from apt.wimpys.world, rpm.wimpys.world, pkg.wimpys.world, apk.wimpys.world, flatpak.wimpys.world

Format  Repository        Published  New
apt     apt.wimpys.world          0   18
rpm     rpm.wimpys.world          0   18
arch    pkg.wimpys.world          0   18
apk     apk.wimpys.world          0   18

72 new packages. Nothing written. Run `just publish` to publish them.
```

The plan matches packages to the published state by the SHA256 checksum of each release asset, the same test that `just publish` uses to skip a download. It does not download packages, so it cannot inspect their native identities.

`just publish` prints the same discovery lines and one line for each format step:

```text
apk   locked
apt   locked
...
apt   preparing 18 new packages
apt   signed metadata
...
apt   uploaded 20 objects
apt   wrote haberdasher.json
...
apt   unlocked
Published 72 packages to 4 repositories.
```

When nothing is new, each format prints `unchanged` and the summary is `Nothing changed in 4 repositories.`

### Local test root

Tests and proofs use a hidden `--local-root PATH` option on `python -m haberdasher publish` and `unlock`. It ignores the R2 buckets and writes to `<root>/public/<format>`. A local root must be disposable, outside the checkout, and distinct from the home root. Symlink paths reject. A local run uses the same publication scope, and treats a format as published when `<root>/public/<format>/haberdasher.json` exists.

A local run takes its signing fingerprint from the key in `HD_SIGNING_KEY_FILE` or `HD_SIGNING_KEY`. Use a disposable test key outside the checkout, in a private file with mode `0400` or `0600`. Without a key, a local run can publish only output that needs no signature. Do not copy or decrypt the canonical SOPS key for this fixture.

Production local signing reads the existing SOPS-managed path through `HD_SIGNING_KEY_FILE`. CI reads `HD_SIGNING_KEY`. Supply only one signing source. Keep the local SOPS convention. Do not copy, decrypt, or export the production key as a setup workaround. Signing requires the expected RSA4096 primary with signing and certification capabilities, without subkeys. Temporary keyrings and Alpine PKCS#8 conversion stay outside the checkout and Nix store. Cleanup stops owned agents and removes private exports.

### Remote publication

`just publish` checks the storage credentials before discovery. It always signs with the production fingerprint `PRODUCTION_FINGERPRINT` in `src/haberdasher/config.py`. The signing key must match that fingerprint.

Storage subprocesses receive only the three documented `HD_CLOUDFLARE_*` storage variables through an isolated AWS configuration. Conditional create requires absence. Conditional replace requires the exact observed ETag. An ETag identifies a revision, not a SHA256 digest.

## Publication and state

`discovery.py` scans configured releases and assets, including additions to existing releases. Assets without a matching release checksum remain pending. Admission verifies source SHA256 before native import and rejects changed bytes under equivalent native identities.

Each bucket's public `haberdasher.json` is the publication state for its format. It holds the inventory allow-list (package identity, source, published digests, and referenced objects) and the accepted history and metadata keys that the native adapter needs. There is no private state bucket. A run reads each inventory first. An asset whose bytes are already in the inventory needs no download. When a format changes, the run downloads only the published metadata that the inventory references, not the package pool. Unchanged runs avoid package downloads, inspection, indexing, and signing, and write nothing except the locks. APT renews metadata within its renewal window. Flatpak restoration downloads every object of its OSTree repository.

Both OpenPGP exports appear in every published bucket. The native APK public key appears only with the first APK index. An empty APK bucket does not claim native APK trust. Changed public export bytes reject even when the fingerprint stays unchanged. Key rotation is not supported.

For each format, a run writes the bootstrap keys and packages, then dependency metadata, then entry metadata, then `haberdasher.json`. A run replaces published entries only on the exact ETag that it read. Objects that the published inventory references never change. A run can overwrite an object that the published inventory does not reference, because an interrupted run can leave one with other signature bytes. RPM and Arch package signatures are not deterministic.

There is no multi-object atomicity. Split entry/signature pairs can temporarily fail client verification. The publisher retains older referenced objects and performs no deletion or retention change.

## Locks

Before it writes, `just publish` creates `haberdasher.lock` in each bucket of the publication scope, in sorted format order, with a conditional create. The lock holds a random run identifier, the host name or GitHub runner and run URL, and the UTC start time. It never appears in `haberdasher.json`. A local test root holds the same file in each format directory.

When a lock already exists, the run deletes the locks that it created and fails. The error names the bucket and shows the existing lock. At the end of a run, and after a handled error, the run deletes only its own locks, conditionally on the ETags that it created.

A run that stops without cleanup, for example after a killed process, leaves its locks. When you know that the run has stopped, delete them explicitly:

```sh
just unlock
```

`just unlock` deletes the existing locks in all five buckets and exits without publishing. It prints one line for each bucket:

```text
apk   no lock
apt   removed lock from builder started 2026-11-09T10:00:00+00:00
```

## Recovery

Recover from an interrupted run with a full rerun of `just publish`. The rerun reads the last complete `haberdasher.json`, prepares and signs again, overwrites leftover unreferenced objects, and publishes new metadata. There is no replay, write journal, or crash-recovery state.

An unknown write outcome stops the run. Delete a stale lock with `just unlock` first when the run could not release it.

See `src/haberdasher/{cli,state,publish,storage}.py` and `tests/unit/test_publish.py` for the exact behaviour.
