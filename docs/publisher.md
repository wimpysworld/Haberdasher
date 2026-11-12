# Publisher operations

`just plan` is read-only. `just publish` writes to the R2 buckets in the `PUBLIC` table of `src/haberdasher/config.py`. A run takes a lock in each bucket that it writes. A full rerun is the only recovery.

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
| Format | Asset suffix and release layout: `.deb` APT, `.rpm` RPM, `.pkg.tar.zst` and `.pkg.tar.xz` Arch, `.apk` Alpine, `.flatpak` Flatpak, macOS binaries and `.zip` apps Homebrew, Windows `.exe` and `.zip` apps Scoop, and release `nix/` expressions or `.tar.gz`, `.deb`, `.dmg`, and macOS `.zip` assets Nix. Native inspection confirms the type. Other assets are ignored. |
| Architecture | Package metadata or binary headers, never the file name |
| Bucket and public URL | The `PUBLIC` table in `src/haberdasher/config.py` (`haberdasher-nix` and `https://nix.wimpys.world` for `nix`) |
| APT suite and component | Constants in `src/haberdasher/formats/apt.py`: `stable` and `main`. `Release` has a `Date` and no `Valid-Until`. |
| Upstream signatures | Not checked. RPM inputs lose upstream signatures before Haberdasher signs them. APK inputs lose their `.SIGN.*` stream. Arch ignores release `.sig` assets. APT publishes `.deb` packages unchanged. Flatpak commits lose their detached upstream signatures. |

A `.flatpak` bundle supplies its own settings. The application ref gives the app ID, architecture, and branch. The application metadata gives the runtime. The bundle's `runtime-repo` gives the runtime repository, or Flathub (`https://dl.flathub.org/repo/flathub.flatpakrepo`) when the bundle has none. All applications go into one OSTree repository, with `wimpysworld.flatpakrepo` and one `<app-id>.flatpakref` per application at its root. The `.flatpakref` file takes its `Title` from the AppStream name and its `RuntimeRepo` from the bundle. A run fails when bundles name different runtime repositories, because `wimpysworld.flatpakrepo` holds one `RuntimeRepo`.

For Nix, `haberdasher-nix` (`https://nix.wimpys.world`) serves a bare Git flake repository at `packages.git` over dumb HTTP and a signed HTTP binary cache (`nix-cache-info` with `Priority: 41` and `WantMassQuery: 1`, `<hash>.narinfo`, and `nar/<hash>.nar.zst`). When a release tag contains a package expression under `nix/` (such as `nix/default.nix`, `nix/linux.nix`, `nix/darwin.nix`, or `nix/package.nix`), the adapter uses that upstream expression and rewrites its `fetchurl` hashes to the verified SRI hashes of the release assets. When no upstream `nix/` package expression exists, the adapter derives a package expression from Linux and macOS `.tar.gz` release archives, or falls back to `.deb` and macOS `.dmg` or `.zip` assets when the release has no `.tar.gz` archives. Each commit in `packages.git` is tagged at `refs/tags/<rev>`, and the flake source tree and `x86_64-linux` store paths are signed with the deterministic `nix.wimpys.world-1` Ed25519 key and exported to the binary cache.

### Architectures

Each format accepts these architectures:

| Format | Architectures | Architecture-independent placement |
| --- | --- | --- |
| APT | `amd64`, `arm64`, `all` | `all` packages appear in every `binary-<arch>/Packages` index |
| RPM | `x86_64`, `aarch64`, `noarch` | One repository holds every architecture |
| Arch | `x86_64`, `aarch64`, `any` | `any` packages appear in every `<arch>/` directory and database |
| Alpine | `x86_64`, `aarch64`, `noarch` | `noarch/` holds the package, and every `<arch>/APKINDEX.tar.gz` lists it, because `apk` fetches from the directory of the package architecture |
| Nix | `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin` | `packages.git` exposes each package under `packages.<system>.<name>` for its supported systems, and the binary cache serves `x86_64-linux` store paths and the flake source tree |

Flatpak accepts application bundles for `x86_64` and `aarch64`. A package with another architecture is skipped with one line that names the file and the architecture, for example `apt   skipped tool_1.0_armhf.deb: unsupported APT architecture 'armhf'`. An Android `.apk` is skipped the same way. `just plan` and `just publish` print the same line, and continue with the other assets and sources.

### Releases

Discovery reads only the GitHub "Latest" release of each source, from `repos/<owner>/<repo>/releases/latest`. GitHub never marks a draft or a pre-release as "Latest". When a source has no latest release (HTTP 404), the plan prints `<source>: no latest release` and continues. Any other failed request stops the run.

A run adds the packages of each latest release to the published repositories. Versions that are already published stay published, and their objects stay in the buckets. When a new release becomes "Latest", the next run adds its packages beside the earlier versions. When an asset is added to the latest release after publication, the next run adds that asset. Older releases that were never published are not read and are not backfilled.

### Checksums and cosign

Each release needs a checksum before import. Discovery reads combined checksum files (`SHA256SUMS`, `checksums.txt`, `*_checksums.txt`, `*.sha256sum`) and per-asset `<asset>.sha256` files. A per-asset file can hold a bare digest. When two checksum files list the same asset, their digests must agree.

GitHub reports a `sha256:` digest for each release asset. Discovery checks each checksum file and listed asset against it. When a release has no checksum file entry for a package, the GitHub digest is the checksum. A package without any checksum is skipped, and the plan line counts it.

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

`just plan` uses runtime `GH_TOKEN` or `GITHUB_TOKEN`. When both are unset, Haberdasher reads the token of the stored `gh` login with `gh auth token`. That command receives only `PATH`, `HOME`, and the `gh` configuration and keyring variables, never the storage or signing variables. The plan uses no storage credentials or signing. Other GitHub subprocesses use an isolated configuration. Native subprocesses receive neither GitHub nor storage credentials.

`just publish` publishes each format in the publication scope to its R2 bucket. `just unlock` deletes stale locks, as described in [Locks](#locks).

Each command prints plain text lines to stdout as each step starts or ends, then a short summary. An error prints one `Error:` line to stderr and exits with status 1.

`just plan` checks the checksums and cosign bundle of the latest release of each source. Then it reads the public `haberdasher.json` of every format over HTTPS without credentials. HTTP 404 means that nothing is published. The table shows each format that the sources provide or that is already published. A repository that cannot be read shows `?` and the plan continues:

```text
Reading haberdasher.yaml: 2 sources
wimpysworld/tailor: latest release v0.6.0
  v0.6.0  checksums OK  cosign OK  8 packages
wimpysworld/sidra: latest release 1.3.0
  1.3.0  GitHub digests OK  no cosign bundle  6 packages
Reading published state from apt.wimpys.world, rpm.wimpys.world, pkg.wimpys.world, apk.wimpys.world, flatpak.wimpys.world

Format   Repository            Published  New
apt      apt.wimpys.world              0    4
rpm      rpm.wimpys.world              0    4
arch     pkg.wimpys.world              0    2
apk      apk.wimpys.world              0    2
flatpak  flatpak.wimpys.world          0    2

14 new packages. Nothing written. Run `just publish` to publish them.
```

The plan also reads each published `index.html`. When the page is missing or differs from the page that `just publish` would write, the plan prints one line before the table, for example `apt   would write index.html`, and the summary counts the pages, for example `No new packages. 5 index pages to write.`

The plan matches packages to the published state by the SHA256 checksum of each release asset, the same test that `just publish` uses to skip a download. It downloads and inspects each new asset, so it skips the same unsupported assets as `just publish`. It does not compare native identities with the published history.

`just publish` prints the same discovery lines and one line for each format step:

```text
apk   locked
apt   locked
...
apt   preparing 18 new packages
apt   signed metadata
...
apt   uploading 10 objects (214 MB)
apt     keys/haberdasher.asc (3 KB)
apt     pool/main/s/sidra/sidra_1.3.0_amd64.deb (104 MB)
...
apt   138.106 MiB / 204.513 MiB, 68%, 156.941 KiB/s, ETA 7m13s
apt   upload stalled, waiting
apt   upload resumed
apt   182.400 MiB / 204.513 MiB, 89%, 9.871 MiB/s, ETA 2s
apt   uploaded 10 objects in 5m11s
apt     dists/stable/main/binary-amd64/Packages (2 KB)
...
apt     dists/stable/InRelease (4 KB)
apt   wrote haberdasher.json
apt   wrote index.html
...
flatpak uploading 530 objects (226 MB)
flatpak   keys/haberdasher.asc (2 KB)
flatpak   objects/ 522 files (225 MB)
...
flatpak uploaded 530 objects in 1m02s
flatpak   refs/heads/app/world.wimpys.Sidra/x86_64/stable (65 B)
...
apt   unlocked
Published 72 packages to 4 repositories.
```

Each upload lists every object by key and size before `rclone` starts. Flatpak lists OSTree `objects/` as one line. Each metadata line names the key before its write. `rclone` reports progress every 10 seconds while an upload runs. An upload that ends within 10 seconds prints no progress lines, and no upload prints the final total. When the byte count does not change, one `upload stalled, waiting` line replaces the repeated progress lines until the upload continues.

When nothing is new, each format prints `unchanged` and the summary is `Nothing changed in 4 repositories.` A run that writes metadata but no new packages, for example the first public keys of a bucket, ends with `Refreshed apt metadata.` A run that writes only index pages ends with `Refreshed the apt and rpm index pages.`

### Local test root

Tests use a hidden `--local-root PATH` option on `python -m haberdasher publish` and `unlock`. It ignores the R2 buckets and writes to `<root>/public/<format>`. A local root must be disposable, outside the checkout, and distinct from the home root. Symlink paths reject. A local run uses the same publication scope, and treats a format as published when `<root>/public/<format>/haberdasher.json` exists.

A local run takes its signing fingerprint from the key in `HD_SIGNING_KEY_FILE` or `HD_SIGNING_KEY`. Use a disposable test key outside the checkout, in a private file with mode `0400` or `0600`. Without a key, a local run can publish only output that needs no signature. Do not copy or decrypt the canonical SOPS key for this fixture.

Production local signing reads the existing SOPS-managed path through `HD_SIGNING_KEY_FILE`. CI reads `HD_SIGNING_KEY`. Supply only one signing source. Keep the local SOPS convention. Do not copy, decrypt, or export the production key as a setup workaround. Signing requires the expected RSA4096 primary with signing and certification capabilities, without subkeys. Temporary keyrings, Alpine PKCS#8 conversion, and Nix Ed25519 derivation stay outside the checkout and Nix store. Cleanup stops owned agents and removes private exports.

### Remote publication

`just publish` checks the storage credentials before discovery. It always signs with the production fingerprint `PRODUCTION_FINGERPRINT` in `src/haberdasher/config.py`. The signing key must match that fingerprint.

Storage subprocesses receive only the three documented `HD_CLOUDFLARE_*` storage variables through an isolated AWS configuration. Conditional create requires absence. Conditional replace requires the exact observed ETag. An ETag identifies a revision, not a SHA256 digest.

Each format uploads its new packages, signatures, dependency metadata, keys, and Flatpak objects with one `rclone copy` run for each content type and cache policy, 16 transfers at a time, then confirms their sizes and MD5 checksums with one `rclone lsjson` run. While `rclone` runs, the format prints its transfer statistics every 10 seconds. Locks, entry metadata, `haberdasher.json`, and `index.html` use conditional single-object writes with `aws s3api`.

APT places each package at `pool/main/<prefix>/<source>/<package>_<version>_<arch>.deb`, without the epoch, for example `pool/main/s/sidra/sidra_1.3.0_amd64.deb`. RPM places each package at `packages/<name>-<version>-<release>.<arch>.rpm`, for example `packages/sidra-1.3.0-1.x86_64.rpm`. When two packages need one file name, the run stops with one line that names the file and both sources.

## Publication and state

`discovery.py` scans the latest release of each source and its assets, including assets added to that release later. Assets without a matching release checksum are skipped. Admission verifies source SHA256 before native import and rejects changed bytes under equivalent native identities.

Each bucket's public `haberdasher.json` is the publication state for its format. It holds the inventory allow-list (package identity, source, published digests, and referenced objects) and the accepted history and metadata keys that the native adapter needs. There is no private state bucket. A run reads each inventory first. An asset whose bytes are already in the inventory needs no download. When a format changes, the run downloads only the published metadata that the inventory references, not the package pool. Unchanged runs avoid package downloads, inspection, indexing, and signing, and write nothing except the locks. Flatpak restoration downloads only a working set: the repository entries, the current summaries, each head commit and its signature, the AppStream trees, and the `/metadata` and `/files/share/app-info` paths of each application head. `flatpak build-update-repo` needs those AppStream paths to keep unchanged applications in the AppStream catalogue. Payload files and earlier commits stay published and are not downloaded again. Nix restoration downloads only `packages.git` objects, tags, and refs, `nix-cache-info`, and `keys/haberdasher-nix.pub`. Published `nar/*.nar.zst` archives and `*.narinfo` files stay referenced in the inventory without re-downloading.

Both OpenPGP exports appear in every published signed bucket. The native APK public key appears only with the first APK index, and `keys/haberdasher-nix.pub` appears with the first Nix publication. An empty APK or Nix bucket does not claim native cache or index trust. Changed public export bytes reject even when the fingerprint stays unchanged. Key rotation is not supported.

For each format, a run writes the bootstrap keys and packages, then dependency metadata, then entry metadata, then `haberdasher.json`. A run replaces published entries only on the exact ETag that it read. Objects that the published inventory references never change. A run can overwrite an object that the published inventory does not reference, because an interrupted run can leave one with other signature bytes. RPM and Arch package signatures are not deterministic.

After `haberdasher.json`, a run writes the format's `index.html`. See [Repository pages](#repository-pages).

There is no multi-object atomicity. Split entry/signature pairs can temporarily fail client verification. The publisher retains older referenced objects and performs no deletion or retention change.

## Repository pages

Each bucket serves one `index.html` with `Cache-Control: public, max-age=300`. `src/haberdasher/site.py` builds it from the bucket's `haberdasher.json`, with no per-project settings. The page shows, in order:

1. The repository name, links to the eight repository sites, a "Works with" row of distribution logos, and an unofficial-repository notice.
2. For the signed formats (APT, RPM, Arch, Alpine, Flatpak, and Nix), the full signing key fingerprint and one command that prints it. The Homebrew and Scoop pages have no signing-key step, because those repositories are not signed. Their trust comes from HTTPS, the `sha256` in each cask, and the `hash` in each manifest.
3. The common setup steps for the format. The RPM page has DNF and zypper steps.
4. One section for each source repository: its name, the package description, a GitHub link, the packages and architectures of its newest published release, and the install command.
5. The commands that remove the repository.
6. The published files as nested disclosures, each linked with its size. Flatpak `objects/`, Homebrew `tap.git/`, Scoop `wimpysworld/`, and Nix `packages.git/` and `nar/` each fold onto one summary line with a file count and a total size.
7. The date of the last page write.

The description comes from package metadata: DEB `Description`, RPM `Summary`, Arch `%DESC%`, APK `T:`, and release descriptions for Homebrew, Scoop, and Nix. Flatpak inspection stores the untranslated AppStream `summary` in the inventory. A source without a description in one format uses its description from another format in the same run, for example Sidra in Flatpak.

Each page loads one µCSS theme and its fonts from pinned jsDelivr URLs with SRI hashes, and distribution logos from pinned `simple-icons` URLs. Browsers do not check SRI for images or for font files that a stylesheet loads. A few lines of inline JavaScript show a copy button beside each command. Without JavaScript, the commands stay selectable.

The page embeds a content hash of everything except the date, in `<meta name="haberdasher-content">`. A run writes the page only when it is missing or that hash differs, so an unchanged rerun writes no page. The setup commands share their repository definitions with the native client tests through `apt_sources`, `rpm_repo`, and `pacman_repo` in `src/haberdasher/site.py`.

## Locks

Before it writes, `just publish` creates `haberdasher.lock` in each bucket of the publication scope, in sorted format order, with a conditional create. The lock holds a random run identifier, the host name or GitHub runner and run URL, and the UTC start time. It never appears in `haberdasher.json`. A local test root holds the same file in each format directory.

When a lock already exists, the run deletes the locks that it created and fails. The error names the bucket and shows the existing lock. At the end of a run, and after a handled error, the run deletes only its own locks, conditionally on the ETags that it created.

A run that stops without cleanup, for example after a killed process, leaves its locks. When you know that the run has stopped, delete them explicitly:

```sh
just unlock
```

`just unlock` deletes the existing locks in all eight buckets and exits without publishing. It prints one line for each bucket:

```text
apk   no lock
apt   removed lock from builder started 2026-11-09T10:00:00+00:00
```

## Recovery

Recover from an interrupted run with a full rerun of `just publish`. The rerun reads the last complete `haberdasher.json`, prepares and signs again, overwrites leftover unreferenced objects, and publishes new metadata. There is no write journal or crash-recovery state.

An interrupted run can stop after it replaced some entry metadata and before it wrote `haberdasher.json`. Under the bucket lock, only that run can have changed those entries. The rerun accepts each entry whose bytes differ from the inventory, rebuilds it from the accepted history and the new packages, and replaces it on its current ETag. Changed bytes for a published package identity still stop the run. The rerun finds the changed entries only when it prepares that format, so the assets of the interrupted run must still be in the latest releases.

An unknown write outcome stops the run. Delete a stale lock with `just unlock` first when the run could not release it.

See `src/haberdasher/{cli,state,publish,storage}.py` and `tests/unit/test_publish.py` for the exact behaviour.
