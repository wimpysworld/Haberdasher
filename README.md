# Haberdasher

Haberdasher publishes prebuilt GitHub release packages as signed Linux repositories on Cloudflare R2. It is Martin's personal publisher, not a package builder.

> [!IMPORTANT]
> The publisher passes isolated local tests. Production publication is not activated. Public domains and production client setup remain unqualified.

## Quick start

Use the Tailor-managed flake and locked Python environment:

```sh
nix develop --no-write-lock-file
just setup
just check-tools
just build
just test
just lint
```

`just setup` creates the root `.venv` from `uv.lock`. Haberdasher requires Python 3.14 or later and PyYAML 6.0.3 with LibYAML `CSafeLoader`. There is no pure-Python YAML fallback.

On `x86_64-linux`, run native acceptance separately:

```sh
just proof
just proof apt
```

`just proof` runs all five preserved shell proofs and the production adapter tests. A named format runs its shell proof and native tests. Native runtime qualification is `x86_64-linux` only. `aarch64-linux` and `aarch64-darwin` pass evaluation only. Darwin supplies common development tools, not the Linux repository tools.

## Plan and publish

`haberdasher.yaml` selects GitHub sources and optional format settings:

```yaml
sources:
  - wimpysworld/tailor
formats:
  apt:
    architectures: [amd64, arm64]
    suite: stable
    component: main
    validity_seconds: 604800
    renewal_seconds: 172800
```

Three recipes run Haberdasher. None takes arguments, and each reads `haberdasher.yaml` in the working directory:

```sh
just plan
just publish
just unlock
```

`just plan` checks each release, reads the published state from each public repository, and prints a table of published and new packages. It writes nothing and signs nothing. `just publish` publishes every configured format to its R2 bucket. `just unlock` deletes stale locks after a stopped run.

Planning reads GitHub and checksum assets. Supply `GH_TOKEN` or `GITHUB_TOKEN` through the runtime environment. The isolated GitHub configuration does not use a stored personal `gh` login.

Each command prints plain progress lines and a short summary, for example:

```text
Format  Repository        Published  New
apt     apt.wimpys.world          0   18
rpm     rpm.wimpys.world          0   18
arch    pkg.wimpys.world          0   18
apk     apk.wimpys.world          0   18

72 new packages. Nothing written. Run `just publish` to publish them.
```

Read the [publisher guide](docs/publisher.md) before you run `just publish` or `just unlock`.

> [!WARNING]
> All configured public formats form one publication. A partial update of shared state is not supported.

## Architecture

A small Python coordinator handles discovery, admission, bucket locks, and conditional storage. Native tools inspect, index, sign, and verify packages. There is no plugin framework or Go migration.

Haberdasher reconciles releases and late assets, verifies release SHA256 checksums, and derives identity from native metadata. It rejects changed bytes under an accepted identity. Retained native state avoids routine downloads of the historical package pool.

Each bucket's public `haberdasher.json` holds the publication state. A run locks each bucket that it writes. Public keys and packages precede native entries. Each format's inventory follows its entries. A full rerun recovers an interrupted run. Publication is not atomic across objects. Older referenced objects remain available, without deletion or retention changes.

## Repositories and setup

| Format | Intended domain | Public R2 bucket |
| --- | --- | --- |
| APT `.deb` | `apt.wimpys.world` | `haberdasher-apt` |
| RPM `.rpm` | `rpm.wimpys.world` | `haberdasher-rpm` |
| Arch `.pkg.tar.zst` | `pkg.wimpys.world` | `haberdasher-pkg` |
| Alpine `.apk` | `apk.wimpys.world` | `haberdasher-apk` |
| Flatpak `.flatpak` | `flatpak.wimpys.world` | `haberdasher-flatpak` |

Bucket provisioning and earlier read-only access do not prove publication permissions or domain readiness. [Client setup](docs/clients.md) contains post-activation templates, not a claim that these URLs are ready. No separate public website is implemented.

Every configured public role receives `keys/haberdasher.asc` and `keys/haberdasher.gpg`. APK also receives `keys/haberdasher.rsa.pub` with its first native index. Repository signatures prove publisher identity and integrity, not payload safety.

## Credentials and activation

The storage interface remains:

- `HD_CLOUDFLARE_S3_API_ENDPOINT`
- `HD_CLOUDFLARE_ACCESS_KEY_ID`
- `HD_CLOUDFLARE_SECRET_ACCESS_KEY`

Local SOPS configuration supplies credentials at runtime. GitHub Secrets use the same names. Local signing uses `HD_SIGNING_KEY_FILE`. CI signing uses `HD_SIGNING_KEY`. Do not commit credentials or private keys. Haberdasher does not decrypt credential files or use `HD_CLOUDFLARE_TOKEN_VALUE`.

The manual publish workflow remains disabled unless `HD_PUBLISH_ENABLED` is `true`. It also requires the default branch and the `publisher` environment. There is no schedule. [Validation and activation](docs/validation.md) separates local evidence from remaining production checks.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Use the pinned Just commands for changes. See the [proof guides](docs/proofs/README.md) for format-specific evidence and limits.
