# Haberdasher

Haberdasher is Martin Wimpress's personal publisher. It takes the prebuilt packages from the GitHub "Latest" release of each listed repository that Martin controls and publishes them as signed APT, RPM, Arch, Alpine, Flatpak, and Nix repositories, plus a Homebrew tap and a Scoop bucket, on Cloudflare R2. It is not a package builder.

## Use

`haberdasher.yaml` is a list of GitHub repositories and nothing else. To publish a new project, add its line:

```yaml
sources: [wimpysworld/tailor, wimpysworld/sidra]
```

Three recipes run Haberdasher. None takes arguments, and each reads `haberdasher.yaml` in the working directory:

| Recipe | Action |
| --- | --- |
| `just plan` | Reads the release and the published state, then prints a table of published and new packages. It writes nothing and signs nothing. |
| `just publish` | Publishes every format that the sources provide or that is already published. |
| `just unlock` | Deletes stale locks after a stopped run. |

Read the [publisher guide](docs/publisher.md) before you run `just publish` or `just unlock`.

> [!WARNING]
> All configured formats form one publication. A partial update of shared state is not supported.

## How it works

Haberdasher derives everything else from the release assets:

- The asset suffix selects the format.
- The package metadata gives the architecture and the package identity.
- A checksum file or the GitHub asset digest verifies each package before import. A cosign bundle is verified when the release has one.
- One Haberdasher key signs the repository metadata.

Each run publishes the latest release of each source, including assets that are added to it later. It keeps every version that is already published and does not backfill older releases. It rejects changed bytes for an existing package identity. Stored metadata avoids a download of the whole package pool.

Each bucket holds a public `haberdasher.json` inventory of the packages in it. A run takes a lock in each bucket that it writes. It publishes packages and dependency metadata before the entry metadata of each format. Publication is not atomic across objects. A full rerun recovers an interrupted run. See the [publisher guide](docs/publisher.md#publication-and-state) for detail.

## Repositories

| Format | Domain | Bucket |
| --- | --- | --- |
| APT `.deb` | `apt.wimpys.world` | `haberdasher-apt` |
| RPM `.rpm` | `rpm.wimpys.world` | `haberdasher-rpm` |
| Arch `.pkg.tar.zst` | `pkg.wimpys.world` | `haberdasher-pkg` |
| Alpine `.apk` | `apk.wimpys.world` | `haberdasher-apk` |
| Flatpak `.flatpak` | `flatpak.wimpys.world` | `haberdasher-flatpak` |
| Homebrew | `brew.wimpys.world` | `haberdasher-brew` |
| Scoop | `scoop.wimpys.world` | `haberdasher-scoop` |
| Nix | `nix.wimpys.world` | `haberdasher-nix` |

The Homebrew tap and the Scoop bucket are not signed. They rely on HTTPS and on the `sha256` in each cask or the `hash` in each manifest. Nix signs binary cache `.narinfo` metadata with a deterministic `nix.wimpys.world-1` Ed25519 key derived from the Haberdasher RSA4096 primary key.

[Client setup](docs/clients.md) shows how to trust the key and add each repository.

## Credentials and signing keys

Haberdasher reads credentials only from the runtime environment:

- `HD_CLOUDFLARE_S3_API_ENDPOINT`
- `HD_CLOUDFLARE_ACCESS_KEY_ID`
- `HD_CLOUDFLARE_SECRET_ACCESS_KEY`
- `HD_SIGNING_KEY_FILE` for the signing key on a local run
- `HD_SIGNING_KEY` for the signing key in CI

Local runs take the Cloudflare values from SOPS. GitHub Secrets use the same names. When `GH_TOKEN` and `GITHUB_TOKEN` are unset, Haberdasher reads the token of the stored `gh` login with `gh auth token`.

One RSA4096 key signs every format. Never commit a credential or a private key.

The [publish workflow](.github/workflows/publish.yml) is a manual run with no schedule. It runs when the repository variable `HD_PUBLISH_ENABLED` is `true`, the ref is the default branch, and the `publisher` environment allows it. One concurrency group serialises its runs.

## Development

Enter the Nix shell, set up the locked Python environment, and run the checks:

```sh
nix develop --no-write-lock-file
just setup
just check-tools
just build
just test
just lint
```

Haberdasher needs Python 3.14 or later and PyYAML with the LibYAML `CSafeLoader`.

`just proof` runs the native test suite against disposable keys and loopback servers. `just proof apt` runs the native tests for one format. The tests need an `x86_64-linux` Nix shell.

- [Validation](docs/validation.md): checks and evidence
- [Proof guides](docs/proofs/README.md): evidence for each format

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Use the Just recipes for changes.
