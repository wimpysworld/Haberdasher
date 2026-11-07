# Haberdasher

Haberdasher is Martin's personal tool for publishing prebuilt GitHub Release packages as signed Linux repositories on Cloudflare R2. Native package managers will handle installation and updates, including direct Arch packages without third-party Arch User Repository (AUR) build scripts.

## Status

The repository has Tailor development files, a Nix flake and lock file, and a justfile. Package collection, signing, publication, and automation are planned, not implemented.

Five R2 buckets exist with custom domains enabled. Domain activation is unverified. Local read-only requests succeeded for all buckets. Writes and access from GitHub Actions are untested. Client installation instructions are not ready.

| Format | Domain | R2 bucket |
| --- | --- | --- |
| `.deb` | `apt.wimpys.world` | `haberdasher-apt` |
| `.rpm` | `rpm.wimpys.world` | `haberdasher-rpm` |
| `.apk` | `apk.wimpys.world` | `haberdasher-apk` |
| `.pkg.tar.zst` | `pkg.wimpys.world` | `haberdasher-pkg` |
| `.flatpak` | `flatpak.wimpys.world` | `haberdasher-flatpak` |

## Planned flow

Upstream projects build packages with tools such as GoReleaser and electron-builder. Haberdasher will:

1. Reconcile releases from explicitly configured sources, not only their latest tags.
2. Verify assets against release SHA256 checksums and reject changed bytes under an existing package identity.
3. Preserve a durable manifest and metadata for each repository format.
4. Upload immutable package objects before entry metadata, with format-specific recovery and protection against concurrent local or CI writers.

Repository signatures establish publisher identity and integrity, not payload safety.

Shell scripts will use native repository tools where possible. The incremental metadata strategy still needs validation for each format. No Go rewrite or generic plugin framework is planned.

The Nix flake and lock file will pin tools through Tailor conventions. Local runs and a Determinate Nix GitHub runner will use the same justfile recipes. Triggers will include manual runs and scheduled reconciliation, with optional cross-repository dispatch after asset uploads.

## Credentials

The R2 environment interface is:

- `HD_CLOUDFLARE_S3_API_ENDPOINT`
- `HD_CLOUDFLARE_ACCESS_KEY_ID`
- `HD_CLOUDFLARE_SECRET_ACCESS_KEY`

Local SOPS configuration injects credentials at runtime. GitHub Secrets use the same names. Haberdasher will not decrypt secrets or require global credentials or `HD_CLOUDFLARE_TOKEN_VALUE`.
