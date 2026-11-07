# Haberdasher

Haberdasher is Martin's personal tool for publishing prebuilt GitHub Release packages as signed Linux repositories on Cloudflare R2. Native package managers will handle installation and updates, including direct Arch packages without third-party Arch User Repository (AUR) build scripts.

## Status

The pinned Nix environment supplies common development tools and Linux tools for all five planned repository formats. Package collection, signing, publication, and automation are not implemented.

Five R2 buckets exist with custom domains enabled. Domain activation is unverified. Local read-only requests succeeded for all buckets. Writes and access from GitHub Actions are untested. Client installation instructions are not ready.

| Format | Domain | R2 bucket |
| --- | --- | --- |
| `.deb` | `apt.wimpys.world` | `haberdasher-apt` |
| `.rpm` | `rpm.wimpys.world` | `haberdasher-rpm` |
| `.apk` | `apk.wimpys.world` | `haberdasher-apk` |
| `.pkg.tar.zst` | `pkg.wimpys.world` | `haberdasher-pkg` |
| `.flatpak` | `flatpak.wimpys.world` | `haberdasher-flatpak` |

## Development environment

Enter the pinned shell and check its tools:

```sh
nix develop
just check-tools
just lint
just test
```

`just check-tools` reports executable paths from the declared Nix packages, without using inherited host tools. It fails if a required executable is missing. It makes no network requests and does not create keys, configuration, or repositories. Nix can download packages when you enter the shell.

Common tools include Bash, GNU utilities, archive tools, jq, curl, OpenSSL, GnuPG, rclone, ShellCheck, shfmt, and nixfmt. The existing gh, just, and actionlint tools remain available.

Linux also supplies `apt-ftparchive`, `dpkg-deb`, `createrepo_c`, `modifyrepo_c`, `rpm`, `rpmsign`, `apk`, `abuild-sign`, `repo-add`, `repo-remove`, `flatpak`, and `ostree`.

The executable check, lint, and local tests passed on `x86_64-linux`. The `aarch64-linux` and `aarch64-darwin` shells passed evaluation only. Darwin supplies common development tools, not repository tools. Publishing requires Linux because the complete native tool set requires Linux. Tool availability does not prove signing or client installation.

`just test` checks platform selection and missing-tool failures without running package tools. `nix flake check` also checks the Nix package selection for each evaluated system.

## Planned flow

Upstream projects build packages with tools such as GoReleaser and electron-builder. Haberdasher will:

1. Reconcile releases from explicitly configured sources, not only their latest tags.
2. Verify assets against release SHA256 checksums and reject changed bytes under an existing package identity.
3. Preserve a durable manifest and metadata for each repository format.
4. Upload immutable package objects before entry metadata, with format-specific recovery and protection against concurrent local or CI writers.

Repository signatures establish publisher identity and integrity, not payload safety.

Shell scripts will use native repository tools where possible. The incremental metadata strategy still needs validation for each format. No Go rewrite or generic plugin framework is planned.

The Nix flake and lock file pin tools through Tailor conventions. Local runs use Just recipes. A future Determinate Nix GitHub runner will use the same recipes. Triggers will include manual runs and scheduled reconciliation, with optional cross-repository dispatch after asset uploads.

## Credentials

The R2 environment interface is:

- `HD_CLOUDFLARE_S3_API_ENDPOINT`
- `HD_CLOUDFLARE_ACCESS_KEY_ID`
- `HD_CLOUDFLARE_SECRET_ACCESS_KEY`

Local SOPS configuration injects credentials at runtime. GitHub Secrets use the same names. Haberdasher will not decrypt secrets or require global credentials or `HD_CLOUDFLARE_TOKEN_VALUE`.
