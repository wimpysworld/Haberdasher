# Haberdasher

Haberdasher is a personal-use publisher for prebuilt GitHub release assets from `wimpysworld`, not a package builder or general-purpose product.

## Architecture notes

- Keep implementation shell-first.
- Do not introduce an automatic Go migration or a plugin framework.
- Consume upstream `.deb`, `.rpm`, `.apk`, `.pkg.tar.zst`, and `.flatpak` assets from tools such as GoReleaser and electron-builder.
- Reuse native indexing and signing tools, not handwritten package-format encoders.
- Treat `docs/HANDOVER.md` as design background, not current implementation evidence.
  Its latest-tag state model and workflow-only serialisation are insufficient.
- Verify implementation in repository files before documenting commands or claiming capabilities.

## Setup

- Preserve the Tailor-managed Nix flake, lock file, and Just structure.
- Use the justfile as the common command path for local work and continuous integration (CI).
- Use Determinate Nix for GitHub Actions.
- Inspect existing recipes and tests before naming commands or claiming test coverage.

## Publishing invariants

- Verify release checksums before importing packages.
- Derive package identity from package metadata under each ecosystem's rules, not filenames or release tags alone.
- Reject changed bytes for an existing package identity.
  Require a new package version or release identity under that ecosystem's rules.
- Maintain a durable per-asset manifest and per-format metadata state.
- Reconcile configured releases and assets beyond a latest-tag map.
- Reuse stored metadata instead of downloading the entire historical package pool on each run.
- Serialise publishers across local runs and CI.
  GitHub Actions workflow concurrency alone is insufficient.
- Publish immutable packages and dependency metadata before each format's entry metadata.
- Record completion only after successful publication.
- Do not claim atomicity across multiple objects.
- Retain older objects that published metadata still references.
- Obtain approval before changing deletion or retention behaviour.
- Distinguish repository metadata signing from package signing.
- Keep native client signature checks enabled.

## Testing

- Prove incremental handling, including unchanged releases and assets added to existing releases.
- Test checksum failures, identity conflicts, interrupted publication, recovery, and competing local and CI publishers.
- Verify native client installation and signature checks before claiming repository support.
- Verify domain activation separately from bucket provisioning.
- Do not infer write or CI permissions from a successful local read-only credential check.

## Security and secrets

Treat the five package buckets as public:

| Domain | Bucket |
| --- | --- |
| `apt.wimpys.world` | `haberdasher-apt` |
| `rpm.wimpys.world` | `haberdasher-rpm` |
| `apk.wimpys.world` | `haberdasher-apk` |
| `pkg.wimpys.world` | `haberdasher-pkg` |
| `flatpak.wimpys.world` | `haberdasher-flatpak` |

- Keep secrets and control state out of these buckets.
- Read publisher credentials only from the runtime environment:
  `HD_CLOUDFLARE_S3_API_ENDPOINT`, `HD_CLOUDFLARE_ACCESS_KEY_ID`, and `HD_CLOUDFLARE_SECRET_ACCESS_KEY`.
  Local credentials use SOPS in `~/Zero/nix-config`. GitHub Secrets use the same variable names.
- Do not read or decrypt credential files into agent context.
- Never print, trace, globally export, or commit plaintext credentials, or put credentials in the Nix store.
- Do not use `HD_CLOUDFLARE_TOKEN_VALUE`.
- Test publisher permissions with publisher credentials, not the separate managed administration token.
