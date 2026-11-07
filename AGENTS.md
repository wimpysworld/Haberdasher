# Haberdasher

Haberdasher is a personal-use publisher for prebuilt GitHub release assets from `wimpysworld`, not a package builder or general-purpose product.

## Architecture notes

- Keep implementation shell-first.
- Do not introduce an automatic Go migration or a plugin framework.
- Consume upstream `.deb`, `.rpm`, `.apk`, `.pkg.tar.zst`, and `.flatpak` assets from tools such as GoReleaser and electron-builder.
- Reuse native indexing and signing tools, not handwritten package-format encoders.
- Use WW-370 for the repository proof scope and its linked research for design background.
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
- Use SHA256 OpenPGP signatures across APT, RPM, Arch, and Flatpak.
- For APT (WW-371), sign `Release` as `InRelease` and `Release.gpg`, not `.deb` packages.
- For RPM (WW-372), sign packages with `rpmsign` before `createrepo_c`, then create detached armoured `repomd.xml.asc`.
  Record source digests separately from signed published digests.
- For Arch (WW-373), sign packages first. Sign database/files metadata with `repo-add --include-sigs --sign`.
- For Alpine v2 (WW-374), use explicit `abuild-sign -t RSA256`, not the SHA1 default.
  Match the `.rsa.pub` filename to signature members and client trust files.
- For Flatpak (WW-375), sign and verify both commits and summaries with GPG.

## Testing

- Prove incremental handling, including unchanged releases and assets added to existing releases.
- Test checksum failures, identity conflicts, interrupted publication, recovery, and competing local and CI publishers.
- Verify native client installation and signature checks before claiming repository support.
  Treat signature compatibility tests as separate from end-to-end publication and installation tests.
- For Alpine, verify indexes and packages with native `apk verify`, then check actual resolver and fetched-package outputs.
  Neither `apk update` nor `apk fetch --recursive` exit `0` proves trust or successful resolution.
  Tampered metadata can remain searchable without an installable candidate.
  Preserve upstream APK bytes. Do not infer unsigned-package acceptance from tests with signed packages.
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

- Use one dedicated Haberdasher RSA4096 private primary with signing and certification capabilities, without subkeys or per-format keypairs.
  Sign directly with that primary for APT, RPM, Arch, and Flatpak. Convert the same RSA private numbers to PKCS#8 PEM for Alpine.
- Keep one canonical private OpenPGP export in local SOPS and GitHub Secrets. An offline backup copies the same key.
  Generate a production key only with explicit approval.
- Derive PEM only in temporary private directories outside the checkout and Nix store. Set directories to `0700` and files to `0600`.
  Clean up keyrings, agents, and exports even on failure. Never put plaintext private keys in the repository, R2, or public manifests.
- Select the existing key with `Key-Grip` when `gpgsm` creates the conversion-only self-signed X.509 certificate.
  Import that certificate, then export the same key with `--armor --export-secret-key-p8`.
  Do not generate another key or require an external certificate authority or certificate service.
- Configure scoped public-key trust for each native client. Do not require personal keys, keyservers, or the public web of trust.
- Permit one public, non-secret `haberdasher.json` package inventory per bucket for package identity, source, published digests, and referenced objects.
- Keep secrets, credentials, private provenance, locks, pending journals, and other private control state out of these buckets.
- Read publisher credentials only from the runtime environment:
  `HD_CLOUDFLARE_S3_API_ENDPOINT`, `HD_CLOUDFLARE_ACCESS_KEY_ID`, and `HD_CLOUDFLARE_SECRET_ACCESS_KEY`.
  Local credentials use SOPS in `~/Zero/nix-config`. GitHub Secrets use the same variable names.
- Do not read or decrypt credential files into agent context.
- Never print, trace, globally export, or commit plaintext credentials, or put credentials in the Nix store.
- Do not use `HD_CLOUDFLARE_TOKEN_VALUE`.
- Test publisher permissions with publisher credentials, not the separate managed administration token.
