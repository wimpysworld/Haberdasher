# Haberdasher

Haberdasher publishes prebuilt packages from the GitHub releases of the owner's projects into signed Linux package repositories. It is not a package builder or a general-purpose product.

## Purpose and principles

- Haberdasher is by Martin, for Martin, and publishes his own packages.
  The source is public so that others can learn from it. It is not a product for other users.
- Every source is a GitHub project under the owner's control, in `wimpysworld` or another organisation.
  Treat release assets as trusted inputs. Checksum and signature checks catch corruption and mistakes. They do not judge trust.
- Choose the simplest solution that does the job. This project is allergic to complexity.
- Expose the fewest options and parameters possible. Resolve values in code and do the right thing.
  Before you add a setting, flag, file, or check, find a way to derive the value or remove the need.
- When linked research or an earlier design conflicts with these principles, this file wins.

## Architecture notes

- Use Python for orchestration and native tools for package formats, cryptography, and client verification.
- Do not introduce an automatic Go migration or a plugin framework.
- Consume upstream `.deb`, `.rpm`, `.apk`, `.pkg.tar.zst`, `.pkg.tar.xz`, and `.flatpak` assets from tools such as GoReleaser and electron-builder.
- Reuse native indexing and signing tools, not handwritten package-format encoders.
- WW-370 and WW-377 and their linked research are historical background only. This file overrides them.
- Verify implementation in repository files before documenting commands or claiming capabilities.

## Setup

- Preserve the Tailor-managed Nix flake, lock file, and Just structure.
- Use the justfile as the common command path for local work and continuous integration (CI).
- Use Determinate Nix for GitHub Actions.
- Run `just setup` before checks to prepare the locked Python environment.
- Require Python 3.14 or later and PyYAML `CSafeLoader` with LibYAML.
- Inspect existing recipes and tests before naming commands or claiming test coverage.

## Publishing invariants

- Use `just plan` for a read-only plan, without storage changes or signing.
- Use `just publish` to publish `haberdasher.yaml` to R2, and `just unlock` to delete stale locks.
  Keep these recipes free of arguments.
- Keep `haberdasher.yaml` to a list of GitHub repositories, for example `sources: [wimpysworld/tailor]`.
  Do not add per-project settings. Haberdasher must handle dozens of projects with different release layouts.
- Derive formats from asset types, and architectures from package metadata.
  Verify the cosign bundle of a checksum file when the release has one. Keep bucket names and public URLs in code.
- Do not add a separate policy file, or approval gates in code or configuration.
- Publish every format that the sources provide, plus formats already published, in one run.
- Verify each package against a release checksum file or its GitHub asset digest before import.
- Derive package identity from package metadata under each ecosystem's rules, not filenames or release tags alone.
- Name and place published packages by each ecosystem's standard layout, built from package metadata.
  For example, APT uses `pool/main/<prefix>/<source>/<name>_<version>_<arch>.deb`. Never name packages by digest.
- Reject changed upstream bytes for an existing package identity.
  Require a new package version or release identity under that ecosystem's rules.
  When Haberdasher changes package bytes, record the upstream digest separately from the published digest.
- Keep publication state in each bucket's public `haberdasher.json` inventory and published metadata.
  Do not add a private state bucket.
- Publish only the GitHub "Latest" release of each source, including assets added to it later.
  Keep every version already published. Do not backfill older releases.
- Reuse published metadata instead of downloading the entire historical package pool on each run.
- Serialise publishers with a `haberdasher.lock` object in each bucket that a run writes.
  Create each lock with a conditional write, in a fixed bucket order, and delete the locks when the run ends.
  Release a stale lock only with `just unlock`.
- Publish immutable packages and dependency metadata before each format's entry metadata.
- Upload packages and other content-addressed objects in parallel with one `rclone` run per content type and cache policy.
  Keep conditional single-object writes for locks, entry metadata, and `haberdasher.json`.
- Publish each format's allow-listed inventory after its entry metadata.
- Recover from an interrupted run with a full rerun.
  Do not add replay, write journals, or crash-recovery state.
- Do not claim atomicity across multiple objects.
- Keep older objects that published metadata still references.
  Ask the owner before you change deletion or retention behaviour.
- Distinguish repository metadata signing from package signing.
- Never reject a package because the upstream signed it.
  Remove or ignore upstream package signatures, and sign with the Haberdasher key where the format needs it.
- Keep native client signature checks enabled.
- Use SHA256 OpenPGP signatures across APT, RPM, Arch, and Flatpak.
- For APT (WW-371), sign `Release` as `InRelease` and `Release.gpg`, not `.deb` packages.
- For RPM (WW-372), sign packages with `rpmsign` before `createrepo_c`, then create detached armoured `repomd.xml.asc`.
- For Arch (WW-373), sign packages first. Sign database/files metadata with `repo-add --include-sigs --sign`.
- For Alpine v2 (WW-374), use explicit `abuild-sign -t RSA256`, not the SHA1 default.
  Match the `.rsa.pub` filename to signature members and client trust files.
  Preserve the bytes of unsigned upstream APKs.
- For Flatpak (WW-375), sign and verify both commits and summaries with GPG.

## Testing

- Use loopback `miniserve` for native HTTP tests with normal conditional and range request semantics.
  Do not bypass client caching or signature checks to make tests pass.
- Prove incremental handling, including unchanged runs and assets added to the latest release.
- Test checksum failures, identity conflicts, an interrupted run followed by a full rerun, and competing publishers.
- Verify native client installation and signature checks before claiming repository support.
  Treat signature compatibility tests as separate from end-to-end publication and installation tests.
- For Alpine, verify indexes and packages with native `apk verify`, then check actual resolver and fetched-package outputs.
  Neither `apk update` nor `apk fetch --recursive` exit `0` proves trust or successful resolution.
  Tampered metadata can remain searchable without an installable candidate.
  Do not infer unsigned-package acceptance from tests with signed packages.
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
  Never generate another key, and do not require a certificate authority or certificate service.
- Derive the Alpine PEM only in temporary private directories outside the checkout and Nix store, with directories at `0700` and files at `0600`.
  Clean up keyrings, agents, and exports even on failure. `src/haberdasher/signing.py` holds the conversion steps.
- Never put plaintext private keys in the repository, R2, or public manifests.
- Configure scoped public-key trust for each native client. Do not require personal keys, keyservers, or the public web of trust.
- Permit one public, non-secret `haberdasher.json` package inventory per bucket for package identity, source, published digests, referenced objects, and the publication state that the adapters need.
  Enforce the explicit public inventory allow-list. Never include secrets or local paths.
- Permit a temporary `haberdasher.lock` per bucket that holds only a run identifier, the publisher host or CI run URL, and the start time.
- Keep secrets and credentials out of these buckets.
- Read publisher credentials only from the runtime environment:
  `HD_CLOUDFLARE_S3_API_ENDPOINT`, `HD_CLOUDFLARE_ACCESS_KEY_ID`, and `HD_CLOUDFLARE_SECRET_ACCESS_KEY`.
  Local credentials use SOPS in `~/Zero/nix-config`. GitHub Secrets use the same variable names.
- Do not read or decrypt credential files into agent context.
- Never print, trace, globally export, or commit plaintext credentials, or put credentials in the Nix store.
- Do not use `HD_CLOUDFLARE_TOKEN_VALUE`.
- Test publisher permissions with publisher credentials, not the separate managed administration token.
