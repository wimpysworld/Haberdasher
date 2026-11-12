# Validation

This page is the status page. It lists the local checks, the production checks still to do, and the checks done. Other docs describe design and behaviour only.

## Reproduce locally

Use an ordinary user on `x86_64-linux`:

```sh
nix develop --no-write-lock-file
just setup
just check-tools
just build
just test
just lint
just proof
```

Setup checks `uv.lock` and synchronises the root `.venv` without Python downloads. Build creates the Python wheel and source archive. Test runs unit tests and the shell tests of the Just tool and proof routing scripts. Lint checks Python formatting, Ruff, strict BasedPyright, dependency audit, shell scripts, workflows, and Nix formatting. Dependency audit can contact its advisory service.

`just proof` clears inherited credentials and runs the native suite with private HOME and TMPDIR. Tests create disposable keys, roots, packages, and loopback servers. They make no production credential reads, cloud writes, host installs, or application launches.

The path-based flake includes current files without Git staging:

```sh
nix flake check "path:$PWD" --no-write-lock-file
nix flake check "path:$PWD" --no-write-lock-file --no-build --all-systems
```

The first command builds the current system's checks. The second evaluates all declared systems. Evaluation does not prove runtime support. Only `x86_64-linux` has native runtime acceptance. ARM Linux and Darwin are evaluation-only. The proof router rejects other systems.

## Evidence map

| Boundary | Executable evidence | What it establishes |
| --- | --- | --- |
| CLI and configuration | `tests/unit/test_cli.py`, `test_config.py` | Three commands without options, read-only planning, a `sources` list as the only key, early rejection of missing credentials |
| Discovery and admission | `tests/unit/test_discovery.py`, `tests/native/test_pipeline.py` | Only the GitHub "Latest" release is read, a source without one, no backfill of older releases, late assets, packages without a checksum, cosign bundles, native identity conflicts, no-op behaviour |
| Locked publication | `tests/unit/test_publish.py`, `test_storage.py` | Bucket locks, `unlock`, conditional writes and deletes, unchanged reruns, late assets, a new latest release that keeps the published version, unsupported assets skipped with one line, interruptions before and after an entry write followed by a full rerun |
| Hosted workflow | `tests/unit/test_publish_workflow.py` | Workflow gates, step inputs, and the exact publish command, with a synthetic `nix` |
| Storage clients | `tests/native/test_storage_clients.py` | Native transport against local protocol fixtures, not real R2 permissions |
| Native adapters | `tests/native/test_{apt,rpm,arch,apk,flatpak,brew,scoop,nix}.py` | Retained state, install/update, rejection cases, signed upstream packages, local HTTP acquisition |
| Served trust | `tests/native/test_pipeline.py` | Fetched public keys, full independent fixture fingerprint, fresh and existing strict clients |
| Repository pages | `tests/unit/test_site.py`, `test_publish.py`, `tests/native/test_pipeline.py` | Escaping, the file tree with the Flatpak `objects/` line, install sections, the content hash, the plan line, an `index.html` with pinned theme assets in each bucket, and no page write on an unchanged rerun |

The pipeline runs the real CLI with recorded GitHub responses, real native adapters, durable local storage, and loopback HTTP clients. It checks unchanged runs, which write only their locks, and assets added to the latest release. For each format, interruptions before the first entry write and after each entry write, and interruptions during bootstrap key writes, each converge with a full rerun to signed metadata that native clients install with signature checks on. A further rerun writes only its locks.

See [the proof index](proofs/README.md) for the native tests of each format.

## Safe example checks

`python -m haberdasher --help` needs no token or key. Parse the README source example with `load_config` from `src/haberdasher/config.py`.

Run `tests/native/test_pipeline.py` for served-key trust without production URLs or credentials. APT deb822 templates must keep the same scoped key, suite, component, and architecture as the tested client.

## CI boundary

`.github/workflows/check.yml` uses pinned checkout and Determinate Nix actions. It runs the same Just setup, build, test, lint, and proof path. Permissions are `contents: read`, with no persisted checkout credentials.

`.github/workflows/publish.yml` has only `workflow_dispatch`. The job requires `HD_PUBLISH_ENABLED == 'true'`, the default branch, and the `publisher` environment. Concurrency does not replace the bucket locks. There is no scheduled trigger.

The workflow passes `github.token` as `GH_TOKEN` with `contents: read`. Storage variables and `HD_SIGNING_KEY` come from secrets. These inputs stay scoped to the publish step.

The publish step runs `just publish`. It reads sources from the committed `haberdasher.yaml`. Buckets are in code. No secret holds publisher configuration.

## Production checks

Keep `HD_PUBLISH_ENABLED` unset until every check in this list is done, except while you test hosted execution. Unset it again after that test. Use publisher credentials for the R2 checks, not the administration token. A read-only credential check does not prove write or CI permissions.

To do:

- [ ] Real R2: test lock conflicts, conditional replace and delete, and exact ETags against disposable buckets.
- [ ] Hosted execution: set the CI secrets, `HD_PUBLISH_ENABLED`, and the `publisher` environment protection, then test hosted permissions.
- [ ] Public delivery: test HTTPS, content types, cache headers, delayed clients, and split entry/signature reads on the live domains.
- [ ] Distribution clients: test official images for each format, including `arm64` APT and `aarch64` packages, separately from the pinned Nix clients.
- [ ] Repository pages: test the page commands on official images. The `zypper` steps are untested, because nixpkgs has no `zypper`. The Arch `pacman-key --add` and `--lsign-key` steps and the RPM `rpm -e gpg-pubkey-87db88e0` step were checked only in disposable directories.
- [ ] Repository pages: after the first page publication, check that `/` serves `index.html` with `text/html` and `max-age=300` on each domain.

Done:

- [x] Real R2 publication with publisher credentials: conditional lock writes, lock release, and parallel `rclone` uploads with size and MD5 checks.
- [x] Real R2 recovery after a network interruption during upload: the first full publish on 2026-11-09 completed after a router restart stalled the APT upload for about 3 minutes.
- [x] Live installs with signature checks on, using the pinned Nix clients in private roots: Tailor 0.6.0 with APT, DNF5, pacman, and apk on x86_64, with `tailor --version` from each; arm64 and aarch64 packages downloaded and verified for every format; Sidra 1.3.0 from its `.flatpakref`, with the runtime from Flathub. Served packages match the upstream assets byte for byte, except where Haberdasher signs them.
- [x] Production signing: `just publish` matched the production key to `PRODUCTION_FINGERPRINT` and signed all five formats.
- [x] Real inputs: the latest Tailor and Sidra releases published to all five repositories.
- [x] Live APT metadata: `dists/stable/InRelease` has a `Date` and no `Valid-Until`, and the APT inventory has no expiry.
- [x] Domain activation: each custom domain is attached to its bucket, with SSL and ownership `active` and `r2.dev` access off.
- [x] Native signature checks on pinned Nix clients for all five formats, over loopback HTTP.
- [x] Latest-release discovery, checksum verification, and cosign verification against recorded GitHub responses.
- [x] Bucket locks, `just unlock`, and a full rerun after an interruption before or after any entry write, on local storage.
- [x] Unchanged reruns that write only locks, and assets added to the latest release.
- [x] Signed upstream RPM, Arch, APK, and Flatpak inputs that Haberdasher publishes with its own signature.
- [x] Flatpak runs that download only the working set.
- [x] Publish workflow gates and step inputs, with a synthetic `nix`.
- [x] Repository pages rendered in headless Chromium from the live inventories, at 390 and 1280 pixels wide, in light and dark mode: SRI loads without errors, no horizontal page scroll, WCAG AA contrast on measured text, keyboard focus on links and copy buttons, and commands without JavaScript.
