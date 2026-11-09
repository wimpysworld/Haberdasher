# Validation and activation

Local tests qualify the Python publisher and native adapters with synthetic inputs. They do not activate production services.

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

Setup checks `uv.lock` and synchronises the root `.venv` without Python downloads. Build creates the Python wheel and source archive. Test runs unit tests and shell routing/isolation tests. Lint checks Python formatting, Ruff, strict BasedPyright, dependency audit, shell scripts, workflows, and Nix formatting. Dependency audit can contact its advisory service.

`just proof` clears inherited credentials. It runs the five preserved shell proofs, then the native suite with private HOME and TMPDIR. Tests create disposable keys, roots, packages, and loopback servers. They make no production credential reads, cloud writes, host installs, or application launches.

The path-based flake includes current files without Git staging:

```sh
nix flake check "path:$PWD" --no-write-lock-file
nix flake check "path:$PWD" --no-write-lock-file --no-build --all-systems
```

The first command builds the current system's checks. The second evaluates all declared systems. Evaluation does not prove runtime support. Only `x86_64-linux` has native runtime acceptance. ARM Linux and Darwin remain evaluation-only. The proof router rejects unqualified systems.

## Evidence map

| Boundary | Executable evidence | What it establishes |
| --- | --- | --- |
| CLI and configuration | `tests/unit/test_cli.py`, `test_config.py` | Subcommands without options, read-only planning, strict policy, early destination rejection |
| Discovery and admission | `tests/unit/`, `tests/native/test_pipeline.py` | Release reconciliation, late assets, pending checksums, native identity conflicts, no-op behaviour |
| Locked publication | `tests/unit/test_publish.py`, `test_storage.py` | Bucket locks, `unlock`, conditional writes and deletes, unchanged reruns, late assets, an interrupted run followed by a full rerun |
| Hosted policy input | `tests/unit/test_publish_workflow.py` | Synthetic workflow execution, exact policy bytes, private permissions, empty-input rejection, cleanup on success, failure, and signals |
| Storage clients | `tests/native/test_storage_clients.py` | Native transport against local protocol fixtures, not real R2 permissions |
| Native adapters | `tests/native/test_{apt,rpm,arch,apk,flatpak}.py` | Retained state, install/update, rejection cases, local HTTP acquisition |
| Served trust | `tests/native/test_pipeline.py` | Fetched public keys, full independent fixture fingerprint, fresh and existing strict clients |
| Historical proofs | `tests/proofs/` | Independent shell approaches and their original format boundaries |

The pipeline runs the real CLI with recorded GitHub responses, real native adapters, durable local storage, and loopback HTTP clients. It checks unchanged runs, which write only their locks, and assets added to an existing release. An interruption before entry metadata, and interruptions during bootstrap key writes, each converge with a full rerun to signed metadata that native clients install.

See [the proof index](proofs/README.md) for preserved shell evidence. Do not substitute those scripts for production adapter acceptance.

## Safe example checks

`python -m haberdasher --help` needs no token or key. Parse the README source example with `load_config` and the publisher policy example with `load_policy` from `src/haberdasher/config.py`.

Run `tests/native/test_pipeline.py` for served-key trust without production URLs or credentials. APT deb822 templates must retain the same scoped key, suite, component, and architecture as the tested client.

## CI boundary

`.github/workflows/check.yml` uses pinned checkout and Determinate Nix actions. It runs the same Just setup, build, test, lint, and proof path. Permissions are `contents: read`, with no persisted checkout credentials.

`.github/workflows/publish.yml` has only `workflow_dispatch`. The job requires `HD_PUBLISH_ENABLED == 'true'`, the default branch, and the `publisher` environment. Concurrency does not replace the bucket locks. There is no scheduled trigger.

The workflow passes `github.token` as `GH_TOKEN` with `contents: read`. Storage variables and `HD_SIGNING_KEY` come from secrets. These inputs stay scoped to the publish step.

The publish step runs `just publish`. It reads buckets and formats from the committed `haberdasher.yaml`. No secret holds publisher configuration.

This change does not provision secrets, change environment protection, or enable `HD_PUBLISH_ENABLED`. Keep publication disabled until the activation checks below pass. Workflow configuration alone does not prove hosted access.

## Remaining activation checks

| Check | Required action before activation |
| --- | --- |
| Real R2 | Test publisher credentials, conditional create/replace/delete, exact ETags, lock conflicts, and a full rerun after an interruption against disposable destinations |
| Production signing | Use the existing production identity and verify its full fingerprint without exposing private bytes |
| Hosted execution | Configure CI secrets, default-branch policy, environment protection, and hosted permissions |
| Public delivery | Qualify custom-domain HTTPS, content types, cache headers, delayed clients, and split entry/signature recovery |
| APK | Accept native v2 SHA1 control identity and test declared real inputs/client compatibility |
| Flatpak | Configure source owner, application refs, runtime origin, extensions, and empty collection in `haberdasher.yaml` |
| Distribution clients | Test declared official distribution images and architectures separately from pinned Nix clients |

Already-signed RPMs and signed upstream Flatpak bundles remain rejected. Flatpak source/runtime configuration is not yet in `haberdasher.yaml`, and there is no automatic source addition. No activation test above ran as part of the local acceptance path.

Obtain explicit approval before production credentials, key use, public actions, or external permission tests. No deletion or retention change forms part of activation.
