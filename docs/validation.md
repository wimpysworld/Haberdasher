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
| CLI and configuration | `tests/unit/test_cli.py`, `test_config.py` | Default planning, strict policy, explicit destinations, early format-selection rejection |
| Discovery and admission | `tests/unit/`, `tests/native/test_pipeline.py` | Release reconciliation, late assets, pending checksums, native identity conflicts, no-op behaviour |
| Durable publication | `tests/unit/test_state.py`, `test_publish.py`, `test_recovery.py` | Conditional writes, exclusion, fault injection, exact frozen replay, private completion |
| Hosted policy input | `tests/unit/test_publish_workflow.py` | Synthetic workflow execution, exact policy bytes, private permissions, empty-input rejection, cleanup on success, failure, and signals |
| Storage clients | `tests/native/test_storage_clients.py` | Native transport against local protocol fixtures, not real R2 permissions |
| Native adapters | `tests/native/test_{apt,rpm,arch,apk,flatpak}.py` | Retained state, install/update, rejection cases, local HTTP acquisition |
| Served trust | `tests/native/test_pipeline.py` | Fetched public keys, full independent fixture fingerprint, fresh and existing strict clients |
| Historical proofs | `tests/proofs/` | Independent shell approaches and their original format boundaries |

The pipeline runs the real CLI with recorded GitHub responses, real native adapters, durable local storage, and loopback HTTP clients. It checks unchanged runs and assets added to an existing release. Recovery removes source packages and signing access, then uses exact frozen bytes. Bootstrap interruptions check key-before-entry ordering and acknowledgement recovery.

See [the proof index](proofs/README.md) for preserved shell evidence. Do not substitute those scripts for production adapter acceptance.

## Safe example checks

`just publish --help` needs no token or key. Parse the README source example with `load_config` and the publisher policy example with `load_policy` from `src/haberdasher/config.py`.

Decode the recovery example with `state.parse` and `state.decode_record(state.RecoveryEvidence, ...)`. Schema validity proves no operator assertion. Never use sample evidence to unlock a real owner.

Run `tests/native/test_pipeline.py` for served-key trust without production URLs or credentials. APT deb822 templates must retain the same scoped key, suite, component, and architecture as the tested client.

## CI boundary

`.github/workflows/check.yml` uses pinned checkout and Determinate Nix actions. It runs the same Just setup, build, test, lint, and proof path. Permissions are `contents: read`, with no persisted checkout credentials.

`.github/workflows/publish.yml` has only `workflow_dispatch`. The job requires `HD_PUBLISH_ENABLED == 'true'`, the default branch, and the `publisher` environment. Concurrency does not replace durable publisher ownership. There is no scheduled trigger.

The workflow passes `github.token` as `GH_TOKEN` with `contents: read`. Storage variables and `HD_SIGNING_KEY` come from secrets. These inputs stay scoped to the publish step.

Before activation, configure the protected `publisher` environment with the secret `HD_PUBLISH_POLICY`. Set its value to the complete, approved YAML publisher policy, using the [publisher policy example](publisher.md#configuration) as the schema reference. Do not put credentials or private signing keys in the policy. Keep those values in their existing dedicated secrets. Policy approvals require an operator decision, not a copy of sample approvals.

The publish step rejects an empty `HD_PUBLISH_POLICY` before publication. It writes the exact bytes without logging them to a mode `0600` temporary file under `/tmp`, outside the checkout and Nix store. It uses `umask 077` and passes the private path through `--policy-file`. Exit and `HUP`, `INT`, and `TERM` traps remove the file after success, failure, or interruption. The step removes `HD_PUBLISH_POLICY` from the environment before it starts Nix.

This change does not provision secrets, change environment protection, or enable `HD_PUBLISH_ENABLED`. Keep publication disabled until the activation gates below pass. Workflow configuration alone does not prove hosted access.

## Remaining activation gates

| Gate | Required action before activation |
| --- | --- |
| Real R2 | Approve and test publisher credentials, conditional create/replace, exact ETags, and ambiguous-request recovery against disposable destinations |
| Private control storage | Approve a separate non-public bucket, access boundaries, and durable recovery records |
| Production signing | Approve use of the existing production identity and verify its full fingerprint without exposing private bytes |
| Hosted execution | Approve CI secrets, default-branch policy, environment protection, and hosted permissions |
| Public delivery | Qualify custom-domain HTTPS, content types, cache headers, delayed clients, and split entry/signature recovery |
| APK policy | Approve native v2 SHA1 control identity and declared real inputs/client compatibility |
| Flatpak policy | Approve source owner, application refs, runtime origin, extensions, and empty collection policy |
| Distribution clients | Test declared official distribution images and architectures separately from pinned Nix clients |

Already-signed RPMs and signed upstream Flatpak bundles remain rejected. Flatpak source/runtime approval is pending, with no automatic source addition. No activation test above ran as part of the local acceptance path.

Obtain explicit approval before production credentials, key use, public actions, or external permission tests. No deletion or retention change forms part of activation.
