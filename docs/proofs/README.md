# Repository proofs

`just proof` runs two distinct layers: the preserved WW-370 shell proofs and the production Python adapter tests. Both use disposable local fixtures.

## Run

After `just setup`, use an ordinary user in the pinned `x86_64-linux` Nix shell:

```sh
just proof
just proof apt
```

The first command selects all formats, plus shared signing, HTTP, storage-client, and pipeline tests. Replace `apt` with `rpm`, `arch`, `apk`, or `flatpak` to select one shell proof and its native adapter tests.

The router clears inherited credentials and uses the declared tool path. Private workspaces isolate client configuration, packages, and keys. Cleanup removes private files and stops owned servers and agents. Long temporary paths use a private `/tmp` fallback when GnuPG socket limits require it.

Native runtime qualification is `x86_64-linux` only. ARM Linux and Darwin pass evaluation only. Official distribution images are not qualified. No proof writes to R2, installs onto the host, or executes an installed application.

## Evidence layers

| Layer | Sources | Scope |
| --- | --- | --- |
| Preserved shell proofs | `tests/proofs/{apt,rpm,arch,apk,flatpak}.sh` | Independent format experiments, local inventories and frozen directories, format-specific trust boundaries |
| Production adapters | `src/haberdasher/formats/`, `tests/native/test_*.py` | Shared typed records, verified retained state, native signatures, isolated HTTP clients |
| Complete local pipeline | `tests/native/test_pipeline.py` | Recorded GitHub discovery, real CLI, durable local publication, served public trust, no-op, late assets, signer-free recovery |

Shell proof ledgers are not the publisher's durable schema. Their local inventories are not public `haberdasher.json`. Their original results do not establish production transport or permissions.

The production pipeline fetches both public OpenPGP exports over HTTP and compares full fingerprints with an independently supplied disposable identity. It checks public-only packets and uses the fetched keys for native client trust. APK also checks the served RSA key against that primary. Fresh clients and existing clients check installed records and payloads.

## Format guides

- [APT](apt.md): scoped trust, expiry, by-hash, and delayed clients.
- [RPM](rpm.md): package signing, metadata signing, and split pairs.
- [Arch](arch.md): strict package/database trust and retained archives.
- [Alpine APK](apk.md): RSA256 index trust and the native SHA1 boundary.
- [Flatpak](flatpak.md): commit/summary trust, runtime origin, and payload restoration.

## Current production implementation

The earlier discovery, admission, state, writer exclusion, storage, recovery, native adapter, and public-key follow-ons are implemented. The coordinator is minimal Python with native repository tools, not a shell-only publisher or plugin framework.

`src/haberdasher/core.py` defines records. `discovery.py` and `admission.py` reconcile and verify assets. `state.py`, `storage.py`, and `publish.py` freeze, conditionally publish, and recover generations. All configured public formats share one publication. Multiple configured formats require `--format all`.

Exact public-key bytes freeze before public writes. Bootstrap keys precede native entries, inventories follow their format outputs, and private completion follows all acknowledgements. Ownership has no automatic expiry. Unknown writes require stopped-owner evidence, not a timed takeover.

These controls do not provide multi-object atomicity. Older referenced objects remain available. No deletion or retention change is authorised.

## Remaining work

Use [publisher operations](../publisher.md) for the real CLI and policy schema. [Client setup](../clients.md) is the setup document, not a separate implemented website.

Production permission tests, private bucket approval, production key use, protected CI secrets, public HTTPS/cache qualification, and official distribution clients remain approval-dependent. APK SHA1 acceptance and Flatpak source/runtime approval remain pending. See [validation and activation](../validation.md) before any external action.
