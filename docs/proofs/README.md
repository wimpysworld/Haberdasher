# Repository proofs

`just proof` runs two layers: the WW-370 shell proofs and the Python adapter tests. Both use disposable local fixtures.

## Run

After `just setup`, use an ordinary user in the pinned `x86_64-linux` Nix shell:

```sh
just proof
just proof apt
```

The first command selects all formats, plus shared signing, HTTP, storage-client, and pipeline tests. Replace `apt` with `rpm`, `arch`, `apk`, or `flatpak` to select one shell proof and its native adapter tests.

The router clears inherited credentials and uses the declared tool path. Private workspaces isolate client configuration, packages, and keys. Cleanup removes private files and stops owned servers and agents. Long temporary paths use a private `/tmp` fallback when GnuPG socket limits require it.

The native tools need `x86_64-linux`, so the proof router rejects every other system. ARM Linux and Darwin pass Nix evaluation only. The proofs use pinned Nix clients, not official distribution images. No proof writes to R2, installs onto the host, or executes an installed application.

## Evidence layers

| Layer | Sources | Scope |
| --- | --- | --- |
| Shell proofs | `tests/proofs/{apt,rpm,arch,apk,flatpak}.sh` | Independent format experiments, local inventories and frozen directories, format-specific trust boundaries |
| Production adapters | `src/haberdasher/formats/`, `tests/native/test_*.py` | Shared typed records, verified retained state, native signatures, isolated HTTP clients |
| Complete local pipeline | `tests/native/test_pipeline.py` | Recorded GitHub discovery, real CLI, locked local publication, served public trust, no-op, late assets, full rerun after an interruption |

Shell proof ledgers and their frozen-directory retry experiments are separate from the publisher's state and recovery. Their local inventories are not public `haberdasher.json`. They use local files, not production transport or permissions.

The production pipeline fetches both public OpenPGP exports over HTTP and compares full fingerprints with an independently supplied disposable identity. It checks public-only packets and uses the fetched keys for native client trust. APK also checks the served RSA key against that primary. Fresh clients and existing clients check installed records and payloads.

## Format guides

- [APT](apt.md): scoped trust, expiry, by-hash, and delayed clients.
- [RPM](rpm.md): package signing, metadata signing, and split pairs.
- [Arch](arch.md): strict package/database trust and retained archives.
- [Alpine APK](apk.md): RSA256 index trust and the native SHA1 boundary.
- [Flatpak](flatpak.md): commit/summary trust, runtime origin, and payload restoration.

## Publisher implementation

The coordinator is minimal Python that calls native repository tools. It is not a shell-only publisher or a plugin framework.

`src/haberdasher/core.py` defines records. `discovery.py` and `admission.py` reconcile and verify assets. `state.py` reads each bucket's public `haberdasher.json` and manages the bucket locks. `storage.py` and `publish.py` conditionally publish. All published formats share one publication.

Bootstrap keys and packages precede native entries, and inventories follow their format outputs. Locks have no automatic expiry. Only `just unlock` deletes a stale lock. A full rerun recovers an interrupted run.

These controls do not provide multi-object atomicity. Older referenced objects stay published.

See [publisher operations](../publisher.md) for the CLI and the derived settings. [Client setup](../clients.md) shows how to trust the key and add each repository. [Validation](../validation.md) lists the production checks that no proof covers.
