# Repository proofs

`just proof` runs the native Python tests of the publisher adapters and the complete local pipeline. The tests use disposable local fixtures.

## Run

After `just setup`, use an ordinary user in the pinned `x86_64-linux` Nix shell:

```sh
just proof
just proof apt
```

The first command selects all formats, plus shared signing, HTTP, storage-client, and pipeline tests. Replace `apt` with `rpm`, `arch`, `apk`, `flatpak`, `brew`, `scoop`, or `nix` to select the native tests of one format.

The router clears inherited credentials and uses the declared tool path. The tests run with a private HOME and TMPDIR. Private workspaces isolate client configuration, packages, and keys. Cleanup removes private files and stops owned servers and agents.

The native tools need `x86_64-linux`, so the proof router rejects every other system. ARM Linux and Darwin pass Nix evaluation only. The tests use pinned Nix clients, not official distribution images. No test writes to R2, installs onto the host, or executes an installed application.

## Evidence layers

| Layer | Sources | Scope |
| --- | --- | --- |
| Production adapters | `src/haberdasher/formats/`, `tests/native/test_{apt,rpm,arch,apk,flatpak,brew,scoop,nix}.py` | Native preparation, verified retained state, native signatures, strict clients over loopback HTTP |
| Complete local pipeline | `tests/native/test_pipeline.py` | Recorded GitHub discovery, real CLI, locked local publication, served public trust, no-op, late assets, full rerun after an interruption |

The pipeline fetches both public OpenPGP exports over HTTP and compares full fingerprints with an independently supplied disposable identity. It checks public-only packets and uses the fetched keys for native client trust. APK also checks the served RSA key against that primary. Fresh clients and existing clients check installed records and payloads.

The pipeline interrupts one publication of each format before its first entry write, and then after each entry write in turn, with a full rerun after each interruption. The final rerun publishes signed metadata that fresh and existing clients install with signature checks on, and a further rerun writes only its locks.

## Format guides

- [APT](apt.md): scoped trust, by-hash indexes, and delayed clients.
- [RPM](rpm.md): package signing, metadata signing, and split pairs.
- [Arch](arch.md): strict package and database trust.
- [Alpine APK](apk.md): RSA256 index trust and the native SHA1 boundary.
- [Flatpak](flatpak.md): commit and summary trust, runtime origin, and payload restoration.
- [Nix](nix.md): dumb-HTTP flake tags, deterministic Ed25519 cache signing, and `--max-jobs 0` binary substitution.

## Publisher implementation

The coordinator is minimal Python that calls native repository tools. It is not a shell-only publisher or a plugin framework.

`src/haberdasher/core.py` defines records. `discovery.py` and `admission.py` reconcile and verify assets. `state.py` reads each bucket's public `haberdasher.json` and manages the bucket locks. `storage.py` and `publish.py` conditionally publish. All published formats share one publication.

Bootstrap keys and packages precede native entries, and inventories follow their format outputs. Locks have no automatic expiry. Only `just unlock` deletes a stale lock. A full rerun recovers an interrupted run.

These controls do not provide multi-object atomicity. Older referenced objects stay published.

See [publisher operations](../publisher.md) for the CLI and the derived settings. [Client setup](../clients.md) shows how to trust the key and add each repository. [Validation](../validation.md) lists the production checks that no test covers.
