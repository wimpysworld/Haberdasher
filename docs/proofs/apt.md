# APT proof

The native APT tests check that APT clients verify signed `Release` metadata from a local HTTP repository. They use no public service.

## Reproduce

In the Linux Nix development shell, use an ordinary user account:

```sh
just proof apt
```

This command runs `tests/native/test_apt.py`. `tests/native/test_pipeline.py` separately checks the complete publisher path.

## Publisher adapter

`src/haberdasher/formats/apt.py` admits new DEBs by whole-file SHA256 and native package, version, and architecture identity, with `dpkg --compare-versions` equality. It keeps the complete `apt-ftparchive packages` record of each package in the inventory, so a run rebuilds every `Packages` index and `Release` from the accepted history without historical DEBs.

Published DEB bytes equal the source DEB bytes. Packages stay unsigned. GnuPG signs `Release` with SHA256 as `InRelease` and detached `Release.gpg`. `Release` declares `Acquire-By-Hash: yes` and SHA256 checksums. It has a `Date` and no `Valid-Until`, so it does not expire. Immutable by-hash indexes precede the entries.

## Native client evidence

`tests/native/test_apt.py` runs APT clients in private dpkg roots with scoped `signed-by` trust:

- A client installs version `1.0` with its dependencies, then updates to version `2.0`. A second update gets HTTP `304` for `InRelease`.
- A delayed client with the old `InRelease` fetches the old by-hash index and installs version `1.0`.
- Without `InRelease`, a client falls back to `Release.gpg` and installs version `2.0`.
- A wrong key, a missing key, an altered `InRelease`, a corrupt by-hash index, and a corrupt package each stop installation.
- A `Release` with a `Date` 400 days old still updates, because it does not expire.
- A failed signer produces no prepared state. Retained validation checks both signature forms, and indexes are the same across roots and times.

## Limits

The loopback server uses shared `miniserve` with distinct modification times and normal conditional `304` and range `206` responses. Local HTTP proves acquisition paths and these request semantics, not production cache behaviour or crash durability. The tests do not cover native arm64 installation.

See [client setup](../clients.md#apt) for the client configuration.
