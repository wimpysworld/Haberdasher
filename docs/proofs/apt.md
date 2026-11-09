# APT proof

The WW-371 shell proof and the Python adapter tests check that APT clients verify signed `Release` metadata from a local HTTP repository. Neither uses public service.

## Reproduce

In the Linux Nix development shell, use an ordinary user account:

```sh
just proof apt
```

This command runs the [shell proof](../../tests/proofs/apt.sh) and `tests/native/test_apt.py`. `tests/native/test_pipeline.py` separately checks the complete publisher path.

The shell proof ran with APT **3.3.5**, dpkg **1.23.7**, and GnuPG **2.4.9**. Its scope
is `proof/main/amd64`, with data-only synthetic DEBs. It does not cover Noble,
Trixie, or native arm64 installation.

## Admission and retained state

Admission requires a matching whole-file SHA256. Native metadata supplies
package/version/architecture identity, with `dpkg --compare-versions`
equality. Missing/wrong checksums, changed bytes for an existing identity,
and equivalent `1.0-0` are rejected. Identical repeated input causes no
extraction, signing, or duplicate record.

The proof retains complete `apt-ftparchive packages` records in
`state/records/<SHA256>`, the `state/assets` ledger, and `state/history`
inventory. Generation two concatenates exact old and new records.
The proof removes the historical publisher DEBs and makes other historical copies
inaccessible, so any read of them fails during generation-two preparation.

Source DEB bytes equal published DEB bytes. Packages stay unsigned.
GnuPG signs `Release` with SHA256 as `InRelease` and detached armoured
`Release.gpg`. APT verifies both entry forms with scoped `signed-by` trust,
without global trust or disabled checks.

`Release` declares `Acquire-By-Hash: yes` and SHA256 checksums. The proof
sets `Valid-Until` to preparation time plus one day. Date and expiry checks
stay enabled. Signed metadata expired by one day is rejected. This is a
local expiry decision, not a production refresh policy.

## Native client evidence

One disposable client installs `1.0`/`first`, then updates to
`2.0`/`second`. Native dpkg status and installed payload confirm both versions.

After generation two, a delayed client uses the old `InRelease`. The server
records its exact old SHA256 by-hash index request. Installation selects
version one. Immutable pool and by-hash objects stay available.

Missing trust, wrong trust, altered `InRelease`, corrupt index, corrupt
package, and expired metadata each reject installation. All six clients
retain no installed dpkg state or payload. Rejection leaves the accepted
publication unchanged.

## Frozen retry and cleanup

The retry inputs are frozen package objects, `Packages`, `Packages.gz`,
their by-hash copies, `Release`, `Release.gpg`, and `InRelease`. Frozen
`order`, `assets`, `objects`, `inventory`, and `control.sha256` define the retry
and its verification. The retry also keeps historical objects from the prior
publication.

Six real signing calls precede freeze. Index, entry, and inventory
interruptions return 75 without advancing completion. Retries verify frozen
checksums and native signatures, add no signing calls, retain history, and
pass native installation.

Failure, INT, and TERM tests return 1, 130, and 143. Each stops the loopback
server and both owned agents, then removes private files.

## Limits

The [loopback helper](../../tests/proofs/apt/server.py) uses shared `miniserve`
with deterministic, distinct modification times and normal conditional `304`
and range `206` responses. It does not delete request headers.
Local HTTP proves acquisition paths and these request semantics, not production
cache behaviour, remote recovery, or crash durability.

## Publisher adapter

`src/haberdasher/formats/apt.py` uses admitted new inputs and retained package records. It signs both Release forms and publishes immutable by-hash dependencies before entries. Default validity is seven days, with renewal within two days, set in code.

`tests/native/test_apt.py` covers HTTP install/update, strict rejection, delayed by-hash clients, retained records, and expiry. `tests/native/test_pipeline.py` adds real CLI publication, served-key trust, late assets, no-op, and a full rerun after an interruption.

A run renews APT metadata inside the renewal window and rejects expired metadata before it writes entries.

See [client setup](../clients.md#apt) for the client configuration.
