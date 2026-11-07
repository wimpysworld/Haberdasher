# APT proof

CORE PASS: independent WW-371 validation passed on 2026-11-07. This local
result is not production repository support.

## Reproduce

In the Linux Nix development shell, use an ordinary user account:

```sh
just proof apt
```

The [executable proof](../../tests/proofs/apt.sh) contains the native commands
and assertions. The [common helper](../../tests/proofs/common.sh) isolates
credentials, client state, and disposable keys.

Executed tools were APT **3.3.5**, dpkg **1.23.7**, and GnuPG **2.4.9**. Scope
is only `proof/main/amd64`, with data-only synthetic DEBs. Noble and Trixie
remain untested candidates. Native arm64 installation is untested.

## Admission and retained state

Admission requires a matching whole-file SHA256. Native metadata supplies
package/version/architecture identity, with `dpkg --compare-versions`
equality. Missing/wrong checksums, changed bytes for an existing identity,
and equivalent `1.0-0` are rejected. Identical repeated input causes no
extraction, signing, or duplicate record.

The proof retains complete `apt-ftparchive packages` records in
`state/records/<SHA256>`, the `state/assets` ledger, and `state/history`
inventory. Generation two concatenates exact old and new records.
Historical publisher DEBs are removed, other historical copies are
inaccessible, and an actual read fails during generation-two preparation.

Source DEB bytes equal published DEB bytes. Packages remain unsigned.
GnuPG signs `Release` with SHA256 as `InRelease` and detached armoured
`Release.gpg`. APT verifies both entry forms with scoped `signed-by` trust,
without global trust or disabled checks.

`Release` declares `Acquire-By-Hash: yes` and SHA256 checksums. The proof
sets `Valid-Until` to preparation time plus one day. Date and expiry checks
remain enabled. Signed metadata expired by one day is rejected. This is a
local expiry decision, not a production refresh policy.

## Native client evidence

One disposable client installs `1.0`/`first`, then updates to
`2.0`/`second`. Native dpkg status and installed payload confirm both versions.

After generation two, a delayed client uses the old `InRelease`. The server
records its exact old SHA256 by-hash index request. Installation selects
version one. Immutable pool and by-hash objects remain available.

Missing trust, wrong trust, altered `InRelease`, corrupt index, corrupt
package, and expired metadata each reject installation. All six clients
retain no installed dpkg state or payload. Rejection leaves the accepted
publication unchanged.

## Frozen recovery and cleanup

Exact recovery inputs are frozen package objects, `Packages`, `Packages.gz`,
their by-hash copies, `Release`, `Release.gpg`, and `InRelease`. Frozen
`order`, `assets`, `objects`, `inventory`, and `control.sha256` define replay
and verification. Recovery also retains historical objects from the prior
publication.

Six real signing calls precede freeze. Index, entry, and inventory
interruptions return 75 without advancing completion. Retries verify frozen
checksums and native signatures, add no signing calls, retain history, and
pass native installation.

Failure, INT, and TERM tests return 1, 130, and 143. Each stops the loopback
server and both owned agents, then removes private files.

## Decision and limits

**SHIP** the bounded local approach. **REJECT** invalid admission and
unverifiable frozen output. **DEFER** production support and compatibility
approval.

The [loopback helper](../../tests/proofs/apt/server.py) ignores
`If-Modified-Since`. Local HTTP proves acquisition paths, not production
cache behaviour, remote recovery, or crash durability.

Recommend a small production adapter from admitted new inputs and retained
native state. Follow the [shared production follow-ons][follow-ons] before
public setup instructions.

[follow-ons]: README.md#production-follow-ons
