# Arch local proof

SHIP the bounded local proof for WW-373. Independent validator
`9cecaf12-b13e-4d9` reports LOCAL CORE PASS with 49 assertions.
DEFER official Arch distribution compatibility and production availability policy.

## Run and environment

In the Linux Nix development shell, use an ordinary account:

```sh
just proof arch
```

The tested platform is x86_64 Linux. Pacman, repo-add, and vercmp use version
7.1.0 from this exact Nix build:

```text
/nix/store/02qab8gqfkg4r51dwwdiqwxfhx8z0y1n-pacman-7.1.0-unstable-2026-01-25
```

Pacman reports libalpm 16.0.1. This Nix client is not an official Arch image.
Official-client acceptance remains incomplete.

The [common helper](../../tests/proofs/common.sh) clears inherited credentials
and creates disposable RSA4096 signing keys, private temporary state, and
isolated client paths.
Cleanup removes that state and stops its GnuPG agents.
The [Arch script](../../tests/proofs/arch.sh) uses local `file://` publication.
`fakeroot` emulates root user identity and file ownership for native operations.
This fake user ID (UID) support is emulation, not a security boundary.

## Inputs, signatures, and retained state

Admission checks whole-package SHA256 and native name, version, and architecture.
Unchanged identity is a no-op. Changed bytes reject, including versions `1-1` and
`1-01` that native `vercmp` considers equal.
Detached SHA256 OpenPGP signatures preserve `.pkg.tar.zst` bytes.
Packages receive signatures before `repo-add --include-sigs --sign` indexes them.

Generation two indexes only the new `updateable` package with retained signed
`proof.db.tar.gz` and `proof.files.tar.gz` archives.
Historical package inputs are absent from the indexer.
Both archives retain byte-identical `keeper` records and the non-empty dependency
`updateable>=1`. File records remain unchanged.

The output gate checks both archive signatures, aliases, two-record counts,
package sidecars, and embedded `%PGPSIG%` bytes and validity.
A real two-record signer passes the positive control.
Failed signing and zero-output signing return native status `0`, but explicit
signature checks reject both archives before inventory completion.
Signature-only repairs pass the full gate, without record repairs.
Missing outputs also reject.

Retained state includes admission `history`, both signed archives, aliases,
package bytes/signatures, `inventory`, and frozen `generation.sha256` checksums.
The client retains public-key trust and native configuration, without a secret key.
Frozen generations include historical objects for retry, not routine indexing
input.

## Native acceptance and recovery

All signature settings use `Required TrustedOnly`.
Native refresh, dependency-resolved installation, update, queries, payload checks,
and file search pass.
Invalid or missing package and archive signatures reject.
An untrusted signing key rejects.
Package-fault tests retain valid signed metadata and correct package checksums.

Both split-generation orders reject for `.db` and `.files`: old data/new signature
and new data/old signature.
Matching frozen bytes restore strict refresh.
Interruptions after packages, `.db`, `.files`, and before inventory preserve the
previous completion inventory.
Exact frozen replay restores packages, signatures, both archives, and inventory
without re-signing or deletion.

## Deferred work

Bound the future Arch adapter to admitted new packages, verified retained state,
two-generation tests, explicit output gates, and exact frozen replay.
Test a declared official Arch client separately, including trust bootstrap,
installation, update, and file search over the intended transport.
Resolve HTTP/cache behaviour and split-publication availability before deployment.
Use the [shared production follow-ons](README.md#production-follow-ons) for these
separate tasks.
