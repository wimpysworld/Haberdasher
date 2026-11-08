# Arch local proof

The preserved WW-373 shell proof passed independent local validation. The production Python adapter also passes isolated HTTP acceptance. Official Arch distribution compatibility and production delivery remain unqualified.

## Run and environment

In the Linux Nix development shell, use an ordinary account:

```sh
just proof arch
```

This command now runs the preserved shell proof and `tests/native/test_arch.py`. The historical shell evidence below uses x86_64 Linux. Pacman, repo-add, and vercmp use version
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

## Production adapter and remaining gates

`src/haberdasher/formats/arch.py` implements admitted new packages, verified retained archives, signature gates, and exact frozen output. `tests/native/test_arch.py` checks HTTP installation, update, file search, dependencies, and rejection under strict trust.

`tests/native/test_pipeline.py` adds real CLI publication, served public keys, fresh/existing clients, no-op, late assets, and recovery without source packages or signing access.

The client `GPGDir` is global to the selected pacman invocation, not a per-repository signer allow-list. [Arch setup](../clients.md#arch) explains the dedicated configuration/root boundary.

Official Arch images, other architectures, public HTTPS/cache behaviour, split-publication availability, and real R2 permissions remain unqualified. Use the [activation gates](../validation.md#remaining-activation-gates) before deployment.
