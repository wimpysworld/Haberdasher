# RPM proof

The preserved WW-372 shell proof passed independent local validation. The production Python adapter also passes isolated HTTP acceptance on `x86_64-linux`. Production activation remains pending.

## Reproduce

In the project Nix development shell, use an ordinary account:

```sh
just proof rpm
```

This command now runs the preserved shell proof and `tests/native/test_rpm.py`. The shell evidence below remains distinct from production pipeline acceptance.

[The proof](../../tests/proofs/rpm.sh),
[XML helper](../../tests/proofs/rpm/metadata.py), and
[shared helper](../../tests/proofs/common.sh) contain the native commands and
assertions.

| Tool                            | Tested version |
| ------------------------------- | -------------- |
| RPM, rpmsign, rpmkeys, rpmbuild | 4.20.1         |
| createrepo_c                    | 1.2.6          |
| DNF5                            | 5.4.6.0        |
| GnuPG                           | 2.4.9          |
| fakeroot                        | 1.38.1         |
| fakechroot                      | 2.20.1         |

## Admission and retained state

Admission verifies the original whole-file source SHA256 before extraction or
signing. Native NEVRA means name, epoch, version, release, and architecture.
Absent epoch and explicit zero are equivalent. Changed source bytes under an
existing identity reject.

`rpmsign` signs synthetic unsigned RPMs before `createrepo_c` indexes them.
Native identity stays unchanged. The inventory separates original source SHA256
from signed publication SHA256 and records object locations. GnuPG creates
detached armoured `repomd.xml.asc`. Both signatures use SHA256 with a disposable
RSA4096 primary.

Retained state includes `repomd.xml`, its signature, compressed
primary/filelists/other XML, inventories, and frozen generations. Validation
checks signatures, compressed/open SHA256 and sizes, complete membership, and
full historical package elements.

Generation two uses `--update --recycle-pkglist --skip-stat`, an explicit
new-package list, and `--read-pkgs-list`. Only the new RPM is parsed. Historical
RPMs remain published, but are absent from publisher inputs. Dependencies,
files, and changelogs survive. Missing, corrupt, incomplete, or malformed XML
rejects without changing completion or publication. Unchanged input performs no
extraction, signing, or indexing.

Frozen retry preserves exact signed bytes after interruptions following
immutable objects, entry replacement, or signature replacement before
completion. Immutable packages/XML precede separate entry/signature writes.
Completion follows successful writes. Retry performs no package work and retains
historical objects. These writes are not atomic.

## Native client evidence

DNF5 installs app version 1 and its dependency, then upgrades the app to
version 2. Native database, dependency, file-provider, file-list, changelog, and
payload-digest checks pass.

Private configuration enables `gpgcheck=1` and `repo_gpgcheck=1`. Scoped
metadata trust is pre-seeded because librepo 1.20 cannot trigger the missing-key
import retry. Package trust uses the disposable public key.

DNF5 independently rejects an unsigned package with signed metadata and unsigned
metadata with signed packages. Old entry/new signature and new entry/old
signature both reject. Each failure retains installed version 1. Restoring
matching frozen output permits ordinary `--refresh` upgrade without cache
deletion or disabled checks.

## Limits and next work

Fakechroot/fakeroot emulates root for trusted script-free fixtures, not a
security boundary. Cleanup removes temporary state and keys.

This proof does not authorise replacing upstream signatures. Defer
already-signed RPM ingestion until the owner approves a preservation or
replacement policy.

## Production adapter and remaining gates

`src/haberdasher/formats/rpm.py` implements unsigned-input admission, package signing before indexing, retained XML, and output verification. Already-signed RPMs reject. Trust-policy fields do not qualify upstream signature replacement.

`tests/native/test_rpm.py` checks HTTP install/update, dependencies, retained metadata, and strict package/metadata rejection. `tests/native/test_pipeline.py` adds real CLI publication, served-key bootstrap, no-op, late assets, and a full rerun after an interruption.

Package trust applies globally to the selected RPM database. Metadata trust uses a repository-specific keyring. The pinned librepo client needs pre-seeded metadata trust. See [RPM setup](../clients.md#rpm).

Fedora, RHEL, and openSUSE images, public HTTPS/cache behaviour, real R2 reruns, production keys, and hosted permissions remain unqualified. Use the [activation checks](../validation.md#remaining-activation-checks) before external tests.
