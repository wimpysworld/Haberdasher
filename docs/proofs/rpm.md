# RPM proof

**SHIP** the bounded WW-372 local proof. **DEFER** production ingestion and
publication. Independent validation passed all 29 cases on 2026-11-07 as UID
1000 on `x86_64-linux`.

## Reproduce

In the project Nix development shell, use an ordinary account:

```sh
just proof rpm
```

The independent run used this command from the checkout:

```sh
TMPDIR=/tmp timeout 900 nix develop "path:$PWD" --command \
  bash --noprofile --norc -c 'TMPDIR=/tmp just proof rpm'
```

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

Bound the adapter to admitted inputs, retained XML, and frozen replay. Follow
the [shared production follow-ons](README.md#production-follow-ons). Test
Fedora, RHEL, openSUSE, authenticated public setup, and remote recovery
separately. Local files prove no production transport, writer exclusion, or
availability policy. No credentials, production keys, buckets, activation, or
external writes are involved.
