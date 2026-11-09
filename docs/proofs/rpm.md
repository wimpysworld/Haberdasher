# RPM proof

The native RPM tests check that DNF5 verifies signed RPM packages and signed `repomd.xml` from a local HTTP repository. They run on `x86_64-linux`.

## Reproduce

In the project Nix development shell, use an ordinary account:

```sh
just proof rpm
```

This command runs `tests/native/test_rpm.py`. `tests/native/test_pipeline.py` separately checks the complete publisher path.

## Publisher adapter

`src/haberdasher/formats/rpm.py` admits new RPMs by whole-file SHA256 and native NEVRA (name, epoch, version, release, and architecture). Absent epoch and explicit zero are equivalent. Changed source bytes under an existing identity stop the run.

The adapter removes any upstream signature with `rpmsign --delsign`, then signs each package before `createrepo_c` indexes it. GnuPG creates a detached armoured `repomd.xml.asc`. Both signatures use SHA256. The inventory records the source digest of the GitHub asset separately from the digest of the signed package.

A later run uses `createrepo_c --update --recycle-pkglist --skip-stat` with an explicit list of the new packages and `--read-pkgs-list`, so it reads only the new RPMs. Historical RPMs stay published but are not publisher inputs. Packages and compressed XML precede `repomd.xml` and its signature.

## Native client evidence

`tests/native/test_rpm.py` runs DNF5 in private roots with `gpgcheck=1` and `repo_gpgcheck=1`:

- A client installs the application and its dependency, then upgrades the application. The second preparation signs one package, runs `createrepo_c` once, and reads only the new RPM.
- A missing metadata signature, old entry with a new signature, new entry with an old signature, and an unsigned package each stop the upgrade. Each failure keeps the installed version. Restoring matching output permits a normal upgrade without cache deletion or disabled checks.
- Missing, corrupt, incomplete, and malformed retained XML each stop preparation. A failed signer produces no prepared state.
- A signed upstream RPM installs with Haberdasher trust only.
- Two sources with one RPM file name stop the run with one line.

## Limits

Fakechroot and fakeroot emulate root for trusted script-free fixtures. They are not a security boundary. Scoped metadata trust is pre-seeded, because the pinned librepo cannot trigger the missing-key import retry.

Package trust applies globally to the selected RPM database. Metadata trust uses a repository-specific keyring. See [RPM setup](../clients.md#rpm).
