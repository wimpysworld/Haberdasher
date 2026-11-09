# Arch proof

The native Arch tests check that pacman verifies signed packages and signed databases from a local HTTP repository. They use a pinned Nix pacman, not an official Arch image.

## Reproduce

In the Linux Nix development shell, use an ordinary account:

```sh
just proof arch
```

This command runs `tests/native/test_arch.py`. `tests/native/test_pipeline.py` separately checks the complete publisher path.

## Publisher adapter

`src/haberdasher/formats/arch.py` admits new packages by whole-package SHA256 and native name, version, and architecture. Changed bytes stop the run, including versions such as `1-1` and `1-01` that `vercmp` considers equal. Detached SHA256 OpenPGP signatures preserve the package bytes.

The inventory keeps the complete `desc` and `files` records of each database. A run rebuilds the database and files archives of each changed architecture from those records, then indexes only the new packages with `repo-add --include-sigs --sign`. Historical package files are not indexer inputs. `any` packages appear in every architecture directory and database.

## Native client evidence

`tests/native/test_arch.py` runs pacman with `SigLevel = Required TrustedOnly`:

- A client refreshes, installs a package with its dependency, searches files with `pacman -F`, then updates to the next version.
- Both split orders of `.db` and `.files` with their signatures stop refresh: old data with a new signature, and new data with an old signature.
- An untrusted key, an invalid or missing package signature, and missing database outputs each stop installation or preparation. A signer that fails, or that exits `0` without output, produces no prepared state.
- One generation publishes an x86_64 and an aarch64 package. A client with `Architecture = aarch64` installs the aarch64 package on the x86_64 host. No aarch64 host or emulation runs the installed files.

## Limits

`fakeroot` emulates root identity and file ownership for native operations. It is not a security boundary. The client `GPGDir` is global to the selected pacman invocation, not a per-repository signer allow-list. [Arch setup](../clients.md#arch) explains the dedicated configuration and root boundary.
