# Nix proof

The native Nix tests check that `nix` substitutes signed store paths from a local HTTP binary cache with `--max-jobs 0`, after Haberdasher builds them from local fixture flakes. They run on `x86_64-linux`.

## Reproduce

In the Linux Nix development shell, use an ordinary account:

```sh
just proof nix
```

This command runs `tests/native/test_nix.py`.

## Publisher adapter

`src/haberdasher/formats/nix.py` takes the GitHub "Latest" release tag of each source and evaluates the `packages.<system>` outputs of the project's own flake, `github:<owner>/<repo>/<tag>`, for the publisher's host system. When the GitHub compare API shows the `latest` tag ahead of the release tag, it evaluates the commit that `latest` names, `github:<owner>/<repo>/<commit>`, instead. It ignores a `default` package that duplicates a named package. Each package has the identity `(pname, system, version)`, with `pname` from the derivation and the version from the release tag without a leading `v`. The inventory also keeps the derivation `version`. A source without a flake or host packages, and a package whose `meta.platforms` excludes the host, are skipped with one line. A package whose build fails is skipped with one line, and the run continues.

The adapter builds each new package, then exports the built store paths that `cache.nixos.org` does not sign to the binary cache with `nix copy --to file://...?compression=zstd&secret-key=...`, and checks them with `nix store verify`. `haberdasher.json` records the repository, tag, flake, attribute, and store path of each package, so a later run evaluates only a new release tag or a moved `latest` tag. It downloads nothing to restore the cache.

`SigningSession.nix_key()` derives the `nix.wimpys.world-1` Ed25519 keypair deterministically from the canonical RSA4096 secret numbers with RFC 5869 HKDF-SHA256 and verifies the public key with `nix key convert-secret-to-public`.

## Native client evidence

`tests/native/test_nix.py` publishes local fixture flakes through the locked publisher run, serves the bucket over loopback `miniserve`, and runs strict `nix` client checks:

- A fresh `--store` root substitutes the built package with `--max-jobs 0` across two release tags (`v1.0.0` and `v2.0.0`), and runs it. The second package takes version `2.0.0` from its tag, although its derivation reports `0.0.0-abc1234`.
- A fixture flake without `flake.nix`, a flake without packages for the host, and a package whose build fails are each skipped with one line.
- An unchanged rerun evaluates no published tag, builds nothing, and leaves the bucket bytes unchanged.
- A `latest` tag ahead of the release rebuilds the release from that commit, replaces its package record, keeps the earlier store path in the cache, and shows `github:<owner>/<repo>/latest` on the page.
- Missing `trusted-public-keys`, a wrong Ed25519 public key, an unsigned or forged `.narinfo`, a changed `NarSize`, and tampered `nar/*.nar.zst` bytes each fail closed and leave no path in the client store.

## Limits

Only the publisher's host system, `x86_64-linux`, is built and cached. Consumers on other systems build from the project flake. A consumer hits the cache only when its evaluation gives the same store path, so an input that sets `inputs.nixpkgs.follows` builds locally. See [Nix setup](../clients.md#nix).
