# Nix proof

The native Nix tests check that `nix` evaluates a bare Git flake repository over dumb HTTP and substitutes signed store paths from a local HTTP binary cache with `--max-jobs 0`. They run on `x86_64-linux`.

## Reproduce

In the Linux Nix development shell, use an ordinary account:

```sh
just proof nix
```

This command runs `tests/native/test_nix.py`. `tests/native/test_pipeline.py` separately checks the complete publisher path.

## Publisher adapter

`src/haberdasher/formats/nix.py` admits release assets by whole-file SHA256 and native `(pname, system, version)` identity across `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`. When a release tag has a package expression under `nix/`, the adapter uses that upstream expression and rewrites its `fetchurl` hashes to the verified SRI hashes of the release assets. Otherwise, it generates a package expression from `.tar.gz` release archives (detecting static and dynamically linked ELF binaries and Mach-O headers from binary headers, never filenames), or falls back to `.deb` and macOS `.dmg` or `.zip` assets when no `.tar.gz` archive exists.

The adapter commits `flake.nix`, `flake.lock`, and `pkgs/<name>/` to a bare Git repository at `packages.git`, tags each commit at `refs/tags/<rev>`, and runs `git update-server-info` for dumb HTTP. It pre-seeds the local Nix store with the verified release assets via `nix store add-file`, archives the `packages.git` flake source tree, builds each `x86_64-linux` package, and exports the flake source path and locally built store paths to the binary cache with `nix copy --to file://...?compression=zstd&secret-key=...`.

`SigningSession.nix_key()` derives the `nix.wimpys.world-1` Ed25519 keypair deterministically from the canonical RSA4096 secret numbers with RFC 5869 HKDF-SHA256 and verifies the public key with `nix key convert-secret-to-public`. A later run restores only `packages.git` objects, tags, and refs, `nix-cache-info`, and `keys/haberdasher-nix.pub`. Published `nar/*.nar.zst` archives and `*.narinfo` files stay referenced in `haberdasher.json` without re-downloading.

## Native client evidence

`tests/native/test_nix.py` serves the published directory over loopback `miniserve` and runs strict `nix` client checks:

- `git clone` over dumb HTTP succeeds for `packages.git`, `refs/tags/<rev>` resolves for each published generation, and `nix flake show --offline` and `nix eval` expose all declared systems.
- A consumer flake that locks `git+http://127.0.0.1:<port>/nix/packages.git` substitutes both the locked flake source tree and the built package into a fresh `--store` root with `--max-jobs 0`, across two generations (`1.0.0` to `2.0.0`).
- Upstream `nix/` expressions whose release tag carries a stale hash are rewritten to the verified asset SRI hash and build without network fetches.
- Static and dynamically linked ELF tarballs, plus `.deb` fallback packages, build and substitute cleanly.
- Missing `--trusted-public-keys`, a wrong Ed25519 public key, tampered `.narinfo` metadata, and tampered `nar/*.nar.zst` bytes each fail closed and leave no path in the client store.

## Limits

Only `x86_64-linux` derivations are realised and exported into the binary cache on the `x86_64-linux` builder. `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin` derivations are exposed in `packages.git` and evaluated offline, but are not built or cached by the `x86_64-linux` publisher. See [Nix setup](../clients.md#nix).
