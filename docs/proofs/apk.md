# Alpine APK proof

The native APK tests check that `apk` verifies a signed v2 index from a local HTTP repository. They use a pinned Nix `apk`, not an official Alpine image.

## Reproduce

In the Linux Nix development shell, run:

```sh
just proof apk
```

This command runs `tests/native/test_apk.py`. `tests/native/test_pipeline.py` separately checks the complete publisher path.

## Publisher adapter

`src/haberdasher/formats/apk.py` admits new packages by whole-file SHA256, then parses v2 input with `apk index --allow-untrusted`. It rejects native v3 `ADB` input and Android packages. Unsigned packages keep their bytes. A signed upstream package loses its `.SIGN.*` gzip stream, so the published bytes equal the unsigned package with the same control and payload streams. The `C:` control identity does not change.

The inventory keeps the complete index stanza of each package. A run rebuilds the index of each changed architecture from those stanzas with `apk index --merge`, then signs only the index with `abuild-sign -t RSA256`. The native key basename is `wimpysworld.rsa.pub`, and it matches the signature member and the client trust file. `noarch` packages appear in every architecture index.

## Native client evidence

`tests/native/test_apk.py` runs strict clients that never use `--allow-untrusted`:

- A client installs an unsigned package through the signed index, then updates over two generations. Standalone verification of the same unsigned package fails, so installation depends on the trusted index.
- A missing key, a wrong key, and changed control, payload, or index bytes each stop installation. The checks read installed records, payloads, and fetched files, because `apk update` and `apk fetch --recursive` can exit `0` without trust.
- Missing retained state, missing input, and a missing signer produce no prepared state.
- Signed upstream packages lose their signature, alone and mixed with unsigned packages.
- Packages with versions that have no `-rN` suffix publish for x86_64 and aarch64. A client with `--arch aarch64` installs and fetches the aarch64 package on the x86_64 host. No aarch64 host or emulation runs the installed files.

## Limits

Native v2 `Q1` control identity uses SHA1. Compressed-payload `datahash` uses SHA256. Source admission uses whole-file SHA256. The tests do not cover older Alpine clients.

An empty APK bucket receives the two OpenPGP exports. It receives the native RSA public key only with its first index. See [APK setup](../clients.md#alpine-apk).
