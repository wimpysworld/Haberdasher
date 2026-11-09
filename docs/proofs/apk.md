# Alpine APK proof

The preserved WW-374 shell proof passed independent local validation. The production Python adapter also passes isolated HTTP acceptance. Production configuration and distribution compatibility remain untested.

## Reproduce

In the Linux Nix development shell, run:

```sh
just proof apk
```

This command now runs [the preserved shell proof](../../tests/proofs/apk.sh) and `tests/native/test_apk.py`. The native tests also publish unsigned x86_64 and aarch64 packages with versions that have no `-rN` suffix. A client with `--arch aarch64` installs and fetches the aarch64 package on the x86_64 host. No aarch64 host or emulation runs the installed files. The historical shell evidence follows. [The shared helper](../../tests/proofs/common.sh) isolates disposable state and keys.

The executed tools were apk-tools **3.0.5** (compiled for **x86_64**), abuild **3.17.0**, GnuPG/gpgsm **2.4.9**, and OpenSSL **3.5.9**. Client commands explicitly select `--arch x86_64`.

## Proven boundary

After expected whole-file SHA256 admission, the publisher parses unsigned v2 input with `apk index --allow-untrusted`. It signs only the index:

```sh
abuild-sign -t RSA256 -k "$W/alpine.rsa" -p "$W/keys/alpine.rsa.pub" "$1"
```

The proof checks `.SIGN.RSA256.alpine.rsa.pub` and matching client trust filenames. A fresh strict native client installs and fetches the unchanged unsigned APK. The client never uses `--allow-untrusted`. Standalone verification and installation reject that same unsigned source. No package receives a signature after admission.

The unsigned fixture covers one generation. A separate signed-upstream comparison proves actual installation of version one, then same-client update to version two and installation of an added asset. Installed records, payloads, and fetched SHA256 values confirm success.

## Retained state and assertions

The proof retains a signed native v2 `APKINDEX.tar.gz`, an identity/source-SHA256 ledger, and frozen generations with package/index inventories and an inventory SHA256.

- `apk index --merge --index` retains four expected name/version/architecture/dependency tuples using only two new package inputs. Plain `--index` loses both historical records.
- Assertions check empty dependencies and the `Q1` checksum prefix, not complete historical stanza equality.
- Admission rejects wrong checksums, changed bytes under an existing identity, malformed input, and native v3 `ADB` input. Unchanged admission preserves the ledger.
- Missing/corrupt retained state, missing input, and signer failure produce no completion inventory, despite permissive native indexing defaults.
- Publication writes packages, index, then completion inventory. Package/index/inventory interruptions preserve prior completion. Exact frozen replay checks SHA256, retains old objects, and performs no retry signing. Recovered targets receive no separate client test.

Missing/wrong keys and changed index/control/payload bytes cause installation failure, absent installed records/payloads, and empty fetch directories. `apk update` can exit `0`. `apk fetch --recursive` can also exit `0` without files. Neither status nor searchable metadata proves trust.

## Decision and limits

**SHIP** the bounded local approach. **REJECT** v3 and invalid admission. **DEFER** production configuration and compatibility checks.

Native v2 `Q1` control identity uses SHA1. Compressed-payload `datahash` uses SHA256. Source admission uses whole-file SHA256. The SHA1 identity risk remains a production decision. Older Alpine clients are untested.

Same-key conversion proves one disposable RSA4096 primary, matching keygrips and public DER across OpenPGP, X.509, and PKCS#8. No production key is used.

## Production adapter and remaining gates

`src/haberdasher/formats/apk.py` implements v2 admission, retained records, and RSA256 index signing. Unsigned packages keep their bytes. A signed upstream package loses its `.SIGN.*` gzip stream, so the published bytes equal the unsigned package with the same control and payload streams. The `C:` control identity does not change. The native key basename is `haberdasher.rsa.pub`, distinct from the historical shell fixture basename.

`tests/native/test_apk.py` checks HTTP install/update and strict rejection. `tests/native/test_pipeline.py` fetches the public RSA key, binds its modulus to the independently verified OpenPGP primary, and checks fresh/existing clients after a full rerun that follows an interruption.

Strict installation of unsigned packages depends on the trusted index. Standalone unsigned-package verification still rejects. The client never disables trust. Native SHA1 control identity remains a known production limitation.

An empty configured APK role receives the two OpenPGP exports. It receives the native RSA public key only with its first index. See [APK setup](../clients.md#alpine-apk).

Official Alpine clients, real-input policy, public HTTPS/cache behaviour, production permissions, and real R2 reruns remain unqualified. Use the [activation checks](../validation.md#remaining-activation-checks) before public use.
