# Alpine APK proof

PASS: all seven WW-374 local criteria passed independent validation on 2026-11-07. This result is not production repository or client compatibility approval.

## Reproduce

In the Linux Nix development shell, run:

```sh
just proof apk
```

[The executable proof](../../tests/proofs/apk.sh) contains the commands and assertions. [The shared helper](../../tests/proofs/common.sh) isolates temporary state and removes disposable keys.

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

**SHIP** the bounded local approach. **REJECT** v3 and invalid admission. **DEFER** production policy and compatibility approval.

Native v2 `Q1` control identity uses SHA1. Compressed-payload `datahash` uses SHA256. Source admission uses whole-file SHA256. The SHA1 identity risk remains a production decision. Older Alpine clients are untested.

Same-key conversion proves one disposable RSA4096 primary, matching keygrips and public DER across OpenPGP, X.509, and PKCS#8. No production key is used.

Transport is local files, without R2, remote recovery, cache, or domain activation evidence. Follow the [shared production follow-ons](README.md#production-follow-ons): bound the APK adapter to admitted inputs, retained state, and frozen replay. Resolve real-input/SHA1 and declared-client compatibility first. Prove authenticated fresh-client setup over production transport before publishing setup or installation commands.
