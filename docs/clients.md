# Native client setup

These are post-activation setup templates. The intended public domains are not yet qualified. Do not treat these examples as live installation instructions.

Local acceptance uses pinned Nix clients on `x86_64-linux`, disposable roots, and loopback HTTP. Official distribution images, public HTTPS, host installation, and application execution remain unqualified.

## Authenticate public keys first

Obtain the full primary fingerprint through an independent approved channel. A fingerprint fetched beside the key is not independent evidence.

Every configured public role serves `keys/haberdasher.asc` and `keys/haberdasher.gpg`. Download from the same approved origin as the repository. For example, after APT activation:

```sh
set -eu
: "${EXPECTED_FINGERPRINT:?Set the independently approved full primary fingerprint}"
: "${BOOTSTRAP_DIR:?Set a private temporary directory outside the checkout}"
curl --fail --silent --show-error \
  https://apt.wimpys.world/keys/haberdasher.gpg \
  --output "$BOOTSTRAP_DIR/haberdasher.gpg"
gpg --no-options --homedir "$BOOTSTRAP_DIR" --batch --no-autostart \
  --with-colons --with-key-data --show-keys "$BOOTSTRAP_DIR/haberdasher.gpg" \
  > "$BOOTSTRAP_DIR/key.txt"
test "$(grep '^fpr:' "$BOOTSTRAP_DIR/key.txt" | cut -d: -f10)" \
  = "$EXPECTED_FINGERPRINT"
test "$(grep -E '^(pub|sub|sec|ssb):' "$BOOTSTRAP_DIR/key.txt" | cut -d: -f1)" \
  = pub
```

Create `BOOTSTRAP_DIR` with mode `0700` before these commands. The checks require exactly one public primary and no subkey. Reject missing or additional fingerprints. Do not import a key that fails verification.

`tests/native/test_pipeline.py::native_client` fetches both exports, compares their full fingerprint and public data, and checks that no secret packets exist. Client trust uses those fetched bytes, not the private fixture keyring.

## APT

Install the verified binary export as `/etc/apt/keyrings/haberdasher.gpg`, readable by APT. Use this deb822 content in `/etc/apt/sources.list.d/haberdasher.sources`:

```deb822
Types: deb
URIs: https://apt.wimpys.world
Suites: stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/haberdasher.gpg
```

Match suite, component, and architecture to publisher configuration. The native fixture uses `stable/main/amd64`. The deb822 form expresses the same scoped Signed-By trust.

After approval, use ordinary `apt-get update`, `apt-get install PACKAGE`, and `apt-get install --only-upgrade PACKAGE`. Keep signature, date, and `Valid-Until` checks enabled. Do not use `apt-key`, global trust, or `trusted=yes`.

APT verifies signed repository metadata, not signatures on individual DEBs. Immutable pool and by-hash objects support delayed clients.

## RPM

Verify the public export from `https://rpm.wimpys.world/keys/haberdasher.gpg`. Keep a verified armoured export for package-key import. Use this repository definition:

```ini
[haberdasher]
name=Haberdasher
baseurl=https://rpm.wimpys.world
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/haberdasher.asc
skip_if_unavailable=0
```

Both package and metadata verification are required. Import only the verified public key with `rpm --import /etc/pki/rpm-gpg/haberdasher.asc` after approval.

RPM package trust is global to the selected RPM database, not a per-repository signer allow-list. A repository's `gpgkey` does not remove that wider trust. Use a separate installation root/database when that boundary is required.

The pinned DNF5/librepo client requires a pre-seeded repository-specific metadata keyring. `tests/native/fixtures/rpm.py::DnfClient` defines the exact cache-keyring setup and private root. Do not assume another distribution needs the same workaround. After client qualification, ordinary `dnf5 --refresh install PACKAGE` and `dnf5 --refresh upgrade PACKAGE` must preserve both checks.

The production adapter removes upstream RPM signatures with `rpmsign --delsign`, then signs with the Haberdasher key. Clients need only the Haberdasher key.

## Arch

Verify the public export from `https://pkg.wimpys.world/keys/haberdasher.gpg`. Initialise a dedicated GnuPG directory and import only that key. Set owner trust only after independent fingerprint verification.

Use these settings in the selected pacman configuration. Set `Architecture` to `x86_64` or `aarch64`. Each architecture has its own signed `haberdasher` database under `$arch`.

```ini
[options]
Architecture = x86_64
GPGDir = /etc/pacman.d/haberdasher-gnupg
SigLevel = Required TrustedOnly
LocalFileSigLevel = Required TrustedOnly
RemoteFileSigLevel = Required TrustedOnly

[haberdasher]
Server = https://pkg.wimpys.world/$arch
```

`GPGDir` applies globally to that pacman invocation. It is not a per-repository allow-list. Use a dedicated configuration and installation root to keep this key separate from unrelated repositories.

The native tests import the verified key and explicit owner trust, then run strict refresh, dependency installation, update, and file search. Preserve `Required TrustedOnly` for packages and databases. Do not use `TrustAll` or optional signatures.

## Alpine APK

The native public key appears at `https://apk.wimpys.world/keys/haberdasher.rsa.pub` with the first APK index. An empty APK role needs no native RSA-key claim.

Fetch that public PEM and both OpenPGP exports. Verify the OpenPGP primary independently. Compare the PEM modulus and exponent with that primary's RSA public numbers before trust. `tests/native/test_pipeline.py::native_client` checks this binding for the fixed-exponent RSA4096 primary.

Install the verified PEM with the exact basename `haberdasher.rsa.pub` in the selected APK keys directory. The index signature member is `.SIGN.RSA256.haberdasher.rsa.pub`. A different basename does not establish the required trust.

The repository entry is the base URL:

```text
https://apk.wimpys.world
```

APK selects the architecture-specific index, `x86_64/APKINDEX.tar.gz` or `aarch64/APKINDEX.tar.gz`. The test clients use `--arch x86_64` or `--arch aarch64`, explicit `--keys-dir` and `--repositories-file`, and a private `--root`.

A strict client can install unchanged unsigned v2 packages through the trusted signed index. Standalone verification rejects those same unsigned packages. No client uses `--allow-untrusted`. The publisher uses that flag only for bounded unsigned-input inspection.

RSA256 signs the index with SHA256. Native v2 `Q1` control identity still uses SHA1, while payload `datahash` and whole-file admission use SHA256. Production acceptance of this SHA1 boundary remains pending. Successful `apk update` or `apk fetch` exit status alone does not prove trust. Check actual installed records, payloads, and fetched files.

## Flatpak

Approve application refs and a separate runtime origin before setup. Verify each origin's public key through its independent full fingerprint. Runtime policy must bind URL, remote, branch, architecture, refs, extensions, and collection.

The current adapter supports an empty collection binding. It rejects unapproved extensions, extra-data, source owners, refs, and signed upstream bundles. Do not add an arbitrary `RuntimeRepo` from an application bundle or descriptor.

Use separate deny-by-default filter files. Save the approved application filter as `/approved/app.filter`:

```text
deny *
allow app/APP_ID/x86_64/stable
```

Save the separately approved runtime and extension filter as `/approved/runtime.filter`:

```text
deny *
allow runtime/APPROVED_RUNTIME_ID/APPROVED_ARCH/APPROVED_RUNTIME_BRANCH
allow runtime/APPROVED_EXTENSION_ID/APPROVED_ARCH/APPROVED_EXTENSION_BRANCH
```

Replace each ref placeholder with an exact approved value, without wildcards.
The runtime URL and `/verified/runtime.gpg` are operator-supplied placeholders for the approved provider and its verified public key.
Verify that key against the provider's independently approved full fingerprint, not the Haberdasher fingerprint.
This example grants no runtime approval.

After replacing the placeholders with approved values, add the two origins explicitly:

```sh
flatpak --user remote-add --gpg-import=/verified/runtime.gpg \
  --filter=/approved/runtime.filter provider https://APPROVED_RUNTIME_ORIGIN
flatpak --user remote-add --gpg-import=/verified/haberdasher.gpg \
  --filter=/approved/app.filter publisher https://flatpak.wimpys.world
```

Do not disable commit or summary verification. Check remote URLs, imported fingerprints, filters, and collection settings before `flatpak --user install publisher APP_ID`. After an update, check exact ref, commit, runtime, extension, and origin.

The fixture approves a separate local runtime and extension. It does not add a production source or use Flathub implicitly. `tests/native/test_flatpak.py` checks the exact remote configuration and deployed data. No installed application executes.

## Qualification

Use [the validation guide](validation.md) for safe reproduction. Obtain explicit approval before public-domain tests or host setup. Keep signature checks enabled throughout qualification.
