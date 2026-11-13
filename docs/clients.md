# Native client setup

In each signed package repository (APT, RPM, Arch, Alpine, Flatpak, and Nix), the client trusts the Haberdasher public key for that repository, with native signature checks enabled.

For the setup and install commands, use the page of each repository: [APT](https://apt.wimpys.world/), [RPM](https://rpm.wimpys.world/), [Arch Linux](https://pkg.wimpys.world/), [Alpine Linux](https://apk.wimpys.world/), [Flatpak](https://flatpak.wimpys.world/), [Homebrew](https://brew.wimpys.world/), [Scoop](https://scoop.wimpys.world/), and [Nix](https://nix.wimpys.world/). Each page lists its packages and published files. This guide explains the trust model and the tested client configuration. The Homebrew and Scoop repositories are not signed, so they have no key to trust. They rely on HTTPS and the `sha256` in each cask or the `hash` in each manifest.

The native tests run pinned Nix clients on `x86_64-linux` against disposable roots and loopback HTTP. They do not cover official distribution images, public HTTPS, host installation, or the execution of an installed application.

## Authenticate public keys first

Obtain the full primary fingerprint through an independent trusted channel. A fingerprint fetched beside the key is not independent evidence.

Every published repository serves `keys/haberdasher.asc` and `keys/haberdasher.gpg`. Download from the same origin as the repository. For example, for APT:

```sh
set -eu
: "${EXPECTED_FINGERPRINT:?Set the independently verified full primary fingerprint}"
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

The publisher uses suite `stable` and component `main`, and indexes `amd64` and `arm64`. Set `Architectures` to the client architecture. The native fixture uses `stable/main/amd64`. The deb822 form expresses the same scoped Signed-By trust.

Then use ordinary `apt-get update`, `apt-get install PACKAGE`, and `apt-get install --only-upgrade PACKAGE`. Keep signature and date checks enabled. The `Release` file has no `Valid-Until`, so it does not expire. Do not use `apt-key`, global trust, or `trusted=yes`.

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

Both package and metadata verification are required. Import only the verified public key with `rpm --import /etc/pki/rpm-gpg/haberdasher.asc`.

RPM package trust is global to the selected RPM database, not a per-repository signer allow-list. A repository's `gpgkey` does not remove that wider trust. Use a separate installation root/database when that boundary is required.

The pinned DNF5/librepo client requires a pre-seeded repository-specific metadata keyring. `tests/native/fixtures/rpm.py::DnfClient` defines the exact cache-keyring setup and private root. Do not assume another distribution needs the same workaround. Ordinary `dnf5 --refresh install PACKAGE` and `dnf5 --refresh upgrade PACKAGE` keep both checks.

The production adapter removes upstream RPM signatures with `rpmsign --delsign`, then signs with the Haberdasher key. Clients need only the Haberdasher key.

## Arch

Verify the public export from `https://pkg.wimpys.world/keys/haberdasher.gpg`. Initialise a dedicated GnuPG directory and import only that key. Set owner trust only after independent fingerprint verification. Without owner trust, pacman fails with `unknown trust`.

```sh
sudo install -d -m 0700 /etc/pacman.d/haberdasher-gnupg
curl -fsSL https://pkg.wimpys.world/keys/haberdasher.gpg \
  | sudo gpg --homedir /etc/pacman.d/haberdasher-gnupg --import
echo 'B39939A127C7A8D338F53A3AE132098A87DB88E0:6:' \
  | sudo gpg --homedir /etc/pacman.d/haberdasher-gnupg --import-ownertrust
```

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

The native tests import the verified key and explicit owner trust, then run strict refresh, dependency installation, update, and file search. Keep `Required TrustedOnly` for packages and databases. Do not use `TrustAll` or optional signatures.

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

RSA256 signs the index with SHA256. Native v2 `Q1` control identity uses SHA1, while payload `datahash` and whole-file admission use SHA256. Successful `apk update` or `apk fetch` exit status alone does not prove trust. Check actual installed records, payloads, and fetched files.

## Flatpak

Install an application with one command from its `.flatpakref` file at the bucket root. For Sidra:

```sh
flatpak --user install https://flatpak.wimpys.world/world.wimpys.sidra.flatpakref
```

The file holds the Haberdasher public key, so no separate key import is necessary. Flatpak adds the `wimpysworld` remote. It also adds the runtime repository from the file's `RuntimeRepo` key, which is Flathub for Sidra, when the runtime is not already installed. Each application has its own `<app-id>.flatpakref` file.

To add only the remote, use its remote description. `flatpak remote-add` does not act on `RuntimeRepo`, so add Flathub first:

```sh
flatpak --user remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak --user remote-add --from wimpysworld https://flatpak.wimpys.world/wimpysworld.flatpakrepo
flatpak --user install wimpysworld APP_ID
```

Haberdasher signs every commit and the summary with its own key, and removes any upstream commit signature. Do not disable commit or summary verification. `tests/native/test_flatpak.py` adds the publisher from the published file, with a local runtime provider that has a separate key, and checks the remote configuration and deployed data. It also installs from a `.flatpakref` file whose `RuntimeRepo` names a loopback runtime repository, and checks that Flatpak adds that runtime remote with GPG verification. No installed application executes.

## Nix

The Nix binary cache public key appears at `https://nix.wimpys.world/keys/haberdasher-nix.pub` with the first published package. Haberdasher derives the `nix.wimpys.world-1` Ed25519 key deterministically from the secret RSA4096 primary numbers with HKDF-SHA256. A client cannot check that derivation from the public OpenPGP key alone. Verify `https://nix.wimpys.world/keys/haberdasher.gpg` against your independently verified primary fingerprint to check the origin's published OpenPGP key material, and trust `haberdasher-nix.pub` from `https://nix.wimpys.world/keys/haberdasher-nix.pub` over HTTPS, pinned by value in `extra-trusted-public-keys`:

```sh
set -eu
: "${EXPECTED_FINGERPRINT:?Set the independently verified full primary fingerprint}"
: "${BOOTSTRAP_DIR:?Set a private temporary directory outside the checkout}"
curl --fail --silent --show-error \
  https://nix.wimpys.world/keys/haberdasher.gpg \
  --output "$BOOTSTRAP_DIR/haberdasher.gpg"
gpg --no-options --homedir "$BOOTSTRAP_DIR" --batch --no-autostart \
  --with-colons --with-key-data --show-keys "$BOOTSTRAP_DIR/haberdasher.gpg" \
  > "$BOOTSTRAP_DIR/key.txt"
test "$(grep '^fpr:' "$BOOTSTRAP_DIR/key.txt" | cut -d: -f10)" \
  = "$EXPECTED_FINGERPRINT"
test "$(grep -E '^(pub|sub|sec|ssb):' "$BOOTSTRAP_DIR/key.txt" | cut -d: -f1)" \
  = pub
curl --fail --silent --show-error \
  https://nix.wimpys.world/keys/haberdasher-nix.pub
```

Add the binary cache and its `nix.wimpys.world-1:<base64>` public key to your NixOS configuration:

```nix
nix.settings = {
  extra-substituters = [ "https://nix.wimpys.world" ];
  extra-trusted-public-keys = [ "nix.wimpys.world-1:<base64>" ];
};
```

On standalone Nix installations, add the equivalent lines to `/etc/nix/nix.conf`:

```ini
extra-substituters = https://nix.wimpys.world
extra-trusted-public-keys = nix.wimpys.world-1:<base64>
```

The packages come from each project's own flake on GitHub. Run the default package, or add a package to your profile:

```sh
nix run github:<owner>/<repo>
nix profile add github:<owner>/<repo>#<package>
```

Or add the flake input to `flake.nix`, and use `inputs.<repo>.packages.${pkgs.stdenv.hostPlatform.system}.<package>`:

```nix
inputs.<repo>.url = "github:<owner>/<repo>";
```

The cache serves a package only when your evaluation gives the same store path that Haberdasher built. Haberdasher builds the release tag, or the commit of the `latest` tag when that tag is at or ahead of the release tag. The page shows `github:<owner>/<repo>/latest` when Haberdasher built the commit that `latest` names, so `nix flake update` locks the commit that Haberdasher built. Otherwise the page shows `github:<owner>/<repo>`, and the cache serves packages only while the default branch matches the release. Do not set `inputs.<repo>.inputs.nixpkgs.follows`, because a different nixpkgs gives a different store path, and Nix then builds locally. The cache holds `x86_64-linux` store paths only. In tests, pass `--max-jobs 0` to verify that Nix substitutes from the signed binary cache instead of building locally.

To remove a package and the binary cache configuration:

```sh
nix profile remove <package>
sudo sed -i '/nix\.wimpys\.world/d' /etc/nix/nix.conf
```

## Verification

[The validation guide](validation.md) lists the local checks and the production checks. Keep signature checks enabled in every test.
