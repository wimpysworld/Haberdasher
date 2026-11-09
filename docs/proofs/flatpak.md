# Flatpak local proof

The WW-375 shell proof and the Python adapter tests check that Flatpak verifies signed commits and summaries from a local repository. No test executes an application.

## Run and boundary

In the project Linux Nix development shell, run:

```sh
just proof flatpak
```

This command runs the shell proof and `tests/native/test_flatpak.py`. The shell proof ran on x86_64 Linux with Flatpak 1.18.4, OSTree 2026.2, GnuPG 2.4.9, and `file://` transport. That Flatpak version is not a compatibility floor.

The [proof](../../tests/proofs/flatpak.sh) uses the
[common isolation helper](../../tests/proofs/common.sh), disposable RSA4096
primary keys without subkeys, and private clients. No app executes. Deployment
triggers fail UID mapping with
`bwrap: setting up uid map: Permission denied`. The proof does not test sandbox execution, successful
triggers, or desktop integration.

Native catalogue export requires the pinned MIME database from
`shared-mime-info`. The proof sets `XDG_DATA_DIRS` from that tool's store path and
requires `mime/mime.cache`. It does not edit trusted client cache bytes.

## Admission and native clients

The full application ref is `app/world.wimpress.HaberdasherProof/x86_64/stable`.
Admission checks native commit/ref bindings, source SHA256, expected
name/version/runtime metadata, and the version payload. Asset history accepts
the identical asset again and rejects changed bytes under an accepted identity. Wrong
checksums and source ownership reject.

A valid native bundle passes first. Separate wrong-name, wrong-runtime, and
wrong-version bundles then reach their intended predicates and reject. Accepted
state stays byte-identical, with no publisher, public pool, state directory, or
completion marker.

The collection decision is `collection=none`. A non-empty collection binding
rejects. Import preserves source bundle bytes and commit identity, while adding
detached signatures. Commit, summary, and summary-index signatures use SHA256.
Native verification stays enabled.

Native search discovers version one. A fresh client installs the app and local
runtime fixture `world.wimpress.HaberdasherRuntime/x86_64/stable`. Checks
cover exact refs, commits, runtime, origin, and installed data. Normal update
deploys the exact version-two commit. Another fresh client installs that commit
and runtime.

## Cold restoration and publication

The [cold helper](../../tests/proofs/flatpak/cold.sh) starts a fresh publisher
process without old bundles or the old working repository. Retained state
contains asset history, expected refs/digests, trust, and native configuration.
The next app bundle is the only new input.

Restoration fetches current-head trees plus payload for the app, runtime,
`appstream/x86_64`, and `appstream2/x86_64`. Catalogue entries and 64/128-pixel
icons survive. Commit-only restoration fails checkout. This is not metadata-only
restoration.

The validated restore measures **13,594 logical bytes**, including
**1,991 compressed payload bytes**, across 51 files and 38 native objects.
The
[inventory helper](../../tests/proofs/flatpak/fixture.py) measures stored bytes,
not network traffic.

Three generations retain modern digest-addressed signatures and dependencies.
Delayed clients work without canonical `summary.idx.sig`. Both legacy
summary-first and signature-first mismatches fail native trust checks.
Missing/wrong keys, altered commits/indexes, and missing signatures reject
without deployment.

After dependency, entry, and inventory interruptions, a retry restores exact frozen bytes without
re-signing or deletion. Completion follows the retry. Split legacy entries can
temporarily remove availability. The proof does not show multi-object atomicity.

## Publisher adapter

`src/haberdasher/formats/flatpak.py` implements bundle admission, retained heads and payload, and signed commit and summary output. The application ref gives the app ID, architecture, and branch. The application metadata gives the runtime, and the bundle gives the runtime repository, or Flathub when it names none. The adapter removes upstream commit signatures and rejects a bundle with a collection ID.

`tests/native/test_flatpak.py` checks HTTP search, install/update, commit/summary trust, runtime and extension origins, exact deployed commits, rejection cases, and that signed upstream apps and several architectures share one repository. `tests/native/test_pipeline.py` adds real CLI publication, served-key bootstrap, no-op, late assets, and a full rerun after an interruption. It also runs three incremental publications and checks that later runs do not download the payload files or earlier commits.

The runtime origin is separate from the application origin. A `.flatpakref` install adds the runtime repository that the bundle names, or Flathub when it names none. `flatpak remote-add` from `wimpysworld.flatpakrepo` adds no runtime source. See [Flatpak setup](../clients.md#flatpak).
