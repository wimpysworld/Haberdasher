# Flatpak local proof

**SHIP: bounded local approach. DEFER: production support.** Independent final
validation passed all 27 records.

## Run and boundary

In the project Linux Nix development shell, run:

```sh
just proof flatpak
```

The tested boundary is x86_64 Linux, Flatpak 1.18.4, OSTree 2026.2, GnuPG 2.4.9,
and local `file://` transport. Flatpak 1.18.4 is the minimum tested client,
not an established compatibility floor.

The [proof](../../tests/proofs/flatpak.sh) uses the
[common isolation helper](../../tests/proofs/common.sh), disposable RSA4096
primary keys without subkeys, and private clients. No app executes. Deployment
triggers fail UID mapping with
`bwrap: setting up uid map: Permission denied`. Sandbox execution, successful
triggers, and desktop integration remain unproved.

Native catalogue export requires the pinned MIME database from
`shared-mime-info`. The proof sets `XDG_DATA_DIRS` from that tool's store path and
requires `mime/mime.cache`. It does not edit trusted client cache bytes.

## Admission and native clients

The full application ref is `app/world.wimpress.HaberdasherProof/x86_64/stable`.
Admission checks native commit/ref bindings, source SHA256, expected
name/version/runtime metadata, and the version payload. Asset history accepts
identical replay and rejects changed bytes under an accepted identity. Wrong
checksums and source ownership reject.

A valid native bundle passes first. Separate wrong-name, wrong-runtime, and
wrong-version bundles then reach their intended predicates and reject. Accepted
state stays byte-identical, with no publisher, public pool, state directory, or
completion marker.

The collection decision is `collection=none`. A non-empty collection binding
rejects. Import preserves source bundle bytes and commit identity, while adding
detached signatures. Commit, summary, and summary-index signatures use SHA256.
Native verification stays enabled.

Native search discovers version one. A fresh client installs the app and approved
local runtime fixture `world.wimpress.HaberdasherRuntime/x86_64/stable`. Checks
cover exact refs, commits, runtime, origin, and installed data. Normal update
deploys the exact version-two commit. Another fresh client installs that commit
and runtime.

## Cold restoration and publication

The [cold helper](../../tests/proofs/flatpak/cold.sh) starts a fresh publisher
process without old bundles or the old working repository. Retained state
contains asset history, expected refs/digests, trust, and native configuration.
Only the next app bundle remains as new input.

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

Dependency, entry, and inventory interruptions recover exact frozen bytes without
re-signing or deletion. Completion follows recovery. Split legacy entries can
temporarily remove availability. No multi-object atomicity is proved.

## Production decision

Defer production transport, older-client/architecture compatibility,
availability policy, real upstream inputs, and sandbox execution. Bound the
Flatpak adapter to admitted bundles, retained heads/payload, signed frozen
output, and exact replay. Use the
[shared contract and follow-ons](README.md#production-follow-ons) before
production integration.
