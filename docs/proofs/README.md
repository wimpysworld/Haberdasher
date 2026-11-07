# Local repository proofs

These local fixtures test native repository updates, signature checks, and interrupted publication. They are not a production publisher or installation instructions for public repositories.

## Run

In the Linux Nix development shell, use an ordinary user account:

```sh
just proof
just proof apt
```

The first command selects all five formats. Replace `apt` with `rpm`, `arch`, `apk`, or `flatpak` for one proof. Arch requires `x86_64`.

The router clears inherited credentials and uses the pinned tool path. Each proof creates a private temporary workspace with disposable packages, keys, and client configuration. Cleanup removes the workspace and stops its GnuPG agents. APT serves fixtures on loopback. The other proofs use local files. No proof writes to R2.

Read the format evidence before making a support claim:

- [APT](apt.md)
- [RPM](rpm.md)
- [Arch](arch.md)
- [Alpine APK](apk.md)
- [Flatpak](flatpak.md)

These independent WW-370 proofs can run in parallel. They do not activate production publication. Individual results and support decisions belong in the format guides.

## Current proof inputs and outputs

The scripts in `tests/proofs/` create their own fixtures, not GitHub downloads. Admission receives a local package path and an expected whole-file SHA256. Negative cases supply a wrong checksum or changed bytes. Flatpak also supplies a fixture owner, asset identity, and expected version.

Each proof reads native metadata. APT uses package, version, and architecture with Debian version comparison. RPM uses name, epoch, version, release, and architecture, with absent epoch normalised to zero. Arch uses package, version, and architecture with `vercmp`. APK extracts package, version, and architecture from native index records for its bounded fixtures. Flatpak checks the full ref, commit, runtime, version, and collection binding, alongside asset history. These checks are not a shared identity implementation.

Retained state differs by format: complete APT package records, RPM repository metadata, signed Arch database/files archives, and a signed APK index. Flatpak retains admission history, expected heads, trust, and native configuration. Its cold restore fetches current-head trees and payload, not only commit metadata. The format guides define the exact retained files and limits.

Each script prepares signed output before local replay. Frozen directories retain the generation's package objects, dependency metadata, and entry files. Proofs use local checksum inventories, byte comparisons, or tree hashes to check published output and retries. RPM records source and signed-package SHA256 separately. Flatpak preserves bundle bytes and commit identity, but adds detached signatures and repository objects. The other proofs preserve admitted package bytes.

Completion is a local final inventory copy or marker after publication. The inventories differ in content and coverage. They are neither a common schema nor the proposed public `haberdasher.json`. Temporary proof state is not durable production recovery state.

## Proposed production input/output contract

This semantic contract is a proposal, not a current API. It does not define a plugin framework or configuration options.

| Item | Proposed input | Required output or rule |
| --- | --- | --- |
| Source admission | Verified source repository, release/asset identity, local bytes, and expected SHA256 | Record the source SHA256 before native import. Reject missing checksums and changed source bytes for an existing identity. |
| Native identity | Package metadata and format-specific comparison rules | Preserve ecosystem version semantics. Do not derive identity from filenames or release tags alone. Record Flatpak refs, commits, runtime, and binding policy. |
| New packages | Only newly admitted package files, plus accepted asset history | Unchanged input causes no new signing or indexing. Discover assets added to an existing release. Do not require the historical binary pool as routine input. |
| Retained native state | Verified metadata and native configuration from the completed generation | Retain enough native state for incremental indexing. Record any required Flatpak current-head payload restore and its cost. Reject incomplete state. |
| Signing and digests | Runtime access to the approved signing identity and an explicit transformation policy | Record source SHA256 separately from published object SHA256. Preserve unchanged bytes where required. Verify native signatures before publication. |
| Prepared generation | Newly admitted packages and retained state | Freeze exact signed dependency objects, entry files, object paths, sizes, digests, and publication order for retry without re-signing. |
| Public package inventory | Completed publication and non-secret package/object records | Write one public `haberdasher.json` per bucket. Exclude credentials, private provenance, locks, and pending journals. |
| Private completion journal | Frozen generation, previous completion, and publication progress | Keep pending state private and durable. Advance completion only after all required writes and checks succeed. |

Production uses the approved single RSA4096 primary without subkeys across all five formats, with Alpine PKCS#8 conversion. Proof keys are disposable, not production keys.

Publish immutable packages and dependency objects before format entry files. Write the public inventory last, then record private completion. Retain older objects that published metadata still references. This order does not make an object set atomic. Split entry/signature pairs can cause temporary native-client failure. Production must settle the acceptable retry and availability policy before deployment. No deletion or retention change is authorised.

No shared adapter, discovery, storage, or locking service is implemented. Haberdasher does not yet parse releases from `haberdasher.yaml`. Domain activation and publication permissions in continuous integration (CI) remain unverified. Local read access does not establish write access.

## Production follow-ons

These are documentation-only scope estimates, not tracker updates. S means one bounded module change with tests. M means several files in one subsystem, with tests and documentation. Unresolved design starts with an S investigation, not an oversized implementation task.

| Named follow-on | Size | Boundary and completion evidence |
| --- | --- | --- |
| GitHub release and asset discovery | M | Read configured sources, reconcile releases and late assets, and test unchanged runs. No signing or storage writes. |
| Checksum admission | S | Verify discovered assets against release SHA256 records before import. Test missing, mismatched, and replaced assets. |
| Durable private publisher state | M | Persist accepted asset history, native state, frozen generations, and pending/completed journals. Test restart recovery. Exclude public storage. |
| Writer exclusion design | S | Select a shared local/CI exclusion mechanism and stale-owner policy. Produce the design and contention test plan. No locking service implementation. |
| Local/CI writer exclusion | M | Implement the agreed exclusion design. Test contention and stale-owner recovery. Workflow concurrency alone is insufficient. |
| Immutable R2 object publication | M | Upload and verify package/dependency objects before entries. Reject changed immutable objects. Test with a disposable destination, not production buckets. |
| Frozen R2 publication recovery | M | Replay one prepared generation after each interrupted phase. Verify digests, inventory-last ordering, and private completion without re-signing or deletion. |
| Production native adapter, one task per format | M each | Adapt one proof to admitted new inputs and retained native state. Test two generations and exact frozen replay. No shared discovery or locking implementation. |
| Unproven native compatibility policy, per affected format | S each | Resolve one format's open input, signature, client, or availability decision. Use its guide's evidence gaps. Produce a bounded client test plan. |
| Native trust bootstrap and compatibility, one task per format | M each | Prove one declared client/architecture over the production transport. Publish a predictable public-key URL. Authenticate bootstrap and test copy-paste setup, install, and update commands. |
| Public setup page | S | Choose the page location after bootstrap tests. Link the five tested setup guides and verification keys. No DNS changes. |

The per-format rows describe separate tasks, not one combined estimate. Shared state and publication work precede production integration. Native compatibility investigations precede their affected adapters and setup instructions. Keep the existing pinned Nix/Just path for local processing and Determinate Nix CI.

Start with discovery and checksum admission. Obtain explicit authority before any production key, domain, bucket, or publication-permission test.
