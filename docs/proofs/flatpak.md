# Flatpak proof

The native Flatpak tests check that Flatpak verifies signed commits and summaries from a local HTTP repository. No test executes an application.

## Reproduce

In the project Linux Nix development shell, run:

```sh
just proof flatpak
```

This command runs `tests/native/test_flatpak.py`. `tests/native/test_pipeline.py` separately checks the complete publisher path.

Native catalogue export requires the pinned MIME database from `shared-mime-info`. The tests use pinned Nix clients in private roots. They do not test sandbox execution, deployment triggers, or desktop integration.

## Publisher adapter

`src/haberdasher/formats/flatpak.py` admits application bundles by source SHA256, native commit and ref bindings, and the AppStream version. The application ref gives the app ID, architecture, and branch. The application metadata gives the runtime, and the bundle gives the runtime repository, or Flathub when it names none. The adapter rejects a bundle with a collection ID.

Import keeps the upstream commit identity and replaces any detached upstream signature with the publisher signature. Commit, summary, and summary-index signatures use SHA256. `flatpak build-update-repo` writes the summary and the AppStream branches. All applications share one OSTree repository, with `wimpysworld.flatpakrepo` and one `<app-id>.flatpakref` per application.

A run restores only a working set: the repository entries, the current summaries, each head commit and its signature, the AppStream trees, and the `/metadata` and `/files/share/app-info` paths of each application head. Payload files and earlier commits stay published and are not downloaded again.

## Native client evidence

`tests/native/test_flatpak.py` runs private clients with `gpg-verify-summary=true`:

- A client searches the AppStream catalogue, installs the application with its runtime and extension, and updates to the exact next commit.
- A cold restore downloads only the working set, and the payload of the application head stays out of it.
- A tampered summary index and a missing signature each stop installation without deployment. Corrupt retained files stop preparation.
- Signed upstream applications and several architectures share one repository.

## Limits

The runtime origin is separate from the application origin. A `.flatpakref` install adds the runtime repository that the bundle names, or Flathub when it names none. `flatpak remote-add` from `wimpysworld.flatpakrepo` adds no runtime source. See [Flatpak setup](../clients.md#flatpak).
