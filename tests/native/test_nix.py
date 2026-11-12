# pyright: reportPrivateUsage=false

"""Production Nix flake and signed HTTP binary cache acceptance with loopback clients."""

from __future__ import annotations

import base64
import re
import shutil
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from haberdasher.admission import AdmissionFailure, admit
from haberdasher.config import ARCHITECTURES, FormatPolicy
from haberdasher.core import (
    AdmittedAsset,
    RetainedFormat,
    VerifiedAsset,
    atomic_write,
    canonical_json,
)
from haberdasher.formats import nix
from haberdasher.runtime import Runtime, private_workspace
from haberdasher.signing import NIX_KEY_NAME, signing_session
from tests.native.fixtures.nix import (
    NixClient,
    bind_github_metadata,
    deb_executable_asset,
    publish,
    tarball_asset,
    upstream_nix_files,
)
from tests.support.http import serve
from tests.support.keys import disposable_key, run

NOW1 = datetime(2026, 11, 11, tzinfo=UTC)
NOW2 = datetime(2026, 11, 12, tzinfo=UTC)
POLICY = FormatPolicy("nix", ARCHITECTURES["nix"])
EMPTY = RetainedFormat("nix", (), (), {}, ())
STALE_HASH = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def accept(
    asset: VerifiedAsset,
    runtime: Runtime,
    history: Sequence[AdmittedAsset] = (),
    policy: FormatPolicy = POLICY,
) -> AdmittedAsset:
    item = nix.inspect(asset, policy=policy, runtime=runtime, out=runtime.root / "inspection")
    return admit(item, history, compare=nix.compare, policy=policy, runtime=runtime)


def parse_narinfo(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            fields[key.strip()] = val.strip()
    return fields


def find_narinfo_for_pname(public_nix: Path, pname: str, version: str) -> tuple[Path, str]:
    suffix = f"-{pname}-{version}"
    for narinfo_path in sorted(public_nix.glob("*.narinfo")):
        info = parse_narinfo(narinfo_path)
        store_path = info.get("StorePath", "")
        if store_path.endswith(suffix):
            return narinfo_path, store_path
    raise AssertionError(f"No .narinfo found for {pname}-{version}")


def find_flake_source_narinfo(public_nix: Path) -> tuple[Path, str]:
    for narinfo_path in sorted(public_nix.glob("*.narinfo")):
        info = parse_narinfo(narinfo_path)
        store_path = info.get("StorePath", "")
        if store_path.endswith("-source") and not info.get("References", ""):
            return narinfo_path, store_path
    raise AssertionError("No flake source .narinfo found")


def test_two_generations_dumb_http_flake_cache_substitution_and_rejections() -> None:
    with (
        private_workspace() as runtime,
        disposable_key() as key,
        disposable_key() as wrong_key,
        signing_session(
            runtime,
            expected_fingerprint=key.fingerprint,
            key_file=key.key_file,
        ) as signer,
        signing_session(
            runtime,
            expected_fingerprint=wrong_key.fingerprint,
            key_file=wrong_key.key_file,
        ) as wrong_signer,
    ):
        print(run(runtime, "nix", "--version").decode().strip())
        _, _, nix_pub = signer.nix_key()
        _, _, wrong_nix_pub = wrong_signer.nix_key()
        assert nix_pub != wrong_nix_pub

        tool_v1 = tarball_asset(
            runtime,
            "hd-tool",
            "1.0.0",
            "hd-tool-v1",
            repository="wimpysworld/hd-tool",
            asset_id=1,
        )
        sidra_v1 = deb_executable_asset(
            runtime,
            "hd-sidra",
            "1.0.0",
            "hd-sidra-v1",
            repository="wimpysworld/sidra",
            asset_id=2,
        )
        tool_v2 = tarball_asset(
            runtime,
            "hd-tool",
            "2.0.0",
            "hd-tool-v2",
            repository="wimpysworld/hd-tool",
            asset_id=3,
        )

        upstream_map = {
            "wimpysworld/sidra": upstream_nix_files(
                "hd-sidra", repository="wimpysworld/sidra", stale_hash=STALE_HASH
            )
        }
        with bind_github_metadata(runtime, tag="v1.0.0", upstream_by_repo=upstream_map):
            accepted_tool_v1 = accept(tool_v1, runtime)
            accepted_sidra_v1 = accept(sidra_v1, runtime)
            assert accepted_tool_v1.inspected.metadata["mode"] == "tarball"
            assert accepted_sidra_v1.inspected.metadata["mode"] == "upstream-nix"
            changed_bytes = tarball_asset(
                runtime,
                "hd-tool",
                "1.0.0",
                "hd-tool-tampered",
                repository="wimpysworld/hd-tool",
                asset_id=4,
            )
            with pytest.raises(AdmissionFailure, match="Changed bytes"):
                accept(changed_bytes, runtime, (accepted_tool_v1,))

        accepted1 = [accepted_tool_v1, accepted_sidra_v1]
        generation1 = nix.prepare(
            accepted1,
            EMPTY,
            policy=POLICY,
            runtime=runtime,
            signer=signer,
            now=NOW1,
            out=runtime.root / "generation1",
        )
        nix.validate_retained(generation1.retained, policy=POLICY, runtime=runtime)
        assert (generation1.retained.metadata["public_key"]) == nix_pub

        http_root = runtime.root / "http"
        public_nix = http_root / "nix"
        public_nix.mkdir(parents=True)

        with serve(http_root) as http:
            state1 = publish(generation1, public_nix, generation=1)
            assert (public_nix / "nix-cache-info").read_bytes() == nix.CACHE_INFO
            assert (public_nix / "keys/haberdasher-nix.pub").read_text().strip() == nix_pub

            head1 = str(state1.metadata["head"])
            assert re.fullmatch(r"[0-9a-f]{40}", head1)

            # 1. Prove git clone over dumb HTTP and refs/tags/<head> resolution.
            clone1 = runtime.root / "clone1"
            run(runtime, "git", "clone", "--quiet", http.url("nix/packages.git"), str(clone1))
            cloned_head1 = (
                run(runtime, "git", "-C", str(clone1), "rev-parse", "HEAD").decode().strip()
            )
            tag_rev1 = (
                run(runtime, "git", "-C", str(clone1), "rev-parse", f"refs/tags/{head1}")
                .decode()
                .strip()
            )
            assert cloned_head1 == head1 == tag_rev1

            # 2. Prove upstream-nix mode rewrote the stale fetchurl hash to the verified SRI hash.
            expected_sidra_sri = "sha256-" + base64.b64encode(
                bytes.fromhex(sidra_v1.sha256)
            ).decode("ascii")
            linux_nix_text = (clone1 / "pkgs/hd-sidra/linux.nix").read_text(encoding="utf-8")
            assert STALE_HASH not in linux_nix_text
            assert expected_sidra_sri in linux_nix_text

            # 3. Prove binary cache substitution (--max-jobs 0) for both locked flake source and packages.
            flake_narinfo1, flake_source_store_path1 = find_flake_source_narinfo(public_nix)
            assert parse_narinfo(flake_narinfo1)["Sig"].startswith(f"{NIX_KEY_NAME}:")
            _, tool1_store_path = find_narinfo_for_pname(public_nix, "hd-tool", "1.0.0")
            _, sidra1_store_path = find_narinfo_for_pname(public_nix, "hd-sidra", "1.0.0")

            client1 = NixClient(runtime, "client-gen1", http.url("nix"), nix_pub)
            client1.run_nix("build", "--no-link", flake_source_store_path1)
            assert (client1.real_store_path(flake_source_store_path1) / "flake.nix").is_file()
            client1.substitute_and_run(tool1_store_path, "hd-tool", "hd-tool-v1")
            client1.substitute_and_run(sidra1_store_path, "hd-sidra", "hd-sidra-v1")

            # 4. Incremental generation 2 (1.0.0 -> 2.0.0) without historical source payloads.
            tool_v1.local_path.rename(tool_v1.local_path.with_suffix(".unavailable"))
            sidra_v1.local_path.rename(sidra_v1.local_path.with_suffix(".unavailable"))
            with bind_github_metadata(runtime, tag="v2.0.0", upstream_by_repo=upstream_map):
                accepted_tool_v2 = accept(tool_v2, runtime, state1.accepted_history)

            generation2 = nix.prepare(
                [accepted_tool_v2],
                state1,
                policy=POLICY,
                runtime=runtime,
                signer=signer,
                now=NOW2,
                out=runtime.root / "generation2",
            )
            before_json = canonical_json(generation2)
            with (
                patch.object(nix, "prepare", side_effect=AssertionError("No retry preparation")),
                patch.object(
                    type(signer), "nix_key", side_effect=AssertionError("No retry signing")
                ),
            ):
                nix.validate_prepared(generation2, policy=POLICY, runtime=runtime)
                state2 = publish(generation2, public_nix, generation=2)
                nix.validate_prepared(generation2, policy=POLICY, runtime=runtime)
            assert canonical_json(generation2) == before_json

            head2 = str(state2.metadata["head"])
            assert head2 != head1 and re.fullmatch(r"[0-9a-f]{40}", head2)
            run(runtime, "git", "-C", str(clone1), "fetch", "--quiet", "--tags", "origin", "main")
            assert (
                run(runtime, "git", "-C", str(clone1), "rev-parse", f"refs/tags/{head1}")
                .decode()
                .strip()
                == head1
            )
            assert (
                run(runtime, "git", "-C", str(clone1), "rev-parse", f"refs/tags/{head2}")
                .decode()
                .strip()
                == head2
            )

            _, tool2_store_path = find_narinfo_for_pname(public_nix, "hd-tool", "2.0.0")
            client2 = NixClient(runtime, "client-gen2", http.url("nix"), nix_pub)
            client2.substitute_and_run(tool2_store_path, "hd-tool", "hd-tool-v2")
            client2.substitute_and_run(sidra1_store_path, "hd-sidra", "hd-sidra-v1")

            requests = http.requests()
            assert any(
                r.path == "/nix/nix-cache-info" and r.status == 200 and r.bytes_sent > 0
                for r in requests
            )
            assert any(
                r.path.endswith(".narinfo") and r.status == 200 and r.bytes_sent > 0
                for r in requests
            )
            assert any(
                r.path.endswith(".nar.zst") and r.status == 200 and r.bytes_sent > 0
                for r in requests
            )

            # 5. Negative trust controls: missing key and wrong Ed25519 key fail closed.
            missing_key_client = NixClient(runtime, "missing-key", http.url("nix"), "")
            res_missing = missing_key_client.run_nix(
                "build", "--no-link", tool2_store_path, check=False, trusted_keys=""
            )
            assert res_missing.returncode != 0
            assert (
                "not signed by any of the keys in 'trusted-public-keys'"
                in res_missing.stderr.decode(errors="replace")
            )
            assert not missing_key_client.real_store_path(tool2_store_path).exists()

            wrong_key_client = NixClient(runtime, "wrong-key", http.url("nix"), wrong_nix_pub)
            res_wrong = wrong_key_client.run_nix(
                "build", "--no-link", tool2_store_path, check=False
            )
            assert res_wrong.returncode != 0
            assert (
                "not signed by any of the keys in 'trusted-public-keys'"
                in res_wrong.stderr.decode(errors="replace")
            )
            assert not wrong_key_client.real_store_path(tool2_store_path).exists()

        # 6. Negative integrity controls: tampered .narinfo Sig, tampered NarSize, and tampered .nar.zst.
        for tamper_kind in ("sig", "narsize", "nar"):
            bad_root = runtime.root / f"bad-{tamper_kind}"
            bad_nix = bad_root / "nix"
            shutil.copytree(public_nix, bad_nix)
            narinfo_path, target_store_path = find_narinfo_for_pname(bad_nix, "hd-tool", "2.0.0")
            narinfo_text = narinfo_path.read_text(encoding="utf-8")
            if tamper_kind == "sig":
                tampered_sig = f"Sig: {NIX_KEY_NAME}:{'A' * 86}==\n"
                narinfo_path.write_text(
                    re.sub(r"^Sig: .*$", tampered_sig.strip(), narinfo_text, flags=re.M),
                    encoding="utf-8",
                )
            elif tamper_kind == "narsize":
                info = parse_narinfo(narinfo_path)
                bad_size = int(info["NarSize"]) + 1
                narinfo_path.write_text(
                    re.sub(r"^NarSize: \d+$", f"NarSize: {bad_size}", narinfo_text, flags=re.M),
                    encoding="utf-8",
                )
            else:
                info = parse_narinfo(narinfo_path)
                nar_file = bad_nix / info["URL"]
                raw = bytearray(nar_file.read_bytes())
                raw[-1] ^= 0xFF
                atomic_write(nar_file, bytes(raw))
            with serve(bad_root) as bad_http:
                bad_client = NixClient(
                    runtime, f"client-bad-{tamper_kind}", bad_http.url("nix"), nix_pub
                )
                res_bad = bad_client.run_nix("build", "--no-link", target_store_path, check=False)
                assert res_bad.returncode != 0
                bad_stderr = res_bad.stderr.decode(errors="replace")
                if tamper_kind in ("sig", "narsize"):
                    assert "not signed by any of the keys in 'trusted-public-keys'" in bad_stderr
                else:
                    assert f"copying path '{target_store_path}'" in bad_stderr
                    assert "Failed to open archive" in bad_stderr
                assert not bad_client.real_store_path(target_store_path).exists()
