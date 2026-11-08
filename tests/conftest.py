"""Keep test collection independent of publisher credentials."""

import os

import pytest


@pytest.fixture(autouse=True)
def scrub_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.startswith(("HD_", "AWS_", "RCLONE_", "GH_", "GITHUB_")):
            monkeypatch.delenv(name)
