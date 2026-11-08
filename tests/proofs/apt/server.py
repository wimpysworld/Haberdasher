#!/usr/bin/env python3
"""Use the shared loopback fixture for the retained APT shell proof."""

import os
import pathlib
import signal
import sys

repository = pathlib.Path(__file__).resolve().parents[3]
sys.path[:0] = [str(repository), str(repository / "src")]

from tests.support.http import serve, set_generation_mtime  # noqa: E402

if sys.argv[1] == "--mtime":
    generation = int(sys.argv[2])
    root = pathlib.Path(sys.argv[3])
    set_generation_mtime(tuple(path for path in root.rglob("*") if path.is_file()), generation)
else:
    root, port_file, request_log = map(pathlib.Path, sys.argv[1:])
    with serve(root) as fixture:
        # Keep the existing path-only log assertions, with one shared log reader.
        os.link(fixture.request_log, request_log)
        port_file.write_text(str(fixture.port))
        print("ready", flush=True)
        signal.pause()
