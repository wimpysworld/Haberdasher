#!/usr/bin/env python3
"""Serve disposable APT repositories on loopback and record acquisition paths."""

import functools
import http.server
import pathlib
import sys

root, port_file, request_log = map(pathlib.Path, sys.argv[1:])


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Generations can change within one second, below HTTP timestamp precision.
        if "If-Modified-Since" in self.headers:
            del self.headers["If-Modified-Since"]
        with request_log.open("a") as log:
            log.write(self.path + "\n")
        super().do_GET()

    def log_message(self, format, *args):
        pass


with http.server.ThreadingHTTPServer(
    ("127.0.0.1", 0), functools.partial(Handler, directory=str(root))
) as server:
    port_file.write_text(str(server.server_port))
    print("ready", flush=True)
    server.serve_forever()
