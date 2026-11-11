#!/usr/bin/env bash
# Render the OpenGraph preview images from the HTML templates with Firefox headless.
#
# Usage: ./render.sh [apt rpm arch apk flatpak]
#
# Each template loads its fonts from ./fonts, which holds the latin woff2 files from the
# pinned jsDelivr fontsource packages (see fetch-fonts.sh). Renders run one at a time in the
# foreground. Each PNG goes to src/haberdasher/og, where `just publish` reads it.
# The script checks that each PNG is exactly 1200 x 630 and under 300 KB.
set -euo pipefail
cd "$(dirname "$0")"

sites=("$@")
[ ${#sites[@]} -eq 0 ] && sites=(apt rpm arch apk flatpak)

# Firefox needs a writable home and its own profile. The content-process sandbox cannot start
# inside the agent sandbox, so the Mozilla sandbox is disabled for the render only.
export HOME=/tmp/og-home
export XDG_CONFIG_HOME=$HOME/.config XDG_CACHE_HOME=$HOME/.cache XDG_DATA_HOME=$HOME/.local/share
export MOZ_CRASHREPORTER_DISABLE=1 MOZ_DISABLE_CONTENT_SANDBOX=1 MOZ_DISABLE_GMP_SANDBOX=1
export MOZ_DISABLE_RDD_SANDBOX=1 MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1 MOZ_DISABLE_UTILITY_SANDBOX=1
mkdir -p "$HOME" /tmp/og-ffprof

for s in "${sites[@]}"; do
  out="$PWD/../src/haberdasher/og/$s.png"
  rm -f "$out"
  timeout 120 nix shell nixpkgs#firefox -c firefox --headless --no-remote --profile /tmp/og-ffprof \
    --screenshot "$out" --window-size=1200,630 "file://$PWD/$s.html" >/dev/null 2>&1 || true
  [ -f "$out" ] || { echo "FAIL $s: no screenshot" >&2; exit 1; }
  nix shell nixpkgs#oxipng -c oxipng -q -o 4 --strip safe "$out"
  read -r w h < <(nix shell nixpkgs#python3 -c python3 -c "
import struct,sys
d=open(sys.argv[1],'rb').read(24); print(*struct.unpack('>II',d[16:24]))" "$out")
  size=$(stat -c %s "$out")
  [ "$w" = 1200 ] && [ "$h" = 630 ] || { echo "FAIL $s: ${w}x${h}" >&2; exit 1; }
  [ "$size" -lt 300000 ] || { echo "FAIL $s: $size bytes" >&2; exit 1; }
  printf '%-8s %dx%d  %d bytes\n' "$s" "$w" "$h" "$size"
done
