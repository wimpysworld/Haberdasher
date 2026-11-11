#!/usr/bin/env bash
# Fetch the latin woff2 files that the templates use, from the pinned jsDelivr fontsource packages.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p fonts
B=https://cdn.jsdelivr.net/npm
for p in \
  "@fontsource-variable/ubuntu-sans@5.3.0/files/ubuntu-sans-latin-wght-normal.woff2" \
  "@fontsource-variable/ubuntu-sans-mono@5.3.0/files/ubuntu-sans-mono-latin-wght-normal.woff2" \
  "@fontsource/red-hat-display@5.3.0/files/red-hat-display-latin-700-normal.woff2" \
  "@fontsource/red-hat-text@5.3.0/files/red-hat-text-latin-400-normal.woff2" \
  "@fontsource/red-hat-text@5.3.0/files/red-hat-text-latin-500-normal.woff2" \
  "@fontsource/red-hat-mono@5.3.0/files/red-hat-mono-latin-400-normal.woff2" \
  "@fontsource/dejavu-sans@5.3.0/files/dejavu-sans-latin-700-normal.woff2" \
  "@fontsource/dejavu-sans@5.3.0/files/dejavu-sans-latin-400-normal.woff2" \
  "@fontsource/dejavu-mono@5.3.0/files/dejavu-mono-latin-400-normal.woff2" \
  "@fontsource/arimo@5.3.0/files/arimo-latin-400-normal.woff2" \
  "@fontsource/arimo@5.3.0/files/arimo-latin-700-normal.woff2" \
  "@fontsource/cousine@5.3.0/files/cousine-latin-400-normal.woff2" \
  "@fontsource/comfortaa@5.3.0/files/comfortaa-latin-700-normal.woff2" \
  "@fontsource-variable/inter@5.3.0/files/inter-latin-wght-normal.woff2" \
  "@fontsource/jetbrains-mono@5.3.0/files/jetbrains-mono-latin-400-normal.woff2" \
  "@fontsource/jetbrains-mono@5.3.0/files/jetbrains-mono-latin-700-normal.woff2"; do
  curl -sfL -o "fonts/$(basename "$p")" "$B/$p"
done
