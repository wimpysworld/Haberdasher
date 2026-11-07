{ pkgs }:
with pkgs;
[
  bash
  coreutils
  findutils
  gnugrep
  gnused
  gnutar
  gzip
  xz
  zstd
  libarchive
  jq
  curl
  openssl
  gnupg
  shellcheck
  shfmt
  nixfmt
  rclone
]
++ lib.optionals stdenv.hostPlatform.isLinux [
  apt
  dpkg
  createrepo_c
  rpm
  apk-tools
  abuild
  getopt
  pacman
  flatpak
  ostree
]
