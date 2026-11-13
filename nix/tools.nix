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
  cosign
  shellcheck
  shfmt
  nixfmt
  rclone
  awscli2
  miniserve
  git
]
++ lib.optionals stdenv.hostPlatform.isLinux [
  apt
  dpkg
  createrepo_c
  rpm
  dnf5
  fakechroot
  fakeroot
  apk-tools
  abuild
  getopt
  pacman
  flatpak
  ostree
  shared-mime-info
  appstream
  ruby
  nix
]
++ lib.optionals (stdenv.hostPlatform.isLinux && builtins.pathExists ./flatpak-metadata.nix) (
  import ./flatpak-metadata.nix { inherit pkgs; }
)
