{ pkgs }:
let
  python = pkgs.python3.withPackages (ps: [ ps.pygobject3 ]);
  helper = pkgs.writeShellScriptBin "haberdasher-flatpak-metadata" ''
    export GI_TYPELIB_PATH="${
      pkgs.lib.makeSearchPath "lib/girepository-1.0" [
        pkgs.flatpak
        pkgs.ostree
        pkgs.glib
      ]
    }"
    exec ${python}/bin/python3 ${../src/haberdasher/formats/flatpak_native.py} "$@"
  '';
in
[ helper ]
