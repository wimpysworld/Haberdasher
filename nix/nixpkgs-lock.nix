{ pkgs }:
let
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  payload = builtins.toJSON {
    store_path = "${pkgs.path}";
    locked = lock.nodes.nixpkgs.locked;
    original = lock.nodes.nixpkgs.original;
  };
in
[
  (pkgs.writeShellScriptBin "haberdasher-nixpkgs" ''
    printf '%s\n' '${payload}'
  '')
]
