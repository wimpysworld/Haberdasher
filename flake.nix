{
  description = "Nix flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    nix-packages.url = "git+https://nix.wimpys.world/packages.git";
    nix-packages.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      nixpkgs,
      nix-packages,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-darwin"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          tools = (import ./nix/tools.nix { inherit pkgs; }) ++ import ./nix/python.nix { inherit pkgs; };
          names = map pkgs.lib.getName tools;
          linuxTools = [
            "apt"
            "dpkg"
            "createrepo_c"
            "rpm"
            "dnf5"
            "fakechroot"
            "fakeroot"
            "apk-tools"
            "abuild"
            "getopt"
            "pacman"
            "flatpak"
            "ostree"
            "shared-mime-info"
            "appstream"
            "nix"
          ];
        in
        assert builtins.all (name: builtins.elem name names == pkgs.stdenv.hostPlatform.isLinux) linuxTools;
        assert builtins.all (name: builtins.elem name names) [
          "python3"
          "uv"
          "ruff"
          "basedpyright"
          "awscli2"
          "miniserve"
          "cosign"
        ];
        {
          tools =
            pkgs.runCommand "haberdasher-tools-test"
              {
                nativeBuildInputs = [
                  pkgs.bash
                  pkgs.just
                ];
              }
              ''
                mkdir -p just/project
                cp ${./just/project.just} just/project.just
                cp ${./just/project/tools.sh} just/project/tools.sh
                cp ${./just/project/proof.sh} just/project/proof.sh
                bash ${./just/project/test.sh}
                ${pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
                  test "$(${pkgs.getopt}/bin/getopt --options h --longoptions help -- --help)" = " --help --"
                  test -x ${pkgs.shared-mime-info}/bin/update-mime-database
                  test -f ${pkgs.shared-mime-info}/share/mime/mime.cache
                ''}
                touch "$out"
              '';
        }
      );
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.lib.optionalAttrs (builtins.pathExists ./nix/lib/blender.nix) {
          blender-agent-bridge-extension = (import ./nix/lib/blender.nix { inherit pkgs; }).extension;
        }
      );
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          # Keep the development shell available when Tailor has no package for this system.
          tailorPkgs = nix-packages.packages.${system} or { };
          projectTools = [
            pkgs.actionlint
            pkgs.gh
            pkgs.just
          ]
          ++ import ./nix/tools.nix { inherit pkgs; }
          ++ import ./nix/loader.nix { inherit pkgs; };
        in
        {
          default = pkgs.mkShell {
            shellHook = import ./nix/hooks.nix { inherit pkgs; };
            HABERDASHER_TOOL_PATH = pkgs.lib.makeBinPath projectTools;
            HABERDASHER_TOOL_SYSTEM = system;
            packages = projectTools ++ (if tailorPkgs ? tailor then [ tailorPkgs.tailor ] else [ ]);
          };
        }
        //
          pkgs.lib.optionalAttrs
            (system == "x86_64-linux" && builtins.pathExists ./nix/shells/go-ebitengine-android.nix)
            {
              android = import ./nix/shells/go-ebitengine-android.nix { inherit pkgs; };
            }
      );
    };
}
