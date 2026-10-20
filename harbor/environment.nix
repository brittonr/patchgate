# The environment of the patchgate Harbor tasks, for the Docker and the bubblewrap backends.
# harbor/Dockerfile builds `default` into the image patchgate-harbor:dev.
# The environment/default.nix file of each task gives `default` to the bubblewrap backend.
# Nixpkgs is the nixpkgs-src input of devenv.lock, so the tasks use the pijul and the Python of the devenv shell.
{
  lock ? builtins.fromJSON (builtins.readFile ../devenv.lock),
  pkgs ? import (builtins.fetchTarball {
    # <!-- ste-disable-next-line semicolon -->
    url = "https://github.com/NixOS/nixpkgs/archive/${lock.nodes.nixpkgs-src.locked.rev}.tar.gz";
    # <!-- ste-disable-next-line semicolon -->
    sha256 = lock.nodes.nixpkgs-src.locked.narHash;
    # <!-- ste-disable-next-line semicolon -->
  }) { config = { }; overlays = [ ]; },
}:

let
  # <!-- ste-disable-next-line semicolon -->
  pijul = import ../nix/pijul.nix { inherit pkgs; };

  # Rust fixtures need a compiler, linker, and process tools.
  # <!-- ste-disable-next-line semicolon -->
  rustTools = (with pkgs; [ cargo rustc stdenv.cc ]) ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.procps ];

  # Harbor also retains the runtime of the older tasks.
  # <!-- ste-disable-next-line semicolon -->
  shellTools = with pkgs; [ bashInteractive coreutils findutils gnugrep gnutar gzip openssh python3 ];

  # <!-- ste-disable-next-line semicolon -->
  tools = pkgs.buildEnv { name = "patchgate-harbor-tools"; paths = [ pijul ] ++ shellTools ++ rustTools; };

  # The shared Rust package supplies the executable.
  # <!-- ste-disable-next-line semicolon -->
  patchgate = import ../nix/package.nix { inherit pkgs; };
  # <!-- ste-disable-next-line semicolon -->
  runtimeCheck = import ../nix/runtime-check.nix { inherit pkgs; package = patchgate; };

  # Only the Harbor script enters the task layout.
  # <!-- ste-disable-next-line semicolon -->
  project = pkgs.lib.fileset.toSource { root = ../.; fileset = ./scenarios.py; };

  # The rootfs directory gives /opt/patchgate and one repository for each scenario in /scenarios.
  scenarios = pkgs.runCommand "patchgate-harbor-scenarios" {
    # <!-- ste-disable-next-line semicolon -->
    nativeBuildInputs = [ tools patchgate patchgate.eval ];
  } ''
    # The compiled gate starts each repository.

    mkdir -p $out/rootfs/opt
    cp -R ${project} $out/rootfs/opt/patchgate
    chmod -R u+w $out/rootfs/opt/patchgate
    # Both runners use the compiled gate from the shared package.
    HOME=$TMPDIR python3 ${project}/harbor/scenarios.py setup-all $out/rootfs/scenarios
    # <!-- ste-disable-next-line semicolon -->
    HOME=$TMPDIR patchgate-eval setup-all $out/rootfs/scenarios'';
in
{
  # <!-- ste-disable-next-line semicolon -->
  inherit tools runtimeCheck;
  # The environment retains the existing task layout.
  default = pkgs.buildEnv {
    # <!-- ste-disable-next-line semicolon -->
    name = "patchgate-harbor-environment";
    # <!-- ste-disable-next-line semicolon -->
    paths = [ tools patchgate patchgate.eval scenarios ];
  # <!-- ste-disable-next-line semicolon -->
  };
}
