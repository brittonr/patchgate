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
  # Rust fixtures need a compiler, linker, and process tools.
  # <!-- ste-disable-next-line semicolon -->
  rustTools = (with pkgs; [ cargo rustc stdenv.cc ]) ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.procps ];

  # Harbor also retains the runtime of the older tasks.
  # <!-- ste-disable-next-line semicolon -->
  tools = pkgs.buildEnv { name = "patchgate-harbor-tools"; paths = (with pkgs; [ bashInteractive coreutils findutils gnugrep gnutar gzip openssh pijul python3 ]) ++ rustTools; };

  # The shared Rust package supplies the executable.
  # <!-- ste-disable-next-line semicolon -->
  patchgate = import ../nix/package.nix { inherit pkgs; };

  # Only the Harbor script enters the task layout.
  # <!-- ste-disable-next-line semicolon -->
  project = pkgs.lib.fileset.toSource { root = ../.; fileset = ./scenarios.py; };

  # The rootfs directory gives /opt/patchgate and one repository for each scenario in /scenarios.
  # <!-- ste-disable-next-line semicolon -->
  scenarios = pkgs.runCommand "patchgate-harbor-scenarios" { nativeBuildInputs = [ tools patchgate ]; } ''
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
  inherit tools;
  # The environment retains the existing task layout.
  # <!-- ste-disable-next-line semicolon -->
  default = pkgs.buildEnv { name = "patchgate-harbor-environment"; paths = [ tools patchgate scenarios ]; };
}
