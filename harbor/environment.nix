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
  # Harbor needs bash, coreutils, findutils, tar and gzip. patchgate needs pijul, Python and OpenSSH.
  # <!-- ste-disable-next-line semicolon -->
  tools = pkgs.buildEnv { name = "patchgate-harbor-tools"; paths = with pkgs; [ bashInteractive coreutils findutils gnugrep gnutar gzip openssh pijul python3 ]; };

  # Only these two project files go into the environment.
  # <!-- ste-disable-next-line semicolon -->
  project = pkgs.lib.fileset.toSource { root = ../.; fileset = pkgs.lib.fileset.unions [ ../patchgate.py ./scenarios.py ]; };

  # The rootfs directory gives /opt/patchgate and one repository for each scenario in /scenarios.
  # <!-- ste-disable-next-line semicolon -->
  scenarios = pkgs.runCommand "patchgate-harbor-scenarios" { nativeBuildInputs = [ tools ]; } ''

    mkdir -p $out/bin $out/rootfs/opt
    cp -R ${project} $out/rootfs/opt/patchgate
    chmod -R u+w $out/rootfs/opt/patchgate
    HOME=$TMPDIR python3 ${project}/harbor/scenarios.py setup-all $out/rootfs/scenarios
    printf '#!/usr/bin/env bash\nexec python3 /opt/patchgate/patchgate.py "$@"\n' > $out/bin/patchgate
    chmod +x $out/bin/patchgate'';
in
{
  # <!-- ste-disable-next-line semicolon -->
  inherit tools;
  # <!-- ste-disable-next-line semicolon -->
  default = pkgs.buildEnv { name = "patchgate-harbor-environment"; paths = [ tools scenarios ]; };
}
