# Stable runtime tools do not depend on application packaging or checks.
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
  pijul = import ./pijul.nix { inherit pkgs; };

  # Rust fixtures need a compiler, linker, and process tools.
  # <!-- ste-disable-next-line semicolon -->
  rustTools = (with pkgs; [ cargo rustc stdenv.cc ]) ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.procps ];

  # Harbor also retains the runtime of the older tasks.
  # <!-- ste-disable-next-line semicolon -->
  shellTools = with pkgs; [ bashInteractive coreutils findutils gnugrep gnutar gzip openssh python3 ];

  # <!-- ste-disable-next-line semicolon -->
  tools = pkgs.buildEnv { name = "patchgate-harbor-tools"; paths = [ pijul ] ++ shellTools ++ rustTools; };

in

{
  # <!-- ste-disable-next-line semicolon -->
  inherit pkgs tools;

  # Export the tools and the package's pinned Nix command.
  # <!-- ste-disable-next-line semicolon sentence-length -->
  runtimeClosure = pkgs.closureInfo { rootPaths = [ tools (pkgs.lib.getBin pkgs.nix) ]; };
}
