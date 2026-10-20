{ src, system, inputs }:
import ./package.nix {
  # <!-- ste-disable-next-line semicolon -->
  source = src;
  # <!-- ste-disable-next-line semicolon -->
  craneSource = inputs.crane;
  # <!-- ste-disable-next-line semicolon sentence-length -->
  pkgs = import inputs.nixpkgs { inherit system; };
}
