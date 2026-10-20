# <!-- ste-disable-next-line semicolon sentence-length -->
{ src, system, inputs }: import ./package.nix { source = src; pkgs = import inputs.nixpkgs { inherit system; }; }
