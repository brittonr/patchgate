{ pkgs }:

pkgs.rustPlatform.buildRustPackage {
  # <!-- ste-disable-next-line semicolon -->
  pname = "patchgate";
  # <!-- ste-disable-next-line semicolon -->
  version = "0.1.0";

  # Only Cargo inputs and Rust source files enter the package.
  src = pkgs.lib.fileset.toSource {
    # <!-- ste-disable-next-line semicolon -->
    root = ../.;
    fileset = pkgs.lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      (pkgs.lib.fileset.fileFilter (file: file.hasExt "rs") ../src)
    # <!-- ste-disable-next-line semicolon -->
    ];
  # <!-- ste-disable-next-line semicolon -->
  };

  # <!-- ste-disable-next-line semicolon -->
  cargoLock.lockFile = ../Cargo.lock;
}
