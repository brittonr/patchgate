# <!-- ste-disable-next-line sentence-length -->
{ pkgs, source ? ../. }:

let
  # <!-- ste-disable-next-line semicolon sentence-length -->
  sourceRoot = /. + builtins.unsafeDiscardStringContext (toString source);
  # <!-- ste-disable-next-line semicolon -->
  pijul = import ./pijul.nix { inherit pkgs; };
  # <!-- ste-disable-next-line semicolon sentence-length -->
  runtimeTools = [ pijul pkgs.openssh pkgs.nix ];
  evalTools =
    runtimeTools
    ++ [ pkgs.cargo pkgs.rustc pkgs.stdenv.cc ]
    ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ]
    # <!-- ste-disable-next-line semicolon -->
    ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.darwin.ps ];
in
pkgs.rustPlatform.buildRustPackage {
  # <!-- ste-disable-next-line semicolon -->
  pname = "patchgate";
  # <!-- ste-disable-next-line semicolon -->
  version = "0.1.0";

  # The application output excludes evaluator and compiler dependencies.
  # <!-- ste-disable-next-line semicolon -->
  outputs = [ "out" "eval" ];
  # <!-- ste-disable-next-line semicolon -->
  nativeBuildInputs = [ pkgs.makeBinaryWrapper ];
  # <!-- ste-disable-next-line semicolon sentence-length -->
  nativeCheckInputs = [ pijul pkgs.openssh ];

  # Only Cargo inputs and Rust source files enter the package.
  src = pkgs.lib.fileset.toSource {
    # <!-- ste-disable-next-line semicolon sentence-length -->
    root = sourceRoot;
    fileset = pkgs.lib.fileset.unions [
      (sourceRoot + "/Cargo.toml")
      (sourceRoot + "/Cargo.lock")
      (pkgs.lib.fileset.fileFilter (file: file.hasExt "rs") (sourceRoot + "/src"))
    # <!-- ste-disable-next-line semicolon -->
    ];
  # <!-- ste-disable-next-line semicolon -->
  };

  # <!-- ste-disable-next-line semicolon sentence-length -->
  cargoLock.lockFile = sourceRoot + "/Cargo.lock";

  postInstall = ''
    mkdir -p "$out/libexec" "$eval/bin" "$eval/libexec"
    mv "$out/bin/patchgate" "$out/libexec/patchgate"
    mv "$out/bin/patchgate-eval" "$eval/libexec/patchgate-eval"

    makeBinaryWrapper "$out/libexec/patchgate" "$out/bin/patchgate" \
      --prefix PATH : ${pkgs.lib.makeBinPath runtimeTools}
    makeBinaryWrapper "$eval/libexec/patchgate-eval" "$eval/bin/patchgate-eval" \
      --prefix PATH : ${pkgs.lib.makeBinPath evalTools} \
      --set-default PATCHGATE_BIN "$out/bin/patchgate" \
      --set-default PATCHGATE_EVAL_UNWRAPPED_BIN "$out/libexec/patchgate"
  # <!-- ste-disable-next-line semicolon -->
  '';

  # <!-- ste-disable-next-line semicolon -->
  meta.mainProgram = "patchgate";
  # <!-- ste-disable-next-line semicolon -->
  meta.outputsToInstall = [ "out" ];
}
