# <!-- ste-disable-next-line sentence-length -->
{ pkgs, source ? ../., craneSource ? null }:

let
  # <!-- ste-disable-next-line semicolon sentence-length -->
  sourceRoot = /. + builtins.unsafeDiscardStringContext (toString source);
  # The trusted manifest also pins Crane for standalone builds.
  # <!-- ste-disable-next-line semicolon sentence-length -->
  cranePin = (builtins.fromJSON (builtins.readFile ./checks.json)).inputs.crane;
  craneLib = import
    (if craneSource == null then builtins.fetchTarball {
      # <!-- ste-disable-next-line semicolon -->
      url = cranePin.url;
      # <!-- ste-disable-next-line semicolon -->
      sha256 = cranePin.nar_hash;
    } else craneSource)
    # <!-- ste-disable-next-line semicolon sentence-length -->
    { inherit pkgs; };
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

  # Dependency artifacts use manifests, not application source.
  # Crane must inspect the filtered store tree, not the original directory.
  dependencySource = toString (pkgs.lib.fileset.toSource {
    # <!-- ste-disable-next-line semicolon -->
    root = sourceRoot;
    fileset = pkgs.lib.fileset.unions [
      (sourceRoot + "/Cargo.toml")
      (sourceRoot + "/Cargo.lock")
    # <!-- ste-disable-next-line semicolon -->
    ];
  # <!-- ste-disable-next-line semicolon -->
  });

  commonArgs = {
    # <!-- ste-disable-next-line semicolon -->
    pname = "patchgate";
    # <!-- ste-disable-next-line semicolon -->
    version = "0.1.0";

    # <!-- ste-disable-next-line semicolon -->
    strictDeps = true;
    # <!-- ste-disable-next-line semicolon -->
    doCheck = true;

    # <!-- ste-disable-next-line semicolon -->
    src = dependencySource;
    # <!-- ste-disable-next-line semicolon sentence-length -->
    cargoVendorDir = craneLib.vendorCargoDeps { src = dependencySource; };
  # <!-- ste-disable-next-line semicolon -->
  };

  # <!-- ste-disable-next-line semicolon -->
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  # <!-- ste-disable-next-line semicolon sentence-length -->
  cargoManifest = builtins.fromTOML (builtins.readFile (sourceRoot + "/Cargo.toml"));

  # Each target receives only its own Rust source files.
  compileBinary = name: files: craneLib.buildPackage (commonArgs // {
    # <!-- ste-disable-next-line semicolon -->
    pname = "${name}-unwrapped";
    # <!-- ste-disable-next-line semicolon -->
    cargoExtraArgs = "--locked --bin ${name}";
    # <!-- ste-disable-next-line semicolon sentence-length -->
    cargoTestExtraArgs = "--tests";

    # Cargo integration tests build every declared binary. Select one target.
    postPatch = let
      manifest = cargoManifest // {
        # <!-- ste-disable-next-line semicolon sentence-length -->
        package = cargoManifest.package // { default-run = name; };
        # <!-- ste-disable-next-line semicolon sentence-length -->
        bin = builtins.filter (binary: binary.name == name) cargoManifest.bin;
      # <!-- ste-disable-next-line semicolon -->
      };
    in ''
      cp ${craneLib.writeTOML "${name}-Cargo.toml" manifest} Cargo.toml
    # <!-- ste-disable-next-line semicolon -->
    '';

    src = toString (pkgs.lib.fileset.toSource {
      # <!-- ste-disable-next-line semicolon -->
      root = sourceRoot;
      fileset = pkgs.lib.fileset.unions [
        (sourceRoot + "/Cargo.toml")
        (sourceRoot + "/Cargo.lock")
        files
      # <!-- ste-disable-next-line semicolon -->
      ];
    # <!-- ste-disable-next-line semicolon -->
    });

    # <!-- ste-disable-next-line semicolon -->
    inherit cargoArtifacts;
    # <!-- ste-disable-next-line semicolon sentence-length -->
    nativeCheckInputs = [ pijul pkgs.openssh ];
    # <!-- ste-disable-next-line semicolon sentence-length -->
    disallowedReferences = [ commonArgs.cargoVendorDir cargoArtifacts ];
    # <!-- ste-disable-next-line semicolon -->
    meta.mainProgram = name;
  # <!-- ste-disable-next-line semicolon -->
  });

  # <!-- ste-disable-next-line semicolon sentence-length -->
  rustSources = pkgs.lib.fileset.fileFilter (file: file.hasExt "rs") (sourceRoot + "/src");

  compiledApplication = compileBinary "patchgate" (
    pkgs.lib.fileset.unions [
      (pkgs.lib.fileset.difference rustSources (pkgs.lib.fileset.maybeMissing (sourceRoot + "/src/bin")))
      (pkgs.lib.fileset.fileFilter (file: file.hasExt "rs") (sourceRoot + "/tests"))
    ]
  # <!-- ste-disable-next-line semicolon -->
  );

  compiledEvaluator = compileBinary "patchgate-eval" (
    pkgs.lib.fileset.unions [
      (pkgs.lib.fileset.fileFilter (file: file.hasExt "rs") (sourceRoot + "/src/bin/patchgate-eval"))
      (sourceRoot + "/src/artifact.rs")
      (sourceRoot + "/src/bundle.rs")
      (sourceRoot + "/src/change.rs")
      (sourceRoot + "/src/isolation.rs")
      (sourceRoot + "/src/pijul.rs")
      (sourceRoot + "/src/release_policy.rs")
      (sourceRoot + "/src/secrets.rs")
    ]
  # <!-- ste-disable-next-line semicolon -->
  );
in
pkgs.runCommand "patchgate-0.1.0" {
  # Wrappers bind the independently compiled binaries to the current gate.
  # <!-- ste-disable-next-line semicolon -->
  outputs = [ "out" "eval" ];
  # <!-- ste-disable-next-line semicolon sentence-length -->
  nativeBuildInputs = [ pkgs.makeBinaryWrapper ];

  # Neither output may retain compiled component paths or build-only dependencies.
  # <!-- ste-disable-next-line semicolon sentence-length -->
  disallowedReferences = [ compiledApplication compiledEvaluator commonArgs.cargoVendorDir cargoArtifacts ];

  passthru = {
    # <!-- ste-disable-next-line semicolon sentence-length -->
    inherit cargoArtifacts compiledApplication compiledEvaluator;
  # <!-- ste-disable-next-line semicolon -->
  };

  # <!-- ste-disable-next-line semicolon -->
  meta.mainProgram = "patchgate";
  # <!-- ste-disable-next-line semicolon -->
  meta.outputsToInstall = [ "out" ];
} ''
  mkdir -p "$out/bin" "$out/libexec" "$eval/bin" "$eval/libexec"
  cp ${compiledApplication}/bin/patchgate "$out/libexec/patchgate"
  cp ${compiledEvaluator}/bin/patchgate-eval "$eval/libexec/patchgate-eval"

  makeBinaryWrapper "$out/libexec/patchgate" "$out/bin/patchgate" \
    --prefix PATH : ${pkgs.lib.makeBinPath runtimeTools}
  makeBinaryWrapper "$eval/libexec/patchgate-eval" "$eval/bin/patchgate-eval" \
    --prefix PATH : ${pkgs.lib.makeBinPath evalTools} \
    --set-default PATCHGATE_BIN "$out/bin/patchgate" \
    --set-default PATCHGATE_EVAL_UNWRAPPED_BIN "$out/libexec/patchgate"
''
