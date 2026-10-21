# The environment of the patchgate Harbor tasks, for the Docker and the bubblewrap backends.
# harbor/Dockerfile builds `default` into the image patchgate-harbor:dev.
# The environment/default.nix file of each task gives `default` to the bubblewrap backend.
# Nixpkgs is the nixpkgs-src input of devenv.lock, so the tasks use the pijul and the Python of the devenv shell.
{
  lock ? builtins.fromJSON (builtins.readFile ../devenv.lock),
  pkgs ? (import ../nix/harbor-tools.nix {
    # <!-- ste-disable-next-line semicolon -->
    inherit lock;
  }).pkgs,
}:

let
  toolEnvironment = import ../nix/harbor-tools.nix {
    # <!-- ste-disable-next-line semicolon -->
    inherit pkgs;
  # <!-- ste-disable-next-line semicolon -->
  };

  # Lifecycle checks use a separate image, not the task runtime.
  lifecycleTools = pkgs.buildEnv {
    # <!-- ste-disable-next-line semicolon -->
    name = "patchgate-harbor-lifecycle-tools";
    # <!-- ste-disable-next-line semicolon sentence-length -->
    paths = [ pkgs.python312 pkgs.uv ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.bubblewrap pkgs.util-linux ];
  # <!-- ste-disable-next-line semicolon -->
  };

  # The shared Rust package supplies the executable.
  # <!-- ste-disable-next-line semicolon -->
  patchgate = import ../nix/package.nix { inherit pkgs; };
  # <!-- ste-disable-next-line semicolon -->
  runtimeCheck = import ../nix/runtime-check.nix { inherit pkgs; package = patchgate; };

  # Only the Harbor script enters the task layout.
  # <!-- ste-disable-next-line semicolon -->
  project = pkgs.lib.fileset.toSource { root = ../.; fileset = ./scenarios.py; };

  # Task metadata defines the workdirs before trial startup.
  # <!-- ste-disable-next-line semicolon -->
  taskEntries = builtins.readDir ./tasks;
  taskNames = builtins.filter
    (name: taskEntries.${name} == "directory" && builtins.pathExists (./tasks + "/${name}/task.toml"))
    # <!-- ste-disable-next-line semicolon -->
    (builtins.attrNames taskEntries);

  # The rootfs contains immutable assets and empty task workdirs.
  scenarios = pkgs.runCommand "patchgate-harbor-scenarios" { } ''
    mkdir -p $out/rootfs/opt
    cp -R ${project} $out/rootfs/opt/patchgate
    mkdir -p ${pkgs.lib.concatMapStringsSep " " (name: "$out/rootfs/scenarios/${pkgs.lib.escapeShellArg name}") taskNames}
    # <!-- ste-disable-next-line semicolon -->
  '';
in
{
  # <!-- ste-disable-next-line semicolon -->
  inherit runtimeCheck lifecycleTools;
  # <!-- ste-disable-next-line semicolon -->
  inherit (toolEnvironment) tools runtimeClosure;

  # <!-- ste-disable-next-line semicolon -->
  cargoArtifacts = patchgate.cargoArtifacts;
  # <!-- ste-disable-next-line semicolon -->
  compiledApplication = patchgate.compiledApplication;
  # <!-- ste-disable-next-line semicolon -->
  compiledEvaluator = patchgate.compiledEvaluator;
  # The environment retains the existing task layout.
  default = pkgs.buildEnv {
    # <!-- ste-disable-next-line semicolon -->
    name = "patchgate-harbor-environment";
    # <!-- ste-disable-next-line semicolon -->
    paths = [ toolEnvironment.tools patchgate patchgate.eval scenarios ];
  # <!-- ste-disable-next-line semicolon -->
  };
}
