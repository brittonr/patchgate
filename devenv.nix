{
  inputs,
  pkgs,
  lib,
  config,
  ...
}:

let
  # <!-- ste-disable-next-line semicolon -->
  package = import ./nix/package.nix { inherit pkgs; };
  # <!-- ste-disable-next-line semicolon -->
  runtimeCheck = import ./nix/runtime-check.nix { inherit pkgs package; };
  # The lock fixes the backend source revision and its content hash.
  # <!-- ste-disable-next-line semicolon sentence-length -->
  harborBackend = pkgs.runCommand "patchgate-harbor-bubblewrap-source" { } "cp -R ${inputs.harbor-bubblewrap}/python/hell_env $out";
in
{
  # Pijul stores changes. Cargo runs the Rust gate from the current source.
  packages = [
    # <!-- ste-disable-next-line semicolon -->
    (import ./nix/pijul.nix { inherit pkgs; })
    pkgs.openssh
    pkgs.cargo
    pkgs.rustc
  # <!-- ste-disable-next-line semicolon -->
  ];
  # Python runs only the Harbor tools.
  # <!-- ste-disable-next-line semicolon -->
  languages.python.enable = true;

  # Both outputs reuse the same independently compiled binaries as Harbor.
  # <!-- ste-disable-next-line semicolon -->
  outputs.patchgate = package;
  # <!-- ste-disable-next-line semicolon -->
  outputs.patchgate-eval = package.eval;
  # <!-- ste-disable-next-line semicolon -->
  outputs.runtime-check = runtimeCheck;

  # patchgate sends each change to a model server with an OpenAI-compatible API.
  # LM Studio gives this API on port 1234. Ollama and llama.cpp also give it.
  # <!-- ste-disable-next-line semicolon -->
  env.PATCHGATE_MODEL_URL = "http://127.0.0.1:1234/v1";
  # <!-- ste-disable-next-line semicolon -->
  env.PATCHGATE_MODEL = "google/gemma-4-e4b";
  # These files control the gate. A human must accept each change to them.
  # patchgate always protects POLICY.md.
  # <!-- ste-disable-next-line semicolon -->
  env.PATCHGATE_PROTECTED = "src/*,Cargo.toml,Cargo.lock,nix/*,devenv.nix,devenv.yaml,devenv.lock,.envrc,harbor/environment.nix,harbor/Dockerfile,.dockerignore";

  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate.description = "Let the local model merge conflicting inbox changes and decide which changes go into main";

  # The gate signs its merges with its own key in a private ssh-agent.
  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate.packages = [ pkgs.openssh ];
  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate.exec = ''exec cargo run --locked --quiet --manifest-path "$DEVENV_ROOT/Cargo.toml" -- "$@"'';

  # Rust handles the new scenarios, verifier controls, and live model jobs.
  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate-eval.description = "Evaluate Rust Harbor tasks";

  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate-eval.exec = ''exec cargo run --locked --quiet --manifest-path "$DEVENV_ROOT/Cargo.toml" --bin patchgate-eval -- "$@"'';

  # `devenv up` runs the gate. `devenv test` does not run it, because the gate changes main.
  # <!-- ste-disable-next-line semicolon -->
  processes.patchgate = lib.mkIf (!config.devenv.isTesting) { exec = "patchgate watch"; };

  # `patchgate-harbor` runs the Harbor tasks in harbor/tasks with Docker, in the Colima profile patchgate.
  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate-harbor.description = "Run the Harbor tasks of patchgate in Docker, or compare the control agents with check";

  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate-harbor.packages = [ pkgs.colima pkgs.docker-client pkgs.uv ];

  # The Compose and Buildx plugins and the Python 3.12 of Harbor come from Nix.
  # <!-- ste-disable-next-line semicolon sentence-length -->
  scripts.patchgate-harbor.exec = ''PATCHGATE_DOCKER_PLUGINS=${pkgs.docker-compose}/libexec/docker/cli-plugins:${pkgs.docker-buildx}/libexec/docker/cli-plugins PATCHGATE_HARBOR_PYTHON=${pkgs.python312}/bin/python3.12 PATCHGATE_HARBOR_BACKEND=${harborBackend} exec python3 "$DEVENV_ROOT/harbor/controls.py" "$@"'';

  # `devenv test` runs each Harbor task with the oracle agent and with the nop agent.
  # The oracle must get reward 1, and the nop agent must get reward 0.
  # <!-- ste-disable-next-line semicolon -->
  enterTest = ''
    test -f ${runtimeCheck}/result
    patchgate-harbor lifecycle
    patchgate-harbor check
  # <!-- ste-disable-next-line semicolon -->
  '';
}
