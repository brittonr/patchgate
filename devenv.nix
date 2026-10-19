{
  pkgs,
  lib,
  config,
  ...
}:

{
  # Pijul is the version control system. Python runs patchgate.
  # <!-- ste-disable-next-line semicolon -->
  packages = [ pkgs.pijul ];
  # <!-- ste-disable-next-line semicolon -->
  languages.python.enable = true;

  # patchgate sends each change to a model server with an OpenAI-compatible API.
  # LM Studio gives this API on port 1234. Ollama and llama.cpp also give it.
  # <!-- ste-disable-next-line semicolon -->
  env.PATCHGATE_MODEL_URL = "http://127.0.0.1:1234/v1";
  # <!-- ste-disable-next-line semicolon -->
  env.PATCHGATE_MODEL = "google/gemma-4-e4b";
  # These files control the gate. A human must accept each change to them.
  # patchgate always protects POLICY.md.
  # <!-- ste-disable-next-line semicolon -->
  env.PATCHGATE_PROTECTED = "patchgate.py,devenv.nix,devenv.yaml,devenv.lock,.envrc";

  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate.description = "Let the local model merge conflicting inbox changes and decide which changes go into main";

  # The gate signs its merges with its own key in a private ssh-agent.
  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate.packages = [ pkgs.openssh ];
  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate.exec = ''exec python3 "$DEVENV_ROOT/patchgate.py" "$@"'';

  # `devenv up` runs the gate. `devenv test` does not run it, because the gate changes main.
  # <!-- ste-disable-next-line semicolon -->
  processes.patchgate = lib.mkIf (!config.devenv.isTesting) { exec = "patchgate watch"; };

  # `patchgate-harbor` runs the Harbor tasks in harbor/tasks with Docker, in the Colima profile patchgate.
  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate-harbor.description = "Run the Harbor tasks of patchgate in Docker, or compare the control agents with check";

  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate-harbor.packages = [ pkgs.colima pkgs.docker-client pkgs.uv ];

  # The Compose and Buildx plugins and the Python 3.12 of Harbor come from Nix.
  # <!-- ste-disable-next-line semicolon -->
  scripts.patchgate-harbor.exec = ''PATCHGATE_DOCKER_PLUGINS=${pkgs.docker-compose}/libexec/docker/cli-plugins:${pkgs.docker-buildx}/libexec/docker/cli-plugins PATCHGATE_HARBOR_PYTHON=${pkgs.python312}/bin/python3.12 exec python3 "$DEVENV_ROOT/harbor/controls.py" "$@"'';

  # `devenv test` runs each Harbor task with the oracle agent and with the nop agent.
  # The oracle must get reward 1, and the nop agent must get reward 0.
  # <!-- ste-disable-next-line semicolon -->
  enterTest = "patchgate-harbor check";
}
