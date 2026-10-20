{ pkgs, package }:

pkgs.runCommand "patchgate-runtime-check"
  (pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
    # The Rust model fixture uses only the loopback interface.
    # <!-- ste-disable-next-line semicolon -->
    __darwinAllowLocalNetworking = true;
  })
  ''
    work=$(${pkgs.coreutils}/bin/mktemp -d)
    export HOME="$work/home"
    export TMPDIR="$work/tmp"
    export PATCHGATE_RUNTIME_MARKER="$work/incorrect-command"
    ${pkgs.coreutils}/bin/mkdir -p "$HOME" "$TMPDIR" "$work/wrong-bin"

    # These commands must not execute, even if the application handles their errors.
    for command in pijul ssh ssh-add ssh-agent ssh-keygen
    do
      ${pkgs.coreutils}/bin/cat > "$work/wrong-bin/$command" <<'COMMAND'
    #!${pkgs.runtimeShell}
    printf '%s\n' "$0" >> "$PATCHGATE_RUNTIME_MARKER"
    exit 97
    COMMAND
      ${pkgs.coreutils}/bin/chmod +x "$work/wrong-bin/$command"
    done

    for mode in empty incorrect
    do
      directory="$work/$mode"
      ${pkgs.coreutils}/bin/mkdir -p "$directory"
      caller_path=""
      if [ "$mode" = incorrect ]
      then
        caller_path="$work/wrong-bin"
      fi

      # Change only the application environment, not the evaluator tools.
      ${pkgs.coreutils}/bin/cat > "$directory/patchgate" <<LAUNCHER
    #!${pkgs.runtimeShell}
    export PATH="$caller_path"
    exec ${package}/bin/patchgate "\$@"
    LAUNCHER
      ${pkgs.coreutils}/bin/chmod +x "$directory/patchgate"
      export PATCHGATE_BIN="$directory/patchgate"

      ${package.eval}/bin/patchgate-eval setup rust-model-merge "$directory/scenario"
      ${package.eval}/bin/patchgate-eval solve rust-model-merge "$directory/scenario" --control oracle
      ${package.eval}/bin/patchgate-eval check rust-model-merge "$directory/scenario" \
        --reward "$directory/reward.txt"

      # The check command writes a reward and does not fail on verifier errors.
      test "$(${pkgs.coreutils}/bin/cat "$directory/reward.txt")" = 1
      ${pkgs.jq}/bin/jq -e '
        .scenario == "rust-model-merge" and .reward == 1
        and .failures == [] and .verifier_error == null
      ' "$directory/patchgate-check.json"

      # Match the actual merge hash to its author in native Pijul log data.
      merge=$(${pkgs.jq}/bin/jq -r -s -e '
        map(select(.decision == "merge")) | select(length == 1) | .[0].hash
      ' "$directory/scenario/repo/.pijul/patchgate/ledger.jsonl")
      (
        cd "$directory/scenario/repo"
        # <!-- ste-disable-next-line semicolon -->
        ${import ./pijul.nix { inherit pkgs; }}/bin/pijul log --channel main --output-format json --files
      ) > "$directory/main-log.json"
      ${pkgs.jq}/bin/jq -e --arg hash "$merge" '
        map(select(.hash == $hash)) |
        length == 1 and (.[0].authors | index("patchgate") != null)
      ' "$directory/main-log.json"
      test ! -e "$PATCHGATE_RUNTIME_MARKER"
    done

    # The evaluator must inspect its own processes without caller tools.
    ${pkgs.coreutils}/bin/env -u PATCHGATE_BIN -u PATCHGATE_EVAL_UNWRAPPED_BIN \
      PATH="" ${package.eval}/bin/patchgate-eval smoke --case concurrent-review-once

    ${pkgs.coreutils}/bin/mkdir "$out"
    printf 'passed\n' > "$out/result"
  ''
