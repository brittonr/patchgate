# Interrupt watch during a real Nix build

The repository is `repo` in this scenario directory.
Start watch and wait for the real sandbox builder marker.
Send SIGINT to the gate process.

Watch must stop with exit 130 within three seconds.
Preserve main and every earlier audit byte.
Do not leave a candidate acceptance or acceptance journal.

Run `patchgate-eval solve nix-interrupt /scenarios/nix-interrupt`.
Do not replace Nix or edit the audit or fixture facts.
