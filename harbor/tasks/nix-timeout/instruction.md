# Enforce the real build deadline

The repository is `repo` in this scenario directory.
The trusted check starts a real sandbox build with a long delay.
Try acceptance with a six-second check deadline.

The builder must start before the deadline expires.
The command must return failure without candidate acceptance.
Preserve the exact main state and all earlier audit bytes.

Run `patchgate-eval solve nix-timeout /scenarios/nix-timeout`.
Do not replace Nix or edit the audit or fixture facts.
