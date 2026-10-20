# Refuse a sandbox exception

The repository is `repo` in this scenario directory.
The trusted definition requests `__noChroot = true`.
Try acceptance through the real Nix client.

The gate must reject this exception before builder execution.
Preserve the exact main state and all earlier audit bytes.
Do not write an acceptance record or leave an acceptance journal.

Run `patchgate-eval solve nix-sandbox-exception /scenarios/nix-sandbox-exception`.
Do not replace Nix or edit the audit or fixture facts.
