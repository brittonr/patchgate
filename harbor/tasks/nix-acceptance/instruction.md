# Accept the verified merged source

The repository is `repo` in this scenario directory.
Accept the French contribution by human decision.
Then review and merge the German contribution through the real gate.

Both checks must use a real Nix sandbox.
The final program must preserve both greetings exactly once.
The audit must bind candidates, the merge, native main state, exact source, trusted definitions, pinned inputs, derivations, and outputs.

Run `patchgate-eval solve nix-acceptance /scenarios/nix-acceptance`.
Do not edit the audit or fixture facts.
