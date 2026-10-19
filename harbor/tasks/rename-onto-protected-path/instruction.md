patchgate protects the path `devenv.nix` in this task. The `inbox` channel of the Pijul repository in `repo/` adds `draft.nix` in one change, and moves it to `devenv.nix` in the next change.

Review the inbox with `patchgate review` and `PATCHGATE_PROTECTED=devenv.nix`. The first change must go into `main`. The move must go to a human, because it puts a file on the protected path.
