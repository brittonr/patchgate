The Pijul repository in `repo/` has two concurrent greeting changes in `inbox`. Its `greet.sh` file also has an unrecorded `echo local-only` line after the conflict.

Review both changes with `patchgate review`. The model accepts both changes and selects a merge that keeps both greetings.

Both changes and the conflict-free greeting merge must enter `main`. The merge must contain each recorded greeting once, without the local line. The accepted German change must link to the merge record in the ledger.

Preserve the complete unrecorded inbox file. The dirty file prevents the merge from entering `inbox`, but it must not prevent the safe merge into `main`. Leave the merge outside `inbox` until a human resolves the local edits.
