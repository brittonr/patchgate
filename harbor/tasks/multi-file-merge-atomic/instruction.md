The Pijul repository in `repo/` has two concurrent changes in `inbox`. Each change adds a greeting to both `a.sh` and `z.sh`.

Review both changes with `patchgate review`. The model accepts both changes for review. It offers to keep both greetings in `a.sh`, but escalates the conflict in `z.sh`.

The first change must enter `main`. The second change must remain outside `main`, with one conflict escalation by the gate. Both files in `main` must contain only the first greeting. No partial resolution or merge record can enter `main` or the ledger. Preserve both changes in `inbox`.
