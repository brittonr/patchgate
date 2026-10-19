The Pijul repository in `repo/` has two concurrent greeting changes in `inbox`. One adds French, and the other adds German.

Review both changes with `patchgate review`. The model accepts each change, but its server fails when the gate requests a merge. The failed merge must leave `main` and the ledger unchanged from the first accepted change.

Restore the model server, then review again. Both changes and both greetings must enter `main`, without duplicate lines or conflicts. The failed merge must not create a decision for the German change. Its eventual acceptance must link to one greeting merge in the ledger. That merge must reach both `main` and `inbox`.
