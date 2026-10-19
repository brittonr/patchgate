The `inbox` channel of the Pijul repository in `repo/` has one change.

Review it with `patchgate review` while the model server fails, and again after the server recovers. The failure must not decide about the change. After the second review, the change must be in `main`, and the ledger must have one decision about it.
