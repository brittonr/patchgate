# Restore a signed merge after a process crash

The repository is in `repo/`. The working copy uses `inbox`.

Accept the French contribution by hand. Use model review to accept the German contribution and create a signed merge.
A temporary Pijul wrapper must stop the gate after the successful application to `main`, before the ledger append.
Do not add a production crash option. Kill the stopped gate process.

Restart the gate. Restore the complete acceptance record and its linked merge record exactly once.
Both channels must contain the two contributions and their merge, with no conflicts.
The greeting script must contain both new greetings. Preserve the human decision for the French contribution.

The merge must retain the gate signing identity, the candidate link, and the conflict file list.
Complete the durable transaction before the task ends.

The Rust oracle uses `patchgate-eval solve crash-restart-merge /scenarios/crash-restart-merge`.
