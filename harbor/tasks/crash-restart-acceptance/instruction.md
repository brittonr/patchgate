# Restore acceptance records after a process crash

The repository is in `repo/`. The working copy uses `inbox`.

Accept the normal content change through model review. Stop the gate after Pijul applies the change to `main`, but before the ledger append.
Use a temporary Pijul wrapper. Do not add a production crash option.
Kill the stopped gate process. Restart the gate and restore the complete acceptance record.

Repeat this crash and recovery path for the policy revision with an explicit human acceptance.
Both changes must remain in `main` and `inbox`. The files must match the accepted content.
The ledger must contain one model acceptance and one human acceptance, with no duplicate decisions.
Preserve the earlier policy escalation. Complete the durable transaction before the task ends.

The Rust oracle uses `patchgate-eval solve crash-restart-acceptance /scenarios/crash-restart-acceptance`.
