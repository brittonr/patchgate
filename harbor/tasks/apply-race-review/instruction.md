# Refuse a stale review at native application

The repository is in `repo/`. The working copy uses `inbox`.

Accept the seed contribution by hand. Preserve its complete audit record.
Use model review for the notes candidate.
A temporary Pijul wrapper must intercept the final `apply --channel main` after the gate prepares its durable acceptance journal.
Before the native application, advance `main` through an independent real Pijul command.
Do not replace native application with a mock or add a production test option.

The stale candidate must remain outside `main`. Preserve the external content, inbox files, and exact existing ledger bytes.
The gate can cancel the journal after an explicit native refusal.
Use a normal gate command to confirm journal recovery without an acceptance record.
Retry review against fresh `main`. Complete exactly one model acceptance with current native review evidence.

Both channels must contain the seed, external update, and notes candidate without conflicts.
A repeat review must preserve the exact completed audit bytes. The final journal must be absent.

The Rust oracle uses `patchgate-eval solve apply-race-review /scenarios/apply-race-review`.
