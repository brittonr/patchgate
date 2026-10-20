# Refuse a stale recorded merge at native application

The repository is in `repo/`. The working copy uses `inbox`.

Accept the French contribution by hand. Preserve its complete audit record.
Use model review for the German contribution and record a merge that preserves both greetings.
A temporary Pijul wrapper must intercept the final `apply --channel main` after the gate prepares its durable acceptance journal.
Before the native application, advance `main` through an independent real Pijul command.
Do not replace native application with a mock or add a production test option.

The stale candidate and recorded merge must remain outside `main`. The stale merge must also remain outside `inbox`.
Preserve the external content, inbox files, and exact existing ledger bytes.
The gate can cancel the journal after an explicit native refusal.
Use a normal gate command to confirm journal recovery without an acceptance or merge audit record.

Retry review against fresh `main`. Complete exactly one model acceptance and its linked merge record.

Both channels must contain the external update, both greetings, and the gate-authored merge without conflicts.
Preserve the candidate link and conflict file list. A repeat review must preserve the exact audit bytes.
The final journal must be absent.

The Rust oracle uses `patchgate-eval solve apply-race-merge /scenarios/apply-race-merge`.
