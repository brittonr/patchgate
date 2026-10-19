The `inbox` channel in `repo/` has two independent benign changes. The recovery notes precede the separate notes.

Use `patchgate review` with the SystemOne API and a scripted local model. No model download is necessary.
Test four invalid replies on the pending recovery notes: a missing answer, a wrong answer type, and probabilities of `-0.1` and `1.1`.

Use the `answers.review` envelope. The wrong type is `score`.
The probability tests use the `choice` type and select `accept`.

Each invalid reply must abort review with a nonzero exit.
Preserve both channel hash sets and the exact ledger bytes after each failure.
The failures must not let the separate notes run or receive a decision.

Then send a valid typed `accept` choice with a valid `confidence` probability for the recovery notes.
For the separate notes, send the unknown choice `unlisted-choice`. The gate must escalate that change and must not accept it.

Only the exact recovery notes and policy must enter `main`. Keep both exact changes in `inbox` without conflicts.
The ledger must contain only one model acceptance for the recovery notes and one gate escalation for the separate notes.
No failed reply may create a decision record.
