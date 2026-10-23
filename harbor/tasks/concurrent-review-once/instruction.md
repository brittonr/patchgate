# Review one repository with concurrent commands

The Pijul repository is `/scenarios/concurrent-review-once/repo`.
Three changes await review in `inbox`.
Two changes add independent notes.
A protected change adds `release.txt` and needs a human decision.

Use two real `patchgate review` processes against this repository.
Hold an actual HTTP model request until both reviewers and the human acceptance command exist at the same time.
Do not use a delay to assume process overlap.
Accept the protected change as `harbor-owner` with this exact reason:
`The owner approves the protected release note.`

Both channels must retain all three patches and their exact content.
Each patch must have one final acceptance.
The protected patch must retain its initial gate escalation and later human acceptance.
A repeat review must preserve every ledger field.
A concurrent command can refuse a stale state with a nonzero exit.
Repeat a refused human acceptance after the concurrent commands finish.
Run a recovery review before the repeat review.
Each recovery command and the repeat review must return zero.
All commands must leave no fixture processes.

The Rust driver supplies the HTTP barrier and process cleanup:

```sh
patchgate-eval solve concurrent-review-once /scenarios/concurrent-review-once
```

The verifier checks real channel content, exact decision histories, and process lifecycle evidence.
Do not edit the ledger or fixture facts.
