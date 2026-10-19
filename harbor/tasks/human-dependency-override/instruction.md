The `inbox` channel in `repo/` contains a secret prerequisite and an extension that depends on it.

Use a scripted model to reject the prerequisite. The dependent must remain outside `main` without a decision.

Try to accept the dependent by hand before its prerequisite. The command must fail and preserve both channel hash sets and all ledger bytes.

Accept the prerequisite by hand. Then use normal model review to accept the dependent. Repeat review to check that acceptance occurs only once.

Both changes must remain in both channels. The prerequisite history must contain a model rejection, then human acceptance. The dependent must have exactly one model acceptance. The file in `main` must contain the complete extension.
