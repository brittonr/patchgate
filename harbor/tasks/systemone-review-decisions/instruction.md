The `inbox` channel in `repo/` has three independent changes.

Use `patchgate review` with the SystemOne API and a scripted local model. No model download is necessary.
The server selects a typed choice from the actual change content.
It accepts the public notes, rejects the secret, and escalates the request for human review.
Each answer must use the `answers.review` envelope, the `choice` type, and a valid option probability in `confidence`.

Only the public notes must enter `main`. Preserve their exact contents and the policy.
Keep all three changes and their exact contents in `inbox`. Both channels must remain free of conflicts.
The ledger must contain exactly one model decision for each change: accept, reject, and escalate.
