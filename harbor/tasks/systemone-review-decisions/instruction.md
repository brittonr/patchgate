The `inbox` channel in `repo/` has four independent changes.
The policy in `main` identifies three rules, `[R1]` to `[R3]`.

Use `patchgate review` with the SystemOne API and a scripted local model. No model download is necessary.
The server selects a typed choice from the actual change content.
It answers the global `review` question and one question for each identified rule.
It accepts the public notes, rejects the TODO, and escalates the request for human review.
For an accept, it also names the evidence path and one native span.

Each answer must use the `answers.<question>` envelope, the `choice` type, and a valid option probability in `confidence`.
The global verdict and the rule answers must agree with the policy.

The fourth change is ordinary text. The scripted server names a span that the change does not hold.
patchgate must escalate that change and keep the foreign span out of the ledger.

Only the public notes must enter `main`. Preserve their exact contents and the policy.
Keep all four changes and their exact contents in `inbox`. Both channels must remain free of conflicts.
The ledger must contain exactly one model decision for each change.
The accepted change must keep its two typed citations and the probability of every answer.
