# Refuse a stale policy decision

The repository is `repo` in this scenario directory.
Hold a real model review request for the notes candidate.
Use an independent Pijul command to apply the pending policy change to `main`.
Then release the old acceptance response.

The gate must return an error before it applies or records the stale decision.
A new review must use the policy from the current main channel and reject the notes.
Preserve the candidate in inbox and preserve the new policy in both channels.
One fresh model rejection must remain in the audit.

The Rust driver supplies the HTTP barrier and the independent command.
Do not edit fixture facts or audit records.

```sh
patchgate-eval solve stale-policy-review /scenarios/stale-policy-review
```
