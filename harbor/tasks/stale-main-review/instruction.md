# Refuse a stale main snapshot

The repository is `repo` in this scenario directory.
Hold a real model review request for the notes candidate.
Use an independent Pijul command to apply the pending epoch change to `main`.
Then release the old acceptance response.

The gate must return an error before it applies or records the stale decision.
A new review must accept the notes against the current main channel.
Both channels must retain the independent update and the candidate.
One fresh model acceptance must remain in the audit.

The Rust driver supplies the HTTP barrier and the independent command.
Do not edit fixture facts or audit records.

```sh
patchgate-eval solve stale-main-review /scenarios/stale-main-review
```
