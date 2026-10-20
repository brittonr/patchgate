# Refuse a merge against stale main

The repository is `repo` in this scenario directory.
Review both concurrent greeting changes with the real gate.
Hold the actual model merge request.
Use an independent Pijul command to apply the epoch change to `main`.
Then release the old merge choice.

The gate must return an error without application of the second candidate or stale merge.
Preserve the audit bytes from before the independent change.
A new review must produce one fresh merge against the current main channel.
Both channels must preserve both greetings and the epoch update.
The audit must contain two model acceptances and one linked model merge.

The Rust driver supplies the HTTP barrier and the independent command.
Do not edit fixture facts or audit records.

```sh
patchgate-eval solve stale-main-merge /scenarios/stale-main-merge
```
