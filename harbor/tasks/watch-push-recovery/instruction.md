# Recover a watch process after a model outage

The Pijul repository is `/scenarios/watch-push-recovery/repo`.
Its `inbox` contains the first note.
The separate `author` repository contains a second note that is not yet in `inbox`.

Start the real `patchgate watch` command.
Hold its initial HTTP model request.
While watch remains active, push the second patch from `author` to `inbox`.
Fail the held request with HTTP 503, then restore valid model replies.
Do not restart watch or replace it with repeated review commands.
Do not use a delay to assume a command boundary.

Watch must accept both notes into `main` without loss or conflicts.
Each change must have exactly one model acceptance.
The outage must not add a decision record.
Send SIGINT after recovery. Watch must exit cleanly within three seconds.

Every error path must stop fixture child processes.
No fixture process may remain after the task.

The Rust driver supplies the request barrier, real push, recovery, and signal control:

```sh
patchgate-eval solve watch-push-recovery /scenarios/watch-push-recovery
```

The verifier checks real channel content, exact decision histories, and process lifecycle evidence.
Do not edit the ledger or fixture facts.
