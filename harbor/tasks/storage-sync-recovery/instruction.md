# Recover from sync errors

The repository is in `repo/`. The working copy uses `inbox`.

Inject EIO through a Rust syscall library when the gate syncs its complete temporary acceptance journal.
The gate must return an error before it applies the candidate to `main`.
The earlier audit bytes must remain unchanged. Retry without the fault and accept the candidate exactly once.

Inject EIO again when the gate syncs the complete second acceptance in the real ledger.
Do not fail the earlier ledger sync before Pijul application.
This fault must occur after Pijul applies the candidate to `main` and writes the complete audit record.
Restart the gate without the fault. Preserve every byte and audit field from the durable transaction.

Repeat recovery twice. Neither recovery may add duplicate records or change the accepted history.
Both channels must contain the exact expected hashes and files.
The ledger must preserve its earlier record and contain exactly one acceptance for each candidate.
The durable transaction and temporary journal must not remain.

These faults need Linux x86_64 or aarch64, procfs, rustc, a C linker, and a gate with a dynamic libc dependency.
Darwin has no native fixture. An absent prerequisite must cause an error, not acceptance.
Do not add production fault options or substitute process termination for syscall errors.

Use `patchgate-eval solve storage-sync-recovery /scenarios/storage-sync-recovery`.
