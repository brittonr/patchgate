# Recover from disk-full errors

The repository is in `repo/`. The working copy uses `inbox`.

Inject ENOSPC through a Rust syscall library when the gate writes its temporary acceptance journal.
The gate must return an error before it applies the candidate to `main`.
The earlier audit bytes must remain unchanged. Retry without the fault and accept the candidate exactly once.

Inject ENOSPC again when the gate appends the second acceptance to the real ledger.
This fault must occur after Pijul applies the candidate to `main`.
Restart the gate without the fault. Restore every audit field from the durable transaction.
Repeat recovery twice. Neither recovery may add duplicate records or change the accepted history.

Both channels must contain the exact expected hashes and files.
The ledger must preserve its earlier record and contain exactly one acceptance for each candidate.
The durable transaction and temporary journal must not remain.

These faults need Linux x86_64 or aarch64, procfs, rustc, a C linker, and a gate with a dynamic libc dependency.
Darwin has no native fixture. An absent prerequisite must cause an error, not acceptance.
Do not add production fault options or substitute process termination for syscall errors.

Use `patchgate-eval solve storage-full-recovery /scenarios/storage-full-recovery`.
