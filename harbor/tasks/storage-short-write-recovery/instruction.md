# Recover from partial writes

The repository is in `repo/`. The working copy uses `inbox`.

Use a Rust syscall library to write a proper byte prefix to the real temporary acceptance journal.
The next write must return EIO. The gate must return an error before it applies the candidate to `main`.
Preserve the earlier audit bytes. Retry without the fault and accept the candidate exactly once.

Repeat the partial write and next EIO at the real ledger append.
The ledger must contain actual partial record bytes after Pijul applies the second candidate to `main`.
Do not replace the ledger with an evidence file.
Restart without the fault. Complete the record from the durable transaction and preserve every existing byte and audit field.

Repeat recovery twice. Neither recovery may add duplicate records or change the accepted history.
Both channels must contain the exact expected hashes and files.
The ledger must preserve its earlier record and contain exactly one acceptance for each candidate.
The durable transaction and temporary journal must not remain.

These faults need Linux x86_64 or aarch64, procfs, rustc, a C linker, and a gate with a dynamic libc dependency.
Darwin has no native fixture. An absent prerequisite must cause an error, not acceptance.
Do not add production fault options or substitute process termination for syscall errors.

Use `patchgate-eval solve storage-short-write-recovery /scenarios/storage-short-write-recovery`.
