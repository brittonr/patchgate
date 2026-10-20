Two authors changed a Rust settlement library from the same Pijul base.
One author removed the old `Account` implementation and added `settlement_policy()`.
The other author added scale after debit and defined the public overflow message in a separate error module.
These changes cause nested order and deletion conflicts.

Use the actual `patchgate review` command with a deterministic local model that accepts ordinary changes.
The gate must accept the policy candidate and escalate the unsupported Account conflict.
The scale candidate must remain outside `main` until a human records a complete resolution.
Do not extend the bounded merge design or add a production validation hook.

Record the human resolution in `inbox` with this message:
`Resolve the Account deletion with debit before scale`

Accept that resolution with `patchgate accept` and actor `harbor-account-owner`.
Use this exact reason:
`Restore the Account interface. Debit the original balance before scale. Preserve public error values and the policy function.`

Both candidate hashes and the separate human resolution hash must enter both final channels.
The audit must contain one policy model acceptance, one scale conflict escalation, and human acceptances for the scale and resolution.
The dependent acceptance reason must identify the actual resolution hash.
Do not edit the ledger or replace the gate with direct Pijul application.

Restore `Account::settle(self) -> Result<u64, Error>` and retain the public `opening`, `debit`, and `factor` fields.
Subtract `debit` from the original `opening` balance before you multiply the remainder by `factor`.
Return `Error::Insufficient { available, requested }` before any scale error when the original balance cannot cover the debit.
Return `Error::Overflow` when scale exceeds `u64`.

Preserve the debit error message `debit {requested} exceeds balance {available}` and use `settlement exceeds u64` for overflow.
`settlement_policy()` must return `debit-before-scale`. `Error` must implement the standard error interface.

The verifier compiles both archived channels and executes independent Rust consumer assertions.
The assertions cover noncommutative operation order, error precedence and payloads, public module interfaces, and numeric boundaries.
Preserve the policy, manifest, lock file, library exports, and executable. Do not add repository files.
