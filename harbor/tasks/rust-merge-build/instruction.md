Two authors changed `repo/src/lib.rs` from the same base on the `inbox` channel.
One author removed the old `Parcel` implementation and added `route_label()`.
The other author changed the shipping rate from two to three per weight unit.
These changes cause nested order and deletion conflicts.

Use the actual `patchgate review` command with a scripted local model that accepts ordinary changes.
The gate must escalate the nested conflict. The rate change must remain outside `main` until a human resolves it.
The route change must enter `main` through one model acceptance.

Record a human resolution in `inbox` that restores the complete implementation with the new rate and retains the route label.
Accept that resolution with `patchgate accept`.
Both candidate hashes and the separate human resolution must enter `main` and `inbox`.
Both channels must remain free of conflicts.
The ledger must contain the route model acceptance, the rate conflict escalation, and human acceptances for the rate and resolution.
Do not replace the gate with direct ledger edits.

The merged Rust program must compile offline and pass the verifier-owned Rust tests on both channels.
Preserve the complete `Parcel` structure and its implementation.
`shipping_cost()` must calculate `weight * 3 + zones`.
`route_label()` must return `tracked`. `label()` and the executable must still return or print `parcel`.

Preserve the package manifest, lock file, entry point, and policy. Do not add repository files.
