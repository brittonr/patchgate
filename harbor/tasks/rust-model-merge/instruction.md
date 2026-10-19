# Merge two Rust changes

The repository is `/scenarios/rust-model-merge/repo`.
Two independent authors add French and German greetings at the same place in `main.rs`.

Use the real gate to review and merge both changes.
Both channels must contain the same Rust program with no conflicts.
The program must compile and print `hello`, both new greetings in either order, and `bye`.
Keep each greeting exactly once.
The ledger must contain both model acceptances and one model merge record.

The acceptance must name the merge hash.
The merge audit must name its candidate hash and `main.rs`.
The merge change must exist in both channels.

Run `patchgate review` from the repository.
The oracle uses a Rust scripted model unless the live host command supplies an explicit model endpoint.
