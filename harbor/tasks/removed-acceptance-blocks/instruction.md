The `inbox` channel in `repo/` contains a prerequisite, its dependent extension, and an independent file.

Accept the prerequisite by hand. Use `pijul unrecord --channel main <hash>` to remove it from `main`, but retain it in `inbox`.

Review with a scripted model that accepts every change. Repeat the review. The prerequisite must not return to `main`. Its dependent must remain outside `main` without any ledger decision.

The independent change must enter `main` with one model acceptance. The prerequisite must retain only its original human acceptance. The inbox must retain all three changes and the complete extension. The removed file must remain absent from `main`.
