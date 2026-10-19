The Pijul repository in `repo/` has two changes in its `inbox` channel. One change removes the `clean` function of `lib.sh`. The other change edits a line of `clean`, so that it also removes the `dist` directory, and it did not know about the removal.

Land both changes in the `main` channel. The edit wins, so `lib.sh` in `main` must have the `clean` function with the line `rm -rf build dist`. After that, `main` and `inbox` must have no conflict.

`patchgate review` can do this when a model server answers at `PATCHGATE_MODEL_URL`.
