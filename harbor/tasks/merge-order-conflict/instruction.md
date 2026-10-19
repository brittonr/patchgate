The Pijul repository in `repo/` has two changes in its `inbox` channel. Both changes edit the same line of `greet.sh`, and neither change knew about the other. One greets in French, and the other greets in German.

Land both changes in the `main` channel. After that, `main` and `inbox` must have no conflict, and `greet.sh` in `main` must keep both greetings.

`patchgate review` can do this when a model server answers at `PATCHGATE_MODEL_URL`.
