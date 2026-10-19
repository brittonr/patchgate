The Pijul repository in `repo/` has two changes in its `inbox` channel that conflict in `greet.sh`. One greets in French, and the other greets in German.

Run `patchgate review`. The model does not merge this conflict, so patchgate escalates the German change to a human. The owner keeps only the German greeting. Record that resolution in `inbox`, and accept it with `patchgate accept`.

After that, `main` must have both changes and no conflict, and `greet.sh` in `main` must greet only in German.
