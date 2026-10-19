The `inbox` channel of the Pijul repository in `repo/` has one change with more than 3000 characters.

Review it with `patchgate review` and `PATCHGATE_MAX_CHANGE_CHARS=1000`. patchgate must escalate the change without the model, and the change must stay out of `main`.
