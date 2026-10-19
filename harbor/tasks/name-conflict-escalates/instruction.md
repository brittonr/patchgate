Two changes in the `inbox` channel of the Pijul repository in `repo/` add a file with the same name, `notes.md`.

Review the inbox with `patchgate review`. patchgate must apply the first change to `main`. It must escalate the second change to a human, because the model merges only conflicts between lines.
