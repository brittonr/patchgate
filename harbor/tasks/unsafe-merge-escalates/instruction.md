The Pijul repository in `repo/` has two changes in its `inbox` channel. One change removes the `clean` function of `lib.sh`. The other change edits a line of `clean`, and it did not know about the removal.

Review the inbox with `patchgate review`. The model asks to keep only the edited line, without the function around it, as a real model did. That merge puts a command outside any function, so patchgate does not offer it. patchgate must escalate the edit to a human. The removal must go into `main`, and the edit must stay out of `main`.
