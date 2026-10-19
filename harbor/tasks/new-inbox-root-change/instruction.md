Someone made the `inbox` channel of the Pijul repository in `repo/` before `main` had a change. The inbox has the Pijul root change, a change that adds notes, and a change that adds `POLICY.md`.

Review the inbox with `patchgate review`. The root change must go into `main`. The review must then stop, because `main` has no policy for the model.

Accept the policy change as a human with `patchgate accept`, and review again. After that, `main` must have all three changes.
