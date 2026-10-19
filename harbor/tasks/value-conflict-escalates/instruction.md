The Pijul repository in `repo/` has two changes in its `inbox` channel. One change sets the port in `server.conf` to 8080, and the other change sets it to 9090. Neither change knew about the other.

Review the inbox with `patchgate review`. The two sides replace the same line with different values, so only a human can choose a value. The first change must go into `main`. patchgate must escalate the second change without a merge, even when the model asks to keep the value of the change under review.
