Two authors changed the same location in `greet.sh` in the `inbox` channel of `repo/`.
One change adds `echo bonjour`. The other adds `echo hallo`.

Use `patchgate review` with the SystemOne API and a scripted local model. No model download is necessary.
The server must accept both changes through typed `review` choices before the gate merges them.
For the typed `merge` question, select the offered choice `both, side 1 first`.
Each answer must use the `answers` envelope, the `choice` type, and a valid option probability in `confidence`.

Both changes must enter `main`. Both channels must contain each greeting exactly once and must remain free of conflicts.
Preserve the policy, shell header, initial greeting, and final farewell. Do not add other files.

The ledger must contain two accepted model reviews and one model merge record.
The merge must be a real recorded change in both channels. Its ledger record must link to the accepted candidate.
