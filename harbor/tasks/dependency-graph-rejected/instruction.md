The `repo` directory contains a fixed-seed Pijul dependency graph on `inbox`.
The graph has a deep chain, a diamond, a three-parent join, and separate branches.
`facts.json` lists base hashes and graph nodes with `id`, `hash`, and `parents` fields.
The fixture checks every edge against actual Pijul change dependencies.

The `root` node adds a secret and must receive one model rejection.
Use the actual `patchgate review` command and a local model endpoint.
A local scripted endpoint is enough.
Before review, attempt human acceptance of `triple-join` while its prerequisites are absent.
The command must fail without repository or audit changes.

Every descendant of `root` must stay outside `main` and have no decision record.
All independent nodes must enter `main`, each with exactly one model acceptance.
The separate `side-root` node must enter `main`, although `triple-join` stays blocked.
The exact base and all graph nodes must remain on `inbox`.
Both channels must have exactly their expected hashes, files, and contents.

Repeat review at least three times after the first review without state or history changes.
Attempt human acceptance of every blocked descendant.
Each command must fail without changes to channels, files, or audit records.
A later review must not admit any blocked node or add a duplicate decision.
Do not replace the gate with direct audit edits or add repository files.
