The `repo` directory contains a fixed-seed Pijul dependency graph on `inbox`.
The graph has a deep chain, a diamond, a three-parent join, and separate branches.
`facts.json` lists base hashes and graph nodes with `id`, `hash`, and `parents` fields.
The fixture checks every edge against actual Pijul change dependencies.

First, attempt human acceptance of `triple-join` while its prerequisites are absent.
The command must fail without repository or audit changes.
Use `patchgate accept` to accept `root` by hand.
Use `pijul unrecord --channel main <root hash>` to remove that root from `main` only.
Preserve its original human acceptance record and the complete graph on `inbox`.

Use the actual `patchgate review` command and a local model endpoint.
A local scripted endpoint is enough.
Review must not restore `root` or admit any of its descendants.
Every descendant must have no decision record.
All independent nodes must enter `main`, each with exactly one model acceptance.
The separate `side-root` node must enter `main`, although `triple-join` stays blocked.

Repeat review at least three times after the first review without state or history changes.
Attempt human acceptance of every blocked descendant.
Each command must fail without changes to channels, files, or audit records.
A later review must not admit any blocked node or add a duplicate decision.
Both channels must have exactly their expected hashes, files, and contents.
Do not write audit records directly or add repository files.
