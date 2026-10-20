The `repo` directory contains a fixed-seed Pijul dependency graph on `inbox`.
The graph has a deep chain, a diamond, a three-parent join, and separate branches.
`facts.json` lists the initial `main` hashes in `base`.
Each `nodes` object has an `id`, a `hash`, and direct prerequisite hashes in `parents`.
The fixture checks these edges against actual Pijul change dependencies.

Use the actual `patchgate review` command and a local model endpoint to accept all nodes.
A local scripted endpoint is enough.
First, attempt human acceptance of `triple-join` while its prerequisites are absent.
The command must fail without changes to either channel, files, or audit records.

Both channels must contain the exact base and graph closure, with each hash once.
Preserve every graph file and its exact contents.
Each graph node must have exactly one model acceptance record.
Repeat review at least three times after the first review.
Repeated review must not change repository state or decision histories.

After review, human acceptance of `root` and `triple-join` must fail because both changes are already in `main`.
These refusals must not change either channel or its audit records.
Do not write audit records directly or add repository files.
The optional task artifact `model-metrics.json` is not repository state and cannot prove graph acceptance.
