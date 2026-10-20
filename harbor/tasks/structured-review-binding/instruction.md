# Bind decisions to native review state

The repository is `repo` in this scenario directory.
Accept both dependent release changes through the real gate.
The main archive must expose the second release text.

Each request must bind the actual candidate hash and the exact policy SHA-256 digest.
Preserve all policy whitespace in the digest.
Use the native main state at HTTP request time.
The second request must observe the native state after the first acceptance.
Each model audit must retain that exact review binding.

The Rust driver observes native state at the HTTP boundary.
The verifier also compares audit states with independent native snapshots.
False policy and main-state bindings must fail the verifier without an exception.
Do not edit fixture facts, HTTP observations, or audit records.

```sh
patchgate-eval solve structured-review-binding /scenarios/structured-review-binding
```
