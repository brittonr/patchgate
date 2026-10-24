# Review policy

patchgate sends this policy and one change to the local model. The model accepts, rejects, or escalates the change. patchgate reads this file from the main channel. A human must accept each change to this file.

## Reject the change if one of these conditions is true

1. [R1] The change adds a secret, such as a password, a token, an API key, or a private key.
2. [R2] The change adds local state or build output, such as `.devenv/`, `.direnv/`, `result`, or `__pycache__/`.
3. [R3] The change adds a large binary file or generated data.
4. [R4] The message of the change does not tell what the change does.
5. [R5] The change does two or more unrelated things. Tell the author to split the change.
6. [R6] The change removes a test or a check, and it does not replace the test or the check.

## Escalate the change if one of these conditions is true

1. [R7] You are not sure that the change is safe and correct.
2. [R8] The change removes much code, or it changes how the project builds or runs.
3. [R9] No rule in this policy applies to the change.

## Accept the change if all of these conditions are true

1. No reject rule and no escalate rule applies.
2. The change does one thing, and its message tells what that thing is.
