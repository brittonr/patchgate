# Escalate excessive complete context

The repository is `repo` in this scenario directory.
The candidate changes one row in a large nested reference file.
Its raw patch fits the review limit, but its complete native context exceeds the limit.

Review through the real gate with `PATCHGATE_MAX_CHANGE_CHARS=4000`.
The gate must escalate the candidate to a human without a model request.
Do not truncate the context or review only the small patch.
Main must retain the original file and native history.
Inbox must retain the candidate and its exact edited text.
The gate audit must not claim a model review binding.

The Rust driver counts requests at the HTTP boundary.
The verifier checks the native channel histories and archive contents.
Do not edit fixture facts, HTTP observations, or audit records.

```sh
patchgate-eval solve structured-context-limit /scenarios/structured-context-limit
```
