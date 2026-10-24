# Review identified rules and native evidence

The cases are in `/scenarios/rust-model-rules/cases`.
Each repository contains one candidate and a trusted policy with three rule IDs.
Two cases need acceptance, one needs rejection, and one needs human review.

Both accept candidates change the same two paths and have the same message.
Their trusted policies name different paths as decisive evidence.
Each target path has multiple native add and delete spans.
Select the policy target and its added approval status, not the timestamp change.

Use the real gate for every case.
Do not change policies, candidates, facts, or audit records.
The verifier checks exact histories, file bytes, rule labels, probabilities, and native citation origins.

Run `patchgate-eval solve rust-model-rules /scenarios/rust-model-rules`.
The Rust oracle needs no external endpoint.
A live run needs the SystemOne API, an endpoint, and explicit model revision metadata.
The report retains every request and response with latency and native audit evidence.
