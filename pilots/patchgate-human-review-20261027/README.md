# Native pilot review sheet

This sheet covers two genuine native Pijul changes.
It contains case identifiers and candidate hashes, not captured source or local filesystem paths.
All human decisions, reasons, and measurements remain empty.
`routine` is a declared workload classification, not verified evidence.

## Private case access

A Git clone does not include the native case store.
Use the original Pijul repository or a private review packet to examine these cases.
Do not publish captured source or native metadata with this sheet.
Copy `reviews.csv` to private storage before you enter human measurements.

The local CLI can display each captured case without a model request:

```console
patchgate cases show 1aeeb6ee7aaba5aec26965b8f2e25b5a1745ae4c775a723ddbdc45c4e4b8b9f6
patchgate cases show 907caa389c77b5441e2fa0fc03d3bbf6384995c5c0f0ac4dc5bed2e97b911a74
```

## Independent baseline

1. Start a stopwatch before you examine each case. Pause it for interruptions.
2. Read the captured policy and source before any model output for that case.
3. Enter `accept`, `reject`, or `escalate` in `baseline_decision`.
4. Enter your actual reason in `baseline_reason` and active review seconds in `baseline_seconds`.
5. Enter `true` in `independent_baseline` only if you saw no model output for that case.
6. Run `patchgate cases label` with your case ID, decision, reason, and `--json`.
7. Copy the recorded label `user` into `reviewer` and its exact `time` into `label_time`.

Record both labels before any shadow replay.
Leave `assisted_seconds`, `correction_seconds`, `assisted_decision`, and `final_decision` empty until the corresponding human review and correction steps end.
Do not replace an unknown value with zero.
No assistant decision, command duration, or model latency can replace human review effort.

## Pilot evaluation

Resolve the selected model service before the real shadow replay.
Do not change models or resource limits to bypass a failure.
Export the labeled cases, then run the isolated replay.
Record the actual effort and decisions from the human review and correction steps.

This CSV is an intake sheet, not a `--measurements` artifact.
Create the evaluator measurement JSON after the real replay.
Use its exact SHA-256 digest and variant ID.
Copy only the documented measurement fields into the evaluator input.
Omit unknown values from that JSON. Do not insert `null`.

`candidate`, `baseline_decision`, and `baseline_reason` are CSV fields, not evaluator measurement fields.
The [pilot documentation](../../README.md#practical-value-pilot-reports) defines the complete measurement contract and evidence limits.

This sheet supplies no acceptance authority or pilot metrics.
It does not assert human identity, model identity, or reviewer independence.
