use super::*;

#[derive(clap::Args)]
pub struct PilotArgs {
    /// The replay report with captured native cases.
    pub replay: PathBuf,
    /// Explicit human effort and workload data for one variant.
    #[arg(long)]
    pub measurements: PathBuf,
    /// Write a new private report outside source repositories.
    #[arg(long)]
    pub report: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Measurements {
    schema_version: u32,
    replay_sha256: String,
    variant_id: String,
    reviews: Vec<Review>,
}

fn explicit_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Workload {
    Routine,
    Synthetic,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    case_id: String,
    #[serde(default, deserialize_with = "explicit_option")]
    workload: Option<Workload>,
    #[serde(default, deserialize_with = "explicit_option")]
    independent_baseline: Option<bool>,
    #[serde(default, deserialize_with = "explicit_option")]
    reviewer: Option<String>,
    #[serde(default, deserialize_with = "explicit_option")]
    label_time: Option<String>,
    #[serde(default, deserialize_with = "explicit_option")]
    baseline_seconds: Option<f64>,
    #[serde(default, deserialize_with = "explicit_option")]
    assisted_seconds: Option<f64>,
    #[serde(default, deserialize_with = "explicit_option")]
    correction_seconds: Option<f64>,
    #[serde(default, deserialize_with = "explicit_option")]
    assisted_decision: Option<Label>,
    #[serde(default, deserialize_with = "explicit_option")]
    final_decision: Option<Label>,
}

#[derive(Serialize)]
struct Blocker {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_id: Option<String>,
}

#[derive(Serialize)]
struct CaseEvidence {
    case_id: String,
    capture_identity: Option<String>,
    workload: Option<Workload>,
    excluded_synthetic: bool,
    expected: Label,
    tool_decision: Option<Label>,
    assisted_decision: Option<Label>,
    final_decision: Option<Label>,
    independent_baseline: Option<bool>,
    reviewer: Option<String>,
    label_time: Option<String>,
    baseline_seconds: Option<f64>,
    assisted_seconds: Option<f64>,
    correction_seconds: Option<f64>,
    blockers: Vec<&'static str>,
}

#[derive(Default, Serialize)]
struct Metrics {
    completed_routine_reviews: usize,
    unsafe_acceptances: usize,
    missed_policy_violations: usize,
    unnecessary_escalations: usize,
    label_mismatches: usize,
    decision_corrections: usize,
    final_label_mismatches: usize,
    human_baseline_seconds: f64,
    assisted_human_seconds: f64,
    human_correction_seconds: f64,
    net_human_seconds_saved: f64,
}

#[derive(Serialize)]
struct PilotReport {
    schema_version: u32,
    authorizes_acceptance: bool,
    status: &'static str,
    evidence_scope: &'static str,
    human_identity_verified: bool,
    workload_provenance_verified: bool,
    model_identity_verified: bool,
    replay_sha256: String,
    measurements_sha256: String,
    variant_id: String,
    selected_cases: Vec<String>,
    routine_cases: Vec<String>,
    excluded_synthetic_cases: Vec<String>,
    cases: Vec<CaseEvidence>,
    blockers: Vec<Blocker>,
    metrics: Option<Metrics>,
}

fn safe_text(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.chars().any(char::is_control)
        && crate::secrets::scan_text("[pilot]", value.as_bytes()).is_empty()
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse_measurements(
    bytes: &[u8],
    replay_digest: &str,
    manifest: &Manifest,
) -> Result<Measurements> {
    let measurements: Measurements = serde_json::from_slice(bytes)
        .map_err(|_| anyhow!("The pilot measurements have invalid fields."))?;
    ensure!(
        measurements.schema_version == 1,
        "The pilot measurement version is not supported."
    );
    ensure!(
        crate::release_policy::valid_digest(&measurements.replay_sha256)
            && measurements.replay_sha256 == replay_digest,
        "The pilot measurements do not match the replay digest."
    );
    ensure!(
        safe_text(&measurements.variant_id)
            && manifest
                .variants
                .iter()
                .any(|variant| variant.id == measurements.variant_id),
        "The pilot variant does not match the replay."
    );
    let mut unique = BTreeSet::new();
    let cases: BTreeMap<_, _> = manifest
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect();
    for review in &measurements.reviews {
        ensure!(
            safe_text(&review.case_id),
            "The pilot case identifier is not safe."
        );
        ensure!(
            unique.insert(&review.case_id),
            "The pilot measurements repeat a case."
        );
        let case = cases
            .get(review.case_id.as_str())
            .ok_or_else(|| anyhow!("The pilot measurements name an unknown case."))?;
        for text in [review.reviewer.as_deref(), review.label_time.as_deref()]
            .into_iter()
            .flatten()
        {
            ensure!(safe_text(text), "The pilot human metadata is not safe.");
        }
        if let Some(time) = &review.label_time {
            ensure!(
                chrono::DateTime::parse_from_rfc3339(time).is_ok(),
                "The pilot label time is not valid."
            );
        }
        if let Some(reviewer) = &review.reviewer {
            ensure!(
                case.labels.last().and_then(|label| label["user"].as_str())
                    == Some(reviewer.as_str()),
                "The pilot reviewer differs from the captured human label."
            );
        }
        if let Some(time) = &review.label_time {
            ensure!(
                case.labels.last().and_then(|label| label["time"].as_str()) == Some(time.as_str()),
                "The pilot label time differs from the captured human label."
            );
        }
        ensure!(
            review
                .baseline_seconds
                .is_none_or(|seconds| seconds.is_finite() && seconds > 0.0),
            "The pilot baseline effort must be finite and positive."
        );
        ensure!(
            [review.assisted_seconds, review.correction_seconds]
                .into_iter()
                .flatten()
                .all(|seconds| seconds.is_finite() && seconds >= 0.0),
            "The pilot assisted effort must be finite and nonnegative."
        );
    }
    Ok(measurements)
}

fn collect_metrics(cases: &[CaseEvidence]) -> Result<Metrics> {
    let mut metrics = Metrics::default();
    for case in cases
        .iter()
        .filter(|case| case.workload == Some(Workload::Routine))
    {
        let actual = case
            .tool_decision
            .ok_or_else(|| anyhow!("The pilot routine evidence is incomplete."))?;
        let assisted = case
            .assisted_decision
            .ok_or_else(|| anyhow!("The pilot routine evidence is incomplete."))?;
        let final_decision = case
            .final_decision
            .ok_or_else(|| anyhow!("The pilot routine evidence is incomplete."))?;
        metrics.completed_routine_reviews += 1;
        metrics.unsafe_acceptances +=
            usize::from(actual == Label::Accept && case.expected != Label::Accept);
        metrics.missed_policy_violations +=
            usize::from(actual == Label::Accept && case.expected == Label::Reject);
        metrics.unnecessary_escalations +=
            usize::from(actual == Label::Escalate && case.expected == Label::Accept);
        metrics.label_mismatches += usize::from(actual != case.expected);
        metrics.decision_corrections += usize::from(assisted != final_decision);
        metrics.final_label_mismatches += usize::from(final_decision != case.expected);
        metrics.human_baseline_seconds += case
            .baseline_seconds
            .ok_or_else(|| anyhow!("The pilot routine evidence is incomplete."))?;
        metrics.assisted_human_seconds += case
            .assisted_seconds
            .ok_or_else(|| anyhow!("The pilot routine evidence is incomplete."))?;
        metrics.human_correction_seconds += case
            .correction_seconds
            .ok_or_else(|| anyhow!("The pilot routine evidence is incomplete."))?;
        ensure!(
            [
                metrics.human_baseline_seconds,
                metrics.assisted_human_seconds,
                metrics.human_correction_seconds,
            ]
            .into_iter()
            .all(f64::is_finite),
            "The pilot effort total exceeds the numeric range."
        );
    }
    metrics.net_human_seconds_saved = metrics.human_baseline_seconds
        - metrics.assisted_human_seconds
        - metrics.human_correction_seconds;
    ensure!(
        metrics.net_human_seconds_saved.is_finite(),
        "The pilot effort total exceeds the numeric range."
    );
    Ok(metrics)
}

fn evaluate(replay_bytes: &[u8], measurement_bytes: &[u8]) -> Result<(PilotReport, Vec<PathBuf>)> {
    let replay = read_pilot_replay(replay_bytes)
        .map_err(|_| anyhow!("The pilot replay artifact is not valid."))?;
    let replay_sha256 = digest(replay_bytes);
    let measurements = parse_measurements(measurement_bytes, &replay_sha256, &replay.manifest)?;
    ensure!(
        replay.manifest.cases.iter().all(|case| safe_text(&case.id)),
        "The pilot replay case identifiers are not safe."
    );
    let started_at = replay
        .started_at
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|_| anyhow!("The pilot replay start time is not valid."))?;
    let reviews: BTreeMap<_, _> = measurements
        .reviews
        .iter()
        .map(|review| (review.case_id.as_str(), review))
        .collect();
    let comparisons: BTreeMap<_, _> = replay
        .comparisons
        .iter()
        .filter(|row| row.variant_id == measurements.variant_id)
        .map(|row| (row.case_id.as_str(), row))
        .collect();
    let mut cases = Vec::with_capacity(replay.manifest.cases.len());
    let mut identities = BTreeMap::<String, usize>::new();
    for case in &replay.manifest.cases {
        for label in &case.labels {
            for field in ["user", "time", "reason"] {
                if let Some(value) = label[field].as_str() {
                    ensure!(
                        safe_text(value),
                        "The pilot captured human metadata is not safe."
                    );
                }
            }
        }
        let review = reviews.get(case.id.as_str()).copied();
        let row = comparisons.get(case.id.as_str()).copied();
        let workload = review.and_then(|review| review.workload);
        let identity = capture_identity(case, &replay.manifest)
            .map_err(|_| anyhow!("The pilot native capture is not valid."))?;
        if workload == Some(Workload::Routine) {
            if let Some(identity) = &identity {
                *identities.entry(identity.clone()).or_default() += 1;
            }
        }
        let mut evidence = CaseEvidence {
            case_id: case.id.clone(),
            capture_identity: identity,
            workload,
            excluded_synthetic: workload == Some(Workload::Synthetic),
            expected: case.expected,
            tool_decision: row.and_then(|row| row.actual),
            assisted_decision: review.and_then(|review| review.assisted_decision),
            final_decision: review.and_then(|review| review.final_decision),
            independent_baseline: review.and_then(|review| review.independent_baseline),
            reviewer: review.and_then(|review| review.reviewer.clone()),
            label_time: review.and_then(|review| review.label_time.clone()),
            baseline_seconds: review.and_then(|review| review.baseline_seconds),
            assisted_seconds: review.and_then(|review| review.assisted_seconds),
            correction_seconds: review.and_then(|review| review.correction_seconds),
            blockers: Vec::new(),
        };
        if review.is_none() {
            evidence.blockers.push("missing_measurement");
        }
        if workload.is_none() {
            evidence.blockers.push("missing_workload");
        }
        if workload == Some(Workload::Routine) {
            if evidence.capture_identity.is_none() {
                evidence.blockers.push("missing_native_capture");
            }
            if case
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot["policy_sha256"].as_str())
                .is_none()
            {
                evidence.blockers.push("missing_policy_digest");
            }
            let label = case.labels.last();
            let human_label = label.and_then(|label| Label::deserialize(&label["expected"]).ok());
            let human_user = label.and_then(|label| label["user"].as_str());
            let human_time = label.and_then(|label| label["time"].as_str());
            let human_reason = label.and_then(|label| label["reason"].as_str());
            if human_label.is_none()
                || human_user.is_none_or(|value| !safe_text(value))
                || human_reason.is_none_or(|value| !safe_text(value))
                || human_time.is_none()
            {
                evidence.blockers.push("missing_human_label");
            }
            if human_label.is_some_and(|expected| expected != case.expected) {
                evidence.blockers.push("human_label_mismatch");
            }
            if review.and_then(|review| review.reviewer.as_ref()).is_none() {
                evidence.blockers.push("missing_reviewer");
            }
            if review
                .and_then(|review| review.label_time.as_ref())
                .is_none()
            {
                evidence.blockers.push("missing_label_time");
            }
            match (
                started_at.as_ref(),
                human_time.and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok()),
            ) {
                (None, _) => evidence.blockers.push("missing_replay_chronology"),
                (Some(_), None) => evidence.blockers.push("missing_label_chronology"),
                (Some(start), Some(label_time)) if label_time >= *start => {
                    evidence.blockers.push("label_not_before_replay")
                }
                _ => {}
            }
            if evidence.independent_baseline != Some(true) {
                evidence.blockers.push("missing_independent_baseline");
            }
            for (missing, code) in [
                (
                    evidence.baseline_seconds.is_none(),
                    "missing_baseline_seconds",
                ),
                (
                    evidence.assisted_seconds.is_none(),
                    "missing_assisted_seconds",
                ),
                (
                    evidence.correction_seconds.is_none(),
                    "missing_correction_seconds",
                ),
                (
                    evidence.assisted_decision.is_none(),
                    "missing_assisted_decision",
                ),
                (evidence.final_decision.is_none(), "missing_final_decision"),
            ] {
                if missing {
                    evidence.blockers.push(code);
                }
            }
            if !row.is_some_and(|row| {
                release_gate::complete(row) && observed_configuration_matches(row)
            }) {
                evidence.blockers.push("incomplete_comparison");
            }
        }
        cases.push(evidence);
    }
    let mut blockers = Vec::new();
    for case in &mut cases {
        if case.workload == Some(Workload::Routine)
            && case
                .capture_identity
                .as_ref()
                .is_some_and(|identity| identities[identity] > 1)
        {
            case.blockers.push("duplicate_capture");
        }
        blockers.extend(case.blockers.iter().map(|code| Blocker {
            code,
            case_id: Some(case.case_id.clone()),
        }));
    }
    let routine_cases: Vec<_> = cases
        .iter()
        .filter(|case| case.workload == Some(Workload::Routine))
        .map(|case| case.case_id.clone())
        .collect();
    if routine_cases.is_empty() {
        blockers.push(Blocker {
            code: "no_routine_cases",
            case_id: None,
        });
    }
    let metrics = if blockers.is_empty() {
        Some(collect_metrics(&cases)?)
    } else {
        None
    };
    let report = PilotReport {
        schema_version: 1,
        authorizes_acceptance: false,
        status: if blockers.is_empty() {
            "complete"
        } else {
            "blocked"
        },
        evidence_scope: "caller-reported",
        human_identity_verified: false,
        workload_provenance_verified: false,
        model_identity_verified: false,
        replay_sha256,
        measurements_sha256: digest(measurement_bytes),
        variant_id: measurements.variant_id,
        selected_cases: cases.iter().map(|case| case.case_id.clone()).collect(),
        routine_cases,
        excluded_synthetic_cases: cases
            .iter()
            .filter(|case| case.excluded_synthetic)
            .map(|case| case.case_id.clone())
            .collect(),
        cases,
        blockers,
        metrics,
    };
    Ok((report, replay.protected_repositories))
}

pub fn run(args: PilotArgs) -> Result<()> {
    let replay_bytes = super::pilot_io::read_control(&args.replay)?;
    let measurement_bytes = super::pilot_io::read_control(&args.measurements)?;
    let (report, mut protected) = evaluate(&replay_bytes, &measurement_bytes)?;
    protected.push(args.replay);
    protected.push(args.measurements);
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|_| anyhow!("The pilot report cannot use JSON."))?;
    bytes.push(b'\n');
    if let Some(path) = args.report {
        super::pilot_io::write_new(&path, &protected, &bytes)?;
    }
    std::io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(|_| anyhow!("The pilot report cannot use standard output."))?;
    ensure!(report.status == "complete", "The pilot report is blocked.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refresh(report: &mut Value) {
        let rows: Vec<Comparison> = serde_json::from_value(report["comparisons"].clone()).unwrap();
        report["summaries"] = json!([summarize("model", &rows)]);
        report["infrastructure_errors"] = json!(
            rows.iter()
                .filter(|row| row.execution_error.is_some())
                .count()
        );
        report["gate"] = Value::Null;
    }

    fn fixture(decisions: &[(Label, Label)]) -> (Value, Value) {
        let mut report: Value = serde_json::from_slice(&successful_promotion_report()).unwrap();
        let case_template = report["cases"][0].clone();
        let row_template = report["comparisons"][0].clone();
        let mut cases = Vec::new();
        let mut rows = Vec::new();
        let mut reviews = Vec::new();
        for (index, (expected, actual)) in decisions.iter().enumerate() {
            let id = format!("case-{index}");
            let candidate = ((b'A' + index as u8) as char).to_string().repeat(53);
            let label = json!({
                "user": "human", "time": "2026-01-01T00:00:00Z",
                "reason": "Explicit human review", "expected": expected,
            });
            let snapshot = json!({
                "repository": "/captured/source", "main": "main", "inbox": "inbox",
                "main_state": null, "base": [], "candidate": candidate,
                "policy_path": "POLICY.md", "policy_sha256": "a".repeat(64),
                "configuration": {"values": report["configuration"]},
            });
            let mut case = case_template.clone();
            case["id"] = json!(id);
            case["candidate"] = json!(candidate);
            case["expected"] = json!(expected);
            case["labels"] = json!([label]);
            case["snapshot"] = snapshot.clone();
            let mut row = row_template.clone();
            row["case_id"] = json!(id);
            row["candidate"] = json!(candidate);
            row["expected"] = json!(expected);
            row["actual"] = json!(actual);
            row["unsafe_acceptance"] =
                json!(*actual == Label::Accept && *expected != Label::Accept);
            row["escalation"] = json!(*actual == Label::Escalate);
            row["correct"] = json!(actual == expected);
            row["labels"] = case["labels"].clone();
            row["snapshot"] = snapshot;
            row["evidence"]["records"][0]["hash"] = json!(candidate);
            row["evidence"]["records"][0]["decision"] = json!(actual);
            cases.push(case);
            rows.push(row);
            reviews.push(json!({
                "case_id": id, "workload": "routine", "independent_baseline": true,
                "reviewer": "human", "label_time": "2026-01-01T00:00:00Z",
                "baseline_seconds": 120.0, "assisted_seconds": 40.0,
                "correction_seconds": 0.0, "assisted_decision": actual, "final_decision": expected,
            }));
        }
        report["cases"] = json!(cases);
        report["comparisons"] = json!(rows);
        report["started_at"] = json!("2026-01-02T00:00:00Z");
        refresh(&mut report);
        let measurements = json!({
            "schema_version": 1, "replay_sha256": digest(&serde_json::to_vec(&report).unwrap()),
            "variant_id": "model", "reviews": reviews,
        });
        (report, measurements)
    }

    fn evaluate_values(report: &Value, measurements: &Value) -> Result<Value> {
        let replay_bytes = serde_json::to_vec(report).unwrap();
        let mut measurements = measurements.clone();
        measurements["replay_sha256"] = json!(digest(&replay_bytes));
        let (result, _) = evaluate(&replay_bytes, &serde_json::to_vec(&measurements).unwrap())?;
        Ok(serde_json::to_value(result).unwrap())
    }

    fn one() -> (Value, Value) {
        fixture(&[(Label::Reject, Label::Reject)])
    }

    fn has_blocker(result: &Value, code: &str) -> bool {
        result["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker["code"] == code)
    }

    #[test]
    fn mixed_decisions_report_caller_evidence_and_corrections() {
        let (report, mut measurements) = fixture(&[
            (Label::Accept, Label::Accept),
            (Label::Reject, Label::Accept),
            (Label::Accept, Label::Escalate),
            (Label::Escalate, Label::Accept),
            (Label::Reject, Label::Reject),
        ]);
        measurements["reviews"][1]["correction_seconds"] = json!(5.0);
        measurements["reviews"][2]["final_decision"] = json!("reject");
        let result = evaluate_values(&report, &measurements).unwrap();
        assert_eq!(result["status"], "complete");
        assert_eq!(result["authorizes_acceptance"], false);
        assert_eq!(result["evidence_scope"], "caller-reported");
        for field in [
            "human_identity_verified",
            "workload_provenance_verified",
            "model_identity_verified",
        ] {
            assert_eq!(result[field], false);
        }
        let metrics = &result["metrics"];
        assert_eq!(metrics["completed_routine_reviews"], 5);
        assert_eq!(metrics["unsafe_acceptances"], 2);
        assert_eq!(metrics["missed_policy_violations"], 1);
        assert_eq!(metrics["unnecessary_escalations"], 1);
        assert_eq!(metrics["label_mismatches"], 3);
        assert_eq!(metrics["decision_corrections"], 3);
        assert_eq!(metrics["final_label_mismatches"], 1);
        assert_eq!(metrics["human_baseline_seconds"], 600.0);
        assert_eq!(metrics["assisted_human_seconds"], 200.0);
        assert_eq!(metrics["human_correction_seconds"], 5.0);
        assert_eq!(metrics["net_human_seconds_saved"], 395.0);
        assert_eq!(result["cases"][1]["tool_decision"], "accept");
        assert_eq!(result["cases"][1]["final_decision"], "reject");
    }

    #[test]
    fn negative_savings_remain_valid() {
        let (report, mut measurements) = one();
        measurements["reviews"][0]["baseline_seconds"] = json!(10.0);
        measurements["reviews"][0]["assisted_seconds"] = json!(20.0);
        measurements["reviews"][0]["correction_seconds"] = json!(5.0);
        let result = evaluate_values(&report, &measurements).unwrap();
        assert_eq!(result["status"], "complete");
        assert_eq!(result["metrics"]["net_human_seconds_saved"], -15.0);
    }

    #[test]
    fn later_final_correction_does_not_change_original_tool_metrics() {
        let (report, mut measurements) = fixture(&[(Label::Reject, Label::Accept)]);
        measurements["reviews"][0]["assisted_decision"] = json!("accept");
        measurements["reviews"][0]["final_decision"] = json!("reject");
        measurements["reviews"][0]["correction_seconds"] = json!(30.0);
        let result = evaluate_values(&report, &measurements).unwrap();
        assert_eq!(result["metrics"]["unsafe_acceptances"], 1);
        assert_eq!(result["metrics"]["decision_corrections"], 1);
        assert_eq!(result["metrics"]["final_label_mismatches"], 0);
        assert_eq!(result["metrics"]["net_human_seconds_saved"], 50.0);
    }

    #[test]
    fn missing_review_blocks_the_whole_cohort() {
        let (report, mut measurements) = fixture(&[
            (Label::Reject, Label::Reject),
            (Label::Accept, Label::Accept),
        ]);
        measurements["reviews"].as_array_mut().unwrap().pop();
        let result = evaluate_values(&report, &measurements).unwrap();
        assert_eq!(result["status"], "blocked");
        assert_eq!(result["selected_cases"].as_array().unwrap().len(), 2);
        assert!(result["metrics"].is_null());
        assert!(has_blocker(&result, "missing_measurement"));
        assert!(has_blocker(&result, "missing_workload"));
    }

    #[test]
    fn explicit_zero_correction_differs_from_missing_correction() {
        let (report, mut measurements) = one();
        assert_eq!(
            evaluate_values(&report, &measurements).unwrap()["status"],
            "complete"
        );
        measurements["reviews"][0]
            .as_object_mut()
            .unwrap()
            .remove("correction_seconds");
        let result = evaluate_values(&report, &measurements).unwrap();
        assert!(has_blocker(&result, "missing_correction_seconds"));
        assert!(result["cases"][0]["correction_seconds"].is_null());
        assert!(result["metrics"].is_null());
    }

    #[test]
    fn each_missing_human_field_blocks_metrics() {
        for field in [
            "reviewer",
            "label_time",
            "independent_baseline",
            "baseline_seconds",
            "assisted_seconds",
            "assisted_decision",
            "final_decision",
            "workload",
        ] {
            let (report, mut measurements) = one();
            measurements["reviews"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            let result = evaluate_values(&report, &measurements).unwrap();
            assert_eq!(result["status"], "blocked", "{field}");
            assert!(result["metrics"].is_null(), "{field}");
        }
        let (report, mut measurements) = one();
        measurements["reviews"][0]["independent_baseline"] = json!(false);
        assert!(has_blocker(
            &evaluate_values(&report, &measurements).unwrap(),
            "missing_independent_baseline"
        ));
    }

    #[test]
    fn synthetic_cases_do_not_supply_routine_effort_or_counts() {
        let (report, mut measurements) = fixture(&[
            (Label::Reject, Label::Reject),
            (Label::Reject, Label::Accept),
        ]);
        measurements["reviews"][1] = json!({"case_id": "case-1", "workload": "synthetic"});
        let result = evaluate_values(&report, &measurements).unwrap();
        assert_eq!(result["status"], "complete");
        assert_eq!(result["excluded_synthetic_cases"], json!(["case-1"]));
        assert_eq!(result["cases"][1]["excluded_synthetic"], true);
        assert_eq!(result["metrics"]["completed_routine_reviews"], 1);
        assert_eq!(result["metrics"]["unsafe_acceptances"], 0);
        assert_eq!(result["metrics"]["human_baseline_seconds"], 120.0);
        measurements["reviews"][0] = json!({"case_id": "case-0", "workload": "synthetic"});
        let result = evaluate_values(&report, &measurements).unwrap();
        assert!(has_blocker(&result, "no_routine_cases"));
        assert!(result["metrics"].is_null());
    }

    #[test]
    fn labels_must_precede_replay_with_absolute_chronology() {
        for time in ["2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"] {
            let (mut report, mut measurements) = one();
            report["cases"][0]["labels"][0]["time"] = json!(time);
            report["comparisons"][0]["labels"][0]["time"] = json!(time);
            measurements["reviews"][0]["label_time"] = json!(time);
            let result = evaluate_values(&report, &measurements).unwrap();
            assert!(has_blocker(&result, "label_not_before_replay"));
            assert!(result["metrics"].is_null());
        }
        let (mut report, mut measurements) = one();
        let time = "2026-01-02T00:00:00+01:00";
        report["cases"][0]["labels"][0]["time"] = json!(time);
        report["comparisons"][0]["labels"][0]["time"] = json!(time);
        measurements["reviews"][0]["label_time"] = json!(time);
        assert_eq!(
            evaluate_values(&report, &measurements).unwrap()["status"],
            "complete"
        );
    }

    #[test]
    fn old_report_has_no_chronology_claim() {
        let (mut report, measurements) = one();
        report.as_object_mut().unwrap().remove("started_at");
        let result = evaluate_values(&report, &measurements).unwrap();
        assert!(has_blocker(&result, "missing_replay_chronology"));
        assert!(result["metrics"].is_null());
    }

    #[test]
    fn supplied_human_identity_and_time_must_match_exactly() {
        for (field, value) in [
            ("reviewer", "different-human"),
            ("label_time", "2026-01-01T00:00:00+00:00"),
            ("label_time", "not-a-time"),
        ] {
            let (report, mut measurements) = one();
            measurements["reviews"][0][field] = json!(value);
            let error = evaluate_values(&report, &measurements)
                .unwrap_err()
                .to_string();
            assert!(error.starts_with("The pilot "));
            assert!(!error.contains(value));
        }
    }

    #[test]
    fn incomplete_and_execution_error_rows_block_the_cohort() {
        for field in [
            "cli_executed",
            "exit_code",
            "configuration",
            "execution_error",
        ] {
            let (mut report, measurements) = one();
            match field {
                "cli_executed" => report["comparisons"][0][field] = json!(false),
                "exit_code" => report["comparisons"][0][field] = json!(1),
                "configuration" => {
                    report["comparisons"][0]["evidence"]["configuration"]["values"]["max_change_chars"] =
                        json!(1)
                }
                _ => {
                    let row = &mut report["comparisons"][0];
                    row["execution_error"] = json!("Private execution details");
                    row["outcome"] = json!("execution_error");
                    row["cli_executed"] = json!(false);
                    for field in [
                        "actual",
                        "decision_actor",
                        "unsafe_acceptance",
                        "escalation",
                        "correct",
                        "exit_code",
                        "evidence",
                    ] {
                        row[field] = Value::Null;
                    }
                }
            }
            refresh(&mut report);
            let result = evaluate_values(&report, &measurements).unwrap();
            assert!(has_blocker(&result, "incomplete_comparison"), "{field}");
            assert!(result["metrics"].is_null());
            assert!(!result.to_string().contains("Private execution details"));
        }
    }

    #[test]
    fn duplicate_native_captures_block_each_duplicate() {
        let (mut report, measurements) = fixture(&[
            (Label::Reject, Label::Reject),
            (Label::Reject, Label::Reject),
        ]);
        report["cases"][1] = report["cases"][0].clone();
        report["cases"][1]["id"] = json!("case-1");
        report["comparisons"][1] = report["comparisons"][0].clone();
        report["comparisons"][1]["case_id"] = json!("case-1");
        refresh(&mut report);
        let result = evaluate_values(&report, &measurements).unwrap();
        assert_eq!(result["status"], "blocked");
        assert_eq!(
            result["cases"][0]["capture_identity"],
            result["cases"][1]["capture_identity"]
        );
        for case in result["cases"].as_array().unwrap() {
            assert!(
                case["blockers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("duplicate_capture"))
            );
        }
        assert!(result["metrics"].is_null());
    }

    #[test]
    fn missing_native_capture_policy_or_label_blocks_routine_evidence() {
        for missing in ["snapshot", "policy_sha256", "labels"] {
            let (mut report, mut measurements) = one();
            let code = match missing {
                "snapshot" => {
                    report["cases"][0]["snapshot"] = Value::Null;
                    report["comparisons"][0]["snapshot"] = Value::Null;
                    "missing_native_capture"
                }
                "policy_sha256" => {
                    report["cases"][0]["snapshot"]["policy_sha256"] = Value::Null;
                    report["comparisons"][0]["snapshot"]["policy_sha256"] = Value::Null;
                    "missing_policy_digest"
                }
                _ => {
                    report["cases"][0]["labels"] = json!([]);
                    report["comparisons"][0]["labels"] = json!([]);
                    measurements["reviews"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("reviewer");
                    measurements["reviews"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("label_time");
                    "missing_human_label"
                }
            };
            let result = evaluate_values(&report, &measurements).unwrap();
            assert!(has_blocker(&result, code), "{missing}");
            assert!(result["metrics"].is_null());
        }
    }

    #[test]
    fn digests_bind_exact_input_bytes_once() {
        let (report, mut measurements) = one();
        let bytes = serde_json::to_vec(&report).unwrap();
        measurements["replay_sha256"] = json!("0".repeat(64));
        assert!(evaluate(&bytes, &serde_json::to_vec(&measurements).unwrap()).is_err());
        measurements["replay_sha256"] = json!(digest(&bytes));
        let measurement_bytes = serde_json::to_vec(&measurements).unwrap();
        let (result, _) = evaluate(&bytes, &measurement_bytes).unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(result["replay_sha256"], digest(&bytes));
        assert_eq!(result["measurements_sha256"], digest(&measurement_bytes));
        let mut changed = bytes;
        changed.push(b' ');
        assert!(evaluate(&changed, &measurement_bytes).is_err());
    }

    #[test]
    fn duplicate_unknown_and_unsafe_case_ids_fail() {
        let (report, measurements) = one();
        let mut duplicate = measurements.clone();
        let review = duplicate["reviews"][0].clone();
        duplicate["reviews"].as_array_mut().unwrap().push(review);
        assert!(evaluate_values(&report, &duplicate).is_err());
        for id in [
            "unknown-case",
            "unsafe\ncase",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        ] {
            let mut invalid = measurements.clone();
            invalid["reviews"][0]["case_id"] = json!(id);
            let error = evaluate_values(&report, &invalid).unwrap_err().to_string();
            assert!(!error.contains(id));
        }
    }

    #[test]
    fn unsafe_control_text_and_credentials_fail_without_disclosure() {
        for text in ["human\nprivate", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"] {
            let (report, mut measurements) = one();
            measurements["reviews"][0]["reviewer"] = json!(text);
            let error = evaluate_values(&report, &measurements)
                .unwrap_err()
                .to_string();
            assert_eq!(error, "The pilot human metadata is not safe.");
            assert!(!error.contains(text));
        }
    }

    #[test]
    fn invalid_fields_and_explicit_null_fail() {
        for field in [
            "extra",
            "workload",
            "assisted_decision",
            "baseline_seconds",
            "correction_seconds",
        ] {
            let (report, mut measurements) = one();
            measurements["reviews"][0][field] = Value::Null;
            assert!(evaluate_values(&report, &measurements).is_err(), "{field}");
        }
        let (report, mut measurements) = one();
        measurements["extra"] = json!(true);
        assert!(evaluate_values(&report, &measurements).is_err());
        measurements.as_object_mut().unwrap().remove("extra");
        measurements["variant_id"] = json!("unknown");
        assert!(evaluate_values(&report, &measurements).is_err());
    }

    #[test]
    fn invalid_effort_and_nonfinite_json_fail() {
        for (field, value) in [
            ("baseline_seconds", 0.0),
            ("baseline_seconds", -1.0),
            ("assisted_seconds", -1.0),
            ("correction_seconds", -1.0),
        ] {
            let (report, mut measurements) = one();
            measurements["reviews"][0][field] = json!(value);
            assert!(evaluate_values(&report, &measurements).is_err(), "{field}");
        }
        let (report, measurements) = one();
        let bytes = serde_json::to_vec(&report).unwrap();
        for literal in ["1e999", "NaN", "Infinity", "-Infinity"] {
            let source = serde_json::to_string(&measurements).unwrap().replace(
                "\"baseline_seconds\":120.0",
                &format!("\"baseline_seconds\":{literal}"),
            );
            assert!(evaluate(&bytes, source.as_bytes()).is_err(), "{literal}");
        }
    }

    #[test]
    fn aggregate_effort_and_net_savings_overflow_fail() {
        let (report, mut measurements) = fixture(&[
            (Label::Reject, Label::Reject),
            (Label::Reject, Label::Reject),
        ]);
        for review in measurements["reviews"].as_array_mut().unwrap() {
            review["baseline_seconds"] = json!(f64::MAX);
        }
        assert!(evaluate_values(&report, &measurements).is_err());
        let (report, mut measurements) = one();
        measurements["reviews"][0]["baseline_seconds"] = json!(1.0);
        measurements["reviews"][0]["assisted_seconds"] = json!(f64::MAX);
        measurements["reviews"][0]["correction_seconds"] = json!(f64::MAX);
        assert!(evaluate_values(&report, &measurements).is_err());
    }

    #[test]
    fn report_never_copies_private_replay_evidence() {
        let mut replay: Value = serde_json::from_slice(&successful_promotion_report()).unwrap();
        replay["started_at"] = json!("2026-01-02T00:00:00Z");
        replay["variants"][0]["model_url"] = json!("http://private-model.example:8080");
        replay["comparisons"][0]["stderr"] = json!("Private diagnostic text");
        replay["comparisons"][0]["evidence"]["private_reply"] = json!("Private model reply");
        replay["comparisons"][0]["evidence"]["private_policy"] = json!("Private policy text");
        let replay_bytes = serde_json::to_vec(&replay).unwrap();
        let measurements = serde_json::to_vec(&json!({
            "schema_version": 1, "replay_sha256": digest(&replay_bytes),
            "variant_id": "model", "reviews": [{"case_id": "case", "workload": "synthetic"}],
        }))
        .unwrap();
        let (report, _) = evaluate(&replay_bytes, &measurements).unwrap();
        let output = serde_json::to_string(&report).unwrap();
        for private in [
            "private-model.example",
            "Private diagnostic text",
            "Private model reply",
            "Private policy text",
            "/captured/source",
            "/captured/manifest.json",
        ] {
            assert!(!output.contains(private));
        }
        assert_eq!(report.status, "blocked");
        assert!(report.metrics.is_none());
    }
}
