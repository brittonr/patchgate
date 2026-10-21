use super::*;

#[derive(Deserialize)]
pub(super) struct Baseline {
    schema_version: u32,
    repository: PathBuf,
    main: String,
    inbox: String,
    variants: Vec<Variant>,
    comparisons: Vec<Comparison>,
    authorizes_acceptance: bool,
}

#[derive(Serialize)]
pub(super) struct GateResult {
    schema_version: u32,
    pub(super) passed: bool,
    limits: Limits,
    observed: Observed,
    regressions: Vec<Regression>,
    failures: Vec<Failure>,
}

#[derive(Serialize)]
struct Limits {
    unsafe_acceptances: usize,
    label_mismatches: usize,
    regressions: usize,
}

#[derive(Default, Serialize)]
struct Observed {
    unsafe_acceptances: usize,
    label_mismatches: usize,
    regressions: usize,
    execution_errors: usize,
    incomplete_comparisons: usize,
}

#[derive(Serialize)]
struct Regression {
    case_id: String,
    variant_id: String,
    became_unsafe: bool,
    became_label_mismatch: bool,
}

#[derive(Serialize)]
struct Failure {
    code: &'static str,
    case_id: Option<String>,
    variant_id: Option<String>,
    message: String,
}

impl GateResult {
    fn failure(&mut self, code: &'static str, row: Option<&Comparison>, message: String) {
        self.failures.push(Failure {
            code,
            case_id: row.map(|row| row.case_id.clone()),
            variant_id: row.map(|row| row.variant_id.clone()),
            message,
        });
    }
}

pub(super) fn read_baseline(path: &Path) -> Result<Baseline> {
    serde_json::from_slice(&fs::read(path).context("Read the replay baseline file.")?)
        .context("Read the replay baseline report.")
}

fn unsafe_acceptance(row: &Comparison) -> bool {
    row.actual == Some(Label::Accept) && row.expected != Label::Accept
}

fn label_mismatch(row: &Comparison) -> bool {
    row.actual.is_some_and(|actual| actual != row.expected)
}

fn complete(row: &Comparison) -> bool {
    row.actual.is_some() && row.outcome == "verdict" && row.cli_executed && row.exit_code == Some(0)
}

type Matrix<'a> = BTreeMap<(&'a str, &'a str), &'a Comparison>;

fn matrix<'a>(
    rows: &'a [Comparison],
    manifest: &Manifest,
    baseline: bool,
    result: &mut GateResult,
) -> Matrix<'a> {
    let name = if baseline { "baseline" } else { "replay" };
    let expected: BTreeSet<_> = manifest
        .cases
        .iter()
        .flat_map(|case| {
            manifest
                .variants
                .iter()
                .map(move |variant| (case.id.as_str(), variant.id.as_str()))
        })
        .collect();
    let mut matrix = BTreeMap::new();
    for row in rows {
        let key = (row.case_id.as_str(), row.variant_id.as_str());
        if matrix.insert(key, row).is_some() {
            result.failure(
                "duplicate_comparison",
                Some(row),
                format!("The {name} contains a duplicate case and variant row."),
            );
        }
        if !expected.contains(&key) {
            result.failure(
                "unexpected_comparison",
                Some(row),
                format!("The {name} contains an unexpected case and variant row."),
            );
        }
        if row.execution_error.is_some() {
            result.failure(
                "execution_error",
                Some(row),
                format!("The {name} comparison contains an execution error."),
            );
        }
        if !complete(row) {
            result.failure(
                "incomplete_comparison",
                Some(row),
                format!("The {name} comparison has no complete successful verdict."),
            );
        }
        if !observed_configuration_matches(row) {
            result.failure(
                "observed_settings",
                Some(row),
                format!("The {name} CLI evidence does not match its declared effective settings."),
            );
        }
    }
    for (case_id, variant_id) in expected {
        if !matrix.contains_key(&(case_id, variant_id)) {
            result.failures.push(Failure {
                code: "missing_comparison",
                case_id: Some(case_id.to_owned()),
                variant_id: Some(variant_id.to_owned()),
                message: format!("The {name} has no comparison for this case and variant."),
            });
        }
    }
    matrix
}

fn compatible(row: &Comparison, previous: &Comparison) -> bool {
    row.candidate == previous.candidate
        && row.base == previous.base
        && row.expected == previous.expected
        && row.snapshot == previous.snapshot
        && row.labels == previous.labels
        && row.configuration == previous.configuration
}

pub(super) fn evaluate(
    args: &ReplayArgs,
    manifest: &Manifest,
    origin: &Path,
    comparisons: &[Comparison],
    baseline: Option<&Result<Baseline>>,
) -> Option<GateResult> {
    if !args.gate
        && args.baseline.is_none()
        && args.max_unsafe_acceptances.is_none()
        && args.max_label_mismatches.is_none()
        && args.max_regressions.is_none()
    {
        return None;
    }
    let mut result = GateResult {
        schema_version: 1,
        passed: false,
        limits: Limits {
            unsafe_acceptances: args.max_unsafe_acceptances.unwrap_or(0),
            label_mismatches: args.max_label_mismatches.unwrap_or(0),
            regressions: args.max_regressions.unwrap_or(0),
        },
        observed: Observed::default(),
        regressions: Vec::new(),
        failures: Vec::new(),
    };
    for row in comparisons {
        result.observed.unsafe_acceptances += usize::from(unsafe_acceptance(row));
        result.observed.label_mismatches += usize::from(label_mismatch(row));
        result.observed.execution_errors += usize::from(row.execution_error.is_some());
        result.observed.incomplete_comparisons += usize::from(!complete(row));
    }
    let current = matrix(comparisons, manifest, false, &mut result);
    match baseline {
        Some(Err(error)) => result.failure(
            "invalid_baseline",
            None,
            format!("The baseline is not valid: {error:#}"),
        ),
        Some(Ok(baseline)) => {
            if baseline.schema_version != 1 || baseline.authorizes_acceptance {
                result.failure(
                    "invalid_baseline",
                    None,
                    "The baseline must be a version 1 replay report without acceptance authority."
                        .into(),
                );
            }
            if baseline.repository != origin
                || baseline.main != manifest.main
                || baseline.inbox != manifest.inbox
            {
                result.failure(
                    "incompatible_dataset",
                    None,
                    "The baseline source repository or channel bindings differ from this replay."
                        .into(),
                );
            }
            let variants: BTreeSet<_> = baseline
                .variants
                .iter()
                .map(|variant| variant.id.as_str())
                .collect();
            let expected: BTreeSet<_> = manifest
                .variants
                .iter()
                .map(|variant| variant.id.as_str())
                .collect();
            if variants.len() != baseline.variants.len() || variants != expected {
                result.failure(
                    "incompatible_dataset",
                    None,
                    "The baseline variant IDs differ from this replay or contain duplicates."
                        .into(),
                );
            }
            let previous = matrix(&baseline.comparisons, manifest, true, &mut result);
            for (key, row) in current {
                let Some(previous) = previous.get(&key) else {
                    continue;
                };
                if !compatible(row, previous) {
                    result.failure("incompatible_dataset", Some(row), "The baseline candidate, ordered base, label, snapshot, label history, or effective settings differ.".into());
                    continue;
                }
                if row.execution_error.is_none()
                    && previous.execution_error.is_none()
                    && complete(row)
                    && complete(previous)
                {
                    let became_unsafe = unsafe_acceptance(row) && !unsafe_acceptance(previous);
                    let became_label_mismatch = label_mismatch(row) && !label_mismatch(previous);
                    if became_unsafe || became_label_mismatch {
                        result.regressions.push(Regression {
                            case_id: row.case_id.clone(),
                            variant_id: row.variant_id.clone(),
                            became_unsafe,
                            became_label_mismatch,
                        });
                    }
                }
            }
        }
        None => {}
    }
    result.observed.regressions = result.regressions.len();
    for (code, observed, limit) in [
        (
            "unsafe_acceptance_limit",
            result.observed.unsafe_acceptances,
            result.limits.unsafe_acceptances,
        ),
        (
            "label_mismatch_limit",
            result.observed.label_mismatches,
            result.limits.label_mismatches,
        ),
        (
            "regression_limit",
            result.observed.regressions,
            result.limits.regressions,
        ),
    ] {
        if observed > limit {
            result.failure(
                code,
                None,
                format!("The observed count {observed} exceeds the limit {limit}."),
            );
        }
    }
    result.passed = result.failures.is_empty();
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        serde_json::from_value(json!({
            "schema_version": 1,
            "repository": "/captured/source",
            "cases": [
                {"id": "first", "base": [], "candidate": "A".repeat(53), "expected": "reject"},
                {"id": "second", "base": [], "candidate": "B".repeat(53), "expected": "reject"}
            ],
            "variants": [
                {"id": "model", "model_url": "http://localhost:8080", "model": "model", "api": "openai", "revision": "revision"}
            ]
        })).unwrap()
    }

    fn args() -> ReplayArgs {
        ReplayArgs {
            manifest: Some("manifest.json".into()),
            bundle: None,
            report: None,
            gate: true,
            baseline: None,
            max_unsafe_acceptances: None,
            max_label_mismatches: None,
            max_regressions: None,
        }
    }

    fn rows(manifest: &Manifest, verdicts: [Label; 2]) -> Vec<Comparison> {
        manifest
            .cases
            .iter()
            .zip(verdicts)
            .map(|(case, actual)| {
                let mut row = Comparison::new(case, &manifest.variants[0], &manifest.configuration);
                row.decision(Some(actual), "verdict".into());
                row.cli_executed = true;
                row.exit_code = Some(0);
                row.evidence = Some(json!({"configuration": {"values": row.configuration}}));
                row
            })
            .collect()
    }

    fn baseline(manifest: &Manifest, rows: &[Comparison]) -> Baseline {
        serde_json::from_value(json!({
            "schema_version": 1,
            "repository": manifest.repository,
            "main": manifest.main,
            "inbox": manifest.inbox,
            "variants": manifest.variants,
            "comparisons": rows,
            "summaries": [{"unsafe_acceptances": 999, "label_mismatches": 999}],
            "infrastructure_errors": 999,
            "authorizes_acceptance": false
        }))
        .unwrap()
    }

    fn evaluate_rows(
        args: &ReplayArgs,
        manifest: &Manifest,
        rows: &[Comparison],
        baseline: Option<&Result<Baseline>>,
    ) -> GateResult {
        evaluate(args, manifest, &manifest.repository, rows, baseline).unwrap()
    }

    #[test]
    fn matching_baseline_uses_rows_and_permits_model_changes() {
        let manifest = manifest();
        let rows = rows(&manifest, [Label::Reject, Label::Reject]);
        let mut previous = baseline(&manifest, &rows);
        previous.variants[0].model = "another-model".into();
        previous.variants[0].api = "systemone".into();
        previous.variants[0].revision = "another-revision".into();
        previous.variants[0].policy = Some("another-policy.md".into());
        previous.comparisons[0].revision = "another-revision".into();
        let result = evaluate_rows(&args(), &manifest, &rows, Some(&Ok(previous)));
        assert!(result.passed);
        assert_eq!(result.observed.unsafe_acceptances, 0);
        assert_eq!(result.observed.regressions, 0);
    }

    #[test]
    fn thresholds_activate_gates_without_changing_ungated_behavior() {
        let manifest = manifest();
        let rows = rows(&manifest, [Label::Accept, Label::Escalate]);
        let mut args = args();
        args.gate = false;
        assert!(evaluate(&args, &manifest, &manifest.repository, &rows, None).is_none());
        args.max_unsafe_acceptances = Some(1);
        let result = evaluate_rows(&args, &manifest, &rows, None);
        assert!(!result.passed);
        assert_eq!(result.observed.unsafe_acceptances, 1);
        assert_eq!(result.observed.label_mismatches, 2);
        args.max_label_mismatches = Some(2);
        assert!(evaluate_rows(&args, &manifest, &rows, None).passed);
    }

    #[test]
    fn improvements_do_not_cancel_new_unsafe_comparisons() {
        let manifest = manifest();
        let old_rows = rows(&manifest, [Label::Accept, Label::Reject]);
        let current_rows = rows(&manifest, [Label::Reject, Label::Accept]);
        let previous = Ok(baseline(&manifest, &old_rows));
        let mut args = args();
        args.max_unsafe_acceptances = Some(1);
        args.max_label_mismatches = Some(1);
        let result = evaluate_rows(&args, &manifest, &current_rows, Some(&previous));
        assert!(!result.passed);
        assert_eq!(result.observed.regressions, 1);
        assert_eq!(result.regressions[0].case_id, "second");
        assert!(result.regressions[0].became_unsafe);
        assert!(result.regressions[0].became_label_mismatch);
        args.max_regressions = Some(1);
        assert!(evaluate_rows(&args, &manifest, &current_rows, Some(&previous)).passed);
    }

    #[test]
    fn unsafe_change_from_an_existing_mismatch_is_a_regression() {
        let manifest = manifest();
        let old_rows = rows(&manifest, [Label::Escalate, Label::Reject]);
        let current_rows = rows(&manifest, [Label::Accept, Label::Reject]);
        let previous = Ok(baseline(&manifest, &old_rows));
        let mut args = args();
        args.max_unsafe_acceptances = Some(1);
        args.max_label_mismatches = Some(1);
        let result = evaluate_rows(&args, &manifest, &current_rows, Some(&previous));
        assert!(!result.passed);
        assert_eq!(result.observed.regressions, 1);
        assert!(result.regressions[0].became_unsafe);
        assert!(!result.regressions[0].became_label_mismatch);
    }

    #[test]
    fn matrices_reject_duplicates_missing_rows_and_unknown_rows() {
        let manifest = manifest();
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        for defect in 0..4 {
            let mut previous = baseline(&manifest, &current);
            match defect {
                0 => {
                    previous.comparisons.pop();
                }
                1 => {
                    let duplicate =
                        serde_json::from_value(serde_json::to_value(&current[0]).unwrap()).unwrap();
                    previous.comparisons.push(duplicate);
                }
                2 => {
                    previous.comparisons[0].case_id = "unknown".into();
                }
                _ => {
                    previous.variants[0].id = "unknown".into();
                }
            }
            assert!(!evaluate_rows(&args(), &manifest, &current, Some(&Ok(previous))).passed);
        }
        assert!(!evaluate_rows(&args(), &manifest, &current[..1], None).passed);
        let duplicate = serde_json::from_value(serde_json::to_value(&current[0]).unwrap()).unwrap();
        let mut duplicate_rows = current;
        duplicate_rows.push(duplicate);
        assert!(!evaluate_rows(&args(), &manifest, &duplicate_rows, None).passed);
    }

    #[test]
    fn baseline_bindings_cannot_change() {
        let manifest = manifest();
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        for field in 0..10 {
            let mut previous = baseline(&manifest, &current);
            let row = &mut previous.comparisons[0];
            match field {
                0 => row.candidate = "C".repeat(53),
                1 => row.base = vec!["D".repeat(53)],
                2 => row.expected = Label::Accept,
                3 => row.snapshot = Some(json!({"repository": "/another/source"})),
                4 => row.labels.push(json!({"expected": "accept"})),
                5 => row.configuration.max_change_chars += 1,
                6 => previous.main = "another-main".into(),
                7 => previous.inbox = "another-inbox".into(),
                8 => previous.repository = "/another/source".into(),
                _ => previous.schema_version = 99,
            }
            let result = evaluate_rows(&args(), &manifest, &current, Some(&Ok(previous)));
            assert!(!result.passed, "{field}");
        }
    }

    #[test]
    fn execution_errors_and_incomplete_verdicts_ignore_permissive_limits() {
        let manifest = manifest();
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        let mut args = args();
        args.max_unsafe_acceptances = Some(usize::MAX);
        args.max_label_mismatches = Some(usize::MAX);
        args.max_regressions = Some(usize::MAX);
        for field in 0..5 {
            let mut incomplete = rows(&manifest, [Label::Reject, Label::Reject]);
            match field {
                0 => incomplete[0].execution_error = Some("The model is unavailable.".into()),
                1 => incomplete[0].actual = None,
                2 => incomplete[0].outcome = "blocked".into(),
                3 => incomplete[0].cli_executed = false,
                _ => incomplete[0].exit_code = Some(1),
            }
            assert!(!evaluate_rows(&args, &manifest, &incomplete, None).passed);
            let previous = Ok(baseline(&manifest, &incomplete));
            assert!(!evaluate_rows(&args, &manifest, &current, Some(&previous)).passed);
        }
        let error = Err(anyhow!("The baseline JSON is not valid."));
        assert!(!evaluate_rows(&args, &manifest, &current, Some(&error)).passed);
    }

    #[test]
    fn baseline_flag_activates_gate_and_input_bytes_survive_report_replacement() -> Result<()> {
        let manifest = manifest();
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("baseline.json");
        let value = json!({
            "schema_version": 1, "repository": manifest.repository,
            "main": manifest.main, "inbox": manifest.inbox,
            "variants": manifest.variants, "comparisons": current,
            "authorizes_acceptance": false
        });
        fs::write(&path, serde_json::to_vec(&value)?)?;
        let previous = read_baseline(&path);
        fs::write(&path, b"replacement report")?;
        let mut args = args();
        args.gate = false;
        args.baseline = Some(path);
        assert!(evaluate_rows(&args, &manifest, &current, Some(&previous)).passed);
        Ok(())
    }

    #[test]
    fn baseline_base_order_is_a_source_binding() {
        let mut manifest = manifest();
        manifest.cases[0].base = vec!["C".repeat(53), "D".repeat(53)];
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        let mut previous = baseline(&manifest, &current);
        previous.comparisons[0].base.reverse();
        assert!(!evaluate_rows(&args(), &manifest, &current, Some(&Ok(previous))).passed);
    }

    #[test]
    fn gates_refuse_unobserved_settings_in_current_and_baseline_rows() {
        let manifest = manifest();
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        let mut altered = rows(&manifest, [Label::Reject, Label::Reject]);
        altered[0].evidence.as_mut().unwrap()["configuration"]["values"]["max_change_chars"] =
            json!(1);
        let result = evaluate_rows(&args(), &manifest, &altered, None);
        assert!(!result.passed);
        assert!(
            result
                .failures
                .iter()
                .any(|failure| failure.code == "observed_settings")
        );
        let previous = baseline(&manifest, &altered);
        let result = evaluate_rows(&args(), &manifest, &current, Some(&Ok(previous)));
        assert!(!result.passed);
        assert!(
            result
                .failures
                .iter()
                .any(|failure| failure.code == "observed_settings")
        );
    }
}
