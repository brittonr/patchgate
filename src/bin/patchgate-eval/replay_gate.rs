use super::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    tag: String,
    count: usize,
}

pub(super) fn parse_requirement(value: &str) -> std::result::Result<Requirement, String> {
    let (tag, count) = value.split_once('=').ok_or("Coverage needs TAG=COUNT.")?;
    if !valid_tag(tag) || count.is_empty() || !count.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Coverage needs a lowercase tag and a nonnegative integer count.".into());
    }
    Ok(Requirement {
        tag: tag.into(),
        count: count
            .parse()
            .map_err(|_| "The coverage count is too large.")?,
    })
}

pub(super) fn validate_requirements(args: &ReplayArgs) -> Result<()> {
    for requirements in [&args.min_policy_rule, &args.min_conflict_kind] {
        let mut unique = BTreeSet::new();
        ensure!(
            requirements
                .iter()
                .all(|entry| valid_tag(&entry.tag) && unique.insert(&entry.tag)),
            "Coverage requirements must use unique lowercase tags."
        );
    }
    Ok(())
}

pub(super) fn apply_policy(
    args: &mut ReplayArgs,
    policy: &crate::release_policy::Policy,
) -> Result<()> {
    policy.validate()?;
    validate_requirements(args)?;
    for (value, maximum) in [
        (
            &mut args.max_unsafe_acceptances,
            policy.limits.max_unsafe_acceptances,
        ),
        (
            &mut args.max_label_mismatches,
            policy.limits.max_label_mismatches,
        ),
        (&mut args.max_regressions, policy.limits.max_regressions),
    ] {
        ensure!(
            value.is_none_or(|value| value <= maximum),
            "A supplied release limit is weaker than the trusted release policy."
        );
        if value.is_none() {
            *value = Some(maximum);
        }
    }
    for (requirements, minimums) in [
        (&mut args.min_policy_rule, &policy.coverage.policy_rules),
        (&mut args.min_conflict_kind, &policy.coverage.conflict_kinds),
    ] {
        for (tag, minimum) in minimums {
            if let Some(requirement) = requirements
                .iter()
                .find(|requirement| &requirement.tag == tag)
            {
                ensure!(
                    requirement.count >= *minimum,
                    "A supplied coverage minimum is weaker than the trusted release policy."
                );
            } else {
                requirements.push(Requirement {
                    tag: tag.clone(),
                    count: *minimum,
                });
            }
        }
    }
    ensure!(
        !policy.signatures.require_bundle || args.bundle.is_some(),
        "The trusted release policy needs a signed bundle."
    );
    ensure!(
        !(policy.signatures.require_baseline || policy.baseline_sha256.is_some())
            || args.baseline.is_some(),
        "The trusted release policy needs a baseline."
    );
    if let Some(identity) = &policy.signatures.signer {
        ensure!(
            args.signer.as_ref().is_none_or(|value| value == identity),
            "The supplied signer differs from the trusted release policy."
        );
        args.signer = Some(identity.clone());
    }
    ensure!(
        policy.signatures.allowed_signers_sha256.is_none() || args.allowed_signers.is_some(),
        "The trusted release policy needs an allowed-signers input."
    );
    ensure!(
        policy.signatures.revoked_keys_sha256.is_none() || args.revoked_keys.is_some(),
        "The trusted release policy needs a revocation input."
    );
    args.gate = true;
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    variant_id: String,
    policy_rules: BTreeMap<String, usize>,
    conflict_kinds: BTreeMap<String, usize>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Baseline {
    schema_version: u32,
    repository: PathBuf,
    main: String,
    inbox: String,
    variants: Vec<Variant>,
    comparisons: Vec<Comparison>,
    authorizes_acceptance: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GateResult {
    schema_version: u32,
    pub(super) passed: bool,
    authorizes_acceptance: bool,
    limits: Limits,
    observed: Observed,
    regressions: Vec<Regression>,
    failures: Vec<Failure>,
    coverage: Vec<Coverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    baseline: Option<Baseline>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    unsafe_acceptances: usize,
    label_mismatches: usize,
    regressions: usize,
    policy_rules: Vec<Requirement>,
    conflict_kinds: Vec<Requirement>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observed {
    unsafe_acceptances: usize,
    label_mismatches: usize,
    regressions: usize,
    execution_errors: usize,
    incomplete_comparisons: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Regression {
    case_id: String,
    variant_id: String,
    became_unsafe: bool,
    became_label_mismatch: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    code: String,
    case_id: Option<String>,
    variant_id: Option<String>,
    message: String,
}

impl GateResult {
    fn failure(&mut self, code: &'static str, row: Option<&Comparison>, message: String) {
        self.failures.push(Failure {
            code: code.into(),
            case_id: row.map(|row| row.case_id.clone()),
            variant_id: row.map(|row| row.variant_id.clone()),
            message,
        });
    }
}

pub(super) fn baseline_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .context("Read the replay baseline file.")?;
    ensure!(
        file.metadata()?.is_file(),
        "The replay baseline must use a regular file."
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn read_baseline(bytes: &[u8]) -> Result<Baseline> {
    serde_json::from_slice(bytes).context("Read the replay baseline report.")
}

fn unsafe_acceptance(row: &Comparison) -> bool {
    row.actual == Some(Label::Accept) && row.expected != Label::Accept
}

fn label_mismatch(row: &Comparison) -> bool {
    row.actual.is_some_and(|actual| actual != row.expected)
}

pub(super) fn complete(row: &Comparison) -> bool {
    row.actual.is_some()
        && row.outcome == "verdict"
        && row.cli_executed
        && row.exit_code == Some(0)
        && row.execution_error.is_none()
        && row.elapsed_seconds.is_finite()
        && row.elapsed_seconds >= 0.0
        && row.unsafe_acceptance
            == row
                .actual
                .map(|actual| actual == Label::Accept && row.expected != Label::Accept)
        && row.escalation == row.actual.map(|actual| actual == Label::Escalate)
        && row.correct == row.actual.map(|actual| actual == row.expected)
        && observed_decision_matches(row)
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
    let cases: BTreeMap<_, _> = manifest
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
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
        if let Some(case) = cases.get(row.case_id.as_str()) {
            if !matches_case(row, case, &manifest.configuration) {
                result.failure(
                    "incompatible_dataset",
                    Some(row),
                    format!(
                        "The {name} comparison differs from its captured case and human histories."
                    ),
                );
            }
        }
    }
    for (case_id, variant_id) in expected {
        if !matrix.contains_key(&(case_id, variant_id)) {
            result.failures.push(Failure {
                code: "missing_comparison".into(),
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
        && row.tags == previous.tags
        && row.notes == previous.notes
        && row.seen == previous.seen
        && row.configuration == previous.configuration
}

pub(super) fn matches_case(row: &Comparison, case: &Case, default: &Configuration) -> bool {
    row.candidate == case.candidate
        && row.base == case.base
        && row.expected == case.expected
        && row.snapshot == case.snapshot
        && row.labels == case.labels
        && row.tags == case.tags
        && row.notes == case.notes
        && row.seen == case.seen
        && row.configuration == *case.configuration.as_ref().unwrap_or(default)
}

fn coverage(
    args: &ReplayArgs,
    manifest: &Manifest,
    comparisons: &[Comparison],
    current: &Matrix<'_>,
    result: &mut GateResult,
) {
    let mut multiplicity = BTreeMap::new();
    for row in comparisons {
        *multiplicity
            .entry((row.case_id.as_str(), row.variant_id.as_str()))
            .or_insert(0usize) += 1;
    }
    let captures: Vec<_> = manifest
        .cases
        .iter()
        .map(|case| {
            let labeled = case
                .labels
                .last()
                .is_some_and(|label| label["expected"] == json!(case.expected))
                && validate_tag_history(&case.tags).is_ok();
            (
                case,
                capture_identity(case, manifest).ok().flatten(),
                labeled,
            )
        })
        .collect();
    for variant in &manifest.variants {
        let mut observed = Coverage {
            variant_id: variant.id.clone(),
            policy_rules: args
                .min_policy_rule
                .iter()
                .map(|entry| (entry.tag.clone(), 0))
                .collect(),
            conflict_kinds: args
                .min_conflict_kind
                .iter()
                .map(|entry| (entry.tag.clone(), 0))
                .collect(),
        };
        let mut counted = BTreeSet::new();
        for (case, identity, labeled) in &captures {
            let Some(tags) = case.tags.last() else {
                continue;
            };
            for tag in &tags.policy_rules {
                observed.policy_rules.entry(tag.clone()).or_insert(0);
            }
            for tag in &tags.conflict_kinds {
                observed.conflict_kinds.entry(tag.clone()).or_insert(0);
            }
            let Some(identity) = identity.as_deref() else {
                continue;
            };
            let key = (case.id.as_str(), variant.id.as_str());
            let Some(row) = current.get(&key) else {
                continue;
            };
            if !*labeled
                || multiplicity.get(&key) != Some(&1)
                || !complete(row)
                || !observed_configuration_matches(row)
                || !matches_case(row, case, &manifest.configuration)
                || !counted.insert(identity)
            {
                continue;
            }
            for tag in &tags.policy_rules {
                *observed.policy_rules.entry(tag.clone()).or_default() += 1;
            }
            for tag in &tags.conflict_kinds {
                *observed.conflict_kinds.entry(tag.clone()).or_default() += 1;
            }
        }
        for (kind, requirements, counts) in [
            ("policy_rule", &args.min_policy_rule, &observed.policy_rules),
            (
                "conflict_kind",
                &args.min_conflict_kind,
                &observed.conflict_kinds,
            ),
        ] {
            for requirement in requirements {
                let count = counts.get(&requirement.tag).copied().unwrap_or(0);
                if count < requirement.count {
                    result.failures.push(Failure {
                        code: "coverage_minimum".into(),
                        case_id: None,
                        variant_id: Some(variant.id.clone()),
                        message: format!(
                            "The {kind} tag {} has {count} unique labeled captures. The minimum is {}.",
                            requirement.tag, requirement.count,
                        ),
                    });
                }
            }
        }
        result.coverage.push(observed);
    }
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
        && args.min_policy_rule.is_empty()
        && args.min_conflict_kind.is_empty()
    {
        return None;
    }
    let mut result = GateResult {
        schema_version: 1,
        passed: false,
        authorizes_acceptance: false,
        limits: Limits {
            unsafe_acceptances: args.max_unsafe_acceptances.unwrap_or(0),
            label_mismatches: args.max_label_mismatches.unwrap_or(0),
            regressions: args.max_regressions.unwrap_or(0),
            policy_rules: args.min_policy_rule.clone(),
            conflict_kinds: args.min_conflict_kind.clone(),
        },
        observed: Observed::default(),
        regressions: Vec::new(),
        failures: Vec::new(),
        coverage: Vec::new(),
        baseline: baseline
            .and_then(|baseline| baseline.as_ref().ok())
            .cloned(),
    };
    if let Err(error) = validate_requirements(args) {
        result.failure("invalid_coverage", None, format!("{error:#}"));
    }
    for row in comparisons {
        result.observed.unsafe_acceptances += usize::from(unsafe_acceptance(row));
        result.observed.label_mismatches += usize::from(label_mismatch(row));
        result.observed.execution_errors += usize::from(row.execution_error.is_some());
        result.observed.incomplete_comparisons += usize::from(!complete(row));
    }
    let current = matrix(comparisons, manifest, false, &mut result);
    coverage(args, manifest, comparisons, &current, &mut result);
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
                    result.failure("incompatible_dataset", Some(row), "The baseline candidate, ordered base, label, snapshot, human histories, or effective settings differ.".into());
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

pub(super) fn validate_report(report: &Report) -> Result<()> {
    ensure!(
        report.schema_version == 1
            && !report.authorizes_acceptance
            && report.infrastructure_errors == 0,
        "Promotion needs a successful version 1 replay report without acceptance authority."
    );
    ensure!(
        report.repository.is_absolute() && report.manifest.is_absolute(),
        "The promotion report needs absolute source and input path bindings."
    );
    let declared = report
        .gate
        .as_ref()
        .context("Promotion needs a complete release gate result.")?;
    ensure!(
        declared.schema_version == 1 && declared.passed && !declared.authorizes_acceptance,
        "Promotion needs a declared passing release gate without acceptance authority."
    );
    let manifest = Manifest {
        schema_version: report.schema_version,
        repository: report.repository.clone(),
        main: report.main.clone(),
        inbox: report.inbox.clone(),
        cases: report.cases.clone(),
        variants: report.variants.clone(),
        configuration: report.configuration.clone(),
    };
    validate(&manifest, &manifest.configuration.policy_path)?;
    let args = ReplayArgs {
        gate: true,
        max_unsafe_acceptances: Some(declared.limits.unsafe_acceptances),
        max_label_mismatches: Some(declared.limits.label_mismatches),
        max_regressions: Some(declared.limits.regressions),
        min_policy_rule: declared.limits.policy_rules.clone(),
        min_conflict_kind: declared.limits.conflict_kinds.clone(),
        ..ReplayArgs::default()
    };
    validate_requirements(&args)?;
    validate_variant_rows(&report.comparisons, &report.variants)?;
    if let Some(baseline) = &declared.baseline {
        validate_variant_rows(&baseline.comparisons, &baseline.variants)?;
    }
    let baseline = declared.baseline.clone().map(Ok);
    let observed = evaluate(
        &args,
        &manifest,
        &report.repository,
        &report.comparisons,
        baseline.as_ref(),
    )
    .context("Promotion needs a release gate result.")?;
    ensure!(
        observed.passed,
        "The promotion report fails its declared release gate requirements."
    );
    ensure!(
        serde_json::to_value(&observed)? == serde_json::to_value(declared)?,
        "The promotion report contains a false release gate claim."
    );
    let summaries: Vec<_> = report
        .variants
        .iter()
        .map(|variant| summarize(&variant.id, &report.comparisons))
        .collect();
    ensure!(
        serde_json::to_value(summaries)? == serde_json::to_value(&report.summaries)?,
        "The promotion report summaries differ from its comparison rows."
    );
    if let Some(digest) = &report.bundle_sha256 {
        ensure!(
            crate::release_policy::valid_digest(digest),
            "The promotion report has an invalid bundle digest."
        );
    }
    if let Some(policy) = &report.release_policy {
        ensure!(
            policy.schema_version == 1
                && policy.source_repository.is_absolute()
                && !policy.main.trim().is_empty()
                && !policy.main.starts_with('-')
                && !policy.main.chars().any(char::is_control)
                && crate::release_policy::valid_digest(&policy.policy_sha256),
            "The promotion report has invalid trusted policy evidence."
        );
    }
    validate_signature_evidence(report, declared.baseline.is_some())?;
    Ok(())
}

pub(super) fn validate_variant_rows(rows: &[Comparison], variants: &[Variant]) -> Result<()> {
    for row in rows {
        ensure!(
            variants.iter().any(|variant| variant.id == row.variant_id
                && variant.model == row.model
                && variant.api == row.api
                && variant.revision == row.revision),
            "A promotion comparison differs from its declared model variant."
        );
    }
    Ok(())
}

fn validate_signature_evidence(report: &Report, has_baseline: bool) -> Result<()> {
    let signatures = &report.signatures;
    ensure!(
        signatures.strict || (signatures.bundle.is_none() && signatures.baseline.is_none()),
        "The promotion report has inconsistent signature mode evidence."
    );
    if signatures.strict {
        ensure!(
            (report.bundle_sha256.is_some() || has_baseline)
                && report.bundle_sha256.is_some() == signatures.bundle.is_some()
                && has_baseline == signatures.baseline.is_some(),
            "The promotion report lacks required artifact signature evidence."
        );
    }
    for (kind, namespace, evidence) in [
        (
            crate::artifact::Kind::Bundle,
            "patchgate-bundle-v1",
            &signatures.bundle,
        ),
        (
            crate::artifact::Kind::Baseline,
            "patchgate-baseline-v1",
            &signatures.baseline,
        ),
    ] {
        if let Some(verified) = evidence {
            ensure!(
                verified.schema_version == 1
                    && !verified.authorizes_acceptance
                    && verified.kind == kind
                    && verified.namespace == namespace
                    && !verified.identity.trim().is_empty()
                    && !verified.identity.chars().any(char::is_control)
                    && verified.signer_fingerprint.starts_with("SHA256:")
                    && verified.signer_fingerprint.len() > 7
                    && !verified.signer_fingerprint.chars().any(char::is_control)
                    && crate::release_policy::valid_digest(&verified.sha256)
                    && crate::release_policy::valid_digest(&verified.allowed_signers_sha256)
                    && verified
                        .revoked_keys_sha256
                        .as_deref()
                        .is_none_or(crate::release_policy::valid_digest),
                "The promotion report has invalid artifact signature evidence."
            );
        }
    }
    if let Some(bundle) = &signatures.bundle {
        ensure!(
            Some(&bundle.sha256) == report.bundle_sha256.as_ref(),
            "The report bundle digest differs from its signature evidence."
        );
    }
    validate_trust_consistency(signatures.bundle.as_ref(), signatures.baseline.as_ref())?;
    Ok(())
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
            min_policy_rule: Vec::new(),
            min_conflict_kind: Vec::new(),
            bundle_signature: None,
            baseline_signature: None,
            allowed_signers: None,
            revoked_keys: None,
            release_repo: None,
            release_main: None,
            signer: None,
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
                row.evidence = Some(json!({
                    "schema_version": 1, "dry_run": true, "authorizes_acceptance": false,
                    "records": [{"hash": row.candidate, "decision": row.actual}], "items": [],
                    "configuration": {"values": row.configuration},
                }));
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
        for field in 0..13 {
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
                9 => previous.schema_version = 99,
                10 => row.tags.push(TagRecord {
                    user: "reviewer".into(),
                    time: "2026-10-21T00:00:00Z".into(),
                    reason: "The reviewer identifies a policy rule.".into(),
                    policy_rules: vec!["policy".into()],
                    conflict_kinds: Vec::new(),
                }),
                11 => row.notes.push(serde_json::from_value(json!({
                    "user": "reviewer", "time": "2026-10-21T00:00:00Z",
                    "kind": "comment", "text": "Inspect the file contract.",
                    "references": ["issue:42"], "anchor": null,
                })).unwrap()),
                _ => row.seen.push(SeenRecord {
                    user: "reviewer".into(), time: "2026-10-21T00:00:00Z".into(),
                    path: "value.txt".into(), content_sha256: "a".repeat(64), seen: true,
                }),
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
        let bytes = baseline_bytes(&path)?;
        let previous = read_baseline(&bytes);
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

    fn captured_manifest() -> Manifest {
        let mut manifest = manifest();
        let configuration = manifest.configuration.clone();
        for case in &mut manifest.cases {
            case.snapshot = Some(json!({
                "repository": manifest.repository,
                "main": manifest.main,
                "inbox": manifest.inbox,
                "base": case.base,
                "candidate": case.candidate,
                "policy_path": configuration.policy_path,
                "configuration": {"values": configuration},
            }));
            case.labels = vec![json!({
                "user": "reviewer", "time": "2026-10-21T00:00:00Z",
                "expected": "reject", "reason": "The reviewer rejects the change.",
            })];
            case.tags = vec![TagRecord {
                user: "reviewer".into(),
                time: "2026-10-21T00:00:00Z".into(),
                reason: "The reviewer identifies the applicable rule and conflict.".into(),
                policy_rules: vec!["protected-path".into()],
                conflict_kinds: vec!["content".into()],
            }];
        }
        manifest
    }

    #[test]
    fn coverage_requires_unique_captures_and_activates_the_gate() {
        let mut manifest = captured_manifest();
        let mut args = args();
        args.gate = false;
        args.min_policy_rule = vec![parse_requirement("protected-path=2").unwrap()];
        args.min_conflict_kind = vec![parse_requirement("content=2").unwrap()];
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        let result = evaluate_rows(&args, &manifest, &current, None);
        assert!(result.passed);
        assert_eq!(result.coverage[0].policy_rules["protected-path"], 2);
        manifest.cases[1].snapshot = manifest.cases[0].snapshot.clone();
        manifest.cases[1].candidate = manifest.cases[0].candidate.clone();
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        let result = evaluate_rows(&args, &manifest, &current, None);
        assert!(!result.passed);
        assert_eq!(result.coverage[0].policy_rules["protected-path"], 1);
        assert_eq!(result.coverage[0].conflict_kinds["content"], 1);
        assert!(
            result
                .failures
                .iter()
                .any(|failure| failure.code == "coverage_minimum")
        );
    }

    #[test]
    fn coverage_excludes_errors_missing_rows_duplicates_and_unlabeled_cases() {
        let manifest = captured_manifest();
        let mut args = args();
        args.min_policy_rule = vec![parse_requirement("protected-path=2").unwrap()];
        for defect in 0..7 {
            let mut manifest = captured_manifest();
            let mut current = rows(&manifest, [Label::Reject, Label::Reject]);
            match defect {
                0 => current[0].execution_error = Some("The model is unavailable.".into()),
                1 => {
                    current.remove(0);
                }
                2 => {
                    let duplicate =
                        serde_json::from_value(serde_json::to_value(&current[0]).unwrap()).unwrap();
                    current.push(duplicate);
                }
                3 => current[0].exit_code = Some(1),
                4 => {
                    manifest.cases[0].labels.clear();
                    current[0].labels.clear();
                }
                5 => {
                    manifest.cases[0].snapshot = None;
                    current[0].snapshot = None;
                }
                _ => current[0].evidence = None,
            }
            let result = evaluate_rows(&args, &manifest, &current, None);
            assert!(!result.passed, "{defect}");
            assert_eq!(
                result.coverage[0].policy_rules["protected-path"], 1,
                "{defect}"
            );
        }
        assert!(validate(&manifest, "POLICY.md").is_ok());
    }

    #[test]
    fn coverage_uses_latest_tag_set_and_each_variant() {
        let mut manifest = captured_manifest();
        manifest.cases[0].tags.push(TagRecord {
            user: "reviewer".into(),
            time: "2026-10-21T01:00:00Z".into(),
            reason: "The reviewer clears the tags.".into(),
            policy_rules: Vec::new(),
            conflict_kinds: Vec::new(),
        });
        let mut second: Variant =
            serde_json::from_value(serde_json::to_value(&manifest.variants[0]).unwrap()).unwrap();
        second.id = "second-model".into();
        manifest.variants.push(second);
        let mut current = rows(&manifest, [Label::Reject, Label::Reject]);
        let mut more = rows(&manifest, [Label::Reject, Label::Reject]);
        for row in &mut more {
            row.variant_id = "second-model".into();
        }
        more[1].execution_error = Some("The model is unavailable.".into());
        current.extend(more);
        let mut args = args();
        args.min_policy_rule = vec![parse_requirement("protected-path=1").unwrap()];
        let result = evaluate_rows(&args, &manifest, &current, None);
        assert!(!result.passed);
        assert_eq!(result.coverage[0].policy_rules["protected-path"], 1);
        assert_eq!(result.coverage[1].policy_rules["protected-path"], 0);
    }

    #[test]
    fn coverage_rejects_unknown_snapshot_fields_and_ignores_configuration_metadata() {
        let mut manifest = captured_manifest();
        let mut args = args();
        args.min_policy_rule = vec![parse_requirement("protected-path=2").unwrap()];
        manifest.cases[1] = manifest.cases[0].clone();
        manifest.cases[1].id = "duplicate".into();
        manifest.cases[1].snapshot.as_mut().unwrap()["configuration"]["source"] = json!("file");
        manifest.cases[1].snapshot.as_mut().unwrap()["configuration"]["path"] = json!("/extra");
        manifest.cases[1].snapshot.as_mut().unwrap()["configuration"]["sha256"] =
            json!("f".repeat(64));
        assert!(validate(&manifest, "POLICY.md").is_ok());
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        let result = evaluate_rows(&args, &manifest, &current, None);
        assert!(!result.passed);
        assert_eq!(result.coverage[0].policy_rules["protected-path"], 1);
        manifest.cases[1].tags[0].reason = "The reviewer changes the duplicate history.".into();
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[1].tags = manifest.cases[0].tags.clone();
        manifest.cases[1].snapshot.as_mut().unwrap()["nonce"] = json!("extra");
        assert!(validate(&manifest, "POLICY.md").is_err());
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        let result = evaluate_rows(&args, &manifest, &current, None);
        assert!(!result.passed);
        assert_eq!(result.coverage[0].policy_rules["protected-path"], 1);
    }

    #[test]
    fn malformed_and_duplicate_coverage_requirements_fail() {
        for value in [
            "", "TAG=1", "tag", "tag=-1", "tag=+1", "tag=1=2", "tag=", "tag= 1",
        ] {
            assert!(parse_requirement(value).is_err(), "{value}");
        }
        let mut args = args();
        args.min_policy_rule = vec![
            parse_requirement("tag=1").unwrap(),
            parse_requirement("tag=2").unwrap(),
        ];
        assert!(validate_requirements(&args).is_err());
    }

    #[test]
    fn current_and_baseline_rows_reject_contradictory_review_evidence() {
        let manifest = manifest();
        let current = rows(&manifest, [Label::Reject, Label::Reject]);
        for (pointer, value) in [
            ("/records/0/decision", json!("accept")),
            ("/schema_version", json!(2)),
            ("/dry_run", json!(false)),
            ("/authorizes_acceptance", json!(true)),
        ] {
            let mut altered = current.clone();
            *altered[0]
                .evidence
                .as_mut()
                .unwrap()
                .pointer_mut(pointer)
                .unwrap() = value;
            assert!(!evaluate_rows(&args(), &manifest, &altered, None).passed);
            let previous = Ok(baseline(&manifest, &altered));
            assert!(!evaluate_rows(&args(), &manifest, &current, Some(&previous)).passed);
        }
        for (field, value) in [
            ("execution_error", json!("The candidate review failed.")),
            ("by", json!("human")),
        ] {
            let mut altered = current.clone();
            altered[0].evidence.as_mut().unwrap()["records"][0][field] = value;
            assert!(!evaluate_rows(&args(), &manifest, &altered, None).passed);
            let previous = Ok(baseline(&manifest, &altered));
            assert!(!evaluate_rows(&args(), &manifest, &current, Some(&previous)).passed);
        }
    }
}
