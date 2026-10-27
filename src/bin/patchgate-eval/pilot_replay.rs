use super::*;

pub(super) struct PilotReplay {
    pub manifest: Manifest,
    pub comparisons: Vec<Comparison>,
    pub started_at: Option<String>,
    pub protected_repositories: Vec<PathBuf>,
}

pub(super) fn read_pilot_replay(bytes: &[u8]) -> Result<PilotReplay> {
    read_inner(bytes).map_err(|_| anyhow!("The replay report has invalid pilot evidence."))
}

fn read_inner(bytes: &[u8]) -> Result<PilotReplay> {
    let report: Report = serde_json::from_slice(bytes)?;
    ensure!(
        report.schema_version == 1
            && !report.authorizes_acceptance
            && report.repository.is_absolute()
            && report.manifest.is_absolute(),
        "The pilot needs a version 1 replay report with absolute source bindings."
    );
    if let Some(time) = &report.started_at {
        chrono::DateTime::parse_from_rfc3339(time)?;
    }
    let mut protected_repositories = vec![report.repository.clone()];
    for case in &report.cases {
        if let Some(snapshot) = &case.snapshot {
            let repository = snapshot["repository"]
                .as_str()
                .context("The captured source path is absent.")?;
            protected_repositories.push(PathBuf::from(repository));
        }
    }
    if let Some(policy) = &report.release_policy {
        ensure!(
            policy.schema_version == 1
                && policy.source_repository.is_absolute()
                && !policy.main.trim().is_empty()
                && !policy.main.starts_with('-')
                && !policy.main.chars().any(char::is_control)
                && crate::release_policy::valid_digest(&policy.policy_sha256),
            "The pilot release source binding is not valid."
        );
        protected_repositories.push(policy.source_repository.clone());
    }
    protected_repositories.sort();
    protected_repositories.dedup();
    let manifest = Manifest {
        schema_version: report.schema_version,
        repository: report.repository,
        main: report.main,
        inbox: report.inbox,
        configuration: report.configuration,
        cases: report.cases,
        variants: report.variants,
    };
    validate_manifest(&manifest, &manifest.configuration.policy_path, false)?;
    release_gate::validate_variant_rows(&report.comparisons, &manifest.variants)?;
    let cases: BTreeMap<_, _> = manifest
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect();
    let mut rows = BTreeSet::new();
    for row in &report.comparisons {
        ensure!(
            rows.insert((row.case_id.as_str(), row.variant_id.as_str())),
            "The pilot replay contains duplicate comparison rows."
        );
        let case = cases
            .get(row.case_id.as_str())
            .context("The pilot replay contains an unknown case.")?;
        ensure!(
            release_gate::matches_case(row, case, &manifest.configuration)
                && row.elapsed_seconds.is_finite()
                && row.elapsed_seconds >= 0.0
                && row.unsafe_acceptance
                    == row
                        .actual
                        .map(|actual| { actual == Label::Accept && row.expected != Label::Accept })
                && row.escalation == row.actual.map(|actual| actual == Label::Escalate)
                && row.correct == row.actual.map(|actual| actual == row.expected),
            "The pilot comparison differs from its case or decision."
        );
    }
    let expected_rows = manifest
        .cases
        .len()
        .checked_mul(manifest.variants.len())
        .context("The pilot comparison count exceeds its limit.")?;
    ensure!(
        rows.len() == expected_rows,
        "The pilot replay has an incomplete comparison matrix."
    );
    ensure!(
        report.infrastructure_errors
            == report
                .comparisons
                .iter()
                .filter(|row| row.execution_error.is_some())
                .count(),
        "The pilot replay has an incorrect infrastructure error count."
    );
    ensure!(
        report.summaries.len() == manifest.variants.len()
            && report
                .summaries
                .iter()
                .zip(&manifest.variants)
                .all(|(summary, variant)| {
                    summary == &summarize(&variant.id, &report.comparisons)
                }),
        "The pilot replay summaries differ from its comparison rows."
    );
    Ok(PilotReplay {
        manifest,
        comparisons: report.comparisons,
        started_at: report.started_at,
        protected_repositories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        serde_json::from_slice(&successful_promotion_report()).unwrap()
    }

    fn bytes(report: &Report) -> Vec<u8> {
        serde_json::to_vec(report).unwrap()
    }

    fn summarize_report(report: &mut Report) {
        report.summaries = report
            .variants
            .iter()
            .map(|variant| summarize(&variant.id, &report.comparisons))
            .collect();
        report.infrastructure_errors = report
            .comparisons
            .iter()
            .filter(|row| row.execution_error.is_some())
            .count();
    }

    #[test]
    fn unsafe_and_failed_observations_do_not_need_a_passing_gate() -> Result<()> {
        let mut report = report();
        report.gate = None;
        let row = &mut report.comparisons[0];
        row.decision(Some(Label::Accept), "verdict".into());
        row.evidence.as_mut().unwrap()["records"][0]["decision"] = json!("accept");
        summarize_report(&mut report);
        let accepted = read_pilot_replay(&bytes(&report))?;
        assert_eq!(accepted.comparisons[0].unsafe_acceptance, Some(true));

        let row = &mut report.comparisons[0];
        row.decision(None, "execution_error".into());
        row.execution_error = Some("The model request failed.".into());
        row.evidence = None;
        row.exit_code = Some(1);
        summarize_report(&mut report);
        let failed = read_pilot_replay(&bytes(&report))?;
        assert!(!release_gate::complete(&failed.comparisons[0]));
        Ok(())
    }

    #[test]
    fn false_summaries_counts_and_decision_flags_fail() {
        let mut changed = report();
        changed.summaries[0].unsafe_acceptances = 1;
        assert!(read_pilot_replay(&bytes(&changed)).is_err());
        changed = report();
        changed.infrastructure_errors = 1;
        assert!(read_pilot_replay(&bytes(&changed)).is_err());
        changed = report();
        changed.comparisons[0].unsafe_acceptance = Some(true);
        assert!(read_pilot_replay(&bytes(&changed)).is_err());
    }

    #[test]
    fn duplicate_missing_and_incompatible_matrix_rows_fail() {
        let mut changed = report();
        changed.comparisons.push(changed.comparisons[0].clone());
        summarize_report(&mut changed);
        assert!(read_pilot_replay(&bytes(&changed)).is_err());
        changed = report();
        changed.comparisons.clear();
        summarize_report(&mut changed);
        assert!(read_pilot_replay(&bytes(&changed)).is_err());
        changed = report();
        changed.comparisons[0].model = "another-model".into();
        assert!(read_pilot_replay(&bytes(&changed)).is_err());
        changed = report();
        changed.comparisons[0].candidate = "B".repeat(53);
        assert!(read_pilot_replay(&bytes(&changed)).is_err());
    }

    #[test]
    fn old_chronology_stays_absent_and_bad_timestamps_fail() -> Result<()> {
        let old = read_pilot_replay(&successful_promotion_report())?;
        assert!(old.started_at.is_none());
        let mut report = report();
        report.started_at = Some("PRIVATE_INVALID_TIME".into());
        let error = read_pilot_replay(&bytes(&report)).err().unwrap();
        assert!(!format!("{error:#}").contains("PRIVATE_INVALID_TIME"));
        Ok(())
    }
}
