use anyhow::Result;
use serde::Serialize;

use crate::cases::CaseRecord;
use crate::configuration::Evidence;
use crate::gate::{DependencyInfo, Explanation, Record, State};
use crate::pijul::{NativeVertexKind, ReviewChange};
use crate::review::ReviewBinding;
use crate::review_delta::AnnotationReport;
use crate::secrets::Finding;

#[derive(Serialize)]
pub struct Blocker {
    pub code: String,
    pub detail: String,
}

#[derive(Serialize)]
pub struct RecordStatus {
    pub record_index: usize,
    pub scope: String,
    pub review_binding_matches: Option<bool>,
    pub configuration_matches: Option<bool>,
    pub verification_recorded: bool,
}

#[derive(Serialize)]
pub struct Guide {
    pub candidate: Option<ReviewChange>,
    pub context_unavailable: Option<String>,
    pub conflicts: Vec<crate::change::Conflict>,
    pub preview_includes_unmet_dependencies: bool,
    pub policy_text: Option<String>,
    pub policy_rule_ids: Vec<String>,
    pub policy_error: Option<String>,
    pub findings: Vec<Finding>,
    pub blockers: Vec<Blocker>,
    pub evidence: Vec<RecordStatus>,
    pub annotations: Option<AnnotationReport>,
}

pub struct Input<'a> {
    pub binding: &'a ReviewBinding,
    pub configuration: &'a Evidence,
    pub policy: Option<String>,
    pub context: Result<ReviewChange>,
    pub conflicts: Vec<crate::change::Conflict>,
    pub protected_paths: &'a [String],
    pub dependencies: &'a [DependencyInfo],
    pub records: &'a [Record],
    pub cases: &'a [CaseRecord],
    pub state: State,
}

/// Present recorded evidence without a new verdict or acceptance authority.
pub fn build(input: Input<'_>) -> Result<Guide> {
    let mut findings = Vec::new();
    let (mut candidate, mut context_unavailable) = match input.context {
        Ok(candidate) => {
            findings.extend(crate::secrets::scan_change(&candidate));
            (Some(candidate), None)
        }
        Err(error) => {
            let detail = error.to_string();
            let detail =
                if crate::secrets::scan_text("[review.context]", detail.as_bytes()).is_empty() {
                    detail
                } else {
                    "Exact native text context is unavailable.".into()
                };
            (None, Some(detail))
        }
    };
    let mut policy_text = input.policy;
    if let Some(policy) = &policy_text {
        let policy_findings = crate::secrets::scan_text("[policy]", policy.as_bytes());
        if !policy_findings.is_empty() {
            findings.extend(policy_findings);
            policy_text = None;
        }
    }
    for record in input.records {
        if input.binding.candidates.contains(&record.hash) {
            for finding in &record.findings {
                if !findings.contains(finding) {
                    findings.push(finding.clone());
                }
            }
        }
    }
    if !findings.is_empty() {
        candidate = None;
        context_unavailable = Some(
            "Source context is omitted because credential checks found supported formats.".into(),
        );
    }
    let (policy_rule_ids, policy_error) = match policy_text.as_deref() {
        Some(policy) => match crate::change::policy_rules(policy) {
            Ok(rules) => (rules.into_iter().map(|rule| rule.id).collect(), None),
            Err(error) => (Vec::new(), Some(error)),
        },
        None => (
            Vec::new(),
            Some("Trusted policy text is absent or contains credential data.".into()),
        ),
    };
    let mut blockers = Vec::new();
    if !findings.is_empty() {
        blockers.push(Blocker {
            code: "credential_data".into(),
            detail: "Supported credential data prevents acceptance of this source.".into(),
        });
    }
    if !input.protected_paths.is_empty() && input.state != State::Accepted {
        blockers.push(Blocker {
            code: "protected_paths".into(),
            detail: "Protected paths need an explicit human decision.".into(),
        });
    }
    for dependency in input
        .dependencies
        .iter()
        .filter(|dependency| !dependency.in_main)
    {
        blockers.push(Blocker {
            code: "dependency".into(),
            detail: format!(
                "Dependency {} is {} and is not in main.",
                dependency.hash,
                dependency.state.as_str()
            ),
        });
    }
    let mut conflicts = input.conflicts;
    for conflict in &mut conflicts {
        if !matches!(
            conflict.kind.as_str(),
            "Order conflict"
                | "Deletion conflict"
                | "Name conflict"
                | "Zombie conflict"
                | "Cyclic conflict"
        ) {
            conflict.kind = "Other conflict".into();
        }
        if !findings.is_empty()
            || !crate::secrets::scan_text("[conflict.path]", conflict.path.as_bytes()).is_empty()
            || conflict.path.chars().any(char::is_control)
        {
            conflict.path = "[redacted-path]".into();
        }
    }
    if !conflicts.is_empty() {
        blockers.push(Blocker {
            code: "native_conflicts".into(),
            detail: "A native merge must remove the reported conflicts before acceptance.".into(),
        });
    }
    if policy_error.is_some() {
        blockers.push(Blocker {
            code: "policy".into(),
            detail: "The trusted policy needs inspection before model review.".into(),
        });
    }
    if let Some(detail) = match input.state {
        State::Rejected => Some("A corrected native change is necessary before another review."),
        State::Escalated => Some("A human must inspect the change and decide explicitly."),
        State::Removed | State::Reverted => {
            Some("The earlier removal needs inspection before another decision.")
        }
        State::Unknown => Some("The channel and dependency state need inspection."),
        _ => None,
    } {
        blockers.push(Blocker {
            code: "decision".into(),
            detail: detail.into(),
        });
    }
    let evidence = input
        .records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let review_binding_matches = record
                .review
                .as_ref()
                .map(|binding| binding == input.binding);
            let configuration_matches = record
                .configuration
                .as_ref()
                .map(|configuration| configuration.as_ref() == input.configuration);
            let scope = match review_binding_matches {
                Some(true) if configuration_matches == Some(true) => "current_review",
                Some(_) => "historical_review",
                None => "recorded_decision_without_model_binding",
            };
            RecordStatus {
                record_index: index + 1,
                scope: scope.into(),
                review_binding_matches,
                configuration_matches,
                verification_recorded: record.verification.is_some(),
            }
        })
        .collect();
    let annotations = candidate
        .as_ref()
        .map(|candidate| {
            crate::review_delta::annotations(
                input.binding,
                input.configuration,
                candidate,
                input.cases,
            )
        })
        .transpose()?;
    Ok(Guide {
        candidate,
        context_unavailable,
        conflicts,
        preview_includes_unmet_dependencies: input
            .dependencies
            .iter()
            .any(|dependency| !dependency.in_main),
        policy_text,
        policy_rule_ids,
        policy_error,
        findings,
        blockers,
        evidence,
        annotations,
    })
}

pub(crate) fn write_text(
    output: &mut impl std::io::Write,
    prefix: &str,
    value: &str,
) -> std::io::Result<()> {
    if value.is_empty() {
        return writeln!(output, "{prefix}[empty]");
    }
    for line in value.split_inclusive('\n') {
        writeln!(
            output,
            "{prefix}{}",
            line.strip_suffix('\n').unwrap_or(line).escape_debug()
        )?;
    }
    if !value.ends_with('\n') {
        writeln!(output, "  [no final LF]")?;
    }
    Ok(())
}

fn text(prefix: &str, value: &str) {
    write_text(&mut std::io::stdout().lock(), prefix, value).expect("Write native source evidence");
}

pub fn show(explanation: &Explanation) -> Result<()> {
    println!(
        "{}  {}",
        explanation.hash,
        explanation.message.escape_debug()
    );
    println!("State: {}", explanation.state.as_str());
    println!("Author intent comes from the native change message. It is not a verified claim.");
    println!("Current trusted review binding:");
    crate::print_json(&explanation.current)?;
    for blocker in &explanation.guide.blockers {
        println!(
            "Blocker [{}]: {}",
            blocker.code,
            blocker.detail.escape_debug()
        );
    }
    for dependency in &explanation.dependencies {
        println!(
            "Dependency: {} ({}, in main: {})",
            dependency.hash,
            dependency.state.as_str(),
            dependency.in_main
        );
        for need in &dependency.needs {
            println!("  needs {need}");
        }
    }
    if !explanation.guide.conflicts.is_empty() {
        println!("Native conflicts in the private main-plus-candidate preview:");
        crate::print_json(&explanation.guide.conflicts)?;
    }
    if explanation.guide.preview_includes_unmet_dependencies {
        println!(
            "The private conflict preview includes unmet prerequisites. It grants no acceptance authority."
        );
    }
    println!("Trusted policy:");
    if let Some(policy) = &explanation.guide.policy_text {
        text("  ", policy);
    }
    if let Some(error) = &explanation.guide.policy_error {
        println!("Policy limit: {}", error.escape_debug());
    }
    if explanation.guide.candidate.is_none() {
        for path in &explanation.paths {
            let protected = if explanation.protected_paths.contains(path) {
                " (protected)"
            } else {
                ""
            };
            println!("Path: {}{protected}", path.escape_debug());
        }
    }
    if let Some(candidate) = &explanation.guide.candidate {
        println!("Native source evidence:");
        for file in &candidate.context.files {
            let protected = if explanation.protected_paths.contains(&file.path) {
                " (protected)"
            } else {
                ""
            };
            println!("Path: {}{protected}", file.path.escape_debug());
            for (index, vertex) in file.vertices.iter().enumerate() {
                let (kind, prefix) = match vertex.kind {
                    NativeVertexKind::Add => ("add", "+ "),
                    NativeVertexKind::Del => ("del", "- "),
                    NativeVertexKind::Keep => ("keep", "  "),
                };
                println!(
                    "  Span {}: {kind} {} {}..{}",
                    index + 1,
                    vertex.change,
                    vertex.start,
                    vertex.end
                );
                text(prefix, &vertex.text);
            }
        }
        for file in &candidate.metadata_context {
            let protected = if explanation.protected_paths.contains(&file.path) {
                " (protected)"
            } else {
                ""
            };
            println!("Metadata path: {}{protected}", file.path.escape_debug());
            match &file.before {
                Some(before) => text("- ", before),
                None => println!("  Before: absent"),
            }
            match &file.after {
                Some(after) => text("+ ", after),
                None => println!("  After: absent"),
            }
        }
    }
    if let Some(limit) = &explanation.guide.context_unavailable {
        println!("Context limit: {}", limit.escape_debug());
    }
    for finding in &explanation.guide.findings {
        println!(
            "Credential finding: {} {}:{}",
            finding.rule_id,
            finding.path.escape_debug(),
            finding.line
        );
    }
    if let Some(checks) = &explanation.checks {
        println!("Declared trusted checks. This declaration is not a successful result:");
        crate::print_json(checks)?;
    } else {
        println!("Trusted main declares no Nix checks.");
    }
    for status in &explanation.guide.evidence {
        println!("Evidence {}: {}", status.record_index, status.scope);
        crate::print_json(&explanation.records[status.record_index - 1])?;
    }
    if let Some(annotations) = &explanation.guide.annotations {
        crate::review_delta::show_annotations(annotations);
    }
    for action in &explanation.next_actions {
        println!("Next: {action}");
    }
    println!(
        "This view does not authorize acceptance. Recorded verification does not replace live guards."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::Values;
    use crate::pijul::{NativeContext, NativeContextFile, NativeVertex};
    use crate::review::MainBinding;

    fn fixture(text: &str) -> (ReviewBinding, Evidence, ReviewChange) {
        let hash = "A".repeat(53);
        let binding = ReviewBinding {
            candidates: vec![hash.clone()],
            policy: None,
            main: MainBinding {
                channel: "main".into(),
                state: Some("current-state".into()),
            },
        };
        let configuration = Evidence {
            source: "environment".into(),
            path: None,
            sha256: None,
            values: Values::default(),
        };
        let candidate = ReviewChange {
            hash: hash.clone(),
            message: "Change the value".into(),
            authors: vec!["author".into()],
            timestamp: "2026-10-26T00:00:00Z".into(),
            dependencies: Vec::new(),
            paths: ["value.txt".into()].into_iter().collect(),
            context: NativeContext {
                full: true,
                files: vec![NativeContextFile {
                    path: "value.txt".into(),
                    vertices: vec![NativeVertex {
                        change: hash,
                        start: 0,
                        end: text.len() as u64,
                        kind: NativeVertexKind::Add,
                        text: text.into(),
                    }],
                }],
            },
            metadata_context: Vec::new(),
        };
        (binding, configuration, candidate)
    }

    #[test]
    fn credential_source_is_absent_from_the_review_surface() -> Result<()> {
        let credential = ["ghp_", &"A".repeat(36)].concat();
        let (binding, configuration, candidate) = fixture(&credential);
        let guide = build(Input {
            binding: &binding,
            configuration: &configuration,
            policy: Some("Accept safe changes.".into()),
            context: Ok(candidate),
            conflicts: Vec::new(),
            protected_paths: &[],
            dependencies: &[],
            records: &[],
            cases: &[],
            state: State::Pending,
        })?;
        assert!(guide.candidate.is_none());
        assert!(
            guide
                .findings
                .iter()
                .any(|finding| finding.rule_id == "github-token")
        );
        assert!(!serde_json::to_string(&guide)?.contains(&credential));
        Ok(())
    }

    #[test]
    fn old_binding_and_unknown_evidence_cannot_claim_current_review() -> Result<()> {
        let (binding, configuration, candidate) = fixture("safe source\n");
        let current: Record = serde_json::from_value(serde_json::json!({
            "hash": candidate.hash,
            "decision": "escalate",
            "review": binding,
            "configuration": configuration,
        }))?;
        let mut historical = current.clone();
        historical.review.as_mut().unwrap().main.state = Some("old-state".into());
        let unknown: Record = serde_json::from_value(serde_json::json!({
            "hash": candidate.hash,
            "decision": "escalate",
        }))?;
        let guide = build(Input {
            binding: &binding,
            configuration: &configuration,
            policy: Some("Accept safe changes.".into()),
            context: Ok(candidate),
            conflicts: Vec::new(),
            protected_paths: &[],
            dependencies: &[],
            records: &[current, historical, unknown],
            cases: &[],
            state: State::Escalated,
        })?;
        assert_eq!(guide.evidence[0].scope, "current_review");
        assert_eq!(guide.evidence[1].scope, "historical_review");
        assert_eq!(guide.evidence[1].review_binding_matches, Some(false));
        assert_eq!(guide.evidence[2].review_binding_matches, None);
        assert_ne!(guide.evidence[2].scope, "current_review");
        Ok(())
    }

    #[test]
    fn source_text_distinguishes_empty_and_final_line_endings() -> Result<()> {
        let render = |value: &str| -> Result<Vec<u8>> {
            let mut output = Vec::new();
            write_text(&mut output, "  ", value)?;
            Ok(output)
        };
        assert_ne!(render("")?, render("\n")?);
        assert_ne!(render("value")?, render("value\n")?);
        assert_ne!(render("value\n")?, render("value\n\n")?);
        Ok(())
    }
}
