use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};

use anyhow::Result;
use serde::Serialize;

use crate::configuration;
use crate::model;
use crate::pijul::ReviewChange;
use crate::review::{self, ReviewBinding};
use crate::secrets::{self, Finding};

/// Costs count Unicode characters in exact compact JSON objects.
/// Array separators remain in the report metadata and framing cost.
#[derive(Debug, Serialize)]
pub struct FileCost {
    pub path: String,
    pub context: usize,
    pub metadata_context: usize,
    pub total: usize,
}

/// All costs use Unicode characters, not tokens or model capacity.
/// Policy and fixed instructions do not use the structured input limit.
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub limit: usize,
    pub total: usize,
    pub remaining: usize,
    pub excess: usize,
    pub exceeds_limit: bool,
    pub files: Vec<FileCost>,
    /// This includes bindings, native metadata, path lists, and JSON framing.
    pub metadata_framing: usize,
    pub policy: usize,
    /// This excludes policy, transport schemas, and choice criteria.
    pub fixed_instructions: usize,
    pub findings: Vec<Finding>,
}

#[derive(Default)]
struct CharacterCount(usize);

impl Write for CharacterCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.iter().filter(|&&byte| byte & 0xc0 != 0x80).count();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encoded_chars(value: &impl Serialize) -> serde_json::Result<usize> {
    let mut count = CharacterCount::default();
    serde_json::to_writer(&mut count, value)?;
    Ok(count.0)
}

pub fn report(
    candidate: &ReviewChange,
    binding: &ReviewBinding,
    policy: &str,
    configuration: &configuration::Evidence,
    api: model::Api,
) -> Result<Report> {
    let input = review::input(candidate, binding)?;
    let total = input.get().chars().count();
    let mut costs: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for file in &candidate.context.files {
        costs.entry(&file.path).or_default().0 += encoded_chars(file)?;
    }
    for file in &candidate.metadata_context {
        costs.entry(&file.path).or_default().1 += encoded_chars(file)?;
    }

    let mut findings = secrets::scan_change(candidate);
    for finding in &mut findings {
        if !matches!(
            finding.path.as_str(),
            "[change.hash]"
                | "[change.message]"
                | "[change.timestamp]"
                | "[change.author]"
                | "[change.dependency]"
                | "[change.path]"
                | "[context.change]"
        ) {
            finding.path.clear();
            finding.path.push_str("[redacted-path]");
        }
    }
    findings.extend(secrets::scan_text("[policy]", policy.as_bytes()));
    for hash in &binding.candidates {
        findings.extend(secrets::scan_text("[binding.candidate]", hash.as_bytes()));
    }
    if let Some(policy) = &binding.policy {
        findings.extend(secrets::scan_text(
            "[binding.policy.path]",
            policy.path.as_bytes(),
        ));
        findings.extend(secrets::scan_text(
            "[binding.policy.sha256]",
            policy.sha256.as_bytes(),
        ));
    }
    findings.extend(secrets::scan_text(
        "[binding.main.channel]",
        binding.main.channel.as_bytes(),
    ));
    if let Some(state) = &binding.main.state {
        findings.extend(secrets::scan_text("[binding.main.state]", state.as_bytes()));
    }
    for text in [
        Some(configuration.source.as_str()),
        configuration.path.as_deref(),
        configuration.sha256.as_deref(),
        Some(configuration.values.policy_path.as_str()),
    ]
    .into_iter()
    .flatten()
    .chain(configuration.values.protected.iter().map(String::as_str))
    {
        findings.extend(secrets::scan_text("[configuration]", text.as_bytes()));
    }
    findings
        .sort_unstable_by(|a, b| (&a.path, a.line, &a.rule_id).cmp(&(&b.path, b.line, &b.rule_id)));
    findings.dedup();

    let redacted = !findings.is_empty();
    let files: Vec<_> = costs
        .into_iter()
        .map(|(path, (context, metadata_context))| FileCost {
            path: if redacted { "[redacted-path]" } else { path }.to_owned(),
            context,
            metadata_context,
            total: context + metadata_context,
        })
        .collect();
    let file_total: usize = files.iter().map(|file| file.total).sum();
    let limit = configuration.values.max_change_chars;
    Ok(Report {
        schema_version: 1,
        limit,
        total,
        remaining: limit.saturating_sub(total),
        excess: total.saturating_sub(limit),
        exceeds_limit: total > limit,
        files,
        metadata_framing: total - file_total,
        policy: policy.chars().count(),
        fixed_instructions: model::review_instruction_chars(api),
        findings,
    })
}

impl fmt::Display for Report {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(output, "Context budget (Unicode characters, not tokens)")?;
        writeln!(output, "Structured input: {}", self.total)?;
        writeln!(output, "Limit: {}", self.limit)?;
        writeln!(output, "Remaining: {}", self.remaining)?;
        writeln!(output, "Excess: {}", self.excess)?;
        writeln!(output, "Exceeds limit: {}", self.exceeds_limit)?;
        writeln!(output, "Metadata and framing: {}", self.metadata_framing)?;
        writeln!(output, "Policy outside limit: {}", self.policy)?;
        writeln!(
            output,
            "Fixed instructions outside limit: {}",
            self.fixed_instructions
        )?;
        writeln!(
            output,
            "File costs include encoded context and metadata context."
        )?;
        for file in &self.files {
            writeln!(
                output,
                "  {:?}: {} (context {}, metadata context {})",
                file.path, file.total, file.context, file.metadata_context
            )?;
        }
        for finding in &self.findings {
            writeln!(
                output,
                "Credential location: {:?}:{} ({})",
                finding.path, finding.line, finding.rule_id
            )?;
        }
        Ok(())
    }
}

pub fn show(report: &Report) {
    print!("{report}");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::pijul::{
        MetadataContext, NativeContext, NativeContextFile, NativeVertex, NativeVertexKind,
    };
    use crate::review::{MainBinding, PolicyBinding};

    fn candidate() -> ReviewChange {
        ReviewChange {
            hash: "candidate-hash".into(),
            message: "Private change message".into(),
            authors: vec!["Private author".into()],
            timestamp: "2026-10-21T00:00:00Z".into(),
            dependencies: vec!["dependency-hash".into()],
            paths: BTreeSet::from(["café/🛡.rs".into(), "mode".into()]),
            context: NativeContext {
                full: true,
                files: vec![NativeContextFile {
                    path: "café/🛡.rs".into(),
                    vertices: vec![NativeVertex {
                        change: "origin-hash".into(),
                        start: 0,
                        end: 12,
                        kind: NativeVertexKind::Add,
                        text: "保護 \"é\"\n\\\u{0001}".into(),
                    }],
                }],
            },
            metadata_context: vec![
                MetadataContext {
                    path: "café/🛡.rs".into(),
                    before: Some("before\n".into()),
                    after: Some("after 🛡\n".into()),
                },
                MetadataContext {
                    path: "mode".into(),
                    before: None,
                    after: Some("executable".into()),
                },
            ],
        }
    }

    fn binding() -> ReviewBinding {
        ReviewBinding {
            candidates: vec!["candidate-hash".into()],
            policy: Some(PolicyBinding {
                path: "POLICY.md".into(),
                sha256: "policy-digest".into(),
            }),
            main: MainBinding {
                channel: "main".into(),
                state: Some("main-state".into()),
            },
        }
    }

    fn configuration(limit: usize) -> configuration::Evidence {
        configuration::Evidence {
            source: "environment".into(),
            path: None,
            sha256: None,
            values: configuration::Values {
                policy_path: "POLICY.md".into(),
                protected: Vec::new(),
                documentation_paths: Vec::new(),
                max_change_chars: limit,
                timeout_seconds: 300.0,
                check_timeout_seconds: 900.0,
            },
        }
    }

    fn assert_sum(report: &Report) {
        assert_eq!(
            report.total,
            report.metadata_framing + report.files.iter().map(|file| file.total).sum::<usize>()
        );
        for file in &report.files {
            assert_eq!(file.total, file.context + file.metadata_context);
        }
    }

    #[test]
    fn exact_encoded_file_costs_and_unicode_sum() {
        let candidate = candidate();
        let binding = binding();
        let report = report(
            &candidate,
            &binding,
            "保護 🛡",
            &configuration(8000),
            model::Api::OpenAi,
        )
        .unwrap();
        let input = review::input(&candidate, &binding).unwrap();
        assert_eq!(report.total, input.get().chars().count());
        assert!(report.total < input.get().len());
        assert_sum(&report);
        assert_eq!(report.files.len(), 2);
        let first = &report.files[0];
        assert_eq!(first.path, "café/🛡.rs");
        assert_eq!(
            first.context,
            serde_json::to_string(&candidate.context.files[0])
                .unwrap()
                .chars()
                .count()
        );
        assert_eq!(
            first.metadata_context,
            serde_json::to_string(&candidate.metadata_context[0])
                .unwrap()
                .chars()
                .count()
        );
        assert_eq!(report.files[1].context, 0);
        assert_eq!(
            report.files[1].metadata_context,
            serde_json::to_string(&candidate.metadata_context[1])
                .unwrap()
                .chars()
                .count()
        );
        assert_eq!(report.policy, 4);
    }

    #[test]
    fn equality_and_adjacent_limits_do_not_truncate() {
        let mut candidate = candidate();
        candidate.context.files[0].vertices[0].text = "🛡".repeat(10_000);
        let binding = binding();
        let total = review::input(&candidate, &binding)
            .unwrap()
            .get()
            .chars()
            .count();
        for (limit, exceeds, remaining, excess) in [
            (total - 1, true, 0, 1),
            (total, false, 0, 0),
            (total + 1, false, 1, 0),
            (0, true, 0, total),
        ] {
            let report = report(
                &candidate,
                &binding,
                "",
                &configuration(limit),
                model::Api::OpenAi,
            )
            .unwrap();
            assert_eq!(report.total, total);
            assert_eq!(report.exceeds_limit, exceeds);
            assert_eq!(report.remaining, remaining);
            assert_eq!(report.excess, excess);
            assert_sum(&report);
        }
    }

    #[test]
    fn policy_and_api_instructions_stay_outside_limit() {
        let candidate = candidate();
        let binding = binding();
        let total = review::input(&candidate, &binding)
            .unwrap()
            .get()
            .chars()
            .count();
        let policy = "保護 🛡\n".repeat(10_000);
        for api in [model::Api::OpenAi, model::Api::SystemOne] {
            let report = report(&candidate, &binding, &policy, &configuration(total), api).unwrap();
            assert_eq!(report.total, total);
            assert!(!report.exceeds_limit);
            assert_eq!(report.policy, policy.chars().count());
            assert_eq!(
                report.fixed_instructions,
                model::review_instruction_chars(api)
            );
        }
    }

    #[test]
    fn empty_context_assigns_all_input_to_metadata_and_framing() {
        let mut candidate = candidate();
        candidate.context.files.clear();
        candidate.metadata_context.clear();
        let report = report(
            &candidate,
            &binding(),
            "",
            &configuration(8000),
            model::Api::OpenAi,
        )
        .unwrap();
        assert!(report.files.is_empty());
        assert_eq!(report.metadata_framing, report.total);
        assert_sum(&report);
    }

    #[test]
    fn reports_never_disclose_source_messages_or_authors() {
        let candidate = candidate();
        let report = report(
            &candidate,
            &binding(),
            "Private policy text",
            &configuration(8000),
            model::Api::OpenAi,
        )
        .unwrap();
        for output in [serde_json::to_string(&report).unwrap(), report.to_string()] {
            for forbidden in [
                "Private change message",
                "Private author",
                "Private policy text",
                "origin-hash",
                "executable",
                "保護",
            ] {
                assert!(!output.contains(forbidden), "{output}");
            }
        }
    }

    #[test]
    fn credentials_redact_all_paths_without_cost_changes() {
        let secret = format!("ghp_{}", "A1b2".repeat(9));
        for location in 0..8 {
            let mut candidate = candidate();
            let mut binding = binding();
            let mut configuration = configuration(8000);
            let mut policy = "Safe policy".to_owned();
            match location {
                0 => candidate.context.files[0].vertices[0].text = format!("safe\n{secret}\n"),
                1 => candidate.message = secret.clone(),
                2 => candidate.authors = vec![secret.clone()],
                3 => candidate.context.files[0].path = secret.clone(),
                4 => policy = secret.clone(),
                5 => binding.main.channel = secret.clone(),
                6 => configuration.values.policy_path = secret.clone(),
                7 => candidate.metadata_context[0].after = Some(secret.clone()),
                _ => unreachable!(),
            }
            let report = report(
                &candidate,
                &binding,
                &policy,
                &configuration,
                model::Api::OpenAi,
            )
            .unwrap();
            assert_eq!(
                report.total,
                review::input(&candidate, &binding)
                    .unwrap()
                    .get()
                    .chars()
                    .count()
            );
            assert!(!report.findings.is_empty());
            assert!(
                report
                    .files
                    .iter()
                    .all(|file| file.path == "[redacted-path]")
            );
            assert_sum(&report);
            if location == 0 {
                assert!(report.findings.iter().any(|finding| finding.line == 2));
            }
            for output in [serde_json::to_string(&report).unwrap(), report.to_string()] {
                for forbidden in [secret.as_str(), "café/🛡.rs", "\"mode\""] {
                    assert!(!output.contains(forbidden), "{output}");
                }
            }
        }
    }

    #[test]
    fn text_report_escapes_file_control_characters() {
        let mut candidate = candidate();
        candidate.context.files[0].path = "file\n\u{001b}[31m".into();
        let report = report(
            &candidate,
            &binding(),
            "",
            &configuration(8000),
            model::Api::OpenAi,
        )
        .unwrap();
        let text = report.to_string();
        assert!(!text.contains('\u{001b}'));
        assert!(text.contains("file\\n\\u{1b}[31m"));
    }

    #[test]
    fn credentials_across_vertices_redact_unrelated_file_names() {
        let mut candidate = candidate();
        candidate.context.files[0].vertices[0].text = "ghp_".into();
        candidate.context.files[0].vertices.push(NativeVertex {
            change: "origin-hash".into(),
            start: 4,
            end: 40,
            kind: NativeVertexKind::Add,
            text: "A1b2".repeat(9),
        });
        let report = report(
            &candidate,
            &binding(),
            "",
            &configuration(8000),
            model::Api::OpenAi,
        )
        .unwrap();
        assert!(!report.findings.is_empty());
        assert!(
            report
                .files
                .iter()
                .all(|file| file.path == "[redacted-path]")
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.path == "[redacted-path]")
        );
        assert_sum(&report);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("café"));
        assert!(!json.contains("\"mode\""));
        assert!(!json.contains("A1b2"));
    }

    #[test]
    fn repeated_file_objects_keep_their_complete_cost() {
        let mut candidate = candidate();
        let context = encoded_chars(&candidate.context.files[0]).unwrap();
        let metadata = encoded_chars(&candidate.metadata_context[0]).unwrap();
        candidate.context.files.push(NativeContextFile {
            path: candidate.context.files[0].path.clone(),
            vertices: Vec::new(),
        });
        let second_context = encoded_chars(&candidate.context.files[1]).unwrap();
        candidate.metadata_context.push(MetadataContext {
            path: candidate.metadata_context[0].path.clone(),
            before: None,
            after: None,
        });
        let second_metadata = encoded_chars(&candidate.metadata_context[2]).unwrap();
        let report = report(
            &candidate,
            &binding(),
            "",
            &configuration(8000),
            model::Api::OpenAi,
        )
        .unwrap();
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.files[0].context, context + second_context);
        assert_eq!(report.files[0].metadata_context, metadata + second_metadata);
        assert_sum(&report);
    }

    #[test]
    fn character_counter_accepts_split_utf8_writes() {
        let mut count = CharacterCount::default();
        for byte in "\"保護 🛡\\n\"".as_bytes() {
            count.write_all(&[*byte]).unwrap();
        }
        assert_eq!(count.0, "\"保護 🛡\\n\"".chars().count());
    }
}
