use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::case_view;
use crate::cases::{self, CaseRecord, NoteRecord, SeenRecord, Snapshot, SpanAnchor, Store};
use crate::configuration::Evidence;
use crate::gate::{Ledger, Record};
use crate::pijul::ReviewChange;
use crate::review::{MainBinding, PolicyBinding, ReviewBinding};

#[derive(Serialize)]
pub struct Change<T> {
    pub changed: bool,
    pub before: T,
    pub after: T,
}

#[derive(Clone, Serialize, PartialEq)]
pub struct Span {
    pub anchor: SpanAnchor,
    pub text: String,
}

#[derive(Clone, Serialize, PartialEq)]
pub struct Metadata {
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Serialize)]
pub struct PathDelta {
    pub path: String,
    pub status: &'static str,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
    pub added_spans: Vec<Span>,
    pub removed_spans: Vec<Span>,
    pub kept_spans: Vec<Span>,
    pub metadata: Change<Option<Metadata>>,
}

#[derive(Serialize)]
pub struct DependencyDelta {
    pub changed: bool,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Serialize)]
pub struct ConflictEvidence {
    pub changed: bool,
    pub before: Vec<crate::change::Conflict>,
    pub after: Vec<crate::change::Conflict>,
    pub added: Vec<crate::change::Conflict>,
    pub removed: Vec<crate::change::Conflict>,
}

fn conflict_delta(
    before: &[crate::change::Conflict],
    after: &[crate::change::Conflict],
) -> ConflictEvidence {
    let added: Vec<_> = after
        .iter()
        .filter(|conflict| !before.contains(conflict))
        .cloned()
        .collect();
    let removed: Vec<_> = before
        .iter()
        .filter(|conflict| !after.contains(conflict))
        .cloned()
        .collect();
    ConflictEvidence {
        changed: !added.is_empty() || !removed.is_empty(),
        before: before.to_vec(),
        after: after.to_vec(),
        added,
        removed,
    }
}

#[derive(Serialize, PartialEq)]
pub struct VerificationEvidence {
    pub hash: String,
    pub at: String,
    pub decision: String,
    pub review: Option<ReviewBinding>,
    pub configuration: Option<Evidence>,
    pub verification: Value,
    pub stale_reasons: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct VerificationStatus {
    pub current: Vec<VerificationEvidence>,
    pub historical: Vec<VerificationEvidence>,
}

#[derive(Serialize)]
pub struct VerificationDelta {
    pub current_changed: bool,
    pub historical_changed: bool,
    pub before: VerificationStatus,
    pub after: VerificationStatus,
}

#[derive(Serialize)]
pub struct NoteStatus {
    pub case_id: String,
    pub note: NoteRecord,
    pub stale: bool,
    pub stale_reasons: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct SeenHistory {
    pub case_id: String,
    pub event: SeenRecord,
    pub current: bool,
    pub stale: bool,
    pub stale_reasons: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct SeenStatus {
    pub user: String,
    pub path: String,
    pub seen: bool,
    pub history: Vec<SeenHistory>,
}

#[derive(Serialize)]
pub struct AnnotationReport {
    pub schema_version: u32,
    pub authorizes_acceptance: bool,
    pub binding: ReviewBinding,
    pub configuration: Evidence,
    pub candidate: String,
    pub notes: Vec<NoteStatus>,
    pub seen: Vec<SeenStatus>,
}

#[derive(Serialize)]
pub struct Comparison {
    pub schema_version: u32,
    pub authorizes_acceptance: bool,
    pub before: String,
    pub after: String,
    pub path_scope: &'static str,
    pub binding_changed: bool,
    pub paths: Vec<PathDelta>,
    pub unchanged_paths: Vec<String>,
    pub policy: Change<Option<PolicyBinding>>,
    pub main: Change<MainBinding>,
    pub configuration: Change<Evidence>,
    pub dependencies: DependencyDelta,
    pub conflicts: ConflictEvidence,
    pub verification: VerificationDelta,
    pub annotations: AnnotationReport,
}

fn binding(snapshot: &Snapshot) -> ReviewBinding {
    ReviewBinding {
        candidates: vec![snapshot.candidate.clone()],
        policy: snapshot.policy_sha256.as_ref().map(|sha256| PolicyBinding {
            path: snapshot.policy_path.clone(),
            sha256: sha256.clone(),
        }),
        main: MainBinding {
            channel: snapshot.main.clone(),
            state: snapshot.main_state.clone(),
        },
    }
}

fn configuration(record: &CaseRecord) -> Result<Evidence> {
    serde_json::from_value(record.snapshot.configuration.clone())
        .context("The captured configuration evidence is not valid.")
}

fn binding_matches(snapshot: &Snapshot, current: &ReviewBinding) -> bool {
    current.candidates.len() == 1
        && current.candidates[0] == snapshot.candidate
        && current.main.channel == snapshot.main
        && current.main.state == snapshot.main_state
        && match (&snapshot.policy_sha256, &current.policy) {
            (Some(sha256), Some(policy)) => {
                *sha256 == policy.sha256 && snapshot.policy_path == policy.path
            }
            (None, None) => true,
            _ => false,
        }
}

fn context_reasons(
    record: &CaseRecord,
    current: &ReviewBinding,
    configuration: &Evidence,
) -> Result<Vec<&'static str>> {
    let mut reasons = Vec::new();
    if !binding_matches(&record.snapshot, current) {
        reasons.push("review_binding_changed");
    }
    if self::configuration(record)? != *configuration {
        reasons.push("configuration_changed");
    }
    Ok(reasons)
}

fn vertices<'a>(change: &'a ReviewChange, path: &str) -> &'a [crate::pijul::NativeVertex] {
    change
        .context
        .files
        .iter()
        .find(|file| file.path == path)
        .map_or(&[], |file| file.vertices.as_slice())
}

fn span(path: &str, vertex: &crate::pijul::NativeVertex) -> Span {
    Span {
        anchor: cases::vertex_anchor(path, vertex),
        text: vertex.text.clone(),
    }
}

fn metadata(change: &ReviewChange, path: &str) -> Option<Metadata> {
    change
        .metadata_context
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| Metadata {
            before: entry.before.clone(),
            after: entry.after.clone(),
        })
}

/// Read human metadata without acceptance authority or model input changes.
pub fn annotations(
    binding: &ReviewBinding,
    configuration: &Evidence,
    change: &ReviewChange,
    records: &[CaseRecord],
) -> Result<AnnotationReport> {
    let mut notes = Vec::new();
    let mut seen: BTreeMap<(String, String), Vec<SeenHistory>> = BTreeMap::new();
    let mut anchors = BTreeMap::new();
    let mut digests = BTreeMap::new();
    for path in &change.paths {
        let native = change.context.files.iter().find(|file| file.path == *path);
        let file_anchors: Vec<_> = native
            .into_iter()
            .flat_map(|file| &file.vertices)
            .map(|vertex| cases::vertex_anchor(path, vertex))
            .collect();
        anchors.insert(path.as_str(), file_anchors);
        digests.insert(path.as_str(), cases::file_digest(change, path)?);
    }
    for record in records {
        let reasons = context_reasons(record, binding, configuration)?;
        for note in &record.notes {
            let mut stale_reasons = reasons.clone();
            if let Some(anchor) = &note.anchor {
                match anchors.get(anchor.path.as_str()) {
                    None => stale_reasons.push("path_absent"),
                    Some(spans) => {
                        if !spans.contains(anchor) {
                            stale_reasons.push("native_span_changed");
                        }
                    }
                }
            }
            notes.push(NoteStatus {
                case_id: record.id.clone(),
                note: note.clone(),
                stale: !stale_reasons.is_empty(),
                stale_reasons,
            });
        }
        for event in &record.seen {
            let mut stale_reasons = reasons.clone();
            match digests.get(event.path.as_str()) {
                None => stale_reasons.push("path_absent"),
                Some(digest) if digest != &event.content_sha256 => {
                    stale_reasons.push("file_digest_changed");
                }
                Some(_) => {}
            }
            seen.entry((event.user.clone(), event.path.clone()))
                .or_default()
                .push(SeenHistory {
                    case_id: record.id.clone(),
                    event: event.clone(),
                    current: false,
                    stale: !stale_reasons.is_empty(),
                    stale_reasons,
                });
        }
    }
    notes.sort_by(|left, right| {
        (&left.note.time, &left.case_id, &left.note.user).cmp(&(
            &right.note.time,
            &right.case_id,
            &right.note.user,
        ))
    });
    let seen = seen
        .into_iter()
        .map(|((user, path), mut history)| {
            let current = history.iter().rposition(|entry| !entry.stale);
            let seen = current.is_some_and(|index| history[index].event.seen);
            if let Some(index) = current {
                history[index].current = true;
            }
            SeenStatus {
                user,
                path,
                seen,
                history,
            }
        })
        .collect();
    Ok(AnnotationReport {
        schema_version: 1,
        authorizes_acceptance: false,
        binding: binding.clone(),
        configuration: configuration.clone(),
        candidate: change.hash.clone(),
        notes,
        seen,
    })
}

/// Compare source notes and seen history against an exact captured case.
pub fn case_annotations(
    repo: &Path,
    source: &str,
    against: Option<&str>,
) -> Result<AnnotationReport> {
    let store = Store::new(repo);
    let source = store.get(source)?;
    let target = match against {
        Some(id) => store.get(id)?,
        None => source.clone(),
    };
    let exact = case_view::inspect(repo, &target.id)?;
    let configuration = configuration(&target)?;
    let records = if source.id == target.id {
        vec![source]
    } else {
        vec![source, target.clone()]
    };
    annotations(
        &binding(&target.snapshot),
        &configuration,
        &exact.change,
        &records,
    )
}

type SpanKey<'a> = (&'a str, u64, u64, &'a str, &'a str);

fn span_key(vertex: &crate::pijul::NativeVertex) -> SpanKey<'_> {
    let kind = match vertex.kind {
        crate::pijul::NativeVertexKind::Add => "add",
        crate::pijul::NativeVertexKind::Del => "del",
        crate::pijul::NativeVertexKind::Keep => "keep",
    };
    (&vertex.change, vertex.start, vertex.end, kind, &vertex.text)
}

fn path_delta(
    before: &ReviewChange,
    after: &ReviewChange,
    path: &str,
    before_sha256: Option<String>,
    after_sha256: Option<String>,
) -> PathDelta {
    let before_present = before_sha256.is_some();
    let after_present = after_sha256.is_some();
    let old_spans = vertices(before, path);
    let new_spans = vertices(after, path);
    let mut remaining: BTreeMap<SpanKey<'_>, usize> = BTreeMap::new();
    for vertex in old_spans {
        *remaining.entry(span_key(vertex)).or_default() += 1;
    }
    let mut added_spans = Vec::new();
    let mut kept_spans = Vec::new();
    for vertex in new_spans {
        let count = remaining.get_mut(&span_key(vertex));
        if let Some(count) = count.filter(|count| **count != 0) {
            *count -= 1;
            kept_spans.push(span(path, vertex));
        } else {
            added_spans.push(span(path, vertex));
        }
    }
    let mut removed_spans = Vec::new();
    for vertex in old_spans {
        if let Some(count) = remaining
            .get_mut(&span_key(vertex))
            .filter(|count| **count != 0)
        {
            *count -= 1;
            removed_spans.push(span(path, vertex));
        }
    }
    let before_metadata = metadata(before, path);
    let after_metadata = metadata(after, path);
    PathDelta {
        path: path.to_owned(),
        status: match (before_present, after_present) {
            (false, true) => "new",
            (true, false) => "removed",
            _ => "changed",
        },
        before_sha256,
        after_sha256,
        added_spans,
        removed_spans,
        kept_spans,
        metadata: Change {
            changed: before_metadata != after_metadata,
            before: before_metadata,
            after: after_metadata,
        },
    }
}

fn verification_status(
    history: &[Record],
    binding: &ReviewBinding,
    configuration: &Evidence,
    candidates: &[&str],
) -> Result<VerificationStatus> {
    let mut current = Vec::new();
    let mut historical = Vec::new();
    let expected_main = serde_json::to_value(&binding.main)?;
    let expected_candidates = serde_json::to_value(&binding.candidates)?;
    for record in history {
        let Some(verification) = &record.verification else {
            continue;
        };
        let evidence = serde_json::to_value(verification.as_ref())?;
        let relevant = candidates.contains(&record.hash.as_str())
            || record.review.as_ref().is_some_and(|review| {
                review
                    .candidates
                    .iter()
                    .any(|hash| candidates.contains(&hash.as_str()))
            })
            || evidence
                .get("candidates")
                .and_then(Value::as_array)
                .is_some_and(|hashes| {
                    hashes
                        .iter()
                        .any(|hash| hash.as_str().is_some_and(|hash| candidates.contains(&hash)))
                });
        if !relevant {
            continue;
        }
        let mut stale_reasons = Vec::new();
        if record.review.as_ref() != Some(binding) {
            stale_reasons.push("review_binding_changed_or_absent");
        }
        if record.configuration.as_deref() != Some(configuration) {
            stale_reasons.push("configuration_changed_or_absent");
        }
        if evidence.get("main") != Some(&expected_main)
            || evidence.get("candidates") != Some(&expected_candidates)
            || evidence.get("merge").is_some_and(|merge| !merge.is_null())
        {
            stale_reasons.push("verification_binding_changed");
        }
        let entry = VerificationEvidence {
            hash: record.hash.clone(),
            at: record.at.clone(),
            decision: record.decision.clone(),
            review: record.review.clone(),
            configuration: record.configuration.as_deref().cloned(),
            verification: evidence,
            stale_reasons,
        };
        if entry.stale_reasons.is_empty() {
            current.push(entry);
        } else {
            historical.push(entry);
        }
    }
    Ok(VerificationStatus {
        current,
        historical,
    })
}

/// Compare exact native case context without source writes or gate authority.
pub fn compare(repo: &Path, before: &str, after: &str) -> Result<Comparison> {
    let store = Store::new(repo);
    let before_record = store.get(before)?;
    let after_record = store.get(after)?;
    let before = case_view::inspect(repo, &before_record.id)?;
    let after = case_view::inspect(repo, &after_record.id)?;
    let before_binding = binding(&before.snapshot);
    let after_binding = binding(&after.snapshot);
    let before_configuration = configuration(&before_record)?;
    let after_configuration = configuration(&after_record)?;
    let mut paths = Vec::new();
    let mut unchanged_paths = Vec::new();
    for path in before.change.paths.union(&after.change.paths) {
        let before_digest = before
            .change
            .paths
            .contains(path)
            .then(|| cases::file_digest(&before.change, path))
            .transpose()?;
        let after_digest = after
            .change
            .paths
            .contains(path)
            .then(|| cases::file_digest(&after.change, path))
            .transpose()?;
        if before_digest == after_digest {
            unchanged_paths.push(path.clone());
        } else {
            paths.push(path_delta(
                &before.change,
                &after.change,
                path,
                before_digest,
                after_digest,
            ));
        }
    }
    let old_dependencies: BTreeSet<_> = before.change.dependencies.iter().collect();
    let new_dependencies: BTreeSet<_> = after.change.dependencies.iter().collect();
    let added = new_dependencies
        .difference(&old_dependencies)
        .map(|hash| (*hash).clone())
        .collect();
    let removed = old_dependencies
        .difference(&new_dependencies)
        .map(|hash| (*hash).clone())
        .collect();
    let history = Ledger::new(repo).history()?;
    let candidates = [
        before.snapshot.candidate.as_str(),
        after.snapshot.candidate.as_str(),
    ];
    let old_evidence = verification_status(
        &history,
        &before_binding,
        &before_configuration,
        &candidates,
    )?;
    let new_evidence =
        verification_status(&history, &after_binding, &after_configuration, &candidates)?;
    let verification = VerificationDelta {
        current_changed: old_evidence.current != new_evidence.current,
        historical_changed: old_evidence.historical != new_evidence.historical,
        before: old_evidence,
        after: new_evidence,
    };
    let records = if before_record.id == after_record.id {
        vec![before_record]
    } else {
        vec![before_record, after_record]
    };
    let annotations = annotations(
        &after_binding,
        &after_configuration,
        &after.change,
        &records,
    )?;
    Ok(Comparison {
        schema_version: 1,
        authorizes_acceptance: false,
        before: before.id,
        after: after.id,
        path_scope: "candidate_review_context",
        binding_changed: before_binding != after_binding,
        paths,
        unchanged_paths,
        policy: Change {
            changed: before_binding.policy != after_binding.policy,
            before: before_binding.policy,
            after: after_binding.policy,
        },
        main: Change {
            changed: before_binding.main != after_binding.main,
            before: before_binding.main,
            after: after_binding.main,
        },
        configuration: Change {
            changed: before_configuration != after_configuration,
            before: before_configuration,
            after: after_configuration,
        },
        dependencies: DependencyDelta {
            changed: before.change.dependencies != after.change.dependencies,
            before: before.change.dependencies,
            after: after.change.dependencies,
            added,
            removed,
        },
        conflicts: conflict_delta(&before.conflicts, &after.conflicts),
        verification,
        annotations,
    })
}

fn display(value: &impl Serialize) {
    let text = serde_json::to_string_pretty(value).expect("Serialize human review data");
    for character in text.chars() {
        if character.is_control() && character != '\n' {
            print!("{}", character.escape_default());
        } else {
            print!("{character}");
        }
    }
    println!();
}

pub fn show_annotations(report: &AnnotationReport) {
    if report.notes.is_empty() {
        println!("No human review notes.");
    }
    for (index, status) in report.notes.iter().enumerate() {
        let state = if status.stale { "stale" } else { "current" };
        println!(
            "Note {}: {:?} by {} [{state}]",
            index + 1,
            status.note.kind,
            status.note.user.escape_debug()
        );
        println!("  Case: {}", status.case_id);
        println!("  Time: {}", status.note.time);
        println!("  Text: {}", status.note.text.escape_debug());
        for reference in &status.note.references {
            println!("  Reference: {}", reference.escape_debug());
        }
        if let Some(anchor) = &status.note.anchor {
            println!(
                "  Native anchor: {} {} {}..{} {}",
                anchor.path.escape_debug(),
                anchor.vertex_change,
                anchor.start,
                anchor.end,
                anchor.kind
            );
            println!("  Text SHA-256: {}", anchor.text_sha256);
        }
        for reason in &status.stale_reasons {
            println!("  Stale reason: {reason}");
        }
    }
    if report.seen.is_empty() {
        println!("No seen state exists.");
    }
    for status in &report.seen {
        println!(
            "Seen: {} {} = {}",
            status.user.escape_debug(),
            status.path.escape_debug(),
            status.seen
        );
        for history in &status.history {
            let state = if history.current {
                "current"
            } else if history.stale {
                "stale"
            } else {
                "history"
            };
            println!(
                "  {} seen={} [{state}] case {}",
                history.event.time, history.event.seen, history.case_id
            );
            for reason in &history.stale_reasons {
                println!("    Stale reason: {reason}");
            }
        }
    }
}

pub fn show_comparison(report: &Comparison) {
    println!("Captured case: {} -> {}", report.before, report.after);
    println!("Review binding changed: {}", report.binding_changed);
    println!("Paths describe candidate review context, not source creation or deletion.");
    if report.main.changed {
        println!("Main state change:");
        display(&report.main);
    }
    if report.policy.changed {
        println!("Trusted policy change:");
        display(&report.policy);
    }
    if report.configuration.changed {
        println!("Trusted configuration change:");
        display(&report.configuration);
    }
    if report.dependencies.changed {
        println!("Native dependency change:");
        display(&report.dependencies);
    }
    for path in &report.paths {
        println!("Path [{}]: {}", path.status, path.path.escape_debug());
        for span in &path.removed_spans {
            println!("Removed native span:");
            display(span);
        }
        for span in &path.added_spans {
            println!("Added native span:");
            display(span);
        }
        for span in &path.kept_spans {
            println!("Retained native span:");
            display(span);
        }
        if path.metadata.changed {
            println!("Metadata context change:");
            display(&path.metadata);
        }
    }
    for path in &report.unchanged_paths {
        println!("Unchanged context: {}", path.escape_debug());
    }
    if report.conflicts.changed {
        println!("Native conflict change:");
        display(&report.conflicts);
    } else if !report.conflicts.after.is_empty() {
        println!("Unchanged native conflicts:");
        display(&report.conflicts.after);
    } else {
        println!("No native conflicts.");
    }
    if !report.verification.before.current.is_empty()
        || !report.verification.before.historical.is_empty()
        || !report.verification.after.current.is_empty()
        || !report.verification.after.historical.is_empty()
    {
        println!("Current and historical verification evidence:");
        display(&report.verification);
    } else {
        println!("No recorded verification evidence.");
    }
    show_annotations(&report.annotations);
    println!("This comparison does not authorize acceptance.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::NoteKind;
    use crate::configuration::Values;
    use crate::pijul::{
        MetadataContext, NativeContext, NativeContextFile, NativeVertex, NativeVertexKind,
    };
    use serde_json::json;

    fn evidence() -> Evidence {
        Evidence {
            source: "main".into(),
            path: Some("patchgate.json".into()),
            sha256: Some("configuration".into()),
            values: Values::default(),
        }
    }

    fn change() -> ReviewChange {
        ReviewChange {
            hash: "candidate".into(),
            message: "Exact source".into(),
            authors: vec![],
            timestamp: "2026-01-01T00:00:00Z".into(),
            dependencies: vec!["base".into()],
            paths: BTreeSet::from(["src/lib.rs".into()]),
            context: NativeContext {
                full: true,
                files: vec![NativeContextFile {
                    path: "src/lib.rs".into(),
                    vertices: vec![NativeVertex {
                        change: "candidate".into(),
                        start: 0,
                        end: 4,
                        kind: NativeVertexKind::Add,
                        text: "new\n".into(),
                    }],
                }],
            },
            metadata_context: vec![],
        }
    }

    fn record(change: &ReviewChange) -> CaseRecord {
        CaseRecord {
            schema_version: 1,
            id: "source-case".into(),
            snapshot: Snapshot {
                repository: "/source".into(),
                main: "main".into(),
                inbox: "inbox".into(),
                main_state: Some("state".into()),
                base: vec!["base".into()],
                candidate: change.hash.clone(),
                policy_path: "POLICY.md".into(),
                policy_sha256: Some("policy".into()),
                configuration: serde_json::to_value(evidence()).unwrap(),
            },
            captured_at: "2026-01-01T00:00:00Z".into(),
            labels: vec![],
            tags: vec![],
            notes: vec![NoteRecord {
                user: "alice".into(),
                time: "2026-01-01T00:00:01Z".into(),
                kind: NoteKind::Comment,
                text: "Keep this exact span.".into(),
                references: vec!["local-evidence".into()],
                anchor: Some(cases::span_anchor(change, "src/lib.rs", 1).unwrap()),
            }],
            seen: vec![SeenRecord {
                user: "alice".into(),
                time: "2026-01-01T00:00:02Z".into(),
                path: "src/lib.rs".into(),
                content_sha256: cases::file_digest(change, "src/lib.rs").unwrap(),
                seen: true,
            }],
        }
    }

    #[test]
    fn exact_binding_and_digest_keep_seen_status() -> Result<()> {
        let change = change();
        let record = record(&change);
        let report = annotations(&binding(&record.snapshot), &evidence(), &change, &[record])?;
        assert!(!report.authorizes_acceptance);
        assert!(report.seen[0].seen);
        assert!(report.seen[0].history[0].current);
        assert!(!report.seen[0].history[0].stale);
        assert!(!report.notes[0].stale);
        Ok(())
    }

    #[test]
    fn each_review_binding_change_clears_seen_and_retains_history() -> Result<()> {
        let change = change();
        let record = record(&change);
        let original = binding(&record.snapshot);
        let mut candidate = original.clone();
        candidate.candidates = vec!["other-candidate".into()];
        let mut policy = original.clone();
        policy.policy.as_mut().unwrap().sha256 = "other-policy".into();
        let mut policy_path = original.clone();
        policy_path.policy.as_mut().unwrap().path = "OTHER.md".into();
        let mut main = original.clone();
        main.main.state = Some("other-state".into());
        let mut channel = original.clone();
        channel.main.channel = "other-main".into();
        for current in [candidate, policy, policy_path, main, channel] {
            let report = annotations(
                &current,
                &evidence(),
                &change,
                std::slice::from_ref(&record),
            )?;
            assert!(!report.seen[0].seen);
            let history = &report.seen[0].history;
            assert_eq!(history.len(), 1);
            assert!(history[0].stale);
            assert!(!history[0].current);
            assert_eq!(history[0].event, record.seen[0]);
            assert!(history[0].stale_reasons.contains(&"review_binding_changed"));
        }
        Ok(())
    }

    #[test]
    fn file_digest_change_clears_seen_without_anchor_transfer() -> Result<()> {
        let mut change = change();
        let record = record(&change);
        let original_anchor = record.notes[0].anchor.clone();
        change.context.files[0].vertices[0].text = "old\n".into();
        let report = annotations(&binding(&record.snapshot), &evidence(), &change, &[record])?;
        assert!(!report.seen[0].seen);
        assert!(
            report.seen[0].history[0]
                .stale_reasons
                .contains(&"file_digest_changed")
        );
        assert!(report.notes[0].stale);
        assert_eq!(report.notes[0].note.anchor, original_anchor);
        assert!(
            report.notes[0]
                .stale_reasons
                .contains(&"native_span_changed")
        );
        Ok(())
    }

    #[test]
    fn changed_configuration_clears_seen() -> Result<()> {
        let change = change();
        let record = record(&change);
        let mut configuration = evidence();
        configuration.values.max_change_chars += 1;
        let report = annotations(
            &binding(&record.snapshot),
            &configuration,
            &change,
            &[record],
        )?;
        assert!(!report.seen[0].seen);
        assert!(
            report.seen[0].history[0]
                .stale_reasons
                .contains(&"configuration_changed")
        );
        Ok(())
    }

    #[test]
    fn explicit_unseen_uses_append_order_not_clock_order() -> Result<()> {
        let change = change();
        let mut record = record(&change);
        record.seen[0].time = "2099-01-01T00:00:00Z".into();
        let mut unseen = record.seen[0].clone();
        unseen.time = "2026-01-01T00:00:03Z".into();
        unseen.seen = false;
        record.seen.push(unseen);
        let report = annotations(&binding(&record.snapshot), &evidence(), &change, &[record])?;
        assert!(!report.seen[0].seen);
        assert_eq!(report.seen[0].history.len(), 2);
        assert!(report.seen[0].history[0].event.seen);
        assert!(!report.seen[0].history[0].current);
        assert!(report.seen[0].history[1].current);
        Ok(())
    }

    #[test]
    fn native_span_kind_is_part_of_identity() -> Result<()> {
        let before = change();
        let mut after = change();
        after.context.files[0].vertices[0].kind = NativeVertexKind::Del;
        let delta = path_delta(
            &before,
            &after,
            "src/lib.rs",
            Some(cases::file_digest(&before, "src/lib.rs")?),
            Some(cases::file_digest(&after, "src/lib.rs")?),
        );
        assert_eq!(delta.added_spans.len(), 1);
        assert_eq!(delta.added_spans[0].anchor.kind, "del");
        assert_eq!(delta.removed_spans.len(), 1);
        assert_eq!(delta.removed_spans[0].anchor.kind, "add");
        assert!(delta.kept_spans.is_empty());
        Ok(())
    }

    #[test]
    fn metadata_only_changes_have_exact_before_and_after_text() -> Result<()> {
        let mut before = change();
        before.context.files.clear();
        before.metadata_context.push(MetadataContext {
            path: "src/lib.rs".into(),
            before: Some("base".into()),
            after: Some("old".into()),
        });
        let mut after = change();
        after.context.files.clear();
        after.metadata_context.push(MetadataContext {
            path: "src/lib.rs".into(),
            before: Some("base".into()),
            after: Some("new".into()),
        });
        let delta = path_delta(
            &before,
            &after,
            "src/lib.rs",
            Some(cases::file_digest(&before, "src/lib.rs")?),
            Some(cases::file_digest(&after, "src/lib.rs")?),
        );
        assert!(delta.metadata.changed);
        assert_eq!(delta.metadata.before.unwrap().after.as_deref(), Some("old"));
        assert_eq!(delta.metadata.after.unwrap().after.as_deref(), Some("new"));
        assert_ne!(delta.before_sha256, delta.after_sha256);
        assert!(delta.added_spans.is_empty());
        Ok(())
    }

    #[test]
    fn verification_requires_exact_review_and_configuration() -> Result<()> {
        let change = change();
        let case = record(&change);
        let binding = binding(&case.snapshot);
        let mut record: Record = serde_json::from_value(json!({
            "hash": change.hash,
            "decision": "accept",
            "review": binding,
            "configuration": evidence(),
            "verification": {
                "schema_version": 1,
                "candidates": binding.candidates,
                "merge": null,
                "main": binding.main,
                "source": {"path": "/nix/store/source", "nar_hash": "source"},
                "definitions": {"path": "/nix/store/checks", "nar_hash": "checks"},
                "inputs": {},
                "results": []
            }
        }))?;
        let status = verification_status(&[record.clone()], &binding, &evidence(), &["candidate"])?;
        assert_eq!(status.current.len(), 1);
        assert!(status.historical.is_empty());
        record.configuration = None;
        let status = verification_status(&[record], &binding, &evidence(), &["candidate"])?;
        assert!(status.current.is_empty());
        assert_eq!(status.historical.len(), 1);
        assert!(
            status.historical[0]
                .stale_reasons
                .contains(&"configuration_changed_or_absent")
        );
        Ok(())
    }
    #[test]
    fn target_seen_event_preserves_stale_source_history() -> Result<()> {
        let source_change = change();
        let source = record(&source_change);
        let mut target_change = change();
        target_change.hash = "target-candidate".into();
        target_change.context.files[0].vertices[0].change = target_change.hash.clone();
        let mut target = record(&target_change);
        target.id = "target-case".into();
        target.seen[0].time = "2026-01-01T00:00:03Z".into();
        let target_binding = binding(&target.snapshot);
        let report = annotations(
            &target_binding,
            &evidence(),
            &target_change,
            &[source.clone(), target],
        )?;
        assert!(report.seen[0].seen);
        assert_eq!(report.seen[0].history.len(), 2);
        assert_eq!(report.seen[0].history[0].event, source.seen[0]);
        assert!(report.seen[0].history[0].stale);
        assert!(!report.seen[0].history[0].current);
        assert!(report.seen[0].history[1].current);
        let original_note = report
            .notes
            .iter()
            .find(|note| note.case_id == source.id)
            .unwrap();
        assert!(original_note.stale);
        assert_eq!(original_note.note.anchor, source.notes[0].anchor);
        Ok(())
    }
}

#[cfg(test)]
mod conflict_tests {
    use super::*;

    #[test]
    fn conflicts_retain_exact_native_details_and_report_changes() {
        let retained = crate::change::Conflict {
            kind: "Order conflict".into(),
            path: "src/lib.rs".into(),
            line: 7,
        };
        let removed = crate::change::Conflict {
            kind: "Deletion conflict".into(),
            path: "src/old.rs".into(),
            line: 3,
        };
        let added = crate::change::Conflict {
            kind: "Order conflict".into(),
            path: "src/new.rs".into(),
            line: 11,
        };
        let before = vec![retained.clone(), removed.clone()];
        let after = vec![retained, added.clone()];
        let delta = conflict_delta(&before, &after);
        assert!(delta.changed);
        assert_eq!(delta.before, before);
        assert_eq!(delta.after, after);
        assert_eq!(delta.added, vec![added]);
        assert_eq!(delta.removed, vec![removed]);
    }

    #[test]
    fn conflict_order_alone_does_not_report_a_change() {
        let first = crate::change::Conflict {
            kind: "Order conflict".into(),
            path: "a.rs".into(),
            line: 1,
        };
        let second = crate::change::Conflict {
            kind: "Deletion conflict".into(),
            path: "b.rs".into(),
            line: 2,
        };
        let delta = conflict_delta(&[first.clone(), second.clone()], &[second, first]);
        assert!(!delta.changed);
        assert!(delta.added.is_empty());
        assert!(delta.removed.is_empty());
    }
}
