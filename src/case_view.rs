use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cases::{NoteRecord, SeenRecord, Snapshot, Store, TagRecord};
use crate::configuration::{self, Evidence};
use crate::pijul::{NativeVertexKind, Pijul, ReviewChange};
use crate::review_guide::write_text;

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub authorizes_acceptance: bool,
    pub id: String,
    pub captured_at: String,
    pub snapshot: Snapshot,
    pub tags: Vec<TagRecord>,
    pub notes: Vec<NoteRecord>,
    pub seen: Vec<SeenRecord>,
    pub policy_text: Option<String>,
    pub change_text: String,
    pub change: ReviewChange,
    pub conflicts: Vec<crate::change::Conflict>,
}

fn copy_change(source: &Pijul, private: &Pijul, hash: &str) -> Result<()> {
    let relative = source.change_file(hash);
    let relative = relative.strip_prefix(&source.repo)?;
    let path = crate::pijul::safe_path(&source.repo, relative)?;
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .context("A captured native change is absent or unsafe.")?;
    let before = input.metadata()?;
    ensure!(before.is_file(), "A captured native change is not regular.");
    let target = private.change_file(hash);
    fs::create_dir_all(
        target
            .parent()
            .context("The private change path is absent.")?,
    )?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)?;
    let copied = io::copy(&mut input, &mut output)?;
    let after = input.metadata()?;
    ensure!(
        copied == before.len()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "A captured native change changed during inspection."
    );
    Ok(())
}

fn exact_hashes(pijul: &Pijul, channel: &str, expected: &HashSet<String>) -> Result<()> {
    ensure!(
        pijul.hashes(channel)? == *expected,
        "The private channel differs from the captured native changes."
    );
    Ok(())
}

/// Inspect captured source without source writes or acceptance authority.
pub fn inspect(repository: &Path, prefix: &str) -> Result<Report> {
    let record = Store::new(repository).get(prefix)?;
    let snapshot = &record.snapshot;
    let captured: Evidence = serde_json::from_value(snapshot.configuration.clone())
        .context("The captured configuration evidence is not valid.")?;
    ensure!(
        serde_json::to_value(&captured)? == snapshot.configuration,
        "The captured configuration evidence has unknown fields."
    );
    let directory = tempfile::Builder::new()
        .prefix("patchgate-case-")
        .tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let root = directory.path().join("repo");
    fs::create_dir(&root)?;
    let private = Pijul::with_timeout(root, Duration::from_secs(30));
    private.run(["init", "--channel", snapshot.main.as_str()])?;
    let source = Pijul::new(snapshot.repository.clone());
    // Copy only captured native objects. Do not open source keys or audit data.
    for hash in snapshot
        .base
        .iter()
        .chain(std::iter::once(&snapshot.candidate))
    {
        copy_change(&source, &private, hash)?;
    }
    let mut expected = HashSet::new();
    for hash in &snapshot.base {
        let text = private.change(hash)?;
        ensure!(
            crate::change::dependencies(&text)
                .iter()
                .all(|dependency| expected.contains(dependency)),
            "The captured base does not supply its native prerequisites in order."
        );
        private.run([
            OsStr::new("apply"),
            OsStr::new("--channel"),
            OsStr::new(&snapshot.main),
            private.change_file(hash).as_os_str(),
        ])?;
        expected.insert(hash.clone());
        exact_hashes(&private, &snapshot.main, &expected)?;
    }
    let reconstructed = private.snapshot(&snapshot.main)?;
    ensure!(
        reconstructed.hashes == expected && reconstructed.state == snapshot.main_state,
        "The reconstructed native state differs from its capture."
    );
    let order: Vec<_> = private
        .log(&snapshot.main)?
        .into_iter()
        .map(|entry| entry.hash)
        .collect();
    ensure!(
        order == snapshot.base,
        "The reconstructed base order differs from its capture."
    );
    let configuration = configuration::load(&private, &snapshot.main, &captured.values)?;
    ensure!(
        configuration == captured && configuration.values.policy_path == snapshot.policy_path,
        "The reconstructed configuration differs from its capture."
    );
    let policy = private.read_file_bytes(&snapshot.main, &snapshot.policy_path)?;
    let policy_digest = policy
        .as_ref()
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    ensure!(
        policy_digest == snapshot.policy_sha256,
        "The reconstructed policy differs from its capture."
    );
    let policy_text = policy
        .map(String::from_utf8)
        .transpose()
        .context("The captured policy is not complete UTF-8 text.")?;
    let change_text = private.change(&snapshot.candidate)?;
    ensure!(
        crate::change::dependencies(&change_text)
            .iter()
            .all(|dependency| expected.contains(dependency)),
        "The captured base does not supply all candidate prerequisites."
    );
    private.run([
        "fork",
        "--channel",
        snapshot.main.as_str(),
        snapshot.inbox.as_str(),
    ])?;
    private.run([
        OsStr::new("apply"),
        OsStr::new("--channel"),
        OsStr::new(&snapshot.inbox),
        private.change_file(&snapshot.candidate).as_os_str(),
    ])?;
    expected.insert(snapshot.candidate.clone());
    exact_hashes(&private, &snapshot.inbox, &expected)?;
    let conflicts = private.conflicts(&snapshot.inbox)?;
    let entry = private
        .log(&snapshot.inbox)?
        .into_iter()
        .find(|entry| entry.hash == snapshot.candidate)
        .context("The private inbox lacks the captured candidate.")?;
    let paths = private.touched_paths(&snapshot.inbox, &entry.paths, &change_text)?;
    let change =
        private.review_change(&snapshot.inbox, &snapshot.candidate, &change_text, &paths)?;
    Ok(Report {
        schema_version: 1,
        authorizes_acceptance: false,
        id: record.id,
        captured_at: record.captured_at,
        snapshot: record.snapshot,
        tags: record.tags,
        notes: record.notes,
        seen: record.seen,
        policy_text,
        change_text,
        change,
        conflicts,
    })
}

fn display_json(value: &impl Serialize) -> String {
    let text = serde_json::to_string_pretty(value).expect("Serialize captured case data");
    let mut safe = String::with_capacity(text.len());
    for character in text.chars() {
        if character == '\n' || (character.is_ascii() && !character.is_ascii_control()) {
            safe.push(character);
        } else {
            safe.extend(character.escape_debug());
        }
    }
    safe
}

fn write_change_context(output: &mut impl Write, change: &ReviewChange) -> Result<()> {
    writeln!(output, "Candidate: {}", change.hash.escape_debug())?;
    writeln!(output, "Message: {}", change.message.escape_debug())?;
    writeln!(output, "Authors: {}", display_json(&change.authors))?;
    writeln!(output, "Timestamp: {}", change.timestamp.escape_debug())?;
    writeln!(
        output,
        "Dependencies: {}",
        display_json(&change.dependencies)
    )?;
    writeln!(output, "Paths: {}", display_json(&change.paths))?;
    writeln!(output, "Full context: {}", change.context.full)?;
    for file in &change.context.files {
        writeln!(output, "Path: {}", file.path.escape_debug())?;
        for (index, vertex) in file.vertices.iter().enumerate() {
            let (kind, prefix) = match vertex.kind {
                NativeVertexKind::Add => ("add", "+ "),
                NativeVertexKind::Del => ("del", "- "),
                NativeVertexKind::Keep => ("keep", "  "),
            };
            writeln!(
                output,
                "  Span {}: {kind} {} {}..{}",
                index + 1,
                vertex.change.escape_debug(),
                vertex.start,
                vertex.end
            )?;
            write_text(output, prefix, &vertex.text)?;
        }
    }
    for file in &change.metadata_context {
        writeln!(output, "Metadata path: {}", file.path.escape_debug())?;
        writeln!(output, "  Before:")?;
        match &file.before {
            Some(before) => write_text(output, "- ", before)?,
            None => writeln!(output, "  [absent]")?,
        }
        writeln!(output, "  After:")?;
        match &file.after {
            Some(after) => write_text(output, "+ ", after)?,
            None => writeln!(output, "  [absent]")?,
        }
    }
    Ok(())
}

fn write_report(output: &mut impl Write, report: &Report) -> Result<()> {
    writeln!(output, "Case: {}", report.id.escape_debug())?;
    writeln!(output, "Captured: {}", report.captured_at.escape_debug())?;
    writeln!(output, "Authorizes acceptance: false")?;
    writeln!(output, "Captured snapshot:")?;
    writeln!(output, "{}", display_json(&report.snapshot))?;
    writeln!(output, "Tag history:")?;
    writeln!(output, "{}", display_json(&report.tags))?;
    writeln!(output, "Note history:")?;
    writeln!(output, "{}", display_json(&report.notes))?;
    writeln!(output, "Seen history:")?;
    writeln!(output, "{}", display_json(&report.seen))?;
    writeln!(output, "Captured policy (escaped text):")?;
    match &report.policy_text {
        Some(policy) => write_text(output, "  ", policy)?,
        None => writeln!(output, "  [absent]")?,
    }
    writeln!(output, "Exact native change (escaped text):")?;
    write_text(output, "  ", &report.change_text)?;
    writeln!(output, "Complete change context:")?;
    write_change_context(output, &report.change)?;
    writeln!(output, "Captured native conflicts:")?;
    writeln!(output, "{}", display_json(&report.conflicts))?;
    Ok(())
}

pub fn show(report: &Report) -> Result<()> {
    write_report(&mut io::stdout().lock(), report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::Values;
    use crate::pijul::{AgentEnv, Signer};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    struct Fixture {
        _directory: tempfile::TempDir,
        pijul: Pijul,
        environment: AgentEnv,
        snapshot: Snapshot,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("source");
            fs::create_dir(&root)?;
            let root = fs::canonicalize(root)?;
            let pijul = Pijul::new(root.clone());
            pijul.run(["init"])?;
            let signer = Signer::new(root.join(".pijul/patchgate"));
            let environment = signer.environment()?;
            fs::write(root.join("POLICY.md"), "Preserve exact source.\r\n")?;
            fs::write(root.join("value.txt"), "base\n")?;
            fs::write(
                root.join(configuration::PATH),
                r#"{"schema_version":1,"settings":{"max_change_chars":1}}"#,
            )?;
            pijul.run(["add", "POLICY.md", "value.txt", configuration::PATH])?;
            pijul.call_with_env(
                [
                    "record",
                    "-a",
                    "-m",
                    "Record the base",
                    "--author",
                    "patchgate",
                ],
                &environment.vars,
            )?;
            fs::write(root.join("value.txt"), "captured base\n")?;
            pijul.call_with_env(
                [
                    "record",
                    "-a",
                    "-m",
                    "Extend the base",
                    "--author",
                    "patchgate",
                ],
                &environment.vars,
            )?;
            let evidence = configuration::load(&pijul, "main", &Values::default())?;
            let state = pijul.snapshot("main")?;
            let base = pijul
                .log("main")?
                .into_iter()
                .map(|entry| entry.hash)
                .collect();
            pijul.run(["fork", "inbox"])?;
            pijul.run(["channel", "switch", "inbox"])?;
            fs::write(root.join("value.txt"), "candidate\n")?;
            pijul.call_with_env(
                [
                    "record",
                    "-a",
                    "-m",
                    "Record the candidate",
                    "--author",
                    "patchgate",
                ],
                &environment.vars,
            )?;
            let candidate = pijul
                .log("inbox")?
                .last()
                .context("No candidate exists.")?
                .hash
                .clone();
            let snapshot = Snapshot {
                repository: root,
                main: "main".into(),
                inbox: "inbox".into(),
                main_state: state.state,
                base,
                candidate,
                policy_path: "POLICY.md".into(),
                policy_sha256: Some(format!(
                    "{:x}",
                    Sha256::digest(b"Preserve exact source.\r\n")
                )),
                configuration: serde_json::to_value(evidence)?,
            };
            Ok(Self {
                _directory: directory,
                pijul,
                environment,
                snapshot,
            })
        }

        fn record(&self, message: &str) -> Result<()> {
            self.pijul.call_with_env(
                ["record", "-a", "-m", message, "--author", "patchgate"],
                &self.environment.vars,
            )?;
            Ok(())
        }
    }

    fn source_bytes(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
        fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    visit(root, &entry.path(), files)?;
                } else if entry.file_type()?.is_file() {
                    files.insert(
                        entry.path().strip_prefix(root)?.into(),
                        fs::read(entry.path())?,
                    );
                }
            }
            Ok(())
        }
        let mut files = BTreeMap::new();
        visit(root, root, &mut files)?;
        Ok(files)
    }

    #[test]
    fn human_metadata_binds_exact_native_targets_and_retains_export_data() -> Result<()> {
        use crate::cases::{Label, NoteKind, file_digest, span_anchor};
        let fixture = Fixture::new()?;
        let root = &fixture.snapshot.repository;
        let store = Store::new(root);
        let record = store.capture(fixture.snapshot.clone())?;
        let report = inspect(root, &record.id)?;
        let anchor = span_anchor(&report.change, "value.txt", 1)?;
        let references = vec!["issue:42".into(), "design:stable-output".into()];
        let first = store.note(
            &record.id, NoteKind::Constraint, "Preserve the file contract.", &references,
            Some("value.txt"), Some(1),
        )?;
        assert_eq!(first.notes[0].anchor.as_ref(), Some(&anchor));
        assert_eq!(first.notes[0].references, references);
        assert_eq!(first.snapshot, record.snapshot);
        assert!(first.labels.is_empty());
        let second = store.note(
            &record.id, NoteKind::Alternative, "Use the existing parser.", &[], None, None,
        )?;
        assert_eq!(second.notes[0], first.notes[0]);
        let marked = store.seen(&record.id, "value.txt", true)?;
        let cleared = store.seen(&record.id, "value.txt", false)?;
        assert_eq!(cleared.seen[0], marked.seen[0]);
        assert!(cleared.seen[0].seen);
        assert!(!cleared.seen[1].seen);
        assert_eq!(cleared.seen[0].user, cleared.notes[0].user);
        assert_eq!(cleared.seen[0].content_sha256, file_digest(&report.change, "value.txt")?);
        assert_eq!(store.capture(fixture.snapshot.clone())?, cleared);
        let report = inspect(root, &record.id)?;
        assert_eq!(report.notes, cleared.notes);
        assert_eq!(report.seen, cleared.seen);
        let export_directory = fs::canonicalize(fixture._directory.path())?;
        let variants = export_directory.join("variants.json");
        fs::write(&variants, serde_json::to_vec(&json!([{
            "id": "model", "model_url": "http://localhost:8080", "model": "model",
            "api": "openai", "revision": "checkpoint", "policy": null,
        }]))?)?;
        let output = export_directory.join("manifest.json");
        let bundle = export_directory.join("cases.tar.gz");
        assert!(store.export(std::slice::from_ref(&record.id), &variants, &output).is_err());
        assert!(store.bundle(std::slice::from_ref(&record.id), &variants, &bundle).is_err());
        store.label(&record.id, Label::Reject, "The reviewer rejects the change.")?;
        store.export(std::slice::from_ref(&record.id), &variants, &output)?;
        let manifest: serde_json::Value = serde_json::from_slice(&fs::read(output)?)?;
        assert_eq!(manifest["cases"][0]["notes"], json!(cleared.notes));
        assert_eq!(manifest["cases"][0]["seen"], json!(cleared.seen));
        store.bundle(&[record.id], &variants, &bundle)?;
        let loaded = crate::bundle::load(&bundle)?;
        assert_eq!(loaded.manifest["cases"][0]["notes"], json!(cleared.notes));
        assert_eq!(loaded.manifest["cases"][0]["seen"], json!(cleared.seen));
        Ok(())
    }

    #[test]
    fn human_metadata_refuses_invalid_text_targets_aliases_and_identity() -> Result<()> {
        use crate::cases::NoteKind;
        let fixture = Fixture::new()?;
        let root = &fixture.snapshot.repository;
        let store = Store::new(root);
        let record = store.capture(fixture.snapshot.clone())?;
        let path = root.join(".pijul/patchgate/cases").join(format!("{}.json", record.id));
        let original = fs::read(&path)?;
        for (target, span) in [
            (Some("value.txt"), Some(0)), (Some("value.txt"), Some(usize::MAX)),
            (Some("absent.txt"), Some(1)), (Some("../value.txt"), Some(1)),
            (Some("value.txt"), None), (None, Some(1)),
        ] {
            assert!(store.note(
                &record.id, NoteKind::Comment, "Inspect this span.", &[], target, span,
            ).is_err());
        }
        let credential = ["password = \"", "Ab3dEf5hGj7kLm9nPq2sTu4w", "\""].concat();
        for text in ["", "Line\nbreak", credential.as_str()] {
            assert!(store.note(&record.id, NoteKind::Evidence, text, &[], None, None).is_err());
        }
        for reference in ["", "Line\nbreak", credential.as_str()] {
            assert!(store.note(
                &record.id, NoteKind::Evidence, "Inspect the reference.",
                &[reference.into()], None, None,
            ).is_err());
        }
        for target in ["absent.txt", "../value.txt", ".pijul/key", "value.txt\n"] {
            assert!(store.seen(&record.id, target, true).is_err());
        }
        assert_eq!(fs::read(&path)?, original);
        let alias = fixture._directory.path().join("case-alias");
        fs::hard_link(&path, &alias)?;
        assert!(store.note(&record.id, NoteKind::Comment, "Inspect this case.", &[], None, None).is_err());
        assert!(store.seen(&record.id, "value.txt", true).is_err());
        fs::remove_file(alias)?;
        let mut altered = serde_json::to_value(&record)?;
        altered["snapshot"]["candidate"] = json!("A".repeat(53));
        fs::write(&path, serde_json::to_vec(&altered)?)?;
        assert!(store.note(&record.id, NoteKind::Comment, "Inspect this case.", &[], None, None).is_err());
        assert!(store.seen(&record.id, "value.txt", true).is_err());
        assert_eq!(fs::read(&path)?, serde_json::to_vec(&altered)?);
        Ok(())
    }

    #[test]
    fn inspection_retains_historical_context_without_source_writes() -> Result<()> {
        let fixture = Fixture::new()?;
        let root = &fixture.snapshot.repository;
        let store = Store::new(root);
        let record = store.capture(fixture.snapshot.clone())?;
        store.tag(
            &record.id,
            &["policy".into()],
            &[],
            "The reviewer identifies the rule.",
        )?;
        fixture.pijul.run(["channel", "switch", "main"])?;
        fixture.pijul.apply(&fixture.snapshot.candidate, "main")?;
        fs::write(root.join("POLICY.md"), "Current policy differs.\n")?;
        fs::write(
            root.join(configuration::PATH),
            r#"{"schema_version":1,"settings":{"max_change_chars":999}}"#,
        )?;
        fixture.record("Change current main")?;
        fixture.pijul.run(["channel", "switch", "inbox"])?;
        fs::write(root.join("value.txt"), "current inbox\n")?;
        fixture.record("Change current inbox")?;
        fs::write(root.join("value.txt"), "unrecorded work\n")?;
        fs::write(
            root.join(".pijul/patchgate/ledger.jsonl"),
            b"not valid model decision data",
        )?;
        let before = source_bytes(root)?;
        let report = inspect(root, &record.id[..12])?;
        assert!(!report.authorizes_acceptance);
        assert_eq!(report.snapshot, fixture.snapshot);
        assert_eq!(
            report.policy_text.as_deref(),
            Some("Preserve exact source.\r\n")
        );
        assert_eq!(report.change.hash, fixture.snapshot.candidate);
        assert!(report.change.context.full);
        let text: String = report
            .change
            .context
            .files
            .iter()
            .flat_map(|file| &file.vertices)
            .map(|vertex| vertex.text.as_str())
            .collect();
        assert!(text.contains("candidate\n"));
        assert!(!text.contains("current inbox"));
        assert_eq!(report.tags.len(), 1);
        assert_eq!(source_bytes(root)?, before);
        Ok(())
    }

    #[test]
    fn inspection_reports_conflicts_from_each_captured_main_state() -> Result<()> {
        let fixture = Fixture::new()?;
        let root = &fixture.snapshot.repository;
        let store = Store::new(root);
        let before_case = store.capture(fixture.snapshot.clone())?;
        fixture.pijul.run(["channel", "switch", "main"])?;
        fs::write(root.join("value.txt"), "main side\n")?;
        fixture.record("Change the same native span on main")?;
        let state = fixture.pijul.snapshot("main")?;
        let mut later = fixture.snapshot.clone();
        later.main_state = state.state;
        later.base = fixture.pijul.log("main")?.into_iter().map(|entry| entry.hash).collect();
        let after_case = store.capture(later)?;
        assert_eq!(before_case.snapshot.candidate, after_case.snapshot.candidate);
        assert_ne!(before_case.snapshot.main_state, after_case.snapshot.main_state);
        let source = source_bytes(root)?;
        let before = inspect(root, &before_case.id)?;
        let after = inspect(root, &after_case.id)?;
        assert!(before.conflicts.is_empty());
        assert!(after.conflicts.iter().any(|conflict| conflict.kind == "Order conflict"));
        assert!(!after.authorizes_acceptance);
        assert_eq!(source_bytes(root)?, source);
        Ok(())
    }

    #[test]
    fn inspection_refuses_altered_bindings_and_missing_native_data() -> Result<()> {
        let fixture = Fixture::new()?;
        let root = &fixture.snapshot.repository;
        let store = Store::new(root);
        let mut invalid = fixture.snapshot.clone();
        invalid.main_state = None;
        let record = store.capture(invalid)?;
        assert!(inspect(root, &record.id).is_err());
        let mut invalid = fixture.snapshot.clone();
        invalid.base.reverse();
        let record = store.capture(invalid)?;
        assert!(inspect(root, &record.id).is_err());
        let mut invalid = fixture.snapshot.clone();
        invalid.policy_sha256 = Some("0".repeat(64));
        let record = store.capture(invalid)?;
        assert!(inspect(root, &record.id).is_err());
        let mut invalid = fixture.snapshot.clone();
        invalid.configuration["sha256"] = json!("0".repeat(64));
        let record = store.capture(invalid)?;
        assert!(inspect(root, &record.id).is_err());
        let mut invalid = fixture.snapshot.clone();
        invalid.base.clear();
        invalid.main_state = None;
        invalid.policy_sha256 = None;
        invalid.configuration = json!({
            "source": "environment", "path": null, "sha256": null,
            "values": Values::default()
        });
        let record = store.capture(invalid)?;
        assert!(inspect(root, &record.id).is_err());
        let record = store.capture(fixture.snapshot.clone())?;
        fs::remove_file(fixture.pijul.change_file(&fixture.snapshot.candidate))?;
        assert!(inspect(root, &record.id).is_err());
        Ok(())
    }

    #[test]
    fn text_display_blocks_terminal_controls_and_forged_headers() -> Result<()> {
        let fixture = Fixture::new()?;
        let record = Store::new(&fixture.pijul.repo).capture(fixture.snapshot.clone())?;
        let mut report = inspect(&fixture.pijul.repo, &record.id)?;
        let attack = "\u{1b}]52;c;VEVSTUlOQUxfQ0FOQVJZ\u{7}\u{9b}2J\u{202e}reverse\u{2066}isolate\u{2069}\r\nFORGED-HEADER";
        report.captured_at = attack.into();
        report.snapshot.configuration = json!({"terminal": attack});
        report.policy_text = Some(attack.into());
        report.change_text = attack.into();
        report.change.message = attack.into();
        report.change.authors = vec![attack.into()];
        report.change.timestamp = attack.into();
        report.change.paths = [attack.into()].into_iter().collect();
        for file in &mut report.change.context.files {
            file.path = attack.into();
            for vertex in &mut file.vertices {
                vertex.text = attack.into();
            }
        }
        report.change.metadata_context = vec![crate::pijul::MetadataContext {
            path: attack.into(),
            before: Some(attack.into()),
            after: Some(attack.into()),
        }];
        report.conflicts = vec![crate::change::Conflict {
            kind: attack.into(),
            path: attack.into(),
            line: 1,
        }];
        let mut output = Vec::new();
        write_report(&mut output, &report)?;
        let output = String::from_utf8(output)?;
        assert!(
            !output
                .chars()
                .any(|character| { character.is_control() && character != '\n' })
        );
        for control in ['\u{202e}', '\u{2066}', '\u{2069}'] {
            assert!(!output.contains(control));
        }
        assert!(!output.lines().any(|line| line.starts_with("FORGED-HEADER")));
        Ok(())
    }
}
