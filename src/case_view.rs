use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cases::{Snapshot, Store, TagRecord};
use crate::configuration::{self, Evidence};
use crate::pijul::{Pijul, ReviewChange};

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub authorizes_acceptance: bool,
    pub id: String,
    pub captured_at: String,
    pub snapshot: Snapshot,
    pub tags: Vec<TagRecord>,
    pub policy_text: Option<String>,
    pub change_text: String,
    pub change: ReviewChange,
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
        policy_text,
        change_text,
        change,
    })
}

fn display_json(value: &impl Serialize) -> String {
    let text = serde_json::to_string_pretty(value).expect("Serialize captured case data");
    let mut safe = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() && character != '\n' {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}

pub fn show(report: &Report) {
    // JSON string escapes retain exact text and prevent terminal control commands.
    println!("Case: {}", report.id);
    println!("Captured: {}", report.captured_at);
    println!("Authorizes acceptance: false");
    println!("Captured snapshot:");
    println!("{}", display_json(&report.snapshot));
    println!("Tag history:");
    println!("{}", display_json(&report.tags));
    println!("Captured policy:");
    println!("{}", display_json(&report.policy_text));
    println!("Exact native change:");
    println!("{}", display_json(&report.change_text));
    println!("Complete change context:");
    println!("{}", display_json(&report.change));
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
    fn text_display_escapes_terminal_controls_without_changing_json_data() {
        let text = "\u{1b}[31m\u{9b}31m\r\nsource";
        let displayed = display_json(&text);
        assert!(!displayed.chars().any(char::is_control));
        assert_eq!(
            serde_json::from_str::<String>(&serde_json::to_string(text).unwrap()).unwrap(),
            text
        );
    }
}
