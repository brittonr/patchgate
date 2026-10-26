use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::model::TypedBatch;
use crate::provenance::RequestEvidence;

pub const DIRECTORY: &str = ".pijul/patchgate/windows";
const SCHEMA_VERSION: u32 = 1;
const PROTOCOL_VERSION: &str = "patchgate-window-review-v1";
const MAX_ENTRY_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Serialize)]
pub struct Binding<'a> {
    pub source_sha256: &'a str,
    pub input_sha256: &'a str,
    pub request: &'a RequestEvidence,
    pub model_identity: &'a str,
    pub min_confidence: Option<f64>,
    pub rule_confidence: f64,
    pub escalation_confidence: f64,
    pub escalation_identity: Option<&'a str>,
}

pub fn key(binding: &Binding<'_>) -> Result<String> {
    ensure!(
        binding.min_confidence.is_none_or(f64::is_finite)
            && binding.rule_confidence.is_finite()
            && binding.escalation_confidence.is_finite(),
        "Window cache thresholds must be finite"
    );
    #[derive(Serialize)]
    struct Key<'a, 'b> {
        protocol: &'static str,
        binding: &'a Binding<'b>,
    }
    crate::provenance::digest(&Key {
        protocol: PROTOCOL_VERSION,
        binding,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    schema_version: u32,
    key: String,
    batch: TypedBatch,
}

#[derive(Serialize)]
struct EntryRef<'a> {
    schema_version: u32,
    key: &'a str,
    batch: &'a TypedBatch,
}

pub struct Cache {
    repository: PathBuf,
}

impl Cache {
    pub fn new(repository: &Path) -> Result<Self> {
        let directory = crate::pijul::safe_path(repository, Path::new(DIRECTORY))?;
        DirBuilder::new().recursive(true).mode(0o700).create(&directory)?;
        let file = open_directory(&directory)?;
        ensure!(
            file.metadata()?.uid() == unsafe { libc::geteuid() },
            "A window cache directory must belong to the current user"
        );
        file.set_permissions(fs::Permissions::from_mode(0o700))?;
        private_directory(&file)?;
        Ok(Self {
            repository: repository.to_owned(),
        })
    }

    fn directory(&self) -> Result<(PathBuf, File)> {
        let path = crate::pijul::safe_path(&self.repository, Path::new(DIRECTORY))?;
        let directory = open_directory(&path)?;
        private_directory(&directory)?;
        Ok((path, directory))
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        ensure!(valid_sha256(key), "A window cache key is not valid");
        crate::pijul::safe_path(
            &self.repository,
            &Path::new(DIRECTORY).join(format!("{key}.json")),
        )
    }

    fn read(&self, key: &str) -> Result<Option<Entry>> {
        let (_path, directory) = self.directory()?;
        fs2::FileExt::lock_shared(&directory)?;
        self.read_locked(key)
    }

    fn read_locked(&self, key: &str) -> Result<Option<Entry>> {
        let path = self.path(key)?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o7777 == 0o600,
            "A window cache entry must be a private regular file without aliases"
        );
        ensure!(
            metadata.len() <= MAX_ENTRY_BYTES,
            "A window cache entry exceeds its size limit"
        );
        let mut input = file.take(MAX_ENTRY_BYTES + 1);
        let entry: Entry = serde_json::from_reader(&mut input)
            .map_err(|_| anyhow!("A window cache entry is not valid"))?;
        ensure!(
            input.limit() != 0,
            "A window cache entry exceeds its size limit"
        );
        if entry.schema_version != SCHEMA_VERSION || entry.key != key || !complete(&entry.batch) {
            return Ok(None);
        }
        Ok(Some(entry))
    }

    pub fn load(&self, key: &str, expected: &RequestEvidence) -> Result<Option<TypedBatch>> {
        let Some(entry) = self.read(key)? else {
            return Ok(None);
        };
        if entry.batch.evidence.first() != Some(expected) {
            return Ok(None);
        }
        Ok(Some(entry.batch))
    }

    pub fn store(&self, key: &str, batch: &TypedBatch) -> Result<()> {
        ensure!(complete(batch), "A window cache entry needs a complete typed batch");
        let (directory_path, directory) = self.directory()?;
        let path = self.path(key)?;
        fs2::FileExt::lock_exclusive(&directory)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".tmp")
            .tempfile_in(&directory_path)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        {
            let mut output = BoundedWriter {
                output: &mut temporary,
                remaining: MAX_ENTRY_BYTES,
            };
            serde_json::to_writer(
                &mut output,
                &EntryRef {
                    schema_version: SCHEMA_VERSION,
                    key,
                    batch,
                },
            )?;
            output.write_all(b"\n")?;
        }
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                ensure!(
                    self.read_locked(key)?
                        .is_some_and(|entry| entry.batch.evidence.first() == batch.evidence.first()),
                    "An existing window cache entry does not match its request"
                );
            }
            Err(error) => return Err(error.error.into()),
        }
        directory.sync_all()?;
        Ok(())
    }

    pub fn copy_existing(repository: &Path, destination: &Path) -> Result<()> {
        let source = Self {
            repository: repository.to_owned(),
        };
        let source_path = crate::pijul::safe_path(repository, Path::new(DIRECTORY))?;
        let source_directory = match open_directory(&source_path) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        private_directory(&source_directory)?;
        let destination = Self::new(destination)?;
        for entry in fs::read_dir(&source_path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| anyhow!("A window cache file name is not valid"))?;
            if name.starts_with(".tmp") {
                continue;
            }
            let key = name
                .strip_suffix(".json")
                .filter(|key| valid_sha256(key))
                .ok_or_else(|| anyhow!("A window cache file name is not valid"))?;
            if let Some(entry) = source.read(key)? {
                destination.store(key, &entry.batch)?;
            }
        }
        Ok(())
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

fn private_directory(directory: &File) -> Result<()> {
    let metadata = directory.metadata()?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "A window cache directory must be private"
    );
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn complete(batch: &TypedBatch) -> bool {
    if !batch.invalid.is_empty()
        || !batch.answers.contains_key("review")
        || !batch.answers.contains_key("context")
        || batch.evidence.is_empty()
    {
        return false;
    }
    for (question, answer) in &batch.answers {
        let valid_label = match question.as_str() {
            "review" => matches!(answer.choice.as_str(), "accept" | "reject" | "escalate"),
            "context" => matches!(answer.choice.as_str(), "sufficient" | "needs-context"),
            name if name.strip_prefix("rule-").is_some_and(|id| !id.is_empty()) => {
                matches!(
                    answer.choice.as_str(),
                    "allows" | "rejects" | "needs-human" | "not-covered"
                )
            }
            _ => false,
        };
        if !valid_label
            || !answer
                .confidence
                .is_some_and(|value| value.is_finite() && (0.0..=1.0).contains(&value))
        {
            return false;
        }
    }
    let initial = &batch.evidence[0];
    if initial.schema_version != 1
        || initial.operation != "review-window"
        || initial.api != "systemone"
        || initial.revision_verified
        || !valid_sha256(&initial.prompt_sha256)
        || !valid_sha256(&initial.schema_sha256)
    {
        return false;
    }
    let mut questions = std::collections::BTreeSet::new();
    batch.evidence.iter().skip(1).all(|evidence| {
        evidence.schema_version == initial.schema_version
            && evidence.api == initial.api
            && evidence.model == initial.model
            && evidence.declared_revision == initial.declared_revision
            && !evidence.revision_verified
            && evidence.prompt_sha256 == initial.prompt_sha256
            && valid_sha256(&evidence.schema_sha256)
            && batch.answers.contains_key(&evidence.operation)
            && questions.insert(evidence.operation.as_str())
    })
}

struct BoundedWriter<W> {
    output: W,
    remaining: u64,
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(io::Error::other("A window cache entry exceeds its size limit"));
        }
        let written = self.output.write(bytes)?;
        self.remaining -= written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::model::MergeChoice;
    use serde_json::json;

    fn request() -> RequestEvidence {
        RequestEvidence::new(
            "review-window",
            "systemone",
            "cache-model",
            Some("revision-1"),
            &json!({"instructions": "Private policy", "state": {"window": 1}}),
            &json!({"review": ["accept", "reject", "escalate"], "context": ["sufficient", "needs-context"], "rule-A": ["allows", "rejects", "needs-human", "not-covered"]}),
        )
        .unwrap()
    }

    fn binding(request: &RequestEvidence) -> Binding<'_> {
        Binding {
            source_sha256: "source-digest",
            input_sha256: "window-digest",
            request,
            model_identity: "endpoint-api-model-revision-digest",
            min_confidence: Some(0.8),
            rule_confidence: 0.75,
            escalation_confidence: 0.9,
            escalation_identity: Some("larger-model-digest"),
        }
    }

    fn batch() -> TypedBatch {
        let initial = request();
        let mut recovery = initial.clone();
        recovery.operation = "rule-A".into();
        recovery.schema_sha256 = crate::provenance::digest(&json!({"rule-A": "choice"})).unwrap();
        TypedBatch {
            answers: [
                ("review", "accept", 0.92),
                ("context", "sufficient", 0.87),
                ("rule-A", "allows", 0.84),
            ]
            .into_iter()
            .map(|(question, choice, confidence)| {
                (
                    question.into(),
                    MergeChoice {
                        choice: choice.into(),
                        reason: format!("Selected {choice}."),
                        confidence: Some(confidence),
                    },
                )
            })
            .collect(),
            evidence: vec![initial, recovery],
            invalid: Vec::new(),
        }
    }

    fn write_entry(cache: &Cache, key: &str, batch: &TypedBatch) -> Result<()> {
        let path = cache.path(key)?;
        fs::write(
            &path,
            serde_json::to_vec(&EntryRef {
                schema_version: SCHEMA_VERSION,
                key,
                batch,
            })?,
        )?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[test]
    fn exact_bindings_restore_complete_batches_after_reopen() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let request = request();
        let key = key(&binding(&request))?;
        let expected = batch();
        {
            let cache = Cache::new(repository.path())?;
            assert!(cache.load(&key, &request)?.is_none());
            cache.store(&key, &expected)?;
        }
        let cache = Cache::new(repository.path())?;
        let restored = cache.load(&key, &request)?.unwrap();
        assert_eq!(restored.answers, expected.answers);
        assert_eq!(restored.evidence, expected.evidence);
        assert!(restored.invalid.is_empty());
        assert_eq!(cache.directory()?.1.metadata()?.permissions().mode() & 0o7777, 0o700);
        assert_eq!(fs::metadata(cache.path(&key)?)?.permissions().mode() & 0o7777, 0o600);
        Ok(())
    }

    #[test]
    fn changed_bindings_cannot_select_stored_work() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let cache = Cache::new(repository.path())?;
        let request = request();
        let original = binding(&request);
        let original_key = key(&original)?;
        cache.store(&original_key, &batch())?;
        for changed in [
            Binding { source_sha256: "other-source", ..original },
            Binding { input_sha256: "other-window", ..original },
            Binding { model_identity: "other-endpoint", ..original },
            Binding { min_confidence: None, ..original },
            Binding { min_confidence: Some(0.81), ..original },
            Binding { rule_confidence: 0.76, ..original },
            Binding { escalation_confidence: 0.91, ..original },
            Binding { escalation_identity: None, ..original },
            Binding { escalation_identity: Some("other-tier"), ..original },
        ] {
            let changed_key = key(&changed)?;
            assert_ne!(changed_key, original_key);
            assert!(cache.load(&changed_key, &request)?.is_none());
        }
        for field in ["operation", "api", "model", "declared_revision", "prompt_sha256", "schema_sha256"] {
            let mut changed = serde_json::to_value(&request)?;
            changed[field] = json!("other-input");
            let changed: RequestEvidence = serde_json::from_value(changed)?;
            let changed_key = key(&binding(&changed))?;
            assert_ne!(changed_key, original_key);
            assert!(cache.load(&changed_key, &changed)?.is_none());
            assert!(cache.load(&original_key, &changed)?.is_none());
        }
        let mut changed = original;
        changed.rule_confidence = f64::NAN;
        assert!(key(&changed).is_err());
        changed = original;
        changed.min_confidence = Some(f64::INFINITY);
        assert!(key(&changed).is_err());
        changed = original;
        changed.escalation_confidence = f64::NEG_INFINITY;
        assert!(key(&changed).is_err());
        Ok(())
    }

    #[test]
    fn incomplete_answers_and_invalid_labels_or_probabilities_are_refused() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let cache = Cache::new(repository.path())?;
        let request = request();
        let key = key(&binding(&request))?;
        let mut invalid = Vec::new();
        for question in ["review", "context", "rule-A"] {
            let mut value = batch();
            value.answers.remove(question);
            invalid.push(value);
        }
        let mut value = batch();
        value.answers.remove("rule-A");
        value.invalid.push("rule-A".into());
        invalid.push(value);
        let mut value = batch();
        value.evidence.clear();
        invalid.push(value);
        for question in ["review", "context", "rule-A"] {
            let mut value = batch();
            value.answers.get_mut(question).unwrap().choice = "unknown-label".into();
            invalid.push(value);
        }
        for confidence in [None, Some(-0.01), Some(1.01)] {
            let mut value = batch();
            value.answers.get_mut("review").unwrap().confidence = confidence;
            invalid.push(value);
        }
        let mut value = batch();
        let answer = value.answers.remove("rule-A").unwrap();
        value.answers.insert("unknown-question".into(), answer);
        invalid.push(value);
        for value in invalid {
            assert!(cache.store(&key, &value).is_err());
            write_entry(&cache, &key, &value)?;
            assert!(cache.load(&key, &request)?.is_none());
            fs::remove_file(cache.path(&key)?)?;
        }
        for confidence in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut value = batch();
            value.answers.get_mut("context").unwrap().confidence = Some(confidence);
            assert!(cache.store(&key, &value).is_err());
        }
        for confidence in [0.0, 1.0] {
            let mut value = batch();
            value.answers.get_mut("context").unwrap().confidence = Some(confidence);
            assert!(complete(&value));
        }
        Ok(())
    }

    #[test]
    fn evidence_identity_and_distinct_recovery_questions_are_mandatory() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let cache = Cache::new(repository.path())?;
        let request = request();
        let key = key(&binding(&request))?;
        for field in ["api", "model", "declared_revision", "prompt_sha256", "operation"] {
            let mut value = serde_json::to_value(batch())?;
            value["evidence"][1][field] = json!("other-identity");
            let value: TypedBatch = serde_json::from_value(value)?;
            assert!(cache.store(&key, &value).is_err());
            write_entry(&cache, &key, &value)?;
            assert!(cache.load(&key, &request)?.is_none());
            fs::remove_file(cache.path(&key)?)?;
        }
        for index in [0, 1] {
            let mut value = batch();
            value.evidence[index].revision_verified = true;
            assert!(cache.store(&key, &value).is_err());
        }
        let mut value = batch();
        value.evidence.push(value.evidence[1].clone());
        assert!(cache.store(&key, &value).is_err());
        let mut value = batch();
        value.evidence[0].operation = "review".into();
        assert!(cache.store(&key, &value).is_err());
        Ok(())
    }

    #[test]
    fn exact_stored_keys_and_versions_are_mandatory() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let cache = Cache::new(repository.path())?;
        let request = request();
        let key = key(&binding(&request))?;
        for (field, replacement) in [("schema_version", json!(2)), ("key", json!("0".repeat(64)))] {
            let mut value = serde_json::to_value(EntryRef {
                schema_version: SCHEMA_VERSION,
                key: &key,
                batch: &batch(),
            })?;
            value[field] = replacement;
            fs::write(cache.path(&key)?, serde_json::to_vec(&value)?)?;
            fs::set_permissions(cache.path(&key)?, fs::Permissions::from_mode(0o600))?;
            assert!(cache.load(&key, &request)?.is_none());
        }
        for key in ["../escape", "", &"A".repeat(64), &"a".repeat(63), &"g".repeat(64)] {
            assert!(cache.load(key, &request).is_err());
            assert!(cache.store(key, &batch()).is_err());
        }
        Ok(())
    }

    #[test]
    fn unsafe_cache_files_cannot_supply_answers() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let cache = Cache::new(repository.path())?;
        let request = request();
        let key = key(&binding(&request))?;
        let path = cache.path(&key)?;
        write_entry(&cache, &key, &batch())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(cache.load(&key, &request).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let alias = repository.path().join("alias");
        fs::hard_link(&path, &alias)?;
        assert!(cache.load(&key, &request).is_err());
        fs::remove_file(&path)?;
        std::os::unix::fs::symlink(&alias, &path)?;
        assert!(cache.load(&key, &request).is_err());
        assert!(cache.store(&key, &batch()).is_err());
        fs::remove_file(&path)?;
        fs::create_dir(&path)?;
        assert!(cache.load(&key, &request).is_err());
        fs::remove_dir(&path)?;
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        ensure!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) } == 0, "The test pipe cannot be created");
        assert!(cache.load(&key, &request).is_err());
        fs::remove_file(&path)?;
        let directory = repository.path().join(DIRECTORY);
        fs::rename(&directory, repository.path().join("old-cache"))?;
        std::os::unix::fs::symlink(repository.path().join("old-cache"), &directory)?;
        assert!(Cache::new(repository.path()).is_err());
        assert!(cache.load(&key, &request).is_err());
        assert!(cache.store(&key, &batch()).is_err());
        Ok(())
    }

    #[test]
    fn entry_size_limits_apply_to_reads_and_writes() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let cache = Cache::new(repository.path())?;
        let request = request();
        let key = key(&binding(&request))?;
        let mut value = batch();
        value.answers.get_mut("review").unwrap().reason.clear();
        let fixed = serde_json::to_vec(&EntryRef {
            schema_version: SCHEMA_VERSION,
            key: &key,
            batch: &value,
        })?.len() as u64 + 1;
        value.answers.get_mut("review").unwrap().reason = "x".repeat((MAX_ENTRY_BYTES - fixed) as usize);
        cache.store(&key, &value)?;
        assert_eq!(fs::metadata(cache.path(&key)?)?.len(), MAX_ENTRY_BYTES);
        assert!(cache.load(&key, &request)?.is_some());
        fs::remove_file(cache.path(&key)?)?;
        value.answers.get_mut("review").unwrap().reason.push('x');
        assert!(cache.store(&key, &value).is_err());
        assert!(cache.load(&key, &request)?.is_none());
        write_entry(&cache, &key, &value)?;
        OpenOptions::new().append(true).open(cache.path(&key)?)?.write_all(b"\n\n")?;
        assert!(cache.load(&key, &request).is_err());
        Ok(())
    }

    #[test]
    fn parser_errors_do_not_expose_cache_contents() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let cache = Cache::new(repository.path())?;
        let request = request();
        let key = key(&binding(&request))?;
        fs::write(cache.path(&key)?, br#"{"schema_version":"PRIVATE_PARSER_INPUT"}"#)?;
        fs::set_permissions(cache.path(&key)?, fs::Permissions::from_mode(0o600))?;
        let error = cache.load(&key, &request).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE_PARSER_INPUT"));
        Ok(())
    }

    #[test]
    fn concurrent_stores_never_replace_an_existing_batch() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let cache = Cache::new(repository.path())?;
        let request = request();
        let key = key(&binding(&request))?;
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| -> Result<()> {
            let mut handles = Vec::new();
            for choice in ["accept", "reject"] {
                let barrier = barrier.clone();
                let cache = &cache;
                let key = &key;
                handles.push(scope.spawn(move || -> Result<()> {
                    let mut value = batch();
                    value.answers.get_mut("review").unwrap().choice = choice.into();
                    barrier.wait();
                    cache.store(key, &value)
                }));
            }
            for handle in handles {
                handle.join().map_err(|_| anyhow!("A cache test thread failed"))??;
            }
            Ok(())
        })?;
        let first = cache.load(&key, &request)?.unwrap();
        assert!(matches!(first.answers["review"].choice.as_str(), "accept" | "reject"));
        let mut replacement = batch();
        replacement.answers.get_mut("review").unwrap().choice = "escalate".into();
        cache.store(&key, &replacement)?;
        let retained = cache.load(&key, &request)?.unwrap();
        assert_eq!(retained.answers, first.answers);
        assert_eq!(retained.evidence, first.evidence);
        Ok(())
    }

    #[test]
    fn isolated_copies_preserve_batches_without_source_writes() -> Result<()> {
        let source = tempfile::tempdir()?;
        let destination = tempfile::tempdir()?;
        Cache::copy_existing(source.path(), destination.path())?;
        assert!(!source.path().join(DIRECTORY).exists());
        let cache = Cache::new(source.path())?;
        let request = request();
        let key = key(&binding(&request))?;
        cache.store(&key, &batch())?;
        let path = cache.path(&key)?;
        let before = fs::metadata(&path)?;
        fs::write(source.path().join(DIRECTORY).join(".tmp-interrupted"), b"{")?;
        let incomplete_key = super::key(&Binding {
            input_sha256: "incomplete-window",
            ..binding(&request)
        })?;
        let mut incomplete = batch();
        incomplete.invalid.push("rule-A".into());
        write_entry(&cache, &incomplete_key, &incomplete)?;
        Cache::copy_existing(source.path(), destination.path())?;
        let copied = Cache::new(destination.path())?.load(&key, &request)?.unwrap();
        assert_eq!(copied.answers, batch().answers);
        assert_eq!(copied.evidence, batch().evidence);
        assert!(
            Cache::new(destination.path())?
                .load(&incomplete_key, &request)?
                .is_none()
        );
        let after = fs::metadata(&path)?;
        assert_eq!((before.ino(), before.len(), before.mtime(), before.mtime_nsec()), (after.ino(), after.len(), after.mtime(), after.mtime_nsec()));
        assert_eq!(after.nlink(), 1);
        fs::hard_link(&path, source.path().join("source-alias"))?;
        assert!(Cache::copy_existing(source.path(), destination.path()).is_err());
        Ok(())
    }
}
