use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provenance::RequestEvidence;
use crate::review::ReviewBinding;

pub const DIRECTORY: &str = ".pijul/patchgate/decisions";
pub const MERGE_DIRECTORY: &str = ".pijul/patchgate/merges";
const SCHEMA_VERSION: u32 = 1;
const MAX_ENTRY_BYTES: u64 = 64 * 1024;

/// A model verdict for one exact candidate, policy, main state, and model identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub schema_version: u32,
    pub key: String,
    pub candidate: String,
    pub policy_path: Option<String>,
    pub policy_sha256: Option<String>,
    pub main_channel: String,
    pub main_state: Option<String>,
    pub model: String,
    pub api: String,
    pub revision: Option<String>,
    pub decision: String,
    pub summary: String,
    pub reason: String,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub min_confidence: Option<f64>,
    /// The typed model identity of the larger escalation tier, when it ran.
    #[serde(default)]
    pub escalation: Option<String>,
    /// The typed answers that produced this verdict.
    #[serde(default)]
    pub answers: Vec<crate::gate::TypedAnswer>,
    pub request: RequestEvidence,
    /// Further request evidence, such as rule fallbacks and typed citations.
    #[serde(default)]
    pub extra_requests: Vec<RequestEvidence>,
}

/// A typed choice for one exact conflict prompt, option set, and model identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeEntry {
    pub schema_version: u32,
    pub key: String,
    pub prompt_sha256: String,
    pub choices_sha256: String,
    pub model: String,
    pub api: String,
    pub revision: Option<String>,
    pub choice: String,
    pub reason: String,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub escalation: Option<String>,
    /// Every typed answer that produced the stored choice.
    #[serde(default)]
    pub answers: Vec<crate::gate::TypedAnswer>,
    pub request: RequestEvidence,
}

/// Bind a merge choice to the exact prompt, labels, and model identity.
pub fn merge_key(
    prompt: &str,
    labels: &[&str],
    model: &str,
    api: &str,
    revision: Option<&str>,
    escalation: Option<&str>,
) -> Result<String> {
    let value = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "prompt_sha256": format!("{:x}", Sha256::digest(prompt.as_bytes())),
        "choices_sha256": format!("{:x}", Sha256::digest(serde_json::to_vec(labels)?)),
        "model": model,
        "api": api,
        "revision": revision,
        "escalation": escalation,
    });
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&value)?)))
}

/// Bind a verdict to every input of the model request. A changed input selects another key.
pub fn key(
    binding: &ReviewBinding,
    candidate: &str,
    model: &str,
    api: &str,
    revision: Option<&str>,
    min_confidence: Option<f64>,
    escalation: Option<&str>,
) -> Result<String> {
    let mut value = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "candidate": candidate,
        "policy": binding.policy.as_ref().map(|policy| (&policy.path, &policy.sha256)),
        "main": (&binding.main.channel, &binding.main.state),
        "model": model,
        "api": api,
        "revision": revision,
        "min_confidence": min_confidence,
        "escalation": escalation,
    });
    if api == "systemone" {
        value["typed_evidence_version"] = serde_json::json!(2);
    }
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&value)?)))
}

pub struct Cache {
    directory: PathBuf,
}

pub struct MergeCache {
    directory: PathBuf,
}

impl MergeCache {
    pub fn new(repository: &Path) -> Result<Self> {
        let directory = crate::pijul::safe_path(repository, Path::new(MERGE_DIRECTORY))?;
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        Ok(Self { directory })
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        ensure!(
            key.len() == 64
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "A merge decision key is not valid"
        );
        Ok(self.directory.join(format!("{key}.json")))
    }

    /// Return a choice only when the prompt, the options, and the model identity still match.
    pub fn load(
        &self,
        key: &str,
        prompt: &str,
        labels: &[&str],
        model: &str,
        api: &str,
        revision: Option<&str>,
        escalation: Option<&str>,
    ) -> Result<Option<MergeEntry>> {
        let path = self.path(key)?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "A merge cache entry is not a regular file without aliases"
        );
        ensure!(
            metadata.len() <= MAX_ENTRY_BYTES,
            "A merge cache entry exceeds its size limit"
        );
        let entry: MergeEntry =
            serde_json::from_reader(file).context("A merge cache entry is not valid")?;
        let matches = entry.schema_version == SCHEMA_VERSION
            && entry.key == key
            && entry.prompt_sha256 == format!("{:x}", Sha256::digest(prompt.as_bytes()))
            && entry.choices_sha256 == format!("{:x}", Sha256::digest(serde_json::to_vec(labels)?))
            && entry.model == model
            && entry.api == api
            && entry.revision.as_deref() == revision
            && entry
                .escalation
                .as_deref()
                .is_none_or(|used| Some(used) == escalation)
            && labels.contains(&entry.choice.as_str());
        if !matches {
            return Ok(None);
        }
        Ok(Some(entry))
    }

    pub fn store(&self, entry: &MergeEntry) -> Result<()> {
        let path = self.path(&entry.key)?;
        if path.exists() {
            return Ok(());
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(".tmp")
            .tempfile_in(&self.directory)?;
        serde_json::to_writer(&mut temporary, entry)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        temporary.persist(&path).map_err(|error| error.error)?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

impl Cache {
    pub fn new(repository: &Path) -> Result<Self> {
        let directory = crate::pijul::safe_path(repository, Path::new(DIRECTORY))?;
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        Ok(Self { directory })
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        ensure!(
            key.len() == 64
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "A decision key is not valid"
        );
        Ok(self.directory.join(format!("{key}.json")))
    }

    /// Return a verdict only when every bound input still matches its exact entry.
    pub fn load(
        &self,
        key: &str,
        binding: &ReviewBinding,
        candidate: &str,
        model: &str,
        api: &str,
        revision: Option<&str>,
        min_confidence: Option<f64>,
        escalation: Option<&str>,
    ) -> Result<Option<Entry>> {
        let path = self.path(key)?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "A decision cache entry is not a regular file without aliases"
        );
        ensure!(
            metadata.len() <= MAX_ENTRY_BYTES,
            "A decision cache entry exceeds its size limit"
        );
        let entry: Entry =
            serde_json::from_reader(file).context("A decision cache entry is not valid")?;
        let previous = binding.policy.as_ref();
        let matches = entry.schema_version == SCHEMA_VERSION
            && entry.key == key
            && entry.candidate == candidate
            && entry.model == model
            && entry.api == api
            && entry.revision.as_deref() == revision
            && entry.min_confidence == min_confidence
            && entry
                .escalation
                .as_deref()
                .is_none_or(|used| Some(used) == escalation)
            && entry.main_channel == binding.main.channel
            && entry.main_state == binding.main.state
            && entry.policy_path.as_deref() == previous.map(|policy| policy.path.as_str())
            && entry.policy_sha256.as_deref() == previous.map(|policy| policy.sha256.as_str())
            && matches!(entry.decision.as_str(), "accept" | "reject" | "escalate");
        if !matches {
            return Ok(None);
        }
        Ok(Some(entry))
    }

    pub fn store(&self, entry: &Entry) -> Result<()> {
        let path = self.path(&entry.key)?;
        if path.exists() {
            return Ok(());
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(".tmp")
            .tempfile_in(&self.directory)?;
        serde_json::to_writer(&mut temporary, entry)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        temporary.persist(&path).map_err(|error| error.error)?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::PolicyBinding;

    fn binding() -> ReviewBinding {
        ReviewBinding {
            candidates: vec!["CANDIDATE".into()],
            policy: Some(PolicyBinding {
                path: "POLICY.md".into(),
                sha256: "policy-digest".into(),
            }),
            main: crate::review::MainBinding {
                channel: "main".into(),
                state: Some("main-state".into()),
            },
        }
    }

    fn request() -> RequestEvidence {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "operation": "review",
            "api": "openai",
            "model": "feature-test",
            "declared_revision": null,
            "revision_verified": false,
            "prompt_sha256": "prompt",
            "schema_sha256": "schema",
        }))
        .unwrap()
    }

    fn entry(key: String) -> Entry {
        Entry {
            schema_version: SCHEMA_VERSION,
            key,
            candidate: "CANDIDATE".into(),
            policy_path: Some("POLICY.md".into()),
            policy_sha256: Some("policy-digest".into()),
            main_channel: "main".into(),
            main_state: Some("main-state".into()),
            model: "feature-test".into(),
            api: "openai".into(),
            revision: None,
            decision: "accept".into(),
            summary: "Safe.".into(),
            reason: "No rule rejects it.".into(),
            confidence: None,
            min_confidence: None,
            escalation: None,
            answers: Vec::new(),
            request: request(),
            extra_requests: Vec::new(),
        }
    }

    #[test]
    fn merge_choices_require_their_exact_prompt_options_and_model() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = MergeCache::new(directory.path())?;
        let labels = ["keep both", "escalate"];
        let key = merge_key(
            "the conflict",
            &labels,
            "clef",
            "systemone",
            Some("rev-1"),
            None,
        )?;
        assert_eq!(
            cache.load(
                &key,
                "the conflict",
                &labels,
                "clef",
                "systemone",
                Some("rev-1"),
                None
            )?,
            None
        );
        cache.store(&MergeEntry {
            schema_version: SCHEMA_VERSION,
            key: key.clone(),
            prompt_sha256: format!("{:x}", Sha256::digest(b"the conflict")),
            choices_sha256: format!("{:x}", Sha256::digest(serde_json::to_vec(&labels)?)),
            model: "clef".into(),
            api: "systemone".into(),
            revision: Some("rev-1".into()),
            escalation: None,
            answers: vec![crate::gate::TypedAnswer {
                schema_version: 1,
                operation: "merge".into(),
                api: "systemone".into(),
                model: "clef".into(),
                question: "merge".into(),
                choice: "keep both".into(),
                confidence: Some(0.91),
                option_count: 2,
                options_sha256: "options".into(),
                abstained: false,
            }],
            choice: "keep both".into(),
            reason: "Both changes apply.".into(),
            confidence: Some(0.91),
            request: request(),
        })?;
        let entry = cache
            .load(
                &key,
                "the conflict",
                &labels,
                "clef",
                "systemone",
                Some("rev-1"),
                None
            )?
            .expect("the exact merge choice must load");
        assert_eq!(entry.choice, "keep both");
        assert_eq!(entry.confidence, Some(0.91));
        assert_eq!(entry.answers.len(), 1);
        assert_eq!(entry.answers[0].choice, "keep both");
        assert_eq!(
            cache.load(
                &key,
                "another conflict",
                &labels,
                "clef",
                "systemone",
                Some("rev-1"),
                None
            )?,
            None
        );
        assert_eq!(
            cache.load(
                &key,
                "the conflict",
                &["keep both", "escalate", "only side 1"],
                "clef",
                "systemone",
                Some("rev-1"),
                None
            )?,
            None
        );
        assert_eq!(
            cache.load(&key, "the conflict", &labels, "clef", "systemone", None, None)?,
            None
        );
        assert_eq!(
            cache.load(
                &key,
                "the conflict",
                &labels,
                "clef",
                "systemone",
                Some("rev-1"),
                Some("larger")
            )?
            .map(|entry| entry.choice),
            Some("keep both".to_owned())
        );
        Ok(())
    }

    #[test]
    fn entries_require_their_exact_binding_and_key() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = Cache::new(directory.path())?;
        let binding = binding();
        let key = key(&binding, "CANDIDATE", "feature-test", "openai", None, None, None)?;
        assert!(
            cache
                .load(&key, &binding, "CANDIDATE", "feature-test", "openai", None, None, None)?
                .is_none()
        );
        cache.store(&entry(key.clone()))?;
        let loaded = cache
            .load(&key, &binding, "CANDIDATE", "feature-test", "openai", None, None, None)?
            .context("The cached verdict is absent")?;
        assert_eq!(loaded.decision, "accept");
        assert_eq!(loaded.summary, "Safe.");
        assert!(
            cache
                .load(&key, &binding, "CANDIDATE", "another-model", "openai", None, None, None)?
                .is_none()
        );
        assert!(
            cache
                .load(&key, &binding, "OTHER", "feature-test", "openai", None, None, None)?
                .is_none()
        );
        let mut other = binding.clone();
        other.main.state = Some("advanced-main".into());
        assert!(
            cache
                .load(&key, &other, "CANDIDATE", "feature-test", "openai", None, None, None)?
                .is_none()
        );
        assert!(key_with("CANDIDATE", "openai", None) != key_with("CANDIDATE", "systemone", None));
        assert!(
            key_with("CANDIDATE", "openai", Some("r1")) != key_with("CANDIDATE", "openai", None)
        );
        Ok(())
    }

    fn key_with(candidate: &str, api: &str, revision: Option<&str>) -> String {
        key(&binding(), candidate, "feature-test", api, revision, None, None).unwrap()
    }

    #[test]
    fn linked_oversized_and_invalid_entries_are_refused() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = Cache::new(directory.path())?;
        let binding = binding();
        let key = key(&binding, "CANDIDATE", "feature-test", "openai", None, None, None)?;
        let path = cache.path(&key)?;
        fs::write(&path, b"{}")?;
        assert!(
            cache
                .load(&key, &binding, "CANDIDATE", "feature-test", "openai", None, None, None)
                .is_err()
        );
        fs::remove_file(&path)?;
        fs::write(&path, vec![b'{'; MAX_ENTRY_BYTES as usize + 1])?;
        assert!(
            cache
                .load(&key, &binding, "CANDIDATE", "feature-test", "openai", None, None, None)
                .is_err()
        );
        fs::remove_file(&path)?;
        fs::write(directory.path().join("target.json"), b"{}")?;
        std::os::unix::fs::symlink(directory.path().join("target.json"), &path)?;
        assert!(
            cache
                .load(&key, &binding, "CANDIDATE", "feature-test", "openai", None, None, None)
                .is_err()
        );
        assert!(cache.path("../escape").is_err());
        Ok(())
    }

    #[test]
    fn stored_entries_never_change_a_valid_input() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = Cache::new(directory.path())?;
        let binding = binding();
        let key = key(&binding, "CANDIDATE", "feature-test", "openai", None, None, None)?;
        let mut first = entry(key.clone());
        first.decision = "reject".into();
        cache.store(&first)?;
        let mut second = entry(key.clone());
        second.decision = "accept".into();
        cache.store(&second)?;
        let loaded = cache
            .load(&key, &binding, "CANDIDATE", "feature-test", "openai", None, None, None)?
            .context("The cached verdict is absent")?;
        assert_eq!(loaded.decision, "reject");
        Ok(())
    }
}
