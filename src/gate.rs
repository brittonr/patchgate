use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use fs2::FileExt;
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::change::{self, Choices, Conflict, ConflictFile, Hunks, Piece, Region, Unmerged, short};
use crate::model::{Api, Model};
use crate::pijul::{ChannelSnapshot, LogEntry, Pijul, Signer};
use crate::review::{self, ReviewBinding};
use crate::verify::{self, Verification};

#[derive(Clone)]
pub struct Settings {
    pub repo: PathBuf,
    pub inbox: String,
    pub main: String,
    pub model_url: String,
    pub model: String,
    pub model_api: Api,
    pub model_revision: Option<String>,
    pub model_profile: Option<String>,
    pub model_key_file: Option<PathBuf>,
    pub policy: String,
    protected: Vec<String>,
    max_change_chars: usize,
    pub(crate) timeout: Duration,
    pub(crate) check_timeout: Duration,
    interrupted: Arc<AtomicBool>,
}

impl Settings {
    pub fn from_env(
        repo: PathBuf,
        inbox: String,
        main: String,
        interrupted: Arc<AtomicBool>,
    ) -> Result<Self> {
        let timeout: f64 = number("PATCHGATE_TIMEOUT", 300.0)?;
        let check_timeout: f64 = number("PATCHGATE_CHECK_TIMEOUT", 900.0)?;
        let model = crate::models::select()?;
        Ok(Self {
            repo,
            inbox,
            main,
            model_url: model.url,
            model: model.model,
            model_api: model.api,
            model_revision: model.revision,
            model_profile: model.profile,
            model_key_file: model.key_file,
            policy: env::var("PATCHGATE_POLICY").unwrap_or_else(|_| "POLICY.md".into()),
            protected: env::var("PATCHGATE_PROTECTED")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect(),
            max_change_chars: number("PATCHGATE_MAX_CHANGE_CHARS", 8000)?,
            timeout: Duration::try_from_secs_f64(timeout)
                .context("PATCHGATE_TIMEOUT must be a finite, nonnegative number")?,
            check_timeout: Duration::try_from_secs_f64(check_timeout)
                .context("PATCHGATE_CHECK_TIMEOUT must be a finite, positive number")?,
            interrupted,
        })
    }

    /// Read the bearer key for the selected profile. The key never reaches a
    /// record, a report, or an error message.
    pub(crate) fn model_key(&self) -> Result<Option<String>> {
        self.model_key_file
            .as_deref()
            .map(crate::models::read_key)
            .transpose()
    }

    pub(crate) fn baseline_values(&self) -> crate::configuration::Values {
        crate::configuration::Values {
            policy_path: self.policy.clone(),
            protected: self.protected.clone(),
            documentation_paths: Vec::new(),
            max_change_chars: self.max_change_chars,
            timeout_seconds: self.timeout.as_secs_f64(),
            check_timeout_seconds: self.check_timeout.as_secs_f64(),
        }
    }
}

fn number<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
{
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| anyhow!("{name} must be a number, not {value:?}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Pending,
    Waiting,
    Blocked,
    Accepted,
    Removed,
    Rejected,
    Escalated,
    Unknown,
}

impl State {
    fn from_decision(decision: &str) -> Self {
        match decision {
            "accept" | "merge" => Self::Removed,
            "reject" => Self::Rejected,
            "escalate" => Self::Escalated,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Waiting => "waiting",
            Self::Blocked => "blocked",
            Self::Accepted => "accepted",
            Self::Removed => "removed",
            Self::Rejected => "rejected",
            Self::Escalated => "escalated",
            Self::Unknown => "unknown",
        }
    }

    pub fn stuck(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Escalated | Self::Removed | Self::Blocked | Self::Unknown
        )
    }
}

#[derive(Serialize)]
pub struct Item {
    pub hash: String,
    pub message: String,
    paths: Vec<String>,
    pub state: State,
    pub reason: String,
    pub needs: Vec<(String, State)>,
    pub decided: bool,
    pub merge: Option<Record>,
    pub note: String,
}

impl From<LogEntry> for Item {
    fn from(entry: LogEntry) -> Self {
        Self {
            hash: entry.hash,
            message: entry.message,
            paths: entry.paths,
            state: State::Pending,
            reason: String::new(),
            needs: Vec::new(),
            decided: false,
            merge: None,
            note: String::new(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Reconsideration {
    pub previous_record_index: usize,
    pub previous_record_sha256: String,
    pub requested_by: String,
    pub reason: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ResolutionAcceptance {
    pub id: String,
    pub main_state: Option<String>,
    pub candidates: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Record {
    pub hash: String,
    pub decision: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::provenance::Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<ReviewBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<crate::secrets::Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Rc<Verification>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<Rc<crate::configuration::Evidence>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconsideration: Option<Reconsideration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<ResolutionAcceptance>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reused: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    conflict: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    merge: Option<String>,
    #[serde(default, rename = "for", skip_serializing_if = "Vec::is_empty")]
    for_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    files: Vec<String>,
}

impl Record {
    fn new(hash: String, message: String, decision: &str, by: &str, reason: String) -> Self {
        Self {
            hash,
            message,
            decision: decision.into(),
            by: by.into(),
            reason,
            summary: String::new(),
            at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, false),
            model: None,
            provenance: None,
            review: None,
            execution_error: None,
            findings: Vec::new(),
            verification: None,
            user: None,
            configuration: None,
            case_id: None,
            reconsideration: None,
            resolution: None,
            reused: false,
            conflict: false,
            merge: None,
            for_hashes: Vec::new(),
            files: Vec::new(),
        }
    }

    fn reject_secrets(&mut self, findings: Vec<crate::secrets::Finding>) {
        let rules: BTreeSet<_> = findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        self.reason = format!(
            "Deterministic secret checks rejected the change ({}). Remove the credential data before another review.",
            rules.into_iter().collect::<Vec<_>>().join(", ")
        );
        self.message.clear();
        self.message.push_str("[message omitted: credential data]");
        self.decision = "reject".into();
        self.by = "gate".into();
        self.model = None;
        self.review = None;
        self.user = None;
        self.reused = false;
        self.findings = findings;
    }
}

fn record_sha256(record: &Record) -> Result<String> {
    struct HashWriter(Sha256);
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, record)?;
    Ok(format!("{:x}", writer.0.finalize()))
}

fn same_native_change(source: &mut File, target: &Path) -> Result<bool> {
    let mut existing = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(target)?;
    if !existing.metadata()?.is_file() {
        bail!("A native change is not a regular file.");
    }
    if source.metadata()?.len() != existing.metadata()?.len() {
        return Ok(false);
    }
    source.rewind()?;
    let mut expected = [0; 8192];
    let mut actual = [0; 8192];
    loop {
        let count = source.read(&mut expected)?;
        if count == 0 {
            return Ok(true);
        }
        existing.read_exact(&mut actual[..count])?;
        if expected[..count] != actual[..count] {
            return Ok(false);
        }
    }
}

fn import_native_change(source: &Path, target: &Path) -> Result<()> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)?;
    if !input.metadata()?.is_file() {
        bail!("A supplemental change is not a regular file.");
    }
    match fs::symlink_metadata(target) {
        Ok(_) => {
            if !same_native_change(&mut input, target)? {
                bail!("A native change differs from the human workspace.");
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = target
        .parent()
        .context("The native change path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    std::io::copy(&mut input, &mut temporary)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(target) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !same_native_change(&mut input, target)? {
                bail!("A native change differs from the human workspace.");
            }
        }
        Err(error) => return Err(error.error.into()),
    }
    sync_directory(parent)
}

struct ResolutionInput<'a> {
    pijul: &'a Pijul,
    imported: &'a HashSet<String>,
}

#[derive(Serialize)]
pub struct DependencyInfo {
    pub hash: String,
    pub state: State,
    pub in_main: bool,
    pub needs: Vec<String>,
}

#[derive(Serialize)]
pub struct Explanation {
    pub schema_version: u8,
    pub hash: String,
    pub message: String,
    pub state: State,
    pub paths: BTreeSet<String>,
    pub protected_paths: Vec<String>,
    pub dependencies: Vec<DependencyInfo>,
    pub current: ReviewBinding,
    pub configuration: Rc<crate::configuration::Evidence>,
    pub checks: Option<serde_json::Value>,
    pub records: Vec<Record>,
    pub next_actions: Vec<String>,
}

#[derive(Serialize)]
pub struct StatusReport {
    pub schema_version: u8,
    pub main: review::MainBinding,
    pub inbox: review::MainBinding,
    pub configuration: Rc<crate::configuration::Evidence>,
    pub items: Vec<Item>,
    pub behind: Vec<LogEntry>,
    pub records: Vec<Record>,
}

#[derive(Default)]
pub struct Selection {
    pub changes: Vec<String>,
    pub authors: Vec<String>,
    pub include_dependencies: bool,
}

impl Selection {
    pub fn targeted(&self) -> bool {
        !self.changes.is_empty() || !self.authors.is_empty()
    }
}

#[derive(Serialize)]
pub struct SelectionReport {
    pub requested_changes: Vec<String>,
    pub requested_authors: Vec<String>,
    pub include_dependencies: bool,
    pub selected: Vec<String>,
    pub added_dependencies: Vec<String>,
}

struct SelectionPlan {
    chosen: Vec<bool>,
    report: SelectionReport,
}

#[derive(Serialize)]
pub struct ReviewReport {
    pub schema_version: u8,
    pub dry_run: bool,
    pub authorizes_acceptance: bool,
    pub main: review::MainBinding,
    pub inbox: review::MainBinding,
    pub configuration: Rc<crate::configuration::Evidence>,
    pub items: Vec<Item>,
    pub records: Vec<Record>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<SelectionReport>,
}

#[derive(Debug)]
struct InvalidModelReply;

impl std::fmt::Display for InvalidModelReply {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("The model reply is invalid")
    }
}

impl std::error::Error for InvalidModelReply {}

#[derive(Debug)]
struct SecretViolation(Vec<crate::secrets::Finding>);

impl std::fmt::Display for SecretViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("A deterministic secret check refused credential data")
    }
}

impl std::error::Error for SecretViolation {}

#[derive(Debug)]
struct StaleMain(String);

impl std::fmt::Display for StaleMain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StaleMain {}

fn stale(message: String) -> anyhow::Error {
    anyhow::Error::new(StaleMain(message))
}

#[derive(Deserialize, Serialize)]
struct Acceptance {
    version: u32,
    main: String,
    inbox: String,
    ledger_offset: u64,
    leading_newline: bool,
    records: Vec<Record>,
}

impl Acceptance {
    fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        if self.leading_newline {
            bytes.push(b'\n');
        }
        for record in &self.records {
            serde_json::to_writer(&mut bytes, record)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    }

    fn applied(&self, main: &HashSet<String>) -> Result<bool> {
        let present = self
            .records
            .iter()
            .filter(|record| main.contains(&record.hash))
            .count();
        if present != 0 && present != self.records.len() {
            bail!(
                "Only part of the durable acceptance transaction is in {}.",
                self.main
            );
        }
        Ok(present == self.records.len())
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?
        .sync_all()
        .with_context(|| path.display().to_string())
}

pub struct Ledger {
    repo: PathBuf,
    directory: PathBuf,
    path: PathBuf,
}

impl Ledger {
    fn new(repo: &Path) -> Self {
        let directory = repo.join(".pijul/patchgate");
        let path = directory.join("ledger.jsonl");
        Self {
            repo: repo.into(),
            directory,
            path,
        }
    }

    fn validate(&self) -> Result<()> {
        for path in [
            &self.directory,
            &self.path,
            &self.directory.join("lock"),
            &self.intent_path(),
            &self.directory.join("acceptance.tmp"),
            &self.directory.join("verification"),
        ] {
            crate::pijul::safe_path(&self.repo, path.strip_prefix(&self.repo)?)?;
        }
        Ok(())
    }

    pub fn history(&self) -> Result<Vec<Record>> {
        self.validate()?;
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).with_context(|| self.path.display().to_string()),
        };
        let mut records = Vec::new();
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if !line.trim().is_empty() {
                records.push(
                    serde_json::from_str(&line)
                        .with_context(|| format!("{}:{}", self.path.display(), index + 1))?,
                );
            }
        }
        Ok(records)
    }

    fn latest(&self) -> Result<HashMap<String, Record>> {
        Ok(self
            .history()?
            .into_iter()
            .map(|record| (record.hash.clone(), record))
            .collect())
    }

    fn append(&self, record: &Record) -> Result<()> {
        self.validate()?;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        let length = file.metadata()?.len();
        if length != 0 {
            file.seek(SeekFrom::End(-1))?;
            let mut last = [0];
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                file.write_all(b"\n")?;
            }
        }
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        sync_directory(&self.directory)
    }

    fn intent_path(&self) -> PathBuf {
        self.directory.join("acceptance.json")
    }

    fn verification_directory(&self) -> Result<PathBuf> {
        self.validate()?;
        let directory =
            crate::pijul::safe_path(&self.repo, Path::new(".pijul/patchgate/verification"))?;
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    fn pending(&self) -> Result<Option<Acceptance>> {
        self.validate()?;
        let file = match File::open(self.intent_path()) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let intent: Acceptance = serde_json::from_reader(file)
            .context("Cannot read the durable acceptance transaction")?;
        if intent.version != 1 || intent.records.is_empty() {
            bail!("The durable acceptance transaction has an unsupported format.");
        }
        Ok(Some(intent))
    }

    fn prepare(&self, main: &str, inbox: &str, records: Vec<Record>) -> Result<Acceptance> {
        self.validate()?;
        if self.intent_path().exists() {
            bail!("An acceptance transaction still needs recovery.");
        }
        self.history()?;
        let mut offset = 0;
        let mut leading_newline = false;
        match File::open(&self.path) {
            Ok(mut file) => {
                offset = file.metadata()?.len();
                if offset != 0 {
                    file.seek(SeekFrom::End(-1))?;
                    let mut last = [0];
                    file.read_exact(&mut last)?;
                    leading_newline = last[0] != b'\n';
                }
                file.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let intent = Acceptance {
            version: 1,
            main: main.into(),
            inbox: inbox.into(),
            ledger_offset: offset,
            leading_newline,
            records,
        };
        let temporary = self.directory.join("acceptance.tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, &intent)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, self.intent_path())?;
        sync_directory(&self.directory)?;
        Ok(intent)
    }

    fn reconcile(&self, intent: &Acceptance, applied: bool) -> Result<()> {
        self.validate()?;
        let expected = intent.bytes()?;
        let mut tail = Vec::new();
        match File::open(&self.path) {
            Ok(mut file) => {
                let length = file.metadata()?.len();
                if length < intent.ledger_offset {
                    bail!("The ledger is shorter than the acceptance transaction boundary.");
                }
                for (index, line) in BufReader::new((&mut file).take(intent.ledger_offset))
                    .lines()
                    .enumerate()
                {
                    let line = line?;
                    if !line.trim().is_empty() {
                        serde_json::from_str::<Record>(&line)
                            .with_context(|| format!("{}:{}", self.path.display(), index + 1))?;
                    }
                }
                if length - intent.ledger_offset > expected.len() as u64 {
                    bail!("Unrelated ledger data follows the acceptance transaction boundary.");
                }
                file.read_to_end(&mut tail)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if intent.ledger_offset != 0 {
                    bail!("The ledger for the acceptance transaction is missing.");
                }
            }
            Err(error) => return Err(error.into()),
        }
        if !expected.starts_with(&tail) {
            bail!("Ledger data does not match the durable acceptance transaction.");
        }
        if !applied {
            if !tail.is_empty() {
                bail!("The ledger records an acceptance that is absent from its main channel.");
            }
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&expected[tail.len()..])?;
        file.sync_all()?;
        sync_directory(&self.directory)
    }

    fn finish(&self) -> Result<()> {
        self.validate()?;
        fs::remove_file(self.intent_path())?;
        sync_directory(&self.directory)
    }

    fn lock(&self) -> Result<File> {
        self.validate()?;
        fs::create_dir_all(&self.directory)?;
        sync_directory(&self.directory)?;
        sync_directory(
            self.directory
                .parent()
                .expect("The ledger directory has a parent"),
        )?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.directory.join("lock"))?;
        FileExt::lock_exclusive(&file)?;
        Ok(file)
    }
}

struct Landing {
    main: HashSet<String>,
    extra: BTreeSet<String>,
    merge: Option<Record>,
    note: String,
}

pub struct Gate {
    pub settings: Settings,
    pijul: Pijul,
    pub ledger: Ledger,
    decisions: crate::decision::Cache,
    signer: Signer,
    model: Model,
    protected: RegexSet,
    documentation: RegexSet,
    documentation_patterns: Vec<String>,
    policy_path: PathBuf,
    changes: HashMap<String, Rc<str>>,
    baseline: crate::configuration::Values,
    configuration: Rc<crate::configuration::Evidence>,
    capture_enabled: bool,
    verifiers: Option<crate::provenance::VerifierVersions>,
}

impl Gate {
    pub fn new(settings: Settings) -> Result<Self> {
        let baseline = settings.baseline_values();
        let configuration = Rc::new(crate::configuration::Evidence {
            source: "environment".into(),
            path: None,
            sha256: None,
            values: baseline.clone(),
        });
        let ledger = Ledger::new(&settings.repo);
        let protected = RegexSet::new(
            settings
                .protected
                .iter()
                .map(|pattern| crate::protected::pattern_regex(pattern)),
        )?;
        let policy_path = crate::pijul::normalize_path(Path::new(&settings.policy))?;
        let model_key = settings.model_key()?;
        let decisions = crate::decision::Cache::new(&settings.repo)?;
        let mut gate = Self {
            pijul: Pijul::new(settings.repo.clone()),
            signer: Signer::new(ledger.directory.clone()),
            model: Model::new(
                &settings.model_url,
                &settings.model,
                settings.timeout,
                settings.model_api,
                settings.model_revision.as_deref(),
                model_key.as_deref(),
            )?,
            protected,
            documentation: RegexSet::empty(),
            documentation_patterns: Vec::new(),
            policy_path,
            settings,
            ledger,
            decisions,
            changes: HashMap::new(),
            baseline,
            configuration,
            capture_enabled: true,
            verifiers: None,
        };
        let _lock = gate.ledger.lock()?;
        gate.recover()?;
        let main = gate.pijul.snapshot(&gate.settings.main)?;
        gate.refresh_configuration(&main)?;
        Ok(gate)
    }

    fn decision_provenance(&mut self) -> Result<crate::provenance::Decision> {
        if self.verifiers.is_none() {
            self.verifiers = Some(crate::provenance::verifier_versions(&self.pijul)?);
        }
        Ok(crate::provenance::Decision {
            requests: Vec::new(),
            verifiers: self
                .verifiers
                .as_ref()
                .context("Verifier versions are absent")?
                .clone(),
        })
    }

    fn refresh_configuration(&mut self, main: &ChannelSnapshot) -> Result<()> {
        let evidence =
            crate::configuration::load(&self.pijul, &self.settings.main, &self.baseline)?;
        self.require_current_main(main)?;
        if *self.configuration == evidence {
            return Ok(());
        }
        let values = &evidence.values;
        if self.settings.protected != values.protected {
            self.protected = RegexSet::new(
                values
                    .protected
                    .iter()
                    .map(|pattern| crate::protected::pattern_regex(pattern)),
            )?;
        }
        if self.documentation_patterns != values.documentation_paths {
            self.documentation = RegexSet::new(
                values
                    .documentation_paths
                    .iter()
                    .map(|pattern| crate::protected::pattern_regex(pattern)),
            )?;
            self.documentation_patterns
                .clone_from(&values.documentation_paths);
        }
        if self.settings.policy != values.policy_path {
            self.policy_path = crate::pijul::normalize_path(Path::new(&values.policy_path))?;
        }
        let timeout = Duration::try_from_secs_f64(values.timeout_seconds)?;
        if timeout != self.settings.timeout {
            let model_key = self.settings.model_key()?;
            self.model = Model::new(
                &self.settings.model_url,
                &self.settings.model,
                timeout,
                self.settings.model_api,
                self.settings.model_revision.as_deref(),
                model_key.as_deref(),
            )?;
        }
        self.settings.policy.clone_from(&values.policy_path);
        self.settings.protected.clone_from(&values.protected);
        self.settings.max_change_chars = values.max_change_chars;
        self.settings.timeout = timeout;
        self.settings.check_timeout = Duration::try_from_secs_f64(values.check_timeout_seconds)?;
        self.configuration = Rc::new(evidence);
        Ok(())
    }

    fn recover(&self) -> Result<()> {
        let Some(intent) = self.ledger.pending()? else {
            return Ok(());
        };
        let main = self.pijul.hashes(&intent.main)?;
        let applied = intent.applied(&main)?;
        self.ledger.reconcile(&intent, applied)?;
        if applied {
            for record in &intent.records {
                if record.decision == "merge" || record.resolution.is_some() {
                    let note = self.mirror_merge(record, &intent.inbox);
                    if !note.is_empty() {
                        eprintln!("{note}");
                    }
                }
            }
        }
        self.ledger.finish()
    }

    fn mirror_merge(&self, record: &Record, inbox: &str) -> String {
        match self.pijul.hashes(inbox).and_then(|hashes| {
            if hashes.contains(&record.hash) {
                Ok(())
            } else {
                self.pijul.apply(&record.hash, inbox)
            }
        }) {
            Ok(()) => String::new(),
            Err(error) => format!(
                "The merge is not in {inbox}. {error} When the working copy is clean, run: pijul apply --channel {inbox} {}",
                short(&record.hash)
            ),
        }
    }

    fn change_text(&mut self, hash: &str) -> Result<Rc<str>> {
        if let Some(text) = self.changes.get(hash) {
            return Ok(Rc::clone(text));
        }
        let text: Rc<str> = self.pijul.change(hash)?.into();
        self.changes.insert(hash.into(), Rc::clone(&text));
        Ok(text)
    }

    fn find_entry(&self, prefix: &str, include_main: bool) -> Result<LogEntry> {
        if prefix.is_empty() {
            bail!("Give a nonempty change hash prefix.");
        }
        let prefix = prefix.to_uppercase();
        let mut found: Option<LogEntry> = None;
        let main = if include_main {
            self.pijul.log(&self.settings.main)?
        } else {
            Vec::new()
        };
        for entry in self
            .pijul
            .log(&self.settings.inbox)?
            .into_iter()
            .chain(main)
        {
            if !entry.hash.starts_with(&prefix) {
                continue;
            }
            if let Some(previous) = &found {
                if previous.hash != entry.hash {
                    bail!("The hash prefix matches more than one change. Give more of the hash.");
                }
            } else {
                found = Some(entry);
            }
        }
        found.context("No change matches this hash prefix")
    }

    pub fn workspace_status(
        settings: Settings,
        workspace: &Path,
    ) -> Result<crate::resolution::Readiness> {
        let mut report =
            crate::resolution::inspect(&settings.repo, workspace, &settings.baseline_values())?;
        let original = Ledger::new(&settings.repo);
        match original.pending() {
            Ok(Some(_)) => report.add_blocker(
                "acceptance_journal",
                "The source acceptance journal needs recovery before acceptance.",
            ),
            Ok(None) => {}
            Err(_) => report.add_blocker(
                "invalid_journal",
                "The source acceptance journal cannot be read safely.",
            ),
        }
        let history = match original.history() {
            Ok(history) => Some(history),
            Err(_) => {
                report.add_blocker(
                    "invalid_ledger",
                    "The source decision history cannot be read safely.",
                );
                None
            }
        };
        if report
            .main
            .as_deref()
            .is_some_and(|main| main != settings.main)
            || report
                .inbox
                .as_deref()
                .is_some_and(|inbox| inbox != settings.inbox)
        {
            report.add_blocker(
                "selected_channels",
                "The selected channels differ from the trusted workspace channels.",
            );
        }
        if let (Some(main), Some(inbox), Some(candidates), Some(history)) =
            (&report.main, &report.inbox, &report.candidates, history)
        {
            let dependency_state = (|| -> Result<bool> {
                let isolated = crate::isolation::copy_repository(&settings.repo)?;
                let mut settings = settings;
                settings.repo = isolated.pijul.repo.clone();
                settings.main.clone_from(main);
                settings.inbox.clone_from(inbox);
                let mut gate = Self::new(settings)?;
                gate.capture_enabled = false;
                for record in history {
                    gate.ledger.append(&record)?;
                }
                let current = gate.pijul.snapshot(main)?;
                let inbox = gate.pijul.log(inbox)?;
                let primary = candidates
                    .last()
                    .context("The workspace has no primary candidate")?;
                if current.hashes.contains(primary)
                    || !inbox.iter().any(|entry| entry.hash == *primary)
                {
                    return Ok(false);
                }
                Ok(
                    gate.with_conflicting_dependencies(primary, &current.hashes, &inbox)?
                        == *candidates,
                )
            })();
            match dependency_state {
                Ok(true) => {}
                Ok(false) => report.add_blocker(
                    "candidate_dependencies",
                    "The permitted source candidate set differs from the prepared workspace.",
                ),
                Err(_) => report.add_blocker(
                    "candidate_dependencies",
                    "Current source dependencies or decisions prevent this prepared acceptance.",
                ),
            }
        }
        Ok(report)
    }

    fn isolated(
        mut settings: Settings,
        materialize: bool,
    ) -> Result<(crate::isolation::Isolated, Self)> {
        let original = Ledger::new(&settings.repo);
        if original.pending()?.is_some() {
            bail!(
                "An acceptance journal needs recovery. Run patchgate status before an isolated operation."
            );
        }
        original.history()?;
        let isolated = crate::isolation::copy_repository(&settings.repo)?;
        for entry in fs::read_dir(isolated.pijul.repo.join(".pijul"))? {
            let entry = entry?;
            if entry.file_name() != "changes" {
                crate::resolution::detach_files(&entry.path())?;
            }
        }
        if materialize {
            isolated.materialize()?;
        }
        settings.repo = isolated.pijul.repo.clone();
        let mut gate = Self::new(settings)?;
        gate.capture_enabled = false;
        match fs::copy(&original.path, &gate.ledger.path) {
            Ok(_) => crate::resolution::detach_files(&gate.ledger.path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok((isolated, gate))
    }

    pub fn verify_resolution(
        settings: Settings,
        workspace: &Path,
    ) -> Result<crate::resolution::VerificationReport> {
        (|| -> Result<_> {
            let prepared = crate::resolution::load(&settings.repo, workspace)?;
            let (isolated, mut gate) = Self::isolated(settings, false)?;
            crate::resolution::detach_files(&isolated.pijul.repo.join(".pijul"))?;
            gate.accept_prepared_resolution(prepared.clone(), Some("Verify the human workspace"), true)?;
            let records: Vec<_> = gate
                .ledger
                .history()?
                .into_iter()
                .filter(|record| {
                    record.resolution.as_ref().is_some_and(|resolution| resolution.id == prepared.id)
                        && record.decision == "accept"
                })
                .collect();
            if records.is_empty() {
                bail!("The private validation audit is absent.");
            }
            Ok(crate::resolution::VerificationReport {
                schema_version: 1,
                authorizes_acceptance: false,
                prepared,
                validated_hashes: records.iter().map(|record| record.hash.clone()).collect(),
                validation: crate::resolution::ValidationEvidence {
                    source_authority: true,
                    current_bindings: true,
                    permitted_dependencies: true,
                    native_expected_state: true,
                    credential_scan: true,
                    conflicts_absent: true,
                },
                verification: records.iter().find_map(|record| record.verification.clone()),
            })
        })()
        .map_err(|_| anyhow!(
            "Workspace verification failed. Check source authority, current bindings, dependencies, native configuration, credentials, conflicts, and trusted Nix checks."
        ))
    }

    fn case_snapshot(
        &mut self,
        hash: &str,
        main: &ChannelSnapshot,
        repository: &Path,
    ) -> Result<crate::cases::Snapshot> {
        if main.hashes.contains(hash) {
            bail!(
                "The change is already in main. Use cases list for its earlier captured snapshot."
            );
        }
        let text = self.change_text(hash)?;
        if change::dependencies(&text)
            .iter()
            .any(|hash| !main.hashes.contains(hash))
        {
            bail!("The candidate has unmet prerequisites. Resolve them before case capture.");
        }
        let base: Vec<_> = self
            .pijul
            .log(&self.settings.main)?
            .into_iter()
            .map(|entry| entry.hash)
            .collect();
        if base.len() != main.hashes.len() || base.iter().any(|hash| !main.hashes.contains(hash)) {
            bail!("Main changed during case capture.");
        }
        let policy = self
            .pijul
            .read_file_bytes(&self.settings.main, &self.settings.policy)?;
        self.require_current_main(main)?;
        Ok(crate::cases::Snapshot {
            repository: repository.to_owned(),
            main: self.settings.main.clone(),
            inbox: self.settings.inbox.clone(),
            main_state: main.state.clone(),
            base,
            candidate: hash.into(),
            policy_path: self.settings.policy.clone(),
            policy_sha256: policy.map(|bytes| format!("{:x}", Sha256::digest(bytes))),
            configuration: serde_json::to_value(self.configuration.as_ref())?,
        })
    }

    fn capture_record_case(
        &mut self,
        hash: &str,
        main: &ChannelSnapshot,
    ) -> Result<Option<String>> {
        if !self.capture_enabled {
            return Ok(None);
        }
        let repository = self.settings.repo.clone();
        let snapshot = self.case_snapshot(hash, main, &repository)?;
        Ok(Some(
            crate::cases::Store::new(&repository).capture(snapshot)?.id,
        ))
    }

    pub fn capture_case(settings: Settings, prefix: &str) -> Result<crate::cases::CaseRecord> {
        let repository = settings.repo.clone();
        let (_isolated, mut gate) = Self::isolated(settings, false)?;
        let entry = gate.find_entry(prefix, false)?;
        let main = gate.pijul.snapshot(&gate.settings.main)?;
        gate.refresh_configuration(&main)?;
        let snapshot = gate.case_snapshot(&entry.hash, &main, &repository)?;
        crate::cases::Store::new(&repository).capture(snapshot)
    }

    pub fn budget(settings: Settings, prefix: &str) -> Result<crate::budget::Report> {
        let (_isolated, mut gate) = Self::isolated(settings, false)?;
        let entry = gate.find_entry(prefix, true)?;
        let main = gate.pijul.snapshot(&gate.settings.main)?;
        gate.refresh_configuration(&main)?;
        let (candidate, policy) = (|| -> Result<_> {
            let text = gate.change_text(&entry.hash)?;
            let paths = gate.pijul.touched_paths(&gate.settings.inbox, &entry.paths, &text)?;
            let candidate = gate.pijul.review_change(&gate.settings.inbox, &entry.hash, &text, &paths)?;
            let policy = gate.pijul.read_file(&gate.settings.main, &gate.settings.policy)?
                .context("Main has no trusted review policy")?;
            Ok((candidate, policy))
        })().map_err(|_| anyhow!(
            "Cannot read complete native text context or trusted policy. No budget report is available."
        ))?;
        let binding = ReviewBinding::new(
            std::slice::from_ref(&entry.hash),
            &gate.settings.policy,
            Some(&policy),
            &gate.settings.main,
            &main,
        );
        gate.require_current_main(&main)?;
        crate::budget::report(
            &candidate,
            &binding,
            &policy,
            &gate.configuration,
            gate.settings.model_api,
        )
    }

    pub fn prepare_resolution(
        settings: Settings,
        prefix: &str,
        workspace: &Path,
    ) -> Result<crate::resolution::Prepared> {
        let repository = settings.repo.clone();
        let (_isolated, mut gate) = Self::isolated(settings, false)?;
        let entry = gate.find_entry(prefix, false)?;
        let main = gate.pijul.snapshot(&gate.settings.main)?;
        if main.hashes.contains(&entry.hash) {
            bail!("The change is already in main.");
        }
        gate.refresh_configuration(&main)?;
        let inbox = gate.pijul.log(&gate.settings.inbox)?;
        let candidates = gate.with_conflicting_dependencies(&entry.hash, &main.hashes, &inbox)?;
        let policy = gate
            .pijul
            .read_file(&gate.settings.main, &gate.settings.policy)?;
        let binding = ReviewBinding::new(
            &candidates,
            &gate.settings.policy,
            policy.as_deref(),
            &gate.settings.main,
            &main,
        );
        gate.require_current_main(&main)?;
        crate::resolution::prepare(
            &repository,
            &gate.pijul,
            &gate.settings.main,
            &gate.settings.inbox,
            &candidates,
            workspace,
            binding,
            gate.configuration.as_ref().clone(),
        )
    }

    pub fn refresh_resolution(
        settings: Settings,
        previous_workspace: &Path,
        workspace: &Path,
    ) -> Result<crate::resolution::Refreshed> {
        let repository = settings.repo.clone();
        let previous = crate::resolution::load(&repository, previous_workspace)?;
        if previous.main != settings.main || previous.inbox != settings.inbox {
            bail!("The old workspace uses different review channels.");
        }
        let primary = previous
            .candidates
            .last()
            .context("The old workspace has no primary change.")?;
        let (_isolated, mut gate) = Self::isolated(settings, false)?;
        let entry = gate.find_entry(primary, false)?;
        let main = gate.pijul.snapshot(&gate.settings.main)?;
        if main.hashes.contains(&entry.hash) {
            bail!(
                "The original primary change is already in main. Submit further human records as a new change."
            );
        }
        gate.refresh_configuration(&main)?;
        let inbox = gate.pijul.log(&gate.settings.inbox)?;
        let candidates = gate.with_conflicting_dependencies(&entry.hash, &main.hashes, &inbox)?;
        let policy = gate
            .pijul
            .read_file(&gate.settings.main, &gate.settings.policy)?;
        let binding = ReviewBinding::new(
            &candidates,
            &gate.settings.policy,
            policy.as_deref(),
            &gate.settings.main,
            &main,
        );
        gate.require_current_main(&main)?;
        crate::resolution::refresh(
            &repository,
            &gate.pijul,
            &previous,
            &candidates,
            workspace,
            binding,
            gate.configuration.as_ref().clone(),
        )
    }

    pub fn reconsider(&mut self, prefix: &str, reason: &str) -> Result<ReviewReport> {
        if reason.trim().is_empty() {
            bail!("Give an explicit reason for reconsideration.");
        }
        self.recover_under_lock()?;
        let main = self.pijul.snapshot(&self.settings.main)?;
        self.refresh_configuration(&main)?;
        let inbox = self.pijul.snapshot(&self.settings.inbox)?;
        let entry = self.find_entry(prefix, false)?;
        if main.hashes.contains(&entry.hash) {
            bail!("The change is already in main.");
        }
        let history = self.ledger.history()?;
        if history.iter().any(|record| {
            record.hash == entry.hash
                && (record.by == "human" || matches!(record.decision.as_str(), "accept" | "merge"))
        }) {
            bail!(
                "Reconsideration cannot reverse a human decision or a removed acceptance. Use an explicit human decision."
            );
        }
        let (index, previous) = history
            .iter()
            .enumerate()
            .rev()
            .find(|(_, record)| record.hash == entry.hash)
            .context("The change has no earlier decision. Use patchgate review.")?;
        if !matches!(previous.by.as_str(), "gate" | "model")
            || !matches!(previous.decision.as_str(), "reject" | "escalate")
        {
            bail!("Only a gate or model rejection or escalation can receive reconsideration.");
        }
        let text = self.change_text(&entry.hash)?;
        if change::dependencies(&text)
            .iter()
            .any(|hash| !main.hashes.contains(hash))
        {
            bail!("The candidate has unmet prerequisites. Decide them before reconsideration.");
        }
        let reconsideration = Reconsideration {
            previous_record_index: index,
            previous_record_sha256: record_sha256(previous)?,
            requested_by: env::var("USER").unwrap_or_else(|_| "a human".into()),
            reason: reason.into(),
        };
        let configuration = Rc::clone(&self.configuration);
        let boundary = history.len();
        let mut item = Item::from(entry);
        let mut hashes = main.hashes;
        self.decide_and_land(&mut item, &text, &mut hashes, Some(reconsideration))?;
        let records = self.ledger.history()?.into_iter().skip(boundary).collect();
        Ok(ReviewReport {
            schema_version: 1,
            dry_run: !self.capture_enabled,
            authorizes_acceptance: false,
            main: review::MainBinding {
                channel: self.settings.main.clone(),
                state: main.state,
            },
            inbox: review::MainBinding {
                channel: self.settings.inbox.clone(),
                state: inbox.state,
            },
            configuration,
            items: vec![item],
            records,
            selection: None,
        })
    }

    pub fn reconsider_dry_run(
        settings: Settings,
        prefix: &str,
        reason: &str,
    ) -> Result<ReviewReport> {
        let (_isolated, mut gate) = Self::isolated(settings, true)?;
        gate.reconsider(prefix, reason)
    }

    pub fn init(&self) -> Result<Vec<String>> {
        let s = &self.settings;
        let (current, names) = self.pijul.channels()?;
        let mut lines = Vec::new();
        if names.contains(&s.inbox) {
            lines.push(format!("Channel {} exists.", s.inbox));
        } else {
            self.pijul.run(["fork", "--channel", &s.main, &s.inbox])?;
            lines.push(format!("Made channel {} from {}.", s.inbox, s.main));
        }
        if current.as_deref() != Some(&s.inbox) {
            self.pijul.run(["channel", "switch", &s.inbox]).map_err(|error| anyhow!(
                "{error}\nRecord or reset the working copy, then run: pijul channel switch {}", s.inbox
            ))?;
            lines.push(format!("The working copy is now on {}.", s.inbox));
        }
        lines.push(format!(
            "Record changes in {}. patchgate decides which changes go into {}.",
            s.inbox, s.main
        ));
        Ok(lines)
    }

    pub fn status(&mut self) -> Result<Vec<Item>> {
        self.walk(false, &Selection::default(), |_| {})
            .map(|(items, _)| items)
    }

    pub fn status_report(&mut self) -> Result<StatusReport> {
        let main = self.pijul.snapshot(&self.settings.main)?;
        self.refresh_configuration(&main)?;
        let inbox = self.pijul.snapshot(&self.settings.inbox)?;
        let items = self.status()?;
        let relevant: HashSet<_> = items.iter().map(|item| item.hash.as_str()).collect();
        let records = self
            .ledger
            .history()?
            .into_iter()
            .filter(|record| {
                relevant.contains(record.hash.as_str())
                    || record
                        .for_hashes
                        .iter()
                        .any(|hash| relevant.contains(hash.as_str()))
            })
            .collect();
        Ok(StatusReport {
            schema_version: 1,
            configuration: Rc::clone(&self.configuration),
            main: review::MainBinding {
                channel: self.settings.main.clone(),
                state: main.state,
            },
            inbox: review::MainBinding {
                channel: self.settings.inbox.clone(),
                state: inbox.state,
            },
            items,
            behind: self.behind()?,
            records,
        })
    }

    pub fn explain(&mut self, prefix: &str) -> Result<Explanation> {
        if prefix.is_empty() {
            bail!("Give a change hash or a nonempty hash prefix.");
        }
        let main = self.pijul.snapshot(&self.settings.main)?;
        self.refresh_configuration(&main)?;
        let entries: BTreeMap<_, _> = self
            .pijul
            .log(&self.settings.main)?
            .into_iter()
            .chain(self.pijul.log(&self.settings.inbox)?)
            .map(|entry| (entry.hash.clone(), entry))
            .collect();
        let prefix = prefix.to_uppercase();
        let mut matches = entries.keys().filter(|hash| hash.starts_with(&prefix));
        let hash = matches
            .next()
            .context("No change matches this hash prefix")?
            .clone();
        if matches.next().is_some() {
            bail!("The hash prefix matches more than one change. Give more of the hash.");
        }
        let entry = &entries[&hash];
        let states: HashMap<_, _> = self
            .status()?
            .into_iter()
            .map(|item| (item.hash, item.state))
            .collect();
        let state_for = |hash: &str| {
            if main.hashes.contains(hash) {
                State::Accepted
            } else {
                states.get(hash).copied().unwrap_or(State::Unknown)
            }
        };
        let state = state_for(&hash);
        let text = self.change_text(&hash)?;
        let mut paths = self
            .pijul
            .touched_paths(&self.settings.inbox, &entry.paths, &text)?;
        let mut protected_paths: Vec<_> = paths
            .iter()
            .filter(|path| self.is_protected(path))
            .cloned()
            .collect();
        let mut pending = change::dependencies(&text);
        let mut seen = HashSet::new();
        let mut dependencies = Vec::new();
        while let Some(dependency) = pending.pop() {
            if !seen.insert(dependency.clone()) {
                continue;
            }
            let in_main = main.hashes.contains(&dependency);
            let needs = if in_main {
                Vec::new()
            } else {
                change::dependencies(&self.change_text(&dependency)?)
                    .into_iter()
                    .filter(|hash| !main.hashes.contains(hash))
                    .collect::<Vec<_>>()
            };
            pending.extend(needs.iter().cloned());
            dependencies.push(DependencyInfo {
                state: state_for(&dependency),
                hash: dependency,
                in_main,
                needs,
            });
        }
        dependencies.sort_by(|left, right| left.hash.cmp(&right.hash));
        let policy = self
            .pijul
            .read_file(&self.settings.main, &self.settings.policy)?;
        let current = ReviewBinding::new(
            std::slice::from_ref(&hash),
            &self.settings.policy,
            policy.as_deref(),
            &self.settings.main,
            &main,
        );
        let checks = self
            .pijul
            .read_file(&self.settings.main, verify::MANIFEST)?
            .map(|text| serde_json::from_str(&text))
            .transpose()
            .context("The trusted Nix manifest is not valid JSON")?;
        let records: Vec<_> = self
            .ledger
            .history()?
            .into_iter()
            .filter(|record| {
                record.hash == hash
                    || seen.contains(&record.hash)
                    || record.for_hashes.contains(&hash)
            })
            .collect();
        let secret_rejection = records
            .iter()
            .any(|record| record.hash == hash && !record.findings.is_empty());
        let message = if secret_rejection {
            paths.clear();
            protected_paths.clear();
            "[message omitted: credential data]".into()
        } else {
            entry.message.clone()
        };
        let next_actions = match state {
            State::Accepted => Vec::new(),
            State::Pending => vec!["patchgate review --dry-run".into()],
            State::Rejected => vec![
                format!("pijul unrecord {}", short(&hash)),
                "Record a corrected change in the inbox.".into(),
            ],
            State::Escalated => vec![
                format!("patchgate accept {}", short(&hash)),
                format!("patchgate reject {}", short(&hash)),
            ],
            State::Waiting | State::Blocked => {
                vec!["Decide the unmet dependencies before this change.".into()]
            }
            State::Removed => vec!["Examine the removal from main before another decision.".into()],
            State::Unknown => vec!["Examine the channel and dependency state.".into()],
        };
        Ok(Explanation {
            schema_version: 1,
            hash,
            message,
            state,
            paths,
            protected_paths,
            dependencies,
            current,
            configuration: Rc::clone(&self.configuration),
            checks,
            records,
            next_actions,
        })
    }

    fn is_protected(&self, path: &str) -> bool {
        let file = Path::new(path);
        file == self.policy_path
            || file == Path::new(crate::configuration::PATH)
            || file == Path::new(crate::release_policy::PATH)
            || file.starts_with(verify::DIRECTORY)
            || self.protected.is_match(path)
    }

    pub fn review_report(&mut self, dry_run: bool, selection: &Selection) -> Result<ReviewReport> {
        self.recover_under_lock()?;
        let main = self.pijul.snapshot(&self.settings.main)?;
        self.refresh_configuration(&main)?;
        let inbox = self.pijul.snapshot(&self.settings.inbox)?;
        let boundary = self.ledger.history()?.len();
        let (items, selection) = self.walk(true, selection, |_| {})?;
        let records = self.ledger.history()?.into_iter().skip(boundary).collect();
        Ok(ReviewReport {
            schema_version: 1,
            dry_run,
            authorizes_acceptance: false,
            configuration: Rc::clone(&self.configuration),
            main: review::MainBinding {
                channel: self.settings.main.clone(),
                state: main.state,
            },
            inbox: review::MainBinding {
                channel: self.settings.inbox.clone(),
                state: inbox.state,
            },
            items,
            records,
            selection,
        })
    }

    pub fn dry_run(settings: Settings, selection: &Selection) -> Result<ReviewReport> {
        let (_isolated, mut gate) = Self::isolated(settings, true)?;
        gate.review_report(true, selection)
    }

    pub fn behind(&self) -> Result<Vec<LogEntry>> {
        let inbox = self.pijul.hashes(&self.settings.inbox)?;
        Ok(self
            .pijul
            .log(&self.settings.main)?
            .into_iter()
            .filter(|entry| !inbox.contains(&entry.hash))
            .collect())
    }

    pub fn review(
        &mut self,
        selection: &Selection,
        report: impl FnMut(&Item),
    ) -> Result<(Vec<Item>, Option<SelectionReport>)> {
        self.recover_under_lock()?;
        self.walk(true, selection, report)
    }

    pub fn decide_by_hand(
        &mut self,
        prefix: &str,
        decision: &str,
        reason: Option<&str>,
    ) -> Result<Item> {
        self.recover_under_lock()?;
        let main = self.pijul.snapshot(&self.settings.main)?;
        self.refresh_configuration(&main)?;
        let inbox = self.pijul.log(&self.settings.inbox)?;
        let prefix_upper = prefix.to_uppercase();
        let mut matches = inbox
            .iter()
            .filter(|entry| entry.hash.starts_with(&prefix_upper));
        let entry = matches.next().ok_or_else(|| {
            anyhow!(
                "No change in {} has a hash that starts with {prefix}.",
                self.settings.inbox
            )
        })?;
        let count = 1 + matches.count();
        if count > 1 {
            bail!("{prefix} matches {count} changes. Give more of the hash.");
        }
        if main.hashes.contains(&entry.hash) {
            let hint = if decision == "reject" {
                format!(
                    " To remove it, run: pijul unrecord --channel {} {}",
                    self.settings.main,
                    short(&entry.hash)
                )
            } else {
                String::new()
            };
            bail!(
                "{} is in {} already.{hint}",
                short(&entry.hash),
                self.settings.main
            );
        }
        let user = env::var("USER").unwrap_or_else(|_| "a human".into());
        let reason = reason
            .filter(|r| !r.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{user} decided by hand."));
        let mut item = Item::from(LogEntry {
            hash: entry.hash.clone(),
            message: entry.message.clone(),
            paths: entry.paths.clone(),
        });
        item.reason = reason.clone();
        item.decided = true;
        let text = self.change_text(&item.hash)?;
        let case_id = if change::dependencies(&text)
            .iter()
            .all(|hash| main.hashes.contains(hash))
        {
            self.capture_record_case(&item.hash, &main)?
        } else {
            None
        };
        let configuration = Rc::clone(&self.configuration);
        let provenance = self.decision_provenance()?;
        let record = |hash: &str| {
            let message = inbox
                .iter()
                .find(|entry| entry.hash == hash)
                .map(|entry| entry.message.clone())
                .unwrap_or_default();
            let explanation = if hash == item.hash {
                reason.clone()
            } else {
                format!("{reason} It lands with {}.", short(&item.hash))
            };
            let mut record = Record::new(hash.into(), message, decision, "human", explanation);
            record.provenance = Some(provenance.clone());
            record.user = Some(user.clone());
            record.configuration = Some(Rc::clone(&configuration));
            if hash == item.hash {
                record.case_id.clone_from(&case_id);
            }
            record
        };
        if decision != "accept" {
            self.append_under_lock(&record(&item.hash))?;
            item.state = State::from_decision(decision);
            return Ok(item);
        }
        let hashes = self.with_conflicting_dependencies(&item.hash, &main.hashes, &inbox)?;
        let records: Vec<_> = hashes.iter().map(|hash| record(hash)).collect();
        let mut merge_requests = Vec::new();
        match self.land(&hashes, &main, &records, None, &mut merge_requests) {
            Err(error) if error.is::<SecretViolation>() => {
                let SecretViolation(findings) = error.downcast::<SecretViolation>()?;
                let mut refusal = record(&item.hash);
                refusal
                    .provenance
                    .as_mut()
                    .context("Decision provenance is absent")?
                    .requests
                    .extend(merge_requests);
                refusal.reject_secrets(findings);
                self.append_under_lock(&refusal)?;
                bail!("{}", refusal.reason);
            }
            Err(error) => {
                let problem = error.downcast::<Unmerged>()?;
                bail!(
                    "{} conflicts with {}, and patchgate did not merge it. {problem} Edit the conflict in {}, record the result, and run: patchgate accept <hash of the result>",
                    short(&item.hash),
                    self.settings.main,
                    self.settings.inbox
                );
            }
            Ok(Landing {
                extra, merge, note, ..
            }) => {
                item.state = State::Accepted;
                item.merge = merge;
                item.note = note;
                self.check_extra(&extra)?;
                Ok(item)
            }
        }
    }

    pub fn accept_resolution(&mut self, workspace: &Path, reason: Option<&str>) -> Result<Item> {
        self.recover_under_lock()?;
        let prepared = crate::resolution::load(&self.settings.repo, workspace)?;
        self.accept_prepared_resolution(prepared, reason, false)
    }

    fn resolution_plan(
        &mut self,
        prepared: &crate::resolution::Prepared,
    ) -> Result<(ChannelSnapshot, Item)> {
        let main = self.pijul.snapshot(&self.settings.main)?;
        self.refresh_configuration(&main)?;
        if prepared.main != self.settings.main
            || prepared.inbox != self.settings.inbox
            || prepared.binding.main.state != main.state
            || prepared.base.len() != main.hashes.len()
            || prepared.base.iter().any(|hash| !main.hashes.contains(hash))
        {
            bail!(
                "Main changed after resolution preparation. Prepare a new workspace before acceptance."
            );
        }
        if prepared.configuration != *self.configuration {
            bail!("Effective review settings changed after preparation. Prepare a new workspace.");
        }
        let policy = self
            .pijul
            .read_file(&self.settings.main, &self.settings.policy)?;
        let binding = ReviewBinding::new(
            &prepared.candidates,
            &self.settings.policy,
            policy.as_deref(),
            &self.settings.main,
            &main,
        );
        if serde_json::to_value(&binding)? != serde_json::to_value(&prepared.binding)? {
            bail!("The trusted policy or review binding changed after preparation.");
        }
        let primary = prepared
            .candidates
            .last()
            .context("The resolution has no candidate")?;
        let item = Item::from(self.find_entry(primary, false)?);
        let inbox = self.pijul.log(&self.settings.inbox)?;
        if self.with_conflicting_dependencies(primary, &main.hashes, &inbox)? != prepared.candidates
        {
            bail!(
                "The permitted candidate set changed after preparation. Prepare a new workspace."
            );
        }
        self.require_current_main(&main)?;
        Ok((main, item))
    }

    fn accept_prepared_resolution(
        &mut self,
        prepared: crate::resolution::Prepared,
        reason: Option<&str>,
        verification_only: bool,
    ) -> Result<Item> {
        let (main, mut item) = self.resolution_plan(&prepared)?;
        let primary = prepared
            .candidates
            .last()
            .context("The resolution has no candidate")?;
        let user = env::var("USER").unwrap_or_else(|_| "a human".into());
        let reason = reason
            .filter(|reason| !reason.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{user} accepted the prepared human resolution."));
        self.require_current_main(&main)?;
        let private = if verification_only {
            Some(crate::resolution::copy_workspace(&prepared)?)
        } else {
            None
        };
        let completed = if let Some(private) = &private {
            crate::resolution::record_private(&prepared, &private.pijul, &self.signer, &reason)?
        } else {
            crate::resolution::record(&prepared, &self.signer, &reason)?
        };
        self.require_current_main(&main)?;
        let entries: HashMap<_, _> = completed
            .pijul
            .review_metadata(&self.settings.main)?
            .into_iter()
            .map(|entry| (entry.hash.clone(), entry))
            .collect();
        let mut findings = Vec::new();
        let provenance = self.decision_provenance()?;
        let records = completed
            .hashes
            .iter()
            .map(|hash| -> Result<Record> {
                let entry = entries
                    .get(hash)
                    .context("The resolution lacks native change metadata")?;
                for (path, text) in [
                    ("[change.message]", entry.message.as_str()),
                    ("[change.timestamp]", entry.timestamp.as_str()),
                ] {
                    findings.extend(crate::secrets::scan_text(path, text.as_bytes()));
                }
                for author in &entry.authors {
                    findings.extend(crate::secrets::scan_text(
                        "[change.author]",
                        author.as_bytes(),
                    ));
                }
                for path in &entry.paths {
                    findings.extend(crate::secrets::scan_text("[change.path]", path.as_bytes()));
                }
                let mut record = Record::new(
                    hash.clone(),
                    entry.message.clone(),
                    "accept",
                    "human",
                    reason.clone(),
                );
                record.provenance = Some(provenance.clone());
                record.user = Some(user.clone());
                record.configuration = Some(Rc::clone(&self.configuration));
                record.resolution = Some(ResolutionAcceptance {
                    id: prepared.id.clone(),
                    main_state: main.state.clone(),
                    candidates: prepared.candidates.clone(),
                });
                Ok(record)
            })
            .collect::<Result<Vec<_>>>()?;
        if !findings.is_empty() {
            let mut refusal = records
                .iter()
                .find(|record| record.hash == *primary)
                .cloned()
                .context("The resolution audit lacks its candidate")?;
            refusal.reject_secrets(findings);
            self.append_under_lock(&refusal)?;
            bail!("{}", refusal.reason);
        }
        for hash in &completed.hashes {
            if !completed.imported.contains(hash) {
                continue;
            }
            let source = completed.pijul.change_file(hash);
            let source = crate::pijul::safe_path(
                &completed.pijul.repo,
                source.strip_prefix(&completed.pijul.repo)?,
            )?;
            let target = self.pijul.change_file(hash);
            let target = crate::pijul::safe_path(
                &self.settings.repo,
                target.strip_prefix(&self.settings.repo)?,
            )?;
            import_native_change(&source, &target)?;
        }
        sync_directory(&self.settings.repo.join(".pijul/changes"))?;
        let landed = match self.land(
            &completed.hashes,
            &main,
            &records,
            Some(ResolutionInput {
                pijul: &completed.pijul,
                imported: &completed.imported,
            }),
            &mut Vec::new(),
        ) {
            Err(error) if error.is::<SecretViolation>() => {
                let SecretViolation(findings) = error.downcast::<SecretViolation>()?;
                let mut refusal = records
                    .iter()
                    .find(|record| record.hash == *primary)
                    .cloned()
                    .context("The resolution audit lacks its candidate")?;
                refusal.reject_secrets(findings);
                self.append_under_lock(&refusal)?;
                bail!("{}", refusal.reason);
            }
            result => result?,
        };
        self.check_extra(&landed.extra)?;
        item.state = State::Accepted;
        item.decided = true;
        item.reason = reason;
        item.note = landed.note;
        item.merge = landed.merge;
        Ok(item)
    }

    fn with_conflicting_dependencies(
        &mut self,
        hash: &str,
        main: &HashSet<String>,
        inbox: &[LogEntry],
    ) -> Result<Vec<String>> {
        let records = self.ledger.latest()?;
        let mut needed = HashSet::new();
        // A resolution can reference a conflict without a direct dependency.
        let mut todo: Vec<_> = change::related_changes(&self.change_text(hash)?)
            .into_iter()
            .filter(|hash| !main.contains(hash))
            .collect();
        while let Some(dependency) = todo.pop() {
            if needed.insert(dependency.clone()) {
                todo.extend(
                    change::related_changes(&self.change_text(&dependency)?)
                        .into_iter()
                        .filter(|hash| !main.contains(hash)),
                );
            }
        }
        let mut blocking: Vec<_> = needed
            .iter()
            .filter(|hash| !records.get(*hash).is_some_and(|record| record.conflict))
            .collect();
        blocking.sort_unstable();
        if !blocking.is_empty() {
            bail!(
                "Accept these dependencies first: {}",
                blocking
                    .iter()
                    .map(|h| short(h))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let mut hashes: Vec<_> = inbox
            .iter()
            .filter(|entry| needed.contains(&entry.hash))
            .map(|entry| entry.hash.clone())
            .collect();
        hashes.push(hash.into());
        Ok(hashes)
    }

    fn selection_plan(
        &mut self,
        selection: &Selection,
        inbox: &[LogEntry],
        main: &HashSet<String>,
        records: &HashMap<String, Record>,
    ) -> Result<SelectionPlan> {
        let mut chosen = vec![false; inbox.len()];
        for prefix in &selection.changes {
            if prefix.is_empty() {
                bail!("Give a nonempty change prefix.");
            }
            let mut matches = inbox.iter().enumerate().filter(|(_, entry)| {
                entry
                    .hash
                    .get(..prefix.len())
                    .is_some_and(|part| part.eq_ignore_ascii_case(prefix))
            });
            let (index, entry) = matches
                .next()
                .context("A selected change is not in inbox.")?;
            if matches.next().is_some() {
                bail!("A selected change prefix is ambiguous.");
            }
            if main.contains(&entry.hash) {
                bail!("A selected change is already in main.");
            }
            chosen[index] = true;
        }
        let positions: HashMap<_, _> =
            if !selection.authors.is_empty() || selection.include_dependencies {
                inbox
                    .iter()
                    .enumerate()
                    .map(|(index, entry)| (entry.hash.as_str(), index))
                    .collect()
            } else {
                HashMap::new()
            };
        if !selection.authors.is_empty() {
            let metadata = self.pijul.review_metadata(&self.settings.inbox)?;
            for author in &selection.authors {
                if author.trim().is_empty() {
                    bail!("Give a nonempty author name.");
                }
                let mut matched = false;
                for entry in &metadata {
                    if !main.contains(&entry.hash)
                        && entry.authors.iter().any(|name| name == author)
                    {
                        let index = positions
                            .get(entry.hash.as_str())
                            .context("Selected author metadata differs from the inbox snapshot.")?;
                        chosen[*index] = true;
                        matched = true;
                    }
                }
                if !matched {
                    bail!("A selected author has no unaccepted inbox change.");
                }
            }
        }
        let mut added = Vec::new();
        if selection.include_dependencies {
            let mut scanned = vec![false; inbox.len()];
            let mut pending: Vec<_> = chosen
                .iter()
                .enumerate()
                .filter_map(|(index, selected)| selected.then_some(index))
                .collect();
            while let Some(index) = pending.pop() {
                if scanned[index] {
                    continue;
                }
                scanned[index] = true;
                if records.contains_key(&inbox[index].hash) {
                    continue;
                }
                for dependency in change::dependencies(&self.change_text(&inbox[index].hash)?) {
                    if main.contains(&dependency) {
                        continue;
                    }
                    let dependency_index = *positions
                        .get(dependency.as_str())
                        .context("A selected prerequisite is absent from inbox.")?;
                    if !chosen[dependency_index] {
                        chosen[dependency_index] = true;
                        added.push(dependency_index);
                    }
                    pending.push(dependency_index);
                }
            }
        }
        added.sort_unstable();
        let report = SelectionReport {
            requested_changes: selection.changes.clone(),
            requested_authors: selection.authors.clone(),
            include_dependencies: selection.include_dependencies,
            selected: inbox
                .iter()
                .zip(&chosen)
                .filter(|(_, selected)| **selected)
                .map(|(entry, _)| entry.hash.clone())
                .collect(),
            added_dependencies: added
                .into_iter()
                .map(|index| inbox[index].hash.clone())
                .collect(),
        };
        Ok(SelectionPlan { chosen, report })
    }

    fn walk(
        &mut self,
        decide: bool,
        selection: &Selection,
        mut report: impl FnMut(&Item),
    ) -> Result<(Vec<Item>, Option<SelectionReport>)> {
        if selection.include_dependencies && !selection.targeted() {
            bail!("Dependency inclusion needs an explicit change or author selection.");
        }
        let mut main = self.pijul.hashes(&self.settings.main)?;
        let records = self.ledger.latest()?;
        let inbox = self.pijul.log(&self.settings.inbox)?;
        let plan = if selection.targeted() {
            Some(self.selection_plan(selection, &inbox, &main, &records)?)
        } else {
            None
        };
        let mut states = HashMap::new();
        let mut items = Vec::new();
        let mut chunk: Vec<(Item, Rc<str>)> = Vec::new();
        for (index, entry) in inbox.into_iter().enumerate() {
            if main.contains(&entry.hash) {
                continue;
            }
            let selected = plan.as_ref().is_none_or(|plan| plan.chosen[index]);
            let mut item = Item::from(entry);
            if let Some(record) = records.get(&item.hash) {
                item.state = State::from_decision(&record.decision);
                item.reason = record.reason.clone();
                if record.message != item.message {
                    item.message.clone_from(&record.message);
                }
                if !record.findings.is_empty() {
                    item.paths.clear();
                }
            } else {
                if !chunk.is_empty() {
                    self.land_chunk(&mut chunk, &mut main, &mut report)?;
                    for (item, _) in chunk.drain(..) {
                        states.insert(item.hash.clone(), item.state);
                        items.push(item);
                    }
                }
                let text = self.change_text(&item.hash)?;
                item.needs = change::dependencies(&text)
                    .into_iter()
                    .filter(|h| !main.contains(h))
                    .map(|hash| {
                        let state = states.get(&hash).copied().unwrap_or(State::Unknown);
                        (hash, state)
                    })
                    .collect();
                if !item.needs.is_empty() {
                    item.state = if item.needs.iter().any(|(_, state)| state.stuck()) {
                        State::Blocked
                    } else {
                        State::Waiting
                    };
                    if selected && selection.targeted() {
                        item.reason = if item.state == State::Blocked {
                            "A prerequisite has a blocked or terminal state. Decide it explicitly before this change.".into()
                        } else {
                            "A prerequisite is outside the ready selection. Select it explicitly or use --include-dependencies.".into()
                        };
                    }
                } else if decide && selected {
                    // A contiguous ready set lands under one conditional transaction.
                    chunk.push((item, Rc::clone(&text)));
                    continue;
                }
            }
            states.insert(item.hash.clone(), item.state);
            if selected {
                items.push(item);
            }
        }
        if !chunk.is_empty() {
            self.land_chunk(&mut chunk, &mut main, &mut report)?;
            for (item, _) in chunk.drain(..) {
                states.insert(item.hash.clone(), item.state);
                items.push(item);
            }
        }
        Ok((items, plan.map(|plan| plan.report)))
    }

    /// Decide each ready change against one snapshot, then land the accepted set once.
    fn land_chunk(
        &mut self,
        chunk: &mut [(Item, Rc<str>)],
        main: &mut HashSet<String>,
        report: &mut impl FnMut(&Item),
    ) -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        let reviewed = self.pijul.snapshot(&self.settings.main)?;
        *main = reviewed.hashes.clone();
        self.refresh_configuration(&reviewed)?;
        let mut decided = Vec::with_capacity(chunk.len());
        for (item, text) in chunk.iter_mut() {
            decided.push(self.decide_ready(item, text, &reviewed, None)?);
        }
        let accepted: Vec<usize> = decided
            .iter()
            .enumerate()
            .filter(|(_, record)| record.decision == "accept")
            .map(|(index, _)| index)
            .collect();
        if accepted.is_empty() {
            for record in &decided {
                self.append_under_lock(record)?;
            }
            for ((item, _), record) in chunk.iter_mut().zip(&decided) {
                self.apply_decision(item, record);
                report(item);
            }
            return Ok(());
        }
        let hashes: Vec<String> = accepted
            .iter()
            .map(|&index| chunk[index].0.hash.clone())
            .collect();
        let records: Vec<Record> = accepted
            .iter()
            .map(|&index| decided[index].clone())
            .collect();
        let mut requests = Vec::new();
        match self.land(&hashes, &reviewed, &records, None, &mut requests) {
            Ok(Landing {
                main: after,
                extra,
                merge,
                note,
            }) => {
                *main = after;
                for record in &decided {
                    if record.decision != "accept" {
                        self.append_under_lock(record)?;
                    }
                }
                for ((item, _), record) in chunk.iter_mut().zip(&decided) {
                    if record.decision == "accept" {
                        item.state = State::Accepted;
                        item.merge.clone_from(&merge);
                        item.note.clone_from(&note);
                        item.decided = true;
                    } else {
                        self.apply_decision(item, record);
                    }
                    report(item);
                }
                self.check_extra(&extra)
            }
            Err(error) if error.is::<SecretViolation>() || error.is::<Unmerged>() => {
                // The set refused as a whole. Decide each accepted change alone.
                for (index, record) in decided.iter().enumerate() {
                    if record.decision != "accept" {
                        self.append_under_lock(record)?;
                    } else {
                        self.land_one(&mut chunk[index].0, record.clone(), &reviewed, main)?;
                    }
                }
                for (item, _) in chunk.iter_mut() {
                    report(item);
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Land one decided change and record the result of a refusal or a conflict.
    fn land_one(
        &mut self,
        item: &mut Item,
        mut record: Record,
        reviewed: &ChannelSnapshot,
        main: &mut HashSet<String>,
    ) -> Result<()> {
        let mut merge_requests = Vec::new();
        match self.land(
            std::slice::from_ref(&item.hash),
            reviewed,
            std::slice::from_ref(&record),
            None,
            &mut merge_requests,
        ) {
            Err(error) if error.is::<SecretViolation>() => {
                let SecretViolation(findings) = error.downcast::<SecretViolation>()?;
                record.reject_secrets(findings);
            }
            Err(error) => {
                let invalid_reply = error.is::<InvalidModelReply>();
                let problem = error.downcast::<Unmerged>()?;
                record.decision = "escalate".into();
                record.by = "gate".into();
                if invalid_reply {
                    record.execution_error = Some("invalid-model-reply".into());
                }
                record.conflict = true;
                record.reason = format!(
                    "The change conflicts with {}, and patchgate did not merge it. {problem} To merge it by hand, edit the conflict in {}, record the result, and run: patchgate accept <hash of the result>",
                    self.settings.main, self.settings.inbox
                );
            }
            Ok(Landing {
                main: after,
                extra,
                merge,
                note,
            }) => {
                *main = after;
                item.state = State::Accepted;
                item.merge = merge;
                item.note = note;
                item.decided = true;
                return self.check_extra(&extra);
            }
        }
        if !merge_requests.is_empty() {
            record
                .provenance
                .as_mut()
                .context("Decision provenance is absent")?
                .requests
                .extend(merge_requests);
        }
        self.append_under_lock(&record)?;
        self.apply_decision(item, &record);
        Ok(())
    }

    fn apply_decision(&self, item: &mut Item, record: &Record) {
        item.state = State::from_decision(&record.decision);
        if !record.findings.is_empty() {
            item.paths.clear();
        }
        item.message.clone_from(&record.message);
        item.reason.clone_from(&record.reason);
        item.decided = true;
    }

    fn decide_ready(
        &mut self,
        item: &mut Item,
        text: &str,
        reviewed: &ChannelSnapshot,
        reconsideration: Option<Reconsideration>,
    ) -> Result<Record> {
        let case_id = self.capture_record_case(&item.hash, reviewed)?;
        let mut record = self.decide(item, text, reviewed)?;
        if reconsideration.is_some() && record.execution_error.is_some() {
            return Err(InvalidModelReply.into());
        }
        record.case_id = case_id;
        record.reconsideration = reconsideration;
        self.require_current_main(reviewed)?;
        Ok(record)
    }

    fn decide_and_land(
        &mut self,
        item: &mut Item,
        text: &str,
        main: &mut HashSet<String>,
        reconsideration: Option<Reconsideration>,
    ) -> Result<()> {
        let reviewed = self.pijul.snapshot(&self.settings.main)?;
        *main = reviewed.hashes.clone();
        self.refresh_configuration(&reviewed)?;
        let record = self.decide_ready(item, text, &reviewed, reconsideration)?;
        if record.decision != "accept" {
            self.append_under_lock(&record)?;
            self.apply_decision(item, &record);
            return Ok(());
        }
        self.land_one(item, record, &reviewed, main)
    }

    fn decide(&mut self, item: &Item, text: &str, main: &ChannelSnapshot) -> Result<Record> {
        let mut record = Record::new(
            item.hash.clone(),
            item.message.clone(),
            "escalate",
            "gate",
            String::new(),
        );
        record.provenance = Some(self.decision_provenance()?);
        record.configuration = Some(Rc::clone(&self.configuration));
        let paths = match self
            .pijul
            .touched_paths(&self.settings.inbox, &item.paths, text)
            .and_then(|paths| {
                self.pijul.check_paths(&paths)?;
                Ok(paths)
            }) {
            Ok(paths) => paths,
            Err(error) => {
                record.reason = format!("Unsafe repository path. A human must review it. {error}");
                return Ok(record);
            }
        };
        if change::is_root_change(text) {
            record.decision = "accept".into();
            record.reason = "The Pijul root change has no content.".into();
            return Ok(record);
        }
        let touched: Vec<_> = paths
            .iter()
            .filter(|path| self.is_protected(path))
            .map(String::as_str)
            .collect();
        if !touched.is_empty() {
            record.reason = format!(
                "The change touches protected paths ({}). A human must accept or reject it.",
                touched.join(", ")
            );
            return Ok(record);
        }
        let candidate =
            match self
                .pijul
                .review_change(&self.settings.inbox, &item.hash, text, &paths)
            {
                Ok(candidate) => candidate,
                Err(error) => {
                    record.reason = format!(
                        "The change has no complete text context. A human must review it. {error}"
                    );
                    return Ok(record);
                }
            };
        let policy = self
            .pijul
            .read_file(&self.settings.main, &self.settings.policy)?
            .ok_or_else(|| anyhow!(
                "{} has no {}, so the model has no policy. Accept the change that adds {}: patchgate accept <hash>",
                self.settings.main, self.settings.policy, self.settings.policy
            ))?;
        let mut findings = crate::secrets::scan_change(&candidate);
        findings.extend(crate::secrets::scan_text(
            "[trusted.policy]",
            policy.as_bytes(),
        ));
        if !findings.is_empty() {
            record.reject_secrets(findings);
            return Ok(record);
        }
        let reviewed: BTreeSet<String> = candidate
            .context
            .files
            .iter()
            .map(|file| file.path.as_str())
            .chain(
                candidate
                    .metadata_context
                    .iter()
                    .map(|entry| entry.path.as_str()),
            )
            .filter_map(|path| {
                crate::pijul::normalize_path(Path::new(path))
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned())
            })
            .collect();
        if !reviewed.is_empty()
            && reviewed
                .iter()
                .all(|path| self.documentation.is_match(path))
        {
            record.decision = "accept".into();
            record.by = "gate".into();
            record.reason = format!(
                "The change touches only documentation paths ({}). Deterministic secret checks and the trusted Nix checks apply, and the model does not review it.",
                reviewed.iter().cloned().collect::<Vec<_>>().join(", ")
            );
            return Ok(record);
        }
        let binding = ReviewBinding::new(
            std::slice::from_ref(&item.hash),
            &self.settings.policy,
            Some(&policy),
            &self.settings.main,
            main,
        );
        let input = review::input(&candidate, &binding)?;
        let length = input.get().chars().count();
        if length > self.settings.max_change_chars {
            record.reason = format!(
                "The structured change context has {length} characters. The model limit is {}. A human must review it.",
                self.settings.max_change_chars
            );
            return Ok(record);
        }
        self.require_current_main(main)?;
        if let Some(cached) = self.cached_verdict(&binding, &item.hash)? {
            record.decision = cached.decision;
            record.summary = cached.summary;
            record.reason = cached.reason;
            record.by = "model".into();
            record.model = Some(cached.model);
            record.review = Some(binding);
            record.reused = true;
            record
                .provenance
                .as_mut()
                .context("Decision provenance is absent")?
                .requests
                .push(cached.request);
            return Ok(record);
        }
        let response = self.model.review(&policy, &input)?;
        let evidence = response.evidence.clone();
        record
            .provenance
            .as_mut()
            .context("Decision provenance is absent")?
            .requests
            .push(response.evidence);
        record.model = Some(self.settings.model.clone());
        match response.value {
            Some(verdict) => {
                if let Err(error) = self.remember_verdict(&binding, &item.hash, &verdict, evidence)
                {
                    eprintln!("patchgate: the decision cache did not record this verdict: {error}");
                }
                record.decision = verdict.decision;
                record.summary = verdict.summary;
                record.reason = verdict.reason;
                record.by = "model".into();
                record.review = Some(binding);
            }
            None => {
                record.execution_error = Some("invalid-model-reply".into());
                record.reason = format!(
                    "The reply of {} is not a valid verdict.",
                    self.settings.model
                )
            }
        }
        Ok(record)
    }

    fn cached_verdict(
        &self,
        binding: &ReviewBinding,
        candidate: &str,
    ) -> Result<Option<crate::decision::Entry>> {
        let key = crate::decision::key(
            binding,
            candidate,
            &self.settings.model,
            self.settings.model_api.as_str(),
            self.settings.model_revision.as_deref(),
        )?;
        self.decisions.load(
            &key,
            binding,
            candidate,
            &self.settings.model,
            self.settings.model_api.as_str(),
            self.settings.model_revision.as_deref(),
        )
    }

    fn remember_verdict(
        &self,
        binding: &ReviewBinding,
        candidate: &str,
        verdict: &crate::model::Verdict,
        request: crate::provenance::RequestEvidence,
    ) -> Result<()> {
        let key = crate::decision::key(
            binding,
            candidate,
            &self.settings.model,
            self.settings.model_api.as_str(),
            self.settings.model_revision.as_deref(),
        )?;
        let entry = crate::decision::Entry {
            schema_version: 1,
            key,
            candidate: candidate.into(),
            policy_path: binding.policy.as_ref().map(|policy| policy.path.clone()),
            policy_sha256: binding.policy.as_ref().map(|policy| policy.sha256.clone()),
            main_channel: binding.main.channel.clone(),
            main_state: binding.main.state.clone(),
            model: self.settings.model.clone(),
            api: self.settings.model_api.as_str().into(),
            revision: self.settings.model_revision.clone(),
            decision: verdict.decision.clone(),
            summary: verdict.summary.clone(),
            reason: verdict.reason.clone(),
            request,
        };
        self.decisions.store(&entry)
    }

    fn append_under_lock(&self, record: &Record) -> Result<()> {
        let _lock = self.ledger.lock()?;
        self.ledger.append(record)
    }

    fn recover_under_lock(&self) -> Result<()> {
        let _lock = self.ledger.lock()?;
        self.recover()
    }

    fn land(
        &mut self,
        hashes: &[String],
        main: &ChannelSnapshot,
        records: &[Record],
        resolution: Option<ResolutionInput<'_>>,
        merge_requests: &mut Vec<crate::provenance::RequestEvidence>,
    ) -> Result<Landing> {
        let entries = if let Some(input) = &resolution {
            input.pijul.log(&self.settings.main)?
        } else {
            self.pijul.log(&self.settings.inbox)?
        };
        let log_paths: HashMap<_, _> = entries
            .into_iter()
            .map(|entry| (entry.hash, entry.paths))
            .collect();
        let mut paths = BTreeSet::new();
        for hash in hashes {
            let text = self.change_text(hash)?;
            let candidate_paths = if let Some(input) = &resolution {
                input.pijul.touched_paths(
                    &self.settings.main,
                    log_paths.get(hash).map(Vec::as_slice).unwrap_or_default(),
                    &text,
                )
            } else {
                self.pijul.touched_paths(
                    &self.settings.inbox,
                    log_paths.get(hash).map(Vec::as_slice).unwrap_or_default(),
                    &text,
                )
            };
            paths.extend(candidate_paths.map_err(|error| Unmerged(error.to_string()))?);
        }
        self.pijul
            .check_paths(&paths)
            .map_err(|error| Unmerged(error.to_string()))?;
        let directory = tempfile::Builder::new().prefix("patchgate-").tempdir()?;
        let path = directory.path().join("main");
        self.pijul.run([
            Path::new("clone"),
            Path::new("--channel"),
            Path::new(&self.settings.main),
            &self.settings.repo,
            &path,
        ])?;
        let scratch = Pijul::new(path);
        if scratch.snapshot(&self.settings.main)? != *main {
            return Err(stale(
                "The main channel changed before candidate verification. Run patchgate review again.".into(),
            ));
        }
        let checks = verify::Plan::load(&scratch, &self.settings.main)?;
        let mut reported = Vec::new();
        for hash in hashes {
            let (_, stderr) = scratch.call([Path::new("apply"), &self.pijul.change_file(hash)])?;
            reported.extend(change::conflict_report(&stderr));
        }
        let staged = scratch.hashes(&self.settings.main)?;
        let planned: HashSet<_> = hashes.iter().map(String::as_str).collect();
        if main.hashes.iter().any(|hash| !staged.contains(hash))
            || hashes.iter().any(|hash| !staged.contains(hash))
            || staged
                .iter()
                .any(|hash| !main.hashes.contains(hash) && !planned.contains(hash.as_str()))
        {
            bail!("The staged source differs from the exact acceptance plan.");
        }
        let mut remaining = scratch.conflicts()?;
        paths.extend(
            reported
                .iter()
                .chain(&remaining)
                .filter(|r| !r.path.is_empty())
                .map(|r| r.path.clone()),
        );
        scratch
            .check_paths(&paths)
            .map_err(|error| Unmerged(error.to_string()))?;
        let files = Self::conflicted_files(&scratch, &paths)?;
        let merge = if remaining.is_empty() && files.is_empty() {
            None
        } else {
            if resolution.is_some() {
                return Err(Unmerged(
                    "Complete the human resolution before acceptance. Conflicts remain.".into(),
                )
                .into());
            }
            remaining.extend(reported.into_iter().filter(|r| files.contains_key(&r.path)));
            Some(self.merge(&scratch, hashes, main, &remaining, &files, merge_requests)?)
        };
        // The native transaction checks main before it applies this candidate.
        let mut args: Vec<_> = hashes
            .iter()
            .map(|hash| {
                if resolution
                    .as_ref()
                    .is_some_and(|input| input.imported.contains(hash))
                {
                    self.pijul.change_file(hash).into_os_string()
                } else {
                    std::ffi::OsString::from(hash)
                }
            })
            .collect();
        let mut expected: HashSet<&str> = hashes.iter().map(String::as_str).collect();
        if let Some(merge) = &merge {
            args.push(scratch.change_file(&merge.hash).into_os_string());
            expected.insert(&merge.hash);
        }
        let mut audit = records.to_vec();
        if let Some(merge) = &merge {
            for record in &mut audit {
                record.merge = Some(merge.hash.clone());
            }
            audit.push(merge.clone());
        }
        for record in &mut audit {
            record.configuration = Some(Rc::clone(&self.configuration));
        }
        let source = directory.path().join("candidate-source");
        scratch.export_source(&self.settings.main, &source)?;
        let findings = crate::secrets::scan_tree(&source)?;
        if !findings.is_empty() {
            return Err(SecretViolation(findings).into());
        }
        if let Some(checks) = checks {
            self.require_current_main(main)?;
            let cache = self.ledger.verification_directory()?;
            let verification = Rc::new(checks.run(
                &source,
                hashes,
                merge.as_ref().map(|record| record.hash.as_str()),
                review::MainBinding {
                    channel: self.settings.main.clone(),
                    state: main.state.clone(),
                },
                self.settings.check_timeout,
                &self.settings.interrupted,
                Some(&cache),
            )?);
            for record in &mut audit {
                record.verification = Some(Rc::clone(&verification));
                record
                    .provenance
                    .as_mut()
                    .context("Decision provenance is absent")?
                    .verifiers
                    .nix = verification.observed_nix_version().map(str::to_owned);
            }
        }
        let _journal = self.ledger.lock()?;
        self.pijul
            .check_paths(&paths)
            .map_err(|error| Unmerged(error.to_string()))?;
        self.require_current_main(main)?;
        if self.settings.interrupted.load(Ordering::Relaxed) {
            bail!("Interrupted before acceptance");
        }
        let intent = self
            .ledger
            .prepare(&self.settings.main, &self.settings.inbox, audit)?;
        if !self
            .pijul
            .apply_if_current(&self.settings.main, main.state.as_deref(), &args)?
        {
            self.ledger.finish()?;
            return Err(stale(format!(
                "Channel {} changed before application. Run patchgate review again.",
                self.settings.main
            )));
        }
        let after = self.pijul.hashes(&self.settings.main)?;
        let mut missing: Vec<_> = expected
            .iter()
            .filter(|hash| !after.contains(**hash))
            .copied()
            .collect();
        missing.sort_unstable();
        if !missing.is_empty() {
            bail!(
                "pijul did not apply {} to {}.",
                missing
                    .into_iter()
                    .map(short)
                    .collect::<Vec<_>>()
                    .join(", "),
                self.settings.main
            );
        }
        let extra = after
            .iter()
            .filter(|hash| !main.hashes.contains(*hash) && !expected.contains(hash.as_str()))
            .cloned()
            .collect();
        self.ledger.reconcile(&intent, true)?;
        let note = intent
            .records
            .iter()
            .filter(|record| record.decision == "merge" || record.resolution.is_some())
            .map(|record| self.mirror_merge(record, &self.settings.inbox))
            .filter(|note| !note.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        self.ledger.finish()?;
        Ok(Landing {
            main: after,
            extra,
            merge,
            note,
        })
    }

    fn require_current_main(&self, expected: &ChannelSnapshot) -> Result<()> {
        if self.pijul.snapshot(&self.settings.main)? != *expected {
            return Err(stale(format!(
                "Channel {} changed during review. Run patchgate review again before another decision.",
                self.settings.main
            )));
        }
        Ok(())
    }

    fn conflicted_files(
        scratch: &Pijul,
        paths: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, ConflictFile>> {
        let mut found = BTreeMap::new();
        for path in paths {
            let target = crate::pijul::safe_path(&scratch.repo, Path::new(path))
                .map_err(|error| Unmerged(error.to_string()))?;
            if !target.is_file() {
                continue;
            }
            let entries: Vec<serde_json::Value> = scratch
                .run(["credit", "--output-format", "json", "--", path])
                .and_then(|output| serde_json::from_str(&output).map_err(Into::into))
                .map_err(|error| {
                    Unmerged(format!(
                        "patchgate cannot read the lines of {path}: {error}"
                    ))
                })?;
            let file = change::split_conflicts(&entries)?;
            if !file.regions.is_empty() {
                found.insert(path.clone(), file);
            }
        }
        Ok(found)
    }

    fn merge(
        &mut self,
        scratch: &Pijul,
        hashes: &[String],
        main: &ChannelSnapshot,
        report: &[Conflict],
        files: &BTreeMap<String, ConflictFile>,
        requests: &mut Vec<crate::provenance::RequestEvidence>,
    ) -> Result<Record> {
        let other: BTreeSet<_> = report
            .iter()
            .filter(|r| !matches!(r.kind.as_str(), "Order conflict" | "Deletion conflict"))
            .map(|r| {
                if r.path.is_empty() {
                    r.kind.clone()
                } else {
                    format!("{} on {}", r.kind, r.path)
                }
            })
            .collect();
        if !other.is_empty() {
            return Err(Unmerged(format!(
                "The model merges only conflicts between lines, and this is a {}.",
                other.into_iter().collect::<Vec<_>>().join(", ")
            ))
            .into());
        }
        if files.is_empty() {
            return Err(Unmerged(format!(
                "patchgate cannot find the conflicting lines ({}).",
                report
                    .iter()
                    .map(|r| r.kind.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .into());
        }
        let kinds: HashMap<_, _> = report
            .iter()
            .filter(|r| !r.path.is_empty())
            .map(|r| ((r.path.as_str(), r.line), r.kind.as_str()))
            .collect();
        let messages: HashMap<_, _> = self
            .pijul
            .log(&self.settings.main)?
            .into_iter()
            .chain(self.pijul.log(&self.settings.inbox)?)
            .map(|entry| (entry.hash, entry.message))
            .collect();
        let mut merged = BTreeMap::new();
        let mut reasons = Vec::new();
        let mut sides = Vec::new();
        let mut seen_sides = HashSet::new();
        for (path, file) in files {
            let mut texts = Vec::new();
            for (index, region) in file.regions.iter().enumerate() {
                let kind = kinds.get(&(path.as_str(), region.line)).copied().unwrap_or(
                    if region.sides.len() > 1 {
                        "Order conflict"
                    } else {
                        "Deletion conflict"
                    },
                );
                let mut involved: Vec<_> = region
                    .sides
                    .iter()
                    .flat_map(|side| side.hashes.iter().cloned())
                    .collect();
                if region.sides.len() == 1 {
                    involved.extend(self.concurrent(path, hashes)?);
                }
                for hash in hashes {
                    if !change::file_hunks(&self.change_text(hash)?, path).is_empty() {
                        involved.push(hash.clone());
                    }
                }
                let mut seen = HashSet::new();
                involved.retain(|hash| seen.insert(hash.clone()));
                for hash in &involved {
                    if seen_sides.insert(hash.clone()) {
                        sides.push(hash.clone());
                    }
                }
                let mut hunks = Hunks::new();
                for hash in &involved {
                    hunks.insert(
                        hash.clone(),
                        change::file_hunks(&self.change_text(hash)?, path),
                    );
                }
                let choices = change::merge_choices(kind, &region.sides, &hunks)
                    .map_err(|problem| Unmerged(format!("{path}: {problem}")))?;
                let prompt = self.merge_prompt(
                    path, kind, region, file, index, &involved, hashes, &messages, &hunks, &choices,
                );
                let length = prompt.chars().count();
                if length > self.settings.max_change_chars {
                    return Err(Unmerged(format!(
                        "The conflict in {path} is too long for the model ({length} characters)."
                    ))
                    .into());
                }
                let findings = crate::secrets::scan_text("[merge.context]", prompt.as_bytes());
                if !findings.is_empty() {
                    return Err(SecretViolation(findings).into());
                }
                let mut labels: Vec<_> = choices.iter().map(|(label, _)| label.as_str()).collect();
                labels.push("escalate");
                let response = self.model.merge(&prompt, &labels)?;
                requests.push(response.evidence);
                let result = response.value.ok_or_else(|| {
                    anyhow::Error::new(InvalidModelReply).context(Unmerged(format!(
                        "The reply of {} for {path} is not one of the choices.",
                        self.settings.model
                    )))
                })?;
                if result.choice == "escalate" {
                    return Err(Unmerged(format!(
                        "{} escalated the conflict in {path}: {}",
                        self.settings.model, result.reason
                    ))
                    .into());
                }
                let text = choices
                    .into_iter()
                    .find(|(label, _)| *label == result.choice)
                    .ok_or_else(|| {
                        Unmerged(format!(
                            "The reply of {} for {path} is not one of the choices.",
                            self.settings.model
                        ))
                    })?
                    .1;
                texts.push(text);
                reasons.push(format!("{path}: {}. {}", result.choice, result.reason));
            }
            let length = file
                .pieces
                .iter()
                .map(|piece| match piece {
                    Piece::Text(text) => text.len(),
                    Piece::Region(index) => texts[*index].len(),
                })
                .sum();
            let mut text = String::with_capacity(length);
            for piece in &file.pieces {
                text.push_str(match piece {
                    Piece::Text(text) => text,
                    Piece::Region(index) => &texts[*index],
                });
            }
            merged.insert(path.clone(), text);
        }
        for (path, text) in &merged {
            let target = crate::pijul::safe_path(&scratch.repo, Path::new(path))
                .map_err(|error| Unmerged(error.to_string()))?;
            fs::write(target, text)?;
        }
        let mut seen_names = HashSet::new();
        let names: Vec<_> = sides
            .iter()
            .chain(hashes)
            .map(|hash| {
                messages
                    .get(hash)
                    .filter(|m| !m.is_empty())
                    .map(String::as_str)
                    .unwrap_or_else(|| short(hash))
            })
            .filter(|name| seen_names.insert(*name))
            .map(|name| format!("\"{}\"", name.chars().take(60).collect::<String>()))
            .collect();
        let message = format!("Merge the conflict between {}", names.join(" and "));
        let env = self.signer.environment()?;
        let (output, _) = scratch.call_with_env(
            ["record", "-a", "-m", &message, "--author", "patchgate"],
            &env.vars,
        )?;
        drop(env);
        let hash = output
            .split_whitespace()
            .next_back()
            .ok_or_else(|| anyhow!("pijul record returned no merge hash"))?;
        let paths = merged.keys().cloned().collect();
        if !scratch.conflicts()?.is_empty() || !Self::conflicted_files(scratch, &paths)?.is_empty()
        {
            return Err(
                Unmerged("The merge of the model does not remove the conflict.".into()).into(),
            );
        }
        let mut record = Record::new(hash.into(), message, "merge", "model", reasons.join(" "));
        let mut provenance = self.decision_provenance()?;
        provenance.requests.clone_from(requests);
        record.provenance = Some(provenance);
        record.model = Some(self.settings.model.clone());
        let policy = self
            .pijul
            .read_file(&self.settings.main, &self.settings.policy)?;
        record.review = Some(ReviewBinding::new(
            hashes,
            &self.settings.policy,
            policy.as_deref(),
            &self.settings.main,
            main,
        ));
        record.for_hashes = hashes.to_vec();
        record.files = merged.into_keys().collect();
        Ok(record)
    }

    fn concurrent(&mut self, path: &str, hashes: &[String]) -> Result<Vec<String>> {
        let mut known = HashSet::new();
        let mut todo = hashes.to_vec();
        while let Some(hash) = todo.pop() {
            if known.insert(hash.clone()) {
                todo.extend(change::related_changes(&self.change_text(&hash)?));
            }
        }
        Ok(self
            .pijul
            .log(&self.settings.main)?
            .into_iter()
            .rev()
            .filter(|entry| !known.contains(&entry.hash) && entry.paths.iter().any(|p| p == path))
            .take(5)
            .map(|entry| entry.hash)
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    fn merge_prompt(
        &self,
        path: &str,
        kind: &str,
        region: &Region,
        file: &ConflictFile,
        index: usize,
        involved: &[String],
        hashes: &[String],
        messages: &HashMap<String, String>,
        hunks: &Hunks,
        choices: &Choices,
    ) -> String {
        use std::fmt::Write;
        let mut prompt = format!(
            "File: {path}\nKind: {}\n\nWhat each change did in this file:",
            kind.to_lowercase()
        );
        for hash in involved {
            let message = messages.get(hash).map(String::as_str).unwrap_or_default();
            let where_is = if hashes.contains(hash) {
                "under review".to_owned()
            } else {
                format!("already in {}", self.settings.main)
            };
            write!(
                prompt,
                "\n- {} {} ({where_is})",
                &hash[..8],
                serde_json::to_string(message).unwrap()
            )
            .unwrap();
            let mut count = 0;
            for hunk in &hunks[hash] {
                for (sign, group) in [("-", &hunk.removed), ("+", &hunk.added)] {
                    for line in group {
                        if count < change::CONTEXT_LINES * 3 {
                            write!(prompt, "\n    {sign} {line}").unwrap();
                        }
                        count += 1;
                    }
                }
            }
            if count == 0 {
                prompt.push_str("\n    (no lines in this file)");
            }
        }
        let (before, after) = change::context(&file.pieces, index);
        prompt.push_str("\n\nLines before the conflict:\n");
        if before.is_empty() {
            prompt.push_str("(start of file)");
        } else {
            for (index, line) in before.iter().enumerate() {
                if index > 0 {
                    prompt.push('\n');
                }
                prompt.push_str(line);
            }
        }
        prompt.push_str("\n\n");
        for (index, side) in region.sides.iter().enumerate() {
            write!(prompt, "Side {}, from ", index + 1).unwrap();
            if side.hashes.is_empty() {
                prompt.push_str("an unknown change");
            } else {
                for (index, hash) in side.hashes.iter().enumerate() {
                    if index > 0 {
                        prompt.push_str(", ");
                    }
                    let message = messages.get(hash).map(String::as_str).unwrap_or_default();
                    write!(
                        prompt,
                        "{} {}",
                        &hash[..8],
                        serde_json::to_string(message).unwrap()
                    )
                    .unwrap();
                }
            }
            prompt.push_str(":\n");
            let text = side.text.trim_end_matches('\n');
            prompt.push_str(if text.is_empty() { "(no lines)" } else { text });
            prompt.push_str("\n\n");
        }
        prompt.push_str("Lines after the conflict:\n");
        if after.is_empty() {
            prompt.push_str("(end of file)");
        } else {
            for (index, line) in after.iter().enumerate() {
                if index > 0 {
                    prompt.push('\n');
                }
                prompt.push_str(line);
            }
        }
        prompt.push_str("\n\nChoices:");
        for (label, text) in choices {
            write!(
                prompt,
                "\n- {}, which puts these lines in place of the conflict:",
                serde_json::to_string(label).unwrap()
            )
            .unwrap();
            if text.is_empty() {
                prompt.push_str("\n    (no lines)");
            } else {
                for line in text.lines() {
                    write!(prompt, "\n    {line}").unwrap();
                }
            }
        }
        prompt.push_str("\n- \"escalate\": a human decides.");
        prompt
    }

    fn check_extra(&self, extra: &BTreeSet<String>) -> Result<()> {
        if !extra.is_empty() {
            let names = extra
                .iter()
                .map(|hash| short(hash))
                .collect::<Vec<_>>()
                .join(" ");
            bail!(
                "pijul also applied changes that the gate did not review: {names}. Examine them. To remove them, run: pijul unrecord --channel {} {names}",
                self.settings.main
            );
        }
        Ok(())
    }
}

pub fn find_repo(start: &Path) -> Result<PathBuf> {
    let start = start
        .canonicalize()
        .with_context(|| start.display().to_string())?;
    for path in start.ancestors() {
        if path.join(".pijul").is_dir() {
            return Ok(path.to_owned());
        }
    }
    bail!("{} is not in a Pijul repository.", start.display())
}

#[cfg(test)]
mod durability_tests {
    use super::*;

    fn fixture() -> Result<(tempfile::TempDir, Ledger)> {
        let directory = tempfile::tempdir()?;
        fs::create_dir(directory.path().join(".pijul"))?;
        let ledger = Ledger::new(directory.path());
        let _lock = ledger.lock()?;
        Ok((directory, ledger))
    }

    fn records() -> Vec<Record> {
        let mut acceptance = Record::new(
            "CANDIDATE".into(),
            "A candidate".into(),
            "accept",
            "model",
            "The policy permits it.".into(),
        );
        acceptance.model = Some("fixture".into());
        acceptance.merge = Some("MERGE".into());
        let mut merge = Record::new(
            "MERGE".into(),
            "A signed merge".into(),
            "merge",
            "model",
            "Preserve both contributions.".into(),
        );
        merge.model = Some("fixture".into());
        merge.for_hashes = vec!["CANDIDATE".into()];
        merge.files = vec!["file.txt".into()];
        vec![acceptance, merge]
    }

    #[test]
    fn every_partial_acceptance_append_recovers_once() -> Result<()> {
        let (_directory, ledger) = fixture()?;
        ledger.append(&Record::new(
            "OLD".into(),
            "An earlier decision".into(),
            "reject",
            "human",
            "A human rejects it.".into(),
        ))?;
        let prefix = fs::read(&ledger.path)?;
        let intent = ledger.prepare("main", "inbox", records())?;
        let expected = intent.bytes()?;
        for boundary in 0..=expected.len() {
            let mut interrupted = prefix.clone();
            interrupted.extend_from_slice(&expected[..boundary]);
            fs::write(&ledger.path, interrupted)?;
            ledger.reconcile(&intent, true)?;
            let complete = fs::read(&ledger.path)?;
            ledger.reconcile(&intent, true)?;
            assert_eq!(fs::read(&ledger.path)?, complete, "boundary {boundary}");
            let history = ledger.history()?;
            assert_eq!(history.len(), 3, "boundary {boundary}");
            assert_eq!(history[1].merge.as_deref(), Some("MERGE"));
            assert_eq!(history[2].for_hashes, ["CANDIDATE"]);
        }
        ledger.finish()?;
        assert!(ledger.pending()?.is_none());
        Ok(())
    }

    #[test]
    fn prepared_unapplied_intent_creates_no_acceptance() -> Result<()> {
        let (_directory, ledger) = fixture()?;
        let intent = ledger.prepare("main", "inbox", records())?;
        ledger.reconcile(&intent, false)?;
        ledger.finish()?;
        assert!(ledger.history()?.is_empty());
        assert!(!ledger.path.exists());
        Ok(())
    }

    #[test]
    fn unapplied_intent_with_ledger_bytes_is_not_discarded() -> Result<()> {
        let (_directory, ledger) = fixture()?;
        let intent = ledger.prepare("main", "inbox", records())?;
        let partial = &intent.bytes()?[..5];
        fs::write(&ledger.path, partial)?;
        assert!(ledger.reconcile(&intent, false).is_err());
        assert_eq!(fs::read(&ledger.path)?, partial);
        assert!(ledger.pending()?.is_some());
        Ok(())
    }

    #[test]
    fn unrelated_tail_corruption_is_preserved() -> Result<()> {
        let (_directory, ledger) = fixture()?;
        let intent = ledger.prepare("main", "inbox", records())?;
        for damaged in [
            b"{not the transaction".to_vec(),
            [intent.bytes()?, b"unrelated\n".to_vec()].concat(),
        ] {
            fs::write(&ledger.path, &damaged)?;
            assert!(ledger.reconcile(&intent, true).is_err());
            assert_eq!(fs::read(&ledger.path)?, damaged);
        }
        assert!(ledger.pending()?.is_some());
        Ok(())
    }

    #[test]
    fn unrelated_prefix_corruption_is_preserved() -> Result<()> {
        let (_directory, ledger) = fixture()?;
        ledger.append(&Record::new(
            "OLD".into(),
            "Old".into(),
            "reject",
            "human",
            "No.".into(),
        ))?;
        let intent = ledger.prepare("main", "inbox", records())?;
        let mut damaged = fs::read(&ledger.path)?;
        damaged[0] = b'!';
        damaged.extend_from_slice(&intent.bytes()?[..7]);
        fs::write(&ledger.path, &damaged)?;
        assert!(ledger.reconcile(&intent, true).is_err());
        assert_eq!(fs::read(&ledger.path)?, damaged);
        Ok(())
    }

    #[test]
    fn missing_or_short_ledger_boundary_is_an_error() -> Result<()> {
        let (_directory, ledger) = fixture()?;
        ledger.append(&Record::new(
            "OLD".into(),
            "Old".into(),
            "reject",
            "human",
            "No.".into(),
        ))?;
        let intent = ledger.prepare("main", "inbox", records())?;
        fs::write(&ledger.path, b"{}")?;
        assert!(ledger.reconcile(&intent, true).is_err());
        fs::remove_file(&ledger.path)?;
        assert!(ledger.reconcile(&intent, true).is_err());
        Ok(())
    }

    #[test]
    fn legacy_final_record_without_newline_remains_readable() -> Result<()> {
        let (_directory, ledger) = fixture()?;
        let old = Record::new("OLD".into(), "Old".into(), "reject", "human", "No.".into());
        let prefix = serde_json::to_vec(&old)?;
        fs::write(&ledger.path, &prefix)?;
        let intent = ledger.prepare("main", "inbox", records())?;
        assert!(intent.leading_newline);
        ledger.reconcile(&intent, true)?;
        assert_eq!(ledger.history()?.len(), 3);
        assert!(fs::read(&ledger.path)?.starts_with(&prefix));
        Ok(())
    }

    #[test]
    fn invalid_journal_remains_an_explicit_error() -> Result<()> {
        let (_directory, ledger) = fixture()?;
        fs::write(ledger.intent_path(), b"{partial")?;
        assert!(ledger.pending().is_err());
        assert_eq!(fs::read(ledger.intent_path())?, b"{partial");
        Ok(())
    }

    #[test]
    fn uncertain_application_never_invents_a_complete_transaction() -> Result<()> {
        let (_directory, ledger) = fixture()?;
        let intent = ledger.prepare("main", "inbox", records())?;
        let mut main = HashSet::new();
        assert!(!intent.applied(&main)?);
        main.insert("CANDIDATE".into());
        assert!(intent.applied(&main).is_err());
        main.insert("MERGE".into());
        assert!(intent.applied(&main)?);
        Ok(())
    }
}

#[cfg(test)]
mod feature_tests {
    use super::*;
    use std::io::BufRead;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    fn source_bytes(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
        let mut pending = vec![root.to_owned()];
        let mut files = BTreeMap::new();
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    pending.push(entry.path());
                } else {
                    files.insert(
                        entry.path().strip_prefix(root)?.to_owned(),
                        fs::read(entry.path())?,
                    );
                }
            }
        }
        Ok(files)
    }

    fn pending_fixture(files: &[(&str, &[u8])]) -> Result<(tempfile::TempDir, Settings, String)> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?.join("repo");
        fs::create_dir(&root)?;
        let pijul = Pijul::new(root.clone());
        pijul.run(["init"])?;
        fs::write(root.join("POLICY.md"), "Accept safe source changes.\n")?;
        fs::write(root.join("value.txt"), "base\n")?;
        pijul.run(["add", "POLICY.md", "value.txt"])?;
        let signer = Signer::new(root.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Define source",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        pijul.run(["fork", "--channel", "main", "inbox"])?;
        pijul.run(["channel", "switch", "inbox"])?;
        for (name, bytes) in files {
            fs::write(root.join(name), bytes)?;
            pijul.run(["add", name])?;
        }
        let (output, _) = pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Change source",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        let candidate = output
            .split_whitespace()
            .next_back()
            .context("The candidate is absent")?
            .to_owned();
        let settings = Settings {
            repo: root,
            inbox: "inbox".into(),
            main: "main".into(),
            model_url: "http://127.0.0.1:9/v1".into(),
            model: "feature-test".into(),
            model_api: Api::OpenAi,
            model_revision: None,
            model_profile: None,
            model_key_file: None,
            policy: "POLICY.md".into(),
            protected: Vec::new(),
            max_change_chars: 100_000,
            timeout: Duration::from_secs(10),
            check_timeout: Duration::from_secs(10),
            interrupted: Arc::new(AtomicBool::new(false)),
        };
        Ok((directory, settings, candidate))
    }

    fn fixture_edit(settings: &Settings, file: &str, text: &str, author: &str) -> Result<String> {
        let pijul = Pijul::new(settings.repo.clone());
        fs::write(settings.repo.join(file), text)?;
        pijul.run(["add", file])?;
        let signer = Signer::new(settings.repo.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        let (output, _) = pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Record the fixture edit",
                "--author",
                author,
            ],
            &environment.vars,
        )?;
        output
            .split_whitespace()
            .next_back()
            .map(str::to_owned)
            .context("The fixture edit has no hash")
    }

    fn independent_fixture_edit(settings: &Settings) -> Result<String> {
        let pijul = Pijul::new(settings.repo.clone());
        pijul.run(["fork", "--channel", "main", "other-author"])?;
        pijul.run(["channel", "switch", "other-author"])?;
        let hash = fixture_edit(
            settings,
            "other.txt",
            "independent source\n",
            "other-author",
        )?;
        pijul.run(["apply", "--channel", "inbox", &hash])?;
        pijul.run(["channel", "switch", "inbox"])?;
        Ok(hash)
    }

    #[test]
    fn targeted_review_does_not_decide_unselected_changes() -> Result<()> {
        let (_directory, mut settings, candidate) =
            pending_fixture(&[("value.txt", b"candidate\n")])?;
        let other = independent_fixture_edit(&settings)?;
        settings.protected = vec!["*.txt".into()];
        let mut gate = Gate::new(settings)?;
        let selection = Selection {
            changes: vec![candidate[..12].to_ascii_lowercase()],
            ..Selection::default()
        };
        let report = gate.review_report(false, &selection)?;
        assert_eq!(report.items.len(), 1);
        assert!(report.items[0].state == State::Escalated);
        let records = gate.ledger.latest()?;
        assert_eq!(records[&candidate].by, "gate");
        assert!(!records.contains_key(&other));
        assert_eq!(report.selection.unwrap().selected, vec![candidate]);
        Ok(())
    }

    #[test]
    fn targeted_dependencies_need_explicit_inclusion_and_retain_terminal_decisions() -> Result<()> {
        let (_directory, mut settings, dependency) =
            pending_fixture(&[("value.txt", b"dependency\n")])?;
        let candidate = fixture_edit(&settings, "value.txt", "dependent candidate\n", "patchgate")?;
        settings.protected = vec!["*.txt".into()];
        let mut gate = Gate::new(settings)?;
        let mut selection = Selection {
            changes: vec![candidate.clone()],
            ..Selection::default()
        };
        let waiting = gate.review_report(false, &selection)?;
        assert_eq!(waiting.items.len(), 1);
        assert!(waiting.items[0].state == State::Waiting);
        assert!(waiting.records.is_empty());
        assert!(gate.ledger.history()?.is_empty());
        selection.include_dependencies = true;
        let included = gate.review_report(false, &selection)?;
        assert_eq!(
            included.selection.unwrap().added_dependencies,
            vec![dependency.clone()]
        );
        assert!(
            included
                .items
                .iter()
                .any(|item| item.hash == candidate && item.state == State::Blocked)
        );
        assert_eq!(gate.ledger.latest()?[&dependency].decision, "escalate");
        assert!(!gate.ledger.latest()?.contains_key(&candidate));
        gate.decide_by_hand(&dependency, "reject", Some("Retain this human rejection"))?;
        let before = fs::read(&gate.ledger.path)?;
        let blocked = gate.review_report(false, &selection)?;
        assert!(
            blocked
                .items
                .iter()
                .any(|item| item.hash == candidate && item.state == State::Blocked)
        );
        assert_eq!(fs::read(&gate.ledger.path)?, before);
        assert_eq!(gate.ledger.latest()?[&dependency].by, "human");
        Ok(())
    }

    #[test]
    fn author_selection_and_hash_selection_form_a_union() -> Result<()> {
        let (_directory, mut settings, candidate) =
            pending_fixture(&[("value.txt", b"candidate\n")])?;
        let other = independent_fixture_edit(&settings)?;
        settings.protected = vec!["*.txt".into()];
        let mut gate = Gate::new(settings)?;
        let mut selection = Selection {
            authors: vec!["other-author".into()],
            ..Selection::default()
        };
        gate.review_report(false, &selection)?;
        let records = gate.ledger.latest()?;
        assert!(records.contains_key(&other));
        assert!(!records.contains_key(&candidate));
        selection.changes.push(candidate.clone());
        let report = gate.review_report(false, &selection)?;
        assert_eq!(
            report.selection.unwrap().selected,
            vec![candidate.clone(), other.clone()]
        );
        assert_eq!(report.records.len(), 1);
        assert_eq!(gate.ledger.latest()?[&candidate].decision, "escalate");
        assert_eq!(
            gate.ledger
                .history()?
                .iter()
                .filter(|record| record.hash == other)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn every_review_selector_is_valid_before_the_first_decision() -> Result<()> {
        let (_directory, mut settings, candidate) =
            pending_fixture(&[("value.txt", b"candidate\n")])?;
        settings.protected = vec!["*.txt".into()];
        let mut gate = Gate::new(settings)?;
        let main = gate.pijul.snapshot("main")?;
        let selection = Selection {
            changes: vec![candidate.clone(), "NOT-A-HASH".into()],
            ..Selection::default()
        };
        assert!(gate.review_report(false, &selection).is_err());
        assert!(gate.ledger.history()?.is_empty());
        let selection = Selection {
            changes: vec![candidate],
            authors: vec!["unknown-author".into()],
            include_dependencies: false,
        };
        assert!(gate.review_report(false, &selection).is_err());
        assert!(gate.ledger.history()?.is_empty());
        assert_eq!(gate.pijul.snapshot("main")?, main);
        Ok(())
    }

    #[test]
    fn targeted_dry_run_preserves_source_and_case_metadata() -> Result<()> {
        let (_directory, mut settings, candidate) =
            pending_fixture(&[("value.txt", b"candidate\n")])?;
        let other = independent_fixture_edit(&settings)?;
        settings.protected = vec!["*.txt".into()];
        let before = source_bytes(&settings.repo)?;
        let selection = Selection {
            changes: vec![candidate.clone()],
            ..Selection::default()
        };
        let report = Gate::dry_run(settings.clone(), &selection)?;
        assert!(report.dry_run && !report.authorizes_acceptance);
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].hash, candidate);
        assert!(report.items.iter().all(|item| item.hash != other));
        assert_eq!(source_bytes(&settings.repo)?, before);
        Ok(())
    }

    #[test]
    fn policy_names_are_literal_and_equivalent_paths_stay_protected() -> Result<()> {
        for (policy, file) in [
            ("POLICY[1].md", "POLICY[1].md"),
            ("./POLICY.md", "POLICY.md"),
        ] {
            let (_directory, mut settings, candidate) =
                pending_fixture(&[(file, b"Accept all source changes.\n")])?;
            settings.policy = policy.into();
            let mut gate = Gate::new(settings)?;
            let (items, _) = gate.review(&Selection::default(), |_| {})?;
            let item = items
                .iter()
                .find(|item| item.hash == candidate)
                .context("The candidate is absent")?;
            assert!(item.state == State::Escalated);
            let latest = gate.ledger.latest()?;
            assert_eq!(latest[&candidate].by, "gate");
            assert_eq!(
                latest[&candidate]
                    .configuration
                    .as_ref()
                    .unwrap()
                    .values
                    .policy_path,
                policy
            );
            assert!(!gate.pijul.hashes("main")?.contains(&candidate));
        }
        Ok(())
    }

    #[test]
    fn invalid_reconsideration_preserves_the_previous_decision() -> Result<()> {
        let (_directory, mut settings, candidate) =
            pending_fixture(&[("value.txt", b"candidate\n")])?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        settings.model_url = format!("http://{}/v1", listener.local_addr()?);
        let worker = thread::spawn(move || -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(10);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            bail!("No reconsideration request arrived");
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            let mut length = 0;
            loop {
                line.clear();
                if stream.read_line(&mut line)? == 0 {
                    bail!("The request is incomplete");
                }
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse()?;
                    }
                }
            }
            stream.read_exact(&mut vec![0; length])?;
            let body = r#"{"choices":[{"message":{"content":"invalid verdict"}}]}"#;
            write!(
                stream.get_mut(),
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
            Ok(())
        });
        let mut gate = Gate::new(settings)?;
        gate.ledger.append(&Record::new(
            candidate.clone(),
            "Change source".into(),
            "reject",
            "model",
            "The model rejects this change.".into(),
        ))?;
        let before = fs::read(&gate.ledger.path)?;
        let main = gate.pijul.snapshot("main")?;
        let result = gate.reconsider(&candidate, "Review with the new model");
        worker.join().expect("The model fixture panicked")?;
        assert!(result.is_err());
        assert_eq!(fs::read(&gate.ledger.path)?, before);
        assert_eq!(gate.pijul.snapshot("main")?, main);
        assert_eq!(gate.ledger.latest()?[&candidate].decision, "reject");
        Ok(())
    }

    #[test]
    fn later_dependency_rejection_stops_prepared_acceptance_before_record() -> Result<()> {
        let (directory, settings, dependency) = pending_fixture(&[("value.txt", b"dependency\n")])?;
        let pijul = Pijul::new(settings.repo.clone());
        fs::write(settings.repo.join("value.txt"), "dependent candidate\n")?;
        let signer = Signer::new(settings.repo.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        let (output, _) = pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Add a dependent change",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        let candidate = output
            .split_whitespace()
            .next_back()
            .context("The candidate is absent")?;
        let mut gate = Gate::new(settings.clone())?;
        let mut conflict = Record::new(
            dependency.clone(),
            "Change source".into(),
            "escalate",
            "gate",
            "A human must resolve this conflict.".into(),
        );
        conflict.conflict = true;
        gate.ledger.append(&conflict)?;
        let prepared = Gate::prepare_resolution(
            settings,
            candidate,
            &fs::canonicalize(directory.path())?.join("workspace"),
        )?;
        assert_eq!(
            prepared.candidates,
            vec![dependency.clone(), candidate.to_owned()]
        );
        gate.decide_by_hand(&dependency, "reject", Some("Retain the current rejection"))?;
        fs::write(prepared.workspace.join("value.txt"), "pending human edit\n")?;
        let workspace = Pijul::new(prepared.workspace.clone());
        let workspace_before = workspace.snapshot("main")?;
        let main = gate.pijul.snapshot("main")?;
        let before = fs::read(&gate.ledger.path)?;
        assert!(gate.accept_resolution(&prepared.workspace, None).is_err());
        assert_eq!(fs::read(&gate.ledger.path)?, before);
        assert_eq!(gate.pijul.snapshot("main")?, main);
        assert_eq!(workspace.snapshot("main")?, workspace_before);
        assert_eq!(
            fs::read(prepared.workspace.join("value.txt"))?,
            b"pending human edit\n"
        );
        Ok(())
    }

    #[test]
    fn workspace_verification_preserves_source_workspace_and_later_live_guards() -> Result<()> {
        let (directory, settings, candidate) = pending_fixture(&[("value.txt", b"candidate\n")])?;
        let prepared = Gate::prepare_resolution(
            settings.clone(),
            &candidate,
            &fs::canonicalize(directory.path())?.join("workspace"),
        )?;
        fs::write(prepared.workspace.join("value.txt"), "pending human work\n")?;
        fs::write(
            prepared.workspace.join("untracked.txt"),
            "untracked human work\n",
        )?;
        fs::write(settings.repo.join("value.txt"), "dirty source bytes\n")?;
        let source = source_bytes(&settings.repo)?;
        let workspace = source_bytes(&prepared.workspace)?;
        let report = Gate::verify_resolution(settings.clone(), &prepared.workspace)?;
        assert_eq!(report.schema_version, 1);
        assert!(!report.authorizes_acceptance);
        assert_eq!(report.prepared.id, prepared.id);
        assert!(report.validated_hashes.contains(&candidate));
        assert!(report.validation.native_expected_state);
        assert!(report.verification.is_none());
        assert_eq!(source_bytes(&settings.repo)?, source);
        assert_eq!(source_bytes(&prepared.workspace)?, workspace);
        let credential = ["ghp_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat();
        fs::write(prepared.workspace.join("first\nsecond"), &credential)?;
        Pijul::new(prepared.workspace.clone()).run(["add", "first\nsecond"])?;
        let changed = source_bytes(&prepared.workspace)?;
        let error = Gate::verify_resolution(settings.clone(), &prepared.workspace)
            .err()
            .context("The credential did not stop private verification")?;
        assert!(!format!("{error:#}").contains(&credential));
        assert_eq!(source_bytes(&settings.repo)?, source);
        assert_eq!(source_bytes(&prepared.workspace)?, changed);
        let mut gate = Gate::new(settings)?;
        assert!(gate.accept_resolution(&prepared.workspace, None).is_err());
        Ok(())
    }

    #[test]
    fn workspace_verification_accepts_read_only_inputs_without_permission_or_byte_changes()
    -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        fn file_modes(root: &Path) -> Result<BTreeMap<PathBuf, u32>> {
            source_bytes(root)?
                .into_keys()
                .map(|path| {
                    let mode = fs::metadata(root.join(&path))?.permissions().mode();
                    Ok((path, mode))
                })
                .collect()
        }
        let (directory, settings, candidate) = pending_fixture(&[("value.txt", b"candidate\n")])?;
        let gate = Gate::new(settings.clone())?;
        gate.ledger.append(&Record::new(
            candidate.clone(),
            "Change source".into(),
            "escalate",
            "human",
            "A human must inspect the workspace.".into(),
        ))?;
        let prepared = Gate::prepare_resolution(
            settings.clone(),
            &candidate,
            &fs::canonicalize(directory.path())?.join("workspace"),
        )?;
        fs::write(prepared.workspace.join("value.txt"), "pending human work\n")?;
        fs::write(prepared.workspace.join("new\nfile"), "new native work\n")?;
        Pijul::new(prepared.workspace.clone()).run(["add", "new\nfile"])?;
        let credential = ["ghp_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat();
        for alias in ["new", "file"] {
            fs::write(prepared.workspace.join(alias), &credential)?;
        }
        for root in [&settings.repo, &prepared.workspace] {
            for path in source_bytes(root)?.into_keys() {
                fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o444))?;
            }
        }
        let source = source_bytes(&settings.repo)?;
        let workspace = source_bytes(&prepared.workspace)?;
        let source_modes = file_modes(&settings.repo)?;
        let workspace_modes = file_modes(&prepared.workspace)?;
        let report = Gate::verify_resolution(settings.clone(), &prepared.workspace)?;
        assert!(!report.authorizes_acceptance);
        assert!(report.validation.credential_scan);
        assert!(report.validation.native_expected_state);
        assert!(report.validated_hashes.contains(&candidate));
        assert_eq!(source_bytes(&settings.repo)?, source);
        assert_eq!(source_bytes(&prepared.workspace)?, workspace);
        assert_eq!(file_modes(&settings.repo)?, source_modes);
        assert_eq!(file_modes(&prepared.workspace)?, workspace_modes);
        Ok(())
    }

    #[test]
    fn workspace_verification_refuses_editable_native_configuration_without_writes() -> Result<()> {
        let (directory, settings, candidate) = pending_fixture(&[("value.txt", b"candidate\n")])?;
        let prepared = Gate::prepare_resolution(
            settings.clone(),
            &candidate,
            &fs::canonicalize(directory.path())?.join("workspace"),
        )?;
        fs::write(
            prepared.workspace.join(".pijul/config.toml"),
            "[hooks]\nrecord = [\"false\"]\n",
        )?;
        let source = source_bytes(&settings.repo)?;
        let workspace = source_bytes(&prepared.workspace)?;
        assert!(Gate::verify_resolution(settings.clone(), &prepared.workspace).is_err());
        assert_eq!(source_bytes(&settings.repo)?, source);
        assert_eq!(source_bytes(&prepared.workspace)?, workspace);
        Ok(())
    }

    #[test]
    fn supplemental_credentials_never_enter_acceptance_audit() -> Result<()> {
        let (directory, settings, candidate) = pending_fixture(&[("value.txt", b"candidate\n")])?;
        let prepared = Gate::prepare_resolution(
            settings.clone(),
            &candidate,
            &fs::canonicalize(directory.path())?.join("workspace"),
        )?;
        let workspace = Pijul::new(prepared.workspace.clone());
        fs::write(prepared.workspace.join("value.txt"), "human edit\n")?;
        let credential = ["ghp_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat();
        let signer = Signer::new(settings.repo.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        workspace.call_with_env(
            [
                "record",
                "-a",
                "-m",
                &format!("Review token {credential}"),
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        let mut gate = Gate::new(settings)?;
        let main = gate.pijul.snapshot("main")?;
        let error = gate
            .accept_resolution(&prepared.workspace, None)
            .err()
            .context("The credential did not stop acceptance")?;
        assert!(!format!("{error:#}").contains(&credential));
        assert_eq!(gate.pijul.snapshot("main")?, main);
        assert!(!String::from_utf8(fs::read(&gate.ledger.path)?)?.contains(&credential));
        let latest = gate.ledger.latest()?;
        assert_eq!(latest[&candidate].decision, "reject");
        assert!(
            latest[&candidate]
                .findings
                .iter()
                .any(|finding| finding.rule_id == "github-token")
        );
        Ok(())
    }

    #[test]
    fn budget_context_errors_do_not_disclose_credential_paths() -> Result<()> {
        let credential = ["ghp_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat();
        let (_directory, settings, candidate) =
            pending_fixture(&[(&credential, b"zero\0bytes\n")])?;
        let before = source_bytes(&settings.repo)?;
        let error = Gate::budget(settings.clone(), &candidate)
            .err()
            .context("The binary context did not stop the budget report")?;
        assert!(!format!("{error:#}").contains(&credential));
        assert_eq!(source_bytes(&settings.repo)?, before);
        Ok(())
    }

    #[test]
    fn native_import_never_publishes_failed_copies_or_replaces_different_bytes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        let target = directory.path().join("changes/target");
        fs::create_dir(&source)?;
        assert!(import_native_change(&source, &target).is_err());
        assert!(!target.exists());
        fs::remove_dir(&source)?;
        fs::write(&source, b"complete native bytes")?;
        import_native_change(&source, &target)?;
        assert_eq!(fs::read(&target)?, b"complete native bytes");
        fs::write(&target, b"partial")?;
        assert!(import_native_change(&source, &target).is_err());
        assert_eq!(fs::read(&target)?, b"partial");
        assert_eq!(fs::read(&source)?, b"complete native bytes");
        Ok(())
    }

    #[test]
    fn accepted_dry_run_preserves_native_state_audit_keys_and_dirty_source() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("repo");
        fs::create_dir(&root)?;
        let pijul = Pijul::new(root.clone());
        pijul.run(["init"])?;
        fs::write(root.join("POLICY.md"), "Accept safe source changes.\n")?;
        fs::write(root.join("value.txt"), "base\n")?;
        pijul.run(["add", "POLICY.md", "value.txt"])?;
        let signer = Signer::new(root.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Define source",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        pijul.run(["fork", "--channel", "main", "inbox"])?;
        pijul.run(["channel", "switch", "inbox"])?;
        fs::write(root.join("value.txt"), "candidate\n")?;
        let (output, _) = pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Change the value",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        let candidate = output
            .split_whitespace()
            .next_back()
            .context("Missing candidate hash")?
            .to_owned();
        drop(environment);
        let ledger = Ledger::new(&root);
        let _lock = ledger.lock()?;
        ledger.append(&Record::new(
            "earlier".into(),
            "Earlier decision".into(),
            "reject",
            "human",
            "Keep it out.".into(),
        ))?;
        drop(_lock);
        fs::write(root.join("value.txt"), "dirty author bytes\n")?;
        fs::write(root.join("untracked"), "untracked author bytes\n")?;
        let main = pijul.snapshot("main")?;
        let inbox = pijul.snapshot("inbox")?;
        let before = source_bytes(&root)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let worker = thread::spawn(move || -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(10);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            bail!("The dry-run made no model request");
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            let mut length = 0;
            loop {
                line.clear();
                if stream.read_line(&mut line)? == 0 {
                    bail!("The model request is incomplete");
                }
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse()?;
                    }
                }
            }
            let mut body = vec![0; length];
            stream.read_exact(&mut body)?;
            let body = r#"{"choices":[{"message":{"content":"{\"decision\":\"accept\",\"summary\":\"Change the value.\",\"reason\":\"The policy allows the change.\"}"}}]}"#;
            write!(
                stream.get_mut(),
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
            Ok(())
        });
        let report = Gate::dry_run(
            Settings {
                repo: root.clone(),
                inbox: "inbox".into(),
                main: "main".into(),
                model_url: format!("http://{address}/v1"),
                model: "dry-run-test".into(),
                model_api: Api::OpenAi,
                model_revision: None,
                model_profile: None,
                model_key_file: None,
                policy: "POLICY.md".into(),
                protected: Vec::new(),
                max_change_chars: 100_000,
                timeout: Duration::from_secs(10),
                check_timeout: Duration::from_secs(10),
                interrupted: Arc::new(AtomicBool::new(false)),
            },
            &Selection::default(),
        )?;
        worker.join().expect("The model fixture panicked")?;
        assert!(report.dry_run);
        assert!(!report.authorizes_acceptance);
        assert!(
            report
                .records
                .iter()
                .any(|record| record.hash == candidate && record.decision == "accept")
        );
        assert_eq!(report.main.state, main.state);
        assert_eq!(report.inbox.state, inbox.state);
        assert_eq!(source_bytes(&root)?, before);
        assert_eq!(pijul.snapshot("main")?, main);
        assert_eq!(pijul.snapshot("inbox")?, inbox);
        Ok(())
    }

    /// Serve exactly `requests` review replies, then stop listening.
    fn accepting_server(requests: usize) -> Result<(String, thread::JoinHandle<Result<()>>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let worker = thread::spawn(move || -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(20);
            for _ in 0..requests {
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                bail!("The model fixture received too few requests");
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(20)))?;
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                let mut length = 0;
                loop {
                    line.clear();
                    if stream.read_line(&mut line)? == 0 {
                        bail!("The model request is incomplete");
                    }
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse()?;
                        }
                    }
                }
                let mut body = vec![0; length];
                stream.read_exact(&mut body)?;
                let body = r#"{"choices":[{"message":{"content":"{\"decision\":\"accept\",\"summary\":\"Safe.\",\"reason\":\"The policy allows it.\"}"}}]}"#;
                write!(
                    stream.get_mut(),
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )?;
            }
            Ok(())
        });
        Ok((format!("http://{address}/v1"), worker))
    }

    #[test]
    fn contiguous_ready_changes_land_in_one_review() -> Result<()> {
        let (_directory, mut settings, first) = pending_fixture(&[("value.txt", b"candidate\n")])?;
        let second = fixture_edit(&settings, "second.txt", "second\n", "patchgate")?;
        let (url, worker) = accepting_server(2)?;
        settings.model_url = url;
        let mut gate = Gate::new(settings)?;
        let (items, _) = gate.review(&Selection::default(), |_| {})?;
        worker.join().expect("The model fixture panicked")?;
        let main = gate.pijul.hashes("main")?;
        assert!(main.contains(&first) && main.contains(&second));
        let latest = gate.ledger.latest()?;
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[&first].decision, "accept");
        assert_eq!(latest[&second].decision, "accept");
        assert!(items.iter().all(|item| item.state == State::Accepted));
        assert!(!gate.ledger.pending()?.is_some());
        Ok(())
    }

    #[test]
    fn documentation_only_changes_skip_the_model() -> Result<()> {
        let (_directory, mut settings, source_change) =
            pending_fixture(&[("value.txt", b"candidate\n")])?;
        let pijul = Pijul::new(settings.repo.clone());
        pijul.run(["channel", "switch", "main"])?;
        fs::write(
            settings.repo.join(crate::configuration::PATH),
            r#"{"schema_version":1,"settings":{"documentation_paths":["docs/*"]}}"#,
        )?;
        pijul.run(["add", crate::configuration::PATH])?;
        let signer = Signer::new(settings.repo.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Declare documentation paths",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        pijul.run(["channel", "switch", "inbox"])?;
        fs::create_dir_all(settings.repo.join("docs"))?;
        let documentation = fixture_edit(&settings, "docs/guide.md", "Guide\n", "patchgate")?;
        assert_eq!(
            crate::configuration::load(&pijul, "main", &settings.baseline_values())?
                .values
                .documentation_paths,
            ["docs/*"]
        );
        let (url, worker) = accepting_server(1)?;
        settings.model_url = url;
        let mut gate = Gate::new(settings)?;
        gate.review(&Selection::default(), |_| {})?;
        worker.join().expect("The model fixture panicked")?;
        let latest = gate.ledger.latest()?;
        assert_eq!(latest[&documentation].decision, "accept");
        assert_eq!(latest[&documentation].by, "gate");
        assert!(
            latest[&documentation]
                .reason
                .contains("documentation paths")
        );
        assert_eq!(latest[&source_change].by, "model");
        let main = gate.pijul.hashes("main")?;
        assert!(main.contains(&documentation) && main.contains(&source_change));
        Ok(())
    }

    #[test]
    fn an_exact_cached_verdict_avoids_the_model_request() -> Result<()> {
        let (_directory, settings, candidate) = pending_fixture(&[("value.txt", b"candidate\n")])?;
        // Any real request fails: the cached verdict alone must decide this change.
        let mut gate = Gate::new(settings)?;
        let main = gate.pijul.snapshot("main")?;
        let policy = gate
            .pijul
            .read_file("main", "POLICY.md")?
            .context("The policy is absent")?;
        let binding = ReviewBinding::new(
            std::slice::from_ref(&candidate),
            "POLICY.md",
            Some(&policy),
            "main",
            &main,
        );
        let verdict = crate::model::Verdict {
            decision: "accept".into(),
            summary: "Safe.".into(),
            reason: "The policy allows it.".into(),
        };
        let request = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "operation": "review",
            "api": "openai",
            "model": "feature-test",
            "declared_revision": null,
            "revision_verified": false,
            "prompt_sha256": "prompt",
            "schema_sha256": "schema",
        }))?;
        gate.remember_verdict(&binding, &candidate, &verdict, request)?;
        gate.review(&Selection::default(), |_| {})?;
        let latest = gate.ledger.latest()?;
        assert_eq!(latest[&candidate].decision, "accept");
        assert_eq!(latest[&candidate].by, "model");
        assert!(latest[&candidate].reused);
        assert_eq!(
            latest[&candidate]
                .provenance
                .as_ref()
                .context("Decision provenance is absent")?
                .requests
                .len(),
            1
        );
        assert!(gate.pijul.hashes("main")?.contains(&candidate));
        Ok(())
    }
}
