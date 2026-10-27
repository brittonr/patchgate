use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use chrono::{SecondsFormat, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::configuration::{Evidence, Values};

use crate::case_metadata as metadata;
pub use crate::case_metadata::{NoteKind, NoteRecord, SeenRecord, SpanAnchor};

use crate::pijul::{MetadataContext, NativeContextFile, NativeVertex, NativeVertexKind, ReviewChange};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub repository: PathBuf,
    pub main: String,
    pub inbox: String,
    pub main_state: Option<String>,
    pub base: Vec<String>,
    pub candidate: String,
    pub policy_path: String,
    pub policy_sha256: Option<String>,
    pub configuration: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Label {
    Accept,
    Reject,
    Escalate,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabelRecord {
    pub user: String,
    pub time: String,
    pub expected: Label,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TagRecord {
    pub user: String,
    pub time: String,
    pub reason: String,
    pub policy_rules: Vec<String>,
    pub conflict_kinds: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRecord {
    pub schema_version: u32,
    pub id: String,
    pub snapshot: Snapshot,
    pub captured_at: String,
    pub labels: Vec<LabelRecord>,
    #[serde(default)]
    pub tags: Vec<TagRecord>,
    #[serde(default)]
    pub notes: Vec<NoteRecord>,
    #[serde(default)]
    pub seen: Vec<SeenRecord>,
}

#[derive(Debug, Serialize)]
pub struct ExportReport {
    pub schema_version: u32,
    pub output: PathBuf,
    pub cases: Vec<String>,
    pub variants: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Variant {
    id: String,
    model_url: String,
    model: String,
    api: String,
    revision: String,
    policy: Option<PathBuf>,
}

pub struct Store {
    repo: PathBuf,
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 53
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn file_context<'a>(
    change: &'a ReviewChange,
    path: &str,
) -> Result<(Option<&'a NativeContextFile>, Option<&'a MetadataContext>)> {
    metadata::validate_path(path)?;
    ensure!(change.context.full, "The native file context is not complete.");
    let mut files = change.context.files.iter().filter(|file| file.path == path);
    let mut metadata = change.metadata_context.iter().filter(|file| file.path == path);
    let file = files.next();
    let context = metadata.next();
    ensure!(
        file.is_some() != context.is_some() && files.next().is_none() && metadata.next().is_none(),
        "The captured file path is absent or ambiguous."
    );
    Ok((file, context))
}

struct DigestWriter(Sha256);

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn file_digest(change: &ReviewChange, path: &str) -> Result<String> {
    let (file, metadata) = file_context(change, path)?;
    let mut writer = DigestWriter(Sha256::new());
    serde_json::to_writer(&mut writer, &(path, file, metadata))?;
    Ok(format!("{:x}", writer.0.finalize()))
}

pub fn span_anchor(change: &ReviewChange, path: &str, span: usize) -> Result<SpanAnchor> {
    let (file, _) = file_context(change, path)?;
    let vertex = file
        .and_then(|file| span.checked_sub(1).and_then(|index| file.vertices.get(index)))
        .context("The native span index is not valid for this file.")?;
    Ok(vertex_anchor(path, vertex))
}

pub fn vertex_anchor(path: &str, vertex: &NativeVertex) -> SpanAnchor {
    SpanAnchor {
        path: path.into(),
        vertex_change: vertex.change.clone(),
        start: vertex.start,
        end: vertex.end,
        kind: match vertex.kind {
            NativeVertexKind::Add => "add",
            NativeVertexKind::Del => "del",
            NativeVertexKind::Keep => "keep",
        }.into(),
        text_sha256: digest(vertex.text.as_bytes()),
    }
}

fn identity(snapshot: &Snapshot) -> Result<String> {
    Ok(digest(&serde_json::to_vec(snapshot)?))
}

fn safe_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn validate_tag_set(tags: &[String]) -> Result<()> {
    let mut unique = BTreeSet::new();
    for tag in tags {
        ensure!(
            !tag.is_empty()
                && tag.len() <= 64
                && tag.as_bytes()[0].is_ascii_lowercase()
                && tag.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_'))
                && unique.insert(tag),
            "Tags must use unique lowercase identifiers with at most 64 characters."
        );
    }
    Ok(())
}

fn validate_tags(record: &TagRecord) -> Result<()> {
    ensure!(
        safe_text(&record.user) && safe_text(&record.reason),
        "Human tags need a valid user and an explicit reason without control characters."
    );
    chrono::DateTime::parse_from_rfc3339(&record.time).context("The tag time is not valid.")?;
    validate_tag_set(&record.policy_rules)?;
    validate_tag_set(&record.conflict_kinds)?;
    for value in [&record.user, &record.reason]
        .into_iter()
        .chain(&record.policy_rules)
        .chain(&record.conflict_kinds)
    {
        ensure!(
            crate::secrets::scan_text("[case.tags]", value.as_bytes()).is_empty(),
            "The human tags contain credential data."
        );
    }
    Ok(())
}

fn validate_values(values: &Values) -> Result<()> {
    let policy = crate::pijul::normalize_path(Path::new(&values.policy_path))
        .map_err(|_| anyhow::anyhow!("The captured policy path is not safe."))?;
    ensure!(
        !values.policy_path.is_empty()
            && !policy.as_os_str().is_empty()
            && !policy.starts_with(".pijul"),
        "The captured policy path is not safe."
    );
    ensure!(
        std::time::Duration::try_from_secs_f64(values.timeout_seconds).is_ok()
            && std::time::Duration::try_from_secs_f64(values.check_timeout_seconds).is_ok(),
        "Captured time limits must be finite and nonnegative."
    );
    crate::configuration::validate_review_limits(
        values.max_review_requests,
        values.review_timeout_seconds,
    )?;
    ensure!(
        values
            .protected
            .iter()
            .all(|pattern| safe_text(pattern) && !pattern.contains(',')),
        "The captured protected patterns are not valid."
    );
    Ok(())
}

fn settings(snapshot: &Snapshot) -> Result<Values> {
    let evidence: Evidence = serde_json::from_value(snapshot.configuration.clone())
        .context("The captured configuration evidence is not valid.")?;
    validate_values(&evidence.values)?;
    ensure!(
        snapshot.policy_path == evidence.values.policy_path,
        "The captured policy path differs from its configuration."
    );
    Ok(evidence.values)
}

fn validate_snapshot(snapshot: &Snapshot, repository: &Path) -> Result<()> {
    ensure!(
        snapshot.repository == repository,
        "The case belongs to a different repository."
    );
    for channel in [&snapshot.main, &snapshot.inbox] {
        ensure!(
            safe_text(channel) && !channel.starts_with('-'),
            "The captured channel name is not valid."
        );
    }
    ensure!(
        snapshot.main != snapshot.inbox,
        "Captured channels must differ."
    );
    ensure!(
        valid_hash(&snapshot.candidate),
        "The captured candidate hash is not valid."
    );
    let mut hashes = BTreeSet::new();
    for hash in &snapshot.base {
        ensure!(
            valid_hash(hash) && hashes.insert(hash),
            "The captured base hashes are not valid or unique."
        );
    }
    ensure!(
        !hashes.contains(&snapshot.candidate),
        "The captured base contains its candidate."
    );
    if let Some(hash) = &snapshot.policy_sha256 {
        ensure!(
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "The captured policy digest is not valid."
        );
    }
    settings(snapshot)?;
    ensure!(
        crate::secrets::scan_text("[case.snapshot]", &serde_json::to_vec(snapshot)?).is_empty(),
        "The case snapshot contains credential data."
    );
    Ok(())
}

fn regular_private(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "Case metadata must use a regular file without aliases."
    );
    Ok(())
}

impl Store {
    pub fn new(repo: &Path) -> Self {
        Self { repo: repo.into() }
    }

    fn repository(&self) -> Result<PathBuf> {
        let repo = fs::canonicalize(&self.repo).context("Read the case repository path.")?;
        let metadata = crate::pijul::safe_path(&repo, Path::new(".pijul"))?;
        ensure!(
            metadata.is_dir(),
            "The case repository has no Pijul metadata."
        );
        Ok(repo)
    }

    fn directory(&self, repo: &Path) -> Result<PathBuf> {
        crate::pijul::safe_path(repo, Path::new(".pijul/patchgate/cases"))
    }

    fn lock(&self, repo: &Path) -> Result<File> {
        let directory = self.directory(repo)?;
        fs::create_dir_all(&directory)?;
        File::open(&directory)?.sync_all()?;
        File::open(repo.join(".pijul/patchgate"))?.sync_all()?;
        File::open(repo.join(".pijul"))?.sync_all()?;
        let path = crate::pijul::safe_path(repo, Path::new(".pijul/patchgate/cases/lock"))?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        regular_private(&path)?;
        FileExt::lock_exclusive(&file)?;
        Ok(file)
    }

    fn record(&self, repo: &Path, id: &str) -> Result<Option<CaseRecord>> {
        let relative = Path::new(".pijul/patchgate/cases").join(format!("{id}.json"));
        let path = crate::pijul::safe_path(repo, &relative)?;
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
            "Case metadata must use a regular file without aliases."
        );
        let record: CaseRecord =
            serde_json::from_reader(file).context("Read a captured case record.")?;
        ensure!(
            record.schema_version == 1 && record.id == id && identity(&record.snapshot)? == id,
            "The case record identity is not valid."
        );
        validate_snapshot(&record.snapshot, repo)?;
        chrono::DateTime::parse_from_rfc3339(&record.captured_at)
            .context("The capture time is not valid.")?;
        for label in &record.labels {
            ensure!(
                safe_text(&label.user) && !label.reason.trim().is_empty(),
                "The case label lacks an explicit user or reason."
            );
            chrono::DateTime::parse_from_rfc3339(&label.time)
                .context("The label time is not valid.")?;
        }
        for tags in &record.tags {
            validate_tags(tags)?;
        }
        metadata::validate_histories(&record.notes, &record.seen)?;
        Ok(Some(record))
    }

    fn records(&self, repo: &Path) -> Result<Vec<CaseRecord>> {
        let directory = self.directory(repo)?;
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .context("A case metadata name is not valid UTF-8.")?;
            if name == "lock" || name.starts_with(".tmp") {
                continue;
            }
            let id = name
                .strip_suffix(".json")
                .context("A case metadata name is not valid.")?;
            ensure!(
                id.len() == 64
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "A case metadata ID is not valid."
            );
            records.push(
                self.record(repo, id)?
                    .context("A listed case record is absent.")?,
            );
        }
        records.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(records)
    }

    fn save(&self, repo: &Path, record: &CaseRecord) -> Result<()> {
        let directory = self.directory(repo)?;
        let path = crate::pijul::safe_path(
            repo,
            &Path::new(".pijul/patchgate/cases").join(format!("{}.json", record.id)),
        )?;
        if path.exists() {
            regular_private(&path)?;
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(".tmp")
            .tempfile_in(&directory)?;
        serde_json::to_writer_pretty(&mut temporary, record)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        self.directory(repo)?;
        temporary.persist(&path).map_err(|error| error.error)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    pub fn capture(&self, mut snapshot: Snapshot) -> Result<CaseRecord> {
        let repo = self.repository()?;
        snapshot.repository =
            fs::canonicalize(&snapshot.repository).context("Read the captured repository path.")?;
        validate_snapshot(&snapshot, &repo)?;
        let _lock = self.lock(&repo)?;
        let id = identity(&snapshot)?;
        if let Some(record) = self.record(&repo, &id)? {
            ensure!(
                record.snapshot == snapshot,
                "The case ID has a different snapshot."
            );
            return Ok(record);
        }
        let record = CaseRecord {
            schema_version: 1,
            id,
            snapshot,
            captured_at: now(),
            labels: Vec::new(),
            tags: Vec::new(),
            notes: Vec::new(),
            seen: Vec::new(),
        };
        self.save(&repo, &record)?;
        Ok(record)
    }

    pub fn list(&self) -> Result<Vec<CaseRecord>> {
        let repo = self.repository()?;
        self.records(&repo)
    }

    pub fn get(&self, prefix: &str) -> Result<CaseRecord> {
        let repo = self.repository()?;
        let records = self.records(&repo)?;
        Ok(select(&records, prefix)?.clone())
    }

    pub fn label(&self, prefix: &str, expected: Label, reason: &str) -> Result<CaseRecord> {
        ensure!(
            !reason.trim().is_empty(),
            "A human label needs an explicit reason."
        );
        let repo = self.repository()?;
        let _lock = self.lock(&repo)?;
        let records = self.records(&repo)?;
        let mut record = select(&records, prefix)?.clone();
        let user = std::env::var("USER").unwrap_or_else(|_| "a human".into());
        ensure!(safe_text(&user), "The human user name is not valid.");
        record.labels.push(LabelRecord {
            user,
            time: now(),
            expected,
            reason: reason.into(),
        });
        self.save(&repo, &record)?;
        Ok(record)
    }

    pub fn tag(
        &self,
        prefix: &str,
        policy_rules: &[String],
        conflict_kinds: &[String],
        reason: &str,
    ) -> Result<CaseRecord> {
        let tags = TagRecord {
            user: std::env::var("USER").unwrap_or_else(|_| "a human".into()),
            time: now(),
            reason: reason.into(),
            policy_rules: policy_rules.into(),
            conflict_kinds: conflict_kinds.into(),
        };
        validate_tags(&tags)?;
        let repo = self.repository()?;
        let _lock = self.lock(&repo)?;
        let records = self.records(&repo)?;
        let mut record = select(&records, prefix)?.clone();
        record.tags.push(tags);
        self.save(&repo, &record)?;
        Ok(record)
    }

    pub fn note(
        &self,
        prefix: &str,
        kind: NoteKind,
        text: &str,
        references: &[String],
        path: Option<&str>,
        span: Option<usize>,
    ) -> Result<CaseRecord> {
        ensure!(path.is_some() == span.is_some(), "A note target needs both a path and a span.");
        let mut note = NoteRecord {
            user: std::env::var("USER").unwrap_or_else(|_| "a human".into()),
            time: now(),
            kind,
            text: text.into(),
            references: references.into(),
            anchor: None,
        };
        metadata::validate_histories(std::slice::from_ref(&note), &[])?;
        let repo = self.repository()?;
        let _lock = self.lock(&repo)?;
        let records = self.records(&repo)?;
        let mut record = select(&records, prefix)?.clone();
        let report = crate::case_view::inspect(&repo, &record.id)?;
        ensure!(
            report.snapshot == record.snapshot && report.id == record.id,
            "The note target differs from its captured snapshot."
        );
        if let (Some(path), Some(span)) = (path, span) {
            note.anchor = Some(span_anchor(&report.change, path, span)?);
        }
        metadata::validate_histories(std::slice::from_ref(&note), &[])?;
        record.notes.push(note);
        self.save(&repo, &record)?;
        Ok(record)
    }

    pub fn seen(&self, prefix: &str, path: &str, seen: bool) -> Result<CaseRecord> {
        metadata::validate_path(path)?;
        let repo = self.repository()?;
        let _lock = self.lock(&repo)?;
        let records = self.records(&repo)?;
        let mut record = select(&records, prefix)?.clone();
        let report = crate::case_view::inspect(&repo, &record.id)?;
        ensure!(
            report.snapshot == record.snapshot && report.id == record.id,
            "The seen file differs from its captured snapshot."
        );
        let entry = SeenRecord {
            user: std::env::var("USER").unwrap_or_else(|_| "a human".into()),
            time: now(),
            path: path.into(),
            content_sha256: file_digest(&report.change, path)?,
            seen,
        };
        metadata::validate_histories(&[], std::slice::from_ref(&entry))?;
        record.seen.push(entry);
        self.save(&repo, &record)?;
        Ok(record)
    }

    fn export_manifest(&self, ids: &[String], variants: &Path, portable: bool) -> Result<Value> {
        let repo = self.repository()?;
        let records = self.records(&repo)?;
        let selected = if ids.is_empty() {
            records
                .iter()
                .filter(|record| !record.labels.is_empty())
                .collect::<Vec<_>>()
        } else {
            let mut selected = Vec::new();
            let mut unique = BTreeSet::new();
            for id in ids {
                let record = select(&records, id)?;
                ensure!(
                    unique.insert(&record.id),
                    "The export selects one case more than once."
                );
                selected.push(record);
            }
            selected
        };
        ensure!(!selected.is_empty(), "The export has no labeled cases.");
        let first = selected[0];
        for record in &selected {
            ensure!(
                !record.labels.is_empty(),
                "A selected case has no explicit human label."
            );
            ensure!(
                record.snapshot.main == first.snapshot.main
                    && record.snapshot.inbox == first.snapshot.inbox,
                "Selected cases use different channels. Use explicit case IDs."
            );
            for hash in record
                .snapshot
                .base
                .iter()
                .chain(std::iter::once(&record.snapshot.candidate))
            {
                let relative = Path::new(".pijul/changes")
                    .join(&hash[..2])
                    .join(format!("{}.change", &hash[2..]));
                let path = crate::pijul::safe_path(&repo, &relative)?;
                ensure!(
                    fs::symlink_metadata(path)?.is_file(),
                    "A native case change is not a regular file."
                );
            }
        }
        let variants_path = fs::canonicalize(variants).context("Read the replay variants path.")?;
        let mut variants: Vec<Variant> = serde_json::from_slice(&fs::read(&variants_path)?)
            .context("Read the replay variants array.")?;
        if portable {
            for variant in &variants {
                if let Some(policy) = &variant.policy {
                    crate::bundle::validate_policy(
                        &repo,
                        &variants_path
                            .parent()
                            .context("The variants parent is absent.")?
                            .join(policy),
                    )?;
                }
            }
        }
        validate_variants(
            &mut variants,
            variants_path
                .parent()
                .context("The variants parent is absent.")?,
        )?;
        let cases = selected
            .iter()
            .map(|record| -> Result<Value> {
                Ok(json!({
                    "id": record.id,
                    "base": record.snapshot.base,
                    "candidate": record.snapshot.candidate,
                    "expected": record.labels.last().context("The case label is absent.")?.expected,
                    "configuration": record.snapshot.configuration["values"],
                    "snapshot": record.snapshot,
                    "labels": record.labels,
                    "tags": record.tags,
                    "notes": record.notes,
                    "seen": record.seen,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let manifest = json!({
            "schema_version": 1,
            "repository": repo,
            "main": first.snapshot.main,
            "inbox": first.snapshot.inbox,
            "configuration": first.snapshot.configuration["values"],
            "cases": cases,
            "variants": variants,
        });
        Ok(manifest)
    }

    pub fn bundle(
        &self,
        ids: &[String],
        variants: &Path,
        output: &Path,
    ) -> Result<crate::bundle::Export> {
        ensure!(!ids.is_empty(), "A bundle needs explicit case IDs.");
        let manifest = self.export_manifest(ids, variants, true)?;
        let repo = self.repository()?;
        crate::bundle::write(&repo, manifest, output)
    }

    pub fn export(&self, ids: &[String], variants: &Path, output: &Path) -> Result<ExportReport> {
        let manifest = self.export_manifest(ids, variants, false)?;
        let repo = self.repository()?;
        let variants_path = fs::canonicalize(variants).context("Read the replay variants path.")?;
        let output = export_path(output, &repo)?;
        ensure!(
            output != variants_path,
            "The export cannot replace the variants file."
        );
        let parent = output.parent().context("The export parent is absent.")?;
        fs::create_dir_all(parent)?;
        export_path(&output, &repo)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(&mut temporary, &manifest)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        export_path(&output, &repo)?;
        temporary
            .persist_noclobber(&output)
            .map_err(|error| error.error)?;
        File::open(parent)?.sync_all()?;
        Ok(ExportReport {
            schema_version: 1,
            output,
            cases: manifest["cases"]
                .as_array()
                .context("The export cases are absent.")?
                .iter()
                .map(|case| case["id"].as_str().unwrap().to_owned())
                .collect(),
            variants: manifest["variants"]
                .as_array()
                .context("The export variants are absent.")?
                .len(),
        })
    }
}

fn select<'a>(records: &'a [CaseRecord], prefix: &str) -> Result<&'a CaseRecord> {
    ensure!(
        !prefix.is_empty()
            && prefix.len() <= 64
            && prefix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "The case ID prefix is not valid."
    );
    let mut matches = records
        .iter()
        .filter(|record| record.id.starts_with(prefix));
    let record = matches.next().context("No case matches the ID prefix.")?;
    ensure!(matches.next().is_none(), "The case ID prefix is ambiguous.");
    Ok(record)
}

fn validate_variants(variants: &mut [Variant], directory: &Path) -> Result<()> {
    ensure!(!variants.is_empty(), "The variants array is empty.");
    let mut ids = BTreeSet::new();
    for variant in variants {
        ensure!(
            safe_text(&variant.id) && ids.insert(variant.id.clone()),
            "Variant IDs must be nonempty and unique."
        );
        ensure!(
            safe_text(&variant.model) && safe_text(&variant.revision),
            "A variant needs a model and an explicit revision."
        );
        ensure!(
            matches!(variant.api.as_str(), "openai" | "systemone"),
            "The variant API is not valid."
        );
        let address = variant
            .model_url
            .strip_prefix("http://")
            .or_else(|| variant.model_url.strip_prefix("https://"));
        ensure!(
            address.is_some_and(|address| !address
                .split('/')
                .next()
                .unwrap_or_default()
                .is_empty())
                && !variant.model_url.chars().any(char::is_whitespace),
            "A variant needs an HTTP or HTTPS model URL."
        );
        if let Some(path) = &variant.policy {
            let path =
                fs::canonicalize(directory.join(path)).context("Read a variant policy path.")?;
            ensure!(path.is_file(), "A variant policy must name a regular file.");
            fs::read_to_string(&path).context("Read a variant policy file.")?;
            variant.policy = Some(path);
        }
    }
    Ok(())
}

fn export_path(path: &Path, repo: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.into()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        absolute
            .components()
            .all(|part| !matches!(part, Component::ParentDir | Component::CurDir)),
        "The export path must not contain relative components."
    );
    let mut parent = absolute.parent().context("The export parent is absent.")?;
    let mut suffix = vec![
        absolute
            .file_name()
            .context("The export path must name a file.")?
            .to_owned(),
    ];
    loop {
        match fs::symlink_metadata(parent) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix.push(
                    parent
                        .file_name()
                        .context("The export parent is not valid.")?
                        .to_owned(),
                );
                parent = parent.parent().context("The export parent is absent.")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut resolved = fs::canonicalize(parent)?;
    for part in suffix.into_iter().rev() {
        resolved.push(part);
    }
    ensure!(
        !resolved.starts_with(repo),
        "The export must be outside the source repository."
    );
    match fs::symlink_metadata(&resolved) {
        Ok(_) => bail!("The export destination already exists."),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_case_files_default_to_empty_human_metadata() {
        let (_directory, snapshot) = fixture();
        let store = Store::new(&snapshot.repository);
        let record = store.capture(snapshot).unwrap();
        let mut old = serde_json::to_value(&record).unwrap();
        old.as_object_mut().unwrap().remove("notes");
        old.as_object_mut().unwrap().remove("seen");
        let path = record.snapshot.repository.join(".pijul/patchgate/cases")
            .join(format!("{}.json", record.id));
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        assert_eq!(store.get(&record.id).unwrap(), record);
    }

    fn native_fixture() -> ReviewChange {
        ReviewChange {
            hash: "A".repeat(53),
            message: "Change a file".into(),
            authors: Vec::new(),
            timestamp: String::new(),
            dependencies: Vec::new(),
            paths: ["value.txt".into(), "empty.txt".into()].into_iter().collect(),
            context: serde_json::from_value(json!({
                "full": true, "files": [{"path": "value.txt", "vertices": [{
                    "change": "A".repeat(53), "start": 4, "end": 8,
                    "kind": "add", "text": "one\n"
                }]}]
            })).unwrap(),
            metadata_context: vec![crate::pijul::MetadataContext {
                path: "empty.txt".into(), before: None, after: Some(String::new()),
            }],
        }
    }

    #[test]
    fn native_targets_bind_origin_range_kind_text_and_metadata() {
        let mut change = native_fixture();
        let anchor = span_anchor(&change, "value.txt", 1).unwrap();
        assert_eq!(anchor.path, "value.txt");
        assert_eq!(anchor.vertex_change, "A".repeat(53));
        assert_eq!((anchor.start, anchor.end), (4, 8));
        assert_eq!(anchor.kind, "add");
        assert_eq!(anchor.text_sha256, digest(b"one\n"));
        assert!(span_anchor(&change, "value.txt", 0).is_err());
        assert!(span_anchor(&change, "value.txt", 2).is_err());
        assert!(span_anchor(&change, "empty.txt", 1).is_err());
        for path in ["missing.txt", "../value.txt", "/value.txt", "./value.txt", ".pijul/key"] {
            assert!(file_digest(&change, path).is_err());
        }
        let original = file_digest(&change, "value.txt").unwrap();
        change.context.files[0].vertices[0].change = "B".repeat(53);
        assert_ne!(file_digest(&change, "value.txt").unwrap(), original);
        change = native_fixture();
        change.context.files[0].vertices[0].start = 3;
        assert_ne!(file_digest(&change, "value.txt").unwrap(), original);
        change = native_fixture();
        change.context.files[0].vertices[0].kind = NativeVertexKind::Keep;
        assert_ne!(file_digest(&change, "value.txt").unwrap(), original);
        change = native_fixture();
        change.context.files[0].vertices[0].text = "two\n".into();
        assert_ne!(file_digest(&change, "value.txt").unwrap(), original);
        let empty = file_digest(&change, "empty.txt").unwrap();
        change.metadata_context[0].before = Some(String::new());
        assert_ne!(file_digest(&change, "empty.txt").unwrap(), empty);
        change.context.full = false;
        assert!(file_digest(&change, "value.txt").is_err());
    }

    fn fixture() -> (tempfile::TempDir, Snapshot) {
        let directory = tempfile::tempdir().unwrap();
        let repo = directory.path().join("source");
        fs::create_dir_all(repo.join(".pijul/changes/AA")).unwrap();
        fs::write(
            repo.join(".pijul/changes/AA")
                .join(format!("{}.change", "A".repeat(51))),
            b"native data",
        )
        .unwrap();
        let snapshot = Snapshot {
            repository: repo,
            main: "main".into(),
            inbox: "inbox".into(),
            main_state: None,
            base: Vec::new(),
            candidate: "A".repeat(53),
            policy_path: "POLICY.md".into(),
            policy_sha256: None,
            configuration: json!({"source": "environment", "path": null, "sha256": null,
                "values": {"policy_path": "POLICY.md", "protected": [], "max_change_chars": 8000,
                    "timeout_seconds": 0.125, "check_timeout_seconds": 2.75}}),
        };
        (directory, snapshot)
    }

    fn variants(directory: &Path) -> PathBuf {
        let path = directory.join("variants.json");
        fs::write(
            &path,
            serde_json::to_vec(
                &json!([{"id": "model", "model_url": "http://localhost:8080",
            "model": "model", "api": "openai", "revision": "checkpoint-12"}]),
            )
            .unwrap(),
        )
        .unwrap();
        path
    }

    #[test]
    fn capture_rejects_unsafe_review_limits() {
        let (_directory, snapshot) = fixture();
        let store = Store::new(&snapshot.repository);
        let mut invalid = snapshot.clone();
        invalid.configuration["values"]["max_review_requests"] = json!(0);
        assert!(store.capture(invalid).is_err());
        for seconds in [0.0, -1.0, 1e-100, 1e19, f64::MAX] {
            let mut invalid = snapshot.clone();
            invalid.configuration["values"]["review_timeout_seconds"] = json!(seconds);
            assert!(store.capture(invalid).is_err(), "{seconds}");
        }
    }

    #[test]
    fn historical_review_limits_do_not_change_case_bytes_or_identity() {
        let (directory, mut snapshot) = fixture();
        snapshot.repository = fs::canonicalize(&snapshot.repository).unwrap();
        let store = Store::new(&snapshot.repository);
        let expected_id = identity(&snapshot).unwrap();
        let record = store.capture(snapshot.clone()).unwrap();
        assert_eq!(record.id, expected_id);
        let path = snapshot
            .repository
            .join(".pijul/patchgate/cases")
            .join(format!("{}.json", record.id));
        let original = fs::read(&path).unwrap();
        let loaded = store.list().unwrap().pop().unwrap();
        assert_eq!(loaded.id, expected_id);
        assert_eq!(loaded.snapshot.configuration, snapshot.configuration);
        assert_eq!(fs::read(&path).unwrap(), original);
        store
            .label(&record.id, Label::Reject, "The reviewer rejects the change.")
            .unwrap();
        let labeled = fs::read(&path).unwrap();
        let variants = variants(directory.path());
        let output = directory.path().join("historical.json");
        store.export(&[record.id], &variants, &output).unwrap();
        let manifest: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        let exported = &manifest["cases"][0];
        assert_eq!(exported["id"], expected_id);
        assert_eq!(exported["snapshot"]["configuration"], snapshot.configuration);
        assert_eq!(exported["configuration"], snapshot.configuration["values"]);
        assert_eq!(fs::read(path).unwrap(), labeled);
    }

    #[test]
    fn capture_deduplicates_and_retains_explicit_label_history() {
        let (_directory, snapshot) = fixture();
        let store = Store::new(&snapshot.repository);
        let first = store.capture(snapshot.clone()).unwrap();
        assert!(first.labels.is_empty());
        assert!(store.label(&first.id[..12], Label::Reject, "").is_err());
        store
            .label(
                &first.id[..12],
                Label::Reject,
                "The change violates policy.",
            )
            .unwrap();
        let labeled = store
            .label(
                &first.id,
                Label::Accept,
                "The reviewer approves the change.",
            )
            .unwrap();
        assert_eq!(labeled.labels.len(), 2);
        assert_eq!(labeled.labels[0].expected, Label::Reject);
        assert_eq!(store.capture(snapshot).unwrap(), labeled);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn human_tags_retain_history_identity_and_export_data() {
        let (directory, snapshot) = fixture();
        let store = Store::new(&snapshot.repository);
        let first = store.capture(snapshot.clone()).unwrap();
        let labeled = store
            .label(&first.id, Label::Reject, "The reviewer rejects the change.")
            .unwrap();
        let tagged = store
            .tag(
                &first.id[..12],
                &["protected-path".into()],
                &["content".into()],
                "The reviewer identifies the applicable rule and conflict.",
            )
            .unwrap();
        assert_eq!(tagged.id, first.id);
        assert_eq!(tagged.snapshot, first.snapshot);
        assert_eq!(tagged.labels, labeled.labels);
        let cleared = store
            .tag(&first.id, &[], &[], "The reviewer clears the tags.")
            .unwrap();
        assert_eq!(cleared.tags.len(), 2);
        assert_eq!(cleared.tags[0], tagged.tags[0]);
        assert!(cleared.tags[1].policy_rules.is_empty());
        assert!(cleared.tags[1].conflict_kinds.is_empty());
        assert_eq!(store.capture(snapshot).unwrap(), cleared);
        let output = directory.path().join("manifest.json");
        store
            .export(&[], &variants(directory.path()), &output)
            .unwrap();
        let manifest: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(manifest["cases"][0]["tags"], json!(cleared.tags));
    }

    #[test]
    fn tags_refuse_invalid_input_and_record_aliases() {
        let (directory, snapshot) = fixture();
        let store = Store::new(&snapshot.repository);
        let first = store.capture(snapshot).unwrap();
        for tags in [
            vec!["Uppercase".into()],
            vec!["bad tag".into()],
            vec!["bad\n".into()],
            vec!["duplicate".into(), "duplicate".into()],
            vec!["".into()],
            vec!["-option".into()],
            vec!["path/name".into()],
        ] {
            assert!(
                store
                    .tag(&first.id, &tags, &[], "The reviewer identifies the rule.")
                    .is_err()
            );
            assert!(
                store
                    .tag(
                        &first.id,
                        &[],
                        &tags,
                        "The reviewer identifies the conflict."
                    )
                    .is_err()
            );
        }
        let credential = ["password = \"", "Ab3dEf5hGj7kLm9nPq2sTu4w", "\""].concat();
        for reason in ["", "Line\nbreak", credential.as_str()] {
            assert!(store.tag(&first.id, &[], &[], reason).is_err());
        }
        assert!(store.list().unwrap()[0].tags.is_empty());
        let record = store
            .repo
            .join(".pijul/patchgate/cases")
            .join(format!("{}.json", first.id));
        fs::hard_link(&record, directory.path().join("alias")).unwrap();
        assert!(
            store
                .tag(&first.id, &[], &[], "The reviewer clears the tags.")
                .is_err()
        );
        assert_eq!(
            serde_json::from_slice::<CaseRecord>(&fs::read(record).unwrap()).unwrap(),
            first
        );
    }

    #[test]
    fn concurrent_tags_retain_each_human_record() {
        let (_directory, snapshot) = fixture();
        let first = Store::new(&snapshot.repository)
            .capture(snapshot.clone())
            .unwrap();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let repo = snapshot.repository.clone();
                let id = first.id.clone();
                std::thread::spawn(move || {
                    Store::new(&repo)
                        .tag(
                            &id,
                            &["policy".into()],
                            &[],
                            "The reviewer identifies the rule.",
                        )
                        .unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let records = Store::new(&snapshot.repository).list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tags.len(), 8);
    }

    #[test]
    fn historical_cases_default_to_empty_tag_history() {
        let (_directory, snapshot) = fixture();
        let record = Store::new(&snapshot.repository).capture(snapshot).unwrap();
        let mut value = serde_json::to_value(&record).unwrap();
        value.as_object_mut().unwrap().remove("tags");
        let historical: CaseRecord = serde_json::from_value(value).unwrap();
        assert_eq!(historical, record);
    }

    #[test]
    fn concurrent_capture_and_labels_retain_every_human_record() {
        let (_directory, snapshot) = fixture();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let snapshot = snapshot.clone();
                std::thread::spawn(move || {
                    let store = Store::new(&snapshot.repository);
                    let record = store.capture(snapshot).unwrap();
                    store
                        .label(
                            &record.id,
                            Label::Reject,
                            "The reviewer rejects the change.",
                        )
                        .unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let records = Store::new(&snapshot.repository).list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].labels.len(), 8);
    }

    #[test]
    fn snapshot_identity_binds_order_state_policy_and_configuration() {
        let (_directory, mut snapshot) = fixture();
        snapshot.candidate = "C".repeat(53);
        snapshot.base = vec!["A".repeat(53), "B".repeat(53)];
        let original = identity(&snapshot).unwrap();
        snapshot.base.reverse();
        assert_ne!(identity(&snapshot).unwrap(), original);
        snapshot.base.reverse();
        snapshot.main_state = Some("state".into());
        assert_ne!(identity(&snapshot).unwrap(), original);
        snapshot.main_state = None;
        snapshot.policy_sha256 = Some("a".repeat(64));
        assert_ne!(identity(&snapshot).unwrap(), original);
        snapshot.policy_sha256 = None;
        snapshot.configuration["values"]["timeout_seconds"] = json!(0.5);
        assert_ne!(identity(&snapshot).unwrap(), original);
    }

    #[test]
    fn export_preserves_snapshots_labels_and_per_case_settings() {
        let (directory, snapshot) = fixture();
        let store = Store::new(&snapshot.repository);
        let first = store.capture(snapshot.clone()).unwrap();
        let variants = variants(directory.path());
        let output = directory.path().join("manifest.json");
        assert!(
            store
                .export(&[first.id.clone()], &variants, &output)
                .is_err()
        );
        store
            .label(&first.id, Label::Reject, "The reviewer rejects the change.")
            .unwrap();
        let mut second = snapshot.clone();
        second.configuration["values"]["max_change_chars"] = json!(16000);
        second.configuration["values"]["max_review_requests"] = json!(5);
        second.configuration["values"]["review_timeout_seconds"] = json!(0.25);
        let second = store.capture(second).unwrap();
        store
            .label(
                &second.id,
                Label::Escalate,
                "The change needs a human decision.",
            )
            .unwrap();
        let report = store.export(&[], &variants, &output).unwrap();
        assert_eq!(report.cases.len(), 2);
        let manifest: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        for case in manifest["cases"].as_array().unwrap() {
            assert_eq!(
                serde_json::from_value::<Values>(case["configuration"].clone()).unwrap(),
                serde_json::from_value::<Values>(
                    case["snapshot"]["configuration"]["values"].clone()
                )
                .unwrap()
            );
            assert_eq!(case["base"], case["snapshot"]["base"]);
            assert_eq!(case["expected"], case["labels"][0]["expected"]);
        }
        assert!(store.export(&[], &variants, &output).is_err());
        assert!(
            store
                .export(&[], &variants, &snapshot.repository.join("manifest.json"))
                .is_err()
        );
        let nested = directory.path().join("reports/nested/manifest.json");
        assert!(store.export(&[], &variants, &nested).is_ok());
    }

    #[test]
    fn export_refuses_mixed_channels_unknown_ids_and_file_aliases() {
        let (directory, snapshot) = fixture();
        let store = Store::new(&snapshot.repository);
        let first = store.capture(snapshot.clone()).unwrap();
        store
            .label(
                &first.id,
                Label::Accept,
                "The reviewer approves the change.",
            )
            .unwrap();
        let mut other = snapshot.clone();
        other.inbox = "other".into();
        let other = store.capture(other).unwrap();
        store
            .label(&other.id, Label::Reject, "The reviewer rejects the change.")
            .unwrap();
        let variants = variants(directory.path());
        let output = directory.path().join("manifest.json");
        assert!(store.export(&[], &variants, &output).is_err());
        assert!(store.export(&["f".repeat(64)], &variants, &output).is_err());
        let source_file = snapshot.repository.join("data");
        fs::write(&source_file, b"source bytes").unwrap();
        fs::hard_link(&source_file, &output).unwrap();
        assert!(
            store
                .export(&[first.id.clone()], &variants, &output)
                .is_err()
        );
        assert_eq!(fs::read(&source_file).unwrap(), b"source bytes");
        fs::remove_file(&output).unwrap();
        std::os::unix::fs::symlink(&source_file, &output).unwrap();
        assert!(
            store
                .export(&[first.id.clone()], &variants, &output)
                .is_err()
        );
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&snapshot.repository, &alias).unwrap();
        assert!(
            store
                .export(&[first.id], &variants, &alias.join("export.json"))
                .is_err()
        );
    }

    #[test]
    fn explicit_selection_and_variant_validation_do_not_omit_cases() {
        let (directory, snapshot) = fixture();
        let store = Store::new(&snapshot.repository);
        let first = store.capture(snapshot.clone()).unwrap();
        store
            .label(
                &first.id,
                Label::Accept,
                "The reviewer approves the change.",
            )
            .unwrap();
        let mut other = snapshot;
        other.inbox = "other".into();
        let other = store.capture(other).unwrap();
        store
            .label(&other.id, Label::Reject, "The reviewer rejects the change.")
            .unwrap();
        let variants_path = variants(directory.path());
        let output = directory.path().join("selected.json");
        let report = store
            .export(&[first.id[..12].into()], &variants_path, &output)
            .unwrap();
        assert_eq!(report.cases, vec![first.id.clone()]);
        let mut records = store.list().unwrap();
        records[0].id = format!("abc{}", "a".repeat(61));
        records[1].id = format!("abc{}", "b".repeat(61));
        assert!(select(&records, "abc").is_err());
        let mut invalid: Vec<Variant> =
            serde_json::from_slice(&fs::read(&variants_path).unwrap()).unwrap();
        invalid[0].revision.clear();
        assert!(validate_variants(&mut invalid, directory.path()).is_err());
        assert!(
            store
                .export(
                    &[first.id.clone(), first.id],
                    &variants_path,
                    &directory.path().join("duplicate.json")
                )
                .is_err()
        );
    }

    #[test]
    fn metadata_paths_refuse_links_and_record_aliases() {
        let (directory, snapshot) = fixture();
        fs::create_dir_all(snapshot.repository.join(".pijul/patchgate")).unwrap();
        std::os::unix::fs::symlink(
            directory.path(),
            snapshot.repository.join(".pijul/patchgate/cases"),
        )
        .unwrap();
        assert!(
            Store::new(&snapshot.repository)
                .capture(snapshot.clone())
                .is_err()
        );
        fs::remove_file(snapshot.repository.join(".pijul/patchgate/cases")).unwrap();
        let store = Store::new(&snapshot.repository);
        let record = store.capture(snapshot.clone()).unwrap();
        let path = snapshot
            .repository
            .join(".pijul/patchgate/cases")
            .join(format!("{}.json", record.id));
        fs::hard_link(&path, directory.path().join("record-alias")).unwrap();
        assert!(
            store
                .label(
                    &record.id,
                    Label::Accept,
                    "The reviewer approves the change."
                )
                .is_err()
        );
    }

    #[test]
    fn bundle_retains_selected_data_without_the_source_repository() {
        let (directory, snapshot) = fixture();
        let root = fs::canonicalize(directory.path()).unwrap();
        let store = Store::new(&snapshot.repository);
        let first = store.capture(snapshot.clone()).unwrap();
        store
            .label(&first.id, Label::Reject, "The reviewer rejects the change.")
            .unwrap();
        let labeled = store
            .label(
                &first.id,
                Label::Accept,
                "The reviewer approves the change.",
            )
            .unwrap();
        let labeled = store
            .tag(
                &labeled.id,
                &["protected-path".into()],
                &["content".into()],
                "The reviewer identifies the applicable rule and conflict.",
            )
            .unwrap();
        let mut other = snapshot.clone();
        other.candidate = "B".repeat(53);
        fs::create_dir_all(snapshot.repository.join(".pijul/changes/BB")).unwrap();
        fs::write(
            snapshot
                .repository
                .join(".pijul/changes/BB")
                .join(format!("{}.change", "B".repeat(51))),
            b"unselected native data",
        )
        .unwrap();
        let other = store.capture(other).unwrap();
        store
            .label(&other.id, Label::Reject, "The reviewer rejects the change.")
            .unwrap();
        let signer = snapshot.repository.join(".pijul/patchgate/key");
        fs::write(&signer, b"private signer state").unwrap();
        fs::write(
            snapshot.repository.join("private.txt"),
            b"private source data",
        )
        .unwrap();
        let policy = root.join("variant-policy.txt");
        fs::write(&policy, b"Use the alternate policy.\n").unwrap();
        let variants = variants(&root);
        let mut values: Value = serde_json::from_slice(&fs::read(&variants).unwrap()).unwrap();
        values[0]["policy"] = json!(policy);
        fs::write(&variants, serde_json::to_vec(&values).unwrap()).unwrap();
        let output = root.join("review.tar.gz");
        assert!(store.bundle(&[], &variants, &output).is_err());
        let report = store
            .bundle(&[first.id[..12].into()], &variants, &output)
            .unwrap();
        assert_eq!(report.cases, vec![first.id.clone()]);
        assert_eq!(report.native_changes, 1);
        assert_eq!(fs::read(&signer).unwrap(), b"private signer state");
        assert_eq!(store.list().unwrap().len(), 2);
        fs::remove_dir_all(&snapshot.repository).unwrap();
        fs::remove_file(&policy).unwrap();
        fs::remove_file(&variants).unwrap();
        let loaded = crate::bundle::load(&output).unwrap();
        assert_eq!(loaded.sha256, report.sha256);
        assert_eq!(loaded.origin_repository, labeled.snapshot.repository);
        assert_eq!(
            loaded.manifest["cases"][0]["snapshot"],
            json!(labeled.snapshot)
        );
        assert_eq!(loaded.manifest["cases"][0]["labels"], json!(labeled.labels));
        assert_eq!(loaded.manifest["cases"][0]["tags"], json!(labeled.tags));
        assert_eq!(loaded.manifest["cases"][0]["id"], first.id);
        assert_eq!(
            fs::read(
                loaded
                    .repository
                    .join(".pijul/changes/AA")
                    .join(format!("{}.change", "A".repeat(51)))
            )
            .unwrap(),
            b"native data"
        );
        assert!(!loaded.repository.join(".pijul/changes/BB").exists());
        assert!(!loaded.repository.join(".pijul/patchgate").exists());
        assert!(!loaded.repository.join("private.txt").exists());
        let policy = loaded.manifest["variants"][0]["policy"].as_str().unwrap();
        assert_eq!(
            fs::read(loaded.directory.path().join(policy)).unwrap(),
            b"Use the alternate policy.\n"
        );
    }

    #[test]
    fn bundle_refuses_signer_policies_and_destination_aliases() {
        let (directory, snapshot) = fixture();
        let root = fs::canonicalize(directory.path()).unwrap();
        let store = Store::new(&snapshot.repository);
        let record = store.capture(snapshot.clone()).unwrap();
        store
            .label(
                &record.id,
                Label::Accept,
                "The reviewer approves the change.",
            )
            .unwrap();
        let signer = fs::canonicalize(&snapshot.repository)
            .unwrap()
            .join(".pijul/patchgate/key");
        fs::write(&signer, b"private signer state").unwrap();
        let alias = root.join("policy-alias");
        fs::hard_link(&signer, &alias).unwrap();
        let variants = variants(&root);
        let mut values: Value = serde_json::from_slice(&fs::read(&variants).unwrap()).unwrap();
        let output = root.join("review.tar.gz");
        for policy in [&signer, &alias] {
            values[0]["policy"] = json!(policy);
            fs::write(&variants, serde_json::to_vec(&values).unwrap()).unwrap();
            assert!(
                store
                    .bundle(&[record.id.clone()], &variants, &output)
                    .is_err()
            );
            assert!(!output.exists());
        }
        fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&signer, &alias).unwrap();
        values[0]["policy"] = json!(alias);
        fs::write(&variants, serde_json::to_vec(&values).unwrap()).unwrap();
        assert!(
            store
                .bundle(&[record.id.clone()], &variants, &output)
                .is_err()
        );
        values[0]["policy"] = Value::Null;
        fs::write(&variants, serde_json::to_vec(&values).unwrap()).unwrap();
        assert!(
            store
                .bundle(&[record.id.clone()], &variants, &variants)
                .is_err()
        );
        let source_alias = root.join("source-alias");
        std::os::unix::fs::symlink(&snapshot.repository, &source_alias).unwrap();
        assert!(
            store
                .bundle(
                    &[record.id.clone()],
                    &variants,
                    &source_alias.join("bundle")
                )
                .is_err()
        );
        std::os::unix::fs::symlink(&signer, &output).unwrap();
        assert!(store.bundle(&[record.id], &variants, &output).is_err());
        assert_eq!(fs::read(signer).unwrap(), b"private signer state");
    }
}
