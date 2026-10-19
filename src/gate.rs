use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use fs2::FileExt;
use regex::RegexSet;
use serde::{Deserialize, Serialize};

use crate::change::{self, Choices, Conflict, ConflictFile, Hunks, Piece, Region, Unmerged, short};
use crate::model::{Api, Model};
use crate::pijul::{LogEntry, Pijul, Signer};

pub struct Settings {
    pub repo: PathBuf,
    pub inbox: String,
    pub main: String,
    pub model_url: String,
    pub model: String,
    pub model_api: Api,
    pub policy: String,
    protected: Vec<String>,
    max_change_chars: usize,
    timeout: Duration,
}

impl Settings {
    pub fn from_env(repo: PathBuf, inbox: String, main: String) -> Result<Self> {
        let timeout: f64 = number("PATCHGATE_TIMEOUT", 300.0)?;
        Ok(Self {
            repo,
            inbox,
            main,
            model_url: env::var("PATCHGATE_MODEL_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:1234/v1".into()),
            model: env::var("PATCHGATE_MODEL").unwrap_or_else(|_| "google/gemma-4-e4b".into()),
            model_api: env::var("PATCHGATE_MODEL_API")
                .unwrap_or_else(|_| "openai".into())
                .parse()?,
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
        })
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

#[derive(Clone, Copy, PartialEq, Eq)]
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

#[derive(Deserialize, Serialize)]
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
    pub user: Option<String>,
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
            user: None,
            conflict: false,
            merge: None,
            for_hashes: Vec::new(),
            files: Vec::new(),
        }
    }
}

pub struct Ledger {
    directory: PathBuf,
    path: PathBuf,
}

impl Ledger {
    fn new(repo: &Path) -> Self {
        let directory = repo.join(".pijul/patchgate");
        let path = directory.join("ledger.jsonl");
        Self { directory, path }
    }

    pub fn history(&self) -> Result<Vec<Record>> {
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
        fs::create_dir_all(&self.directory)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    fn lock(&self) -> Result<File> {
        fs::create_dir_all(&self.directory)?;
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
    signer: Signer,
    model: Model,
    protected: RegexSet,
    changes: HashMap<String, Rc<str>>,
    policy: Option<String>,
}

impl Gate {
    pub fn new(settings: Settings) -> Result<Self> {
        let ledger = Ledger::new(&settings.repo);
        let protected = RegexSet::new(
            std::iter::once(&settings.policy)
                .chain(&settings.protected)
                .map(|pattern| crate::protected::pattern_regex(pattern)),
        )?;
        Ok(Self {
            pijul: Pijul::new(settings.repo.clone()),
            signer: Signer::new(ledger.directory.clone()),
            model: Model::new(
                &settings.model_url,
                &settings.model,
                settings.timeout,
                settings.model_api,
            )?,
            protected,
            settings,
            ledger,
            changes: HashMap::new(),
            policy: None,
        })
    }

    fn change_text(&mut self, hash: &str) -> Result<Rc<str>> {
        if let Some(text) = self.changes.get(hash) {
            return Ok(Rc::clone(text));
        }
        let text: Rc<str> = self.pijul.change(hash)?.into();
        self.changes.insert(hash.into(), Rc::clone(&text));
        Ok(text)
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
        self.walk(false, |_| {})
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

    pub fn review(&mut self, report: impl FnMut(&Item)) -> Result<Vec<Item>> {
        let _lock = self.ledger.lock()?;
        self.policy = None;
        self.walk(true, report)
    }

    pub fn decide_by_hand(
        &mut self,
        prefix: &str,
        decision: &str,
        reason: Option<&str>,
    ) -> Result<Item> {
        let _lock = self.ledger.lock()?;
        let main = self.pijul.hashes(&self.settings.main)?;
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
        if main.contains(&entry.hash) {
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
            record.user = Some(user.clone());
            record
        };
        if decision != "accept" {
            self.ledger.append(&record(&item.hash))?;
            item.state = State::from_decision(decision);
            return Ok(item);
        }
        let hashes = self.with_conflicting_dependencies(&item.hash, &main, &inbox)?;
        match self.land(&hashes, &main) {
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
                for hash in &hashes {
                    self.ledger.append(&record(hash))?;
                }
                if let Some(merge) = &merge {
                    self.ledger.append(merge)?;
                }
                item.state = State::Accepted;
                item.merge = merge;
                item.note = note;
                self.check_extra(&extra)?;
                Ok(item)
            }
        }
    }

    fn with_conflicting_dependencies(
        &mut self,
        hash: &str,
        main: &HashSet<String>,
        inbox: &[LogEntry],
    ) -> Result<Vec<String>> {
        let records = self.ledger.latest()?;
        let mut needed = HashSet::new();
        let mut todo: Vec<_> = change::dependencies(&self.change_text(hash)?)
            .into_iter()
            .filter(|hash| !main.contains(hash))
            .collect();
        while let Some(dependency) = todo.pop() {
            if needed.insert(dependency.clone()) {
                todo.extend(
                    change::dependencies(&self.change_text(&dependency)?)
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

    fn walk(&mut self, decide: bool, mut report: impl FnMut(&Item)) -> Result<Vec<Item>> {
        let mut main = self.pijul.hashes(&self.settings.main)?;
        let records = self.ledger.latest()?;
        let mut states = HashMap::new();
        let mut items = Vec::new();
        for entry in self.pijul.log(&self.settings.inbox)? {
            if main.contains(&entry.hash) {
                continue;
            }
            let mut item = Item::from(entry);
            if let Some(record) = records.get(&item.hash) {
                item.state = State::from_decision(&record.decision);
                item.reason = record.reason.clone();
            } else {
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
                } else if decide {
                    self.decide_and_land(&mut item, &text, &mut main)?;
                    report(&item);
                }
            }
            states.insert(item.hash.clone(), item.state);
            items.push(item);
        }
        Ok(items)
    }

    fn decide_and_land(
        &mut self,
        item: &mut Item,
        text: &str,
        main: &mut HashSet<String>,
    ) -> Result<()> {
        let mut record = self.decide(item, text)?;
        let mut extra = BTreeSet::new();
        if record.decision == "accept" {
            match self.land(std::slice::from_ref(&item.hash), main) {
                Err(error) => {
                    let problem = error.downcast::<Unmerged>()?;
                    record.decision = "escalate".into();
                    record.by = "gate".into();
                    record.conflict = true;
                    record.reason = format!(
                        "The change conflicts with {}, and patchgate did not merge it. {problem} To merge it by hand, edit the conflict in {}, record the result, and run: patchgate accept <hash of the result>",
                        self.settings.main, self.settings.inbox
                    );
                }
                Ok(Landing {
                    main: after,
                    extra: unexpected,
                    merge,
                    note,
                }) => {
                    *main = after;
                    extra = unexpected;
                    record.merge = merge.as_ref().map(|merge| merge.hash.clone());
                    item.merge = merge;
                    item.note = note;
                }
            }
        }
        self.ledger.append(&record)?;
        if let Some(merge) = &item.merge {
            self.ledger.append(merge)?;
        }
        item.state = if record.decision == "accept" {
            State::Accepted
        } else {
            State::from_decision(&record.decision)
        };
        item.reason = record.reason;
        item.decided = true;
        self.check_extra(&extra)
    }

    fn decide(&mut self, item: &Item, text: &str) -> Result<Record> {
        let mut record = Record::new(
            item.hash.clone(),
            item.message.clone(),
            "escalate",
            "gate",
            String::new(),
        );
        if change::is_root_change(text) {
            record.decision = "accept".into();
            record.reason = "The Pijul root change has no content.".into();
            return Ok(record);
        }
        let touched: Vec<_> = change::touched_paths(&item.paths, text)
            .into_iter()
            .filter(|path| self.protected.is_match(path))
            .collect();
        if !touched.is_empty() {
            record.reason = format!(
                "The change touches protected paths ({}). A human must accept or reject it.",
                touched.join(", ")
            );
            return Ok(record);
        }
        let length = text.chars().count();
        if length > self.settings.max_change_chars {
            record.reason = format!(
                "The change text has {length} characters. The model limit is {}. A human must review it.",
                self.settings.max_change_chars
            );
            return Ok(record);
        }
        if self.policy.is_none() {
            self.policy = self
                .pijul
                .read_file(&self.settings.main, &self.settings.policy)?;
        }
        let policy = self.policy.as_deref().ok_or_else(|| anyhow!(
            "{} has no {}, so the model has no policy. Accept the change that adds {}: patchgate accept <hash>",
            self.settings.main, self.settings.policy, self.settings.policy
        ))?;
        match self.model.review(policy, &item.hash, text)? {
            Some(verdict) => {
                record.decision = verdict.decision;
                record.summary = verdict.summary;
                record.reason = verdict.reason;
                record.by = "model".into();
                record.model = Some(self.settings.model.clone());
            }
            None => {
                record.reason = format!(
                    "The reply of {} is not a valid verdict.",
                    self.settings.model
                )
            }
        }
        Ok(record)
    }

    fn land(&mut self, hashes: &[String], main: &HashSet<String>) -> Result<Landing> {
        let log_paths: HashMap<_, _> = self
            .pijul
            .log(&self.settings.inbox)?
            .into_iter()
            .map(|entry| (entry.hash, entry.paths))
            .collect();
        let mut paths = BTreeSet::new();
        for hash in hashes {
            paths.extend(change::touched_paths(
                log_paths.get(hash).map(Vec::as_slice).unwrap_or_default(),
                &self.change_text(hash)?,
            ));
        }
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
        let mut reported = Vec::new();
        for hash in hashes {
            let (_, stderr) = scratch.call([Path::new("apply"), &self.pijul.change_file(hash)])?;
            reported.extend(change::conflict_report(&stderr));
        }
        let mut remaining = scratch.conflicts()?;
        paths.extend(
            reported
                .iter()
                .chain(&remaining)
                .filter(|r| !r.path.is_empty())
                .map(|r| r.path.clone()),
        );
        let files = Self::conflicted_files(&scratch, &paths)?;
        let merge = if remaining.is_empty() && files.is_empty() {
            None
        } else {
            remaining.extend(reported.into_iter().filter(|r| files.contains_key(&r.path)));
            Some(self.merge(&scratch, hashes, &remaining, &files)?)
        };
        // Apply the candidate and its resolution in one Pijul transaction.
        let mut args = vec![
            std::ffi::OsString::from("apply"),
            "--channel".into(),
            self.settings.main.clone().into(),
        ];
        args.extend(hashes.iter().map(std::ffi::OsString::from));
        let mut expected: HashSet<&str> = hashes.iter().map(String::as_str).collect();
        if let Some(merge) = &merge {
            args.push(scratch.change_file(&merge.hash).into_os_string());
            expected.insert(&merge.hash);
        }
        self.pijul.run(args)?;
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
            .filter(|hash| !main.contains(*hash) && !expected.contains(hash.as_str()))
            .cloned()
            .collect();
        let note = match &merge {
            Some(record) => match self.pijul.apply(&record.hash, &self.settings.inbox) {
                Ok(()) => String::new(),
                Err(error) => format!(
                    "The merge is not in {}. {error} When the working copy is clean, run: pijul apply --channel {} {}",
                    self.settings.inbox,
                    self.settings.inbox,
                    short(&record.hash)
                ),
            },
            None => String::new(),
        };
        Ok(Landing {
            main: after,
            extra,
            merge,
            note,
        })
    }

    fn conflicted_files(
        scratch: &Pijul,
        paths: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, ConflictFile>> {
        let mut found = BTreeMap::new();
        for path in paths {
            if !scratch.repo.join(path).is_file() {
                continue;
            }
            let entries: Vec<serde_json::Value> = scratch
                .run(["credit", "--output-format", "json", path])
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
        report: &[Conflict],
        files: &BTreeMap<String, ConflictFile>,
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
                let mut labels: Vec<_> = choices.iter().map(|(label, _)| label.as_str()).collect();
                labels.push("escalate");
                let result = self.model.merge(&prompt, &labels)?.ok_or_else(|| {
                    Unmerged(format!(
                        "The reply of {} for {path} is not one of the choices.",
                        self.settings.model
                    ))
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
            fs::write(scratch.repo.join(path), text)?;
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
        record.model = Some(self.settings.model.clone());
        record.for_hashes = hashes.to_vec();
        record.files = merged.into_keys().collect();
        Ok(record)
    }

    fn concurrent(&mut self, path: &str, hashes: &[String]) -> Result<Vec<String>> {
        let mut known = HashSet::new();
        let mut todo = hashes.to_vec();
        while let Some(hash) = todo.pop() {
            if known.insert(hash.clone()) {
                todo.extend(change::dependencies(&self.change_text(&hash)?));
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
