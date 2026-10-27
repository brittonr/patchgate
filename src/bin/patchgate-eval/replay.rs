use super::support::*;
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Component;
use std::sync::Arc;

#[path = "replay_gate.rs"]
mod release_gate;

use crate::case_metadata;
use crate::case_metadata::{NoteRecord, SeenRecord};

#[derive(Args, Default)]
pub struct ReplayArgs {
    #[arg(required_unless_present = "bundle", conflicts_with = "bundle")]
    pub manifest: Option<PathBuf>,
    #[arg(
        long,
        required_unless_present = "manifest",
        conflicts_with = "manifest"
    )]
    pub bundle: Option<PathBuf>,
    #[arg(long)]
    pub report: Option<PathBuf>,
    #[arg(long)]
    pub gate: bool,
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    #[arg(long)]
    pub max_unsafe_acceptances: Option<usize>,
    #[arg(long)]
    pub max_label_mismatches: Option<usize>,
    #[arg(long)]
    pub max_regressions: Option<usize>,
    #[arg(long, value_parser = release_gate::parse_requirement)]
    pub min_policy_rule: Vec<release_gate::Requirement>,
    #[arg(long, value_parser = release_gate::parse_requirement)]
    pub min_conflict_kind: Vec<release_gate::Requirement>,
    #[arg(long)]
    pub bundle_signature: Option<PathBuf>,
    #[arg(long)]
    pub baseline_signature: Option<PathBuf>,
    #[arg(long)]
    pub allowed_signers: Option<PathBuf>,
    #[arg(long)]
    pub revoked_keys: Option<PathBuf>,
    #[arg(long)]
    pub release_repo: Option<PathBuf>,
    #[arg(long, requires = "release_repo")]
    pub release_main: Option<String>,
    #[arg(long)]
    pub signer: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    repository: PathBuf,
    #[serde(default = "main_channel")]
    main: String,
    #[serde(default = "inbox_channel")]
    inbox: String,
    cases: Vec<Case>,
    variants: Vec<Variant>,
    #[serde(default)]
    configuration: Configuration,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Configuration {
    policy_path: String,
    protected: Vec<String>,
    max_change_chars: usize,
    timeout_seconds: f64,
    check_timeout_seconds: f64,
    max_review_requests: usize,
    review_timeout_seconds: f64,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            policy_path: "POLICY.md".into(),
            protected: Vec::new(),
            max_change_chars: 8000,
            timeout_seconds: 300.0,
            check_timeout_seconds: 900.0,
            max_review_requests: 128,
            review_timeout_seconds: 900.0,
        }
    }
}

fn main_channel() -> String {
    "main".into()
}

fn inbox_channel() -> String {
    "inbox".into()
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    base: Vec<String>,
    candidate: String,
    expected: Label,
    #[serde(default)]
    configuration: Option<Configuration>,
    #[serde(default)]
    snapshot: Option<Value>,
    #[serde(default)]
    labels: Vec<Value>,
    #[serde(default)]
    tags: Vec<TagRecord>,
    #[serde(default)]
    notes: Vec<NoteRecord>,
    #[serde(default)]
    seen: Vec<SeenRecord>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TagRecord {
    user: String,
    time: String,
    reason: String,
    policy_rules: Vec<String>,
    conflict_kinds: Vec<String>,
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag.as_bytes()[0].is_ascii_lowercase()
        && tag.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn validate_tag_history(tags: &[TagRecord]) -> Result<()> {
    for record in tags {
        ensure!(
            [&record.user, &record.reason]
                .iter()
                .all(|value| { !value.trim().is_empty() && !value.chars().any(char::is_control) })
                && chrono::DateTime::parse_from_rfc3339(&record.time).is_ok(),
            "Human tags need a valid user, time, and explicit reason."
        );
        for set in [&record.policy_rules, &record.conflict_kinds] {
            let mut unique = BTreeSet::new();
            ensure!(
                set.iter().all(|tag| valid_tag(tag) && unique.insert(tag)),
                "Human tags must use unique lowercase identifiers."
            );
        }
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
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureSnapshot {
    repository: PathBuf,
    main: String,
    inbox: String,
    main_state: Option<String>,
    base: Vec<String>,
    candidate: String,
    policy_path: String,
    policy_sha256: Option<String>,
    configuration: Value,
}

fn capture_identity(case: &Case, manifest: &Manifest) -> Result<Option<String>> {
    let Some(snapshot) = &case.snapshot else {
        return Ok(None);
    };
    let snapshot = CaptureSnapshot::deserialize(snapshot)
        .map_err(|_| anyhow!("The case snapshot has invalid fields."))?;
    let configuration = Configuration::deserialize(&snapshot.configuration["values"])
        .map_err(|_| anyhow!("The captured settings are not valid."))?;
    ensure!(
        snapshot.repository.is_absolute()
            && snapshot.base == case.base
            && snapshot.candidate == case.candidate
            && snapshot.main == manifest.main
            && snapshot.inbox == manifest.inbox
            && snapshot.policy_path == configuration.policy_path
            && configuration
                == *case
                    .configuration
                    .as_ref()
                    .unwrap_or(&manifest.configuration)
            && snapshot
                .policy_sha256
                .as_deref()
                .is_none_or(crate::release_policy::valid_digest),
        "The case snapshot differs from its replay bindings."
    );
    let bindings = (
        snapshot.repository,
        snapshot.main,
        snapshot.inbox,
        snapshot.main_state,
        snapshot.base,
        snapshot.candidate,
        snapshot.policy_path,
        snapshot.policy_sha256,
        configuration,
    );
    Ok(Some(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&bindings)?)
    )))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Label {
    Accept,
    Reject,
    Escalate,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Variant {
    id: String,
    model_url: String,
    model: String,
    api: String,
    revision: String,
    policy: Option<PathBuf>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Comparison {
    case_id: String,
    variant_id: String,
    candidate: String,
    base: Vec<String>,
    expected: Label,
    actual: Option<Label>,
    decision_actor: Option<String>,
    outcome: String,
    unsafe_acceptance: Option<bool>,
    escalation: Option<bool>,
    correct: Option<bool>,
    elapsed_seconds: f64,
    revision: String,
    api: String,
    model: String,
    execution_error: Option<String>,
    cli_executed: bool,
    policy_change: Option<String>,
    exit_code: Option<i32>,
    stderr: String,
    evidence: Option<Value>,
    configuration: Configuration,
    snapshot: Option<Value>,
    labels: Vec<Value>,
    #[serde(default)]
    tags: Vec<TagRecord>,
    #[serde(default)]
    notes: Vec<NoteRecord>,
    #[serde(default)]
    seen: Vec<SeenRecord>,
}

impl Comparison {
    fn new(case: &Case, variant: &Variant, default: &Configuration) -> Self {
        Self {
            case_id: case.id.clone(),
            variant_id: variant.id.clone(),
            candidate: case.candidate.clone(),
            base: case.base.clone(),
            expected: case.expected,
            actual: None,
            decision_actor: None,
            outcome: "execution_error".into(),
            unsafe_acceptance: None,
            escalation: None,
            correct: None,
            elapsed_seconds: 0.0,
            revision: variant.revision.clone(),
            api: variant.api.clone(),
            model: variant.model.clone(),
            execution_error: None,
            cli_executed: false,
            policy_change: None,
            exit_code: None,
            stderr: String::new(),
            evidence: None,
            configuration: case.configuration.as_ref().unwrap_or(default).clone(),
            snapshot: case.snapshot.clone(),
            labels: case.labels.clone(),
            tags: case.tags.clone(),
            notes: case.notes.clone(),
            seen: case.seen.clone(),
        }
    }

    fn decision(&mut self, actual: Option<Label>, outcome: String) {
        self.actual = actual;
        self.outcome = outcome;
        self.unsafe_acceptance =
            actual.map(|label| label == Label::Accept && self.expected != Label::Accept);
        self.escalation = actual.map(|label| label == Label::Escalate);
        self.correct = actual.map(|label| label == self.expected);
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    variant_id: String,
    comparisons: usize,
    verdicts: usize,
    unsafe_acceptances: usize,
    escalations: usize,
    escalation_rate: Option<f64>,
    label_mismatches: usize,
    blocked_or_no_decision: usize,
    infrastructure_errors: usize,
    latency: Latency,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Latency {
    samples: usize,
    total_seconds: f64,
    mean_seconds: Option<f64>,
    median_seconds: Option<f64>,
    p95_seconds: Option<f64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: u32,
    manifest: PathBuf,
    repository: PathBuf,
    main: String,
    inbox: String,
    configuration: Configuration,
    variants: Vec<Variant>,
    cases: Vec<Case>,
    comparisons: Vec<Comparison>,
    summaries: Vec<Summary>,
    infrastructure_errors: usize,
    authorizes_acceptance: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gate: Option<release_gate::GateResult>,
    signatures: SignatureEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    release_policy: Option<crate::release_policy::Evidence>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignatureEvidence {
    strict: bool,
    bundle: Option<crate::artifact::Verified>,
    baseline: Option<crate::artifact::Verified>,
}

fn validate_trust_consistency(
    bundle: Option<&crate::artifact::Verified>,
    baseline: Option<&crate::artifact::Verified>,
) -> Result<()> {
    if let (Some(bundle), Some(baseline)) = (bundle, baseline) {
        ensure!(
            bundle.identity == baseline.identity
                && bundle.allowed_signers_sha256 == baseline.allowed_signers_sha256
                && bundle.revoked_keys_sha256 == baseline.revoked_keys_sha256,
            "The report artifacts use different trust inputs."
        );
    }
    Ok(())
}

fn strict_signatures(args: &ReplayArgs) -> Result<bool> {
    let strict = args.bundle_signature.is_some()
        || args.baseline_signature.is_some()
        || args.allowed_signers.is_some()
        || args.signer.is_some()
        || args.revoked_keys.is_some();
    if strict {
        ensure!(
            args.bundle.is_some() || args.baseline.is_some(),
            "Signature options need a bundle or baseline input."
        );
        ensure!(
            args.allowed_signers.is_some()
                && args
                    .signer
                    .as_ref()
                    .is_some_and(|identity| !identity.trim().is_empty()),
            "Signature mode needs an explicit allowed-signers file and signer identity."
        );
        ensure!(
            args.bundle.is_some() == args.bundle_signature.is_some()
                && args.baseline.is_some() == args.baseline_signature.is_some(),
            "Signature mode needs one signature for each selected bundle and baseline."
        );
    }
    Ok(strict)
}

fn signature_trust(args: &ReplayArgs, signature: &Path) -> crate::artifact::Trust {
    crate::artifact::Trust {
        signature: signature.into(),
        allowed_signers: args
            .allowed_signers
            .as_ref()
            .expect("validated trust")
            .clone(),
        identity: args.signer.as_ref().expect("validated trust").clone(),
        revoked_keys: args.revoked_keys.clone(),
    }
}

fn load_release_policy(args: &ReplayArgs) -> Result<crate::release_policy::Loaded> {
    ensure!(
        args.release_main.is_none() || args.release_repo.is_some(),
        "An explicit release channel needs an explicit release repository."
    );
    if let Some(repository) = &args.release_repo {
        let loaded = crate::release_policy::load(
            repository,
            args.release_main.as_deref().unwrap_or("main"),
        )?;
        ensure!(
            loaded.policy.is_some(),
            "The explicit release repository has no recorded release policy."
        );
        return Ok(loaded);
    }
    let cwd = std::env::current_dir().context("Read the caller directory.")?;
    caller_release_policy(&cwd)
}

fn caller_release_policy(cwd: &Path) -> Result<crate::release_policy::Loaded> {
    for repository in cwd.ancestors() {
        match fs::symlink_metadata(repository.join(".pijul")) {
            Ok(_) => return crate::release_policy::load(repository, "main"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => bail!("Cannot inspect the caller repository metadata."),
        }
    }
    Ok(crate::release_policy::Loaded {
        policy: None,
        evidence: None,
    })
}

fn validate_policy_artifact(
    policy: &crate::release_policy::Policy,
    verified: &crate::artifact::Verified,
) -> Result<()> {
    let trust = &policy.signatures;
    ensure!(
        trust
            .signer
            .as_ref()
            .is_none_or(|identity| identity == &verified.identity)
            && trust
                .allowed_signers_sha256
                .as_ref()
                .is_none_or(|digest| digest == &verified.allowed_signers_sha256)
            && trust
                .revoked_keys_sha256
                .as_ref()
                .is_none_or(|digest| Some(digest) == verified.revoked_keys_sha256.as_ref()),
        "The artifact trust inputs differ from the trusted release policy."
    );
    Ok(())
}

fn baseline_input_pinned(
    path: &Path,
    trust: Option<&crate::artifact::Trust>,
    policy: Option<&crate::release_policy::Policy>,
) -> Result<(release_gate::Baseline, Option<crate::artifact::Verified>)> {
    let bytes = release_gate::baseline_bytes(path)?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if let Some(expected) = policy.and_then(|policy| policy.baseline_sha256.as_ref()) {
        ensure!(
            &digest == expected,
            "The baseline bytes differ from the trusted release policy."
        );
    }
    let verified = trust
        .map(|trust| {
            crate::artifact::verify_digest(crate::artifact::Kind::Baseline, &digest, trust)
        })
        .transpose()?;
    if let (Some(policy), Some(verified)) = (policy, &verified) {
        validate_policy_artifact(policy, verified)?;
    }
    Ok((release_gate::read_baseline(&bytes)?, verified))
}

#[cfg(test)]
fn baseline_input(
    path: &Path,
    trust: Option<&crate::artifact::Trust>,
) -> Result<(release_gate::Baseline, Option<crate::artifact::Verified>)> {
    baseline_input_pinned(path, trust, None)
}

pub(super) fn validate_promotion_report(bytes: &[u8]) -> Result<()> {
    let report: Report = serde_json::from_slice(bytes)
        .map_err(|_| anyhow!("The promotion report has invalid JSON or fields."))?;
    release_gate::validate_report(&report)
}

#[cfg(test)]
pub(super) fn successful_promotion_report() -> Vec<u8> {
    let manifest: Manifest = serde_json::from_value(json!({
        "schema_version": 1,
        "repository": "/captured/source",
        "cases": [{"id": "case", "base": [], "candidate": "A".repeat(53), "expected": "reject"}],
        "variants": [{"id": "model", "model_url": "http://localhost:8080", "model": "model", "api": "openai", "revision": "revision"}]
    })).unwrap();
    let mut row = Comparison::new(
        &manifest.cases[0],
        &manifest.variants[0],
        &manifest.configuration,
    );
    row.decision(Some(Label::Reject), "verdict".into());
    row.cli_executed = true;
    row.exit_code = Some(0);
    row.evidence = Some(json!({
        "schema_version": 1, "dry_run": true, "authorizes_acceptance": false,
        "records": [{"hash": row.candidate, "decision": row.actual}], "items": [],
        "configuration": {"values": row.configuration},
    }));
    let comparisons = vec![row];
    let args = ReplayArgs {
        gate: true,
        ..ReplayArgs::default()
    };
    let gate = release_gate::evaluate(&args, &manifest, &manifest.repository, &comparisons, None);
    let report = Report {
        schema_version: 1,
        manifest: "/captured/manifest.json".into(),
        repository: manifest.repository,
        main: manifest.main,
        inbox: manifest.inbox,
        configuration: manifest.configuration,
        summaries: manifest
            .variants
            .iter()
            .map(|variant| summarize(&variant.id, &comparisons))
            .collect(),
        variants: manifest.variants,
        cases: manifest.cases,
        comparisons,
        infrastructure_errors: 0,
        authorizes_acceptance: false,
        bundle_sha256: None,
        gate,
        signatures: SignatureEvidence::default(),
        release_policy: None,
    };
    serde_json::to_vec(&report).unwrap()
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 53
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
}

fn validate_configuration(configuration: &Configuration) -> Result<()> {
    ensure!(
        std::time::Duration::try_from_secs_f64(configuration.timeout_seconds).is_ok()
            && std::time::Duration::try_from_secs_f64(configuration.check_timeout_seconds).is_ok(),
        "Replay time limits must be finite and nonnegative."
    );
    ensure!(
        configuration.max_review_requests > 0,
        "The review request limit must be positive."
    );
    let seconds = configuration.review_timeout_seconds;
    ensure!(
        seconds.is_finite()
            && seconds > 0.0
            && std::time::Duration::try_from_secs_f64(seconds).is_ok_and(|duration| {
                !duration.is_zero() && Instant::now().checked_add(duration).is_some()
            }),
        "The review time limit must be finite, positive, and within the clock range."
    );
    let policy = normalize_policy_path(Path::new(&configuration.policy_path))?;
    ensure!(
        !policy.as_os_str().is_empty() && !policy.starts_with(".pijul"),
        "The replay policy must name a relative file outside .pijul."
    );
    ensure!(
        configuration.protected.iter().all(|pattern| {
            !pattern.trim().is_empty()
                && !pattern.contains(',')
                && !pattern.chars().any(char::is_control)
        }),
        "Protected path patterns must be nonempty and cannot contain commas or control characters."
    );
    Ok(())
}

fn validate(manifest: &Manifest, policy_path: &str) -> Result<()> {
    validate_configuration(&manifest.configuration)?;
    ensure!(
        manifest.schema_version == 1,
        "The manifest schema_version must be 1."
    );
    ensure!(
        !manifest.cases.is_empty(),
        "The manifest cases list is empty."
    );
    ensure!(
        !manifest.variants.is_empty(),
        "The manifest variants list is empty."
    );
    for channel in [&manifest.main, &manifest.inbox] {
        ensure!(
            !channel.trim().is_empty()
                && !channel.starts_with('-')
                && !channel.chars().any(char::is_control),
            "The channel name is not valid."
        );
    }
    ensure!(
        manifest.main != manifest.inbox,
        "Main and inbox must use different channels."
    );
    let policy = normalize_policy_path(Path::new(policy_path))?;
    ensure!(
        !policy.as_os_str().is_empty() && !policy.starts_with(".pijul"),
        "PATCHGATE_POLICY must name a relative file outside .pijul."
    );
    let mut ids = BTreeSet::new();
    let mut captures = BTreeMap::new();
    for case in &manifest.cases {
        validate_configuration(
            case.configuration
                .as_ref()
                .unwrap_or(&manifest.configuration),
        )?;
        validate_tag_history(&case.tags)?;
        case_metadata::validate_histories(&case.notes, &case.seen)?;
        ensure!(
            (case.notes.is_empty() && case.seen.is_empty()) || case.snapshot.is_some(),
            "Human notes and seen records need a captured snapshot."
        );
        if let Some(identity) = capture_identity(case, manifest)? {
            if let Some((tags, labels, notes, seen, expected)) =
                captures.insert(identity, (&case.tags, &case.labels, &case.notes, &case.seen, case.expected))
            {
                ensure!(
                    tags == &case.tags && labels == &case.labels && notes == &case.notes
                        && seen == &case.seen && expected == case.expected,
                    "Duplicate captures must use the same human metadata and labels."
                );
            }
        }
        for label in &case.labels {
            ensure!(
                label["user"]
                    .as_str()
                    .is_some_and(|user| !user.trim().is_empty())
                    && label["reason"]
                        .as_str()
                        .is_some_and(|reason| !reason.trim().is_empty())
                    && label["time"]
                        .as_str()
                        .is_some_and(|time| chrono::DateTime::parse_from_rfc3339(time).is_ok())
                    && matches!(
                        label["expected"].as_str(),
                        Some("accept" | "reject" | "escalate")
                    ),
                "Each case label needs a user, time, expected value, and explicit reason."
            );
        }
        if case.snapshot.is_some() {
            ensure!(
                case.labels
                    .last()
                    .is_some_and(|label| label["expected"] == json!(case.expected)),
                "The captured case needs its explicit human label."
            );
        }
        ensure!(
            !case.id.trim().is_empty() && ids.insert(&case.id),
            "Case IDs must be nonempty and unique."
        );
        ensure!(
            valid_hash(&case.candidate),
            "Case {} has an invalid candidate hash.",
            case.id
        );
        let mut base = BTreeSet::new();
        for hash in &case.base {
            ensure!(
                valid_hash(hash),
                "Case {} has an invalid base hash.",
                case.id
            );
            ensure!(
                base.insert(hash),
                "Case {} has a duplicate base hash.",
                case.id
            );
        }
        ensure!(
            !base.contains(&case.candidate),
            "Case {} contains its candidate in base.",
            case.id
        );
    }
    ids.clear();
    for variant in &manifest.variants {
        ensure!(
            !variant.id.trim().is_empty() && ids.insert(&variant.id),
            "Variant IDs must be nonempty and unique."
        );
        ensure!(
            !variant.model.trim().is_empty(),
            "Variant {} has no model.",
            variant.id
        );
        ensure!(
            !variant.revision.trim().is_empty(),
            "Variant {} has no explicit checkpoint revision.",
            variant.id
        );
        ensure!(
            matches!(variant.api.as_str(), "openai" | "systemone"),
            "Variant {} has an invalid API.",
            variant.id
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
            "Variant {} requires an HTTP or HTTPS model URL.",
            variant.id
        );
    }
    Ok(())
}

fn change_file(root: &Path, hash: &str) -> PathBuf {
    root.join(".pijul/changes")
        .join(&hash[..2])
        .join(format!("{}.change", &hash[2..]))
}

fn plain_file(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut path = root.to_owned();
    for part in relative.components() {
        let Component::Normal(part) = part else {
            bail!("The file path is not relative.");
        };
        path.push(part);
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "The file path contains a symbolic link: {}",
            path.display()
        );
    }
    ensure!(
        fs::metadata(&path)?.is_file(),
        "The path is not a regular file: {}",
        path.display()
    );
    Ok(path)
}

fn copy_changes(source: &Path, repo: &Repo, case: &Case) -> Result<()> {
    for hash in case.base.iter().chain(std::iter::once(&case.candidate)) {
        let relative = change_file(Path::new(""), hash);
        let source_file = plain_file(source, &relative)
            .with_context(|| format!("The native change {hash} is absent or unsafe."))?;
        let target = repo.path.join(relative);
        fs::create_dir_all(target.parent().context("The change directory is absent.")?)?;
        match fs::hard_link(&source_file, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                fs::copy(source_file, target)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn init_repo(path: PathBuf, channel: &str, env: &Arc<Env>) -> Result<Repo> {
    fs::create_dir_all(&path)?;
    let repo = Repo {
        path,
        env: Arc::clone(env),
    };
    repo.pijul(&["init", "--channel", channel])?;
    Ok(repo)
}

// Only numbered entries in the native Dependencies section are prerequisites.
fn dependencies(text: &str) -> Result<Vec<String>> {
    let mut inside = false;
    let mut dependencies = Vec::new();
    for line in text.lines() {
        if line.starts_with("# ") {
            inside = line.trim_end() == "# Dependencies";
        } else if inside {
            let mut words = line.split_whitespace();
            let Some(index) = words
                .next()
                .and_then(|word| word.strip_prefix('['))
                .and_then(|word| word.strip_suffix(']'))
            else {
                continue;
            };
            if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let hash = words
                .next()
                .context("A native prerequisite hash is absent.")?;
            ensure!(valid_hash(hash), "A native prerequisite hash is not valid.");
            dependencies.push(hash.to_owned());
        }
    }
    Ok(dependencies)
}

fn validate_order(case: &Case, dependencies: &BTreeMap<String, Vec<String>>) -> Result<()> {
    let mut applied = BTreeSet::new();
    for hash in case.base.iter().chain(std::iter::once(&case.candidate)) {
        for dependency in dependencies
            .get(hash)
            .context("The native prerequisites are absent.")?
        {
            ensure!(
                applied.contains(dependency),
                "Case {} requires {} before {}. The declared base does not supply it in order.",
                case.id,
                dependency,
                hash
            );
        }
        applied.insert(hash.clone());
    }
    Ok(())
}

fn exact_hashes(repo: &Repo, channel: &str, expected: &BTreeSet<String>) -> Result<()> {
    ensure!(
        repo.hashes(channel)? == *expected,
        "Channel {channel} differs from the declared native changes."
    );
    Ok(())
}

fn reconstruct(repo: &Repo, case: &Case, main: &str) -> Result<()> {
    let mut expected = BTreeSet::new();
    for hash in &case.base {
        let file = change_file(&repo.path, hash);
        repo.pijul(&[
            "apply",
            "--channel",
            main,
            file.to_str()
                .context("The native change path is not UTF-8.")?,
        ])?;
        expected.insert(hash.clone());
        exact_hashes(repo, main, &expected)?;
    }
    exact_hashes(repo, main, &expected)
}

fn candidate_inbox(repo: &Repo, case: &Case, main: &str, inbox: &str) -> Result<()> {
    repo.pijul(&["fork", "--channel", main, inbox])?;
    let file = change_file(&repo.path, &case.candidate);
    repo.pijul(&[
        "apply",
        "--channel",
        inbox,
        file.to_str().context("The candidate path is not UTF-8.")?,
    ])?;
    let mut expected = repo.hashes(main)?;
    expected.insert(case.candidate.clone());
    exact_hashes(repo, inbox, &expected)?;
    repo.pijul(&["channel", "switch", inbox])?;
    Ok(())
}

fn normalize_policy_path(path: &Path) -> Result<PathBuf> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                ensure!(result.pop(), "The policy archive path escapes the channel.");
            }
            Component::Normal(name) => result.push(name),
            Component::RootDir | Component::Prefix(_) => {
                bail!("The policy archive path is absolute.");
            }
        }
    }
    Ok(result)
}

enum PolicyMember {
    File(Vec<u8>),
    Link(PathBuf),
    Other,
}

fn policy_archive_member(archive: &Path, target: &Path) -> Result<Option<PolicyMember>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(fs::File::open(archive)?));
    let mut member = None;
    for entry in tar.entries()? {
        let mut entry = entry?;
        if normalize_policy_path(&entry.path()?)? != target {
            continue;
        }
        let kind = entry.header().entry_type();
        member = Some(if kind.is_file() || kind.is_gnu_sparse() {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            PolicyMember::File(bytes)
        } else if kind.is_symlink() || kind.is_hard_link() {
            let link = entry
                .link_name()?
                .context("The policy archive link has no target.")?;
            let link = if kind.is_symlink() {
                normalize_policy_path(
                    &target.parent().unwrap_or(Path::new("")).join(link.as_ref()),
                )?
            } else {
                normalize_policy_path(&link)?
            };
            PolicyMember::Link(link)
        } else {
            PolicyMember::Other
        });
    }
    Ok(member)
}

fn policy_archive_bytes(archive: &Path, path: &str) -> Result<Option<Vec<u8>>> {
    let mut target = normalize_policy_path(Path::new(path))?;
    let mut visited = BTreeSet::new();
    // Use the production archive rules for file links and directory links.
    for _ in 0..128 {
        ensure!(
            visited.insert(target.clone()),
            "The policy archive contains a link cycle."
        );
        match policy_archive_member(archive, &target)? {
            Some(PolicyMember::File(bytes)) => return Ok(Some(bytes)),
            Some(PolicyMember::Link(link)) => target = link,
            Some(PolicyMember::Other) | None => {
                let mut resolved = None;
                for parent in target
                    .ancestors()
                    .skip(1)
                    .filter(|path| !path.as_os_str().is_empty())
                {
                    if let Some(PolicyMember::Link(link)) = policy_archive_member(archive, parent)?
                    {
                        resolved = Some(normalize_policy_path(
                            &link.join(target.strip_prefix(parent)?),
                        )?);
                        break;
                    }
                }
                match resolved {
                    Some(path) => target = path,
                    None => return Ok(None),
                }
            }
        }
    }
    bail!("The policy archive link depth exceeds the channel limit.")
}

fn recorded_policy_digest(repo: &Repo, channel: &str, path: &str) -> Result<Option<String>> {
    let directory = tempfile::tempdir()?;
    let archive = directory.path().join("channel.tar.gz");
    repo.pijul(&[
        "archive",
        "--channel",
        channel,
        "-o",
        archive
            .to_str()
            .context("The policy archive path is not UTF-8.")?,
    ])?;
    Ok(policy_archive_bytes(&archive, path)?.map(|bytes| format!("{:x}", Sha256::digest(bytes))))
}

fn preflight(
    source: &Path,
    origin: &Path,
    root: &Path,
    case: &Case,
    manifest: &Manifest,
    env: &Arc<Env>,
) -> Result<()> {
    let repo = init_repo(root.to_owned(), &manifest.main, env)?;
    copy_changes(source, &repo, case)?;
    let mut prerequisites = BTreeMap::new();
    for hash in case.base.iter().chain(std::iter::once(&case.candidate)) {
        prerequisites.insert(hash.clone(), dependencies(&repo.pijul(&["change", hash])?)?);
    }
    validate_order(case, &prerequisites)?;
    reconstruct(&repo, case, &manifest.main)?;
    if let Some(snapshot) = &case.snapshot {
        ensure!(
            snapshot["repository"] == json!(origin),
            "The captured case belongs to a different source repository."
        );
        let states: Vec<Value> = serde_json::from_str(&repo.pijul(&[
            "log",
            "--channel",
            &manifest.main,
            "--state",
            "--output-format",
            "json",
        ])?)?;
        let state = states
            .first()
            .map(|entry| entry["state"].clone())
            .unwrap_or(Value::Null);
        ensure!(
            state == snapshot["main_state"],
            "The reconstructed native state differs from its capture."
        );
        let configuration = case
            .configuration
            .as_ref()
            .unwrap_or(&manifest.configuration);
        ensure!(
            snapshot["policy_path"] == configuration.policy_path,
            "The captured policy path differs from its replay settings."
        );
        let policy_digest =
            recorded_policy_digest(&repo, &manifest.main, &configuration.policy_path)?;
        ensure!(
            json!(policy_digest) == snapshot["policy_sha256"],
            "The reconstructed policy differs from its capture."
        );
    }
    candidate_inbox(&repo, case, &manifest.main, &manifest.inbox)?;
    Ok(())
}

fn apply_policy(repo: &Repo, main: &str, policy_path: &str, text: &str) -> Result<Option<String>> {
    repo.pijul(&["channel", "switch", main])?;
    let target = repo.path.join(policy_path);
    let mut cursor = repo.path.clone();
    for component in Path::new(policy_path).components() {
        cursor.push(component.as_os_str());
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "The policy path contains a symbolic link."
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    if target.is_file() && fs::read(&target)? == text.as_bytes() {
        return Ok(None);
    }
    repo.write(policy_path, text)?;
    let hash = repo.record("Set the replay policy")?;
    ensure!(valid_hash(&hash), "The policy change hash is not valid.");
    Ok(Some(hash))
}

fn observed_configuration_matches(row: &Comparison) -> bool {
    row.evidence.as_ref().is_some_and(|report| {
        Configuration::deserialize(&report["configuration"]["values"])
            .is_ok_and(|observed| observed == row.configuration)
    })
}

fn candidate_actor(report: &Value, hash: &str) -> Option<String> {
    report["records"]
        .as_array()
        .and_then(|records| {
            records
                .iter()
                .rev()
                .find(|record| record["hash"].as_str() == Some(hash))
        })
        .and_then(|record| record["by"].as_str())
        .map(str::to_owned)
}

fn observed_decision_matches(row: &Comparison) -> bool {
    row.evidence.as_ref().is_some_and(|report| {
        candidate_decision(report, &row.candidate)
            .is_ok_and(|(actual, outcome)| actual == row.actual && outcome == row.outcome)
            && candidate_actor(report, &row.candidate) == row.decision_actor
    })
}

fn candidate_decision(report: &Value, hash: &str) -> Result<(Option<Label>, String)> {
    ensure!(
        report["schema_version"] == 1
            && report["dry_run"] == true
            && report["authorizes_acceptance"] == false,
        "The CLI did not return a version 1 dry-run report."
    );
    let records = report["records"]
        .as_array()
        .context("The dry-run records are absent.")?;
    let items = report["items"]
        .as_array()
        .context("The dry-run items are absent.")?;
    if let Some(record) = records
        .iter()
        .rev()
        .find(|record| record["hash"].as_str() == Some(hash))
    {
        if let Some(error) = record
            .get("execution_error")
            .filter(|error| !error.is_null())
        {
            bail!("The candidate review has an execution error: {error}");
        }
        let label = match record["decision"].as_str() {
            Some("accept") => Label::Accept,
            Some("reject") => Label::Reject,
            Some("escalate") => Label::Escalate,
            _ => bail!("The candidate record has an invalid decision."),
        };
        return Ok((Some(label), "verdict".into()));
    }
    let item = items
        .iter()
        .find(|item| item["hash"].as_str() == Some(hash));
    let Some(item) = item else {
        return Ok((None, "no_decision".into()));
    };
    let result = match item["state"].as_str() {
        Some("accepted" | "removed") if item["decided"] == true => (Some(Label::Accept), "verdict"),
        Some("rejected") if item["decided"] == true => (Some(Label::Reject), "verdict"),
        Some("escalated") if item["decided"] == true => (Some(Label::Escalate), "verdict"),
        Some("blocked") => (None, "blocked"),
        _ => (None, "no_decision"),
    };
    Ok((result.0, result.1.into()))
}

fn execute(
    comparison: &mut Comparison,
    source: &Path,
    directory: PathBuf,
    case: &Case,
    variant: &Variant,
    policy: Option<&str>,
    policy_path: &str,
    manifest: &Manifest,
    env: &Arc<Env>,
    binary: &Path,
) -> Result<()> {
    let repo = init_repo(directory, &manifest.main, env)?;
    copy_changes(source, &repo, case)?;
    reconstruct(&repo, case, &manifest.main)?;
    let original_main = repo.hashes(&manifest.main)?;
    let policy_change = if let Some(text) = policy {
        apply_policy(&repo, &manifest.main, policy_path, text)?
    } else {
        None
    };
    let mut expected_main = original_main;
    expected_main.extend(policy_change.iter().cloned());
    exact_hashes(&repo, &manifest.main, &expected_main)?;
    candidate_inbox(&repo, case, &manifest.main, &manifest.inbox)?;
    comparison.policy_change = policy_change;
    let output = Command::new(binary)
        .args(["review", "--dry-run", "--json"])
        .current_dir(&repo.path)
        .env_clear()
        .envs(repo.env.iter())
        .env("PATCHGATE_MAIN", &manifest.main)
        .env("PATCHGATE_INBOX", &manifest.inbox)
        .env("PATCHGATE_POLICY", policy_path)
        .env(
            "PATCHGATE_PROTECTED",
            comparison.configuration.protected.join(","),
        )
        .env(
            "PATCHGATE_MAX_CHANGE_CHARS",
            comparison.configuration.max_change_chars.to_string(),
        )
        .env(
            "PATCHGATE_TIMEOUT",
            comparison.configuration.timeout_seconds.to_string(),
        )
        .env(
            "PATCHGATE_CHECK_TIMEOUT",
            comparison.configuration.check_timeout_seconds.to_string(),
        )
        .env(
            "PATCHGATE_MAX_REVIEW_REQUESTS",
            comparison.configuration.max_review_requests.to_string(),
        )
        .env(
            "PATCHGATE_REVIEW_TIMEOUT",
            comparison.configuration.review_timeout_seconds.to_string(),
        )
        .env("PATCHGATE_MODEL_URL", &variant.model_url)
        .env("PATCHGATE_MODEL", &variant.model)
        .env("PATCHGATE_MODEL_API", &variant.api)
        .env("PATCHGATE_MODEL_REVISION", &variant.revision)
        .stdin(Stdio::null())
        .output()
        .context("Execute the isolated dry-run CLI.")?;
    comparison.exit_code = output.status.code();
    comparison.cli_executed = true;
    comparison.stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let parsed = serde_json::from_slice::<Value>(&output.stdout);
    match parsed {
        Ok(report) => {
            comparison.evidence = Some(report);
        }
        Err(error) => {
            comparison.evidence = Some(json!({"stdout": String::from_utf8_lossy(&output.stdout)}));
            bail!("The dry-run CLI report is not valid JSON: {error}");
        }
    }
    ensure!(
        output.status.success(),
        "The dry-run CLI returned {}.",
        output.status
    );
    ensure!(
        observed_configuration_matches(comparison),
        "The CLI effective review settings differ from the replay settings."
    );
    let (actual, outcome) = candidate_decision(
        comparison
            .evidence
            .as_ref()
            .context("The dry-run report is absent.")?,
        &case.candidate,
    )?;
    comparison.decision_actor = comparison
        .evidence
        .as_ref()
        .and_then(|report| candidate_actor(report, &case.candidate));
    comparison.decision(actual, outcome);
    Ok(())
}

fn summarize(variant_id: &str, comparisons: &[Comparison]) -> Summary {
    let rows: Vec<_> = comparisons
        .iter()
        .filter(|row| row.variant_id == variant_id)
        .collect();
    let verdicts = rows
        .iter()
        .filter(|row| row.execution_error.is_none() && row.actual.is_some())
        .count();
    let escalations = rows
        .iter()
        .filter(|row| row.escalation == Some(true) && row.execution_error.is_none())
        .count();
    let mut latency: Vec<_> = rows
        .iter()
        .filter(|row| row.cli_executed)
        .map(|row| row.elapsed_seconds)
        .collect();
    latency.sort_by(f64::total_cmp);
    let total_seconds = latency.iter().sum();
    let median_seconds = if latency.is_empty() {
        None
    } else if latency.len() % 2 == 0 {
        Some((latency[latency.len() / 2 - 1] + latency[latency.len() / 2]) / 2.0)
    } else {
        Some(latency[latency.len() / 2])
    };
    Summary {
        variant_id: variant_id.into(),
        comparisons: rows.len(),
        verdicts,
        unsafe_acceptances: rows
            .iter()
            .filter(|row| row.unsafe_acceptance == Some(true) && row.execution_error.is_none())
            .count(),
        escalations,
        escalation_rate: (verdicts > 0).then(|| escalations as f64 / verdicts as f64),
        label_mismatches: rows
            .iter()
            .filter(|row| row.correct == Some(false) && row.execution_error.is_none())
            .count(),
        blocked_or_no_decision: rows
            .iter()
            .filter(|row| row.execution_error.is_none() && row.actual.is_none())
            .count(),
        infrastructure_errors: rows
            .iter()
            .filter(|row| row.execution_error.is_some())
            .count(),
        latency: Latency {
            samples: latency.len(),
            total_seconds,
            mean_seconds: (!latency.is_empty()).then(|| total_seconds / latency.len() as f64),
            median_seconds,
            p95_seconds: (!latency.is_empty())
                .then(|| latency[(latency.len() * 95).div_ceil(100) - 1]),
        },
    }
}

fn report_outside_source(path: &Path, source: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    match fs::symlink_metadata(&absolute) {
        Ok(metadata) => ensure!(
            !metadata.file_type().is_symlink(),
            "The report destination cannot be a symbolic link."
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut parent = absolute.parent().context("The report parent is absent.")?;
    let mut suffix = vec![
        absolute
            .file_name()
            .context("The report path must name a file.")?
            .to_owned(),
    ];
    loop {
        match fs::symlink_metadata(parent) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix.push(
                    parent
                        .file_name()
                        .context("The report path is not valid.")?
                        .to_owned(),
                );
                parent = parent.parent().context("The report parent is absent.")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut resolved = fs::canonicalize(parent)?;
    for part in suffix.into_iter().rev() {
        resolved.push(part);
    }
    ensure!(
        !crate::bundle::directory_contains(source, &resolved)?,
        "The report path must be outside the source repository."
    );
    Ok(resolved)
}

fn report_outside_repositories(
    path: &Path,
    source: &Path,
    origin: &Path,
    release_repository: Option<&Path>,
) -> Result<PathBuf> {
    let path = report_outside_source(path, source)?;
    ensure!(
        source == origin || !crate::bundle::directory_contains(origin, &path)?,
        "The report path must be outside the captured source repository."
    );
    if let Some(repository) = release_repository {
        ensure!(
            !crate::bundle::directory_contains(repository, &path)?,
            "The report path must be outside the trusted release repository."
        );
    }
    Ok(path)
}

fn write_report(
    path: &Path,
    source: &Path,
    origin: &Path,
    release_repository: Option<&Path>,
    bytes: &[u8],
) -> Result<()> {
    let path = report_outside_repositories(path, source, origin, release_repository)?;
    let parent = path.parent().context("The report parent is absent.")?;
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    report_outside_repositories(&path, source, origin, release_repository)?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn trusted_runtime_path() -> Result<std::ffi::OsString> {
    let directories: Vec<_> = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .filter(|path| path.is_absolute())
        .collect();
    let pijul = directories
        .iter()
        .map(|directory| directory.join("pijul"))
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .context("Replay needs Pijul in an absolute PATH directory.")?;
    let pijul = fs::canonicalize(pijul)?;
    let parent = pijul
        .parent()
        .context("The Pijul executable has no parent directory.")?;
    std::env::join_paths(
        std::iter::once(parent.to_owned()).chain(
            directories
                .into_iter()
                .filter(|directory| directory != parent),
        ),
    )
    .context("The trusted runtime PATH is not valid.")
}

pub fn run(args: ReplayArgs) -> Result<()> {
    release_gate::validate_requirements(&args)?;
    let policy = load_release_policy(&args)?;
    run_with_release_policy(args, policy)
}

fn run_with_release_policy(
    mut args: ReplayArgs,
    policy: crate::release_policy::Loaded,
) -> Result<()> {
    if let Some(policy) = &policy.policy {
        release_gate::apply_policy(&mut args, policy)?;
    }
    let strict = strict_signatures(&args)?;
    let mut signatures = SignatureEvidence {
        strict,
        ..SignatureEvidence::default()
    };
    let input = args
        .manifest
        .as_deref()
        .or(args.bundle.as_deref())
        .context("Replay needs one manifest or bundle.")?;
    ensure!(
        args.manifest.is_some() != args.bundle.is_some(),
        "Replay needs exactly one manifest or bundle."
    );
    let manifest_path = fs::canonicalize(input).context("Read the replay input path.")?;
    let authenticated = args
        .bundle_signature
        .as_ref()
        .map(|signature| {
            crate::artifact::snapshot(
                input,
                crate::artifact::Kind::Bundle,
                &signature_trust(&args, signature),
            )
        })
        .transpose()?;
    if let (Some(policy), Some(snapshot)) = (&policy.policy, &authenticated) {
        validate_policy_artifact(policy, &snapshot.verified)?;
    }
    let baseline = args.baseline.as_deref().map(|path| {
        let trust = args
            .baseline_signature
            .as_ref()
            .map(|signature| signature_trust(&args, signature));
        let (baseline, verified) =
            baseline_input_pinned(path, trust.as_ref(), policy.policy.as_ref())?;
        signatures.baseline = verified;
        Ok(baseline)
    });
    if strict || policy.policy.is_some() {
        if let Some(Err(error)) = &baseline {
            bail!("The selected release baseline is not valid: {error:#}");
        }
    }
    validate_trust_consistency(
        authenticated.as_ref().map(|snapshot| &snapshot.verified),
        signatures.baseline.as_ref(),
    )?;
    let mut loaded = args
        .bundle
        .as_ref()
        .map(|_| {
            crate::bundle::load(authenticated.as_ref().map_or(
                manifest_path.as_path(),
                crate::artifact::VerifiedSnapshot::path,
            ))
        })
        .transpose()?;
    signatures.bundle = authenticated.map(|snapshot| snapshot.verified);
    let mut manifest: Manifest = match &mut loaded {
        Some(bundle) => serde_json::from_value(std::mem::take(&mut bundle.manifest)),
        None => serde_json::from_slice(&fs::read(&manifest_path)?),
    }
    .context("Read the replay manifest.")?;
    let directory = match &loaded {
        Some(bundle) => bundle.directory.path(),
        None => manifest_path
            .parent()
            .context("The manifest directory is absent.")?,
    };
    let policy_path = manifest.configuration.policy_path.clone();
    validate(&manifest, &policy_path)?;
    let (source, origin) = match &loaded {
        Some(bundle) => (bundle.repository.clone(), bundle.origin_repository.clone()),
        None => {
            let source = fs::canonicalize(directory.join(&manifest.repository))
                .context("Read the source repository path.")?;
            ensure!(
                source.is_dir() && source.join(".pijul").is_dir(),
                "The source repository has no Pijul metadata."
            );
            (source.clone(), source)
        }
    };
    let report_path = args
        .report
        .as_deref()
        .map(|path| {
            report_outside_repositories(
                path,
                &source,
                &origin,
                policy
                    .evidence
                    .as_ref()
                    .map(|evidence| evidence.source_repository.as_path()),
            )
        })
        .transpose()?;
    let mut policies = BTreeMap::new();
    let mut policy_errors = BTreeMap::new();
    for variant in &mut manifest.variants {
        if let Some(path) = &variant.policy {
            let path = directory.join(path);
            match fs::canonicalize(&path)
                .and_then(|path| fs::read_to_string(&path).map(|text| (path, text)))
            {
                Ok((path, text)) => {
                    variant.policy = Some(path);
                    policies.insert(variant.id.clone(), text);
                }
                Err(error) => {
                    policy_errors.insert(
                        variant.id.clone(),
                        format!("Read the policy variant: {error}"),
                    );
                }
            }
        }
    }
    let temporary = tempfile::Builder::new().prefix("pge-replay-").tempdir()?;
    let binary =
        gate_binary().and_then(|path| fs::canonicalize(path).context("Read the gate binary path."));
    let home = temporary.path().join("home");
    fs::create_dir(&home)?;
    let mut env: Env = std::env::vars_os().collect();
    let runtime_path = trusted_runtime_path();
    env.insert(
        "PATH".into(),
        runtime_path.as_ref().cloned().unwrap_or_default(),
    );
    env.insert("HOME".into(), home.into_os_string());
    env.remove(std::ffi::OsStr::new("XDG_CONFIG_HOME"));
    env.remove(std::ffi::OsStr::new("SSH_AUTH_SOCK"));
    let env = Arc::new(env);
    let signer = manifest
        .variants
        .iter()
        .any(|variant| variant.policy.is_some())
        .then(|| match &runtime_path {
            Ok(path) => Signer::with_path(path.clone()),
            Err(error) => Err(anyhow!("Read the trusted runtime PATH: {error:#}")),
        });
    let mut prerequisites = BTreeMap::new();
    for (index, case) in manifest.cases.iter().enumerate() {
        let result = match &runtime_path {
            Ok(_) => preflight(
                &source,
                &origin,
                &temporary.path().join(format!("preflight-{index}")),
                case,
                &manifest,
                &env,
            ),
            Err(error) => Err(anyhow!("Read the trusted runtime PATH: {error:#}")),
        };
        if let Err(error) = result {
            prerequisites.insert(case.id.clone(), format!("{error:#}"));
        }
    }
    let mut comparisons = Vec::new();
    for (variant_index, variant) in manifest.variants.iter().enumerate() {
        let variant_env = if variant.policy.is_some() {
            match &signer {
                Some(Ok(signer)) => Ok(&signer.env),
                Some(Err(error)) => Err(anyhow!("Create the fixture signer: {error:#}")),
                None => Err(anyhow!("The policy signer is absent.")),
            }
        } else {
            Ok(&env)
        };
        for (case_index, case) in manifest.cases.iter().enumerate() {
            let mut comparison = Comparison::new(case, variant, &manifest.configuration);
            let case_policy_path = comparison.configuration.policy_path.clone();
            let start = Instant::now();
            let result = match (&variant_env, &binary) {
                (_, Err(error)) => Err(anyhow!("Read the gate binary: {error:#}")),
                (Err(error), _) => Err(anyhow!("{error:#}")),
                (Ok(_), _) if prerequisites.contains_key(&case.id) => {
                    Err(anyhow!("{}", prerequisites[&case.id]))
                }
                (Ok(_), _) if policy_errors.contains_key(&variant.id) => {
                    Err(anyhow!("{}", policy_errors[&variant.id]))
                }
                (Ok(env), Ok(binary)) => execute(
                    &mut comparison,
                    &source,
                    temporary
                        .path()
                        .join(format!("case-{case_index}-variant-{variant_index}")),
                    case,
                    variant,
                    policies.get(&variant.id).map(String::as_str),
                    &case_policy_path,
                    &manifest,
                    env,
                    binary,
                ),
            };
            comparison.elapsed_seconds = start.elapsed().as_secs_f64();
            if let Err(error) = result {
                comparison.execution_error = Some(format!("{error:#}"));
            }
            comparisons.push(comparison);
        }
    }
    let summaries = manifest
        .variants
        .iter()
        .map(|variant| summarize(&variant.id, &comparisons))
        .collect();
    let infrastructure_errors = comparisons
        .iter()
        .filter(|row| row.execution_error.is_some())
        .count();
    let gate = release_gate::evaluate(&args, &manifest, &origin, &comparisons, baseline.as_ref());
    let gate_passed = gate.as_ref().is_none_or(|result| result.passed);
    let report = Report {
        schema_version: 1,
        manifest: manifest_path,
        repository: origin,
        main: manifest.main,
        inbox: manifest.inbox,
        configuration: manifest.configuration,
        variants: manifest.variants,
        cases: manifest.cases,
        comparisons,
        summaries,
        infrastructure_errors,
        authorizes_acceptance: false,
        bundle_sha256: loaded.as_ref().map(|bundle| bundle.sha256.clone()),
        gate,
        signatures,
        release_policy: policy.evidence,
    };
    let mut text = serde_json::to_string_pretty(&report)?;
    text.push('\n');
    print!("{text}");
    if let Some(path) = report_path {
        write_report(
            &path,
            &source,
            &report.repository,
            report
                .release_policy
                .as_ref()
                .map(|evidence| evidence.source_repository.as_path()),
            text.as_bytes(),
        )?;
    }
    ensure!(
        gate_passed,
        "The replay release gate failed. The JSON report contains each failure."
    );
    ensure!(
        infrastructure_errors == 0,
        "Replay contains {infrastructure_errors} infrastructure errors. The JSON report retains each error."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Manifest {
        serde_json::from_value(json!({
            "schema_version": 1,
            "repository": "repo",
            "cases": [{"id": "case", "base": [], "candidate": "A".repeat(53), "expected": "reject"}],
            "variants": [{"id": "variant", "model_url": "http://localhost:8080", "model": "model", "api": "openai", "revision": "checkpoint-12"}]
        })).unwrap()
    }

    #[test]
    fn per_case_settings_override_root_and_preserve_fractional_limits() {
        let mut manifest = fixture();
        manifest.configuration.max_change_chars = 100;
        manifest.configuration.timeout_seconds = 1.25;
        manifest.configuration.max_review_requests = 11;
        manifest.configuration.review_timeout_seconds = 1.75;
        let mut configuration = Configuration::default();
        configuration.max_change_chars = 200;
        configuration.timeout_seconds = 0.125;
        configuration.check_timeout_seconds = 2.75;
        configuration.max_review_requests = 3;
        configuration.review_timeout_seconds = 0.5;
        manifest.cases[0].configuration = Some(configuration.clone());
        assert!(validate(&manifest, "POLICY.md").is_ok());
        let comparison = Comparison::new(
            &manifest.cases[0],
            &manifest.variants[0],
            &manifest.configuration,
        );
        assert_eq!(comparison.configuration, configuration);
        let mut observed = comparison;
        observed.evidence = Some(json!({"configuration": {"values": manifest.configuration}}));
        assert!(!observed_configuration_matches(&observed));
        observed.evidence = Some(json!({"configuration": {"values": configuration}}));
        assert!(observed_configuration_matches(&observed));
        manifest.cases[0]
            .configuration
            .as_mut()
            .unwrap()
            .timeout_seconds = f64::INFINITY;
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[0]
            .configuration
            .as_mut()
            .unwrap()
            .timeout_seconds = -0.1;
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[0].configuration = None;
        assert_eq!(
            Comparison::new(
                &manifest.cases[0],
                &manifest.variants[0],
                &manifest.configuration
            )
            .configuration
            .timeout_seconds,
            1.25
        );
    }

    #[test]
    fn replay_rejects_unsafe_review_limits_at_each_scope() {
        let mut manifest = fixture();
        manifest.configuration.max_review_requests = 0;
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.configuration = Configuration::default();
        manifest.cases[0].configuration = Some(Configuration {
            max_review_requests: 0,
            ..Configuration::default()
        });
        assert!(validate(&manifest, "POLICY.md").is_err());
        for seconds in [
            0.0, -1.0, f64::NAN, f64::INFINITY, f64::MAX, 1e-100, 1e19,
        ] {
            manifest.cases[0].configuration = None;
            manifest.configuration.review_timeout_seconds = seconds;
            assert!(validate(&manifest, "POLICY.md").is_err(), "{seconds}");
            manifest.configuration = Configuration::default();
            manifest.cases[0].configuration = Some(Configuration {
                review_timeout_seconds: seconds,
                ..Configuration::default()
            });
            assert!(validate(&manifest, "POLICY.md").is_err(), "{seconds}");
        }
    }

    #[test]
    fn captured_bindings_and_human_labels_remain_explicit() {
        let mut manifest = fixture();
        manifest.cases[0].snapshot = Some(json!({
            "repository": "/captured/source",
            "policy_path": "POLICY.md",
            "base": [],
            "candidate": manifest.cases[0].candidate,
            "main": "main",
            "inbox": "inbox",
            "configuration": {"values": manifest.configuration},
        }));
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[0].labels = vec![json!({
            "user": "reviewer", "time": "2026-10-21T00:00:00Z",
            "expected": "reject", "reason": "The reviewer rejects the change.",
        })];
        assert!(validate(&manifest, "POLICY.md").is_ok());
        let comparison = Comparison::new(
            &manifest.cases[0],
            &manifest.variants[0],
            &manifest.configuration,
        );
        let encoded = serde_json::to_value(comparison).unwrap();
        assert_eq!(
            encoded["snapshot"],
            manifest.cases[0].snapshot.clone().unwrap()
        );
        assert_eq!(encoded["labels"], json!(manifest.cases[0].labels));
        manifest.cases[0].expected = Label::Accept;
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[0].expected = Label::Reject;
        manifest.cases[0].snapshot.as_mut().unwrap()["configuration"]["values"]
            ["max_review_requests"] = json!(1);
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[0].snapshot.as_mut().unwrap()["configuration"]["values"]
            ["max_review_requests"] = json!(manifest.configuration.max_review_requests);
        manifest.cases[0].snapshot.as_mut().unwrap()["configuration"]["values"]
            ["review_timeout_seconds"] = json!(0.5);
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[0].snapshot.as_mut().unwrap()["configuration"]["values"]
            ["review_timeout_seconds"] = json!(manifest.configuration.review_timeout_seconds);
        manifest.cases[0].snapshot.as_mut().unwrap()["base"] = json!(["B".repeat(53)]);
        assert!(validate(&manifest, "POLICY.md").is_err());
    }

    #[test]
    fn duplicate_capture_human_histories_must_match() {
        let mut manifest = fixture();
        manifest.cases[0].snapshot = Some(json!({
            "repository": "/captured/source",
            "base": [], "candidate": manifest.cases[0].candidate,
            "main": "main", "inbox": "inbox", "main_state": null,
            "policy_path": "POLICY.md", "policy_sha256": null,
            "configuration": {"values": manifest.configuration},
        }));
        manifest.cases[0].labels = vec![json!({
            "user": "reviewer", "time": "2026-10-21T00:00:00Z",
            "expected": "reject", "reason": "The reviewer rejects the change.",
        })];
        manifest.cases[0].tags = vec![TagRecord {
            user: "reviewer".into(),
            time: "2026-10-21T00:00:00Z".into(),
            reason: "The reviewer identifies the rule.".into(),
            policy_rules: vec!["protected-path".into()],
            conflict_kinds: Vec::new(),
        }];
        manifest.cases[0].notes = vec![serde_json::from_value(json!({
            "user": "reviewer", "time": "2026-10-21T00:00:00Z", "kind": "evidence",
            "text": "The test report supports this claim.", "references": ["test:parser"],
            "anchor": {"path": "value.txt", "vertex_change": "A".repeat(53),
                "start": 0, "end": 4, "kind": "add", "text_sha256": "a".repeat(64)},
        })).unwrap()];
        manifest.cases[0].seen = vec![SeenRecord {
            user: "reviewer".into(), time: "2026-10-21T00:00:00Z".into(),
            path: "value.txt".into(), content_sha256: "b".repeat(64), seen: true,
        }];
        let duplicate: Case = serde_json::from_value(json!({
            "id": "duplicate", "base": manifest.cases[0].base,
            "candidate": manifest.cases[0].candidate, "expected": "reject",
            "snapshot": manifest.cases[0].snapshot, "labels": manifest.cases[0].labels,
            "tags": manifest.cases[0].tags,
            "notes": manifest.cases[0].notes, "seen": manifest.cases[0].seen,
        }))
        .unwrap();
        manifest.cases.push(duplicate);
        assert!(validate(&manifest, "POLICY.md").is_ok());
        let comparison = Comparison::new(
            &manifest.cases[0],
            &manifest.variants[0],
            &manifest.configuration,
        );
        assert_eq!(
            serde_json::to_value(&comparison).unwrap()["tags"],
            json!(manifest.cases[0].tags)
        );
        let encoded = serde_json::to_value(&comparison).unwrap();
        assert_eq!(encoded["notes"], json!(manifest.cases[0].notes));
        assert_eq!(encoded["seen"], json!(manifest.cases[0].seen));
        manifest.cases[1].notes[0].references.clear();
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[1].notes = manifest.cases[0].notes.clone();
        manifest.cases[1].seen[0].seen = false;
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[1].seen = manifest.cases[0].seen.clone();
        manifest.cases[1].labels.clear();
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[1].labels = manifest.cases[0].labels.clone();
        manifest.cases[1].tags[0].policy_rules.clear();
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[1].tags = manifest.cases[0].tags.clone();
        manifest.cases[1].tags[0].reason = "Line\nbreak".into();
        assert!(validate(&manifest, "POLICY.md").is_err());
    }

    #[test]
    fn manifest_requires_explicit_revisions_unique_ids_and_full_hashes() {
        let mut manifest = fixture();
        assert!(validate(&manifest, "POLICY.md").is_ok());
        manifest.variants[0].revision.clear();
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.variants[0].revision = "checkpoint-12".into();
        manifest.cases[0].candidate = "A".repeat(52);
        assert!(validate(&manifest, "POLICY.md").is_err());
        manifest.cases[0].candidate = "A".repeat(53);
        let duplicate: Case = serde_json::from_value(
            json!({"id": "case", "base": [], "candidate": "B".repeat(53), "expected": "accept"}),
        )
        .unwrap();
        manifest.cases.push(duplicate);
        assert!(validate(&manifest, "POLICY.md").is_err());
        for path in [
            "",
            ".",
            "docs/..",
            "../POLICY.md",
            "/POLICY.md",
            ".pijul/policy",
            "docs/../.pijul/policy",
        ] {
            assert!(validate(&fixture(), path).is_err(), "{path}");
            let mut manifest = fixture();
            manifest.configuration.policy_path = path.into();
            assert!(validate(&manifest, "POLICY.md").is_err(), "{path}");
        }
    }

    #[test]
    fn labels_do_not_come_from_model_history() {
        assert!(serde_json::from_value::<Label>(json!("accepted")).is_err());
        assert!(serde_json::from_value::<Label>(json!("unknown")).is_err());
    }

    #[test]
    fn prerequisites_must_precede_candidate_and_each_base_change() {
        let mut manifest = fixture();
        let a = "A".repeat(53);
        let b = "B".repeat(53);
        let c = "C".repeat(53);
        manifest.cases[0].base = vec![b.clone(), a.clone()];
        manifest.cases[0].candidate = c.clone();
        let prerequisites = BTreeMap::from([
            (a.clone(), vec![]),
            (b.clone(), vec![a.clone()]),
            (c.clone(), vec![b.clone()]),
        ]);
        assert!(validate_order(&manifest.cases[0], &prerequisites).is_err());
        manifest.cases[0].base = vec![a.clone(), b.clone()];
        assert!(validate_order(&manifest.cases[0], &prerequisites).is_ok());
        manifest.cases[0].base = vec![a];
        assert!(validate_order(&manifest.cases[0], &prerequisites).is_err());
    }

    #[test]
    fn native_context_is_not_a_prerequisite() {
        let a = "A".repeat(53);
        let b = "B".repeat(53);
        let text = format!("# Dependencies\n[1] {a}\n[*] {b}\n# Hunks\n[2] {b}\n");
        assert_eq!(dependencies(&text).unwrap(), vec![a]);
    }

    #[test]
    fn blocked_and_missing_decisions_are_not_escalations() {
        let hash = "A".repeat(53);
        let mut report = json!({"schema_version": 1, "dry_run": true, "authorizes_acceptance": false, "records": [], "items": [{"hash": hash, "state": "blocked", "decided": false}]});
        assert_eq!(
            candidate_decision(&report, &hash).unwrap(),
            (None, "blocked".into())
        );
        report["items"] = json!([]);
        assert_eq!(
            candidate_decision(&report, &hash).unwrap(),
            (None, "no_decision".into())
        );
        report["records"] =
            json!([{"hash": hash, "decision": "escalate", "review": {"policy": "digest"}}]);
        assert_eq!(
            candidate_decision(&report, &hash).unwrap().0,
            Some(Label::Escalate)
        );
    }

    #[test]
    fn invalid_model_replies_are_errors_not_escalations() {
        let hash = "A".repeat(53);
        let mut report = json!({
            "schema_version": 1, "dry_run": true, "authorizes_acceptance": false,
            "items": [],
            "records": [{"hash": hash, "decision": "escalate", "by": "gate",
                "execution_error": "invalid-model-reply"}]
        });
        assert!(candidate_decision(&report, &hash).is_err());
        report["records"][0] = json!({"hash": hash, "decision": "escalate",
            "by": "gate", "reason": "The change touches protected paths."});
        assert_eq!(
            candidate_decision(&report, &hash).unwrap().0,
            Some(Label::Escalate)
        );
        assert!(candidate_decision(&json!([]), &hash).is_err());
    }

    #[test]
    fn source_paths_refuse_links_and_report_writes() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        let source = fs::canonicalize(source).unwrap();
        fs::write(source.join("change"), b"native data").unwrap();
        std::os::unix::fs::symlink(source.join("change"), source.join("link")).unwrap();
        assert!(plain_file(&source, Path::new("change")).is_ok());
        assert!(plain_file(&source, Path::new("link")).is_err());
        assert!(report_outside_source(&source.join("nested/report.json"), &source).is_err());
        assert!(report_outside_source(&temporary.path().join("report.json"), &source).is_ok());
    }

    #[test]
    fn metrics_exclude_errors_and_count_unsafe_policy_escalations() {
        let manifest = fixture();
        let case = &manifest.cases[0];
        let variant = &manifest.variants[0];
        let mut unsafe_row = Comparison::new(case, variant, &manifest.configuration);
        unsafe_row.expected = Label::Escalate;
        unsafe_row.decision(Some(Label::Accept), "verdict".into());
        unsafe_row.exit_code = Some(0);
        unsafe_row.cli_executed = true;
        unsafe_row.elapsed_seconds = 1.0;
        let mut escalation = Comparison::new(case, variant, &manifest.configuration);
        escalation.decision(Some(Label::Escalate), "verdict".into());
        escalation.exit_code = Some(0);
        escalation.cli_executed = true;
        escalation.elapsed_seconds = 3.0;
        let mut error = Comparison::new(case, variant, &manifest.configuration);
        error.execution_error = Some("The model API is unavailable.".into());
        let blocked = Comparison {
            outcome: "blocked".into(),
            ..Comparison::new(case, variant, &manifest.configuration)
        };
        let summary = summarize(&variant.id, &[unsafe_row, escalation, error, blocked]);
        assert_eq!(summary.verdicts, 2);
        assert_eq!(summary.unsafe_acceptances, 1);
        assert_eq!(summary.label_mismatches, 2);
        assert_eq!(summary.escalation_rate, Some(0.5));
        assert_eq!(summary.infrastructure_errors, 1);
        assert_eq!(summary.blocked_or_no_decision, 1);
        assert_eq!(summary.latency.median_seconds, Some(2.0));
        assert_eq!(summary.latency.p95_seconds, Some(3.0));
    }

    #[test]
    fn historical_reconstruction_registers_changes_and_excludes_later_source() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let signer = Signer::new()?;
        let source = init_repo(directory.path().join("source"), "main", &signer.env)?;
        source.change(&[("value.txt", "base\n")], "Define the base value")?;
        let base: Vec<_> = source
            .pijul(&["log", "--channel", "main", "--hash-only"])?
            .split_whitespace()
            .rev()
            .map(str::to_owned)
            .collect();
        source.pijul(&["fork", "--channel", "main", "inbox"])?;
        source.pijul(&["channel", "switch", "inbox"])?;
        let candidate = source.change(&[("value.txt", "candidate\n")], "Change the value")?;
        source.change(
            &[("later.txt", "Do not replay this file.\n")],
            "Add later source",
        )?;
        let source_hashes = source.hashes("inbox")?;
        let mut case = Case {
            id: "historical".into(),
            base,
            candidate,
            expected: Label::Accept,
            configuration: None,
            snapshot: None,
            labels: Vec::new(),
            tags: Vec::new(),
            notes: Vec::new(),
            seen: Vec::new(),
        };
        let source_path = fs::canonicalize(&source.path)?;
        let states: Vec<Value> = serde_json::from_str(&source.pijul(&[
            "log",
            "--channel",
            "main",
            "--state",
            "--output-format",
            "json",
        ])?)?;
        case.snapshot = Some(json!({
            "repository": source_path,
            "main": "main",
            "inbox": "inbox",
            "main_state": states[0]["state"],
            "base": case.base,
            "candidate": case.candidate,
            "policy_path": "POLICY.md",
            "policy_sha256": null,
            "configuration": {
                "source": "environment", "path": null, "sha256": null,
                "values": Configuration::default(),
            },
        }));
        case.labels = vec![json!({
            "user": "reviewer", "time": "2026-10-21T00:00:00Z",
            "expected": "accept", "reason": "The reviewer approves the change.",
        })];
        preflight(
            &source_path,
            &source_path,
            &directory.path().join("preflight"),
            &case,
            &fixture(),
            &signer.env,
        )?;
        let replay = init_repo(directory.path().join("replay"), "main", &signer.env)?;
        copy_changes(&source.path, &replay, &case)?;
        reconstruct(&replay, &case, "main")?;
        candidate_inbox(&replay, &case, "main", "inbox")?;
        let main = replay.archive("main")?;
        let inbox = replay.archive("inbox")?;
        assert_eq!(main.files["value.txt"], b"base\n");
        assert_eq!(inbox.files["value.txt"], b"candidate\n");
        assert!(!main.files.contains_key("later.txt"));
        assert!(!inbox.files.contains_key("later.txt"));
        assert_eq!(source.hashes("inbox")?, source_hashes);
        Ok(())
    }

    #[test]
    fn captured_policy_paths_replay_with_exact_recorded_bytes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let signer = Signer::new()?;
        let source = init_repo(directory.path().join("source"), "main", &signer.env)?;
        let policy = "# Policy\r\nReject a change that adds a secret.\r\n";
        source.change(
            &[("docs/POLICY.md", policy), ("value.txt", "base\n")],
            "Define the policy and base value",
        )?;
        let base = source
            .pijul(&["log", "--channel", "main", "--hash-only"])?
            .split_whitespace()
            .rev()
            .map(str::to_owned)
            .collect();
        let states: Vec<Value> = serde_json::from_str(&source.pijul(&[
            "log",
            "--channel",
            "main",
            "--state",
            "--output-format",
            "json",
        ])?)?;
        source.pijul(&["fork", "--channel", "main", "inbox"])?;
        source.pijul(&["channel", "switch", "inbox"])?;
        let candidate = source.change(&[("value.txt", "candidate\n")], "Change the value")?;
        let source_path = fs::canonicalize(&source.path)?;
        let mut manifest = fixture();
        manifest.cases[0].base = base;
        manifest.cases[0].candidate = candidate;
        manifest.cases[0].labels = vec![json!({
            "user": "reviewer", "time": "2026-10-21T00:00:00Z",
            "expected": "reject", "reason": "The reviewer rejects the change.",
        })];
        let main_hashes = source.hashes("main")?;
        let inbox_hashes = source.hashes("inbox")?;
        for (index, path) in [
            "docs/./POLICY.md",
            "./docs/POLICY.md",
            "docs/unused/../POLICY.md",
        ]
        .into_iter()
        .enumerate()
        {
            let configuration = Configuration {
                policy_path: path.into(),
                ..Configuration::default()
            };
            manifest.cases[0].configuration = Some(configuration.clone());
            manifest.cases[0].snapshot = Some(json!({
                "repository": source_path,
                "main": "main",
                "inbox": "inbox",
                "main_state": states[0]["state"],
                "base": manifest.cases[0].base,
                "candidate": manifest.cases[0].candidate,
                "policy_path": path,
                "policy_sha256": format!("{:x}", Sha256::digest(policy.as_bytes())),
                "configuration": {
                    "source": "environment", "path": null, "sha256": null,
                    "values": configuration,
                },
            }));
            validate(&manifest, path)?;
            preflight(
                &source_path,
                &source_path,
                &directory.path().join(format!("match-{index}")),
                &manifest.cases[0],
                &manifest,
                &signer.env,
            )?;
            let comparison = Comparison::new(
                &manifest.cases[0],
                &manifest.variants[0],
                &manifest.configuration,
            );
            assert_eq!(comparison.configuration.policy_path, path);
            assert_eq!(comparison.snapshot.unwrap()["policy_path"], path);
        }
        assert_eq!(source.hashes("main")?, main_hashes);
        assert_eq!(source.hashes("inbox")?, inbox_hashes);
        assert_eq!(
            fs::read(source.path.join("docs/POLICY.md"))?,
            policy.as_bytes()
        );
        assert!(!source.path.join(".pijul/patchgate").exists());

        source.pijul(&["channel", "switch", "main"])?;
        let changed = source.change(
            &[(
                "docs/POLICY.md",
                "# Policy\nReject a change that adds a secret.\n",
            )],
            "Change the exact policy bytes",
        )?;
        manifest.cases[0].base.push(changed);
        let states: Vec<Value> = serde_json::from_str(&source.pijul(&[
            "log",
            "--channel",
            "main",
            "--state",
            "--output-format",
            "json",
        ])?)?;
        let base = json!(manifest.cases[0].base);
        let snapshot = manifest.cases[0].snapshot.as_mut().unwrap();
        snapshot["base"] = base;
        snapshot["main_state"] = states[0]["state"].clone();
        validate(&manifest, "docs/./POLICY.md")?;
        let main_hashes = source.hashes("main")?;
        let error = preflight(
            &source_path,
            &source_path,
            &directory.path().join("changed-policy"),
            &manifest.cases[0],
            &manifest,
            &signer.env,
        )
        .unwrap_err();
        assert!(!error.to_string().contains(policy));
        assert_eq!(source.hashes("main")?, main_hashes);
        assert_eq!(source.hashes("inbox")?, inbox_hashes);
        assert!(!source.path.join(".pijul/patchgate").exists());
        manifest.cases[0].snapshot.as_mut().unwrap()["policy_sha256"] = json!(format!(
            "{:x}",
            Sha256::digest(b"# Policy\nReject a change that adds a secret.\n")
        ));
        preflight(
            &source_path,
            &source_path,
            &directory.path().join("new-policy-binding"),
            &manifest.cases[0],
            &manifest,
            &signer.env,
        )?;
        Ok(())
    }

    #[test]
    fn policy_archive_reads_internal_aliases_and_refuses_unsafe_links() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("channel.tar.gz");
        let encoder = flate2::write::GzEncoder::new(
            fs::File::create(&archive)?,
            flate2::Compression::default(),
        );
        let mut tar = tar::Builder::new(encoder);
        let bytes = b"# Policy\r\nExact bytes.\r\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "docs/POLICY.md", &bytes[..])?;
        for (name, target, kind) in [
            ("alias", "docs/POLICY.md", tar::EntryType::Symlink),
            (
                "docs/relative",
                "../docs/./POLICY.md",
                tar::EntryType::Symlink,
            ),
            ("directory", "docs", tar::EntryType::Symlink),
            ("hard", "docs/POLICY.md", tar::EntryType::Link),
            ("escape", "../marker", tar::EntryType::Symlink),
            ("absolute", "/marker", tar::EntryType::Symlink),
            ("cycle-a", "cycle-b", tar::EntryType::Symlink),
            ("cycle-b", "cycle-a", tar::EntryType::Symlink),
            (
                "nested-cycle",
                "nested-cycle/child",
                tar::EntryType::Symlink,
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(0);
            header.set_mode(0o777);
            tar.append_link(&mut header, name, target)?;
        }
        tar.into_inner()?.finish()?;
        for path in [
            "docs/./POLICY.md",
            "alias",
            "docs/relative",
            "directory/POLICY.md",
            "hard",
        ] {
            assert_eq!(
                policy_archive_bytes(&archive, path)?.as_deref(),
                Some(&bytes[..]),
                "{path}"
            );
        }
        assert_eq!(policy_archive_bytes(&archive, "missing")?, None);
        for path in [
            "escape",
            "absolute",
            "cycle-a",
            "directory/../escape",
            "../marker",
            "/marker",
            "nested-cycle/POLICY.md",
        ] {
            assert!(policy_archive_bytes(&archive, path).is_err(), "{path}");
        }
        Ok(())
    }

    #[test]
    fn report_aliases_cannot_change_source_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        let source = fs::canonicalize(source)?;
        let original = source.join("data");
        fs::write(&original, b"source bytes")?;
        let alias = directory.path().join("report");
        fs::hard_link(&original, &alias)?;
        write_report(&alias, &source, &source, None, b"report bytes")?;
        assert_eq!(fs::read(&original)?, b"source bytes");
        assert_eq!(fs::read(&alias)?, b"report bytes");
        let dangling = directory.path().join("dangling");
        std::os::unix::fs::symlink(source.join("missing"), &dangling)?;
        assert!(write_report(&dangling, &source, &source, None, b"must not enter source").is_err());
        assert!(!source.join("missing").exists());
        let parent = directory.path().join("parent-alias");
        std::os::unix::fs::symlink(&source, &parent)?;
        assert!(
            write_report(&parent.join("nested/report"), &source, &source, None, b"no").is_err()
        );
        assert!(!source.join("nested").exists());
        Ok(())
    }

    #[test]
    fn bundle_reports_cannot_replace_original_source_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source");
        let runtime = root.join("runtime");
        fs::create_dir(&source)?;
        fs::create_dir(&runtime)?;
        let original = source.join("POLICY.md");
        fs::write(&original, b"Retain the original source.\n")?;
        assert!(write_report(&original, &runtime, &source, None, b"report").is_err());
        assert_eq!(fs::read(&original)?, b"Retain the original source.\n");
        let alias = source.with_file_name("SOURCE").join("POLICY.md");
        if alias.is_file() {
            assert!(write_report(&alias, &runtime, &source, None, b"report").is_err());
            assert_eq!(fs::read(&original)?, b"Retain the original source.\n");
        }
        fs::remove_dir_all(&source)?;
        assert!(write_report(&original, &runtime, &source, None, b"report").is_err());
        assert!(!source.exists());
        Ok(())
    }

    #[test]
    fn reports_cannot_replace_trusted_release_repository_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source");
        let origin = root.join("origin");
        let trusted = root.join("trusted");
        fs::create_dir(&source)?;
        fs::create_dir(&origin)?;
        fs::create_dir_all(trusted.join(".pijul/patchgate"))?;
        let key = trusted.join(".pijul/patchgate/key");
        fs::write(&key, b"private authority bytes")?;
        assert!(write_report(&key, &source, &origin, Some(&trusted), b"report").is_err());
        assert_eq!(fs::read(&key)?, b"private authority bytes");
        let nested = trusted.join("new/directory/report.json");
        assert!(write_report(&nested, &source, &origin, Some(&trusted), b"report").is_err());
        assert!(!trusted.join("new").exists());
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&trusted, &alias)?;
        assert!(
            write_report(
                &alias.join(".pijul/patchgate/key"),
                &source,
                &origin,
                Some(&trusted),
                b"report",
            )
            .is_err()
        );
        let case_alias = trusted
            .with_file_name("TRUSTED")
            .join(".pijul/patchgate/key");
        if case_alias.is_file() {
            assert!(
                write_report(&case_alias, &source, &origin, Some(&trusted), b"report").is_err()
            );
        }
        assert_eq!(fs::read(&key)?, b"private authority bytes");
        let outside = root.join("reports/report.json");
        write_report(&outside, &source, &origin, Some(&trusted), b"report")?;
        assert_eq!(fs::read(outside)?, b"report");
        Ok(())
    }
}

#[cfg(test)]
mod input_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        replay: ReplayArgs,
    }

    #[test]
    fn replay_requires_exactly_one_input() {
        assert!(Cli::try_parse_from(["replay"]).is_err());
        assert!(
            Cli::try_parse_from(["replay", "manifest.json", "--bundle", "cases.tar.gz"]).is_err()
        );
        assert!(Cli::try_parse_from(["replay", "manifest.json"]).is_ok());
        let cli = Cli::try_parse_from([
            "replay",
            "--bundle",
            "cases.tar.gz",
            "--baseline",
            "baseline.json",
            "--max-unsafe-acceptances",
            "1",
            "--max-label-mismatches",
            "2",
            "--max-regressions",
            "3",
        ])
        .unwrap();
        assert_eq!(cli.replay.bundle, Some("cases.tar.gz".into()));
        assert_eq!(cli.replay.max_unsafe_acceptances, Some(1));
        assert_eq!(cli.replay.max_label_mismatches, Some(2));
        assert_eq!(cli.replay.max_regressions, Some(3));
    }

    #[test]
    fn strict_signature_options_require_each_selected_artifact() {
        for arguments in [
            vec!["replay", "manifest.json", "--signer", "reviewer"],
            vec![
                "replay",
                "manifest.json",
                "--baseline",
                "baseline.json",
                "--signer",
                "reviewer",
            ],
            vec![
                "replay",
                "--bundle",
                "cases.tar.gz",
                "--allowed-signers",
                "reviewers",
                "--signer",
                "reviewer",
            ],
            vec![
                "replay",
                "--bundle",
                "cases.tar.gz",
                "--bundle-signature",
                "bundle.sig",
            ],
            vec![
                "replay",
                "manifest.json",
                "--baseline-signature",
                "baseline.sig",
                "--allowed-signers",
                "reviewers",
                "--signer",
                "reviewer",
            ],
            vec![
                "replay",
                "--bundle",
                "cases.tar.gz",
                "--baseline",
                "baseline.json",
                "--bundle-signature",
                "bundle.sig",
                "--allowed-signers",
                "reviewers",
                "--signer",
                "reviewer",
            ],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(strict_signatures(&cli.replay).is_err());
        }
        for arguments in [
            vec![
                "replay",
                "manifest.json",
                "--baseline",
                "baseline.json",
                "--baseline-signature",
                "baseline.sig",
                "--allowed-signers",
                "reviewers",
                "--signer",
                "reviewer",
            ],
            vec![
                "replay",
                "--bundle",
                "cases.tar.gz",
                "--bundle-signature",
                "bundle.sig",
                "--allowed-signers",
                "reviewers",
                "--signer",
                "reviewer",
            ],
            vec![
                "replay",
                "--bundle",
                "cases.tar.gz",
                "--baseline",
                "baseline.json",
                "--bundle-signature",
                "bundle.sig",
                "--baseline-signature",
                "baseline.sig",
                "--allowed-signers",
                "reviewers",
                "--signer",
                "reviewer",
            ],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(strict_signatures(&cli.replay).unwrap());
        }
        let cli = Cli::try_parse_from(["replay", "manifest.json"]).unwrap();
        assert!(!strict_signatures(&cli.replay).unwrap());
    }

    #[test]
    fn signature_failure_precedes_manifest_and_native_replay() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manifest = directory.path().join("manifest.json");
        let baseline = directory.path().join("baseline.json");
        let signature = directory.path().join("baseline.sig");
        let allowed = directory.path().join("reviewers");
        let report = directory.path().join("report.json");
        fs::write(&manifest, b"{}")?;
        fs::write(&baseline, b"{}")?;
        fs::write(&signature, b"invalid signature")?;
        fs::write(&allowed, b"invalid trust")?;
        let cli = Cli::try_parse_from([
            std::ffi::OsStr::new("replay"),
            manifest.as_os_str(),
            std::ffi::OsStr::new("--baseline"),
            baseline.as_os_str(),
            std::ffi::OsStr::new("--baseline-signature"),
            signature.as_os_str(),
            std::ffi::OsStr::new("--allowed-signers"),
            allowed.as_os_str(),
            std::ffi::OsStr::new("--signer"),
            std::ffi::OsStr::new("reviewer"),
            std::ffi::OsStr::new("--report"),
            report.as_os_str(),
        ])?;
        let policy = caller_release_policy(directory.path())?;
        assert!(run_with_release_policy(cli.replay, policy).is_err());
        assert!(!report.exists());
        assert_eq!(fs::read(&manifest)?, b"{}");
        assert_eq!(fs::read(&baseline)?, b"{}");
        Ok(())
    }

    #[test]
    fn coverage_cli_repeats_and_rejects_malformed_requirements() {
        let cli = Cli::try_parse_from([
            "replay",
            "manifest.json",
            "--min-policy-rule",
            "protected-path=2",
            "--min-policy-rule",
            "review=0",
            "--min-conflict-kind",
            "content=1",
        ])
        .unwrap();
        assert_eq!(cli.replay.min_policy_rule.len(), 2);
        assert_eq!(cli.replay.min_conflict_kind.len(), 1);
        assert!(
            Cli::try_parse_from(["replay", "manifest.json", "--min-policy-rule", "bad"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["replay", "manifest.json", "--min-conflict-kind", "Bad=1"])
                .is_err()
        );
    }

    #[test]
    fn portable_native_replay_preserves_origin_after_source_deletion() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let signer = Signer::new()?;
        let source = init_repo(root.join("source"), "main", &signer.env)?;
        source.change(&[("value.txt", "base\n")], "Define the base value")?;
        let base: Vec<_> = source
            .pijul(&["log", "--channel", "main", "--hash-only"])?
            .split_whitespace()
            .rev()
            .map(str::to_owned)
            .collect();
        let states: Vec<Value> = serde_json::from_str(&source.pijul(&[
            "log",
            "--channel",
            "main",
            "--state",
            "--output-format",
            "json",
        ])?)?;
        source.pijul(&["fork", "--channel", "main", "inbox"])?;
        let candidate = source.change(&[("value.txt", "candidate\n")], "Change the value")?;
        let origin = fs::canonicalize(&source.path)?;
        let configuration = Configuration::default();
        let snapshot = json!({
            "repository": origin, "main": "main", "inbox": "inbox",
            "main_state": states[0]["state"], "base": base, "candidate": candidate,
            "policy_path": "POLICY.md", "policy_sha256": null,
            "configuration": {"source": "environment", "path": null, "sha256": null, "values": configuration},
        });
        let manifest = json!({
            "schema_version": 1, "repository": origin, "main": "main", "inbox": "inbox",
            "configuration": configuration,
            "cases": [{
                "id": "portable", "base": base, "candidate": candidate, "expected": "accept",
                "configuration": configuration, "snapshot": snapshot,
                "labels": [{
                    "user": "reviewer", "time": "2026-10-21T00:00:00Z",
                    "expected": "accept", "reason": "The reviewer approves the change.",
                }],
            }],
            "variants": [{
                "id": "model", "model_url": "http://localhost:8080",
                "model": "model", "api": "openai", "revision": "revision",
            }],
        });
        let path = root.join("cases.tar.gz");
        crate::bundle::write(&origin, manifest, &path)?;
        fs::remove_dir_all(&source.path)?;
        let mut loaded = crate::bundle::load(&path)?;
        let manifest: Manifest = serde_json::from_value(std::mem::take(&mut loaded.manifest))?;
        validate(&manifest, &manifest.configuration.policy_path)?;
        assert_eq!(loaded.origin_repository, origin);
        assert_eq!(manifest.cases[0].snapshot.as_ref().unwrap(), &snapshot);
        preflight(
            &loaded.repository,
            &loaded.origin_repository,
            &directory.path().join("portable-preflight"),
            &manifest.cases[0],
            &manifest,
            &signer.env,
        )?;
        assert!(
            preflight(
                &loaded.repository,
                &directory.path().join("wrong-origin"),
                &directory.path().join("wrong-origin-preflight"),
                &manifest.cases[0],
                &manifest,
                &signer.env,
            )
            .is_err()
        );
        assert!(!origin.exists());
        Ok(())
    }

    #[test]
    fn signed_baseline_uses_one_snapshot_and_retains_trust_evidence() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let key = root.join("reviewer");
        checked_output(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .output()?,
            "Create the review key",
        )?;
        let allowed = root.join("allowed-signers");
        fs::write(
            &allowed,
            format!(
                "reviewer {}",
                fs::read_to_string(key.with_extension("pub"))?
            ),
        )?;
        let path = root.join("baseline.json");
        let bytes = serde_json::to_vec(&json!({
            "schema_version": 1, "repository": "/captured/source",
            "main": "main", "inbox": "inbox", "variants": [], "comparisons": [],
            "authorizes_acceptance": false,
        }))?;
        fs::write(&path, &bytes)?;
        let signature = root.join("baseline.sig");
        crate::artifact::sign(
            &root,
            &path,
            crate::artifact::Kind::Baseline,
            &key,
            &signature,
        )?;
        let trust = crate::artifact::Trust {
            signature,
            allowed_signers: allowed,
            revoked_keys: None,
            identity: "reviewer".into(),
        };
        let (_baseline, verified) = baseline_input(&path, Some(&trust))?;
        fs::write(&path, b"replacement report")?;
        let verified = verified.unwrap();
        assert_eq!(verified.sha256, format!("{:x}", Sha256::digest(&bytes)));
        assert_eq!(verified.identity, "reviewer");
        assert!(!verified.authorizes_acceptance);
        assert!(baseline_input(&path, Some(&trust)).is_err());
        let evidence = SignatureEvidence {
            strict: true,
            bundle: None,
            baseline: Some(verified),
        };
        let json = serde_json::to_value(evidence)?;
        assert_eq!(json["baseline"]["identity"], "reviewer");
        assert_eq!(json["baseline"]["authorizes_acceptance"], false);
        assert_eq!(json["baseline"]["namespace"], "patchgate-baseline-v1");
        Ok(())
    }

    #[test]
    fn strict_artifacts_reject_trust_file_changes_between_verifications() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let key = root.join("reviewer");
        checked_output(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .output()?,
            "Create the review key",
        )?;
        let allowed = root.join("allowed-signers");
        let allowed_bytes = format!(
            "reviewer {}",
            fs::read_to_string(key.with_extension("pub"))?
        );
        fs::write(&allowed, &allowed_bytes)?;
        let revoked = root.join("revoked-keys");
        fs::write(&revoked, b"")?;
        let bundle = root.join("bundle.tar.gz");
        fs::write(&bundle, b"exact bundle bytes")?;
        let bundle_signature = root.join("bundle.sig");
        crate::artifact::sign(
            &root,
            &bundle,
            crate::artifact::Kind::Bundle,
            &key,
            &bundle_signature,
        )?;
        let baseline = root.join("baseline.json");
        fs::write(&baseline, successful_promotion_report())?;
        let baseline_signature = root.join("baseline.sig");
        crate::artifact::sign(
            &root,
            &baseline,
            crate::artifact::Kind::Baseline,
            &key,
            &baseline_signature,
        )?;
        let mut trust = crate::artifact::Trust {
            signature: bundle_signature,
            allowed_signers: allowed.clone(),
            revoked_keys: Some(revoked.clone()),
            identity: "reviewer".into(),
        };
        let authenticated =
            crate::artifact::snapshot(&bundle, crate::artifact::Kind::Bundle, &trust)?;
        trust.signature = baseline_signature;
        let (_, verified) = baseline_input(&baseline, Some(&trust))?;
        validate_trust_consistency(Some(&authenticated.verified), verified.as_ref())?;
        for (path, replacement) in [
            (&allowed, format!("{allowed_bytes}# New trust snapshot\n")),
            (&revoked, "# New revocation snapshot\n".into()),
        ] {
            fs::write(path, replacement)?;
            let (_, verified) = baseline_input(&baseline, Some(&trust))?;
            assert!(
                validate_trust_consistency(Some(&authenticated.verified), verified.as_ref())
                    .is_err()
            );
            fs::write(&allowed, &allowed_bytes)?;
            fs::write(&revoked, b"")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod release_policy_tests {
    use super::*;

    fn policy() -> crate::release_policy::Policy {
        serde_json::from_value(json!({
            "schema_version": 1,
            "limits": {"max_unsafe_acceptances": 1, "max_label_mismatches": 2, "max_regressions": 3},
            "coverage": {"policy_rules": {"security": 2}, "conflict_kinds": {"order": 1}},
            "signatures": {"require_bundle": false, "require_baseline": false}
        })).unwrap()
    }

    #[test]
    fn policy_rejects_weaker_overrides_and_preserves_stricter_requirements() {
        let policy = policy();
        let mut args = ReplayArgs {
            max_label_mismatches: Some(1),
            min_policy_rule: vec![
                release_gate::parse_requirement("security=3").unwrap(),
                release_gate::parse_requirement("extra=1").unwrap(),
            ],
            ..ReplayArgs::default()
        };
        release_gate::apply_policy(&mut args, &policy).unwrap();
        assert!(args.gate);
        assert_eq!(args.max_unsafe_acceptances, Some(1));
        assert_eq!(args.max_label_mismatches, Some(1));
        assert_eq!(args.min_policy_rule.len(), 2);
        assert_eq!(args.min_conflict_kind.len(), 1);
        for mut args in [
            ReplayArgs {
                max_unsafe_acceptances: Some(2),
                ..ReplayArgs::default()
            },
            ReplayArgs {
                max_label_mismatches: Some(3),
                ..ReplayArgs::default()
            },
            ReplayArgs {
                max_regressions: Some(4),
                ..ReplayArgs::default()
            },
            ReplayArgs {
                min_policy_rule: vec![release_gate::parse_requirement("security=1").unwrap()],
                ..ReplayArgs::default()
            },
            ReplayArgs {
                min_policy_rule: vec![
                    release_gate::parse_requirement("security=2").unwrap(),
                    release_gate::parse_requirement("security=3").unwrap(),
                ],
                ..ReplayArgs::default()
            },
        ] {
            assert!(release_gate::apply_policy(&mut args, &policy).is_err());
        }
    }

    #[test]
    fn policy_requires_selected_artifacts_and_exact_verified_trust() {
        let mut policy = policy();
        policy.signatures.require_bundle = true;
        policy.signatures.signer = Some("reviewer".into());
        policy.signatures.allowed_signers_sha256 = Some("a".repeat(64));
        policy.signatures.revoked_keys_sha256 = Some("b".repeat(64));
        policy.baseline_sha256 = Some("c".repeat(64));
        let mut args = ReplayArgs::default();
        assert!(release_gate::apply_policy(&mut args, &policy).is_err());
        args.bundle = Some("bundle.tar.gz".into());
        args.baseline = Some("baseline.json".into());
        args.allowed_signers = Some("allowed-signers".into());
        args.revoked_keys = Some("revoked-keys".into());
        release_gate::apply_policy(&mut args, &policy).unwrap();
        assert!(strict_signatures(&args).is_err());
        args.bundle_signature = Some("bundle.sig".into());
        args.baseline_signature = Some("baseline.sig".into());
        assert!(strict_signatures(&args).unwrap());
        let mut verified: crate::artifact::Verified = serde_json::from_value(json!({
            "schema_version": 1, "authorizes_acceptance": false,
            "kind": "bundle", "sha256": "d".repeat(64), "identity": "reviewer",
            "allowed_signers_sha256": "a".repeat(64),
            "signer_fingerprint": "SHA256:verified",
            "revoked_keys_sha256": "b".repeat(64), "namespace": "patchgate-bundle-v1"
        }))
        .unwrap();
        validate_policy_artifact(&policy, &verified).unwrap();
        verified.allowed_signers_sha256 = "e".repeat(64);
        assert!(validate_policy_artifact(&policy, &verified).is_err());
        verified.allowed_signers_sha256 = "a".repeat(64);
        verified.revoked_keys_sha256 = None;
        assert!(validate_policy_artifact(&policy, &verified).is_err());
        let directory = tempfile::tempdir().unwrap();
        let baseline = directory.path().join("baseline.json");
        fs::write(&baseline, b"{}").unwrap();
        assert!(baseline_input_pinned(&baseline, None, Some(&policy)).is_err());
    }

    #[test]
    fn promotion_recomputes_rows_bounds_and_gate_claims() {
        let bytes = successful_promotion_report();
        validate_promotion_report(&bytes).unwrap();
        let original: Value = serde_json::from_slice(&bytes).unwrap();
        let mut allowed = original.clone();
        allowed["comparisons"][0]["actual"] = json!("accept");
        allowed["comparisons"][0]["evidence"]["records"][0]["decision"] = json!("accept");
        allowed["comparisons"][0]["unsafe_acceptance"] = json!(true);
        allowed["comparisons"][0]["correct"] = json!(false);
        allowed["gate"]["limits"]["unsafe_acceptances"] = json!(1);
        allowed["gate"]["limits"]["label_mismatches"] = json!(1);
        allowed["gate"]["observed"]["unsafe_acceptances"] = json!(1);
        allowed["gate"]["observed"]["label_mismatches"] = json!(1);
        allowed["summaries"][0]["unsafe_acceptances"] = json!(1);
        allowed["summaries"][0]["label_mismatches"] = json!(1);
        validate_promotion_report(&serde_json::to_vec(&allowed).unwrap()).unwrap();
        for (pointer, value) in [
            ("/comparisons", json!([])),
            ("/comparisons/0/exit_code", json!(1)),
            ("/comparisons/0/configuration/max_change_chars", json!(1)),
            ("/comparisons/0/elapsed_seconds", json!(-1)),
            ("/gate/observed/unsafe_acceptances", json!(99)),
            ("/gate/limits/regressions", json!(-1)),
            ("/gate/passed", json!(false)),
            ("/gate", Value::Null),
            ("/summaries/0/comparisons", json!(99)),
        ] {
            let mut report = original.clone();
            *report.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_promotion_report(&serde_json::to_vec(&report).unwrap()).is_err(),
                "{pointer}"
            );
        }
        allowed["gate"]["limits"]["unsafe_acceptances"] = json!(0);
        assert!(validate_promotion_report(&serde_json::to_vec(&allowed).unwrap()).is_err());
    }

    #[test]
    fn promotion_rejects_contradictory_current_and_baseline_review_evidence() {
        let mut original: Value = serde_json::from_slice(&successful_promotion_report()).unwrap();
        original["gate"]["baseline"] = json!({
            "schema_version": 1, "repository": original["repository"],
            "main": original["main"], "inbox": original["inbox"],
            "variants": original["variants"], "comparisons": original["comparisons"],
            "authorizes_acceptance": false,
        });
        validate_promotion_report(&serde_json::to_vec(&original).unwrap()).unwrap();
        for rows in ["/comparisons", "/gate/baseline/comparisons"] {
            for (field, value) in [
                ("decision", json!("accept")),
                ("execution_error", json!("The candidate review failed.")),
                ("by", json!("human")),
            ] {
                let mut report = original.clone();
                report.pointer_mut(rows).unwrap()[0]["evidence"]["records"][0][field] = value;
                assert!(validate_promotion_report(&serde_json::to_vec(&report).unwrap()).is_err());
            }
            for field in ["dry_run", "authorizes_acceptance"] {
                let mut report = original.clone();
                report.pointer_mut(rows).unwrap()[0]["evidence"][field] =
                    json!(field == "authorizes_acceptance");
                assert!(validate_promotion_report(&serde_json::to_vec(&report).unwrap()).is_err());
            }
        }
    }
}

#[cfg(test)]
mod caller_policy_tests {
    use super::*;

    #[test]
    fn caller_main_policy_cannot_be_omitted_or_replaced_by_working_policy() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("repo");
        let cwd = root.join("nested");
        fs::create_dir_all(&cwd)?;
        let pijul = crate::pijul::Pijul::new(root.clone());
        pijul.run(["init"])?;
        fs::write(root.join("base.txt"), "base\n")?;
        pijul.run(["add", "base.txt"])?;
        let signer = crate::pijul::Signer::new(root.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        let record = |message: &str| -> Result<()> {
            pijul.call_with_env(
                ["record", "-a", "-m", message, "--author", "patchgate"],
                &environment.vars,
            )?;
            Ok(())
        };
        record("Record the base")?;
        let path = root.join(crate::release_policy::PATH);
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "limits": {"max_unsafe_acceptances": 0, "max_label_mismatches": 2, "max_regressions": 0},
                "coverage": {"policy_rules": {}, "conflict_kinds": {}},
                "signatures": {"require_bundle": false, "require_baseline": false}
            }))?,
        )?;
        assert!(caller_release_policy(&cwd)?.policy.is_none());
        let explicit = ReplayArgs {
            release_repo: Some(root.clone()),
            ..ReplayArgs::default()
        };
        assert!(load_release_policy(&explicit).is_err());
        pijul.run(["add", crate::release_policy::PATH])?;
        record("Record release requirements")?;
        fs::write(&path, "unrecorded invalid policy")?;
        let loaded = caller_release_policy(&cwd)?;
        let mut args = ReplayArgs::default();
        release_gate::apply_policy(&mut args, loaded.policy.as_ref().unwrap())?;
        assert!(args.gate);
        assert_eq!(args.max_label_mismatches, Some(2));
        assert_eq!(fs::read_to_string(&path)?, "unrecorded invalid policy");
        record("Record invalid release requirements")?;
        assert!(caller_release_policy(&cwd).is_err());
        assert!(load_release_policy(&explicit).is_err());
        Ok(())
    }
}
