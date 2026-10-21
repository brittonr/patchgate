use super::support::*;
use clap::Args;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Component;
use std::sync::Arc;

#[derive(Args)]
pub struct ReplayArgs {
    pub manifest: PathBuf,
    #[arg(long)]
    pub report: Option<PathBuf>,
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

#[derive(Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Configuration {
    policy_path: String,
    protected: Vec<String>,
    max_change_chars: usize,
    timeout_seconds: u64,
    check_timeout_seconds: u64,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            policy_path: "POLICY.md".into(),
            protected: Vec::new(),
            max_change_chars: 8000,
            timeout_seconds: 300,
            check_timeout_seconds: 900,
        }
    }
}

fn main_channel() -> String {
    "main".into()
}

fn inbox_channel() -> String {
    "inbox".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    base: Vec<String>,
    candidate: String,
    expected: Label,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Label {
    Accept,
    Reject,
    Escalate,
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

#[derive(Serialize)]
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
}

impl Comparison {
    fn new(case: &Case, variant: &Variant) -> Self {
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

#[derive(Serialize)]
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

#[derive(Serialize)]
struct Latency {
    samples: usize,
    total_seconds: f64,
    mean_seconds: Option<f64>,
    median_seconds: Option<f64>,
    p95_seconds: Option<f64>,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    manifest: PathBuf,
    repository: PathBuf,
    main: String,
    inbox: String,
    configuration: Configuration,
    variants: Vec<Variant>,
    comparisons: Vec<Comparison>,
    summaries: Vec<Summary>,
    infrastructure_errors: usize,
    authorizes_acceptance: bool,
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 53
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
}

fn validate(manifest: &Manifest, policy_path: &str) -> Result<()> {
    ensure!(
        manifest.schema_version == 1,
        "The manifest schema_version must be 1."
    );
    ensure!(
        manifest.configuration.timeout_seconds > 0
            && manifest.configuration.check_timeout_seconds > 0,
        "Replay time limits must be positive."
    );
    ensure!(
        manifest.configuration.protected.iter().all(|pattern| {
            !pattern.trim().is_empty()
                && !pattern.contains(',')
                && !pattern.chars().any(char::is_control)
        }),
        "Protected path patterns must be nonempty and cannot contain commas or control characters."
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
    let policy = Path::new(policy_path);
    ensure!(
        !policy_path.is_empty()
            && policy
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            && !policy.starts_with(".pijul"),
        "PATCHGATE_POLICY must name a relative file outside .pijul."
    );
    let mut ids = BTreeSet::new();
    for case in &manifest.cases {
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

fn preflight(
    source: &Path,
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
            manifest.configuration.protected.join(","),
        )
        .env(
            "PATCHGATE_MAX_CHANGE_CHARS",
            manifest.configuration.max_change_chars.to_string(),
        )
        .env(
            "PATCHGATE_TIMEOUT",
            manifest.configuration.timeout_seconds.to_string(),
        )
        .env(
            "PATCHGATE_CHECK_TIMEOUT",
            manifest.configuration.check_timeout_seconds.to_string(),
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
        .and_then(|report| report["records"].as_array())
        .and_then(|records| {
            records
                .iter()
                .rev()
                .find(|record| record["hash"].as_str() == Some(case.candidate.as_str()))
        })
        .and_then(|record| record["by"].as_str())
        .map(str::to_owned);
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
        !resolved.starts_with(source),
        "The report path must be outside the source repository."
    );
    Ok(resolved)
}

fn write_report(path: &Path, source: &Path, bytes: &[u8]) -> Result<()> {
    let path = report_outside_source(path, source)?;
    let parent = path.parent().context("The report parent is absent.")?;
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    report_outside_source(&path, source)?;
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
    let manifest_path =
        fs::canonicalize(&args.manifest).context("Read the replay manifest path.")?;
    let directory = manifest_path
        .parent()
        .context("The manifest directory is absent.")?;
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(&manifest_path)?).context("Read the replay manifest.")?;
    let policy_path = manifest.configuration.policy_path.clone();
    validate(&manifest, &policy_path)?;
    let source = fs::canonicalize(directory.join(&manifest.repository))
        .context("Read the source repository path.")?;
    ensure!(
        source.is_dir() && source.join(".pijul").is_dir(),
        "The source repository has no Pijul metadata."
    );
    let report_path = args
        .report
        .as_deref()
        .map(|path| report_outside_source(path, &source))
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
    let runtime_path = trusted_runtime_path()?;
    env.insert("PATH".into(), runtime_path.clone());
    env.insert("HOME".into(), home.into_os_string());
    env.remove(std::ffi::OsStr::new("XDG_CONFIG_HOME"));
    env.remove(std::ffi::OsStr::new("SSH_AUTH_SOCK"));
    let env = Arc::new(env);
    let signer = manifest
        .variants
        .iter()
        .any(|variant| variant.policy.is_some())
        .then(|| Signer::with_path(runtime_path));
    let mut prerequisites = BTreeMap::new();
    for (index, case) in manifest.cases.iter().enumerate() {
        if let Err(error) = preflight(
            &source,
            &temporary.path().join(format!("preflight-{index}")),
            case,
            &manifest,
            &env,
        ) {
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
            let mut comparison = Comparison::new(case, variant);
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
                    &policy_path,
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
    let report = Report {
        schema_version: 1,
        manifest: manifest_path,
        repository: source,
        main: manifest.main,
        inbox: manifest.inbox,
        configuration: manifest.configuration,
        variants: manifest.variants,
        comparisons,
        summaries,
        infrastructure_errors,
        authorizes_acceptance: false,
    };
    let mut text = serde_json::to_string_pretty(&report)?;
    text.push('\n');
    print!("{text}");
    if let Some(path) = report_path {
        write_report(&path, &report.repository, text.as_bytes())?;
    }
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
        assert!(validate(&fixture(), "../POLICY.md").is_err());
        assert!(validate(&fixture(), ".pijul/policy").is_err());
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
        let mut unsafe_row = Comparison::new(case, variant);
        unsafe_row.expected = Label::Escalate;
        unsafe_row.decision(Some(Label::Accept), "verdict".into());
        unsafe_row.exit_code = Some(0);
        unsafe_row.cli_executed = true;
        unsafe_row.elapsed_seconds = 1.0;
        let mut escalation = Comparison::new(case, variant);
        escalation.decision(Some(Label::Escalate), "verdict".into());
        escalation.exit_code = Some(0);
        escalation.cli_executed = true;
        escalation.elapsed_seconds = 3.0;
        let mut error = Comparison::new(case, variant);
        error.execution_error = Some("The model API is unavailable.".into());
        let blocked = Comparison {
            outcome: "blocked".into(),
            ..Comparison::new(case, variant)
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
        let case = Case {
            id: "historical".into(),
            base,
            candidate,
            expected: Label::Accept,
        };
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
    fn report_aliases_cannot_change_source_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        let source = fs::canonicalize(source)?;
        let original = source.join("data");
        fs::write(&original, b"source bytes")?;
        let alias = directory.path().join("report");
        fs::hard_link(&original, &alias)?;
        write_report(&alias, &source, b"report bytes")?;
        assert_eq!(fs::read(&original)?, b"source bytes");
        assert_eq!(fs::read(&alias)?, b"report bytes");
        let dangling = directory.path().join("dangling");
        std::os::unix::fs::symlink(source.join("missing"), &dangling)?;
        assert!(write_report(&dangling, &source, b"must not enter source").is_err());
        assert!(!source.join("missing").exists());
        let parent = directory.path().join("parent-alias");
        std::os::unix::fs::symlink(&source, &parent)?;
        assert!(write_report(&parent.join("nested/report"), &source, b"no").is_err());
        assert!(!source.join("nested").exists());
        Ok(())
    }
}
