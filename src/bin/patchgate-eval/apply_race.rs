use super::support::*;
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "apply-race-review",
        setup: setup_review,
        solve: solve_review,
        check: check_review,
    },
    Scenario {
        name: "apply-race-human",
        setup: setup_human,
        solve: solve_human,
        check: check_human,
    },
    Scenario {
        name: "apply-race-merge",
        setup: setup_merge,
        solve: solve_merge,
        check: check_merge,
    },
];

const MAIN: &str = "main";
const EPOCH: &str = "An independent command advances main.\n";
const NOTES: &str = "The candidate needs a current main state.\n";
const SEED: &str = "Preserve this accepted contribution.\n";
const HUMAN_POLICY: &str = "# Review policy\n\nReject a change that adds a secret. Accept other changes.\n\nA human approved this policy revision.\n";
const GREETING: &str = "#!/bin/sh\necho hello\necho bye\n";
const FRENCH: &str = "#!/bin/sh\necho hello\necho bonjour\necho bye\n";
const GERMAN: &str = "#!/bin/sh\necho hello\necho hallo\necho bye\n";

fn hash<'a>(facts: &'a Value, name: &str) -> Result<&'a str> {
    facts[name]
        .as_str()
        .with_context(|| format!("The fixture hash {name} is absent"))
}

fn setup_review(dir: &Path, signer: &Signer) -> Result<Value> {
    setup_plain(dir, signer, false)
}

fn setup_human(dir: &Path, signer: &Signer) -> Result<Value> {
    setup_plain(dir, signer, true)
}

fn setup_plain(dir: &Path, signer: &Signer, human: bool) -> Result<Value> {
    let repo = start(dir, signer, &[("POLICY.md", POLICY)])?;
    let base = repo.hashes(MAIN)?;
    let seed = repo.change(
        &[("seed.txt", SEED)],
        "Preserve an earlier human acceptance",
    )?;
    let files = if human {
        [("POLICY.md", HUMAN_POLICY)]
    } else {
        [("notes.txt", NOTES)]
    };
    let (candidate, advance) = concurrent(
        &repo,
        &files,
        "Accept the candidate against current main",
        &[("epoch.txt", EPOCH)],
        "Advance main at the native application boundary",
    )?;
    Ok(json!({"base": base, "seed": seed, "candidate": candidate, "advance": advance}))
}

fn setup_merge(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(
        dir,
        signer,
        &[("POLICY.md", POLICY), ("greet.sh", GREETING)],
    )?;
    let base = repo.hashes(MAIN)?;
    let (seed, candidate) = concurrent(
        &repo,
        &[("greet.sh", FRENCH)],
        "Preserve the French contribution",
        &[("greet.sh", GERMAN)],
        "Accept the German contribution with a recorded merge",
    )?;
    let directory = tempfile::tempdir()?;
    let author = Repo {
        path: directory.path().join("author"),
        env: Arc::clone(&repo.env),
    };
    checked_output(
        Command::new("pijul")
            .args(["clone", "--channel", MAIN])
            .arg(&repo.path)
            .arg(&author.path)
            .env_clear()
            .envs(repo.env.iter())
            .stdin(Stdio::null())
            .output()?,
        "Create the independent main author",
    )?;
    let advance = author.change(
        &[("epoch.txt", EPOCH)],
        "Advance main at the native merge application boundary",
    )?;
    author.pijul(&[
        "push",
        repo.path
            .to_str()
            .context("The repository path is not UTF-8")?,
        "--to-channel",
        "inbox",
        "--no-notify",
        "-a",
    ])?;
    Ok(json!({"base": base, "seed": seed, "candidate": candidate, "advance": advance}))
}

struct Interceptor {
    _directory: tempfile::TempDir,
    path: String,
    real: String,
    executable: String,
}

impl Interceptor {
    fn new(repo: &Repo) -> Result<Self> {
        let source_path = repo.env.get(OsStr::new("PATH")).context("PATH is absent")?;
        let real = std::env::split_paths(source_path)
            .map(|directory| directory.join("pijul"))
            .find(|path| path.is_file())
            .context("The real Pijul binary is absent")?
            .canonicalize()?;
        let directory = tempfile::Builder::new()
            .prefix("patchgate-apply-race-")
            .tempdir()?;
        let wrapper = directory.path().join("pijul");
        fs::write(
            &wrapper,
            "#!/bin/sh\nexec \"$PATCHGATE_EVAL_INTERCEPTOR\" intercept-apply-race \"$@\"\n",
        )?;
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755))?;
        let path = std::env::join_paths(
            std::iter::once(directory.path().to_path_buf())
                .chain(std::env::split_paths(source_path)),
        )?
        .into_string()
        .map_err(|_| anyhow!("PATH is not UTF-8"))?;
        Ok(Self {
            _directory: directory,
            path,
            real: real.to_str().context("The Pijul path is not UTF-8")?.into(),
            executable: std::env::current_exe()?
                .to_str()
                .context("The evaluator path is not UTF-8")?
                .into(),
        })
    }
}

fn journal(repo: &Repo) -> PathBuf {
    repo.path.join(".pijul/patchgate/acceptance.json")
}

fn ledger_bytes(repo: &Repo) -> Result<Vec<u8>> {
    match fs::read(repo.path.join(".pijul/patchgate/ledger.jsonl")) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn working_file(repo: &Repo, path: &str) -> Result<Option<Vec<u8>>> {
    match fs::read(repo.path.join(path)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn native_state(repo: &Repo) -> Result<Value> {
    let log: Value = serde_json::from_str(&repo.pijul(&[
        "log",
        "--channel",
        MAIN,
        "--state",
        "--output-format",
        "json",
    ])?)?;
    let entries = log.as_array().context("The native log is not an array")?;
    match entries.first() {
        None => Ok(Value::Null),
        Some(entry) => Ok(json!(
            entry["state"]
                .as_str()
                .context("The native state is absent")?
        )),
    }
}

pub fn intercept_pijul(args: &[OsString]) -> Result<()> {
    let real = std::env::var_os("PATCHGATE_EVAL_REAL_PIJUL")
        .context("The evaluation wrapper has no real Pijul binary")?;
    let selected_hash = std::env::var_os("PATCHGATE_EVAL_RACE_HASH");
    let selected_repo = std::env::var_os("PATCHGATE_EVAL_RACE_REPO");
    let selected = args.first().is_some_and(|arg| arg == "apply")
        && args.get(1).is_some_and(|arg| arg == "--channel")
        && args.get(2).is_some_and(|arg| arg == MAIN)
        && selected_hash
            .as_ref()
            .is_some_and(|hash| args[3..].contains(hash))
        && selected_repo.as_ref().is_some_and(|repo| {
            std::env::current_dir()
                .ok()
                .and_then(|path| path.canonicalize().ok())
                == Path::new(repo).canonicalize().ok()
        });
    if selected {
        let repo = Repo::open(std::env::current_dir()?);
        let marker = PathBuf::from(
            std::env::var_os("PATCHGATE_EVAL_RACE_MARKER")
                .context("The evaluation wrapper has no boundary marker")?,
        );
        ensure!(
            !marker.exists(),
            "The application boundary occurred more than once"
        );
        let intent_bytes = fs::read(journal(&repo))
            .context("The gate did not prepare its acceptance journal before native application")?;
        let intent: Value = serde_json::from_slice(&intent_bytes)?;
        let candidate = selected_hash
            .as_ref()
            .context("The candidate hash is absent")?;
        ensure!(
            intent["records"]
                .as_array()
                .is_some_and(|records| records.iter().any(|record| {
                    record["hash"]
                        .as_str()
                        .is_some_and(|hash| OsStr::new(hash) == candidate)
                        && record["decision"] == "accept"
                })),
            "The journal does not contain the selected acceptance"
        );
        let before = repo.hashes(MAIN)?;
        let audit_before = ledger_bytes(&repo)?;
        let advance = std::env::var_os("PATCHGATE_EVAL_RACE_ADVANCE")
            .context("The independent change hash is absent")?;
        checked_output(
            Command::new(&real)
                .args([
                    OsStr::new("apply"),
                    OsStr::new("--channel"),
                    OsStr::new(MAIN),
                    &advance,
                ])
                .stdin(Stdio::null())
                .output()?,
            "Advance main through an independent native command",
        )?;
        let advanced = repo.hashes(MAIN)?;
        ensure!(
            advanced != before
                && advanced.contains(
                    advance
                        .to_str()
                        .context("The independent hash is not UTF-8")?
                ),
            "The independent command did not advance main"
        );
        ensure!(
            ledger_bytes(&repo)? == audit_before,
            "The independent command changed the audit"
        );
        let evidence = json!({
            "args": args.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>(),
            "journal": intent,
            "journal_bytes": intent_bytes,
            "before_main": before,
            "advanced_main": advanced,
            "advanced_state": native_state(&repo)?,
            "audit_before": audit_before,
        });
        fs::write(marker, serde_json::to_vec_pretty(&evidence)?)?;
    }
    let status = Command::new(real)
        .args(args)
        .status()
        .context("Execute the real Pijul binary")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn solve_review(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, false, false)
}

fn solve_human(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, true, false)
}

fn solve_merge(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, false, true)
}

fn solve(dir: &Path, human: bool, merge: bool) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let facts = load_facts(dir)?;
    let model = accepting_model()?;
    let binary = match repo
        .env
        .get(OsStr::new("PATCHGATE_EVAL_UNWRAPPED_BIN"))
        .or_else(|| repo.env.get(OsStr::new("PATCHGATE_BIN")))
    {
        Some(path) => PathBuf::from(path),
        None => gate_binary()?,
    };
    let binary = binary.to_str().context("The gate path is not UTF-8")?;
    let plain = [("PATCHGATE_BIN", binary)];
    checked_output(
        repo.gate(
            None,
            &[
                "accept",
                hash(&facts, "seed")?,
                "-m",
                "Preserve the earlier human decision",
            ],
            &plain,
        )?,
        "Accept the earlier contribution",
    )?;
    let before_main = repo.hashes(MAIN)?;
    let before_inbox = repo.hashes("inbox")?;
    let before_working = repo.archive("inbox")?.files;
    let before_working_files = before_working
        .keys()
        .map(|path| Ok((path.clone(), working_file(&repo, path)?)))
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    let before_audit = ledger_bytes(&repo)?;
    ensure!(
        !before_audit.is_empty(),
        "The fixture needs an existing audit record"
    );
    let candidate = hash(&facts, "candidate")?;
    let advance = hash(&facts, "advance")?;
    ensure!(
        !before_main.contains(candidate) && !before_main.contains(advance),
        "The fixture main is not at the race base"
    );
    let wrapper = Interceptor::new(&repo)?;
    let marker = dir.join("apply-race-boundary.json");
    ensure!(
        !marker.exists(),
        "The race boundary evidence already exists"
    );
    let repo_path = repo.path.canonicalize()?;
    let extra = [
        ("PATCHGATE_BIN", binary),
        ("PATH", wrapper.path.as_str()),
        ("PATCHGATE_EVAL_INTERCEPTOR", wrapper.executable.as_str()),
        ("PATCHGATE_EVAL_REAL_PIJUL", wrapper.real.as_str()),
        ("PATCHGATE_EVAL_RACE_HASH", candidate),
        ("PATCHGATE_EVAL_RACE_ADVANCE", advance),
        (
            "PATCHGATE_EVAL_RACE_REPO",
            repo_path
                .to_str()
                .context("The repository path is not UTF-8")?,
        ),
        (
            "PATCHGATE_EVAL_RACE_MARKER",
            marker.to_str().context("The marker path is not UTF-8")?,
        ),
    ];
    let human_args = [
        "accept",
        candidate,
        "-m",
        "A human approves the current policy",
    ];
    let args: &[&str] = if human { &human_args } else { &["review"] };
    let output = repo.gate(Some(&model), args, &extra)?;
    let boundary: Value = serde_json::from_slice(
        &fs::read(&marker)
            .context("The gate did not reach the final native application boundary")?,
    )?;
    let mut advanced_main = before_main.clone();
    advanced_main.insert(advance.to_owned());
    ensure!(
        boundary["before_main"] == json!(before_main),
        "The main state changed before the selected boundary"
    );
    ensure!(
        boundary["advanced_main"] == json!(advanced_main),
        "The independent command applied an unexpected change set"
    );
    ensure!(
        boundary["audit_before"] == json!(before_audit),
        "The gate changed the audit before final application"
    );
    ensure!(
        !output.status.success(),
        "The gate accepted a stale candidate"
    );
    ensure!(
        repo.hashes(MAIN)? == advanced_main,
        "The stale native application changed main"
    );
    ensure!(
        repo.hashes("inbox")? == before_inbox,
        "The stale application changed inbox"
    );
    ensure!(
        repo.archive("inbox")?.files == before_working,
        "The stale application changed the inbox files"
    );
    for (path, bytes) in &before_working_files {
        ensure!(
            working_file(&repo, path)? == *bytes,
            "The stale application changed a working-copy file"
        );
    }
    ensure!(
        ledger_bytes(&repo)? == before_audit,
        "The stale application changed the exact audit bytes"
    );
    match fs::read(journal(&repo)) {
        Ok(intent_bytes) => ensure!(
            json!(intent_bytes) == boundary["journal_bytes"],
            "The refused application changed its prepared journal"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let snapshot = repo.archive(MAIN)?;
    ensure!(
        snapshot.files.get("epoch.txt").map(Vec::as_slice) == Some(EPOCH.as_bytes()),
        "The independent content is absent from main"
    );
    if human {
        ensure!(
            snapshot.files.get("POLICY.md").map(Vec::as_slice) == Some(POLICY.as_bytes()),
            "The stale policy entered main"
        );
    } else if !merge {
        ensure!(
            !snapshot.files.contains_key("notes.txt"),
            "The stale notes entered main"
        );
    } else {
        ensure!(
            snapshot.files.get("greet.sh").map(Vec::as_slice) == Some(FRENCH.as_bytes()),
            "The stale greeting entered main"
        );
    }
    let records = boundary["journal"]["records"]
        .as_array()
        .context("The journal records are absent")?;
    let merges: Vec<_> = records
        .iter()
        .filter(|record| record["decision"] == "merge")
        .collect();
    ensure!(
        merges.len() == usize::from(merge),
        "The race did not cover the required merge path"
    );
    for record in &merges {
        let hash = record["hash"]
            .as_str()
            .context("The stale merge hash is absent")?;
        ensure!(
            !repo.hashes(MAIN)?.contains(hash) && !repo.hashes("inbox")?.contains(hash),
            "The stale merge entered a durable channel"
        );
        ensure!(
            records
                .iter()
                .any(|accept| accept["hash"] == candidate && accept["merge"] == hash),
            "The stale acceptance does not link to its merge"
        );
    }
    fs::write(
        dir.join("apply-race-refusal.json"),
        serde_json::to_vec_pretty(&json!({
            "exit_code": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
            "main": repo.hashes(MAIN)?,
            "audit": ledger_bytes(&repo)?,
        }))?,
    )?;
    checked_output(
        repo.gate(None, &["status"], &plain)?,
        "Recover the unapplied journal through a normal gate command",
    )?;
    ensure!(
        !journal(&repo).exists(),
        "Normal recovery did not remove the unapplied journal"
    );
    ensure!(
        repo.hashes(MAIN)? == advanced_main && ledger_bytes(&repo)? == before_audit,
        "Recovery changed main or the existing audit"
    );
    let fresh_state = native_state(&repo)?;
    checked_output(
        repo.gate(Some(&model), args, &plain)?,
        "Retry acceptance against fresh main",
    )?;
    let accepts: Vec<_> = repo
        .ledger()?
        .into_iter()
        .filter(|record| record["hash"] == candidate && record["decision"] == "accept")
        .collect();
    ensure!(
        accepts.len() == 1,
        "The fresh retry did not create one acceptance"
    );
    if !human {
        ensure!(
            accepts[0]["review"]["main"]["state"] == fresh_state,
            "The retry audit does not bind the fresh native main state"
        );
    }
    let complete = ledger_bytes(&repo)?;
    ensure!(
        complete.starts_with(&before_audit),
        "The fresh retry changed existing audit bytes"
    );
    checked_output(
        repo.gate(Some(&model), &["review"], &plain)?,
        "Repeat the completed review",
    )?;
    ensure!(
        ledger_bytes(&repo)? == complete,
        "A repeat review changed the exact audit bytes"
    );
    Ok(())
}

fn complete_record(record: &Value) -> bool {
    ["hash", "message", "decision", "by", "reason", "at"]
        .iter()
        .all(|field| record[*field].as_str().is_some_and(|text| !text.is_empty()))
        && match record["by"].as_str() {
            Some("model") => record["model"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            Some("human") => record["user"].as_str().is_some_and(|text| !text.is_empty()),
            _ => true,
        }
}

fn check_review(check: &mut Check) -> Result<()> {
    check_final(check, false, false)
}

fn check_human(check: &mut Check) -> Result<()> {
    check_final(check, true, false)
}

fn check_merge(check: &mut Check) -> Result<()> {
    check_final(check, false, true)
}

fn check_final(check: &mut Check, human: bool, merge: bool) -> Result<()> {
    let ledger = check.repo.ledger()?;
    let merges: Vec<_> = ledger
        .iter()
        .filter(|record| record["decision"] == "merge")
        .collect();
    check.require(
        merges.len() == usize::from(merge),
        "The final audit must contain the required merge count",
    );
    check.require(
        ledger.len() == 2 + usize::from(merge) && ledger.iter().all(complete_record),
        "The final audit must contain only complete expected records",
    );
    check.decision("seed", "accept", "human")?;
    check.decision("candidate", "accept", if human { "human" } else { "model" })?;
    for name in ["seed", "candidate"] {
        check.require(
            check.records(name)?.len() == 1,
            format!("{name} must have exactly one audit record"),
        );
    }
    check.require(
        check.records("advance")?.is_empty(),
        "The external update must not acquire a gate acceptance",
    );
    let mut expected: BTreeSet<String> = check.facts["base"]
        .as_array()
        .context("The base hashes are absent")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("A base hash is not text")
        })
        .collect::<Result<_>>()?;
    for name in ["seed", "candidate", "advance"] {
        expected.insert(hash(&check.facts, name)?.to_owned());
    }
    if let Some(record) = merges.first() {
        let merge_hash = record["hash"]
            .as_str()
            .context("The merge hash is absent")?;
        expected.insert(merge_hash.to_owned());
        let accepts = check.records("candidate")?;
        check.require(
            accepts.len() == 1 && accepts[0]["merge"] == merge_hash,
            "The acceptance must link to its single recorded merge",
        );
        check.require(
            record["for"] == json!([hash(&check.facts, "candidate")?])
                && record["files"] == json!(["greet.sh"]),
            "The merge must identify its candidate and conflict file",
        );
        let log: Value = serde_json::from_str(&check.repo.pijul(&[
            "log",
            "--channel",
            MAIN,
            "--output-format",
            "json",
        ])?)?;
        check.require(
            log.as_array().is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry["hash"] == merge_hash && entry["authors"] == json!(["patchgate"])
                })
            }),
            "The native merge must use the gate author identity",
        );
    }
    for channel in [MAIN, "inbox"] {
        check.require(
            check.repo.hashes(channel)? == expected,
            format!("{channel} must contain exactly the accepted and external changes"),
        );
        check.no_conflicts(channel)?;
        check.require(
            check.file(channel, "epoch.txt")?.as_deref() == Some(EPOCH),
            "The external update must survive in both channels",
        );
        if merge {
            let text = check.file(channel, "greet.sh")?.unwrap_or_default();
            check.require(
                text.lines().count() == 5
                    && text.starts_with("#!/bin/sh\necho hello\n")
                    && text.ends_with("echo bye\n")
                    && text.contains("echo bonjour\n")
                    && text.contains("echo hallo\n"),
                "The final merge must preserve both greeting contributions",
            );
        } else {
            check.require(
                check.file(channel, "seed.txt")?.as_deref() == Some(SEED),
                "The earlier accepted content must survive",
            );
            let (path, text) = if human {
                ("POLICY.md", HUMAN_POLICY)
            } else {
                ("notes.txt", NOTES)
            };
            check.require(
                check.file(channel, path)?.as_deref() == Some(text),
                "The fresh candidate content must exist in both channels",
            );
        }
    }
    check.require(
        !journal(&check.repo).exists(),
        "The final acceptance journal must be absent",
    );
    Ok(())
}
