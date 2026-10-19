use super::support::*;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "crash-restart-acceptance",
        setup: setup_acceptance,
        solve: solve_acceptance,
        check: check_acceptance,
    },
    Scenario {
        name: "crash-restart-merge",
        setup: setup_merge,
        solve: solve_merge,
        check: check_merge,
    },
];

const MAIN: &str = "main";
const GREETING: &str = "#!/bin/sh\necho hello\necho bye\n";
const FRENCH: &str = "#!/bin/sh\necho hello\necho bonjour\necho bye\n";
const GERMAN: &str = "#!/bin/sh\necho hello\necho hallo\necho bye\n";
const HUMAN_POLICY: &str = "# Review policy\n\nReject a change that adds a secret. Accept other changes.\n\nA human approved this policy revision.\n";

fn setup_acceptance(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(
        dir,
        signer,
        &[("POLICY.md", POLICY), ("note.txt", "base\n")],
    )?;
    let base = repo.hashes(MAIN)?;
    let model = repo.change(
        &[("note.txt", "accepted content\n")],
        "Accept a normal change",
    )?;
    let human = repo.change(
        &[("POLICY.md", HUMAN_POLICY)],
        "Accept a policy revision by hand",
    )?;
    Ok(json!({"base": base, "model": model, "human": human}))
}

fn setup_merge(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(
        dir,
        signer,
        &[("POLICY.md", POLICY), ("greet.sh", GREETING)],
    )?;
    let base = repo.hashes(MAIN)?;
    let (french, german) = concurrent(
        &repo,
        &[("greet.sh", FRENCH)],
        "Add the French greeting",
        &[("greet.sh", GERMAN)],
        "Add the German greeting",
    )?;
    Ok(json!({"base": base, "french": french, "german": german}))
}

fn hash<'a>(facts: &'a Value, name: &str) -> Result<&'a str> {
    facts[name]
        .as_str()
        .with_context(|| format!("Missing fixture hash {name}"))
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
            .prefix("patchgate-crash-wrapper-")
            .tempdir()?;
        let wrapper = directory.path().join("pijul");
        fs::write(
            &wrapper,
            "#!/bin/sh\nexec \"$PATCHGATE_EVAL_INTERCEPTOR\" intercept-pijul \"$@\"\n",
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

pub fn intercept_pijul(args: &[OsString]) -> Result<()> {
    let real = std::env::var_os("PATCHGATE_EVAL_REAL_PIJUL")
        .context("The evaluation wrapper has no real Pijul binary")?;
    let status = Command::new(real)
        .args(args)
        .status()
        .context("Execute the real Pijul binary")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    let selected_hash = std::env::var_os("PATCHGATE_EVAL_CRASH_HASH");
    let selected_repo = std::env::var_os("PATCHGATE_EVAL_CRASH_REPO");
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
        let parent = unsafe { libc::getppid() };
        ensure!(parent > 1, "The evaluation wrapper has no gate parent");
        ensure!(
            unsafe { libc::kill(parent, libc::SIGSTOP) } == 0,
            "Cannot stop the gate parent"
        );
        let marker = PathBuf::from(
            std::env::var_os("PATCHGATE_EVAL_CRASH_MARKER")
                .context("The evaluation wrapper has no boundary marker")?,
        );
        let temporary = marker.with_extension("tmp");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let data = json!({
            "parent": parent,
            "hash": selected_hash.as_ref().map(|hash| hash.to_string_lossy()),
            "args": args.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>(),
        });
        serde_json::to_writer(&mut file, &data)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, &marker)?;
        fs::File::open(marker.parent().context("The marker has no parent")?)?.sync_all()?;
    }
    Ok(())
}

fn kill_at_application(
    dir: &Path,
    repo: &Repo,
    model: Option<&ModelServer>,
    args: &[&str],
    candidate: &str,
    label: &str,
) -> Result<()> {
    let wrapper = Interceptor::new(repo)?;
    let marker = dir.join(format!("crash-{label}.json"));
    if marker.exists() {
        fs::remove_file(&marker)?;
    }
    let temporary = marker.with_extension("tmp");
    if temporary.exists() {
        fs::remove_file(temporary)?;
    }
    let repo_path = repo.path.canonicalize()?;
    let extra = [
        ("PATH", wrapper.path.as_str()),
        ("PATCHGATE_EVAL_INTERCEPTOR", wrapper.executable.as_str()),
        ("PATCHGATE_EVAL_REAL_PIJUL", wrapper.real.as_str()),
        ("PATCHGATE_EVAL_CRASH_HASH", candidate),
        (
            "PATCHGATE_EVAL_CRASH_REPO",
            repo_path
                .to_str()
                .context("The repository path is not UTF-8")?,
        ),
        (
            "PATCHGATE_EVAL_CRASH_MARKER",
            marker.to_str().context("The marker path is not UTF-8")?,
        ),
    ];
    let mut child = repo.spawn_gate(model, args, &extra)?;
    let child_id = u64::from(child.id());
    let deadline = Instant::now() + Duration::from_secs(60);
    while !marker.exists() {
        if let Some(status) = child.try_wait()? {
            let output = child.wait_with_output()?;
            bail!(
                "The gate exited before the selected application: {status}. {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            bail!("The gate did not reach the selected application");
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.kill()?;
    let output = child.wait_with_output()?;
    ensure!(
        output.status.signal() == Some(libc::SIGKILL),
        "The gate did not die from SIGKILL"
    );
    let marker: Value = serde_json::from_slice(&fs::read(&marker)?)?;
    ensure!(
        marker["parent"].as_u64() == Some(child_id) && marker["hash"] == candidate,
        "The boundary marker does not identify the gate and its candidate"
    );
    ensure!(
        repo.hashes(MAIN)?.contains(candidate),
        "The killed gate did not apply its candidate"
    );
    ensure!(
        !repo
            .ledger()?
            .iter()
            .any(|record| record["hash"] == candidate && record["decision"] == "accept"),
        "The gate reached the ledger before the crash boundary"
    );
    Ok(())
}

fn restart(repo: &Repo, model: &ModelServer) -> Result<()> {
    checked_output(
        repo.gate(Some(model), &["review"], &[])?,
        "Restart the gate",
    )?;
    let before = repo.ledger()?;
    checked_output(
        repo.gate(Some(model), &["review"], &[])?,
        "Repeat the gate review",
    )?;
    ensure!(
        repo.ledger()? == before,
        "The repeated review added duplicate decisions"
    );
    Ok(())
}

fn solve_acceptance(dir: &Path, _: &RunOptions) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let facts = load_facts(dir)?;
    let model = accepting_model()?;
    kill_at_application(
        dir,
        &repo,
        Some(&model),
        &["review"],
        hash(&facts, "model")?,
        "model",
    )?;
    restart(&repo, &model)?;
    let human = hash(&facts, "human")?;
    kill_at_application(
        dir,
        &repo,
        Some(&model),
        &["accept", human, "-m", "A human approves the policy"],
        human,
        "human",
    )?;
    restart(&repo, &model)
}

fn solve_merge(dir: &Path, _: &RunOptions) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let facts = load_facts(dir)?;
    checked_output(
        repo.gate(
            None,
            &[
                "accept",
                hash(&facts, "french")?,
                "-m",
                "A human approves the French greeting",
            ],
            &[],
        )?,
        "Accept the first contribution",
    )?;
    let model = accepting_model()?;
    kill_at_application(
        dir,
        &repo,
        Some(&model),
        &["review"],
        hash(&facts, "german")?,
        "merge",
    )?;
    restart(&repo, &model)
}

fn complete_record(record: &Value) -> bool {
    ["hash", "message", "decision", "by", "reason", "at"]
        .iter()
        .all(|field| record[*field].as_str().is_some_and(|text| !text.is_empty()))
        && match record["by"].as_str() {
            Some("model") => record["model"]
                .as_str()
                .is_some_and(|model| !model.is_empty()),
            Some("human") => record["user"].as_str().is_some_and(|user| !user.is_empty()),
            _ => true,
        }
}

fn check_channels(check: &mut Check, names: &[&str], merge: Option<&str>) -> Result<()> {
    let mut expected = std::collections::BTreeSet::new();
    for value in check.facts["base"]
        .as_array()
        .context("Missing base hashes")?
    {
        expected.insert(
            value
                .as_str()
                .context("A base hash is not text")?
                .to_owned(),
        );
    }
    for name in names {
        expected.insert(hash(&check.facts, name)?.to_owned());
    }
    if let Some(merge) = merge {
        expected.insert(merge.into());
    }
    for channel in [MAIN, "inbox"] {
        check.require(
            check.repo.hashes(channel)? == expected,
            format!("{channel} has an unexpected change set"),
        );
        check.no_conflicts(channel)?;
    }
    let journal = check.repo.path.join(".pijul/patchgate/acceptance.json");
    check.require(
        !journal.exists(),
        "The gate must complete its durable acceptance transaction",
    );
    Ok(())
}

fn check_acceptance(check: &mut Check) -> Result<()> {
    check_channels(check, &["model", "human"], None)?;
    check.decision("model", "accept", "model")?;
    check.decision("human", "accept", "human")?;
    for name in ["model", "human"] {
        let records = check.records(name)?;
        let accepts: Vec<_> = records
            .iter()
            .filter(|record| record["decision"] == "accept")
            .collect();
        check.require(
            accepts.len() == 1,
            format!("{name} must have exactly one acceptance"),
        );
        check.require(
            records.iter().all(complete_record),
            format!("{name} has an incomplete audit record"),
        );
        let valid_history = if name == "model" {
            records.len() == 1
        } else {
            records.len() == 2 && records[0]["decision"] == "escalate" && records[0]["by"] == "gate"
        };
        check.require(
            valid_history,
            format!("{name} has unexpected audit transitions"),
        );
    }
    check.require(
        check.repo.ledger()?.len() == 3,
        "The ledger must contain one model acceptance and two human transitions",
    );
    for channel in [MAIN, "inbox"] {
        check.require(
            check.file(channel, "note.txt")?.as_deref() == Some("accepted content\n"),
            "The accepted content is absent",
        );
        check.require(
            check.file(channel, "POLICY.md")?.as_deref() == Some(HUMAN_POLICY),
            "The human policy revision is absent",
        );
    }
    Ok(())
}

fn check_merge(check: &mut Check) -> Result<()> {
    let ledger = check.repo.ledger()?;
    let merges: Vec<_> = ledger
        .iter()
        .filter(|record| record["decision"] == "merge")
        .collect();
    check.require(
        merges.len() == 1,
        "The ledger must contain exactly one merge",
    );
    check.require(
        ledger.len() == 3 && ledger.iter().all(complete_record),
        "The ledger must contain three complete audit records",
    );
    check.decision("french", "accept", "human")?;
    check.decision("german", "accept", "model")?;
    if let Some(merge) = merges.first() {
        let merge_hash = merge["hash"].as_str().context("The merge hash is absent")?;
        check_channels(check, &["french", "german"], Some(merge_hash))?;
        let accepts = check.records("german")?;
        check.require(
            accepts.len() == 1 && accepts[0]["merge"] == merge_hash,
            "The acceptance must link to its single merge",
        );
        check.require(
            merge["for"] == json!([hash(&check.facts, "german")?])
                && merge["files"] == json!(["greet.sh"]),
            "The merge must link to its candidate and conflict file",
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
            "The recorded merge must identify patchgate as its author.",
        );
    }
    for channel in [MAIN, "inbox"] {
        let text = check.file(channel, "greet.sh")?.unwrap_or_default();
        check.require(
            text.lines().count() == 5
                && text.contains("echo bonjour\n")
                && text.contains("echo hallo\n")
                && text.starts_with("#!/bin/sh\necho hello\n")
                && text.ends_with("echo bye\n"),
            "The merge must preserve both greeting contributions",
        );
    }
    Ok(())
}
