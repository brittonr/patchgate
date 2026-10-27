use super::support::*;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "revert-race",
        setup,
        solve: solve_race,
        check: check_race,
    },
    Scenario {
        name: "revert-uncertain-error",
        setup,
        solve: solve_uncertain,
        check: check_uncertain,
    },
];

const MAIN: &str = "main";
const TARGET: &str = "Preserve the accepted target until a valid revert.\n";
const EPOCH: &str = "An independent native command advances main.\n";
const REASON: &str = "Remove the accepted fixture target";
const UNCERTAIN_EXIT: i32 = 73;

fn hash<'a>(facts: &'a Value, name: &str) -> Result<&'a str> {
    facts[name]
        .as_str()
        .with_context(|| format!("The fixture hash {name} is absent"))
}

fn gate_path(repo: &Repo) -> Result<PathBuf> {
    match repo
        .env
        .get(OsStr::new("PATCHGATE_EVAL_UNWRAPPED_BIN"))
        .or_else(|| repo.env.get(OsStr::new("PATCHGATE_BIN")))
    {
        Some(path) => Ok(PathBuf::from(path)),
        None => gate_binary(),
    }
}

fn journal(repo: &Repo) -> PathBuf {
    repo.path.join(".pijul/patchgate/acceptance.json")
}

fn optional_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn optional_json(path: &Path) -> Result<Value> {
    optional_bytes(path)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
}

fn ledger_bytes(repo: &Repo) -> Result<Vec<u8>> {
    Ok(optional_bytes(&repo.path.join(".pijul/patchgate/ledger.jsonl"))?.unwrap_or_default())
}

fn work_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if directory == root && entry.file_name() == ".pijul" {
                continue;
            }
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                collect(root, &path, files)?;
            } else {
                files.insert(
                    path.strip_prefix(root)?
                        .to_str()
                        .context("A work-file path is not UTF-8")?
                        .to_owned(),
                    fs::read(path)?,
                );
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    collect(root, root, &mut files)?;
    Ok(files)
}

fn native_state(repo: &Repo) -> Result<String> {
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
        None => Ok("empty".into()),
        Some(entry) => entry["state"]
            .as_str()
            .map(str::to_owned)
            .context("The native state is absent"),
    }
}

fn observe(repo: &Repo) -> Result<Value> {
    Ok(json!({
        "main": repo.hashes(MAIN)?,
        "state": native_state(repo)?,
        "main_files": repo.archive(MAIN)?.files,
        "inbox": repo.hashes("inbox")?,
        "inbox_files": repo.archive("inbox")?.files,
        "work_files": work_files(&repo.path)?,
        "audit": ledger_bytes(repo)?,
        "records": repo.ledger()?,
        "journal_bytes": optional_bytes(&journal(repo))?,
    }))
}

fn setup(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(
        dir,
        signer,
        &[
            ("POLICY.md", POLICY),
            ("work.txt", "Base work-file content.\n"),
        ],
    )?;
    let base = repo.hashes(MAIN)?;
    let (target, epoch) = concurrent(
        &repo,
        &[("target.txt", TARGET)],
        "Accept the native revert target",
        &[("epoch.txt", EPOCH)],
        "Advance main at the native revert boundary",
    )?;
    let binary = gate_path(&repo)?;
    checked_output(
        repo.gate(
            None,
            &["accept", &target, "-m", "Accept the fixture target"],
            &[(
                "PATCHGATE_BIN",
                binary.to_str().context("The gate path is not UTF-8")?,
            )],
        )?,
        "Accept the target through the real gate",
    )?;
    fs::write(
        repo.path.join("work.txt"),
        "Preserve this unrecorded edit.\n",
    )?;
    fs::write(
        repo.path.join("private-scratch.txt"),
        "Preserve this untracked file.\n",
    )?;
    Ok(json!({"base": base, "target": target, "epoch": epoch, "before": observe(&repo)?}))
}

struct Interceptor {
    _directory: tempfile::TempDir,
    path: OsString,
    real: PathBuf,
    executable: PathBuf,
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
            .prefix("patchgate-revert-")
            .tempdir()?;
        let wrapper = directory.path().join("pijul");
        fs::write(
            &wrapper,
            "#!/bin/sh\nexec \"$PATCHGATE_EVAL_INTERCEPTOR\" intercept-revert-race \"$@\"\n",
        )?;
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755))?;
        let path = std::env::join_paths(
            std::iter::once(directory.path().to_path_buf())
                .chain(std::env::split_paths(source_path)),
        )?;
        Ok(Self {
            _directory: directory,
            path,
            real,
            executable: std::env::current_exe()?,
        })
    }
}

fn output_fact(output: &Output) -> Value {
    json!({
        "exit_code": output.status.code(),
        "success": output.status.success(),
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr),
    })
}

pub fn intercept_pijul(args: &[OsString]) -> Result<()> {
    let real = std::env::var_os("PATCHGATE_EVAL_REAL_PIJUL")
        .context("The wrapper has no real Pijul binary")?;
    let target = std::env::var_os("PATCHGATE_EVAL_REVERT_TARGET");
    let selected = args.first().is_some_and(|arg| arg == "unrecord")
        && target.as_ref().is_some_and(|hash| args.contains(hash))
        && std::env::var_os("PATCHGATE_EVAL_REVERT_REPO").is_some_and(|repo| {
            std::env::current_dir()
                .ok()
                .and_then(|path| path.canonicalize().ok())
                == Path::new(&repo).canonicalize().ok()
        });
    if !selected {
        let status = Command::new(real).args(args).status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
    let repo = Repo::open(std::env::current_dir()?);
    let marker = PathBuf::from(
        std::env::var_os("PATCHGATE_EVAL_REVERT_MARKER")
            .context("The wrapper has no boundary marker")?,
    );
    let before = observe(&repo)?;
    let intent = optional_json(&journal(&repo))?;
    let uncertain = std::env::var("PATCHGATE_EVAL_REVERT_MODE").as_deref() == Ok("uncertain");
    let advance = if uncertain {
        Value::Null
    } else {
        let epoch = std::env::var_os("PATCHGATE_EVAL_REVERT_EPOCH")
            .context("The independent epoch hash is absent")?;
        output_fact(
            &Command::new(&real)
                .args([
                    OsStr::new("apply"),
                    OsStr::new("--channel"),
                    OsStr::new(MAIN),
                    &epoch,
                ])
                .stdin(Stdio::null())
                .output()?,
        )
    };
    let at_unrecord = observe(&repo)?;
    let output = Command::new(&real)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    let after = observe(&repo)?;
    fs::write(
        marker,
        serde_json::to_vec_pretty(&json!({
            "before": before,
            "intent": intent,
            "advance": advance,
            "at_unrecord": at_unrecord,
            "native": output_fact(&output),
            "after": after,
        }))?,
    )?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    std::process::exit(if uncertain && output.status.success() {
        UNCERTAIN_EXIT
    } else {
        output.status.code().unwrap_or(1)
    });
}

fn solve_race(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, false)
}

fn solve_uncertain(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, true)
}

fn solve(dir: &Path, uncertain: bool) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let facts = load_facts(dir)?;
    let binary = gate_path(&repo)?;
    let wrapper = Interceptor::new(&repo)?;
    let marker = dir.canonicalize()?.join("revert-boundary.json");
    let repo_path = repo.path.canonicalize()?;
    let extra = [
        (
            "PATCHGATE_BIN",
            binary.to_str().context("The gate path is not UTF-8")?,
        ),
        ("PATH", wrapper.path.to_str().context("PATH is not UTF-8")?),
        (
            "PATCHGATE_EVAL_INTERCEPTOR",
            wrapper
                .executable
                .to_str()
                .context("The evaluator path is not UTF-8")?,
        ),
        (
            "PATCHGATE_EVAL_REAL_PIJUL",
            wrapper
                .real
                .to_str()
                .context("The Pijul path is not UTF-8")?,
        ),
        ("PATCHGATE_EVAL_REVERT_TARGET", hash(&facts, "target")?),
        ("PATCHGATE_EVAL_REVERT_EPOCH", hash(&facts, "epoch")?),
        (
            "PATCHGATE_EVAL_REVERT_REPO",
            repo_path
                .to_str()
                .context("The repository path is not UTF-8")?,
        ),
        (
            "PATCHGATE_EVAL_REVERT_MARKER",
            marker.to_str().context("The marker path is not UTF-8")?,
        ),
        (
            "PATCHGATE_EVAL_REVERT_MODE",
            if uncertain { "uncertain" } else { "race" },
        ),
    ];
    let mut args = vec!["revert", hash(&facts, "target")?, "-m", REASON];
    if !uncertain {
        args.extend(["--expected-state", hash(&facts["before"], "state")?]);
    }
    let output = repo.gate(None, &args, &extra)?;
    let mut evidence = json!({"gate": output_fact(&output), "after": observe(&repo)?});
    fs::write(
        dir.join("revert-result.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    if uncertain {
        let plain = [(
            "PATCHGATE_BIN",
            binary.to_str().context("The gate path is not UTF-8")?,
        )];
        let mut recovery = Vec::new();
        for _ in 0..2 {
            let output = repo.gate(None, &["status"], &plain)?;
            recovery.push(json!({"gate": output_fact(&output), "after": observe(&repo)?}));
        }
        evidence["recovery"] = json!(recovery);
        fs::write(
            dir.join("revert-result.json"),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
    }
    Ok(())
}

fn unchanged_files(check: &mut Check, actual: &Value, before: &Value, label: &str) {
    for field in ["inbox", "inbox_files", "work_files"] {
        check.require(
            actual[field] == before[field],
            format!("{label} must preserve {field}"),
        );
    }
}

fn check_race(check: &mut Check) -> Result<()> {
    check_case(check, false)
}

fn check_uncertain(check: &mut Check) -> Result<()> {
    check_case(check, true)
}

fn check_case(check: &mut Check, uncertain: bool) -> Result<()> {
    let dir = check
        .repo
        .path
        .parent()
        .context("The fixture has no parent")?
        .to_path_buf();
    let boundary = optional_json(&dir.join("revert-boundary.json"))?;
    let result = optional_json(&dir.join("revert-result.json"))?;
    check.require(
        boundary.is_object(),
        "The native unrecord boundary marker must exist",
    );
    check.require(
        result.is_object(),
        "The real gate operation must produce observable facts",
    );
    if !boundary.is_object() || !result.is_object() {
        return Ok(());
    }
    let before = check.facts["before"].clone();
    let target = hash(&check.facts, "target")?.to_owned();
    let epoch = hash(&check.facts, "epoch")?.to_owned();
    let accepts = before["records"].as_array().cloned().unwrap_or_default();
    check.require(
        accepts.len() == 1
            && accepts[0]["hash"] == target
            && accepts[0]["decision"] == "accept"
            && accepts[0]["by"] == "human",
        "The target must enter main through one real gate acceptance",
    );
    let mut accepted_main = check.facts["base"].as_array().cloned().unwrap_or_default();
    accepted_main.push(json!(target));
    accepted_main.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    check.require(
        before["main"] == json!(accepted_main)
            && before["main_files"]["target.txt"] == json!(TARGET.as_bytes())
            && before["journal_bytes"].is_null(),
        "The fixture must contain the accepted target and no prior journal",
    );
    let intent = &boundary["intent"];
    let records = intent["records"].as_array().cloned().unwrap_or_default();
    check.require(
        intent["action"] == "revert"
            && intent["main"] == MAIN
            && intent["inbox"] == "inbox"
            && records.len() == 1
            && records[0]["hash"] == target
            && records[0]["decision"] == "revert"
            && records[0]["by"] == "human",
        "The native boundary must contain one complete correct revert intent",
    );
    for field in ["main", "state", "main_files", "audit", "records"] {
        check.require(
            boundary["before"][field] == before[field],
            format!("The native boundary must preserve the reviewed {field}"),
        );
    }
    unchanged_files(check, &boundary["before"], &before, "The native boundary");
    let mut expected_main = before["main"].as_array().cloned().unwrap_or_default();
    let mut expected_files = before["main_files"].clone();
    if uncertain {
        expected_main.retain(|hash| hash != &json!(target));
        if let Some(files) = expected_files.as_object_mut() {
            files.remove("target.txt");
        }
        check.require(
            boundary["advance"].is_null(),
            "The uncertain case must not advance main",
        );
        check.require(
            boundary["native"]["success"] == true,
            "The real native unrecord must succeed before the wrapper error",
        );
        check.require(
            result["gate"]["success"] == false && result["gate"]["exit_code"] != 42,
            "The gate must report the uncertain native error",
        );
        check.require(
            boundary["at_unrecord"] == boundary["before"],
            "The uncertain native operation must use the reviewed state",
        );
    } else {
        expected_main.push(json!(epoch));
        expected_main.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
        expected_files["epoch.txt"] = json!(EPOCH.as_bytes());
        check.require(
            boundary["advance"]["success"] == true,
            "The real independent epoch application must succeed",
        );
        check.require(
            boundary["native"]["exit_code"] == 42,
            "Native unrecord must refuse the stale state with exit 42",
        );
        check.require(
            result["gate"]["exit_code"] == 42,
            "The gate must report state mismatch with exit 42",
        );
        check.require(
            boundary["after"]["state"] == boundary["at_unrecord"]["state"],
            "Native state refusal must preserve the full channel state",
        );
        check.require(
            boundary["at_unrecord"]["state"] != before["state"]
                && boundary["at_unrecord"]["main"] == json!(expected_main)
                && boundary["at_unrecord"]["main_files"] == expected_files,
            "The independent epoch must advance native main before unrecord",
        );
        check.require(
            boundary["at_unrecord"]["state"]
                .as_str()
                .is_some_and(|observed| {
                    result["gate"]["stderr"]
                        .as_str()
                        .is_some_and(|stderr| stderr.contains(observed))
                }),
            "The gate refusal must identify the actual observed native state",
        );
    }
    check.require(
        result["after"]["state"] == boundary["after"]["state"],
        "The gate result must retain the native operation state",
    );
    for (label, actual) in [
        ("The native result", &boundary["after"]),
        ("The gate result", &result["after"]),
    ] {
        check.require(
            actual["main"] == json!(expected_main) && actual["main_files"] == expected_files,
            format!("{label} must preserve the exact expected main state"),
        );
        check.require(
            actual["audit"] == before["audit"] && actual["records"] == before["records"],
            format!("{label} must preserve the exact accepted audit bytes"),
        );
        unchanged_files(check, actual, &before, label);
    }
    check.require(
        boundary["after"]["journal_bytes"] == boundary["before"]["journal_bytes"]
            && boundary["before"]["journal_bytes"].is_array(),
        "The native command must preserve the prepared journal bytes",
    );
    if uncertain {
        check.require(
            result["after"]["journal_bytes"] == boundary["before"]["journal_bytes"],
            "The uncertain error must retain the exact durable journal",
        );
        let recovery = result["recovery"].as_array().cloned().unwrap_or_default();
        check.require(
            recovery.len() == 2,
            "Two real status commands must exercise recovery",
        );
        let mut expected_records = accepts;
        expected_records.extend(records);
        let mut completed_audit = None;
        for step in &recovery {
            let actual = &step["after"];
            check.require(
                step["gate"]["success"] == true,
                "A real status command must recover the revert",
            );
            check.require(
                actual["main"] == json!(expected_main) && actual["main_files"] == expected_files,
                "Recovery must preserve the native target removal",
            );
            check.require(
                actual["journal_bytes"].is_null(),
                "Recovery must clear the durable journal",
            );
            check.require(
                actual["records"] == json!(expected_records),
                "Recovery must append exactly the prepared revert record once",
            );
            let audit: Vec<u8> =
                serde_json::from_value(actual["audit"].clone()).unwrap_or_default();
            let accepted: Vec<u8> =
                serde_json::from_value(before["audit"].clone()).unwrap_or_default();
            check.require(
                audit.starts_with(&accepted),
                "Recovery must preserve the accepted audit prefix bytes",
            );
            if let Some(previous) = &completed_audit {
                check.require(
                    previous == &actual["audit"],
                    "Repeated recovery must preserve exact audit bytes",
                );
            }
            completed_audit = Some(actual["audit"].clone());
            unchanged_files(check, actual, &before, "Recovery");
        }
        if let Some(last) = recovery.last() {
            check.require(
                observe(&check.repo)? == last["after"],
                "The final repository must match the last real status result",
            );
        }
    } else {
        check.require(
            result["after"]["journal_bytes"].is_null(),
            "State refusal must cancel the prepared journal",
        );
        check.require(
            observe(&check.repo)? == result["after"],
            "The final repository must match the real refusal result",
        );
    }
    Ok(())
}
