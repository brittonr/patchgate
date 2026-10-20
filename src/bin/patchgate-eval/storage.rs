use super::support::*;
use std::collections::BTreeSet;

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "storage-full-recovery",
        setup,
        solve: solve_full,
        check: check_full,
    },
    Scenario {
        name: "storage-short-write-recovery",
        setup,
        solve: solve_short,
        check: check_short,
    },
    Scenario {
        name: "storage-sync-recovery",
        setup,
        solve: solve_sync,
        check: check_sync,
    },
];

const USER: &str = "harbor-storage";
const REASON: &str = "Approve the storage fixture.";
const SEED_MESSAGE: &str = "Preserve an earlier audit record";
const JOURNAL_MESSAGE: &str = "Accept the journal boundary change";
const AUDIT_MESSAGE: &str = "Accept the audit boundary change";
const LEDGER: &str = ".pijul/patchgate/ledger.jsonl";
const INTENT: &str = ".pijul/patchgate/acceptance.json";

fn setup(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(
        dir,
        signer,
        &[("POLICY.md", POLICY), ("base.txt", "base\n")],
    )?;
    let seed = repo.change(&[("seed.txt", "earlier accepted content\n")], SEED_MESSAGE)?;
    accept(&repo, &seed)?;
    let base = repo.hashes("main")?;
    let prefix = fs::read_to_string(repo.path.join(LEDGER))?;
    let prior = repo.ledger()?;
    ensure!(
        prior.len() == 1,
        "The initial audit must contain one record"
    );
    let journal = repo.change(&[("journal.txt", "journal content\n")], JOURNAL_MESSAGE)?;
    let audit = repo.change(&[("audit.txt", "audit content\n")], AUDIT_MESSAGE)?;
    Ok(
        json!({"base": base, "seed": seed, "journal": journal, "audit": audit,
        "prefix": prefix, "prior": prior}),
    )
}

fn hash<'a>(facts: &'a Value, name: &str) -> Result<&'a str> {
    facts[name]
        .as_str()
        .with_context(|| format!("Missing storage hash {name}"))
}

fn accept(repo: &Repo, candidate: &str) -> Result<()> {
    checked_output(
        repo.gate(
            None,
            &["accept", candidate, "-m", REASON],
            &[("USER", USER)],
        )?,
        "Accept the storage candidate",
    )?;
    Ok(())
}

fn native_prerequisite() -> Result<()> {
    ensure!(
        cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )),
        "Storage faults need Linux x86_64 or aarch64. Darwin has no native storage fault fixture."
    );
    ensure!(
        Path::new("/proc/self/fd").is_dir(),
        "Storage faults need procfs"
    );
    Ok(())
}

struct FaultLibrary {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl FaultLibrary {
    fn new() -> Result<Self> {
        native_prerequisite()?;
        let directory = tempfile::Builder::new()
            .prefix("patchgate-storage-fault-")
            .tempdir()?;
        let source = directory.path().join("storage_fault.rs");
        let path = directory.path().join("libpatchgate_storage_fault.so");
        fs::write(&source, include_str!("storage_fault.rs"))?;
        checked_output(
            Command::new("rustc")
                .args(["--edition=2021", "--crate-type=cdylib", "-C", "panic=abort"])
                .arg(&source)
                .arg("-o")
                .arg(&path)
                .output()
                .context("Storage faults need rustc and a native C linker")?,
            "Compile the Rust syscall fault fixture",
        )?;
        Ok(Self {
            _directory: directory,
            path,
        })
    }
}

#[derive(Debug)]
struct Event {
    kind: String,
    requested: usize,
    result: isize,
    errno: i32,
    path: PathBuf,
}

fn events(path: &Path) -> Result<Vec<Event>> {
    let text =
        fs::read_to_string(path).context("The syscall fault did not produce its event log")?;
    text.lines()
        .map(|line| {
            let fields: Vec<_> = line.splitn(5, '\t').collect();
            ensure!(fields.len() == 5, "The syscall event has an invalid format");
            Ok(Event {
                kind: fields[0].into(),
                requested: fields[1].parse()?,
                result: fields[2].parse()?,
                errno: fields[3].parse()?,
                path: fields[4].into(),
            })
        })
        .collect()
}

fn verify_events(log: &Path, kind: &str, target: &Path) -> Result<Vec<Event>> {
    let events = events(log)?;
    ensure!(
        !events.is_empty(),
        "The gate did not encounter a syscall fault"
    );
    ensure!(
        events.iter().all(|event| event.path == target),
        "A fault hit an unrelated file"
    );
    match kind {
        "full" => ensure!(
            events
                .iter()
                .any(|event| event.kind == "full" && event.result == -1 && event.errno == 28),
            "The gate did not encounter ENOSPC"
        ),
        "short" => {
            ensure!(
                events.iter().any(|event| event.kind == "short"
                    && event.errno == 0
                    && event.result > 0
                    && (event.result as usize) < event.requested),
                "The real file did not receive a partial write"
            );
            ensure!(
                events
                    .iter()
                    .any(|event| event.kind == "error" && event.result == -1 && event.errno == 5),
                "The partial write did not encounter its subsequent I/O error"
            );
        }
        "sync" => ensure!(
            events
                .iter()
                .any(|event| event.kind == "sync" && event.result == -1 && event.errno == 5),
            "The gate did not encounter a sync failure"
        ),
        _ => bail!("Unknown storage fault kind"),
    }
    Ok(events)
}

fn base_hashes(facts: &Value) -> Result<BTreeSet<String>> {
    facts["base"]
        .as_array()
        .context("Missing storage base hashes")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("A base hash is not text")
        })
        .collect()
}

fn fault(
    dir: &Path,
    repo: &Repo,
    library: &FaultLibrary,
    facts: &Value,
    kind: &str,
    boundary: &str,
) -> Result<Value> {
    let candidate = hash(facts, boundary)?;
    let before_bytes = fs::read(repo.path.join(LEDGER))?;
    let before_records = repo.ledger()?;
    let before_main = repo.hashes("main")?;
    let before_inbox = repo.hashes("inbox")?;
    let target = repo.path.canonicalize()?.join(if boundary == "journal" {
        ".pijul/patchgate/acceptance.tmp"
    } else {
        LEDGER
    });
    let log = dir
        .canonicalize()?
        .join(format!("storage-{boundary}.events"));
    if log.exists() {
        fs::remove_file(&log)?;
    }
    let library_path = library
        .path
        .to_str()
        .context("The fault library path is not UTF-8")?;
    let target_text = target.to_str().context("The fault target is not UTF-8")?;
    let log_text = log.to_str().context("The fault log path is not UTF-8")?;
    let output = repo.gate(
        None,
        &["accept", candidate, "-m", REASON],
        &[
            ("USER", USER),
            ("LD_PRELOAD", library_path),
            ("PATCHGATE_EVAL_FAULT_TARGET", target_text),
            ("PATCHGATE_EVAL_FAULT_KIND", kind),
            ("PATCHGATE_EVAL_FAULT_LOG", log_text),
            // Prepare syncs the old ledger once before the application.
            (
                "PATCHGATE_EVAL_FAULT_SKIP_SYNC",
                if boundary == "audit" { "1" } else { "0" },
            ),
        ],
    )?;
    ensure!(
        !output.status.success(),
        "The gate accepted a storage syscall failure"
    );
    verify_events(&log, kind, &target)?;
    ensure!(
        repo.hashes("inbox")? == before_inbox,
        "The storage fault changed inbox history"
    );
    let interrupted = fs::read(repo.path.join(LEDGER))?;
    ensure!(
        interrupted.starts_with(&before_bytes),
        "The storage fault changed earlier audit bytes"
    );
    let mut expected_main = before_main.clone();
    let mut expected_records = before_records.clone();
    if boundary == "journal" {
        ensure!(
            repo.hashes("main")? == before_main,
            "The gate applied a change before journal durability"
        );
        ensure!(
            interrupted == before_bytes,
            "The journal failure added an acceptance record"
        );
        ensure!(
            !repo.path.join(INTENT).exists(),
            "The incomplete temporary journal became authoritative"
        );
        ensure!(
            repo.path.join(".pijul/patchgate/acceptance.tmp").is_file(),
            "The journal fault did not reach the actual temporary journal"
        );
        let temporary = fs::read(&target)?;
        match kind {
            "full" => ensure!(
                temporary.is_empty(),
                "ENOSPC unexpectedly wrote journal bytes"
            ),
            "short" => ensure!(
                !temporary.is_empty() && serde_json::from_slice::<Value>(&temporary).is_err(),
                "The real journal does not contain a partial transaction"
            ),
            "sync" => {
                let transaction: Value = serde_json::from_slice(&temporary)?;
                ensure!(
                    transaction["version"] == 1
                        && transaction["records"]
                            .as_array()
                            .is_some_and(
                                |records| records.len() == 1 && records[0]["hash"] == candidate
                            )
                        && temporary.ends_with(b"\n"),
                    "The sync failure did not follow the complete journal write"
                );
            }
            _ => unreachable!(),
        }
    } else {
        expected_main.insert(candidate.to_owned());
        ensure!(
            repo.hashes("main")? == expected_main,
            "The audit fault did not follow the exact application"
        );
        let intent: Value = serde_json::from_slice(&fs::read(repo.path.join(INTENT))?)?;
        ensure!(
            intent["version"] == 1 && intent["main"] == "main" && intent["inbox"] == "inbox",
            "The audit fault has no valid acceptance transaction"
        );
        ensure!(
            intent["ledger_offset"].as_u64() == Some(before_bytes.len() as u64),
            "The acceptance transaction has the wrong audit boundary"
        );
        ensure!(
            intent["leading_newline"] == false,
            "The acceptance transaction changed the audit separator"
        );
        let records = intent["records"]
            .as_array()
            .context("Missing transaction audit records")?;
        ensure!(
            records.len() == 1 && records[0]["hash"] == candidate,
            "The transaction does not describe exactly its candidate"
        );
        expected_records.extend(records.iter().cloned());
        let tail = &interrupted[before_bytes.len()..];
        match kind {
            "full" => ensure!(tail.is_empty(), "ENOSPC unexpectedly wrote audit bytes"),
            "short" => ensure!(
                !tail.is_empty() && serde_json::from_slice::<Value>(tail).is_err(),
                "The real ledger does not contain a partial audit record"
            ),
            "sync" => ensure!(
                serde_json::from_slice::<Value>(tail)? == records[0] && tail.ends_with(b"\n"),
                "The sync failure did not follow the complete audit write"
            ),
            _ => unreachable!(),
        }
    }
    checked_output(
        repo.gate(None, &["status"], &[])?,
        "Recover the storage transaction",
    )?;
    if boundary == "journal" {
        ensure!(
            repo.hashes("main")? == before_main && repo.ledger()? == before_records,
            "Recovery accepted an unapplied journal"
        );
        accept(repo, candidate)?;
        expected_main.insert(candidate.to_owned());
        let records = repo.ledger()?;
        ensure!(
            records.len() == before_records.len() + 1,
            "Retry did not add exactly one acceptance"
        );
        ensure!(
            records[..before_records.len()] == before_records,
            "Retry changed earlier audit records"
        );
        expected_records = records;
    }
    let complete = fs::read(repo.path.join(LEDGER))?;
    ensure!(
        repo.ledger()? == expected_records,
        "Recovery changed a complete audit record"
    );
    ensure!(
        complete.starts_with(&interrupted),
        "Recovery changed bytes from the failed append"
    );
    if boundary == "audit" && kind == "short" {
        ensure!(
            complete.len() > interrupted.len(),
            "Recovery did not complete the partial audit record"
        );
    }
    ensure!(
        repo.hashes("main")? == expected_main,
        "Recovery changed the accepted history"
    );
    ensure!(
        !repo.path.join(INTENT).exists(),
        "Recovery left an unfinished acceptance transaction"
    );
    for _ in 0..2 {
        checked_output(
            repo.gate(None, &["status"], &[])?,
            "Repeat storage recovery",
        )?;
        ensure!(
            fs::read(repo.path.join(LEDGER))? == complete,
            "Repeated recovery duplicated or changed audit bytes"
        );
        ensure!(
            repo.hashes("main")? == expected_main && repo.hashes("inbox")? == before_inbox,
            "Repeated recovery changed channel history"
        );
    }
    Ok(json!({"kind": kind, "boundary": boundary, "target": target,
        "before": String::from_utf8(before_bytes)?, "interrupted": String::from_utf8(interrupted)?,
        "complete": String::from_utf8(complete)?, "records": expected_records}))
}

fn solve(dir: &Path, kind: &str) -> Result<()> {
    let library = FaultLibrary::new()?;
    let repo = Repo::open(dir.join("repo"));
    let facts = load_facts(dir)?;
    ensure!(
        repo.hashes("main")? == base_hashes(&facts)?,
        "The storage fixture is not in its initial state"
    );
    let journal = fault(dir, &repo, &library, &facts, kind, "journal")?;
    let audit = fault(dir, &repo, &library, &facts, kind, "audit")?;
    fs::write(
        dir.join("storage-observation.json"),
        serde_json::to_vec_pretty(&json!({
            "kind": kind, "journal": journal, "audit": audit,
        }))?,
    )?;
    Ok(())
}

fn solve_full(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, "full")
}
fn solve_short(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, "short")
}
fn solve_sync(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, "sync")
}

fn check(check: &mut Check, kind: &str) -> Result<()> {
    native_prerequisite()?;
    let mut expected = base_hashes(&check.facts)?;
    for name in ["journal", "audit"] {
        expected.insert(hash(&check.facts, name)?.to_owned());
    }
    for channel in ["main", "inbox"] {
        check.require(
            check.repo.hashes(channel)? == expected,
            format!("{channel} must contain the exact storage change set"),
        );
        check.no_conflicts(channel)?;
        for (path, text) in [
            ("POLICY.md", POLICY),
            ("base.txt", "base\n"),
            ("seed.txt", "earlier accepted content\n"),
            ("journal.txt", "journal content\n"),
            ("audit.txt", "audit content\n"),
        ] {
            check.require(
                check.file(channel, path)?.as_deref() == Some(text),
                format!("{channel} must preserve {path}"),
            );
        }
        let files = check.repo.archive(channel)?.files;
        check.require(files.len() == 5, format!("{channel} has unexpected files"));
    }
    let records = check.repo.ledger()?;
    check.require(
        records.len() == 3,
        "The audit must contain exactly three complete acceptances",
    );
    for (index, name, message) in [
        (0, "seed", SEED_MESSAGE),
        (1, "journal", JOURNAL_MESSAGE),
        (2, "audit", AUDIT_MESSAGE),
    ] {
        if let Some(record) = records.get(index) {
            check.require(
                record["hash"] == hash(&check.facts, name)?
                    && record["message"] == message
                    && record["decision"] == "accept"
                    && record["by"] == "human"
                    && record["reason"] == REASON
                    && record["user"] == USER
                    && record["at"]
                        .as_str()
                        .is_some_and(|at| chrono::DateTime::parse_from_rfc3339(at).is_ok()),
                format!("{name} must have a complete, correct acceptance record"),
            );
        }
    }
    check.require(
        records.first()
            == check.facts["prior"]
                .as_array()
                .and_then(|prior| prior.first()),
        "The earlier complete audit record changed",
    );
    let bytes = fs::read_to_string(check.repo.path.join(LEDGER))?;
    check.require(
        bytes.starts_with(
            check.facts["prefix"]
                .as_str()
                .context("Missing earlier audit bytes")?,
        ),
        "The earlier audit bytes changed",
    );
    check.require(
        !check.repo.path.join(INTENT).exists(),
        "The storage transaction must finish",
    );
    check.require(
        !check
            .repo
            .path
            .join(".pijul/patchgate/acceptance.tmp")
            .exists(),
        "The storage retry must consume its temporary journal",
    );
    let dir = check
        .repo
        .path
        .parent()
        .context("The storage repository has no scenario directory")?
        .to_owned();
    let observation = match fs::read(dir.join("storage-observation.json")) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            check.require(false, "The storage recovery observations are absent");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    check.require(
        observation["kind"] == kind,
        "The observations describe a different syscall failure",
    );
    for boundary in ["journal", "audit"] {
        let target = check
            .repo
            .path
            .canonicalize()?
            .join(if boundary == "journal" {
                ".pijul/patchgate/acceptance.tmp"
            } else {
                LEDGER
            });
        verify_events(
            &dir.join(format!("storage-{boundary}.events")),
            kind,
            &target,
        )?;
        let observed = &observation[boundary];
        check.require(
            observed["kind"] == kind
                && observed["boundary"] == boundary
                && observed["target"] == json!(target),
            "The observed fault has the wrong boundary",
        );
        let before = observed["before"]
            .as_str()
            .context("Missing pre-fault audit bytes")?;
        let interrupted = observed["interrupted"]
            .as_str()
            .context("Missing interrupted audit bytes")?;
        let complete = observed["complete"]
            .as_str()
            .context("Missing complete audit bytes")?;
        check.require(
            interrupted.starts_with(before) && complete.starts_with(interrupted),
            "The syscall recovery changed existing audit bytes",
        );
        if boundary == "journal" {
            check.require(
                Some(before) == check.facts["prefix"].as_str() && interrupted == before,
                "The pre-application failure claimed acceptance",
            );
            check.require(
                observed["records"] == json!(records.iter().take(2).collect::<Vec<_>>()),
                "Journal recovery changed complete audit fields",
            );
        } else {
            check.require(
                Some(before) == observation["journal"]["complete"].as_str() && complete == bytes,
                "Audit recovery did not preserve the exact complete ledger",
            );
            check.require(
                observed["records"] == json!(records),
                "Audit recovery changed complete audit fields",
            );
            let tail = interrupted
                .strip_prefix(before)
                .context("The interrupted audit lost its prefix")?;
            let expected_tail = complete
                .strip_prefix(before)
                .context("The complete audit lost its prefix")?;
            check.require(
                match kind {
                    "full" => tail.is_empty(),
                    "short" => !tail.is_empty() && tail.len() < expected_tail.len(),
                    "sync" => tail == expected_tail,
                    _ => false,
                },
                "The real ledger bytes do not match the selected syscall fault",
            );
        }
    }
    Ok(())
}

fn check_full(check: &mut Check) -> Result<()> {
    self::check(check, "full")
}
fn check_short(check: &mut Check) -> Result<()> {
    self::check(check, "short")
}
fn check_sync(check: &mut Check) -> Result<()> {
    self::check(check, "sync")
}
