use super::support::*;
use parking_lot::{Condvar, Mutex};
use std::collections::BTreeSet;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "stale-policy-review",
        setup: setup_policy,
        solve: solve_policy,
        check: check_policy,
    },
    Scenario {
        name: "stale-main-review",
        setup: setup_main,
        solve: solve_main,
        check: check_main,
    },
    Scenario {
        name: "stale-main-merge",
        setup: setup_merge,
        solve: solve_merge,
        check: check_merge,
    },
];

const NEW_POLICY: &str = "# Review policy\n\nReject changes to notes.txt. Accept other changes.\n";
const NOTES: &str = "Project notes need the current policy.\n";
const EPOCH: &str = "An independent command advances main.\n";
const BASE: &str = "#!/bin/sh\necho hello\necho bye\n";
const FRENCH: &str = "#!/bin/sh\necho hello\necho bonjour\necho bye\n";
const GERMAN: &str = "#!/bin/sh\necho hello\necho hallo\necho bye\n";

fn setup_policy(dir: &Path, signer: &Signer) -> Result<Value> {
    setup_review(dir, signer, true)
}

fn setup_main(dir: &Path, signer: &Signer) -> Result<Value> {
    setup_review(dir, signer, false)
}

fn setup_review(dir: &Path, signer: &Signer, policy: bool) -> Result<Value> {
    let repo = start(dir, signer, &[("POLICY.md", POLICY)])?;
    let base = repo.hashes("main")?;
    let update = if policy {
        ("POLICY.md", NEW_POLICY)
    } else {
        ("epoch.txt", EPOCH)
    };
    let (candidate, advance) = concurrent(
        &repo,
        &[("notes.txt", NOTES)],
        "Add project notes",
        &[update],
        "Advance the reviewed main channel independently",
    )?;
    Ok(json!({"base": base, "candidate": candidate, "advance": advance}))
}

fn setup_merge(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(dir, signer, &[("POLICY.md", POLICY), ("greet.sh", BASE)])?;
    let base = repo.hashes("main")?;
    let (first, candidate) = concurrent(
        &repo,
        &[("greet.sh", FRENCH)],
        "Retain the French greeting",
        &[("greet.sh", GERMAN)],
        "Retain the German greeting",
    )?;
    let author = Repo {
        path: dir.join("advance-author"),
        env: Arc::clone(&repo.env),
    };
    checked_output(
        Command::new("pijul")
            .args(["clone", "--channel", "main"])
            .arg(&repo.path)
            .arg(&author.path)
            .env_clear()
            .envs(author.env.iter())
            .output()?,
        "Create the independent main author",
    )?;
    let advance = author.change(
        &[("epoch.txt", EPOCH)],
        "Advance main during a merge request",
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
    fs::remove_dir_all(&author.path)?;
    Ok(json!({"base": base, "first": first, "candidate": candidate, "advance": advance}))
}

struct Hold(Arc<(Mutex<bool>, Condvar)>);

impl Hold {
    fn release(&self) {
        let (lock, ready) = &*self.0;
        *lock.lock() = true;
        ready.notify_all();
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release();
    }
}

struct Pending(Option<Child>);

impl Pending {
    fn finish(&mut self) -> Result<Output> {
        let deadline = Instant::now() + Duration::from_secs(45);
        let child = self.0.as_mut().context("The review process is absent")?;
        while child.try_wait()?.is_none() {
            ensure!(Instant::now() < deadline, "The stale review did not exit");
            thread::sleep(Duration::from_millis(10));
        }
        Ok(self
            .0
            .take()
            .context("The review process is absent")?
            .wait_with_output()?)
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            unsafe {
                libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn solve_policy(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, false)
}

fn solve_main(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, false)
}

fn solve_merge(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, true)
}

fn ledger_bytes(repo: &Repo) -> Result<Vec<u8>> {
    match fs::read(repo.path.join(".pijul/patchgate/ledger.jsonl")) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn solve(dir: &Path, merge: bool) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let facts = load_facts(dir)?;
    let state = Arc::new((Mutex::new(false), Condvar::new()));
    let seen = Arc::new(AtomicBool::new(false));
    let (sender, arrived) = mpsc::sync_channel(1);
    let request_state = Arc::clone(&state);
    let model = ModelServer::new(move |request| {
        let body = request.body;
        let is_merge = body["response_format"]["json_schema"]["name"] == "merge";
        if is_merge == merge && !seen.swap(true, Ordering::AcqRel) {
            let _ = sender.send(body.clone());
            let (lock, ready) = &*request_state;
            let mut released = lock.lock();
            ready.wait_while(&mut released, |released| !*released);
        }
        if is_merge {
            chat_reply(
                json!({"choice": "both, side 1 first", "reason": "Preserve both greetings."}),
            )
        } else {
            let reject = body["messages"][0]["content"]
                .as_str()
                .is_some_and(|instructions| instructions.contains("Reject changes to notes.txt."));
            chat_reply(verdict(if reject { "reject" } else { "accept" }))
        }
    })?;
    let hold = Hold(state);
    let mut pending = Pending(Some(repo.spawn_gate(Some(&model), &["review"], &[])?));
    let request = arrived
        .recv_timeout(Duration::from_secs(30))
        .context("The review did not reach its HTTP barrier")?;
    let before = ledger_bytes(&repo)?;
    let before_main = repo.hashes("main")?;
    let candidate = facts["candidate"]
        .as_str()
        .context("The candidate hash is absent")?;
    let advance = facts["advance"]
        .as_str()
        .context("The independent hash is absent")?;
    ensure!(
        !before_main.contains(candidate),
        "The candidate reached main before the held response"
    );
    repo.pijul(&["apply", "--channel", "main", advance])?;
    let advanced_main = repo.hashes("main")?;
    ensure!(
        advanced_main != before_main && advanced_main.contains(advance),
        "The independent Pijul command did not advance main"
    );
    hold.release();
    let output = pending.finish()?;
    let after_main = repo.hashes("main")?;
    let after = ledger_bytes(&repo)?;
    let evidence = json!({
        "request": request,
        "before_main": before_main,
        "advanced_main": advanced_main,
        "after_main": after_main,
        "exit_code": output.status.code(),
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr),
        "audit_before": before,
        "audit_after": after,
    });
    fs::write(
        dir.join("stale-evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    ensure!(
        !output.status.success(),
        "The gate accepted a stale response"
    );
    ensure!(
        after_main == advanced_main,
        "The stale response changed main"
    );
    ensure!(after == before, "The stale response changed the audit");
    ensure!(
        !after_main.contains(candidate),
        "The stale candidate entered main"
    );
    ensure!(
        !repo.path.join(".pijul/patchgate/acceptance.json").exists(),
        "The stale response left an acceptance transaction"
    );
    checked_output(
        repo.gate(Some(&model), &["review"], &[])?,
        "Review the current main channel",
    )?;
    let complete = ledger_bytes(&repo)?;
    checked_output(
        repo.gate(Some(&model), &["review"], &[])?,
        "Repeat the current review",
    )?;
    ensure!(
        ledger_bytes(&repo)? == complete,
        "A repeat review changed the exact audit"
    );
    Ok(())
}

fn expected_base(check: &Check) -> Result<BTreeSet<String>> {
    check.facts["base"]
        .as_array()
        .context("The initial hashes are absent")?
        .iter()
        .map(|hash| {
            hash.as_str()
                .map(str::to_owned)
                .context("An initial hash is invalid")
        })
        .collect()
}

fn check_review(check: &mut Check, policy: bool) -> Result<()> {
    check.within("main", &["advance"])?;
    check.within("inbox", &["candidate", "advance"])?;
    if policy {
        check.outside("main", &["candidate"])?;
        check.decision("candidate", "reject", "model")?;
    } else {
        check.within("main", &["candidate"])?;
        check.decision("candidate", "accept", "model")?;
    }
    let mut expected = expected_base(check)?;
    expected.insert(
        check.facts["advance"]
            .as_str()
            .context("The independent hash is absent")?
            .to_owned(),
    );
    let mut inbox = expected.clone();
    inbox.insert(
        check.facts["candidate"]
            .as_str()
            .context("The candidate hash is absent")?
            .to_owned(),
    );
    if !policy {
        expected = inbox.clone();
    }
    check.require(
        check.repo.hashes("main")? == expected,
        "Main must contain only the fresh reviewed result and the independent change",
    );
    check.require(
        check.repo.hashes("inbox")? == inbox,
        "Inbox must preserve all original changes",
    );
    check.require(
        check.repo.ledger()?.len() == 1 && check.records("candidate")?.len() == 1,
        "Only one fresh candidate decision can enter the audit",
    );
    check.require(
        check.file("inbox", "notes.txt")?.as_deref() == Some(NOTES),
        "Inbox must preserve the candidate content",
    );
    if policy {
        check.require(
            check.file("main", "notes.txt")?.is_none(),
            "The new policy must exclude the notes from main",
        );
        check.require(
            check.file("main", "POLICY.md")?.as_deref() == Some(NEW_POLICY),
            "Main must retain the current policy",
        );
    } else {
        check.require(
            check.file("main", "notes.txt")?.as_deref() == Some(NOTES),
            "Main must contain the fresh accepted notes",
        );
        check.require(
            check.file("main", "epoch.txt")?.as_deref() == Some(EPOCH),
            "Main must preserve the independent update",
        );
    }
    check.no_conflicts("main")?;
    check.no_conflicts("inbox")
}

fn check_policy(check: &mut Check) -> Result<()> {
    check_review(check, true)
}

fn check_main(check: &mut Check) -> Result<()> {
    check_review(check, false)
}

fn check_merge(check: &mut Check) -> Result<()> {
    for channel in ["main", "inbox"] {
        check.within(channel, &["first", "candidate", "advance"])?;
        check.no_conflicts(channel)?;
        check.require(
            check.file(channel, "epoch.txt")?.as_deref() == Some(EPOCH),
            "Both channels must preserve the independent main update",
        );
        let text = check.file(channel, "greet.sh")?.unwrap_or_default();
        let lines: Vec<_> = text.lines().collect();
        check.require(
            lines
                == [
                    "#!/bin/sh",
                    "echo hello",
                    "echo bonjour",
                    "echo hallo",
                    "echo bye",
                ]
                || lines
                    == [
                        "#!/bin/sh",
                        "echo hello",
                        "echo hallo",
                        "echo bonjour",
                        "echo bye",
                    ],
            "The fresh merge must preserve both greetings and the original file boundaries",
        );
    }
    check.decision("first", "accept", "model")?;
    check.decision("candidate", "accept", "model")?;
    let ledger = check.repo.ledger()?;
    check.require(
        ledger.len() == 3,
        "The audit must contain two acceptances and one fresh merge",
    );
    let merges: Vec<_> = ledger
        .iter()
        .filter(|record| record["decision"] == "merge")
        .collect();
    check.require(merges.len() == 1, "The audit must contain one merge");
    let mut expected = expected_base(check)?;
    for name in ["first", "candidate", "advance"] {
        expected.insert(
            check.facts[name]
                .as_str()
                .context("A fixture hash is absent")?
                .to_owned(),
        );
    }
    if let Some(record) = merges.first() {
        let hash = record["hash"].as_str().unwrap_or_default();
        expected.insert(hash.to_owned());
        check.require(
            !hash.is_empty() && record["by"] == "model",
            "The fresh merge must retain its model actor and hash",
        );
        check.require(
            record["for"] == json!([check.facts["candidate"]]),
            "The fresh merge must link to the candidate",
        );
        check.require(
            check
                .records("candidate")?
                .last()
                .is_some_and(|accept| accept["merge"] == hash),
            "The fresh acceptance must link to its merge",
        );
    }
    for channel in ["main", "inbox"] {
        check.require(
            check.repo.hashes(channel)? == expected,
            "Both channels must contain only the expected changes and the fresh merge",
        );
    }
    Ok(())
}
