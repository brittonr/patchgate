use super::support::*;
use parking_lot::{Condvar, Mutex};
use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "concurrent-review-once",
        setup: setup_concurrent,
        solve: solve_concurrent,
        check: check_concurrent,
    },
    Scenario {
        name: "watch-push-recovery",
        setup: setup_watch,
        solve: solve_watch,
        check: check_watch,
    },
];

const WAIT: Duration = Duration::from_secs(45);
const HUMAN_REASON: &str = "The owner approves the protected release note.";

#[derive(Clone)]
struct Trace {
    start: Instant,
    events: Arc<Mutex<Vec<Value>>>,
}

impl Trace {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add(&self, event: &str, data: Value) {
        self.events.lock().push(json!({
            "event": event, "elapsed_ms": self.start.elapsed().as_millis() as u64, "data": data
        }));
    }

    fn save(&self, dir: &Path) -> Result<()> {
        fs::write(
            dir.join("process-evidence.json"),
            serde_json::to_vec_pretty(&*self.events.lock())?,
        )?;
        Ok(())
    }
}

struct Managed {
    child: Child,
    stdout: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    name: &'static str,
    trace: Trace,
}

fn drain(pipe: impl Read + Send + 'static) -> JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut pipe = pipe;
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

impl Managed {
    fn new(mut child: Child, name: &'static str, trace: &Trace, args: &[&str]) -> Self {
        trace.add(
            "spawn",
            json!({"name": name, "pid": child.id(), "args": args}),
        );
        let stdout = child.stdout.take().map(drain);
        let stderr = child.stderr.take().map(drain);
        Self {
            child,
            stdout,
            stderr,
            name,
            trace: trace.clone(),
        }
    }

    fn alive(&mut self) -> Result<()> {
        ensure!(
            self.child.try_wait()?.is_none(),
            "{} exited before the required boundary",
            self.name
        );
        Ok(())
    }

    fn finish(&mut self, timeout: Duration, expected_code: i32) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            ensure!(
                Instant::now() < deadline,
                "{} did not exit within {timeout:?}",
                self.name
            );
            thread::park_timeout(Duration::from_millis(10));
        };
        ensure!(
            !group_exists(self.child.id()),
            "{} left a child process",
            self.name
        );
        let stdout = read_pipe(self.stdout.take())?;
        let stderr = read_pipe(self.stderr.take())?;
        self.trace.add("exit", json!({
            "name": self.name, "pid": self.child.id(), "code": status.code(),
            "stdout": String::from_utf8_lossy(&stdout), "stderr": String::from_utf8_lossy(&stderr)
        }));
        ensure!(
            status.code() == Some(expected_code),
            "{} failed: {}",
            self.name,
            String::from_utf8_lossy(&stderr)
        );
        Ok(status)
    }

    fn interrupt(&mut self) -> Result<()> {
        self.alive()?;
        let result = unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGINT) };
        ensure!(
            result == 0,
            "cannot send SIGINT: {}",
            std::io::Error::last_os_error()
        );
        self.trace.add(
            "signal",
            json!({"name": self.name, "pid": self.child.id(), "signal": "SIGINT"}),
        );
        Ok(())
    }
}

impl Drop for Managed {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(pipe) = self.stdout.take() {
            let _ = pipe.join();
        }
        if let Some(pipe) = self.stderr.take() {
            let _ = pipe.join();
        }
    }
}

fn group_exists(pid: u32) -> bool {
    let result = unsafe { libc::kill(-(pid as libc::pid_t), 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

fn read_pipe(pipe: Option<JoinHandle<std::io::Result<Vec<u8>>>>) -> Result<Vec<u8>> {
    match pipe {
        Some(pipe) => Ok(pipe
            .join()
            .map_err(|_| anyhow!("process output reader failed"))??),
        None => Ok(Vec::new()),
    }
}

struct Hold {
    state: Arc<(Mutex<bool>, Condvar)>,
}

impl Hold {
    fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }
    fn release(&self) {
        let (lock, ready) = &*self.state;
        *lock.lock() = true;
        ready.notify_all();
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release();
    }
}

fn held_model(fail_first: bool, trace: &Trace) -> Result<(ModelServer, Hold, mpsc::Receiver<()>)> {
    let hold = Hold::new();
    let state = Arc::clone(&hold.state);
    let first = AtomicBool::new(true);
    let (sender, receiver) = mpsc::channel();
    let trace = trace.clone();
    let model = ModelServer::new(move |_request| {
        if first.swap(false, Ordering::SeqCst) {
            trace.add("request-held", json!({}));
            let _ = sender.send(());
            let (lock, ready) = &*state;
            let mut released = lock.lock();
            ready.wait_while_for(&mut released, |released| !*released, WAIT);
            if !*released {
                return Reply {
                    status: 503,
                    body: json!({"error": "fixture request barrier expired"}),
                };
            }
            if fail_first {
                trace.add("request-failed", json!({"status": 503}));
                return Reply {
                    status: 503,
                    body: json!({"error": "fixture model outage"}),
                };
            }
        }
        trace.add("request-accepted", json!({}));
        chat_reply(verdict("accept"))
    })?;
    Ok((model, hold, receiver))
}

fn setup_concurrent(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(dir, signer, &[("POLICY.md", POLICY)])?;
    let base = repo.hashes("main")?;
    let human = repo.change(
        &[("release.txt", "owner-approved release note\n")],
        "Add the protected release note",
    )?;
    let first = repo.change(
        &[("first.txt", "first reviewer content\n")],
        "Add the first independent note",
    )?;
    let second = repo.change(
        &[("second.txt", "second reviewer content\n")],
        "Add the second independent note",
    )?;
    Ok(json!({"base": base, "human": human, "first": first, "second": second}))
}

fn solve_concurrent(dir: &Path, _options: &RunOptions) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let facts = load_facts(dir)?;
    let trace = Trace::new();
    let (model, hold, request) = held_model(false, &trace)?;
    let settings = [
        ("PATCHGATE_PROTECTED", "release.txt"),
        ("PATCHGATE_TIMEOUT", "60"),
    ];
    let mut first = Managed::new(
        repo.spawn_gate(Some(&model), &["review"], &settings)?,
        "reviewer-1",
        &trace,
        &["review"],
    );
    request
        .recv_timeout(WAIT)
        .context("first reviewer did not reach the request barrier")?;
    first.alive()?;
    let before = repo.ledger()?;
    ensure!(
        before.len() == 1
            && before[0]["hash"] == facts["human"]
            && before[0]["decision"] == "escalate"
            && before[0]["by"] == "gate",
        "protected change must escalate before overlap"
    );
    trace.add("ledger-before-overlap", json!(before));
    let mut second = Managed::new(
        repo.spawn_gate(Some(&model), &["review"], &settings)?,
        "reviewer-2",
        &trace,
        &["review"],
    );
    let human_hash = facts["human"].as_str().context("missing human hash")?;
    let human_args = ["accept", human_hash, "--reason", HUMAN_REASON];
    let mut human = Managed::new(
        repo.spawn_gate(None, &human_args, &[("USER", "harbor-owner")])?,
        "human",
        &trace,
        &human_args,
    );
    first.alive()?;
    second.alive()?;
    human.alive()?;
    trace.add(
        "overlap",
        json!({"pids": [first.child.id(), second.child.id(), human.child.id()]}),
    );
    hold.release();
    first.finish(WAIT, 0)?;
    second.finish(WAIT, 0)?;
    human.finish(WAIT, 0)?;
    let after = repo.ledger()?;
    ensure!(
        after.first() == before.first(),
        "overlap changed the first decision record"
    );
    trace.add("ledger-after-overlap", json!(after));
    let mut repeat = Managed::new(
        repo.spawn_gate(Some(&model), &["review"], &settings)?,
        "repeat-review",
        &trace,
        &["review"],
    );
    repeat.finish(WAIT, 0)?;
    ensure!(
        repo.ledger()? == after,
        "repeat review changed the exact decision history"
    );
    trace.add("ledger-after-repeat", json!(repo.ledger()?));
    ensure_no_fixture_processes(&repo)?;
    trace.save(dir)
}

fn setup_watch(dir: &Path, signer: &Signer) -> Result<Value> {
    let repo = start(dir, signer, &[("POLICY.md", POLICY)])?;
    let base = repo.hashes("main")?;
    let root = fs::canonicalize(dir)?;
    let author_path = root.join("author");
    checked_output(
        Command::new("pijul")
            .args(["clone", "--channel", "main"])
            .arg(fs::canonicalize(&repo.path)?)
            .arg(&author_path)
            .env_clear()
            .envs(repo.env.iter())
            .output()?,
        "clone watch author",
    )?;
    let author = Repo {
        path: author_path,
        env: Arc::clone(&repo.env),
    };
    let first = repo.change(
        &[("first.txt", "before the model outage\n")],
        "Add the first watch note",
    )?;
    let second = author.change(
        &[("second.txt", "pushed during the model outage\n")],
        "Add the second watch note",
    )?;
    Ok(json!({"base": base, "first": first, "second": second}))
}

fn solve_watch(dir: &Path, _options: &RunOptions) -> Result<()> {
    let repo = Repo::open(dir.join("repo"));
    let facts = load_facts(dir)?;
    let trace = Trace::new();
    let (model, hold, request) = held_model(true, &trace)?;
    let args = ["watch", "--interval", "0.05"];
    let mut watch = Managed::new(
        repo.spawn_gate(Some(&model), &args, &[("PATCHGATE_TIMEOUT", "60")])?,
        "watch",
        &trace,
        &args,
    );
    request
        .recv_timeout(WAIT)
        .context("watch did not reach the request barrier")?;
    watch.alive()?;
    ensure!(
        repo.ledger()?.is_empty(),
        "the held model request must not decide a change"
    );
    ensure!(
        !repo
            .hashes("inbox")?
            .contains(facts["second"].as_str().context("missing second hash")?),
        "second change reached inbox before the push"
    );
    trace.add("ledger-during-outage", json!(repo.ledger()?));
    let mut command = Command::new("pijul");
    command
        .arg("push")
        .arg(fs::canonicalize(&repo.path)?)
        .args(["--to-channel", "inbox", "--no-notify", "-a"])
        .current_dir(dir.join("author"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut push = Managed::new(
        command.spawn()?,
        "push",
        &trace,
        &["push", "--to-channel", "inbox", "--no-notify", "-a"],
    );
    push.finish(WAIT, 0)?;
    watch.alive()?;
    let inbox = repo.hashes("inbox")?;
    ensure!(
        inbox.contains(facts["first"].as_str().context("missing first hash")?)
            && inbox.contains(facts["second"].as_str().context("missing second hash")?),
        "push lost a pending change"
    );
    trace.add(
        "push-visible",
        json!({"inbox": inbox, "main": repo.hashes("main")?, "ledger": repo.ledger()?}),
    );
    hold.release();
    let deadline = Instant::now() + WAIT;
    loop {
        watch.alive()?;
        let main = repo.hashes("main")?;
        let complete = complete_ledger(&repo)?;
        if ["first", "second"].iter().all(|name| {
            facts[*name]
                .as_str()
                .is_some_and(|hash| main.contains(hash))
        }) && complete.is_some_and(|history| history.len() == 2)
        {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "watch did not recover both changes"
        );
        thread::park_timeout(Duration::from_millis(20));
    }
    let history = repo.ledger()?;
    trace.add(
        "watch-recovered",
        json!({"main": repo.hashes("main")?, "ledger": history}),
    );
    watch.interrupt()?;
    watch.finish(Duration::from_secs(3), 130)?;
    ensure!(
        repo.ledger()? == history,
        "SIGINT changed the exact decision history"
    );
    trace.add("ledger-after-sigint", json!(repo.ledger()?));
    ensure_no_fixture_processes(&repo)?;
    trace.save(dir)
}

fn complete_ledger(repo: &Repo) -> Result<Option<Vec<Value>>> {
    let text = match fs::read_to_string(repo.path.join(".pijul/patchgate/ledger.jsonl")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !text.ends_with('\n') {
        return Ok(None);
    }
    let history = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    Ok(Some(history))
}

fn ensure_no_fixture_processes(repo: &Repo) -> Result<()> {
    let processes = checked_output(
        Command::new("ps")
            .args(["-axo", "pid=,command="])
            .output()?,
        "inspect fixture processes",
    )?;
    let root = fs::canonicalize(&repo.path)?;
    let root = root.to_string_lossy();
    for line in processes.lines() {
        let mut fields = line.split_whitespace();
        let pid = fields.next().unwrap_or_default();
        let executable = fields
            .next()
            .unwrap_or_default()
            .rsplit('/')
            .next()
            .unwrap_or_default();
        if matches!(executable, "patchgate" | "pijul" | "ssh-agent") && line.contains(root.as_ref())
        {
            bail!("fixture process {pid} remains: {line}");
        }
    }
    Ok(())
}

fn expected_hashes(c: &Check, names: &[&str]) -> Result<BTreeSet<String>> {
    let mut hashes: BTreeSet<String> = serde_json::from_value(c.facts["base"].clone())?;
    for name in names {
        hashes.insert(
            c.facts[*name]
                .as_str()
                .context("missing fixture hash")?
                .to_owned(),
        );
    }
    Ok(hashes)
}

fn exact_records(c: &mut Check, name: &str, expected: &[(&str, &str)]) -> Result<Vec<Value>> {
    let records = c.records(name)?;
    let actual: Vec<_> = records
        .iter()
        .map(|record| {
            (
                record["decision"].as_str().unwrap_or_default(),
                record["by"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    c.require(
        actual == expected,
        format!("{name} must retain its exact decision history"),
    );
    for record in &records {
        c.require(
            record["hash"] == c.facts[name]
                && record["at"].as_str().is_some_and(|at| !at.is_empty()),
            format!("{name} must retain a complete ledger record"),
        );
    }
    Ok(records)
}

fn evidence(c: &mut Check) -> Result<Option<Vec<Value>>> {
    let root = c.repo.path.parent().context("scenario root is absent")?;
    match fs::read(root.join("process-evidence.json")) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            c.require(false, "The process lifecycle evidence is absent");
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn event<'a>(events: &'a [Value], name: &str) -> Result<&'a Value> {
    events
        .iter()
        .find(|event| event["event"] == name)
        .with_context(|| format!("missing process event {name}"))
}

fn event_index(events: &[Value], name: &str) -> Result<usize> {
    events
        .iter()
        .position(|event| event["event"] == name)
        .with_context(|| format!("missing process event {name}"))
}

fn process_exit<'a>(events: &'a [Value], name: &str) -> Result<&'a Value> {
    events
        .iter()
        .find(|event| event["event"] == "exit" && event["data"]["name"] == name)
        .with_context(|| format!("missing exit observation for {name}"))
}

fn check_processes(c: &mut Check, events: &[Value], commands: &[(&str, i32)]) -> Result<()> {
    for &(name, expected_code) in commands {
        let spawned = events
            .iter()
            .find(|entry| entry["event"] == "spawn" && entry["data"]["name"] == name)
            .with_context(|| format!("missing spawn observation for {name}"))?;
        let pid = spawned["data"]["pid"]
            .as_u64()
            .context("missing child process ID")?;
        ensure!(
            pid > 1 && pid <= i32::MAX as u64,
            "invalid child process ID"
        );
        let exited = process_exit(events, name)?;
        c.require(
            exited["data"]["pid"] == pid && exited["data"]["code"] == expected_code,
            format!("{name} must retain its process identity and return {expected_code}"),
        );
        c.require(
            !group_exists(pid as u32),
            format!("{name} must leave no process group"),
        );
    }
    Ok(())
}

fn check_concurrent(c: &mut Check) -> Result<()> {
    let expected = expected_hashes(c, &["human", "first", "second"])?;
    for channel in ["main", "inbox"] {
        c.require(
            c.repo.hashes(channel)? == expected,
            format!("{channel} must retain every patch without extra changes"),
        );
        c.no_conflicts(channel)?;
    }
    exact_records(c, "first", &[("accept", "model")])?;
    exact_records(c, "second", &[("accept", "model")])?;
    let human = exact_records(c, "human", &[("escalate", "gate"), ("accept", "human")])?;
    if let Some(record) = human.last() {
        c.require(
            record["reason"] == HUMAN_REASON && record["user"] == "harbor-owner",
            "the human reason and actor must remain exact",
        );
    }
    c.require(
        c.repo.ledger()?.len() == 4,
        "the ledger must contain exactly four decisions",
    );
    for (file, text) in [
        ("release.txt", "owner-approved release note\n"),
        ("first.txt", "first reviewer content\n"),
        ("second.txt", "second reviewer content\n"),
    ] {
        for channel in ["main", "inbox"] {
            c.require(
                c.file(channel, file)?.as_deref() == Some(text),
                format!("{channel} must preserve exact {file} content"),
            );
        }
    }
    let Some(events) = evidence(c)? else {
        return Ok(());
    };
    check_processes(
        c,
        &events,
        &[
            ("reviewer-1", 0),
            ("reviewer-2", 0),
            ("human", 0),
            ("repeat-review", 0),
        ],
    )?;
    c.require(
        event_index(&events, "request-held")? < event_index(&events, "overlap")?
            && event_index(&events, "overlap")? < event_index(&events, "request-accepted")?,
        "the request barrier must contain the process overlap",
    );
    let pids = event(&events, "overlap")?["data"]["pids"]
        .as_array()
        .context("missing overlap process IDs")?;
    let unique: BTreeSet<_> = pids.iter().filter_map(Value::as_u64).collect();
    c.require(
        unique.len() == 3,
        "the overlap must contain two reviewers and one human command",
    );
    let history = json!(c.repo.ledger()?);
    c.require(
        event(&events, "ledger-after-overlap")?["data"] == history
            && event(&events, "ledger-after-repeat")?["data"] == history,
        "repeat review must preserve every ledger field",
    );
    let before = event(&events, "ledger-before-overlap")?["data"]
        .as_array()
        .context("missing initial ledger")?;
    c.require(
        before.len() == 1 && human.first() == before.first(),
        "the initial escalation record must remain unchanged",
    );
    ensure_no_fixture_processes(&c.repo)
}

fn check_watch(c: &mut Check) -> Result<()> {
    let expected = expected_hashes(c, &["first", "second"])?;
    for channel in ["main", "inbox"] {
        c.require(
            c.repo.hashes(channel)? == expected,
            format!("{channel} must retain both watch changes without extra changes"),
        );
        c.no_conflicts(channel)?;
    }
    for name in ["first", "second"] {
        exact_records(c, name, &[("accept", "model")])?;
    }
    c.require(
        c.repo.ledger()?.len() == 2,
        "the outage must not add a decision record",
    );
    for (file, text) in [
        ("first.txt", "before the model outage\n"),
        ("second.txt", "pushed during the model outage\n"),
    ] {
        for channel in ["main", "inbox"] {
            c.require(
                c.file(channel, file)?.as_deref() == Some(text),
                format!("{channel} must preserve exact {file} content"),
            );
        }
    }
    let Some(events) = evidence(c)? else {
        return Ok(());
    };
    check_processes(c, &events, &[("watch", 130), ("push", 0)])?;
    let phases = [
        "request-held",
        "push-visible",
        "request-failed",
        "request-accepted",
        "watch-recovered",
        "signal",
        "ledger-after-sigint",
    ];
    let indices: Vec<_> = phases
        .iter()
        .map(|phase| event_index(&events, phase))
        .collect::<Result<_>>()?;
    c.require(
        indices.windows(2).all(|pair| pair[0] < pair[1]),
        "watch must remain active through the outage, push, recovery, and SIGINT",
    );
    c.require(
        event(&events, "ledger-during-outage")?["data"] == json!([]),
        "the held request must not decide a patch",
    );
    let pushed = &event(&events, "push-visible")?["data"];
    c.require(
        pushed["inbox"] == json!(expected)
            && pushed["main"] == c.facts["base"]
            && pushed["ledger"] == json!([]),
        "both patches must reach inbox before model recovery",
    );
    let exit = process_exit(&events, "watch")?;
    let signal_ms = event(&events, "signal")?["elapsed_ms"]
        .as_u64()
        .context("missing SIGINT time")?;
    let exit_ms = exit["elapsed_ms"]
        .as_u64()
        .context("missing watch exit time")?;
    c.require(
        exit_ms >= signal_ms && exit_ms - signal_ms <= 3000,
        "watch must exit within three seconds after SIGINT",
    );
    let history = json!(c.repo.ledger()?);
    c.require(
        event(&events, "watch-recovered")?["data"]["ledger"] == history
            && event(&events, "ledger-after-sigint")?["data"] == history,
        "SIGINT must preserve every decision field",
    );
    ensure_no_fixture_processes(&c.repo)
}
