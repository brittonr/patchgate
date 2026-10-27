use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use tempfile::TempDir;

struct Repository {
    directory: TempDir,
    path: PathBuf,
    search_path: OsString,
    pijul: PathBuf,
    agent: Option<Child>,
}

impl Repository {
    fn new() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("pgwh-")
            .tempdir_in("/tmp")?;
        let path = directory.path().join("repo");
        fs::create_dir(&path)?;
        for name in ["home", "config", "cache", "tmp"] {
            fs::create_dir(directory.path().join(name))?;
        }
        let pijul = executable("pijul")?;
        let mut paths = vec![pijul.parent().context("Pijul has no parent")?.to_path_buf()];
        for name in ["ssh-keygen", "ssh-agent", "ssh-add"] {
            paths.push(
                executable(name)?
                    .parent()
                    .context("Tool has no parent")?
                    .to_path_buf(),
            );
        }
        paths.extend([PathBuf::from("/usr/bin"), PathBuf::from("/bin")]);
        let repo = Self {
            directory,
            path,
            search_path: std::env::join_paths(paths)?,
            pijul,
            agent: None,
        };
        repo.native(&["init"])?;
        Ok(repo)
    }

    fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(&self.path)
            .env_clear()
            .env("PATH", &self.search_path)
            .env("HOME", self.directory.path().join("home"))
            .env("XDG_CONFIG_HOME", self.directory.path().join("config"))
            .env("XDG_CACHE_HOME", self.directory.path().join("cache"))
            .env("TMPDIR", self.directory.path().join("tmp"))
            .env(
                "PATCHGATE_MODELS",
                self.directory.path().join("models.toml"),
            )
            .env("PATCHGATE_MODEL", "watch-health-test")
            .env("PATCHGATE_MODEL_API", "openai")
            .env("PATCHGATE_MODEL_URL", "http://127.0.0.1:1/v1")
            .env("PATCHGATE_TIMEOUT", "0.25")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null());
        if self.agent.is_some() {
            command.env("SSH_AUTH_SOCK", self.directory.path().join("agent"));
        }
        command
    }

    fn native(&self, args: &[&str]) -> Result<String> {
        let output = self.command(&self.pijul).args(args).output()?;
        ensure!(
            output.status.success(),
            "Native command {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?)
    }

    fn cli(&self, main: &str, inbox: &str) -> Command {
        let mut command = self.command(env!("CARGO_BIN_EXE_patchgate"));
        command
            .arg("--repo")
            .arg(&self.path)
            .args(["--main", main, "--inbox", inbox]);
        command
    }

    fn health(&self, main: &str, inbox: &str) -> Result<(Output, Value)> {
        let output = self
            .cli(main, inbox)
            .args(["health", "--json"])
            .env("PATCHGATE_TIMEOUT", "not-a-timeout")
            .env("PATCHGATE_MODEL_API", "invalid-api")
            .env("PATCHGATE_MODEL_PROFILE", "absent-profile")
            .output()?;
        let value = serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "Health has no JSON report: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
        Ok((output, value))
    }

    fn wait_health(&self, status: &str, predicate: impl Fn(&Value) -> bool) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let (output, report) = self.health("main", "inbox")?;
            assert_eq!(
                output.status.success(),
                report["healthy"] == true,
                "{report}"
            );
            if report["status"] == status && predicate(&report) {
                return Ok(report);
            }
            ensure!(
                Instant::now() < deadline,
                "Health did not reach {status}: {report}"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn watch(&self) -> Result<Watch> {
        Ok(Watch(
            self.cli("main", "inbox")
                .args(["watch", "--interval", "0.05"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        ))
    }

    fn snapshot(&self, channel: &str) -> Result<Value> {
        Ok(serde_json::from_str(&self.native(&[
            "log",
            "--channel",
            channel,
            "--state",
            "--output-format",
            "json",
        ])?)?)
    }

    fn fixture(&mut self, inbox: bool) -> Result<()> {
        let key = self.directory.path().join("fixture-key");
        let output = self
            .command(executable("ssh-keygen")?)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()?;
        ensure!(output.status.success(), "Cannot create fixture key");
        self.agent = Some(
            self.command(executable("ssh-agent")?)
                .args(["-D", "-a"])
                .arg(self.directory.path().join("agent"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.directory.path().join("agent").exists() {
            ensure!(
                self.agent.as_mut().unwrap().try_wait()?.is_none() && Instant::now() < deadline,
                "Fixture signer did not start"
            );
            thread::sleep(Duration::from_millis(10));
        }
        ensure!(
            self.command(executable("ssh-add")?)
                .arg("-q")
                .arg(key)
                .output()?
                .status
                .success(),
            "Cannot load fixture key"
        );
        fs::write(
            self.path.join("POLICY.md"),
            b"# Policy\nRequire human review for policy changes.\n",
        )?;
        fs::write(self.path.join("work.txt"), b"fixture work\n")?;
        self.native(&["add", "POLICY.md", "work.txt"])?;
        self.record("Define fixture")?;
        if inbox {
            self.native(&["fork", "inbox"])?;
            self.native(&["channel", "switch", "inbox"])?;
        }
        Ok(())
    }

    fn record(&self, message: &str) -> Result<()> {
        self.native(&[
            "record",
            "-a",
            "-m",
            message,
            "--author",
            "watch-health-test",
        ])?;
        Ok(())
    }

    fn assert_work(&self) -> Result<()> {
        assert_eq!(fs::read(self.path.join("work.txt"))?, b"fixture work\n");
        Ok(())
    }
}

impl Drop for Repository {
    fn drop(&mut self) {
        if let Some(agent) = &mut self.agent {
            let _ = agent.kill();
            let _ = agent.wait();
        }
    }
}

struct Watch(Child);

impl Watch {
    fn signal(&mut self, signal: &str) -> Result<()> {
        ensure!(
            Command::new(executable("kill")?)
                .args([signal, &self.0.id().to_string()])
                .status()?
                .success(),
            "Cannot signal watch"
        );
        Ok(())
    }

    fn wait(&mut self) -> Result<std::process::ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            ensure!(Instant::now() < deadline, "Watch did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn executable(name: &str) -> Result<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
        .with_context(|| format!("Missing native executable {name}"))
}

#[test]
fn absent_health_ignores_model_environment_and_creates_no_state() -> Result<()> {
    let repo = Repository::new()?;
    fs::write(repo.path.join("untracked.txt"), b"private work\n")?;
    let main = repo.snapshot("main")?;
    let (output, report) = repo.health("main", "inbox")?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["status"], "missing");
    assert_eq!(report["healthy"], false);
    assert_eq!(report["authorizes_acceptance"], false);
    assert!(report["snapshot"].is_null());
    assert!(report["attention_required"].is_null());
    assert!(!repo.path.join(".pijul/patchgate").exists());
    assert_eq!(repo.snapshot("main")?, main);
    assert_eq!(
        fs::read(repo.path.join("untracked.txt"))?,
        b"private work\n"
    );
    Ok(())
}

#[test]
fn empty_watch_has_one_owner_and_records_normal_stop() -> Result<()> {
    let mut repo = Repository::new()?;
    repo.fixture(true)?;
    let main = repo.snapshot("main")?;
    let inbox = repo.snapshot("inbox")?;
    let mut watch = repo.watch()?;
    let healthy = repo.wait_health("healthy", |_| true)?;
    assert_eq!(healthy["attention_required"], false);
    let instance = healthy["snapshot"]["instance"].clone();
    let mut duplicate = repo.watch()?;
    assert!(!duplicate.wait()?.success());
    let (_, active) = repo.health("main", "inbox")?;
    assert_eq!(active["snapshot"]["instance"], instance);
    assert_eq!(active["healthy"], true);
    let (output, other) = repo.health("main", "other-inbox")?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(other["status"], "missing");
    assert!(other["snapshot"].is_null());
    watch.signal("-INT")?;
    assert_eq!(watch.wait()?.code(), Some(130));
    let (_, stopped) = repo.health("main", "inbox")?;
    assert_eq!(stopped["status"], "stopped");
    assert_eq!(stopped["snapshot"]["phase"], "stopped");
    assert_eq!(stopped["healthy"], false);
    assert_eq!(repo.snapshot("main")?, main);
    assert_eq!(repo.snapshot("inbox")?, inbox);
    repo.assert_work()?;
    Ok(())
}

#[test]
fn missing_inbox_retains_failure_then_native_fork_restores_health() -> Result<()> {
    let mut repo = Repository::new()?;
    repo.fixture(false)?;
    let main = repo.snapshot("main")?;
    let mut watch = repo.watch()?;
    let failed = repo.wait_health("degraded", |report| {
        report["snapshot"]["consecutive_failures"]
            .as_u64()
            .unwrap_or(0)
            >= 2
    })?;
    assert!(!failed["snapshot"]["last_failure_at"].is_null());
    assert!(failed["snapshot"]["last_success_at"].is_null());
    repo.native(&["fork", "inbox"])?;
    let healthy = repo.wait_health("healthy", |_| true)?;
    assert_eq!(healthy["snapshot"]["consecutive_failures"], 0);
    assert!(!healthy["snapshot"]["last_failure_at"].is_null());
    assert!(!healthy["snapshot"]["last_success_at"].is_null());
    assert_eq!(
        healthy["snapshot"]["instance"],
        failed["snapshot"]["instance"]
    );
    assert_eq!(repo.snapshot("main")?, main);
    assert_eq!(repo.snapshot("inbox")?, main);
    repo.assert_work()?;
    watch.signal("-KILL")?;
    assert!(!watch.wait()?.success());
    let (output, dead) = repo.health("main", "inbox")?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(dead["status"], "not-running");
    assert_eq!(dead["healthy"], false);
    assert_eq!(
        dead["snapshot"]["instance"],
        healthy["snapshot"]["instance"]
    );
    Ok(())
}

#[test]
fn policy_escalation_requires_attention_without_service_failure() -> Result<()> {
    let mut repo = Repository::new()?;
    repo.fixture(true)?;
    let main = repo.snapshot("main")?;
    let policy = b"# Policy\nRequire two human approvals for policy changes.\n";
    fs::write(repo.path.join("POLICY.md"), policy)?;
    repo.record("Change policy")?;
    let inbox = repo.snapshot("inbox")?;
    assert_ne!(main, inbox);
    let mut watch = repo.watch()?;
    let healthy = repo.wait_health("healthy", |report| {
        report["snapshot"]["counts"]["escalated"]
            .as_u64()
            .unwrap_or(0)
            > 0
    })?;
    assert_eq!(healthy["attention_required"], true);
    assert_eq!(healthy["snapshot"]["counts"]["execution_errors"], 0);
    assert_eq!(healthy["snapshot"]["consecutive_failures"], 0);
    assert!(healthy["snapshot"]["failure"].is_null());
    assert_eq!(repo.snapshot("main")?, main);
    assert_eq!(repo.snapshot("inbox")?, inbox);
    assert_eq!(fs::read(repo.path.join("POLICY.md"))?, policy);
    repo.assert_work()?;
    watch.signal("-INT")?;
    assert_eq!(watch.wait()?.code(), Some(130));
    Ok(())
}
