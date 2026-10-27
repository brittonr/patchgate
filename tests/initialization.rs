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
        let directory = tempfile::Builder::new().prefix("pgi-").tempdir_in("/tmp")?;
        let path = directory.path().join("repo");
        fs::create_dir(&path)?;
        for name in ["home", "config", "cache", "tmp"] {
            fs::create_dir(directory.path().join(name))?;
        }
        let pijul = executable("pijul")?;
        let mut paths = vec![pijul.parent().context("Pijul has no parent")?.to_path_buf()];
        for name in ["ssh-keygen", "ssh-agent", "ssh-add"] {
            let tool = executable(name)?;
            paths.push(
                tool.parent()
                    .context("The tool has no parent")?
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
            .env("PATCHGATE_MODEL", "initialization-test")
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

    fn init(&self, args: &[&str]) -> Result<(Output, Value)> {
        let output = self
            .command(env!("CARGO_BIN_EXE_patchgate"))
            .arg("--repo")
            .arg(&self.path)
            .args(args)
            .output()?;
        let report = serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "Init has no JSON report: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
        Ok((output, report))
    }

    fn channels(&self) -> Result<(Option<String>, Vec<String>)> {
        let mut current = None;
        let mut names = Vec::new();
        for line in self.native(&["channel"])?.lines() {
            let start = line
                .char_indices()
                .nth(2)
                .map_or(line.len(), |(index, _)| index);
            let name = line[start..].trim();
            if !name.is_empty() {
                if line.starts_with('*') {
                    current = Some(name.to_owned());
                }
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok((current, names))
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

    fn sign(&mut self) -> Result<()> {
        let key = self.directory.path().join("fixture-key");
        let output = self
            .command(executable("ssh-keygen")?)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()?;
        ensure!(output.status.success(), "Cannot create the fixture key");
        let child = self
            .command(executable("ssh-agent")?)
            .args(["-D", "-a"])
            .arg(self.directory.path().join("agent"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        self.agent = Some(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.directory.path().join("agent").exists() {
            ensure!(
                self.agent.as_mut().unwrap().try_wait()?.is_none() && Instant::now() < deadline,
                "The fixture signer did not start"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let output = self
            .command(executable("ssh-add")?)
            .arg("-q")
            .arg(key)
            .output()?;
        ensure!(output.status.success(), "Cannot load the fixture key");
        Ok(())
    }

    fn assert_no_gate_records(&self) {
        assert!(!self.path.join(".pijul/patchgate").exists());
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

fn executable(name: &str) -> Result<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
        .with_context(|| format!("Missing native executable {name}"))
}

fn status<'a>(report: &'a Value, id: &str) -> &'a str {
    report["diagnostics"]["checks"]
        .as_array()
        .expect("Diagnostic checks")
        .iter()
        .find(|check| check["id"] == id)
        .unwrap_or_else(|| panic!("Missing diagnostic {id}: {report}"))["status"]
        .as_str()
        .expect("Diagnostic status")
}

#[test]
fn checked_init_rejects_unrecorded_policy_and_checks_without_source_writes() -> Result<()> {
    let repo = Repository::new()?;
    let policy = b"# Policy\nAccept only verified changes.\n";
    let checks = b"{\"schema_version\":1,\"checks\":[\"unit\"]}\n";
    fs::write(repo.path.join("POLICY.md"), policy)?;
    fs::create_dir(repo.path.join("nix"))?;
    fs::write(repo.path.join("nix/checks.json"), checks)?;
    let channels = repo.channels()?;
    let main = repo.snapshot("main")?;

    let (output, report) = repo.init(&["init", "--json"])?;

    assert!(!output.status.success());
    assert_eq!(report["initialized"], false);
    assert_eq!(report["ready"], false);
    assert_eq!(report["authorizes_acceptance"], false);
    assert_eq!(report["actions"], serde_json::json!([]));
    assert_eq!(report["diagnostics"]["ok"], false);
    assert_eq!(status(&report, "policy.trusted"), "error");
    assert_eq!(status(&report, "nix.manifest"), "error");
    assert_eq!(status(&report, "channel.inbox"), "pass");
    for id in [
        "model.readiness",
        "nix.runtime",
        "nix.sandbox",
        "pijul.runtime_expected_state",
        "nix.runtime_isolation",
    ] {
        assert_eq!(status(&report, id), "unavailable", "{id}");
    }
    assert_eq!(repo.channels()?, channels);
    assert_eq!(repo.snapshot("main")?, main);
    assert_eq!(fs::read(repo.path.join("POLICY.md"))?, policy);
    assert_eq!(fs::read(repo.path.join("nix/checks.json"))?, checks);
    repo.assert_no_gate_records();
    Ok(())
}

#[test]
fn channels_only_init_preserves_native_history_and_work_on_repeat() -> Result<()> {
    let mut repo = Repository::new()?;
    repo.sign()?;
    fs::write(repo.path.join("work.txt"), b"recorded work\n")?;
    repo.native(&["add", "work.txt"])?;
    repo.native(&[
        "record",
        "-a",
        "-m",
        "Define fixture work",
        "--author",
        "initialization-test",
    ])?;
    let main = repo.snapshot("main")?;
    let history = repo.native(&["log", "--channel", "main", "--hash-only"])?;
    fs::write(repo.path.join("untracked.txt"), b"untracked bytes\n")?;

    for dirty in [false, true] {
        if dirty {
            fs::write(repo.path.join("work.txt"), b"private unrecorded work\n")?;
        }
        let (output, report) = repo.init(&["init", "--channels-only", "--json"])?;
        assert!(output.status.success(), "{report}");
        assert_eq!(report["initialized"], true);
        assert_eq!(report["ready"], false);
        assert_eq!(report["channels_only"], true);
        assert_eq!(report["authorizes_acceptance"], false);
        assert_eq!(
            repo.channels()?,
            (Some("inbox".into()), vec!["inbox".into(), "main".into()])
        );
        assert_eq!(repo.snapshot("main")?, main);
        assert_eq!(repo.snapshot("inbox")?, main);
        assert_eq!(
            repo.native(&["log", "--channel", "main", "--hash-only"])?,
            history
        );
        assert_eq!(
            repo.native(&["log", "--channel", "inbox", "--hash-only"])?,
            history
        );
        let expected: &[u8] = if dirty {
            b"private unrecorded work\n"
        } else {
            b"recorded work\n"
        };
        assert_eq!(fs::read(repo.path.join("work.txt"))?, expected);
        assert_eq!(
            fs::read(repo.path.join("untracked.txt"))?,
            b"untracked bytes\n"
        );
        assert!(!repo.path.join("POLICY.md").exists());
        repo.assert_no_gate_records();
    }
    Ok(())
}

#[test]
fn identical_channel_names_refuse_both_init_modes_without_source_writes() -> Result<()> {
    for offline in [false, true] {
        let repo = Repository::new()?;
        fs::write(repo.path.join("private.txt"), b"private bytes\n")?;
        let channels = repo.channels()?;
        let main = repo.snapshot("main")?;
        let mut args = vec!["--main", "main", "--inbox", "main", "init", "--json"];
        if offline {
            args.push("--channels-only");
        }
        let output = repo
            .command(env!("CARGO_BIN_EXE_patchgate"))
            .arg("--repo")
            .arg(&repo.path)
            .args(args)
            .output()?;
        assert!(!output.status.success());
        assert_eq!(repo.channels()?, channels);
        assert_eq!(repo.snapshot("main")?, main);
        assert_eq!(fs::read(repo.path.join("private.txt"))?, b"private bytes\n");
        repo.assert_no_gate_records();
    }
    Ok(())
}

#[test]
fn channels_only_refuses_pending_recovery_without_channel_or_journal_changes() -> Result<()> {
    let repo = Repository::new()?;
    let journal = repo.path.join(".pijul/patchgate/acceptance.json");
    fs::create_dir(journal.parent().context("The journal has no parent")?)?;
    fs::write(&journal, b"private pending journal")?;
    let channels = repo.channels()?;
    let main = repo.snapshot("main")?;

    let output = repo
        .command(env!("CARGO_BIN_EXE_patchgate"))
        .arg("--repo")
        .arg(&repo.path)
        .args(["init", "--channels-only", "--json"])
        .output()?;

    assert!(!output.status.success());
    assert_eq!(repo.channels()?, channels);
    assert_eq!(repo.snapshot("main")?, main);
    assert_eq!(fs::read(&journal)?, b"private pending journal");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private pending journal"));
    Ok(())
}
