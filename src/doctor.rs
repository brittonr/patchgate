use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::configuration::{self, Evidence};
use crate::gate::Settings;
use crate::model::Model;
use crate::pijul::{Pijul, safe_path};
use crate::verify;

const PROBE_LIMIT: Duration = Duration::from_secs(15);
const OUTPUT_LIMIT: u64 = 2 * 1024 * 1024;

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub ok: bool,
    pub checks: Vec<Check>,
    pub configuration: Option<Evidence>,
}

#[derive(Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Error,
    Warning,
    Unavailable,
}

impl Status {
    fn text(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Unavailable => "unavailable",
        }
    }
}

impl Report {
    fn add(
        &mut self,
        id: &'static str,
        status: Status,
        detail: impl Into<String>,
        repair: Option<String>,
    ) {
        if matches!(status, Status::Error | Status::Unavailable) {
            self.ok = false;
        }
        self.checks.push(Check {
            id,
            status,
            detail: detail.into(),
            repair,
        });
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InspectionMode {
    Doctor,
    Initialization,
}

pub fn inspect(settings: &Settings) -> Result<Report> {
    inspect_readiness(settings, InspectionMode::Doctor).map(|(report, _)| report)
}

pub fn inspect_initialization(
    settings: &Settings,
) -> Result<(Report, Option<crate::pijul::ChannelSnapshot>)> {
    inspect_readiness(settings, InspectionMode::Initialization)
}

fn inspect_readiness(
    settings: &Settings,
    mode: InspectionMode,
) -> Result<(Report, Option<crate::pijul::ChannelSnapshot>)> {
    let mut report = Report {
        schema_version: 1,
        ok: true,
        checks: Vec::new(),
        configuration: None,
    };
    let mut main_snapshot = None;
    let command = format!(
        "patchgate --repo {} --main {} --inbox {}",
        quote(&settings.repo.to_string_lossy()),
        quote(&settings.main),
        quote(&settings.inbox)
    );
    let metadata = metadata_safety(&settings.repo);
    match &metadata {
        Ok(()) => report.add("repository.metadata", Status::Pass,
            "Repository metadata contains only directories and regular files. Symbolic links are not permitted.", None),
        Err(error) => report.add("repository.metadata", Status::Error, format!("{error:#}"),
            Some(format!("Restore unsafe metadata from a trusted backup. Inspect it with: stat {}",
                quote(&settings.repo.join(".pijul").to_string_lossy())))),
    }
    let help_directory = tempfile::Builder::new()
        .prefix("patchgate-doctor-help-")
        .tempdir()?;
    let help_pijul = Pijul::with_timeout(help_directory.path().to_path_buf(), PROBE_LIMIT);
    match help_pijul.run(["apply", "--help"]) {
        Ok(help) if supports_expected_state(&help) => report.add("pijul.expected_state", Status::Pass,
            "Pijul advertises apply --expected-state. This read-only probe does not test its transaction semantics.", None),
        Ok(_) => report.add("pijul.expected_state", Status::Error,
            "Pijul does not advertise apply --expected-state.",
            Some("Use the pinned patched Pijul runtime. Run: devenv shell".into())),
        Err(error) => report.add("pijul.expected_state", Status::Error, format!("{error:#}"),
            Some("Use the pinned patched Pijul runtime. Run: devenv shell".into())),
    }

    if metadata.is_ok() {
        match crate::isolation::copy_repository(&settings.repo) {
            Ok(isolated) => {
                let pijul = Pijul::with_timeout(isolated.pijul.repo.clone(), PROBE_LIMIT);
                inspect_isolated_journal(&mut report, &settings.repo, &pijul.repo, &command);
                inspect_channels(&mut report, &pijul, settings, &command, mode);
                if mode == InspectionMode::Initialization {
                    let snapshot = if report
                        .checks
                        .iter()
                        .any(|check| check.id == "channel.main" && check.status == Status::Pass)
                    {
                        pijul.snapshot(&settings.main)
                    } else {
                        Err(anyhow::anyhow!("The main channel is unavailable"))
                    };
                    match snapshot {
                        Ok(snapshot) => {
                            report.add(
                                "channel.main_snapshot",
                                Status::Pass,
                                "The private main snapshot contains native state and change hashes.",
                                None,
                            );
                            main_snapshot = Some(snapshot);
                        }
                        Err(_) => report.add(
                            "channel.main_snapshot",
                            Status::Error,
                            "Cannot read the private main snapshot.",
                            Some("Restore a readable main channel from a trusted backup.".into()),
                        ),
                    }
                }
            }
            Err(error) => {
                for id in [
                    "acceptance.recovery",
                    "configuration.trusted",
                    "channel.main",
                    "channel.inbox",
                    "policy.trusted",
                    "nix.manifest",
                ] {
                    report.add(
                        id,
                        Status::Unavailable,
                        format!("Cannot isolate repository metadata: {error:#}"),
                        Some(format!(
                            "Stop other repository writers, then run: {command} doctor"
                        )),
                    );
                }
            }
        }
    } else {
        for id in [
            "acceptance.recovery",
            "configuration.trusted",
            "channel.main",
            "channel.inbox",
            "policy.trusted",
            "nix.manifest",
        ] {
            report.add(
                id,
                Status::Unavailable,
                "Unsafe repository metadata prevents this diagnostic.",
                None,
            );
        }
    }
    if mode == InspectionMode::Initialization && !report.ok {
        for id in [
            "model.readiness",
            "nix.runtime",
            "nix.sandbox",
            "pijul.runtime_expected_state",
            "nix.runtime_isolation",
        ] {
            report.add(
                id,
                Status::Unavailable,
                "Repository, policy, or check errors prevent this probe.",
                None,
            );
        }
        if settings.escalation_profile.is_some() {
            report.add(
                "model.escalation_readiness",
                Status::Unavailable,
                "Repository, policy, or check errors prevent this probe.",
                None,
            );
        }
        return Ok((report, main_snapshot));
    }
    let values = report.configuration.as_ref().map(|value| &value.values);
    let timeout = values
        .and_then(|value| Duration::try_from_secs_f64(value.timeout_seconds).ok())
        .unwrap_or(settings.timeout)
        .min(PROBE_LIMIT);
    let check_timeout = values
        .and_then(|value| Duration::try_from_secs_f64(value.check_timeout_seconds).ok())
        .unwrap_or(settings.check_timeout)
        .min(PROBE_LIMIT);
    inspect_model(&mut report, settings, timeout);
    if mode == InspectionMode::Initialization {
        inspect_escalation_model(&mut report, settings, timeout);
    }
    inspect_nix(&mut report, check_timeout);
    if mode == InspectionMode::Initialization {
        inspect_runtime_probes(&mut report, settings);
    }
    Ok((report, main_snapshot))
}

/// Run explicit probes in private fixtures after the read-only checks.
pub fn inspect_runtime(settings: &Settings) -> Result<Report> {
    let mut report = inspect(settings)?;
    inspect_runtime_probes(&mut report, settings);
    Ok(report)
}

fn inspect_runtime_probes(report: &mut Report, settings: &Settings) {
    match native_runtime_probe() {
        Ok(()) => report.add(
            "pijul.runtime_expected_state",
            Status::Pass,
            "A private native fixture refused a stale state without state or file changes. The same candidate applied with the current state.",
            None,
        ),
        Err(_) => report.add(
            "pijul.runtime_expected_state",
            Status::Error,
            "The private native transaction probe failed or exceeded its time limit. Native output is omitted.",
            Some("Use the pinned patched Pijul runtime and OpenSSH tools. Run: devenv shell".into()),
        ),
    }
    let timeout = report
        .configuration
        .as_ref()
        .and_then(|value| Duration::try_from_secs_f64(value.values.check_timeout_seconds).ok())
        .unwrap_or(settings.check_timeout)
        .min(PROBE_LIMIT);
    let interrupted = std::sync::atomic::AtomicBool::new(false);
    match verify::probe_runtime_isolation(timeout, &interrupted) {
        Ok(()) => report.add(
            "nix.runtime_isolation",
            Status::Pass,
            "A fresh local derivation could not read the host marker or inherit private client data. Its output matched. This result is not a universal isolation proof.",
            None,
        ),
        Err(_) => report.add(
            "nix.runtime_isolation",
            Status::Error,
            "The private Nix isolation probe failed or exceeded its time limit. Check the local daemon, Nix-store shell, and sandbox-paths. Nix output is omitted.",
            Some(sandbox_repair()),
        ),
    }
}

type ProbeSnapshot = (Option<String>, BTreeSet<String>);

struct NativeProbe {
    directory: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    socket: PathBuf,
    pijul: PathBuf,
    deadline: Instant,
    agent: Option<Child>,
}

impl Drop for NativeProbe {
    fn drop(&mut self) {
        if let Some(agent) = &mut self.agent {
            unsafe {
                libc::kill(-(agent.id() as libc::pid_t), libc::SIGKILL);
            }
            let _ = agent.wait();
        }
    }
}

fn probe_executable(name: &str) -> Result<PathBuf> {
    env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .and_then(|path| fs::canonicalize(path).ok())
        .with_context(|| format!("The runtime probe needs {name} in an absolute PATH directory"))
}

impl NativeProbe {
    fn new() -> Result<Self> {
        let directory = tempfile::Builder::new().prefix("pg-native-").tempdir()?;
        let repo = directory.path().join("repo");
        let home = directory.path().join("home");
        fs::create_dir(&repo)?;
        fs::create_dir(&home)?;
        fs::create_dir(home.join("tmp"))?;
        Ok(Self {
            repo,
            home,
            socket: directory.path().join("agent"),
            pijul: probe_executable("pijul")?,
            directory,
            deadline: Instant::now() + PROBE_LIMIT,
            agent: None,
        })
    }

    fn command(&self, executable: &Path) -> Command {
        let mut command = Command::new(executable);
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("TMPDIR", self.home.join("tmp"))
            .env("PATH", "")
            .env("SSH_AUTH_SOCK", &self.socket)
            .env("NO_COLOR", "1")
            .current_dir(&self.repo)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        command
    }

    fn execute(&self, command: &mut Command) -> Result<(ExitStatus, String)> {
        ensure!(
            Instant::now() < self.deadline,
            "The native runtime probe timed out"
        );
        let mut stdout = tempfile::tempfile_in(self.directory.path())?;
        command.stdout(Stdio::from(stdout.try_clone()?));
        let mut child = command
            .spawn()
            .context("Cannot execute the native runtime probe")?;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < self.deadline => {
                    thread::sleep(Duration::from_millis(20))
                }
                result => {
                    unsafe {
                        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
                    }
                    let _ = child.wait();
                    if let Err(error) = result {
                        return Err(error.into());
                    }
                    bail!("The native runtime probe timed out");
                }
            }
        };
        ensure!(
            stdout.metadata()?.len() <= OUTPUT_LIMIT,
            "Native probe output exceeds its limit"
        );
        stdout.rewind()?;
        let mut text = String::new();
        stdout.take(OUTPUT_LIMIT).read_to_string(&mut text)?;
        Ok((status, text))
    }

    fn run(&self, arguments: &[&str]) -> Result<String> {
        let mut command = self.command(&self.pijul);
        command.args(arguments);
        let (status, text) = self.execute(&mut command)?;
        ensure!(status.success(), "The native fixture command failed");
        Ok(text)
    }

    fn signer(&mut self) -> Result<()> {
        let key = self.directory.path().join("key");
        let mut keygen = self.command(&probe_executable("ssh-keygen")?);
        keygen
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "patchgate-doctor",
                "-f",
            ])
            .arg(&key);
        ensure!(
            self.execute(&mut keygen)?.0.success(),
            "Cannot create the private probe key"
        );
        let mut agent = self.command(&probe_executable("ssh-agent")?);
        agent
            .args(["-D", "-a"])
            .arg(&self.socket)
            .stdout(Stdio::null());
        self.agent = Some(
            agent
                .spawn()
                .context("Cannot start the private probe signer")?,
        );
        while !self.socket.exists() {
            ensure!(
                Instant::now() < self.deadline,
                "The private probe signer timed out"
            );
            ensure!(
                self.agent
                    .as_mut()
                    .context("Missing private signer")?
                    .try_wait()?
                    .is_none(),
                "The private probe signer exited"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let mut add = self.command(&probe_executable("ssh-add")?);
        add.arg("-q").arg(&key);
        ensure!(
            self.execute(&mut add)?.0.success(),
            "Cannot load the private probe key"
        );
        Ok(())
    }

    fn snapshot(&self, channel: &str) -> Result<ProbeSnapshot> {
        let text = self.run(&[
            "log",
            "--channel",
            channel,
            "--state",
            "--output-format",
            "json",
        ])?;
        #[derive(Deserialize)]
        struct Entry {
            hash: String,
            state: String,
        }
        let entries: Vec<Entry> = serde_json::from_str(&text)?;
        ensure!(
            entries
                .iter()
                .all(|entry| !entry.hash.is_empty() && !entry.state.is_empty()),
            "The native probe snapshot is incomplete"
        );
        Ok((
            entries.first().map(|entry| entry.state.clone()),
            entries.into_iter().map(|entry| entry.hash).collect(),
        ))
    }

    fn files(&self) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
        let mut files = BTreeMap::new();
        for entry in fs::read_dir(&self.repo)? {
            let entry = entry?;
            if entry.file_name() == ".pijul" {
                continue;
            }
            ensure!(
                entry.file_type()?.is_file(),
                "The native fixture contains an unexpected entry"
            );
            files.insert(entry.path(), fs::read(entry.path())?);
        }
        Ok(files)
    }

    fn record(&self, message: &str) -> Result<()> {
        self.run(&[
            "record",
            "-a",
            "-m",
            message,
            "--author",
            "patchgate-doctor",
        ])?;
        Ok(())
    }
}

fn native_runtime_probe() -> Result<()> {
    let mut probe = NativeProbe::new()?;
    probe.signer()?;
    probe.run(&["init"])?;
    // All native configuration and file bytes belong to this private fixture.
    for name in [".pijul/config", ".pijul/config.toml", "pijul.toml"] {
        match fs::remove_file(probe.repo.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("Cannot exclude private native fixture configuration");
            }
        }
    }
    fs::write(probe.repo.join("base.txt"), b"private base\n")?;
    probe.run(&["add", "base.txt"])?;
    probe.record("Define the private base")?;
    let stale = probe.snapshot("main")?;
    probe.run(&["fork", "--channel", "main", "candidate"])?;
    probe.run(&["channel", "switch", "candidate"])?;
    fs::write(probe.repo.join("candidate.txt"), b"private candidate\n")?;
    probe.run(&["add", "candidate.txt"])?;
    probe.record("Define the private candidate")?;
    let candidate = probe
        .snapshot("candidate")?
        .1
        .difference(&stale.1)
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        candidate.len() == 1,
        "The private fixture needs one candidate"
    );
    probe.run(&["channel", "switch", "main"])?;
    fs::write(probe.repo.join("current.txt"), b"private current state\n")?;
    probe.run(&["add", "current.txt"])?;
    probe.record("Advance the private main state")?;
    let current = probe.snapshot("main")?;
    ensure!(stale.0 != current.0, "The private state did not advance");
    let before = probe.files()?;
    let mut command = probe.command(&probe.pijul);
    command.args([
        "apply",
        "--channel",
        "main",
        "--expected-state",
        stale.0.as_deref().context("Missing stale probe state")?,
        &candidate[0],
    ]);
    let (status, _) = probe.execute(&mut command)?;
    check_native_refusal(
        status,
        &current,
        &probe.snapshot("main")?,
        &before,
        &probe.files()?,
    )?;
    probe.run(&[
        "apply",
        "--channel",
        "main",
        "--expected-state",
        current
            .0
            .as_deref()
            .context("Missing current probe state")?,
        &candidate[0],
    ])?;
    let applied = probe.snapshot("main")?;
    let mut expected = current.1;
    expected.insert(candidate[0].clone());
    ensure!(
        applied.1 == expected && applied.0 != current.0,
        "Current-state acceptance failed"
    );
    let mut expected_files = before;
    expected_files.insert(
        probe.repo.join("candidate.txt"),
        b"private candidate\n".to_vec(),
    );
    ensure!(
        probe.files()? == expected_files,
        "Current-state acceptance changed unexpected file bytes"
    );
    Ok(())
}

fn check_native_refusal(
    status: ExitStatus,
    before: &ProbeSnapshot,
    after: &ProbeSnapshot,
    before_files: &BTreeMap<PathBuf, Vec<u8>>,
    after_files: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<()> {
    ensure!(
        status.code() == Some(42),
        "Pijul did not report an expected-state refusal"
    );
    ensure!(
        before == after,
        "The refused transaction changed native state"
    );
    ensure!(
        before_files == after_files,
        "The refused transaction changed file bytes"
    );
    Ok(())
}

fn inspect_channels(
    report: &mut Report,
    pijul: &Pijul,
    settings: &Settings,
    command: &str,
    mode: InspectionMode,
) {
    let channels = match pijul.channels() {
        Ok((_, channels)) => channels,
        Err(error) => {
            for id in [
                "channel.main",
                "channel.inbox",
                "configuration.trusted",
                "policy.trusted",
                "nix.manifest",
            ] {
                report.add(
                    id,
                    Status::Unavailable,
                    format!("Cannot list native channels: {error:#}"),
                    Some(format!(
                        "Inspect the repository with: pijul --repository {} channel",
                        quote(&settings.repo.to_string_lossy())
                    )),
                );
            }
            return;
        }
    };
    let main = channels.contains(&settings.main);
    let inbox = channels.contains(&settings.inbox);
    for (id, name, present) in [
        ("channel.main", &settings.main, main),
        ("channel.inbox", &settings.inbox, inbox),
    ] {
        let expected = !present
            && id == "channel.inbox"
            && mode == InspectionMode::Initialization;
        report.add(id, if present || expected { Status::Pass } else { Status::Error },
            if expected {
                format!("Channel {name:?} does not exist. Initialization will create it from main.")
            } else {
                format!("Channel {name:?} {}.", if present { "exists" } else { "does not exist" })
            },
            (!present && !expected).then(|| if id == "channel.inbox" && main {
                format!("Create offline channels with: {command} init --channels-only")
            } else {
                format!("Select the correct channel with --main and --inbox. List channels with: pijul --repository {} channel",
                    quote(&settings.repo.to_string_lossy()))
            }));
    }
    if settings.main == settings.inbox {
        report.add(
            "channel.distinct",
            Status::Error,
            "Main and inbox refer to the same channel.",
            Some("Select different channels with --main and --inbox.".into()),
        );
    } else {
        report.add(
            "channel.distinct",
            Status::Pass,
            "Main and inbox refer to different channels.",
            None,
        );
    }
    if !main {
        for id in ["configuration.trusted", "policy.trusted", "nix.manifest"] {
            report.add(
                id,
                Status::Unavailable,
                "The main channel does not exist.",
                None,
            );
        }
        return;
    }
    let prepare_inbox = if inbox {
        String::new()
    } else {
        format!("Create offline channels first: {command} init --channels-only. ")
    };
    match configuration::load(pijul, &settings.main, &settings.baseline_values()) {
        Ok(evidence) => {
            report.add(
                "configuration.trusted",
                Status::Pass,
                configuration_detail(&evidence),
                None,
            );
            let policy_path = &evidence.values.policy_path;
            let policy_repair = format!(
                "{prepare_inbox}Record {} in the inbox. Accept its change with: {command} accept <hash>",
                quote(policy_path)
            );
            match pijul.read_file(&settings.main, policy_path) {
                Ok(Some(text)) if !text.trim().is_empty() => report.add(
                    "policy.trusted",
                    Status::Pass,
                    "The effective main policy contains nonempty UTF-8 text. This check does not assess policy quality.",
                    None,
                ),
                Ok(_) => report.add(
                    "policy.trusted",
                    Status::Error,
                    "The effective main policy is absent or empty. Work files are not trusted policy.",
                    Some(policy_repair),
                ),
                Err(_) => report.add(
                    "policy.trusted",
                    Status::Error,
                    "Cannot read the effective trusted policy.",
                    Some(policy_repair),
                ),
            }
            report.configuration = Some(evidence);
        }
        Err(error) => {
            report.add(
                "configuration.trusted",
                Status::Error,
                format!("{error:#}"),
                Some(format!(
                    "Correct recorded patchgate.json, then run: {command} accept <hash>"
                )),
            );
            report.add(
                "policy.trusted",
                Status::Unavailable,
                "Invalid trusted configuration prevents effective policy inspection.",
                None,
            );
        }
    }
    match verify::Plan::load(pijul, &settings.main) {
        Ok(Some(_)) => report.add("nix.manifest", Status::Pass,
            "The trusted Nix manifest and recorded check paths pass structural validation. No check was evaluated or built.", None),
        Ok(None) => report.add("nix.manifest",
            if mode == InspectionMode::Initialization { Status::Error } else { Status::Warning },
            "Main has no nix/checks.json. The gate has no trusted Nix checks.",
            Some(format!("{prepare_inbox}Record nix/checks.json and its check definitions in the inbox. Accept its change with: {command} accept <hash>"))),
        Err(error) => report.add("nix.manifest", Status::Error, format!("{error:#}"),
            Some(format!("{prepare_inbox}Correct the recorded nix/checks.json and check paths. Accept its change with: {command} accept <hash>"))),
    }
}

fn configuration_detail(evidence: &Evidence) -> String {
    if evidence.source == "main" {
        format!(
            "Effective settings use recorded patchgate.json. Exact text SHA-256: {}.",
            evidence.sha256.as_deref().unwrap_or("absent")
        )
    } else {
        "Main has no patchgate.json. Effective settings use the caller environment.".into()
    }
}

fn inspect_isolated_journal(report: &mut Report, source: &Path, isolated: &Path, command: &str) {
    match copy_journal(source, isolated) {
        Ok(()) => inspect_journal(report, isolated, command),
        Err(error) => report.add(
            "acceptance.recovery",
            Status::Unavailable,
            format!("Cannot isolate the acceptance journal: {error:#}"),
            Some(format!(
                "Restore journal access, then run: {command} status"
            )),
        ),
    }
}

fn copy_journal(source: &Path, isolated: &Path) -> Result<()> {
    let path = safe_path(source, Path::new(".pijul/patchgate/acceptance.json"))?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            ensure!(
                metadata.is_file(),
                "The acceptance journal is not a regular file"
            );
            let target = isolated.join(".pijul/patchgate/acceptance.json");
            fs::create_dir_all(
                target
                    .parent()
                    .context("The journal has no parent directory")?,
            )?;
            fs::copy(path, target)?;
            Ok(())
        }
    }
}

pub(crate) fn metadata_safety(repo: &Path) -> Result<()> {
    let root = safe_path(repo, Path::new(".pijul"))?;
    ensure!(
        fs::symlink_metadata(&root)?.is_dir(),
        "Repository .pijul metadata is not a directory"
    );
    let mut pending = vec![root];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            ensure!(
                kind.is_dir() || kind.is_file(),
                "Repository metadata is not a regular file or directory: {}",
                entry.path().display()
            );
            if kind.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

fn inspect_journal(report: &mut Report, repository: &Path, command: &str) {
    let path = repository.join(".pijul/patchgate/acceptance.json");
    match File::open(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => report.add(
            "acceptance.recovery",
            Status::Pass,
            "No durable acceptance transaction needs recovery.",
            None,
        ),
        Err(error) => report.add(
            "acceptance.recovery",
            Status::Error,
            format!("Cannot read the acceptance journal: {error}"),
            Some(format!(
                "Restore journal access, then run: {command} status"
            )),
        ),
        Ok(file) => {
            let journal = serde_json::from_reader::<_, Value>(file)
                .context("Cannot decode the acceptance journal")
                .and_then(|value| validate_journal(&value));
            match journal {
                Ok(_) => report.add("acceptance.recovery", Status::Error,
                    "A durable acceptance transaction needs recovery. Doctor did not reconcile or remove it.",
                    Some(format!("Recover the transaction with: {command} status"))),
                Err(error) => report.add("acceptance.recovery", Status::Error,
                    format!("The acceptance journal has an invalid or unsupported format: {error}"),
                    Some(format!("Restore the journal from a trusted backup, then run: {command} status"))),
            }
        }
    }
}

fn validate_journal(value: &Value) -> Result<()> {
    ensure!(
        value.get("version").and_then(Value::as_u64) == Some(1),
        "Unsupported journal version"
    );
    ensure!(
        value.get("main").and_then(Value::as_str).is_some(),
        "Journal has no main channel"
    );
    ensure!(
        value.get("inbox").and_then(Value::as_str).is_some(),
        "Journal has no inbox channel"
    );
    ensure!(
        value.get("ledger_offset").and_then(Value::as_u64).is_some(),
        "Journal has no ledger offset"
    );
    ensure!(
        value
            .get("leading_newline")
            .and_then(Value::as_bool)
            .is_some(),
        "Journal has no newline flag"
    );
    let records = value
        .get("records")
        .and_then(Value::as_array)
        .context("Journal has no records")?;
    ensure!(!records.is_empty(), "Journal has no records");
    for record in records {
        crate::gate::Record::deserialize(record).context("Invalid journal record")?;
    }
    Ok(())
}

fn supports_expected_state(help: &str) -> bool {
    help.split_whitespace()
        .any(|word| word == "--expected-state" || word.starts_with("--expected-state="))
}

fn inspect_model(report: &mut Report, settings: &Settings, timeout: Duration) {
    let api = settings.model_api.as_str();
    let selected = match &settings.model_profile {
        Some(name) => format!("model profile {name:?}"),
        None => "the environment model settings".into(),
    };
    let repair = Some(format!(
        "Start the server for {selected}. Or select another profile with PATCHGATE_MODEL_PROFILE and run patchgate doctor. \
         The variables PATCHGATE_MODEL_URL, PATCHGATE_MODEL, and PATCHGATE_MODEL_API={api} override a profile."
    ));
    if timeout.is_zero() || settings.model.trim().is_empty() {
        report.add(
            "model.readiness",
            Status::Error,
            "The model name must be nonempty and PATCHGATE_TIMEOUT must be positive.",
            repair,
        );
        return;
    }
    // Key-file problems are local configuration, so their detail is safe.
    let model_key = match settings.model_key() {
        Ok(key) => key,
        Err(error) => {
            report.add(
                "model.readiness",
                Status::Error,
                format!("The selected model profile has no usable key file: {error:#}"),
                repair,
            );
            return;
        }
    };
    let result = (|| -> Result<bool> {
        let model = Model::new(
            &settings.model_url,
            &settings.model,
            timeout,
            settings.model_api,
            settings.model_revision.as_deref(),
            model_key.as_deref(),
        )?;
        probe_model(&model)
    })();
    match result {
        Ok(true) => report.add("model.readiness", Status::Pass,
            format!("The configured {api} API and model return a valid review response to fixed harmless data. This does not assess review quality."), None),
        Ok(false) => report.add("model.readiness", Status::Error,
            "The configured model did not return a valid review decision for the harmless probe.", repair),
        Err(_) => report.add("model.readiness", Status::Error,
            "The configured API/model probe failed or exceeded its time limit. Server replies are omitted to protect server data.", repair),
    }
}

fn probe_model(model: &Model) -> Result<bool> {
    // Only fixed public data enters this request. Do not add repository data here.
    let state = serde_json::value::RawValue::from_string(
        r#"{"schema_version":1,"candidate":{"message":"Doctor harmless readiness probe","paths":[],"context":{"full":true,"files":[]},"metadata_context":[]},"binding":{"probe":true}}"#.into()
    )?;
    Ok(model
        .review(
            "Accept this harmless readiness probe. It contains no source changes.",
            &state,
        )?
        .value
        .is_some())
}

fn inspect_escalation_model(report: &mut Report, settings: &Settings, timeout: Duration) {
    let Some(name) = settings.escalation_profile.as_deref() else {
        return;
    };
    let repair = Some(
        "Select a usable systemone profile with PATCHGATE_ESCALATE_PROFILE. Start its model server."
            .into(),
    );
    let selected = (|| -> Result<_> {
        let selection = crate::models::select_named(name)?;
        ensure!(
            matches!(selection.api, crate::model::Api::SystemOne),
            "The escalation profile must use the systemone API"
        );
        let key = selection
            .key_file
            .as_deref()
            .map(crate::models::read_key)
            .transpose()?;
        Ok((selection, key))
    })();
    let (selection, key) = match selected {
        Ok(selected) => selected,
        Err(_) => {
            report.add(
                "model.escalation_readiness",
                Status::Error,
                "The escalation profile or its local key file is invalid.",
                repair,
            );
            return;
        }
    };
    let result = Model::new(
        &selection.url,
        &selection.model,
        timeout,
        selection.api,
        selection.revision.as_deref(),
        key.as_deref(),
    )
    .and_then(|model| probe_model(&model));
    match result {
        Ok(true) => report.add(
            "model.escalation_readiness",
            Status::Pass,
            "The escalation model returns a valid review response to fixed harmless data. This does not assess review quality.",
            None,
        ),
        Ok(false) => report.add(
            "model.escalation_readiness",
            Status::Error,
            "The escalation model did not return a valid review decision for the harmless probe.",
            repair,
        ),
        Err(_) => report.add(
            "model.escalation_readiness",
            Status::Error,
            "The escalation API/model probe failed or exceeded its time limit. Server replies are omitted to protect server data.",
            repair,
        ),
    }
}

fn inspect_nix(report: &mut Report, timeout: Duration) {
    let repair = Some("Use the patchgate Nix runtime with: devenv shell".into());
    let result = nix_configuration(timeout);
    match result {
        Ok(config) => {
            report.add("nix.runtime", Status::Pass,
                "The isolated Nix client returned its configuration. No derivation was evaluated or built.", None);
            match sandbox_setting(&config) {
                Some("true") => report.add("nix.sandbox", Status::Pass,
                    "The isolated Nix client reports sandbox=true. This is not proof of daemon sandbox enforcement.", None),
                Some("relaxed") => report.add("nix.sandbox", Status::Warning,
                    "The isolated Nix client reports sandbox=relaxed. Some builds can bypass the sandbox.",
                    Some(sandbox_repair())),
                _ => report.add("nix.sandbox", Status::Error,
                    "The isolated Nix client does not report an enabled sandbox.",
                    Some(sandbox_repair())),
            }
        }
        Err(error) => {
            report.add("nix.runtime", Status::Error, format!("{error:#}"), repair);
            report.add(
                "nix.sandbox",
                Status::Unavailable,
                "The Nix client configuration is not available.",
                None,
            );
        }
    }
    report.add("nix.daemon_sandbox", Status::Warning,
        "This read-only diagnostic cannot prove daemon enforcement. The daemon, build machines, caches, and sandbox policy remain trusted.",
        Some(sandbox_repair()));
}

fn sandbox_repair() -> String {
    let restart = if cfg!(target_os = "macos") {
        "sudo launchctl kickstart -k system/systems.determinate.nix-daemon (Determinate Nix) \
         or system/org.nixos.nix-daemon (Nix)"
    } else {
        "sudo systemctl restart nix-daemon"
    };
    format!(
        "On the daemon host, set sandbox = true in the Nix configuration. \
         On Determinate Nix, edit /etc/nix/nix.custom.conf. \
         Remove broad host-directory entries from sandbox-paths. \
         Restart the host daemon with: {restart}"
    )
}

fn sandbox_setting(config: &Value) -> Option<&str> {
    let value = config.get("sandbox")?.get("value")?;
    if value == true {
        Some("true")
    } else {
        value.as_str()
    }
}

fn nix_configuration(timeout: Duration) -> Result<Value> {
    ensure!(
        !timeout.is_zero(),
        "PATCHGATE_CHECK_TIMEOUT must be positive"
    );
    let nix = env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join("nix"))
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .context("Nix is not on PATH")?;
    let nix = fs::canonicalize(nix)?;
    let home = tempfile::Builder::new()
        .prefix("patchgate-doctor-nix-")
        .tempdir()?;
    fs::create_dir(home.path().join("tmp"))?;
    let mut command = Command::new(nix);
    command
        .env_clear()
        .env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("PATH", "")
        .env("NIX_PATH", "")
        .env("NIX_USER_CONF_FILES", "")
        .current_dir(home.path())
        .stdin(Stdio::null())
        .process_group(0)
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "--option",
            "flake-registry",
            "",
            "--option",
            "accept-flake-config",
            "false",
            "--option",
            "builders",
            "",
            "--option",
            "access-tokens",
            "",
            "config",
            "show",
            "--json",
        ]);
    if let Some(user) = env::var_os("USER") {
        command.env("USER", user);
    }
    let mut stdout = tempfile::tempfile_in(home.path())?;
    command
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .context("Cannot execute the isolated Nix client")?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(40)),
            result => {
                unsafe {
                    libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
                }
                let _ = child.wait();
                if let Err(error) = result {
                    return Err(error.into());
                }
                bail!("The isolated Nix client exceeded its time limit");
            }
        }
    };
    ensure!(
        status.success(),
        "The isolated Nix client failed with {status}"
    );
    ensure!(
        stdout.metadata()?.len() <= OUTPUT_LIMIT,
        "The Nix configuration exceeds the output limit"
    );
    stdout.rewind()?;
    serde_json::from_reader(stdout.take(OUTPUT_LIMIT))
        .context("The Nix client returned invalid configuration JSON")
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn show(report: &Report) {
    println!(
        "patchgate doctor: {}",
        if report.ok {
            "ready with the stated limits"
        } else {
            "not ready"
        }
    );
    for check in &report.checks {
        println!("{} {}: {}", check.status.text(), check.id, check.detail);
        if let Some(repair) = &check.repair {
            println!("  Repair: {repair}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Api;
    use serde_json::json;
    use std::os::unix::fs::symlink;

    fn initialization_fixture() -> Result<(tempfile::TempDir, Settings)> {
        use std::sync::{Arc, atomic::AtomicBool};

        let directory = tempfile::tempdir()?;
        let pijul = Pijul::new(directory.path().to_path_buf());
        pijul.run(["init"])?;
        fs::write(directory.path().join("POLICY.md"), "Accept safe changes.\n")?;
        pijul.run(["add", "POLICY.md"])?;
        let signer = crate::pijul::Signer::new(directory.path().join(".pijul/patchgate"));
        let environment = signer.environment()?;
        pijul.call_with_env(
            ["record", "-a", "-m", "Record policy", "--author", "patchgate"],
            &environment.vars,
        )?;
        let mut settings = Settings::from_env(
            directory.path().to_path_buf(),
            "inbox".into(),
            "main".into(),
            Arc::new(AtomicBool::new(false)),
        )?;
        settings.policy = "POLICY.md".into();
        Ok((directory, settings))
    }

    fn repository_files(root: &Path) -> Result<BTreeMap<PathBuf, Option<Vec<u8>>>> {
        let mut files = BTreeMap::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                files.insert(path.clone(), None);
                files.extend(repository_files(&path)?);
            } else {
                ensure!(entry.file_type()?.is_file(), "The fixture contains a special file");
                files.insert(path.clone(), Some(fs::read(path)?));
            }
        }
        Ok(files)
    }

    fn channel_report(settings: &Settings, mode: InspectionMode) -> Result<Report> {
        let isolated = crate::isolation::copy_repository(&settings.repo)?;
        let mut report = Report {
            schema_version: 1,
            ok: true,
            checks: Vec::new(),
            configuration: None,
        };
        inspect_channels(&mut report, &isolated.pijul, settings, "patchgate", mode);
        Ok(report)
    }

    fn check_status(report: &Report, id: &str, expected: Status) {
        assert!(report.checks.iter().any(|check| check.id == id && check.status == expected));
    }

    #[test]
    fn initialization_allows_absent_inbox_but_requires_distinct_existing_main() -> Result<()> {
        let (_directory, mut settings) = initialization_fixture()?;
        let before = repository_files(&settings.repo)?;
        let report = channel_report(&settings, InspectionMode::Initialization)?;
        check_status(&report, "channel.main", Status::Pass);
        check_status(&report, "channel.inbox", Status::Pass);
        check_status(&report, "channel.distinct", Status::Pass);
        let report = channel_report(&settings, InspectionMode::Doctor)?;
        check_status(&report, "channel.inbox", Status::Error);

        settings.inbox = settings.main.clone();
        let report = channel_report(&settings, InspectionMode::Initialization)?;
        check_status(&report, "channel.distinct", Status::Error);
        assert!(!report.ok);

        settings.inbox = "inbox".into();
        settings.main = "absent-main".into();
        let (report, snapshot) = inspect_initialization(&settings)?;
        check_status(&report, "channel.main", Status::Error);
        check_status(&report, "channel.main_snapshot", Status::Error);
        check_status(&report, "model.readiness", Status::Unavailable);
        check_status(&report, "nix.runtime_isolation", Status::Unavailable);
        assert!(snapshot.is_none());
        assert!(!report.ok);
        assert_eq!(repository_files(&settings.repo)?, before);
        Ok(())
    }

    #[test]
    fn initialization_requires_recorded_checks_before_model_or_nix_probes() -> Result<()> {
        let (_directory, settings) = initialization_fixture()?;
        fs::create_dir(settings.repo.join("nix"))?;
        fs::write(
            settings.repo.join(verify::MANIFEST),
            r#"{"schema_version":1,"checks":["check.nix"]}"#,
        )?;
        fs::write(settings.repo.join("nix/check.nix"), "{}\n")?;
        let before = repository_files(&settings.repo)?;
        let isolated = crate::isolation::copy_repository(&settings.repo)?;
        let expected = isolated.pijul.snapshot(&settings.main)?;
        let report = channel_report(&settings, InspectionMode::Doctor)?;
        check_status(&report, "nix.manifest", Status::Warning);
        let (report, snapshot) = inspect_initialization(&settings)?;
        check_status(&report, "policy.trusted", Status::Pass);
        check_status(&report, "nix.manifest", Status::Error);
        for id in [
            "model.readiness",
            "nix.runtime",
            "nix.sandbox",
            "pijul.runtime_expected_state",
            "nix.runtime_isolation",
        ] {
            check_status(&report, id, Status::Unavailable);
        }
        assert_eq!(snapshot, Some(expected));
        assert!(!report.ok);
        assert_eq!(repository_files(&settings.repo)?, before);
        Ok(())
    }

    #[test]
    fn model_readiness_uses_response_values_without_revision_identity_claims() -> Result<()> {
        use std::sync::{Arc, atomic::AtomicBool};

        let directory = tempfile::tempdir()?;
        for api in [Api::OpenAi, Api::SystemOne] {
            let valid = match api {
                Api::OpenAi => json!({"choices": [{"message": {
                    "content": "{\"decision\":\"accept\",\"summary\":\"Probe.\",\"reason\":\"Rule.\"}"
                }}]}),
                Api::SystemOne => json!({"answers": {"review": {
                    "type": "choice", "choice": "accept", "confidence": 0.9
                }}}),
            };
            let valid = valid.to_string();
            for (status, reply, expected) in [
                (200, valid.as_str(), Status::Pass),
                (200, "PRIVATE_INVALID_REPLY", Status::Error),
                (503, "PRIVATE_SERVER_REPLY", Status::Error),
            ] {
                let (url, worker) = crate::model::tests::reply_server(status, reply)?;
                let mut settings = Settings::from_env(
                    directory.path().to_path_buf(),
                    "inbox".into(),
                    "main".into(),
                    Arc::new(AtomicBool::new(false)),
                )?;
                settings.model_url = url;
                settings.model = "model".into();
                settings.model_api = api;
                settings.model_revision = Some("DECLARED_REVISION_ONLY".into());
                let mut report = Report {
                    schema_version: 1,
                    ok: true,
                    checks: Vec::new(),
                    configuration: None,
                };
                inspect_model(&mut report, &settings, Duration::from_secs(5));
                let request = worker.join().expect("The model fixture panicked")?;
                assert_eq!(request["model"], "model");
                assert_eq!(report.checks.len(), 1);
                assert_eq!(report.checks[0].id, "model.readiness");
                assert!(report.checks[0].status == expected);
                assert_eq!(report.ok, expected == Status::Pass);
                let encoded = serde_json::to_string(&report)?;
                for private in [
                    "DECLARED_REVISION_ONLY",
                    "PRIVATE_INVALID_REPLY",
                    "PRIVATE_SERVER_REPLY",
                ] {
                    assert!(!encoded.contains(private));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn unusable_key_files_report_their_own_error_without_the_key() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{Arc, atomic::AtomicBool};

        let directory = tempfile::tempdir()?;
        let key = directory.path().join("key");
        std::fs::write(&key, "sk-private\n")?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))?;
        let mut settings = Settings::from_env(
            directory.path().to_path_buf(),
            "inbox".into(),
            "main".into(),
            Arc::new(AtomicBool::new(false)),
        )?;
        settings.model_key_file = Some(key.clone());
        let mut report = Report {
            schema_version: 1,
            ok: true,
            checks: Vec::new(),
            configuration: None,
        };
        inspect_model(&mut report, &settings, Duration::from_secs(1));
        assert_eq!(report.checks.len(), 1);
        assert!(report.checks[0].status == Status::Error);
        let detail = &report.checks[0].detail;
        assert!(detail.contains("chmod 600"), "{detail}");
        assert!(!detail.contains("sk-private"));
        Ok(())
    }

    #[test]
    fn native_refusal_requires_its_exit_code_and_no_mutation() -> Result<()> {
        use std::os::unix::process::ExitStatusExt;
        let state = (Some("state".into()), BTreeSet::from(["base".into()]));
        let files = BTreeMap::from([(PathBuf::from("file"), b"original".to_vec())]);
        let refused = ExitStatus::from_raw(42 << 8);
        check_native_refusal(refused, &state, &state, &files, &files)?;
        assert!(
            check_native_refusal(ExitStatus::from_raw(0), &state, &state, &files, &files).is_err()
        );
        assert!(
            check_native_refusal(ExitStatus::from_raw(1 << 8), &state, &state, &files, &files)
                .is_err()
        );
        let changed = (Some("different".into()), state.1.clone());
        assert!(check_native_refusal(refused, &state, &changed, &files, &files).is_err());
        let changed = (
            state.0.clone(),
            BTreeSet::from(["base".into(), "candidate".into()]),
        );
        assert!(check_native_refusal(refused, &state, &changed, &files, &files).is_err());
        let changed_files = BTreeMap::from([(PathBuf::from("file"), b"changed".to_vec())]);
        assert!(check_native_refusal(refused, &state, &state, &files, &changed_files).is_err());
        assert!(check_native_refusal(refused, &state, &state, &files, &BTreeMap::new()).is_err());
        Ok(())
    }

    #[test]
    fn expected_state_requires_the_exact_option() {
        assert!(supports_expected_state(
            "Options:\n --expected-state <STATE>"
        ));
        assert!(supports_expected_state("--expected-state=STATE"));
        assert!(!supports_expected_state("--expected-state-other <STATE>"));
        assert!(!supports_expected_state(
            "conditional expected-state support"
        ));
    }

    #[test]
    fn sandbox_configuration_does_not_hide_relaxed_mode() {
        assert_eq!(
            sandbox_setting(&json!({"sandbox": {"value": true}})),
            Some("true")
        );
        assert_eq!(
            sandbox_setting(&json!({"sandbox": {"value": "relaxed"}})),
            Some("relaxed")
        );
        assert_ne!(
            sandbox_setting(&json!({"sandbox": {"value": false}})),
            Some("true")
        );
        assert_eq!(sandbox_setting(&json!({})), None);
    }

    #[test]
    fn metadata_links_fail_without_target_changes() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::create_dir(repository.path().join(".pijul"))?;
        fs::write(outside.path().join("ledger"), b"unchanged")?;
        symlink(outside.path(), repository.path().join(".pijul/patchgate"))?;
        assert!(metadata_safety(repository.path()).is_err());
        assert_eq!(fs::read(outside.path().join("ledger"))?, b"unchanged");
        Ok(())
    }

    #[test]
    fn journal_inspection_reads_the_private_copy() -> Result<()> {
        let source = tempfile::tempdir()?;
        let isolated = tempfile::tempdir()?;
        fs::create_dir_all(source.path().join(".pijul/patchgate"))?;
        fs::create_dir(isolated.path().join(".pijul"))?;
        let journal = source.path().join(".pijul/patchgate/acceptance.json");
        fs::write(&journal, b"original invalid journal")?;
        copy_journal(source.path(), isolated.path())?;
        fs::write(&journal, b"different source bytes")?;
        let mut report = Report {
            schema_version: 1,
            ok: true,
            checks: Vec::new(),
            configuration: None,
        };
        inspect_journal(&mut report, isolated.path(), "patchgate");
        assert!(
            report.checks.iter().any(|check| {
                check.id == "acceptance.recovery" && check.status == Status::Error
            })
        );
        assert_eq!(fs::read(&journal)?, b"different source bytes");
        assert_eq!(
            fs::read(isolated.path().join(".pijul/patchgate/acceptance.json"))?,
            b"original invalid journal"
        );
        Ok(())
    }

    #[test]
    fn journal_isolation_refuses_links() -> Result<()> {
        let source = tempfile::tempdir()?;
        let isolated = tempfile::tempdir()?;
        let outside = tempfile::NamedTempFile::new()?;
        fs::create_dir_all(source.path().join(".pijul/patchgate"))?;
        fs::create_dir(isolated.path().join(".pijul"))?;
        symlink(
            outside.path(),
            source.path().join(".pijul/patchgate/acceptance.json"),
        )?;
        assert!(copy_journal(source.path(), isolated.path()).is_err());
        assert!(!isolated.path().join(".pijul/patchgate").exists());
        Ok(())
    }

    #[test]
    fn isolated_channel_checks_use_effective_policy_and_report_configuration() -> Result<()> {
        use crate::pijul::Signer;
        use std::sync::{Arc, atomic::AtomicBool};

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("repo");
        fs::create_dir(&root)?;
        let pijul = Pijul::new(root.clone());
        pijul.run(["init"])?;
        fs::write(
            root.join(configuration::PATH),
            r#"{"schema_version":1,"settings":{"policy_path":"TRUSTED.md"}}"#,
        )?;
        fs::write(root.join("TRUSTED.md"), "Accept safe changes.\n")?;
        fs::create_dir(root.join("nix"))?;
        fs::write(
            root.join(verify::MANIFEST),
            r#"{"schema_version":1,"checks":["check.nix"]}"#,
        )?;
        fs::write(root.join("nix/check.nix"), "{}\n")?;
        pijul.run(["add", configuration::PATH, "TRUSTED.md"])?;
        pijul.run(["add", verify::MANIFEST, "nix/check.nix"])?;
        let signer = Signer::new(root.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Record trusted policy",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        pijul.run(["fork", "--channel", "main", "inbox"])?;
        fs::write(root.join(configuration::PATH), "dirty configuration")?;
        fs::write(root.join("TRUSTED.md"), "")?;
        fs::write(root.join(verify::MANIFEST), "dirty check manifest")?;
        let mut settings = Settings::from_env(
            root.clone(),
            "inbox".into(),
            "main".into(),
            Arc::new(AtomicBool::new(false)),
        )?;
        settings.policy = "UNRECORDED.md".into();
        fs::write(root.join("UNRECORDED.md"), "Do not trust work policy.\n")?;
        for mode in [InspectionMode::Doctor, InspectionMode::Initialization] {
            let report = channel_report(&settings, mode)?;
            check_status(&report, "configuration.trusted", Status::Pass);
            check_status(&report, "policy.trusted", Status::Pass);
            check_status(&report, "nix.manifest", Status::Pass);
            let evidence = report
                .configuration
                .context("Missing configuration evidence")?;
            assert_eq!(evidence.source, "main");
            assert_eq!(evidence.values.policy_path, "TRUSTED.md");
            assert!(configuration_detail(&evidence).contains(evidence.sha256.as_deref().unwrap()));
            assert_eq!(
                fs::read_to_string(root.join(configuration::PATH))?,
                "dirty configuration"
            );
            assert_eq!(fs::read_to_string(root.join("TRUSTED.md"))?, "");
            assert_eq!(
                fs::read_to_string(root.join(verify::MANIFEST))?,
                "dirty check manifest"
            );
        }
        pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Record invalid configuration",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        for mode in [InspectionMode::Doctor, InspectionMode::Initialization] {
            let report = channel_report(&settings, mode)?;
            assert!(report.configuration.is_none());
            check_status(&report, "configuration.trusted", Status::Error);
            check_status(&report, "policy.trusted", Status::Unavailable);
            assert!(!serde_json::to_string(&report)?.contains("dirty configuration"));
        }
        Ok(())
    }
}
