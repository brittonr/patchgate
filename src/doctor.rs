use std::env;
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::gate::Settings;
use crate::model::{Api, Model};
use crate::pijul::{Pijul, safe_path};
use crate::verify;

const PROBE_LIMIT: Duration = Duration::from_secs(15);
const OUTPUT_LIMIT: u64 = 2 * 1024 * 1024;

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub ok: bool,
    pub checks: Vec<Check>,
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

pub fn inspect(settings: &Settings) -> Result<Report> {
    let mut report = Report {
        schema_version: 1,
        ok: true,
        checks: Vec::new(),
    };
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
    if metadata.is_ok() {
        inspect_journal(&mut report, settings, &command);
    } else {
        report.add(
            "acceptance.recovery",
            Status::Unavailable,
            "Unsafe repository metadata prevents acceptance journal inspection.",
            None,
        );
    }

    let timeout = settings.timeout.min(PROBE_LIMIT);
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
                inspect_channels(&mut report, &pijul, settings, &command);
            }
            Err(error) => {
                for id in [
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
    inspect_model(&mut report, settings, timeout);
    inspect_nix(&mut report, settings.check_timeout.min(PROBE_LIMIT));
    Ok(report)
}

fn inspect_channels(report: &mut Report, pijul: &Pijul, settings: &Settings, command: &str) {
    let channels = match pijul.channels() {
        Ok((_, channels)) => channels,
        Err(error) => {
            for id in [
                "channel.main",
                "channel.inbox",
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
        report.add(id, if present { Status::Pass } else { Status::Error },
            format!("Channel {name:?} {}.", if present { "exists" } else { "does not exist" }),
            (!present).then(|| if id == "channel.inbox" && main {
                format!("Create the inbox from main with: {command} init")
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
        for id in ["policy.trusted", "nix.manifest"] {
            report.add(
                id,
                Status::Unavailable,
                "The main channel does not exist.",
                None,
            );
        }
        return;
    }
    let policy_repair = format!(
        "Record {} in the inbox, then accept its change with: {command} accept <hash>",
        quote(&settings.policy)
    );
    match pijul.read_file(&settings.main, &settings.policy) {
        Ok(Some(text)) if !text.trim().is_empty() => report.add("policy.trusted", Status::Pass,
            "The trusted main channel contains nonempty UTF-8 policy text. This check does not assess policy quality.", None),
        Ok(_) => report.add("policy.trusted", Status::Error,
            "The trusted main policy is absent or empty. Work files are not trusted policy.", Some(policy_repair)),
        Err(error) => report.add("policy.trusted", Status::Error, format!("Cannot read trusted policy: {error:#}"),
            Some(policy_repair)),
    }
    match verify::Plan::load(pijul, &settings.main) {
        Ok(Some(_)) => report.add("nix.manifest", Status::Pass,
            "The trusted Nix manifest and recorded check paths pass structural validation. No check was evaluated or built.", None),
        Ok(None) => report.add("nix.manifest", Status::Warning,
            "Main has no nix/checks.json. The gate has no trusted Nix checks.",
            Some(format!("Record nix/checks.json and its check definitions, then run: {command} accept <hash>"))),
        Err(error) => report.add("nix.manifest", Status::Error, format!("{error:#}"),
            Some(format!("Correct the recorded nix/checks.json and check paths, then run: {command} accept <hash>"))),
    }
}

fn metadata_safety(repo: &Path) -> Result<()> {
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

fn inspect_journal(report: &mut Report, settings: &Settings, command: &str) {
    let path = settings.repo.join(".pijul/patchgate/acceptance.json");
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
    let api = match settings.model_api {
        Api::OpenAi => "openai",
        Api::SystemOne => "systemone",
    };
    let repair = Some(format!(
        "Start the configured model server. Set PATCHGATE_MODEL_URL, PATCHGATE_MODEL, and PATCHGATE_MODEL_API={api}, then run patchgate doctor."
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
    // Only fixed public data enters this request. Do not add repository data here.
    let result = (|| -> Result<bool> {
        let state = serde_json::value::RawValue::from_string(
            r#"{"schema_version":1,"candidate":{"message":"Doctor harmless readiness probe","paths":[],"context":{"full":true,"files":[]},"metadata_context":[]},"binding":{"probe":true}}"#.into()
        )?;
        let model = Model::new(
            &settings.model_url,
            &settings.model,
            timeout,
            settings.model_api,
        )?;
        Ok(model
            .review(
                "Accept this harmless readiness probe. It contains no source changes.",
                &state,
            )?
            .is_some())
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
        "sudo launchctl kickstart -k system/org.nixos.nix-daemon"
    } else {
        "sudo systemctl restart nix-daemon"
    };
    format!(
        "On the daemon host, run: sudoedit /etc/nix/nix.conf. Set sandbox = true. Restart the daemon with: {restart}"
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
    use serde_json::json;
    use std::os::unix::fs::symlink;

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
}
