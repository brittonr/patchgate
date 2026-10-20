use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{Read, Seek};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::TempDir;

use crate::pijul::Pijul;
use crate::review::MainBinding;

pub const DIRECTORY: &str = "nix";
pub const MANIFEST: &str = "nix/checks.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    checks: Vec<String>,
    #[serde(default)]
    inputs: BTreeMap<String, Input>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    url: String,
    nar_hash: String,
}

impl Manifest {
    fn parse(text: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(text).context("Invalid trusted Nix manifest")?;
        ensure!(
            manifest.schema_version == 1,
            "Unsupported Nix manifest schema"
        );
        ensure!(
            !manifest.checks.is_empty(),
            "The Nix manifest has no checks"
        );
        let mut seen = BTreeSet::new();
        for check in &manifest.checks {
            ensure!(
                !check.is_empty()
                    && !check.chars().any(char::is_control)
                    && Path::new(check)
                        .components()
                        .all(|part| matches!(part, Component::Normal(_))),
                "Invalid trusted check path: {check:?}"
            );
            ensure!(seen.insert(check), "Repeated trusted check: {check}");
        }
        for (name, input) in &manifest.inputs {
            ensure!(
                !name.is_empty() && !name.chars().any(char::is_control),
                "Invalid Nix input name"
            );
            ensure!(
                input.url.starts_with("https://")
                    || input.url.strip_prefix("path:").is_some_and(|path| {
                        Path::new(path).parent() == Some(Path::new("/nix/store"))
                            && !path.chars().any(|character| {
                                character.is_control()
                                    || character.is_whitespace()
                                    || matches!(character, '?' | '#')
                            })
                    }),
                "Nix input {name} must use HTTPS or an immutable store path"
            );
            ensure!(
                valid_hash(&input.nar_hash),
                "Invalid NAR hash for Nix input {name}"
            );
        }
        Ok(manifest)
    }
}

fn valid_hash(hash: &str) -> bool {
    hash.strip_prefix("sha256-").is_some_and(|value| {
        value.len() == 44
            && value.ends_with('=')
            && value.as_bytes()[..43]
                .iter()
                .copied()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    })
}

#[derive(Clone, Deserialize, Serialize)]
pub struct StoreTree {
    path: String,
    nar_hash: String,
}

impl StoreTree {
    fn expression(&self) -> Result<String> {
        Ok(format!(
            "(builtins.fetchTree {{ type = \"path\"; path = {}; narHash = {}; }})",
            nix_string(&self.path)?,
            nix_string(&self.nar_hash)?
        ))
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct CheckResult {
    check: String,
    drv_path: String,
    outputs: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Verification {
    schema_version: u32,
    candidates: Vec<String>,
    merge: Option<String>,
    main: MainBinding,
    source: StoreTree,
    definitions: StoreTree,
    inputs: BTreeMap<String, StoreTree>,
    results: Vec<CheckResult>,
}

pub struct Plan {
    manifest: Manifest,
    directory: TempDir,
}

impl Plan {
    pub fn load(repo: &Pijul, channel: &str) -> Result<Option<Self>> {
        let Some(text) = repo.read_file(channel, MANIFEST)? else {
            return Ok(None);
        };
        let manifest = Manifest::parse(&text)?;
        let directory = tempfile::Builder::new()
            .prefix("patchgate-checks-")
            .tempdir()?;
        let source = directory.path().join("main");
        repo.export_source(channel, &source)?;
        let definitions = source.join(DIRECTORY);
        ensure!(
            fs::symlink_metadata(&definitions)?.file_type().is_dir(),
            "The trusted Nix directory must be a recorded directory"
        );
        ensure!(
            fs::symlink_metadata(source.join(MANIFEST))?
                .file_type()
                .is_file(),
            "The trusted Nix manifest must be a recorded regular file"
        );
        for check in &manifest.checks {
            ensure!(
                crate::pijul::safe_path(&definitions, Path::new(check))?.is_file(),
                "Trusted check is not a regular file: {check}"
            );
        }
        Ok(Some(Self {
            manifest,
            directory,
        }))
    }

    pub fn run(
        &self,
        source: &Path,
        candidates: &[String],
        merge: Option<&str>,
        main: MainBinding,
        timeout: Duration,
        interrupted: &AtomicBool,
    ) -> Result<Verification> {
        let runner = Runner::new(timeout, interrupted)?;
        runner.require_sandbox()?;
        let definitions = runner.add_tree(&self.directory.path().join("main").join(DIRECTORY))?;
        let source = runner.add_tree(source)?;
        let mut inputs = BTreeMap::new();
        for (name, input) in &self.manifest.inputs {
            let hash = input
                .nar_hash
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D");
            let url = format!(
                "{}{}narHash={hash}",
                input.url,
                if input.url.contains('?') { '&' } else { '?' }
            );
            let value = runner.json(&["flake", "prefetch", "--json", &url])?;
            let path = field(&value, "storePath")?;
            let hash = field(&value, "hash")?;
            ensure!(
                hash == input.nar_hash,
                "NAR hash differs for Nix input {name}"
            );
            let tree = runner.tree(path)?;
            ensure!(
                tree.nar_hash == input.nar_hash,
                "NAR hash differs for Nix input {name}"
            );
            inputs.insert(name.clone(), tree);
        }
        let system = system()?;
        let input_expression = inputs
            .iter()
            .map(|(name, tree)| Ok(format!("{} = {};", nix_string(name)?, tree.expression()?)))
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        let mut results = Vec::with_capacity(self.manifest.checks.len());
        for check in &self.manifest.checks {
            let expression = format!(
                "let definitions = {}; src = {}; inputs = {{ {} }}; in import (definitions + {}) {{ inherit src inputs; system = {}; }}",
                definitions.expression()?,
                source.expression()?,
                input_expression,
                nix_string(&format!("/{check}"))?,
                nix_string(&system)?
            );
            eprintln!("patchgate: verifying trusted Nix check {check}");
            let derivations = runner.evaluate(&["derivation", "show", "--expr", &expression])?;
            let drv_path = checked_derivation(&derivations)?;
            let built = runner.evaluate(&[
                "build",
                "--no-link",
                "--json",
                "--print-build-logs",
                "--expr",
                &expression,
            ])?;
            let built = built
                .as_array()
                .context("Nix did not return build results")?;
            ensure!(
                built.len() == 1,
                "The Nix check returned an invalid build result"
            );
            ensure!(
                field(&built[0], "drvPath")? == drv_path,
                "The Nix build changed its derivation"
            );
            let outputs: BTreeMap<String, String> = serde_json::from_value(
                built[0]
                    .get("outputs")
                    .cloned()
                    .context("The Nix check has no outputs")?,
            )?;
            ensure!(!outputs.is_empty(), "The Nix check has no outputs");
            results.push(CheckResult {
                check: check.clone(),
                drv_path,
                outputs,
            });
        }
        Ok(Verification {
            schema_version: 1,
            candidates: candidates.to_vec(),
            merge: merge.map(str::to_owned),
            main,
            source,
            definitions,
            inputs,
            results,
        })
    }
}

fn checked_derivation(report: &Value) -> Result<String> {
    let derivations = report
        .get("derivations")
        .unwrap_or(report)
        .as_object()
        .context("Nix did not return derivations")?;
    ensure!(
        derivations.len() == 1,
        "Each Nix check must return one derivation"
    );
    let (name, derivation) = derivations
        .iter()
        .next()
        .context("The Nix check is empty")?;
    let path = if name.starts_with("/nix/store/") {
        name.clone()
    } else {
        format!("/nix/store/{name}")
    };
    ensure!(
        Path::new(&path).parent() == Some(Path::new("/nix/store")) && path.ends_with(".drv"),
        "Nix returned an invalid derivation path"
    );
    check_isolation(derivation)?;
    Ok(path)
}

fn check_isolation(derivation: &Value) -> Result<()> {
    let environment = derivation
        .get("env")
        .and_then(Value::as_object)
        .context("The Nix derivation has no environment")?;
    for name in ["__noChroot", "__darwinAllowLocalNetworking", "__impure"] {
        ensure!(
            environment
                .get(name)
                .is_none_or(|value| matches!(value.as_str(), Some("" | "0" | "false"))),
            "The trusted Nix check requests a sandbox exception: {name}"
        );
    }
    ensure!(
        environment
            .get("impureEnvVars")
            .is_none_or(|value| value.as_str() == Some("")),
        "The trusted Nix check requests an impure environment"
    );
    ensure!(
        environment
            .get("requiredSystemFeatures")
            .and_then(Value::as_str)
            .is_none_or(|value| !value
                .split_whitespace()
                .any(|feature| matches!(feature, "recursive-nix" | "impure-derivations"))),
        "The trusted Nix check requests an impure build feature"
    );
    Ok(())
}

fn nix_string(value: &str) -> Result<String> {
    ensure!(
        !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t')),
        "Invalid control character in a Nix argument"
    );
    Ok(serde_json::to_string(value)?.replace("${", "\\${"))
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("Nix result has no {name}"))
}

fn system() -> Result<String> {
    let os = match env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => bail!("Nix verification does not support {other}"),
    };
    ensure!(
        matches!(env::consts::ARCH, "aarch64" | "x86_64"),
        "Unsupported Nix verification architecture"
    );
    Ok(format!("{}-{os}", env::consts::ARCH))
}

struct Runner<'a> {
    nix: PathBuf,
    home: TempDir,
    deadline: Instant,
    interrupted: &'a AtomicBool,
}

impl<'a> Runner<'a> {
    fn new(timeout: Duration, interrupted: &'a AtomicBool) -> Result<Self> {
        ensure!(!timeout.is_zero(), "The Nix check timeout must be positive");
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("The Nix check timeout is too large")?;
        let nix = env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("nix"))
            .find(|path| {
                fs::metadata(path).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
            .ok_or_else(|| anyhow!("Nix is not on PATH. Install the patchgate Nix runtime."))?;
        let nix = fs::canonicalize(nix)?;
        let home = tempfile::Builder::new()
            .prefix("patchgate-nix-")
            .tempdir()?;
        fs::create_dir(home.path().join("tmp"))?;
        Ok(Self {
            nix,
            home,
            deadline,
            interrupted,
        })
    }

    fn command(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("TMPDIR", self.home.path().join("tmp"))
            .env("PATH", "")
            .env("NIX_PATH", "")
            .env("NIX_USER_CONF_FILES", "")
            .current_dir(self.home.path())
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
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
            ]);
        if let Some(user) = env::var_os("USER") {
            command.env("USER", user);
        }
        command
    }

    fn execute(&self, command: &mut Command) -> Result<String> {
        ensure!(
            Instant::now() < self.deadline,
            "Trusted Nix verification timed out"
        );
        ensure!(
            !self.interrupted.load(Ordering::Relaxed),
            "Trusted Nix verification interrupted"
        );
        let mut stdout = tempfile::tempfile_in(self.home.path())?;
        command.stdout(Stdio::from(stdout.try_clone()?));
        let mut child = command
            .spawn()
            .context("Cannot execute trusted Nix verification")?;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None)
                    if !self.interrupted.load(Ordering::Relaxed)
                        && Instant::now() < self.deadline =>
                {
                    thread::sleep(Duration::from_millis(40))
                }
                result => {
                    // Stop the client and its child processes before source cleanup.
                    unsafe {
                        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
                    }
                    let _ = child.wait();
                    if let Err(error) = result {
                        return Err(error.into());
                    }
                    ensure!(
                        !self.interrupted.load(Ordering::Relaxed),
                        "Trusted Nix verification interrupted"
                    );
                    bail!("Trusted Nix verification timed out");
                }
            }
        };
        ensure!(
            !self.interrupted.load(Ordering::Relaxed),
            "Trusted Nix verification interrupted"
        );
        ensure!(
            status.success(),
            "Trusted Nix verification failed with {status}. See the Nix output."
        );
        stdout.rewind()?;
        let mut text = String::new();
        stdout.read_to_string(&mut text)?;
        Ok(text)
    }

    fn json(&self, arguments: &[&str]) -> Result<Value> {
        let mut command = self.command(&self.nix);
        command.args(arguments);
        serde_json::from_str(&self.execute(&mut command)?).context("Nix returned invalid JSON")
    }

    fn evaluate(&self, arguments: &[&str]) -> Result<Value> {
        let mut command = self.command(&self.nix);
        command
            .args([
                "--option",
                "pure-eval",
                "true",
                "--option",
                "restrict-eval",
                "true",
                "--option",
                "allowed-uris",
                "path:/nix/store/",
                "--option",
                "allow-import-from-derivation",
                "false",
            ])
            .args(arguments);
        serde_json::from_str(&self.execute(&mut command)?)
            .context("Nix returned invalid verification JSON")
    }

    fn require_sandbox(&self) -> Result<()> {
        let config = self.json(&["config", "show", "--json"])?;
        ensure!(
            config
                .get("sandbox")
                .and_then(|entry| entry.get("value"))
                .is_some_and(
                    |value| value == true || matches!(value.as_str(), Some("true" | "relaxed"))
                ),
            "Trusted Nix verification needs an enabled Nix sandbox"
        );
        Ok(())
    }

    fn add_tree(&self, path: &Path) -> Result<StoreTree> {
        let mut command = self.command(&self.nix);
        command
            .args(["store", "add-path", "--name", "source"])
            .arg(path);
        let path = self.execute(&mut command)?;
        self.tree(path.trim())
    }

    fn tree(&self, path: &str) -> Result<StoreTree> {
        ensure!(
            path.starts_with("/nix/store/"),
            "Nix returned an invalid store path"
        );
        let mut root = self.command(&self.nix.with_file_name("nix-store"));
        let name = self.home.path().join(format!(
            "root-{}",
            path.rsplit('/').next().context("Invalid store path")?
        ));
        root.args(["--realise", "--add-root"])
            .arg(name)
            .args(["--indirect", path]);
        self.execute(&mut root)?;
        let info = self.json(&["path-info", "--json", path])?;
        let info = info
            .get(path)
            .or_else(|| info.as_array().and_then(|entries| entries.first()))
            .context("Nix returned no store metadata")?;
        let nar_hash = field(info, "narHash")?.to_owned();
        ensure!(valid_hash(&nar_hash), "Nix returned an invalid NAR hash");
        Ok(StoreTree {
            path: path.to_owned(),
            nar_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn invalid_check_requirements_cannot_disable_verification() {
        for manifest in [
            json!({"schema_version": 2, "checks": ["build.nix"]}),
            json!({"schema_version": 1, "checks": []}),
            json!({"schema_version": 1, "checks": ["../build.nix"]}),
            json!({"schema_version": 1, "checks": ["/build.nix"]}),
            json!({"schema_version": 1, "checks": ["build.nix", "build.nix"]}),
            json!({"schema_version": 1, "checks": ["build.nix"], "disabled": true}),
        ] {
            assert!(Manifest::parse(&manifest.to_string()).is_err());
        }
    }

    #[test]
    fn sandbox_exceptions_cannot_authorize_candidate_execution() {
        for environment in [
            json!({"__noChroot": "1"}),
            json!({"__darwinAllowLocalNetworking": "1"}),
            json!({"__impure": "1"}),
            json!({"impureEnvVars": "MODEL_TOKEN"}),
            json!({"requiredSystemFeatures": "recursive-nix"}),
        ] {
            assert!(check_isolation(&json!({"env": environment})).is_err());
        }
    }

    #[test]
    fn versioned_derivations_keep_the_isolation_and_identity_boundary() -> Result<()> {
        let name = "00000000000000000000000000000000-check.drv";
        let report = json!({"version": 4, "derivations": {
            name: {"env": {"__noChroot": "1"}}
        }});
        assert!(checked_derivation(&report).is_err());
        let report = json!({"version": 4, "derivations": {
            name: {"env": {}}
        }});
        assert_eq!(checked_derivation(&report)?, format!("/nix/store/{name}"));
        assert!(
            checked_derivation(&json!({"version": 4, "derivations": {
                name: {"env": {}}, "another.drv": {"env": {}}
            }}))
            .is_err()
        );
        Ok(())
    }
}
