use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Seek, Write};
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
use sha2::{Digest, Sha256};
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
        // Pure imports can copy a tree. Retain its registered runtime references.
        let path = nix_string(&self.path)?;
        Ok(format!(
            "(builtins.appendContext (builtins.fetchTree {{ type = \"path\"; path = {path}; narHash = {}; }}).outPath {{ {path} = {{ path = true; }}; }})",
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
struct IsolationEvidence {
    schema_version: u32,
    nonce: String,
    shell: String,
    drv_path: String,
    output: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    isolation: Option<IsolationEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nix_version: Option<String>,
}

impl Verification {
    pub fn observed_nix_version(&self) -> Option<&str> {
        self.nix_version.as_deref()
    }
}

const CACHE_SCHEMA: u32 = 1;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedResults {
    schema_version: u32,
    source: StoreTree,
    definitions: StoreTree,
    inputs: BTreeMap<String, StoreTree>,
    results: Vec<CheckResult>,
    nix_version: String,
}

#[allow(clippy::too_many_arguments)]
fn cached_key(
    candidates: &[String],
    merge: Option<&str>,
    main: &MainBinding,
    source: &StoreTree,
    definitions: &StoreTree,
    inputs: &BTreeMap<String, StoreTree>,
    checks: &[String],
    nix_version: &str,
) -> Result<String> {
    let hashes: BTreeMap<_, _> = inputs
        .iter()
        .map(|(name, tree)| (name, tree.nar_hash.as_str()))
        .collect();
    let key = serde_json::json!({
        "schema_version": CACHE_SCHEMA,
        "candidates": candidates,
        "merge": merge,
        "main": main,
        "source": source.nar_hash,
        "definitions": definitions.nar_hash,
        "inputs": hashes,
        "checks": checks,
        "nix_version": nix_version,
    });
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&key)?)))
}

fn store_path(path: &str) -> bool {
    path.starts_with("/nix/store/") && !path.chars().any(char::is_control) && !path.contains('\0')
}

/// Read a cached result only when its exact tree, input, check, and Nix binding holds.
fn read_cache(
    directory: &Path,
    key: &str,
    manifest: &Manifest,
    source: &StoreTree,
    definitions: &StoreTree,
    inputs: &BTreeMap<String, StoreTree>,
    nix_version: &str,
) -> Option<Vec<CheckResult>> {
    let bytes = fs::read(directory.join(format!("{key}.json"))).ok()?;
    let cached: CachedResults = serde_json::from_slice(&bytes).ok()?;
    let matches = cached.schema_version == CACHE_SCHEMA
        && cached.source.nar_hash == source.nar_hash
        && cached.definitions.nar_hash == definitions.nar_hash
        && cached.nix_version == nix_version
        && cached.inputs.len() == inputs.len()
        && inputs.iter().all(|(name, tree)| {
            cached
                .inputs
                .get(name)
                .is_some_and(|cached| cached.nar_hash == tree.nar_hash)
        })
        && cached.results.len() == manifest.checks.len()
        && cached
            .results
            .iter()
            .map(|result| result.check.as_str())
            .eq(manifest.checks.iter().map(String::as_str))
        && cached.results.iter().all(|result| {
            store_path(&result.drv_path) && result.outputs.values().all(|path| store_path(path))
        });
    matches.then_some(cached.results)
}

fn write_cache(
    directory: &Path,
    key: &str,
    source: &StoreTree,
    definitions: &StoreTree,
    inputs: &BTreeMap<String, StoreTree>,
    results: &[CheckResult],
    nix_version: &str,
) -> Result<()> {
    fs::create_dir_all(directory)?;
    let value = CachedResults {
        schema_version: CACHE_SCHEMA,
        source: source.clone(),
        definitions: definitions.clone(),
        inputs: inputs.clone(),
        results: results.to_vec(),
        nix_version: nix_version.into(),
    };
    let mut temporary = tempfile::Builder::new()
        .prefix(".tmp")
        .tempfile_in(directory)?;
    serde_json::to_writer(&mut temporary, &value)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(directory.join(format!("{key}.json")))
        .map_err(|error| error.error)?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
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

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        source: &Path,
        candidates: &[String],
        merge: Option<&str>,
        main: MainBinding,
        timeout: Duration,
        interrupted: &AtomicBool,
        cache: Option<&Path>,
    ) -> Result<Verification> {
        let mut runner = Runner::new(timeout, interrupted)?;
        self.run_with_runner(source, candidates, merge, main, &mut runner, cache)
    }

    fn run_with_runner(
        &self,
        source: &Path,
        candidates: &[String],
        merge: Option<&str>,
        main: MainBinding,
        runner: &mut Runner<'_>,
        cache: Option<&Path>,
    ) -> Result<Verification> {
        let isolation = runner.probe_runtime_isolation()?;
        let nix_version = runner.version()?;
        let definitions = runner.add_tree(&self.directory.path().join("main").join(DIRECTORY))?;
        let source_tree = runner.add_tree(source)?;
        let mut inputs = BTreeMap::new();
        for (name, input) in &self.manifest.inputs {
            let tree = if let Some(path) = input.url.strip_prefix("path:") {
                runner.tree(path)?
            } else {
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
                ensure!(
                    field(&value, "hash")? == input.nar_hash,
                    "NAR hash differs for Nix input {name}"
                );
                runner.tree(field(&value, "storePath")?)?
            };
            ensure!(
                tree.nar_hash == input.nar_hash,
                "NAR hash differs for Nix input {name}"
            );
            inputs.insert(name.clone(), tree);
        }
        let key = cached_key(
            candidates,
            merge,
            &main,
            &source_tree,
            &definitions,
            &inputs,
            &self.manifest.checks,
            &nix_version,
        )?;
        if let Some(cache) = cache {
            if let Some(results) = read_cache(
                cache,
                &key,
                &self.manifest,
                &source_tree,
                &definitions,
                &inputs,
                &nix_version,
            ) {
                eprintln!("patchgate: trusted Nix checks reuse an exact recorded result.");
                runner.ensure_active()?;
                return Ok(Verification {
                    schema_version: 1,
                    candidates: candidates.to_vec(),
                    merge: merge.map(str::to_owned),
                    main,
                    source: source_tree,
                    definitions,
                    inputs,
                    results,
                    isolation: Some(isolation),
                    nix_version: Some(nix_version),
                });
            }
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
                source_tree.expression()?,
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
        runner.ensure_active()?;
        if let Some(cache) = cache {
            if let Err(error) = write_cache(
                cache,
                &key,
                &source_tree,
                &definitions,
                &inputs,
                &results,
                &nix_version,
            ) {
                eprintln!("patchgate: the verification cache did not record this result: {error}");
            }
        }
        Ok(Verification {
            schema_version: 1,
            candidates: candidates.to_vec(),
            merge: merge.map(str::to_owned),
            main,
            source: source_tree,
            definitions,
            inputs,
            results,
            isolation: Some(isolation),
            nix_version: Some(nix_version),
        })
    }
}

/// Test the configured runtime with fixed private data, not repository inputs.
pub fn probe_runtime_isolation(timeout: Duration, interrupted: &AtomicBool) -> Result<()> {
    Runner::new(timeout, interrupted)?
        .probe_runtime_isolation()
        .map(|_| ())
}

/// Select a world-readable directory that the sandbox hides from builds.
///
/// The macOS sandbox permits reads of `/private/tmp`, so a marker there stays
/// visible and cannot prove isolation. It denies `/private/var`, which holds
/// the world-readable `/private/var/tmp`. The Linux sandbox mounts a private
/// `/tmp`, so the host `/tmp` stays hidden.
fn probe_marker_root() -> Result<PathBuf> {
    let root = if cfg!(target_os = "macos") {
        Path::new("/private/var/tmp")
    } else {
        Path::new("/tmp")
    };
    ensure!(
        root.is_dir(),
        "The isolation probe needs a world-readable host directory that the sandbox hides"
    );
    Ok(root.to_path_buf())
}

fn runtime_isolation_probe(runner: &Runner<'_>) -> Result<IsolationEvidence> {
    runner.require_sandbox()?;
    let builder = runner.probe_shell()?;
    let builder_tree = runner.tree(
        builder
            .parent()
            .and_then(Path::parent)
            .and_then(Path::to_str)
            .context("The probe shell has no store root")?,
    )?;
    let shell_name = builder
        .file_name()
        .and_then(|name| name.to_str())
        .context("The probe shell name is not UTF-8")?;
    let mut random = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut nonce = String::with_capacity(64);
    for byte in random {
        write!(&mut nonce, "{byte:02x}")?;
    }
    let host = tempfile::Builder::new()
        .prefix("pg-host-probe-")
        .tempdir_in(probe_marker_root()?)?;
    // The build user can read this harmless marker outside the sandbox.
    fs::set_permissions(host.path(), fs::Permissions::from_mode(0o755))?;
    let marker = fs::canonicalize(host.path())?.join("host-marker");
    fs::write(&marker, b"patchgate harmless host marker\n")?;
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o644))?;
    let expected = format!("patchgate-doctor-isolated:{nonce}\n");
    let marker = marker
        .to_str()
        .context("The probe marker path is not UTF-8")?;
    // Shell builtins need no host programs. A visible marker or variable must fail.
    let script = format!(
        "if {{ IFS= read -r markerData < \"$hostMarker\"; }} 2>/dev/null; then exit 71; fi\n\
         if [ \"${{PATCHGATE_DOCTOR_PRIVATE+x}}\" = x ]; then exit 72; fi\n\
         printf '%s\\n' 'patchgate-doctor-isolated:{nonce}' > \"$out\"\n"
    );
    let expression = format!(
        "builtins.derivation {{ name = \"patchgate-doctor-isolation\"; system = {}; \
         builder = ({} + {}); args = [ \"-e\" \"-c\" {} ]; \
         hostMarker = {}; probeNonce = {}; preferLocalBuild = true; allowSubstitutes = false; }}",
        nix_string(&system()?)?,
        builder_tree.expression()?,
        nix_string(&format!("/bin/{shell_name}"))?,
        nix_string(&script)?,
        nix_string(marker)?,
        nix_string(&nonce)?,
    );
    let derivations = runner.evaluate(&["derivation", "show", "--expr", &expression])?;
    let drv_path = checked_derivation(&derivations)?;
    let built = runner.evaluate(&["build", "--no-link", "--json", "--expr", &expression])?;
    let output = probe_output(&built, &drv_path)?;
    ensure!(
        fs::symlink_metadata(output)?.file_type().is_file(),
        "The isolation probe output is not a regular file"
    );
    ensure!(
        fs::metadata(output)?.len() == expected.len() as u64,
        "The isolation probe output has an unexpected size"
    );
    ensure!(
        fs::read(output)? == expected.as_bytes(),
        "The isolation probe output bytes differ"
    );
    runner.ensure_active()?;
    Ok(IsolationEvidence {
        schema_version: 1,
        nonce,
        shell: builder
            .to_str()
            .context("The probe shell path is not UTF-8")?
            .to_owned(),
        drv_path,
        output: output.to_owned(),
    })
}

fn probe_output<'a>(built: &'a Value, drv_path: &str) -> Result<&'a str> {
    let results = built
        .as_array()
        .context("The isolation probe has no build results")?;
    ensure!(
        results.len() == 1,
        "The isolation probe needs one build result"
    );
    ensure!(
        field(&results[0], "drvPath")? == drv_path,
        "The isolation probe derivation changed"
    );
    let outputs = results[0]
        .get("outputs")
        .and_then(Value::as_object)
        .context("The isolation probe has no outputs")?;
    ensure!(outputs.len() == 1, "The isolation probe needs one output");
    let output = outputs
        .get("out")
        .and_then(Value::as_str)
        .context("The isolation probe has no out path")?;
    ensure!(
        Path::new(output).parent() == Some(Path::new("/nix/store"))
            && Path::new(output).file_name().is_some()
            && !output.ends_with(".drv"),
        "The isolation probe returned an invalid output path"
    );
    Ok(output)
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
    runtime_probe: bool,
}

impl<'a> Runner<'a> {
    fn new(timeout: Duration, interrupted: &'a AtomicBool) -> Result<Self> {
        ensure!(!timeout.is_zero(), "The Nix check timeout must be positive");
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("The Nix check timeout is too large")?;
        let nix = env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .filter(|directory| directory.is_absolute())
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
            runtime_probe: false,
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
                "--option",
                "sandbox",
                "true",
                "--option",
                "sandbox-fallback",
                "false",
            ]);
        if let Some(user) = env::var_os("USER") {
            command.env("USER", user);
        }
        if self.runtime_probe {
            command.stderr(Stdio::null()).args([
                "--option",
                "substitute",
                "false",
                "--option",
                "substituters",
                "",
                "--option",
                "fallback",
                "false",
                "--option",
                "max-jobs",
                "1",
            ]);
        }
        command
    }

    fn probe_shell(&self) -> Result<PathBuf> {
        let shell_at = |root: &Path| {
            ["bash", "sh"]
                .into_iter()
                .map(|name| root.join("bin").join(name))
                .find(|path| {
                    fs::metadata(path).is_ok_and(|metadata| {
                        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                    })
                })
        };
        for directory in env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .filter(|directory| directory.is_absolute())
        {
            for name in ["bash", "sh"] {
                let Ok(path) = fs::canonicalize(directory.join(name)) else {
                    continue;
                };
                if let Some(root) = path.parent().and_then(Path::parent) {
                    if root.parent() == Some(Path::new("/nix/store")) {
                        if let Some(shell) = shell_at(root) {
                            return Ok(shell);
                        }
                    }
                }
            }
        }
        // The Nix closure can supply a shell when the caller PATH does not.
        let root: PathBuf = self.nix.components().take(4).collect();
        ensure!(
            root.parent() == Some(Path::new("/nix/store")),
            "The runtime probe needs an existing Nix-store shell"
        );
        let mut command = self.command(&self.nix.with_file_name("nix-store"));
        command.args(["--query", "--requisites"]).arg(root);
        for root in self.execute(&mut command)?.lines().map(Path::new) {
            if root.parent() == Some(Path::new("/nix/store")) {
                if let Some(shell) = shell_at(root) {
                    return Ok(shell);
                }
            }
        }
        bail!("The runtime probe needs an existing Nix-store shell")
    }

    fn probe_runtime_isolation(&mut self) -> Result<IsolationEvidence> {
        self.runtime_probe = true;
        let result = runtime_isolation_probe(self);
        self.runtime_probe = false;
        result
    }

    fn version(&self) -> Result<String> {
        let mut command = self.command(&self.nix);
        command.arg("--version");
        let version = self.execute(&mut command)?.trim().to_owned();
        ensure!(!version.is_empty(), "Nix returned no executable version");
        Ok(version)
    }

    fn ensure_active(&self) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "Trusted Nix verification timed out"
        );
        ensure!(
            !self.interrupted.load(Ordering::Relaxed),
            "Trusted Nix verification interrupted"
        );
        Ok(())
    }

    fn execute(&self, command: &mut Command) -> Result<String> {
        self.ensure_active()?;
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
        self.ensure_active()?;
        ensure!(
            status.success(),
            "Trusted Nix verification failed with {status}. See the Nix output."
        );
        stdout.rewind()?;
        if self.runtime_probe {
            ensure!(
                stdout.metadata()?.len() <= 2 * 1024 * 1024,
                "The runtime probe output exceeds its limit"
            );
        }
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
        if self.runtime_probe {
            command.env("PATCHGATE_DOCTOR_PRIVATE", "private harmless client data");
        }
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

    fn fixture_runner<'a>(script: &str, interrupted: &'a AtomicBool) -> Result<Runner<'a>> {
        let home = tempfile::tempdir()?;
        let nix = home.path().join("nix");
        fs::write(&nix, format!("#!/bin/sh\n{script}\n"))?;
        fs::set_permissions(&nix, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(home.path().join("tmp"))?;
        Ok(Runner {
            nix,
            home,
            deadline: Instant::now() + Duration::from_secs(10),
            interrupted,
            runtime_probe: false,
        })
    }

    fn legacy_verification() -> Value {
        json!({
            "schema_version": 1,
            "candidates": ["candidate"],
            "merge": null,
            "main": {"channel": "main", "state": null},
            "source": {"path": "/nix/store/source", "nar_hash": "source-hash"},
            "definitions": {"path": "/nix/store/checks", "nar_hash": "checks-hash"},
            "inputs": {},
            "results": []
        })
    }

    #[test]
    fn failed_fresh_probes_prevent_candidate_execution() -> Result<()> {
        let interrupted = AtomicBool::new(false);
        let mut runner = fixture_runner(
            "for argument in \"$@\"; do\n\
             if [ \"$argument\" = config ]; then\n\
             printf 'probe\\n' >> \"$HOME/probe-attempts\"\n\
             printf '%s\\n' '{\"sandbox\":{\"value\":false}}'\n\
             exit 0\n\
             fi\n\
             done\n\
             printf 'candidate\\n' > \"$HOME/candidate-executed\"\n\
             exit 1",
            &interrupted,
        )?;
        let directory = tempfile::tempdir()?;
        let plan = Plan {
            manifest: Manifest::parse(r#"{"schema_version":1,"checks":["build.nix"]}"#)?,
            directory,
        };
        for _ in 0..2 {
            assert!(
                plan.run_with_runner(
                    Path::new("/candidate-must-not-execute"),
                    &["candidate".into()],
                    None,
                    MainBinding {
                        channel: "main".into(),
                        state: None,
                    },
                    &mut runner,
                    None,
                )
                .is_err()
            );
        }
        assert_eq!(
            fs::read_to_string(runner.home.path().join("probe-attempts"))?
                .lines()
                .count(),
            2
        );
        assert!(!runner.home.path().join("candidate-executed").exists());
        Ok(())
    }

    #[test]
    fn expired_operation_refuses_the_probe_and_later_steps() -> Result<()> {
        let interrupted = AtomicBool::new(false);
        let mut runner = fixture_runner("printf 'executed\\n' > \"$HOME/executed\"", &interrupted)?;
        runner.deadline = Instant::now();
        assert!(runner.probe_runtime_isolation().is_err());
        assert!(runner.version().is_err());
        assert!(!runner.home.path().join("executed").exists());
        Ok(())
    }

    #[test]
    fn legacy_audit_data_does_not_invent_runtime_evidence() -> Result<()> {
        let legacy = legacy_verification();
        let verification: Verification = serde_json::from_value(legacy.clone())?;
        assert!(verification.isolation.is_none());
        assert_eq!(verification.observed_nix_version(), None);
        assert_eq!(serde_json::to_value(verification)?, legacy);
        Ok(())
    }

    #[test]
    fn isolation_marker_stays_outside_sandbox_visible_temp_roots() -> Result<()> {
        let root = probe_marker_root()?;
        assert!(root.is_dir());
        if cfg!(target_os = "macos") {
            // The macOS sandbox permits reads of /private/tmp and /tmp.
            assert_eq!(root, Path::new("/private/var/tmp"));
        }
        Ok(())
    }

    #[test]
    fn isolation_probe_requires_the_exact_derivation_and_one_store_output() -> Result<()> {
        let drv = "/nix/store/probe.drv";
        let valid = json!([{"drvPath": drv, "outputs": {"out": "/nix/store/probe"}}]);
        assert_eq!(probe_output(&valid, drv)?, "/nix/store/probe");
        for invalid in [
            json!([]),
            json!([{"drvPath": "/nix/store/other.drv", "outputs": {"out": "/nix/store/probe"}}]),
            json!([{"drvPath": drv, "outputs": {"out": "/tmp/probe"}}]),
            json!([{"drvPath": drv, "outputs": {"out": "/nix/store/.."}}]),
            json!([{"drvPath": drv, "outputs": {"out": "/nix/store/probe.drv"}}]),
            json!([{"drvPath": drv, "outputs": {"out": "/nix/store/probe", "extra": "/nix/store/extra"}}]),
        ] {
            assert!(probe_output(&invalid, drv).is_err());
        }
        Ok(())
    }

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
