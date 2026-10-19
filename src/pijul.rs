use std::collections::{BTreeMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;
use serde::{Deserialize, Deserializer};
use tempfile::TempDir;

pub type CommandEnv = BTreeMap<OsString, OsString>;

#[derive(Deserialize)]
pub struct LogEntry {
    pub hash: String,
    #[serde(default, deserialize_with = "null_default")]
    pub message: String,
    #[serde(default, deserialize_with = "null_default")]
    pub paths: Vec<String>,
}

fn null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

pub struct Pijul {
    pub repo: PathBuf,
}

impl Pijul {
    pub fn new(repo: PathBuf) -> Self {
        Self { repo }
    }

    pub fn call<I, S>(&self, args: I) -> Result<(String, String)>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.call_inner(args, None)
    }

    pub fn call_with_env<I, S>(&self, args: I, env: &CommandEnv) -> Result<(String, String)>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.call_inner(args, Some(env))
    }

    fn call_inner<I, S>(&self, args: I, env: Option<&CommandEnv>) -> Result<(String, String)>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new("pijul");
        command
            .args(args)
            .current_dir(&self.repo)
            .stdin(Stdio::null());
        if let Some(env) = env {
            command.env_clear().envs(env);
        }
        command.env("NO_COLOR", "1");
        let output = command.output().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow!("pijul is not on PATH. Run patchgate in the devenv shell.")
            } else {
                anyhow!(error).context(format!("Cannot execute {}", command_name(&command, None)))
            }
        })?;
        let (stdout, stderr) = text_output(output, &command)?;
        Ok((stdout, stderr))
    }

    pub fn run<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Ok(self.call(args)?.0)
    }

    pub fn log(&self, channel: &str) -> Result<Vec<LogEntry>> {
        let output = self.run([
            "log",
            "--channel",
            channel,
            "--output-format",
            "json",
            "--files",
        ])?;
        let mut entries: Vec<LogEntry> =
            serde_json::from_str(&output).context("pijul log gave output that is not JSON")?;
        entries.reverse();
        Ok(entries)
    }

    pub fn hashes(&self, channel: &str) -> Result<HashSet<String>> {
        Ok(self
            .run(["log", "--channel", channel, "--hash-only"])?
            .split_whitespace()
            .map(str::to_owned)
            .collect())
    }

    pub fn change(&self, hash: &str) -> Result<String> {
        self.run(["change", hash])
    }

    pub fn change_file(&self, hash: &str) -> PathBuf {
        let split = hash
            .char_indices()
            .nth(2)
            .map_or(hash.len(), |(index, _)| index);
        self.repo
            .join(".pijul")
            .join("changes")
            .join(&hash[..split])
            .join(format!("{}.change", &hash[split..]))
    }

    pub fn apply(&self, hash: &str, channel: &str) -> Result<()> {
        self.run(["apply", "--channel", channel, hash])?;
        Ok(())
    }

    pub fn channels(&self) -> Result<(Option<String>, Vec<String>)> {
        let mut current = None;
        let mut names = Vec::new();
        for line in self.run(["channel"])?.lines() {
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
        Ok((current, names))
    }

    pub fn read_file(&self, channel: &str, path: &str) -> Result<Option<String>> {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("channel.tar.gz");
        self.run([
            OsStr::new("archive"),
            OsStr::new("--channel"),
            OsStr::new(channel),
            OsStr::new("-o"),
            archive.as_os_str(),
        ])?;
        let mut target = PathBuf::from(path);
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(target.clone()) {
                bail!("Archive link cycle at {}", target.display());
            }
            match archive_member(&archive, &target)? {
                Some(ArchiveMember::File(bytes)) => {
                    return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
                }
                Some(ArchiveMember::Link(link)) => target = link,
                Some(ArchiveMember::Other) | None => return Ok(None),
            }
        }
    }

    pub fn conflicts(&self) -> Result<Vec<crate::change::Conflict>> {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("channel.tar.gz");
        let (_, stderr) =
            self.call([OsStr::new("archive"), OsStr::new("-o"), archive.as_os_str()])?;
        Ok(crate::change::conflict_report(&stderr))
    }
}

enum ArchiveMember {
    File(Vec<u8>),
    Link(PathBuf),
    Other,
}

fn archive_member(archive: &Path, target: &Path) -> Result<Option<ArchiveMember>> {
    let file = File::open(archive)?;
    let mut tar = tar::Archive::new(GzDecoder::new(file));
    let mut member = None;
    for entry in tar.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() != target {
            continue;
        }
        let kind = entry.header().entry_type();
        member = Some(if kind.is_file() || kind.is_gnu_sparse() {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            ArchiveMember::File(bytes)
        } else if kind.is_symlink() || kind.is_hard_link() {
            let link = entry.link_name()?.context("Archive link has no target")?;
            let link = if kind.is_symlink() {
                normalize_path(&target.parent().unwrap_or(Path::new("")).join(link.as_ref()))
            } else {
                link.into_owned()
            };
            ArchiveMember::Link(link)
        } else {
            ArchiveMember::Other
        });
    }
    Ok(member)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if result
                    .file_name()
                    .is_some_and(|name| name != OsStr::new(".."))
                {
                    result.pop();
                } else if !result.has_root() {
                    result.push("..");
                }
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

pub struct Signer {
    key: PathBuf,
    home: PathBuf,
}

pub struct AgentEnv {
    pub vars: CommandEnv,
    agent: Child,
    _directory: TempDir,
}

impl Drop for AgentEnv {
    fn drop(&mut self) {
        let _ = self.agent.kill();
        let _ = self.agent.wait();
    }
}

impl Signer {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            key: directory.join("key"),
            home: directory.join("home"),
        }
    }

    pub fn environment(&self) -> Result<AgentEnv> {
        fs::create_dir_all(
            self.key
                .parent()
                .context("Gate key has no parent directory")?,
        )?;
        if !self.key.exists() {
            let mut keygen = Command::new("ssh-keygen");
            keygen
                .args(["-q", "-t", "ed25519", "-N", "", "-C", "patchgate", "-f"])
                .arg(&self.key);
            tool(&mut keygen)?;
        }
        let directory = tempfile::Builder::new().prefix("patchgate-").tempdir()?;
        let socket = directory.path().join("agent");
        let agent = Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    anyhow!("ssh-agent is not on PATH. patchgate needs OpenSSH to sign its merges.")
                } else {
                    anyhow!(error).context("Cannot execute ssh-agent")
                }
            })?;
        let mut vars: CommandEnv = std::env::vars_os().collect();
        vars.insert(OsString::from("HOME"), self.home.as_os_str().to_owned());
        vars.insert(
            OsString::from("SSH_AUTH_SOCK"),
            socket.as_os_str().to_owned(),
        );
        vars.remove(OsStr::new("XDG_CONFIG_HOME"));
        let mut environment = AgentEnv {
            vars,
            agent,
            _directory: directory,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            if environment.agent.try_wait()?.is_some() || Instant::now() > deadline {
                bail!("ssh-agent did not start.");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let mut add = Command::new("ssh-add");
        add.arg("-q")
            .arg(&self.key)
            .env_clear()
            .envs(&environment.vars);
        tool(&mut add)?;
        Ok(environment)
    }
}

fn tool(command: &mut Command) -> Result<String> {
    command.stdin(Stdio::null());
    let output = command.output().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow!(
                "{} is not on PATH.",
                command.get_program().to_string_lossy()
            )
        } else {
            anyhow!(error).context(format!("Cannot execute {}", command_name(command, Some(1))))
        }
    })?;
    Ok(text_output(output, command)?.0)
}

fn command_name(command: &Command, limit: Option<usize>) -> String {
    let mut name = command.get_program().to_string_lossy().into_owned();
    for arg in command.get_args().take(limit.unwrap_or(usize::MAX)) {
        name.push(' ');
        name.push_str(&arg.to_string_lossy());
    }
    name
}

fn text_output(output: Output, command: &Command) -> Result<(String, String)> {
    let stdout = text_stream(output.stdout)?;
    let stderr = text_stream(output.stderr)?;
    if !output.status.success() {
        let detail = if stderr.is_empty() { &stdout } else { &stderr };
        let limit = (command.get_program() != OsStr::new("pijul")).then_some(1);
        bail!("{} failed: {}", command_name(command, limit), detail.trim());
    }
    Ok((stdout, stderr))
}

fn text_stream(bytes: Vec<u8>) -> Result<String> {
    let text = String::from_utf8(bytes).context("Command output is not UTF-8")?;
    if text.contains('\r') {
        Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        Ok(text)
    }
}
