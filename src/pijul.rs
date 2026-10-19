use std::collections::{BTreeMap, BTreeSet, HashSet};
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

    pub fn touched_paths(
        &self,
        channel: &str,
        log_paths: &[String],
        text: &str,
    ) -> Result<BTreeSet<String>> {
        let mut paths = crate::change::touched_paths(log_paths, text);
        let targets = crate::change::rename_targets(text);
        if !targets.is_empty() {
            let directory = tempfile::tempdir()?;
            let archive = directory.path().join("channel.tar.gz");
            self.run([
                OsStr::new("archive"),
                OsStr::new("--channel"),
                OsStr::new(channel),
                OsStr::new("-o"),
                archive.as_os_str(),
            ])?;
            let mut tar = tar::Archive::new(GzDecoder::new(File::open(archive)?));
            let mut members = Vec::new();
            for entry in tar.entries()? {
                let entry = entry?;
                members.push(normalize_path(&entry.path()?)?);
            }
            for target in targets {
                let target = Path::new(&target);
                let matches: Vec<_> = members
                    .iter()
                    .filter(|path| path.ends_with(target))
                    .collect();
                if matches.is_empty() {
                    bail!("Cannot resolve the rename target {}", target.display());
                }
                for path in &members {
                    if matches.iter().any(|prefix| path.starts_with(prefix)) {
                        paths.insert(
                            path.to_str()
                                .context("Archive path is not UTF-8")?
                                .to_owned(),
                        );
                    }
                }
            }
        }
        Ok(paths
            .into_iter()
            .map(|path| {
                Path::new(&path)
                    .components()
                    .collect::<PathBuf>()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect())
    }

    pub fn check_paths(&self, paths: &BTreeSet<String>) -> Result<()> {
        for path in paths {
            let name = Path::new(path);
            if name
                .components()
                .next()
                .is_some_and(|part| part.as_os_str() == ".pijul")
            {
                bail!("A change cannot write repository metadata: {path}");
            }
            safe_path(&self.repo, name)?;
        }
        Ok(())
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
        read_archive_file(&archive, path)
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

fn read_archive_file(archive: &Path, path: &str) -> Result<Option<String>> {
    let mut target = normalize_path(Path::new(path))?;
    let mut visited = HashSet::new();
    for _ in 0..128 {
        if !visited.insert(target.clone()) {
            bail!("Archive link cycle at {}", target.display());
        }
        match archive_member(archive, &target)? {
            Some(ArchiveMember::File(bytes)) => {
                return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
            }
            Some(ArchiveMember::Link(link)) => target = link,
            Some(ArchiveMember::Other) | None => {
                let mut resolved = None;
                for parent in target
                    .ancestors()
                    .skip(1)
                    .filter(|path| !path.as_os_str().is_empty())
                {
                    if let Some(ArchiveMember::Link(link)) = archive_member(archive, parent)? {
                        resolved = Some(normalize_path(&link.join(target.strip_prefix(parent)?))?);
                        break;
                    }
                }
                match resolved {
                    Some(path) => target = path,
                    None => return Ok(None),
                }
            }
        }
    }
    bail!("Archive link depth exceeds the channel limit")
}

fn archive_member(archive: &Path, target: &Path) -> Result<Option<ArchiveMember>> {
    let file = File::open(archive)?;
    let mut tar = tar::Archive::new(GzDecoder::new(file));
    let mut member = None;
    for entry in tar.entries()? {
        let mut entry = entry?;
        if normalize_path(&entry.path()?)? != target {
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
                normalize_path(&target.parent().unwrap_or(Path::new("")).join(link.as_ref()))?
            } else {
                normalize_path(&link)?
            };
            ArchiveMember::Link(link)
        } else {
            ArchiveMember::Other
        });
    }
    Ok(member)
}

fn normalize_path(path: &Path) -> Result<PathBuf> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    bail!("Archive path escapes the channel: {}", path.display());
                }
            }
            Component::Normal(name) => result.push(name),
            Component::RootDir | Component::Prefix(_) => {
                bail!("Archive path is absolute: {}", path.display());
            }
        }
    }
    Ok(result)
}

pub fn safe_path(repo: &Path, path: &Path) -> Result<PathBuf> {
    let mut target = repo.to_path_buf();
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(name) => target.push(name),
            _ => bail!("Unsafe repository path: {}", path.display()),
        }
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("Repository path uses a symbolic link: {}", path.display());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| target.display().to_string()),
        }
    }
    Ok(target)
}

pub struct Signer {
    key: PathBuf,
    home: PathBuf,
    repo: PathBuf,
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
            repo: directory
                .parent()
                .and_then(Path::parent)
                .unwrap_or(Path::new("."))
                .to_path_buf(),
            key: directory.join("key"),
            home: directory.join("home"),
        }
    }

    pub fn environment(&self) -> Result<AgentEnv> {
        for target in [&self.key, &self.key.with_extension("pub"), &self.home] {
            safe_path(&self.repo, target.strip_prefix(&self.repo)?)?;
        }
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

#[cfg(test)]
mod safety_tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::os::unix::fs::symlink;

    #[test]
    fn repository_paths_preserve_names_and_reject_external_links() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let repo = directory.path().join("repo");
        fs::create_dir(&repo)?;
        let name = "-'quoted\" café.txt";
        assert_eq!(safe_path(&repo, Path::new(name))?, repo.join(name));
        assert!(safe_path(&repo, Path::new("../marker")).is_err());
        assert!(safe_path(&repo, &directory.path().join("marker")).is_err());
        symlink("..", repo.join("external"))?;
        assert!(safe_path(&repo, Path::new("external/marker")).is_err());
        symlink("../marker", repo.join("dangling"))?;
        assert!(safe_path(&repo, Path::new("dangling")).is_err());
        Ok(())
    }

    #[test]
    fn archive_reads_keep_internal_links_and_reject_escapes_and_cycles() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("channel.tar.gz");
        let encoder = GzEncoder::new(File::create(&archive)?, Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "inside/data.txt", &b"safe\n"[..])?;
        for (name, target, kind) in [
            ("alias", "inside/data.txt", tar::EntryType::Symlink),
            (
                "inside/relative",
                "../inside/data.txt",
                tar::EntryType::Symlink,
            ),
            ("directory", "inside", tar::EntryType::Symlink),
            ("hard", "inside/data.txt", tar::EntryType::Link),
            ("escape", "../marker", tar::EntryType::Symlink),
            ("absolute", "/marker", tar::EntryType::Symlink),
            ("cycle-a", "cycle-b", tar::EntryType::Symlink),
            ("cycle-b", "cycle-a", tar::EntryType::Symlink),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(0);
            header.set_mode(0o777);
            tar.append_link(&mut header, name, target)?;
        }
        tar.into_inner()?.finish()?;
        for path in ["alias", "inside/relative", "directory/data.txt", "hard"] {
            assert_eq!(
                read_archive_file(&archive, path)?.as_deref(),
                Some("safe\n")
            );
        }
        for path in ["escape", "absolute", "cycle-a", "../marker", "/marker"] {
            assert!(read_archive_file(&archive, path).is_err(), "{path}");
        }
        Ok(())
    }
}
