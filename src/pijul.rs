use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;
use serde::{Deserialize, Deserializer, Serialize};
use tempfile::TempDir;

const EXPECTED_STATE_MISMATCH: i32 = 42;

pub type CommandEnv = BTreeMap<OsString, OsString>;

#[derive(Deserialize, Serialize)]
pub struct LogEntry {
    pub hash: String,
    #[serde(default, deserialize_with = "null_default")]
    pub message: String,
    #[serde(default, deserialize_with = "null_default")]
    pub paths: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChannelSnapshot {
    pub hashes: HashSet<String>,
    pub state: Option<String>,
}

#[derive(Serialize)]
pub struct ReviewChange {
    pub hash: String,
    pub message: String,
    pub authors: Vec<String>,
    pub timestamp: String,
    pub dependencies: Vec<String>,
    pub paths: BTreeSet<String>,
    pub context: NativeContext,
    pub metadata_context: Vec<MetadataContext>,
}

#[derive(Deserialize, Serialize)]
pub struct NativeContext {
    pub full: bool,
    pub files: Vec<NativeContextFile>,
}

#[derive(Deserialize, Serialize)]
pub struct NativeContextFile {
    pub path: String,
    pub vertices: Vec<NativeVertex>,
}

#[derive(Deserialize, Serialize)]
pub struct NativeVertex {
    pub change: String,
    pub start: u64,
    pub end: u64,
    pub kind: NativeVertexKind,
    pub text: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeVertexKind {
    Add,
    Del,
    Keep,
}

#[derive(Serialize)]
pub struct MetadataContext {
    pub path: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Deserialize)]
struct SnapshotEntry {
    hash: String,
    state: String,
}

#[derive(Deserialize)]
pub struct ReviewEntry {
    pub hash: String,
    #[serde(default, deserialize_with = "null_default")]
    pub message: String,
    pub authors: Vec<String>,
    pub timestamp: String,
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
    timeout: Option<Duration>,
    executable: Option<PathBuf>,
}

impl Pijul {
    pub fn new(repo: PathBuf) -> Self {
        Self {
            repo,
            timeout: None,
            executable: find_executable("pijul"),
        }
    }

    pub fn with_timeout(repo: PathBuf, timeout: Duration) -> Self {
        let mut pijul = Self::new(repo);
        pijul.timeout = Some(timeout);
        pijul
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
        let (command, output) = self.execute(args, env)?;
        text_output(output, &command)
    }

    fn execute<I, S>(&self, args: I, env: Option<&CommandEnv>) -> Result<(Command, Output)>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let executable = self.executable.as_ref().ok_or_else(|| {
            anyhow!(
                "Pijul is not in an absolute PATH directory. Run patchgate in the devenv shell."
            )
        })?;
        let mut command = Command::new(executable);
        command
            .args(args)
            .current_dir(&self.repo)
            .stdin(Stdio::null());
        if let Some(env) = env {
            command.env_clear().envs(env);
        }
        command.env("NO_COLOR", "1");
        let output = match self.timeout {
            Some(timeout) => timed_output(&mut command, timeout),
            None => command.output(),
        }
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow!("pijul is not on PATH. Run patchgate in the devenv shell.")
            } else {
                anyhow!(error).context(format!("Cannot execute {}", command_name(&command, None)))
            }
        })?;
        Ok((command, output))
    }

    pub fn apply_if_current(
        &self,
        channel: &str,
        state: Option<&str>,
        changes: &[OsString],
    ) -> Result<bool> {
        let (command, output) = self.execute(
            [
                "apply",
                "--channel",
                channel,
                "--expected-state",
                state.unwrap_or("empty"),
            ]
            .into_iter()
            .map(OsStr::new)
            .chain(changes.iter().map(OsString::as_os_str)),
            None,
        )?;
        if output.status.code() == Some(EXPECTED_STATE_MISMATCH) {
            return Ok(false);
        }
        text_output(output, &command)?;
        Ok(true)
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

    pub fn snapshot(&self, channel: &str) -> Result<ChannelSnapshot> {
        let output = self.run([
            "log",
            "--channel",
            channel,
            "--state",
            "--output-format",
            "json",
        ])?;
        let entries: Vec<SnapshotEntry> =
            serde_json::from_str(&output).context("Pijul snapshot is not complete JSON")?;
        if entries
            .iter()
            .any(|entry| entry.hash.is_empty() || entry.state.is_empty())
        {
            bail!("Pijul snapshot has an empty hash or state");
        }
        Ok(ChannelSnapshot {
            state: entries.first().map(|entry| entry.state.clone()),
            hashes: entries.into_iter().map(|entry| entry.hash).collect(),
        })
    }

    pub fn review_metadata(&self, channel: &str) -> Result<Vec<ReviewEntry>> {
        let output = self.run([
            "log",
            "--channel",
            channel,
            "--output-format",
            "json",
            "--files",
        ])?;
        serde_json::from_str(&output).context("Native change metadata is not complete JSON")
    }

    pub fn review_change(
        &self,
        channel: &str,
        hash: &str,
        text: &str,
        paths: &BTreeSet<String>,
    ) -> Result<ReviewChange> {
        self.check_paths(paths)?;
        let directory = tempfile::tempdir()?;
        let destination = directory.path().join("candidate");
        self.run([
            OsStr::new("init"),
            OsStr::new("--channel"),
            OsStr::new(channel),
            destination.as_os_str(),
        ])?;
        let isolated = Self::new(destination);
        let dependencies = crate::change::dependencies(text);
        let mut pending = dependencies.clone();
        pending.push(hash.to_owned());
        let mut copied = HashSet::new();
        while let Some(current) = pending.pop() {
            if !copied.insert(current.clone()) {
                continue;
            }
            if current != hash {
                pending.extend(crate::change::dependencies(&self.change(&current)?));
            }
            let source = self.change_file(&current);
            let target = isolated.change_file(&current);
            fs::create_dir_all(target.parent().context("The change path has no parent")?)?;
            // Change files are immutable. Hard links avoid copies.
            if let Err(error) = fs::hard_link(&source, &target) {
                if error.kind() != std::io::ErrorKind::CrossesDevices {
                    return Err(error.into());
                }
                fs::copy(source, target)?;
            }
        }
        isolated.run([Path::new("apply"), &isolated.change_file(hash)])?;
        let actual_text = isolated.change(hash)?;
        if actual_text != text {
            bail!("The isolated candidate differs from the supplied change");
        }
        let entry = isolated
            .review_metadata(channel)?
            .into_iter()
            .find(|entry| entry.hash == hash)
            .context("The isolated channel does not contain the exact candidate hash")?;
        let hashes = isolated.hashes(channel)?;
        let mut context: NativeContext =
            serde_json::from_str(&isolated.run(["change", "--context", hash])?)
                .context("Native review context is not complete JSON")?;
        if !context.full {
            bail!("Native review context is incomplete");
        }

        let after_archive = directory.path().join("after.tar.gz");
        isolated.review_archive(&after_archive)?;
        isolated.run(["unrecord", hash])?;
        let before_archive = directory.path().join("before.tar.gz");
        isolated.review_archive(&before_archive)?;
        let before_paths = archive_paths(&before_archive)?;
        let mut after_paths = archive_paths(&after_archive)?;
        let mut resolved: BTreeSet<_> = before_paths
            .symmetric_difference(&after_paths)
            .cloned()
            .collect();
        let mut members = before_paths;
        members.append(&mut after_paths);
        let hints: BTreeSet<_> = entry.paths.into_iter().filter(|path| path != "/").collect();
        self.check_paths(&hints)?;
        let mut context_paths = BTreeSet::new();
        for file in &mut context.files {
            let matches = resolve_review_path(&file.path, &members)?;
            if matches.len() != 1 {
                bail!("Native context path is ambiguous: {}", file.path);
            }
            file.path = matches
                .into_iter()
                .next()
                .context("Native context has no path")?;
            if !context_paths.insert(file.path.clone()) {
                bail!("Native context repeats a file: {}", file.path);
            }
            resolved.insert(file.path.clone());
            for vertex in &file.vertices {
                if !hashes.contains(&vertex.change)
                    || vertex.end.checked_sub(vertex.start) != Some(vertex.text.len() as u64)
                    || vertex.text.contains('\0')
                {
                    bail!("Native context has invalid or binary spans: {}", file.path);
                }
            }
        }
        for path in hints {
            let matches = resolve_review_path(&path, &resolved)
                .or_else(|_| resolve_review_path(&path, &members))?;
            resolved.extend(matches);
        }
        self.check_paths(&resolved)?;
        let mut before_files = review_archive_files(&before_archive, &resolved)?;
        let mut after_files = review_archive_files(&after_archive, &resolved)?;
        let mut metadata_context = Vec::new();
        for path in &resolved {
            let before = before_files.remove(path.as_str());
            let after = after_files.remove(path.as_str());
            if before.is_none() && after.is_none() {
                bail!("No exact textual context exists for {path}");
            }
            if before.as_ref().is_some_and(|text| text.contains('\0'))
                || after.as_ref().is_some_and(|text| text.contains('\0'))
            {
                bail!("Review context is binary: {path}");
            }
            if let Some(file) = context.files.iter().find(|file| &file.path == path) {
                validate_context_file(file, before.as_deref(), after.as_deref())?;
            }
            if !context_paths.contains(path) {
                metadata_context.push(MetadataContext {
                    path: path.clone(),
                    before,
                    after,
                });
            }
        }
        drop((before_files, after_files));
        if resolved.is_empty() {
            bail!("The candidate has no exact textual review context");
        }
        Ok(ReviewChange {
            hash: entry.hash,
            message: entry.message,
            authors: entry.authors,
            timestamp: entry.timestamp,
            dependencies,
            paths: resolved,
            context,
            metadata_context,
        })
    }

    fn review_archive(&self, archive: &Path) -> Result<()> {
        let (_, stderr) =
            self.call([OsStr::new("archive"), OsStr::new("-o"), archive.as_os_str()])?;
        if !crate::change::conflict_report(&stderr).is_empty() {
            bail!("The isolated review archive contains conflicts");
        }
        Ok(())
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

    /// Export recorded source into a new directory without VCS metadata or build state.
    /// Keep file bytes, file modes, and safe relative links. Reject unsafe archive entries.
    pub fn export_source(&self, channel: &str, destination: &Path) -> Result<()> {
        self.export_archive(channel, destination, false)
    }

    pub fn export_working_copy(&self, channel: &str, destination: &Path) -> Result<()> {
        self.export_archive(channel, destination, true)
    }

    fn export_archive(&self, channel: &str, destination: &Path, conflicts: bool) -> Result<()> {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("channel.tar.gz");
        let (_, stderr) = self.call([
            OsStr::new("archive"),
            OsStr::new("--channel"),
            OsStr::new(channel),
            OsStr::new("-o"),
            archive.as_os_str(),
        ])?;
        if !conflicts && !crate::change::conflict_report(&stderr).is_empty() {
            bail!("The source archive contains conflicts");
        }
        extract_source_archive(&archive, destination)
    }

    pub fn read_file(&self, channel: &str, path: &str) -> Result<Option<String>> {
        self.read_channel_file(channel, path, read_archive_file)
    }

    pub fn read_file_bytes(&self, channel: &str, path: &str) -> Result<Option<Vec<u8>>> {
        self.read_channel_file(channel, path, read_archive_bytes)
    }

    pub fn read_regular_file(&self, channel: &str, path: &str) -> Result<Option<String>> {
        self.read_channel_file(channel, path, read_regular_archive_file)
    }

    fn read_channel_file<T>(
        &self,
        channel: &str,
        path: &str,
        reader: impl FnOnce(&Path, &str) -> Result<T>,
    ) -> Result<T> {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("channel.tar.gz");
        self.run([
            OsStr::new("archive"),
            OsStr::new("--channel"),
            OsStr::new(channel),
            OsStr::new("-o"),
            archive.as_os_str(),
        ])?;
        reader(&archive, path)
    }

    pub fn conflicts(&self) -> Result<Vec<crate::change::Conflict>> {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("channel.tar.gz");
        let (_, stderr) =
            self.call([OsStr::new("archive"), OsStr::new("-o"), archive.as_os_str()])?;
        Ok(crate::change::conflict_report(&stderr))
    }
}

fn find_executable(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .and_then(|path| fs::canonicalize(path).ok())
}

fn timed_output(command: &mut Command, timeout: Duration) -> std::io::Result<Output> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = command
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .process_group(0)
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "The Pijul diagnostic exceeded its time limit",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    stdout.rewind()?;
    stderr.rewind()?;
    let mut output = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    stdout.read_to_end(&mut output.stdout)?;
    stderr.read_to_end(&mut output.stderr)?;
    Ok(output)
}

enum SourceMember {
    File,
    Directory,
    Symlink(PathBuf),
    HardLink(PathBuf),
}

fn source_path(path: &Path) -> Result<PathBuf> {
    if path.components().any(|part| part == Component::ParentDir) {
        bail!(
            "Source archive path contains parent traversal: {}",
            path.display()
        );
    }
    normalize_path(path)
}

fn excluded_source_path(path: &Path) -> bool {
    path.components().next().is_some_and(|part| {
        let name = part.as_os_str();
        [".pijul", ".git", ".devenv", ".direnv", "target", "result"]
            .iter()
            .any(|excluded| name == OsStr::new(excluded))
            || name.as_encoded_bytes().starts_with(b"result-")
    })
}

fn resolve_source_link(path: &Path, members: &BTreeMap<PathBuf, SourceMember>) -> Result<PathBuf> {
    let mut pending: VecDeque<_> = path.components().collect();
    let mut resolved = PathBuf::new();
    let mut links = 0;
    while let Some(component) = pending.pop_front() {
        match component {
            Component::CurDir => continue,
            Component::ParentDir => {
                if !resolved.pop() {
                    bail!("Source link escapes the export root: {}", path.display());
                }
                continue;
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("Source link is absolute: {}", path.display());
            }
            Component::Normal(name) => resolved.push(name),
        }
        match members.get(&resolved) {
            Some(SourceMember::Symlink(target) | SourceMember::HardLink(target)) => {
                links += 1;
                if links > 128 {
                    bail!("Source link cycle or depth limit: {}", path.display());
                }
                if matches!(members.get(&resolved), Some(SourceMember::HardLink(_))) {
                    resolved.clear();
                } else {
                    resolved.pop();
                }
                for part in target.components().rev() {
                    pending.push_front(part);
                }
            }
            Some(SourceMember::File) if !pending.is_empty() => {
                bail!("Source link traverses a file: {}", path.display());
            }
            _ => {}
        }
    }
    Ok(resolved)
}

fn extract_source_archive(archive: &Path, destination: &Path) -> Result<()> {
    let mut tar = tar::Archive::new(GzDecoder::new(File::open(archive)?));
    let mut members = BTreeMap::new();
    let mut seen = HashSet::new();
    for entry in tar.entries()? {
        let entry = entry?;
        let path = source_path(&entry.path()?)?;
        let kind = entry.header().entry_type();
        if path.as_os_str().is_empty() {
            if kind.is_dir() {
                continue;
            }
            bail!("Source archive contains an empty file path");
        }
        if !seen.insert(path.clone()) {
            bail!("Source archive repeats a path: {}", path.display());
        }
        if excluded_source_path(&path) {
            continue;
        }
        let member = if kind.is_file() {
            SourceMember::File
        } else if kind.is_dir() {
            SourceMember::Directory
        } else if kind.is_symlink() || kind.is_hard_link() {
            let target = entry.link_name()?.context("Source link has no target")?;
            if target.as_os_str().is_empty() {
                bail!("Source link has an empty target: {}", path.display());
            }
            if kind.is_symlink() {
                SourceMember::Symlink(target.into_owned())
            } else {
                SourceMember::HardLink(target.into_owned())
            }
        } else {
            bail!("Source archive contains a special file: {}", path.display());
        };
        members.insert(path, member);
    }
    for (path, member) in &members {
        for parent in path.ancestors().skip(1) {
            if let Some(parent_member) = members.get(parent) {
                if !matches!(parent_member, SourceMember::Directory) {
                    bail!(
                        "Source archive path traverses a non-directory: {}",
                        path.display()
                    );
                }
            }
        }
        if matches!(member, SourceMember::Symlink(_) | SourceMember::HardLink(_)) {
            let target = resolve_source_link(path, &members)?;
            if matches!(member, SourceMember::HardLink(_))
                && !matches!(members.get(&target), Some(SourceMember::File))
            {
                bail!(
                    "Source hard link has no regular file target: {}",
                    path.display()
                );
            }
        }
    }

    fs::create_dir(destination).context("Source destination must be a new directory")?;
    let root = fs::canonicalize(destination)?;
    for (path, member) in &members {
        let directory = if matches!(member, SourceMember::Directory) {
            path.as_path()
        } else {
            path.parent().unwrap_or(Path::new(""))
        };
        fs::create_dir_all(root.join(directory))?;
    }
    let mut tar = tar::Archive::new(GzDecoder::new(File::open(archive)?));
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = source_path(&entry.path()?)?;
        if !matches!(members.get(&path), Some(SourceMember::File)) {
            continue;
        }
        let mut file = File::create_new(root.join(&path))?;
        std::io::copy(&mut entry, &mut file)?;
        file.set_permissions(fs::Permissions::from_mode(entry.header().mode()? & 0o777))?;
    }
    for (path, member) in &members {
        if matches!(member, SourceMember::HardLink(_)) {
            let target = resolve_source_link(path, &members)?;
            fs::hard_link(root.join(target), root.join(path))?;
        }
    }
    for (path, member) in &members {
        if let SourceMember::Symlink(target) = member {
            symlink(target, root.join(path))?;
        }
    }
    Ok(())
}

fn archive_paths(archive: &Path) -> Result<BTreeSet<String>> {
    let mut tar = tar::Archive::new(GzDecoder::new(File::open(archive)?));
    let mut paths = BTreeSet::new();
    for entry in tar.entries()? {
        let entry = entry?;
        let kind = entry.header().entry_type();
        if kind.is_file() || kind.is_gnu_sparse() || kind.is_symlink() || kind.is_hard_link() {
            let path = normalize_path(&entry.path()?)?;
            paths.insert(
                path.to_str()
                    .context("Archive path is not UTF-8")?
                    .to_owned(),
            );
        }
    }
    Ok(paths)
}

fn review_archive_files<'a>(
    archive: &Path,
    paths: &'a BTreeSet<String>,
) -> Result<BTreeMap<&'a str, String>> {
    let mut tar = tar::Archive::new(GzDecoder::new(File::open(archive)?));
    let mut files = BTreeMap::new();
    let mut links = Vec::new();
    for entry in tar.entries()? {
        let mut entry = entry?;
        let member = normalize_path(&entry.path()?)?;
        let Some(path) = member.to_str().and_then(|name| paths.get(name)) else {
            continue;
        };
        let kind = entry.header().entry_type();
        if kind.is_file() || kind.is_gnu_sparse() {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let text = String::from_utf8(bytes).context("Archive file is not UTF-8")?;
            if files.insert(path.as_str(), text).is_some() {
                bail!("Review archive repeats a file: {path}");
            }
        } else if kind.is_symlink() || kind.is_hard_link() {
            links.push(path.as_str());
        }
    }
    for path in links {
        if let Some(text) = read_archive_file(archive, path)? {
            files.insert(path, text);
        }
    }
    Ok(files)
}

fn resolve_review_path(path: &str, members: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let path = normalize_path(Path::new(path))?;
    if path.as_os_str().is_empty() {
        bail!("Review context has an empty path");
    }
    let exact: BTreeSet<_> = members
        .iter()
        .filter(|member| Path::new(member).starts_with(&path))
        .cloned()
        .collect();
    if !exact.is_empty() {
        return Ok(exact);
    }
    let suffixes: BTreeSet<_> = members
        .iter()
        .filter_map(|member| {
            let member = Path::new(member);
            member
                .ancestors()
                .find(|ancestor| ancestor.ends_with(&path))
                .map(Path::to_path_buf)
        })
        .collect();
    if suffixes.len() != 1 {
        bail!("Cannot resolve one full review path: {}", path.display());
    }
    let prefix = suffixes
        .iter()
        .next()
        .context("Review path has no prefix")?;
    Ok(members
        .iter()
        .filter(|member| Path::new(member).starts_with(prefix))
        .cloned()
        .collect())
}

fn validate_context_file(
    file: &NativeContextFile,
    before: Option<&str>,
    after: Option<&str>,
) -> Result<()> {
    for (text, original) in [(before.unwrap_or(""), true), (after.unwrap_or(""), false)] {
        let mut remaining = text;
        for vertex in &file.vertices {
            let included = match vertex.kind {
                NativeVertexKind::Keep => true,
                NativeVertexKind::Del => original,
                NativeVertexKind::Add => !original,
            };
            if included {
                remaining = remaining
                    .strip_prefix(vertex.text.as_str())
                    .with_context(|| {
                        format!("Native context differs from the archive: {}", file.path)
                    })?;
            }
        }
        if !remaining.is_empty() {
            bail!("Native context omits archive text: {}", file.path);
        }
    }
    Ok(())
}

enum ArchiveMember {
    File(Vec<u8>),
    Link(PathBuf),
    Other,
}

fn read_archive_file(archive: &Path, path: &str) -> Result<Option<String>> {
    read_archive_bytes(archive, path)?
        .map(String::from_utf8)
        .transpose()
        .context("Archive file is not UTF-8")
}

fn read_archive_bytes(archive: &Path, path: &str) -> Result<Option<Vec<u8>>> {
    let mut target = normalize_path(Path::new(path))?;
    let mut visited = HashSet::new();
    for _ in 0..128 {
        if !visited.insert(target.clone()) {
            bail!("Archive link cycle at {}", target.display());
        }
        match archive_member(archive, &target)? {
            Some(ArchiveMember::File(bytes)) => return Ok(Some(bytes)),
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

fn read_regular_archive_file(archive: &Path, path: &str) -> Result<Option<String>> {
    let target = normalize_path(Path::new(path))?;
    let mut tar = tar::Archive::new(GzDecoder::new(File::open(archive)?));
    let mut bytes = None;
    for entry in tar.entries()? {
        let mut entry = entry?;
        let member = normalize_path(&entry.path()?)?;
        let kind = entry.header().entry_type();
        if member == target {
            if !kind.is_file() || bytes.is_some() {
                bail!("The requested path is not one recorded regular file");
            }
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            bytes = Some(data);
        } else if member.starts_with(&target) || (target.starts_with(&member) && !kind.is_dir()) {
            bail!("The requested regular file path uses a directory, link, or special file");
        }
    }
    bytes
        .map(String::from_utf8)
        .transpose()
        .context("Archive file is not UTF-8")
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

pub(crate) fn normalize_path(path: &Path) -> Result<PathBuf> {
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
            let executable = find_executable("ssh-keygen")
                .context("ssh-keygen is not in an absolute PATH directory")?;
            let mut keygen = Command::new(executable);
            keygen
                .args(["-q", "-t", "ed25519", "-N", "", "-C", "patchgate", "-f"])
                .arg(&self.key);
            tool(&mut keygen)?;
        }
        let directory = tempfile::Builder::new().prefix("patchgate-").tempdir()?;
        let socket = directory.path().join("agent");
        let executable = find_executable("ssh-agent")
            .context("ssh-agent is not in an absolute PATH directory")?;
        let agent = Command::new(executable)
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
        let executable =
            find_executable("ssh-add").context("ssh-add is not in an absolute PATH directory")?;
        let mut add = Command::new(executable);
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

    fn source_fixture(
        tar: &mut tar::Builder<GzEncoder<File>>,
        name: &str,
        kind: tar::EntryType,
        target: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_size(bytes.len() as u64);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        if kind.is_symlink() || kind.is_hard_link() {
            header.set_link_name(target)?;
        }
        header.set_cksum();
        tar.append(&header, bytes)?;
        Ok(())
    }

    #[test]
    fn trusted_regular_file_reads_reject_aliases_and_directory_forms() -> Result<()> {
        use tar::EntryType::{Directory, Link, Regular, Symlink};
        let directory = tempfile::tempdir()?;
        let cases = [
            vec![
                ("patchgate.json", Symlink, "settings.json"),
                ("settings.json", Regular, ""),
            ],
            vec![
                ("patchgate.json", Link, "settings.json"),
                ("settings.json", Regular, ""),
            ],
            vec![("patchgate.json", Directory, "")],
            vec![("patchgate.json/child", Regular, "")],
            vec![
                ("patchgate.json", Regular, ""),
                ("patchgate.json", Regular, ""),
            ],
        ];
        for (index, entries) in cases.iter().enumerate() {
            let archive = directory
                .path()
                .join(format!("configuration-{index}.tar.gz"));
            let encoder = GzEncoder::new(File::create(&archive)?, Compression::default());
            let mut tar = tar::Builder::new(encoder);
            for &(name, kind, target) in entries {
                let data: &[u8] = if kind == Regular {
                    br#"{"schema_version":1}"#
                } else {
                    b""
                };
                source_fixture(&mut tar, name, kind, target, data, 0o600)?;
            }
            tar.into_inner()?.finish()?;
            assert!(
                read_regular_archive_file(&archive, "patchgate.json").is_err(),
                "{index}"
            );
        }
        Ok(())
    }

    #[test]
    fn source_export_keeps_bytes_modes_and_internal_links_without_build_state() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("source.tar.gz");
        let encoder = GzEncoder::new(File::create(&archive)?, Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let bytes = b"\0\xffline\r\n";
        for (name, mode) in [
            ("inside/source", 0o755),
            ("plain", 0o644),
            ("nix/check.nix", 0o644),
            ("inside/.git/config", 0o644),
            (".gitconfig", 0o644),
        ] {
            source_fixture(&mut tar, name, tar::EntryType::Regular, "", bytes, mode)?;
        }
        for name in [
            ".pijul/patchgate/key",
            ".git/config",
            ".devenv/state",
            ".direnv/state",
            "target/program",
            "result",
            "result-debug",
            "result-\u{fffd}/program",
        ] {
            source_fixture(
                &mut tar,
                name,
                tar::EntryType::Regular,
                "",
                b"secret",
                0o600,
            )?;
        }
        source_fixture(
            &mut tar,
            "result-host",
            tar::EntryType::Symlink,
            "/host",
            b"",
            0o777,
        )?;
        for (name, target, kind) in [
            ("inside/alias", "../inside/source", tar::EntryType::Symlink),
            ("view", "inside", tar::EntryType::Symlink),
            ("hard", "inside/source", tar::EntryType::Link),
        ] {
            source_fixture(&mut tar, name, kind, target, b"", 0o777)?;
        }
        tar.into_inner()?.finish()?;
        let destination = directory.path().join("export");
        extract_source_archive(&archive, &destination)?;
        for name in [
            "inside/source",
            "plain",
            "nix/check.nix",
            "inside/.git/config",
            ".gitconfig",
            "inside/alias",
            "view/source",
            "hard",
        ] {
            assert_eq!(fs::read(destination.join(name))?, bytes, "{name}");
        }
        assert_eq!(
            fs::read_link(destination.join("inside/alias"))?,
            Path::new("../inside/source")
        );
        assert_eq!(
            fs::metadata(destination.join("inside/source"))?
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(destination.join("plain"))?
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        for entry in fs::read_dir(&destination)? {
            assert!(!excluded_source_path(Path::new(&entry?.file_name())));
        }
        fs::write(destination.join("marker"), b"unchanged")?;
        assert!(extract_source_archive(&archive, &destination).is_err());
        assert_eq!(fs::read(destination.join("marker"))?, b"unchanged");
        let linked_destination = directory.path().join("linked-export");
        symlink(&destination, &linked_destination)?;
        assert!(extract_source_archive(&archive, &linked_destination).is_err());
        assert_eq!(fs::read(destination.join("marker"))?, b"unchanged");
        Ok(())
    }

    #[test]
    fn source_export_rejects_unsafe_archive_members_before_extraction() -> Result<()> {
        use tar::EntryType::{Char, Fifo, GNUSparse, Link, Regular, Symlink};
        let cases = [
            vec![("/escape", Regular, "")],
            vec![("../escape", Regular, "")],
            vec![("inside/../escape", Regular, "")],
            vec![("same", Regular, ""), ("./same", Regular, "")],
            vec![("special", Fifo, "")],
            vec![("special", Char, "")],
            vec![("special", GNUSparse, "")],
            vec![("escape", Symlink, "/host")],
            vec![("escape", Symlink, "../host")],
            vec![
                ("alias", Symlink, "."),
                ("escape", Symlink, "alias/../host"),
            ],
            vec![("a", Symlink, "b"), ("b", Symlink, "a")],
            vec![("alias", Symlink, "inside"), ("alias/file", Regular, "")],
            vec![("escape", Link, "../host")],
            vec![("missing", Link, "absent")],
        ];
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join("host"), b"unchanged")?;
        for (index, members) in cases.iter().enumerate() {
            let archive = directory.path().join(format!("{index}.tar.gz"));
            let encoder = GzEncoder::new(File::create(&archive)?, Compression::default());
            let mut tar = tar::Builder::new(encoder);
            for (name, kind, target) in members {
                source_fixture(&mut tar, name, *kind, target, b"", 0o755)?;
            }
            tar.into_inner()?.finish()?;
            let destination = directory.path().join(format!("export-{index}"));
            assert!(
                extract_source_archive(&archive, &destination).is_err(),
                "{index}"
            );
            assert!(!destination.exists(), "{index}");
        }
        assert_eq!(fs::read(directory.path().join("host"))?, b"unchanged");
        let archive = directory.path().join("0.tar.gz");
        let destination = directory.path().join("host-link");
        symlink(directory.path(), &destination)?;
        assert!(extract_source_archive(&archive, &destination).is_err());
        assert_eq!(fs::read(directory.path().join("host"))?, b"unchanged");
        Ok(())
    }

    #[test]
    fn export_source_uses_the_recorded_channel_and_omits_host_state() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let repo = directory.path().join("repo");
        fs::create_dir(&repo)?;
        let pijul = Pijul::new(repo.clone());
        pijul.run(["init"])?;
        fs::create_dir(repo.join("nix"))?;
        fs::write(repo.join("nix/check.nix"), b"{ src }: src\n")?;
        fs::write(repo.join("source.bin"), b"\0\xffrecorded\r\n")?;
        fs::set_permissions(repo.join("source.bin"), fs::Permissions::from_mode(0o755))?;
        pijul.run(["add", "nix/check.nix", "source.bin"])?;
        let signer = Signer::new(repo.join(".pijul/patchgate"));
        let environment = signer.environment()?;
        pijul.call_with_env(
            [
                "record",
                "-a",
                "-m",
                "Record source",
                "--author",
                "patchgate",
            ],
            &environment.vars,
        )?;
        fs::write(repo.join("source.bin"), b"unrecorded")?;
        fs::write(repo.join("host-secret"), b"secret")?;
        fs::create_dir(repo.join("target"))?;
        fs::write(repo.join("target/program"), b"host build")?;
        let destination = directory.path().join("export");
        pijul.export_source("main", &destination)?;
        assert_eq!(
            fs::read(destination.join("source.bin"))?,
            b"\0\xffrecorded\r\n"
        );
        assert_eq!(
            fs::metadata(destination.join("source.bin"))?
                .permissions()
                .mode()
                & 0o111,
            0o111
        );
        assert_eq!(
            fs::read(destination.join("nix/check.nix"))?,
            b"{ src }: src\n"
        );
        for name in [".pijul", "host-secret", "target"] {
            assert!(!destination.join(name).exists(), "{name}");
        }
        assert_eq!(fs::read(repo.join("source.bin"))?, b"unrecorded");
        assert!(pijul.export_source("main", &destination).is_err());
        Ok(())
    }

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
        for (name, bytes) in [
            ("exact.txt", &b"line\r\nnext\r\n"[..]),
            ("binary.txt", &b"\xff\xfe"[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, bytes)?;
        }
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
        assert_eq!(
            read_archive_file(&archive, "exact.txt")?.as_deref(),
            Some("line\r\nnext\r\n")
        );
        assert!(read_archive_file(&archive, "binary.txt").is_err());
        for path in ["escape", "absolute", "cycle-a", "../marker", "/marker"] {
            assert!(read_archive_file(&archive, path).is_err(), "{path}");
        }
        Ok(())
    }

    #[test]
    fn review_paths_resolve_nested_files_and_reject_ambiguity() -> Result<()> {
        let paths = BTreeSet::from([
            "docs/archive/source.txt".to_owned(),
            "docs/releases/renamed.txt".to_owned(),
        ]);
        assert_eq!(
            resolve_review_path("renamed.txt", &paths)?,
            BTreeSet::from(["docs/releases/renamed.txt".to_owned()])
        );
        assert_eq!(resolve_review_path("docs", &paths)?, paths);
        let ambiguous = BTreeSet::from(["a/file.txt".to_owned(), "b/file.txt".to_owned()]);
        assert!(resolve_review_path("file.txt", &ambiguous).is_err());
        assert!(resolve_review_path("missing.txt", &paths).is_err());
        Ok(())
    }

    #[test]
    fn native_context_requires_exact_complete_archive_text() -> Result<()> {
        let file = NativeContextFile {
            path: "nested/file.txt".to_owned(),
            vertices: vec![
                NativeVertex {
                    change: "origin".to_owned(),
                    start: 9,
                    end: 15,
                    kind: NativeVertexKind::Keep,
                    text: "keep\r\n".to_owned(),
                },
                NativeVertex {
                    change: "origin".to_owned(),
                    start: 15,
                    end: 20,
                    kind: NativeVertexKind::Del,
                    text: "old\r\n".to_owned(),
                },
                NativeVertex {
                    change: "candidate".to_owned(),
                    start: 0,
                    end: 5,
                    kind: NativeVertexKind::Add,
                    text: "new\r\n".to_owned(),
                },
            ],
        };
        validate_context_file(&file, Some("keep\r\nold\r\n"), Some("keep\r\nnew\r\n"))?;
        assert!(validate_context_file(&file, Some("keep\nold\n"), Some("keep\nnew\n")).is_err());
        assert!(
            validate_context_file(&file, Some("keep\r\nold\r\nextra"), Some("keep\r\nnew\r\n"))
                .is_err()
        );
        assert!(
            validate_context_file(&file, Some("keep\r\nold\r\n"), Some("keep\r\nlater\r\n"))
                .is_err()
        );
        Ok(())
    }
}
