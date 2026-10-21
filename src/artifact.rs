use std::ffi::{CString, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const MAX_CONTROL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOOL_BYTES: u64 = 128 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Bundle,
    Baseline,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Bundle => "bundle",
            Self::Baseline => "baseline",
        }
    }

    fn namespace(self) -> &'static str {
        match self {
            Self::Bundle => "patchgate-bundle-v1",
            Self::Baseline => "patchgate-baseline-v1",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Trust {
    pub signature: PathBuf,
    pub allowed_signers: PathBuf,
    pub identity: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureReport {
    pub schema_version: u32,
    pub authorizes_acceptance: bool,
    pub kind: Kind,
    pub sha256: String,
    pub namespace: String,
    pub signature: PathBuf,
    pub signer_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verified {
    pub schema_version: u32,
    pub authorizes_acceptance: bool,
    pub kind: Kind,
    pub sha256: String,
    pub identity: String,
    pub allowed_signers_sha256: String,
    pub namespace: String,
}

pub struct VerifiedSnapshot {
    pub verified: Verified,
    _directory: TempDir,
    artifact: PathBuf,
}

impl VerifiedSnapshot {
    pub fn path(&self) -> &Path {
        &self.artifact
    }
}

fn copy_digest(mut input: impl Read, mut output: impl Write) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn digest(input: impl Read) -> Result<String> {
    copy_digest(input, std::io::sink())
}

fn envelope(kind: Kind, sha256: &str) -> Result<String> {
    ensure!(
        sha256.len() == 64
            && sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "The artifact digest must be a lowercase SHA-256 value."
    );
    Ok(format!(
        "patchgate-artifact-signature\nversion:1\nkind:{}\nsha256:{sha256}\n",
        kind.name()
    ))
}

fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => continue,
            Component::ParentDir => {
                ensure!(
                    result.is_dir() && result.pop(),
                    "An artifact path has an invalid parent."
                );
                continue;
            }
            _ => result.push(part),
        }
        match fs::symlink_metadata(&result) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "An artifact path must not contain symbolic links."
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(result)
}

fn open_regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .context("Cannot read an artifact input.")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "An artifact input must be a regular file."
    );
    Ok(file)
}

fn control_bytes(path: &Path) -> Result<Vec<u8>> {
    let file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONTROL_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_CONTROL_BYTES,
        "An artifact control file is too large."
    );
    Ok(bytes)
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn directory_contains(directory: &Path, path: &Path) -> Result<bool> {
    if path.starts_with(directory) {
        return Ok(true);
    }
    let expected = match fs::metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    for parent in path.ancestors() {
        match fs::metadata(parent) {
            Ok(metadata) if same_file(&expected, &metadata) => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

fn outside_metadata(source: &Path, path: &Path) -> Result<()> {
    let names_metadata = path.components().any(|part| match part {
        Component::Normal(name) => name.as_bytes().eq_ignore_ascii_case(b".pijul"),
        _ => false,
    });
    ensure!(
        !names_metadata && !directory_contains(&source.join(".pijul"), path)?,
        "Artifact keys and outputs must not use native metadata."
    );
    Ok(())
}

fn source_repository(source: &Path) -> Result<PathBuf> {
    let source = fs::canonicalize(source).context("Cannot read the artifact source directory.")?;
    ensure!(source.is_dir(), "The artifact source must be a directory.");
    for ancestor in source.ancestors() {
        match fs::symlink_metadata(ancestor.join(".pijul")) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "The source native metadata is unsafe."
                );
                return Ok(ancestor.to_path_buf());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Cannot inspect the source native metadata."),
        }
    }
    Ok(source)
}

struct GateKey {
    private: Option<Metadata>,
    public: Option<Vec<u8>>,
}

fn gate_key(source: &Path) -> Result<GateKey> {
    let mut directory = source.to_path_buf();
    for part in [".pijul", "patchgate"] {
        directory.push(part);
        match fs::symlink_metadata(&directory) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "The source gate metadata is ambiguous."
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(GateKey {
                    private: None,
                    public: None,
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    let private = match fs::symlink_metadata(directory.join("key")) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1,
                "The source gate key metadata is ambiguous."
            );
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let public_path = directory.join("key.pub");
    let public = match fs::symlink_metadata(&public_path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1,
                "The source gate public key metadata is ambiguous."
            );
            let file = open_regular(&public_path)?;
            let opened = file.metadata()?;
            ensure!(
                same_file(&metadata, &opened),
                "The source gate public key changed."
            );
            if let Some(private) = &private {
                ensure!(
                    !same_file(private, &opened),
                    "The source gate public key is ambiguous."
                );
            }
            let mut bytes = Vec::new();
            file.take(MAX_TOOL_BYTES + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= MAX_TOOL_BYTES,
                "The source gate public key is too large."
            );
            Some(bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    ensure!(
        private.is_none() || public.is_some(),
        "The source gate public identity is absent."
    );
    Ok(GateKey { private, public })
}

struct Tools {
    home: TempDir,
    executable: PathBuf,
    path: OsString,
    deadline: Instant,
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        let _ = self.0.wait();
    }
}

impl Tools {
    fn new() -> Result<Self> {
        let directories: Vec<_> =
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .filter(|directory| directory.is_absolute())
                .collect();
        let executable = directories
            .iter()
            .map(|directory| directory.join("ssh-keygen"))
            .find(|path| {
                fs::metadata(path).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
            .context("OpenSSH ssh-keygen needs an absolute executable directory.")?;
        Ok(Self {
            home: tempfile::Builder::new()
                .prefix("patchgate-artifact-")
                .tempdir()?,
            executable: fs::canonicalize(executable)?,
            path: std::env::join_paths(directories)?,
            deadline: Instant::now() + TOOL_TIMEOUT,
        })
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = self.home.path().join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(bytes)?;
        Ok(path)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("PATH", &self.path)
            .env("LC_ALL", "C")
            .env("SSH_ASKPASS_REQUIRE", "never")
            .current_dir(self.home.path())
            .stdin(Stdio::null())
            .process_group(0);
        command
    }

    fn execute(&self, command: &mut Command) -> Result<Vec<u8>> {
        ensure!(
            Instant::now() < self.deadline,
            "The artifact signature tool timed out."
        );
        let mut stdout = tempfile::tempfile()?;
        let stderr = tempfile::tempfile()?;
        let mut process = Process(
            command
                .stdout(stdout.try_clone()?)
                .stderr(stderr)
                .spawn()
                .context("Cannot execute the artifact signature tool.")?,
        );
        let status = loop {
            if let Some(status) = process.0.try_wait()? {
                break status;
            }
            ensure!(
                Instant::now() < self.deadline,
                "The artifact signature tool timed out."
            );
            thread::sleep(Duration::from_millis(10));
        };
        ensure!(
            status.success(),
            "The artifact signature tool refused the operation."
        );
        stdout.rewind()?;
        let mut bytes = Vec::new();
        stdout.take(MAX_TOOL_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_TOOL_BYTES,
            "The artifact signature tool output is too large."
        );
        Ok(bytes)
    }

    fn fingerprint(&self, name: &str, public: &[u8]) -> Result<String> {
        let path = self.write(name, public)?;
        let output = self.execute(self.command().args(["-l", "-E", "sha256", "-f"]).arg(path))?;
        let text = std::str::from_utf8(&output).context("The SSH fingerprint is invalid.")?;
        ensure!(
            text.lines().count() == 1,
            "The SSH public identity is ambiguous."
        );
        let fingerprint = text
            .split_whitespace()
            .nth(1)
            .context("The SSH fingerprint is absent.")?;
        ensure!(
            fingerprint.starts_with("SHA256:"),
            "The SSH fingerprint is invalid."
        );
        Ok(fingerprint.to_owned())
    }
}

fn public_identity(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).context("The SSH public identity is invalid.")?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next().context("The SSH public identity is absent.")?;
    ensure!(
        lines.next().is_none(),
        "The SSH public identity is ambiguous."
    );
    let mut words = line.split_whitespace();
    let kind = words.next().context("The SSH public key type is absent.")?;
    let key = words.next().context("The SSH public key data is absent.")?;
    ensure!(
        (kind.starts_with("ssh-") || kind.starts_with("ecdsa-") || kind.starts_with("sk-"))
            && !kind.contains("-cert-")
            && key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte)),
        "The SSH public identity is invalid."
    );
    Ok(format!("{kind} {key}\n").into_bytes())
}

fn open_directory(path: &Path) -> Result<File> {
    let mut directory = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("Cannot open the signature output directory.");
                }
                directory = unsafe { File::from_raw_fd(fd) };
            }
            _ => bail!("The signature output directory is invalid."),
        }
    }
    Ok(directory)
}

struct Publication {
    directory: File,
    temporary: CString,
}

impl Drop for Publication {
    fn drop(&mut self) {
        unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.temporary.as_ptr(), 0) };
    }
}

fn publish(output: &Path, bytes: &[u8], tools: &Tools) -> Result<()> {
    let directory = open_directory(
        output
            .parent()
            .context("The signature output has no parent.")?,
    )?;
    let name = CString::new(
        output
            .file_name()
            .context("The signature output has no name.")?
            .as_bytes(),
    )?;
    let nonce = tools
        .home
        .path()
        .file_name()
        .context("The private signature directory has no name.")?;
    let temporary = CString::new(format!(".{}.signature", nonce.to_string_lossy()))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("Cannot create the private signature output.");
    }
    let publication = Publication {
        directory,
        temporary,
    };
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let result = unsafe {
        libc::linkat(
            publication.directory.as_raw_fd(),
            publication.temporary.as_ptr(),
            publication.directory.as_raw_fd(),
            name.as_ptr(),
            0,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("Cannot publish a new signature file.");
    }
    unsafe {
        libc::unlinkat(
            publication.directory.as_raw_fd(),
            publication.temporary.as_ptr(),
            0,
        )
    };
    publication.directory.sync_all()?;
    Ok(())
}

pub fn sign(
    source: &Path,
    artifact: &Path,
    kind: Kind,
    key: &Path,
    output: &Path,
) -> Result<SignatureReport> {
    let source = source_repository(source)?;
    let artifact = absolute(artifact)?;
    let key = absolute(key)?;
    let output = absolute(output)?;
    outside_metadata(&source, &key)?;
    outside_metadata(&source, &output)?;
    ensure!(
        output != artifact && output != key,
        "The signature output conflicts with an input."
    );
    match fs::symlink_metadata(&output) {
        Ok(_) => bail!("The signature output already exists."),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let gate = gate_key(&source)?;
    let mut reviewer = open_regular(&key)?;
    let reviewer_metadata = reviewer.metadata()?;
    ensure!(
        reviewer_metadata.nlink() == 1,
        "The reviewer key must not have hard links."
    );
    if let Some(private) = &gate.private {
        ensure!(
            !same_file(private, &reviewer_metadata),
            "The reviewer key must differ from the gate key."
        );
    }
    let artifact_file = open_regular(&artifact)?;
    if let Some(private) = &gate.private {
        ensure!(
            !same_file(private, &artifact_file.metadata()?),
            "An artifact must not be the source gate private key."
        );
    }
    let tools = Tools::new()?;
    let reviewer_path = tools.home.path().join("reviewer-key");
    let mut snapshot = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&reviewer_path)?;
    let count = std::io::copy(
        &mut (&mut reviewer).take(MAX_CONTROL_BYTES + 1),
        &mut snapshot,
    )?;
    ensure!(count <= MAX_CONTROL_BYTES, "The reviewer key is too large.");
    drop(snapshot);
    let public = tools.execute(
        tools
            .command()
            .args(["-y", "-P", "", "-f"])
            .arg(&reviewer_path),
    )?;
    let public = public_identity(&public)?;
    let signer_fingerprint = tools.fingerprint("reviewer.pub", &public)?;
    if let Some(gate_public) = gate.public {
        let gate_public = public_identity(&gate_public)?;
        let gate_fingerprint = tools.fingerprint("gate-public-identity", &gate_public)?;
        ensure!(
            gate_fingerprint != signer_fingerprint,
            "The reviewer public identity must differ from the source gate identity."
        );
    }
    let sha256 = digest(artifact_file)?;
    let envelope = tools.write("envelope", envelope(kind, &sha256)?.as_bytes())?;
    let signature = tools.execute(
        tools
            .command()
            .args(["-Y", "sign", "-f"])
            .arg(&reviewer_path)
            .args(["-n", kind.namespace()])
            .stdin(File::open(envelope)?),
    )?;
    ensure!(!signature.is_empty(), "The artifact signature is absent.");
    publish(&output, &signature, &tools)?;
    Ok(SignatureReport {
        schema_version: 1,
        authorizes_acceptance: false,
        kind,
        sha256,
        namespace: kind.namespace().to_owned(),
        signature: output,
        signer_fingerprint,
    })
}

pub fn verify(artifact: &Path, kind: Kind, trust: &Trust) -> Result<Verified> {
    let artifact = absolute(artifact)?;
    verify_digest(kind, &digest(open_regular(&artifact)?)?, trust)
}

/// Copy the opaque artifact bytes and authenticate that exact private snapshot.
pub fn snapshot(artifact: &Path, kind: Kind, trust: &Trust) -> Result<VerifiedSnapshot> {
    let artifact = absolute(artifact)?;
    let input = open_regular(&artifact)?;
    let directory = tempfile::Builder::new()
        .prefix("patchgate-authenticated-")
        .tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let artifact = fs::canonicalize(directory.path())?.join("artifact");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&artifact)?;
    let sha256 = copy_digest(input, &mut output)?;
    drop(output);
    let verified = verify_digest(kind, &sha256, trust)?;
    Ok(VerifiedSnapshot {
        verified,
        _directory: directory,
        artifact,
    })
}

pub fn verify_digest(kind: Kind, sha256: &str, trust: &Trust) -> Result<Verified> {
    let envelope = envelope(kind, sha256)?;
    ensure!(
        !trust.identity.is_empty()
            && trust
                .identity
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.@+-".contains(&byte))
            && trust.identity.as_bytes()[0].is_ascii_alphanumeric(),
        "The trusted signer identity must be explicit."
    );
    let signature = control_bytes(&absolute(&trust.signature)?)?;
    let allowed_signers = control_bytes(&absolute(&trust.allowed_signers)?)?;
    let allowed_signers_sha256 = digest(allowed_signers.as_slice())?;
    let tools = Tools::new()?;
    let signature = tools.write("signature", &signature)?;
    let allowed_signers = tools.write("allowed-signers", &allowed_signers)?;
    let envelope = tools.write("envelope", envelope.as_bytes())?;
    tools.execute(
        tools
            .command()
            .args(["-Y", "verify", "-f"])
            .arg(allowed_signers)
            .arg("-I")
            .arg(&trust.identity)
            .args(["-n", kind.namespace(), "-s"])
            .arg(signature)
            .stdin(File::open(envelope)?),
    )?;
    Ok(Verified {
        schema_version: 1,
        authorizes_acceptance: false,
        kind,
        sha256: sha256.to_owned(),
        identity: trust.identity.clone(),
        allowed_signers_sha256,
        namespace: kind.namespace().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture {
        _directory: TempDir,
        root: PathBuf,
        source: PathBuf,
        artifact: PathBuf,
        reviewer: PathBuf,
        other: PathBuf,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let directory = tempfile::tempdir()?;
            let root = fs::canonicalize(directory.path())?;
            let source = root.join("source");
            fs::create_dir(&source)?;
            let artifact = root.join("artifact");
            fs::write(&artifact, b"review artifact\n")?;
            let reviewer = root.join("reviewer");
            let other = root.join("other");
            let tools = Tools::new()?;
            for key in [&reviewer, &other] {
                tools.execute(
                    tools
                        .command()
                        .args(["-q", "-t", "ed25519", "-N", "", "-C", "fixture", "-f"])
                        .arg(key),
                )?;
            }
            Ok(Self {
                _directory: directory,
                root,
                source,
                artifact,
                reviewer,
                other,
            })
        }

        fn sign(&self, kind: Kind) -> Result<SignatureReport> {
            sign(
                &self.source,
                &self.artifact,
                kind,
                &self.reviewer,
                &self.root.join(format!("{}.sig", kind.name())),
            )
        }

        fn trust(&self, signature: &Path, key: &Path) -> Result<Trust> {
            let allowed_signers = self.root.join("allowed-signers");
            let public = fs::read_to_string(key.with_extension("pub"))?;
            fs::write(&allowed_signers, format!("reviewer@example.test {public}"))?;
            Ok(Trust {
                signature: signature.to_owned(),
                allowed_signers,
                identity: "reviewer@example.test".to_owned(),
            })
        }
    }

    #[test]
    fn local_ssh_signatures_bind_data_kind_identity_and_allowlist() -> Result<()> {
        let fixture = Fixture::new()?;
        for kind in [Kind::Bundle, Kind::Baseline] {
            let report = fixture.sign(kind)?;
            let trust = fixture.trust(&report.signature, &fixture.reviewer)?;
            let verified = verify(&fixture.artifact, kind, &trust)?;
            assert_eq!(verified.sha256, report.sha256);
            assert_eq!(verified.identity, trust.identity);
            assert_eq!(verified.namespace, report.namespace);
            assert!(!verified.authorizes_acceptance);
            assert!(!report.authorizes_acceptance);
            assert_eq!(
                verified.allowed_signers_sha256,
                digest(File::open(&trust.allowed_signers)?)?
            );
            assert_eq!(
                fs::metadata(&report.signature)?.permissions().mode() & 0o777,
                0o600
            );
            let other_kind = if kind == Kind::Bundle {
                Kind::Baseline
            } else {
                Kind::Bundle
            };
            assert!(verify(&fixture.artifact, other_kind, &trust).is_err());
            let mut wrong_identity = trust.clone();
            wrong_identity.identity = "other@example.test".to_owned();
            assert!(verify(&fixture.artifact, kind, &wrong_identity).is_err());
            let untrusted = fixture.trust(&report.signature, &fixture.other)?;
            assert!(verify(&fixture.artifact, kind, &untrusted).is_err());
            let trust = fixture.trust(&report.signature, &fixture.reviewer)?;
            fs::write(&fixture.artifact, b"changed artifact\n")?;
            assert!(verify(&fixture.artifact, kind, &trust).is_err());
            assert!(verify_digest(kind, &"0".repeat(64), &trust).is_err());
            fs::write(&fixture.artifact, b"review artifact\n")?;
            let mut signature = fs::read(&report.signature)?;
            signature[40] ^= 1;
            fs::write(&report.signature, signature)?;
            assert!(verify(&fixture.artifact, kind, &trust).is_err());
        }
        Ok(())
    }

    #[test]
    fn gate_private_keys_aliases_and_copies_cannot_sign() -> Result<()> {
        let fixture = Fixture::new()?;
        let gate = fixture.source.join(".pijul/patchgate");
        fs::create_dir_all(&gate)?;
        fs::copy(&fixture.other, gate.join("key"))?;
        fs::copy(fixture.other.with_extension("pub"), gate.join("key.pub"))?;
        fs::set_permissions(gate.join("key"), fs::Permissions::from_mode(0o000))?;
        let output = fixture.root.join("signature");
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &gate.join("key"),
                &output
            )
            .is_err()
        );
        assert!(
            sign(
                &fixture.source,
                &gate.join("key"),
                Kind::Bundle,
                &fixture.reviewer,
                &output
            )
            .is_err()
        );
        let directory_alias = fixture.source.join(".PIJUL/patchgate/key");
        if directory_alias.is_file() {
            assert!(
                sign(
                    &fixture.source,
                    &fixture.artifact,
                    Kind::Bundle,
                    &directory_alias,
                    &output
                )
                .is_err()
            );
            assert!(
                sign(
                    &fixture.source,
                    &fixture.artifact,
                    Kind::Bundle,
                    &fixture.reviewer,
                    &fixture.source.join(".PIJUL/alias.sig")
                )
                .is_err()
            );
        }
        let alias = fixture.root.join("key-alias");
        fs::hard_link(gate.join("key"), &alias)?;
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &alias,
                &output
            )
            .is_err()
        );
        fs::remove_file(&alias)?;
        symlink(gate.join("key"), &alias)?;
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &alias,
                &output
            )
            .is_err()
        );
        let copy = fixture.root.join("copied-gate-key");
        fs::copy(&fixture.other, &copy)?;
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &copy,
                &output
            )
            .is_err()
        );
        // The separate key works with an unreadable gate private key.
        fixture.sign(Kind::Bundle)?;
        assert!(!output.exists());
        let public = fs::read(gate.join("key.pub"))?;
        fs::write(
            gate.join("key.pub"),
            [public.as_slice(), public.as_slice()].concat(),
        )?;
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &fixture.reviewer,
                &output
            )
            .is_err()
        );
        fs::write(gate.join("key.pub"), &public)?;
        fs::remove_file(gate.join("key.pub"))?;
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &fixture.reviewer,
                &output
            )
            .is_err()
        );
        fs::set_permissions(gate.join("key"), fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[test]
    fn outputs_and_regular_inputs_reject_links_and_replacement() -> Result<()> {
        let fixture = Fixture::new()?;
        let report = fixture.sign(Kind::Bundle)?;
        let before = fs::read(&report.signature)?;
        assert!(fixture.sign(Kind::Bundle).is_err());
        assert_eq!(fs::read(&report.signature)?, before);
        for output in [
            &fixture.artifact,
            &fixture.reviewer,
            &fixture.source.join(".pijul/new-signature"),
        ] {
            assert!(
                sign(
                    &fixture.source,
                    &fixture.artifact,
                    Kind::Bundle,
                    &fixture.reviewer,
                    output
                )
                .is_err()
            );
        }
        let linked = fixture.root.join("linked-directory");
        symlink(&fixture.source, &linked)?;
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &fixture.reviewer,
                &linked.join("signature")
            )
            .is_err()
        );
        let trust = fixture.trust(&report.signature, &fixture.reviewer)?;
        let allowlist_before = fs::read(&trust.allowed_signers)?;
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &fixture.reviewer,
                &trust.allowed_signers
            )
            .is_err()
        );
        assert_eq!(fs::read(&trust.allowed_signers)?, allowlist_before);
        let artifact_link = fixture.root.join("artifact-link");
        symlink(&fixture.artifact, &artifact_link)?;
        assert!(verify(&artifact_link, Kind::Bundle, &trust).is_err());
        assert!(verify(&fixture.source, Kind::Bundle, &trust).is_err());
        Ok(())
    }

    #[test]
    fn public_gate_identity_alone_excludes_a_copied_private_key() -> Result<()> {
        let fixture = Fixture::new()?;
        let gate = fixture.source.join(".pijul/patchgate");
        fs::create_dir_all(&gate)?;
        fs::copy(fixture.other.with_extension("pub"), gate.join("key.pub"))?;
        let output = fixture.root.join("signature");
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &fixture.other,
                &output
            )
            .is_err()
        );
        fixture.sign(Kind::Bundle)?;
        assert!(!gate.join("key").exists());
        Ok(())
    }

    #[test]
    fn explicit_private_key_is_required_without_agent_or_prompt() -> Result<()> {
        let fixture = Fixture::new()?;
        let output = fixture.root.join("signature");
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &fixture.reviewer.with_extension("pub"),
                &output
            )
            .is_err()
        );
        let encrypted = fixture.root.join("encrypted-reviewer");
        let tools = Tools::new()?;
        tools.execute(
            tools
                .command()
                .args(["-q", "-t", "ed25519", "-N", "fixture-passphrase", "-f"])
                .arg(&encrypted),
        )?;
        assert!(
            sign(
                &fixture.source,
                &fixture.artifact,
                Kind::Bundle,
                &encrypted,
                &output
            )
            .is_err()
        );
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn digest_verification_uses_the_exact_caller_snapshot() -> Result<()> {
        let fixture = Fixture::new()?;
        let report = fixture.sign(Kind::Baseline)?;
        let trust = fixture.trust(&report.signature, &fixture.reviewer)?;
        let snapshot = fs::read(&fixture.artifact)?;
        fs::write(&fixture.artifact, b"later data\n")?;
        let verified = verify_digest(Kind::Baseline, &digest(snapshot.as_slice())?, &trust)?;
        assert_eq!(verified.sha256, report.sha256);
        assert!(!verified.authorizes_acceptance);
        assert!(verify(&fixture.artifact, Kind::Baseline, &trust).is_err());
        let mut wildcard = trust;
        wildcard.identity = "*@example.test".to_owned();
        assert!(verify_digest(Kind::Baseline, &report.sha256, &wildcard).is_err());
        Ok(())
    }

    #[test]
    fn nested_sources_exclude_the_enclosing_gate_identity() -> Result<()> {
        let fixture = Fixture::new()?;
        let gate = fixture.source.join(".pijul/patchgate");
        fs::create_dir_all(&gate)?;
        fs::copy(&fixture.other, gate.join("key"))?;
        fs::copy(fixture.other.with_extension("pub"), gate.join("key.pub"))?;
        fs::set_permissions(gate.join("key"), fs::Permissions::from_mode(0o000))?;
        let nested = fixture.source.join("work/nested");
        fs::create_dir_all(&nested)?;
        let copied = fixture.root.join("copied-gate-key");
        fs::copy(&fixture.other, &copied)?;
        let output = fixture.root.join("nested.sig");
        assert!(sign(&nested, &fixture.artifact, Kind::Bundle, &copied, &output).is_err());
        assert!(!output.exists());
        let report = sign(
            &nested,
            &fixture.artifact,
            Kind::Bundle,
            &fixture.reviewer,
            &output,
        )?;
        let trust = fixture.trust(&report.signature, &fixture.reviewer)?;
        assert!(!verify(&fixture.artifact, Kind::Bundle, &trust)?.authorizes_acceptance);
        fs::set_permissions(gate.join("key"), fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[test]
    fn unsafe_enclosing_metadata_is_not_a_non_repository_fallback() -> Result<()> {
        let fixture = Fixture::new()?;
        let nested = fixture.source.join("work/nested");
        fs::create_dir_all(&nested)?;
        let target = fixture.root.join("native");
        fs::create_dir(&target)?;
        let metadata = fixture.source.join(".pijul");
        symlink(&target, &metadata)?;
        let output = fixture.root.join("unsafe.sig");
        assert!(
            sign(
                &nested,
                &fixture.artifact,
                Kind::Bundle,
                &fixture.reviewer,
                &output
            )
            .is_err()
        );
        fs::remove_file(&metadata)?;
        fs::write(&metadata, b"not a metadata directory")?;
        assert!(
            sign(
                &nested,
                &fixture.artifact,
                Kind::Bundle,
                &fixture.reviewer,
                &output
            )
            .is_err()
        );
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn authenticated_snapshots_bind_opaque_bytes_and_own_private_storage() -> Result<()> {
        let fixture = Fixture::new()?;
        // Deliberately not gzip: authentication must not parse the artifact.
        let bytes = b"opaque compressed artifact bytes\0\xff";
        fs::write(&fixture.artifact, bytes)?;
        let report = fixture.sign(Kind::Bundle)?;
        let trust = fixture.trust(&report.signature, &fixture.reviewer)?;
        let authenticated = snapshot(&fixture.artifact, Kind::Bundle, &trust)?;
        let path = authenticated.path().to_path_buf();
        assert_eq!(authenticated.verified.sha256, report.sha256);
        assert_eq!(fs::read(&path)?, bytes);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(path.parent().unwrap())?.permissions().mode() & 0o777,
            0o700
        );
        fs::write(&fixture.artifact, b"replaced source bytes")?;
        assert_eq!(fs::read(&path)?, bytes);
        assert!(snapshot(&fixture.artifact, Kind::Bundle, &trust).is_err());
        drop(authenticated);
        assert!(!path.exists());
        fs::write(&fixture.artifact, bytes)?;
        let mut invalid_signature = fs::read(&trust.signature)?;
        invalid_signature[40] ^= 1;
        fs::write(&trust.signature, invalid_signature)?;
        assert!(snapshot(&fixture.artifact, Kind::Bundle, &trust).is_err());
        Ok(())
    }
}
