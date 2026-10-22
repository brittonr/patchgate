use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Subcommand};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::artifact::{self, Kind, Trust, Verified};

const MAX_CONTROL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Args)]
pub struct BaselineArgs {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    Promote(PromoteArgs),
}

#[derive(Args)]
struct PromoteArgs {
    report: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    allowed_signers: PathBuf,
    #[arg(long)]
    identity: String,
    #[arg(long)]
    store: PathBuf,
    #[arg(short = 'm', long)]
    reason: String,
    #[arg(long)]
    revoked_keys: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    schema_version: u32,
    authorizes_acceptance: bool,
    sequence: u64,
    actor: String,
    time: String,
    reason: String,
    object_sha256: String,
    previous_approval_sha256: Option<String>,
    signature_sha256: String,
    verified: Verified,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Current {
    schema_version: u32,
    authorizes_acceptance: bool,
    sequence: u64,
    approval_sha256: String,
    object_sha256: String,
}

#[derive(Serialize)]
struct PromotionReport {
    schema_version: u32,
    authorizes_acceptance: bool,
    store: PathBuf,
    object: PathBuf,
    object_sha256: String,
    approval: PathBuf,
    approval_sha256: String,
    current: PathBuf,
    sequence: u64,
    actor: String,
    time: String,
    reason: String,
    previous_approval_sha256: Option<String>,
    verified: Verified,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_metadata(actor: &str, reason: &str) -> Result<()> {
    for value in [actor, reason] {
        ensure!(
            !value.trim().is_empty() && !value.chars().any(char::is_control),
            "Baseline approval needs an explicit actor and reason without control characters."
        );
        ensure!(
            crate::secrets::scan_text("[baseline.approval]", value.as_bytes()).is_empty(),
            "Baseline approval metadata contains credential data."
        );
    }
    Ok(())
}

struct Store {
    path: PathBuf,
    directories: Vec<File>,
    missing: Vec<OsString>,
}

impl Store {
    fn open(path: &Path) -> Result<Self> {
        let path = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut resolved = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => ensure!(
                    resolved.pop(),
                    "The baseline store path has an invalid parent."
                ),
                _ => resolved.push(component),
            }
        }
        ensure!(
            resolved.parent().is_some() && resolved.to_str().is_some(),
            "The baseline store path must name a directory with valid Unicode."
        );
        let mut directories = vec![
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/")?,
        ];
        let mut missing = Vec::new();
        for component in resolved.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            if !missing.is_empty() {
                missing.push(name.to_owned());
                continue;
            }
            match open_directory(directories.last().unwrap(), name) {
                Ok(directory) => directories.push(directory),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    missing.push(name.to_owned());
                }
                Err(error) => return Err(error).context("Read the baseline store path."),
            }
        }
        Ok(Self {
            path: resolved,
            directories,
            missing,
        })
    }

    fn directory(&self) -> &File {
        self.directories.last().unwrap()
    }

    fn create(&mut self) -> Result<()> {
        for name in std::mem::take(&mut self.missing) {
            let parent = self.directory();
            let name = CString::new(name.as_bytes())?;
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
            if result != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::last_os_error())
                    .context("Create the private baseline store.");
            }
            let directory = open_directory(parent, OsStr::from_bytes(name.as_bytes()))?;
            private_directory(&directory)?;
            parent.sync_all()?;
            self.directories.push(directory);
        }
        private_directory(self.directory())
    }
}

fn open_at(directory: &File, name: &OsStr, flags: libc::c_int) -> io::Result<File> {
    let name = CString::new(name.as_bytes())?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY)
}

fn create_directory(parent: &File, name: &str) -> Result<File> {
    let raw = CString::new(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), raw.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error()).context("Create a baseline store directory.");
    }
    let directory = open_directory(parent, OsStr::new(name))?;
    private_directory(&directory)?;
    Ok(directory)
}

fn outside_sources(store: &Store, bytes: &[u8]) -> Result<()> {
    #[derive(Deserialize)]
    struct Source {
        repository: PathBuf,
    }
    #[derive(Deserialize)]
    struct Row {
        snapshot: Option<Source>,
    }
    #[derive(Deserialize)]
    struct Policy {
        source_repository: PathBuf,
    }
    #[derive(Deserialize)]
    struct Sources {
        repository: PathBuf,
        release_policy: Option<Policy>,
        comparisons: Vec<Row>,
    }
    let report: Sources =
        serde_json::from_slice(bytes).context("Read the authenticated baseline source paths.")?;
    let repositories = std::iter::once(&report.repository)
        .chain(
            report
                .release_policy
                .iter()
                .map(|policy| &policy.source_repository),
        )
        .chain(
            report
                .comparisons
                .iter()
                .filter_map(|row| row.snapshot.as_ref().map(|snapshot| &snapshot.repository)),
        );
    let mut seen = BTreeSet::new();
    for source in repositories {
        if !seen.insert(source) {
            continue;
        }
        let repository = source
            .to_str()
            .context("A baseline source path is not valid Unicode.")?;
        ensure!(
            source.is_absolute()
                && !repository.chars().any(char::is_control)
                && source.components().all(|component| {
                    matches!(component, Component::RootDir | Component::Normal(_))
                }),
            "A baseline source repository path is not safe."
        );
        ensure!(
            !store.path.starts_with(source),
            "The baseline store must remain outside each source repository."
        );
        let source = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(source)
        {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("Read a baseline source directory."),
        };
        let expected = source.metadata()?;
        // Compare the retained ancestors, not names below a mutable parent.
        for directory in &store.directories {
            let actual = directory.metadata()?;
            ensure!(
                actual.dev() != expected.dev() || actual.ino() != expected.ino(),
                "The baseline store must remain outside each source repository."
            );
        }
    }
    Ok(())
}

fn private_directory(directory: &File) -> Result<()> {
    let metadata = directory
        .metadata()
        .context("Read a baseline store directory.")?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "Baseline store directories must be private directories without links."
    );
    Ok(())
}

fn regular_metadata(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o7777 == 0o600,
        "Baseline store files must be private regular files without aliases."
    );
    Ok(())
}

fn open_regular(directory: &File, name: &str) -> Result<File> {
    let file = open_at(directory, OsStr::new(name), libc::O_RDONLY)
        .context("Read a baseline store file.")?;
    regular_metadata(&file.metadata()?)?;
    Ok(file)
}

fn read_bytes(directory: &File, name: &str, limit: Option<u64>) -> Result<Vec<u8>> {
    let file = open_regular(directory, name)?;
    let mut bytes = Vec::new();
    match limit {
        Some(limit) => {
            file.take(limit + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= limit,
                "A baseline store control file is too large."
            );
        }
        None => {
            let mut file = file;
            file.read_to_end(&mut bytes)?;
        }
    }
    Ok(bytes)
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn entries(directory: &File) -> Result<BTreeSet<String>> {
    private_directory(directory)?;
    let descriptor = open_directory(directory, OsStr::new("."))?.into_raw_fd();
    let pointer = unsafe { libc::fdopendir(descriptor) };
    if pointer.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(descriptor) };
        return Err(error).context("Read a baseline store directory.");
    }
    let stream = DirectoryStream(pointer);
    let mut names = BTreeSet::new();
    loop {
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            ensure!(
                error.raw_os_error().unwrap_or(0) == 0,
                "Read a baseline store directory entry."
            );
            return Ok(names);
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.insert(
                name.to_str()
                    .context("A baseline store entry name is not valid.")?
                    .to_owned(),
            );
        }
    }
}

fn exists(directory: &File, name: &str) -> Result<bool> {
    let name = CString::new(name)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        return Ok(false);
    }
    Err(error).context("Read a baseline store entry.")
}

fn lock_store(directory: &File) -> Result<File> {
    let names = entries(directory)?;
    ensure!(
        names.is_empty() || names.contains("lock"),
        "An existing baseline store has no operation lock."
    );
    let file = match open_at(
        directory,
        OsStr::new("lock"),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
    ) {
        Ok(file) => {
            file.sync_all()?;
            directory.sync_all()?;
            file
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            open_at(directory, OsStr::new("lock"), libc::O_RDWR)
                .context("Read the baseline operation lock.")?
        }
        Err(error) => return Err(error).context("Create the baseline operation lock."),
    };
    regular_metadata(&file.metadata()?)?;
    ensure!(
        file.metadata()?.len() == 0,
        "The baseline operation lock is corrupt."
    );
    FileExt::lock_exclusive(&file)?;
    let current = open_regular(directory, "lock")?.metadata()?;
    ensure!(
        current.dev() == file.metadata()?.dev() && current.ino() == file.metadata()?.ino(),
        "The baseline operation lock changed during access."
    );
    private_directory(directory)?;
    Ok(file)
}

fn initialize_store(directory: &File) -> Result<()> {
    let names = entries(directory)?;
    if names.len() == 1 && names.contains("lock") {
        for name in ["objects", "approvals"] {
            create_directory(directory, name)?.sync_all()?;
        }
        directory.sync_all()?;
        return Ok(());
    }
    ensure!(
        names.contains("lock")
            && names.contains("objects")
            && names.contains("approvals")
            && names.iter().all(|name| {
                matches!(
                    name.as_str(),
                    "lock" | "objects" | "approvals" | "current.json"
                )
            }),
        "The baseline store is partial or contains unknown entries."
    );
    Ok(())
}

fn validate_approval(approvals: &File, id: &str, objects: &BTreeSet<String>) -> Result<Approval> {
    let directory = open_directory(approvals, OsStr::new(id))?;
    let names = entries(&directory)?;
    let bytes = read_bytes(&directory, "approval.json", Some(MAX_CONTROL_BYTES))?;
    ensure!(
        digest(&bytes) == id,
        "A baseline approval identity is corrupt."
    );
    let approval: Approval =
        serde_json::from_slice(&bytes).context("Read a baseline approval record.")?;
    validate_metadata(&approval.actor, &approval.reason)?;
    ensure!(
        approval.schema_version == 1
            && !approval.authorizes_acceptance
            && approval.sequence > 0
            && chrono::DateTime::parse_from_rfc3339(&approval.time).is_ok()
            && valid_digest(&approval.object_sha256)
            && valid_digest(&approval.signature_sha256)
            && approval
                .previous_approval_sha256
                .as_deref()
                .is_none_or(valid_digest)
            && objects.contains(&approval.object_sha256)
            && approval.actor == approval.verified.identity,
        "A baseline approval record is not valid."
    );
    let mut expected: BTreeSet<String> = ["approval.json", "signature", "allowed-signers"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if approval.verified.revoked_keys_sha256.is_some() {
        expected.insert("revoked-keys".into());
    }
    ensure!(
        names == expected,
        "Baseline approval evidence is partial or corrupt."
    );
    let signature = read_bytes(&directory, "signature", Some(MAX_CONTROL_BYTES))?;
    let allowed = read_bytes(&directory, "allowed-signers", Some(MAX_CONTROL_BYTES))?;
    ensure!(
        digest(&signature) == approval.signature_sha256
            && digest(&allowed) == approval.verified.allowed_signers_sha256,
        "Baseline approval evidence has a corrupt identity."
    );
    // Verify only the evidence bytes read through the retained directory descriptor.
    let revoked = approval
        .verified
        .revoked_keys_sha256
        .as_ref()
        .map(|expected| -> Result<Vec<u8>> {
            let bytes = read_bytes(&directory, "revoked-keys", Some(MAX_CONTROL_BYTES))?;
            ensure!(
                digest(&bytes) == *expected,
                "Baseline revocation evidence is corrupt."
            );
            Ok(bytes)
        })
        .transpose()?;
    let verified = artifact::verify_digest_bytes(
        Kind::Baseline,
        &approval.object_sha256,
        &approval.actor,
        &signature,
        &allowed,
        revoked.as_deref(),
    )
    .map_err(|_| anyhow::anyhow!("Baseline approval signature evidence is not valid."))?;
    ensure!(
        serde_json::to_value(&verified)? == serde_json::to_value(&approval.verified)?,
        "The baseline approval has false signer evidence."
    );
    Ok(approval)
}

struct History {
    current: Option<Current>,
    objects: File,
    approvals: File,
}

fn validate_store(store: &Store) -> Result<History> {
    initialize_store(store.directory())?;
    let object_directory = open_directory(store.directory(), OsStr::new("objects"))?;
    let approval_directory = open_directory(store.directory(), OsStr::new("approvals"))?;
    let mut objects = BTreeSet::new();
    for name in entries(&object_directory)? {
        let id = name
            .strip_suffix(".json")
            .filter(|id| valid_digest(id))
            .context("A baseline object name is not valid.")?;
        let bytes = read_bytes(&object_directory, &name, None)?;
        ensure!(
            digest(&bytes) == id,
            "A baseline object identity is corrupt."
        );
        super::replay::validate_promotion_report(&bytes)?;
        outside_sources(store, &bytes)?;
        objects.insert(id.to_owned());
    }
    let mut approvals = BTreeMap::new();
    for id in entries(&approval_directory)? {
        ensure!(valid_digest(&id), "A baseline approval name is not valid.");
        approvals.insert(
            id.clone(),
            validate_approval(&approval_directory, &id, &objects)?,
        );
    }
    if !exists(store.directory(), "current.json")? {
        ensure!(
            approvals.is_empty() && objects.is_empty(),
            "The baseline store has no current pointer."
        );
        return Ok(History {
            current: None,
            objects: object_directory,
            approvals: approval_directory,
        });
    }
    let current: Current = serde_json::from_slice(&read_bytes(
        store.directory(),
        "current.json",
        Some(MAX_CONTROL_BYTES),
    )?)
    .context("Read the current baseline pointer.")?;
    ensure!(
        current.schema_version == 1
            && !current.authorizes_acceptance
            && current.sequence > 0
            && valid_digest(&current.approval_sha256)
            && valid_digest(&current.object_sha256),
        "The current baseline pointer is not valid."
    );
    let mut id = Some(current.approval_sha256.as_str());
    let mut sequence = current.sequence;
    let mut visited = BTreeSet::new();
    while let Some(next) = id {
        ensure!(
            visited.insert(next),
            "The baseline approval history contains a cycle."
        );
        let approval = approvals
            .get(next)
            .context("The baseline approval history is incomplete.")?;
        ensure!(
            approval.sequence == sequence
                && (sequence != current.sequence
                    || approval.object_sha256 == current.object_sha256),
            "The baseline approval order or current object is corrupt."
        );
        sequence = sequence
            .checked_sub(1)
            .context("The baseline approval order is corrupt.")?;
        id = approval.previous_approval_sha256.as_deref();
    }
    ensure!(
        sequence == 0 && visited.len() == approvals.len(),
        "The baseline approval history is partial or contains an unordered branch."
    );
    Ok(History {
        current: Some(current),
        objects: object_directory,
        approvals: approval_directory,
    })
}

fn private_file(directory: &File, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = open_at(
        directory,
        OsStr::new(name),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

struct StagedEntry<'a> {
    parent: &'a File,
    name: CString,
    directory: Option<File>,
    active: bool,
}

impl<'a> StagedEntry<'a> {
    fn file(parent: &'a File, name: &str, bytes: &[u8]) -> Result<Self> {
        let mut file = open_at(
            parent,
            OsStr::new(name),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let staged = Self {
            parent,
            name: CString::new(name)?,
            directory: None,
            active: true,
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(staged)
    }

    fn directory(parent: &'a File, name: &str) -> Result<Self> {
        Ok(Self {
            parent,
            name: CString::new(name)?,
            directory: Some(create_directory(parent, name)?),
            active: true,
        })
    }

    fn publish_new_file(mut self, name: &str) -> Result<()> {
        let name = CString::new(name)?;
        if unsafe {
            libc::linkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                self.parent.as_raw_fd(),
                name.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error()).context("Publish a new baseline object.");
        }
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error()).context("Remove a baseline object stage.");
        }
        self.active = false;
        self.parent.sync_all()?;
        Ok(())
    }

    fn rename(mut self, name: &str, replace: bool) -> Result<()> {
        let name = CString::new(name)?;
        let descriptor = self.parent.as_raw_fd();
        let result = if replace {
            unsafe { libc::renameat(descriptor, self.name.as_ptr(), descriptor, name.as_ptr()) }
        } else {
            #[cfg(target_os = "macos")]
            let result = unsafe {
                libc::renameatx_np(
                    descriptor,
                    self.name.as_ptr(),
                    descriptor,
                    name.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(target_os = "linux")]
            let result = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    descriptor,
                    self.name.as_ptr(),
                    descriptor,
                    name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                ) as libc::c_int
            };
            result
        };
        if result != 0 {
            return Err(io::Error::last_os_error()).context("Publish baseline approval data.");
        }
        self.active = false;
        self.parent.sync_all()?;
        Ok(())
    }
}

impl Drop for StagedEntry<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(directory) = &self.directory {
            for name in [
                c"approval.json",
                c"signature",
                c"allowed-signers",
                c"revoked-keys",
            ] {
                unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
            }
        }
        let flags = if self.directory.is_some() {
            libc::AT_REMOVEDIR
        } else {
            0
        };
        unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), flags) };
    }
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= MAX_CONTROL_BYTES,
        "Baseline approval metadata is too large."
    );
    Ok(bytes)
}

struct PreparedPromotion {
    authenticated: artifact::VerifiedSnapshot,
    bytes: Vec<u8>,
    store: Store,
}

fn prepare_promotion(args: &PromoteArgs) -> Result<PreparedPromotion> {
    validate_metadata(&args.identity, &args.reason)?;
    let authenticated = artifact::snapshot(
        &args.report,
        Kind::Baseline,
        &Trust {
            signature: args.signature.clone(),
            allowed_signers: args.allowed_signers.clone(),
            identity: args.identity.clone(),
            revoked_keys: args.revoked_keys.clone(),
        },
    )?;
    let bytes = fs::read(authenticated.path()).context("Read the private baseline report.")?;
    super::replay::validate_promotion_report(&bytes)?;
    let store = Store::open(&args.store)?;
    outside_sources(&store, &bytes)?;
    Ok(PreparedPromotion {
        authenticated,
        bytes,
        store,
    })
}

fn publish_promotion(args: &PromoteArgs, prepared: PreparedPromotion) -> Result<PromotionReport> {
    let PreparedPromotion {
        authenticated,
        bytes,
        mut store,
    } = prepared;
    store.create()?;
    let _lock = lock_store(store.directory())?;
    let History {
        current: previous,
        objects,
        approvals,
    } = validate_store(&store)?;
    let sequence = previous
        .as_ref()
        .map_or(Some(1), |current| current.sequence.checked_add(1))
        .context("The baseline approval sequence is too large.")?;
    let approval = Approval {
        schema_version: 1,
        authorizes_acceptance: false,
        sequence,
        actor: args.identity.clone(),
        time: Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true),
        reason: args.reason.clone(),
        object_sha256: authenticated.verified.sha256.clone(),
        previous_approval_sha256: previous.map(|current| current.approval_sha256),
        signature_sha256: digest(authenticated.signature()),
        verified: authenticated.verified.clone(),
    };
    let approval_bytes = json_bytes(&approval)?;
    let approval_sha256 = digest(&approval_bytes);
    let object_name = format!("{}.json", approval.object_sha256);
    let object = store.path.join("objects").join(&object_name);
    let approval_directory = store.path.join("approvals").join(&approval_sha256);
    let current = Current {
        schema_version: 1,
        authorizes_acceptance: false,
        sequence,
        approval_sha256: approval_sha256.clone(),
        object_sha256: approval.object_sha256.clone(),
    };
    let current_bytes = json_bytes(&current)?;
    let result = PromotionReport {
        schema_version: 1,
        authorizes_acceptance: false,
        store: store.path.clone(),
        object: object.clone(),
        object_sha256: approval.object_sha256.clone(),
        approval: approval_directory.join("approval.json"),
        approval_sha256,
        current: store.path.join("current.json"),
        sequence,
        actor: approval.actor.clone(),
        time: approval.time.clone(),
        reason: approval.reason.clone(),
        previous_approval_sha256: approval.previous_approval_sha256.clone(),
        verified: approval.verified.clone(),
    };
    let staged =
        StagedEntry::directory(&approvals, &format!(".approval-{}", result.approval_sha256))?;
    let directory = staged.directory.as_ref().unwrap();
    private_file(directory, "approval.json", &approval_bytes)?;
    private_file(directory, "signature", authenticated.signature())?;
    private_file(
        directory,
        "allowed-signers",
        authenticated.allowed_signers(),
    )?;
    if let Some(revoked) = authenticated.revoked_keys() {
        private_file(directory, "revoked-keys", revoked)?;
    }
    directory.sync_all()?;
    let pointer = StagedEntry::file(
        store.directory(),
        &format!(".current-{}", result.approval_sha256),
        &current_bytes,
    )?;
    if exists(&objects, &object_name)? {
        ensure!(
            read_bytes(&objects, &object_name, None)? == bytes,
            "An existing baseline object has different bytes."
        );
    } else {
        StagedEntry::file(
            &objects,
            &format!(".object-{}", result.approval_sha256),
            &bytes,
        )?
        .publish_new_file(&object_name)?;
    }
    staged.rename(&result.approval_sha256, false)?;
    store.directory().sync_all()?;
    // The atomic pointer replacement is the final commit operation.
    pointer.rename("current.json", true)?;
    Ok(result)
}

fn promote(args: &PromoteArgs) -> Result<PromotionReport> {
    publish_promotion(args, prepare_promotion(args)?)
}

pub fn run(args: BaselineArgs) -> Result<()> {
    match args.command {
        Action::Promote(args) => {
            let report = promote(&args)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Schema version: {}", report.schema_version);
                println!("Authorizes acceptance: {}", report.authorizes_acceptance);
                println!("Baseline object: {}", report.object.display());
                println!("Object SHA-256: {}", report.object_sha256);
                println!("Approval: {}", report.approval.display());
                println!("Approval SHA-256: {}", report.approval_sha256);
                println!("Approval sequence: {}", report.sequence);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::os::unix::fs::symlink;
    use std::process::{Command, Stdio};

    struct Fixture {
        _directory: tempfile::TempDir,
        root: PathBuf,
        source: PathBuf,
        report: PathBuf,
        signature: PathBuf,
        allowed_signers: PathBuf,
        reviewer: PathBuf,
        fingerprint: String,
    }

    fn key(path: &Path) -> Result<()> {
        let output = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "fixture", "-f"])
            .arg(path)
            .stdin(Stdio::null())
            .output()?;
        ensure!(output.status.success(), "Create the test signing key.");
        Ok(())
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let directory = tempfile::tempdir()?;
            let root = fs::canonicalize(directory.path())?;
            let source = root.join("source");
            fs::create_dir(&source)?;
            fs::write(source.join("source.txt"), b"Retain the source bytes.\n")?;
            let reviewer = root.join("reviewer");
            key(&reviewer)?;
            let allowed_signers = root.join("allowed-signers");
            fs::write(
                &allowed_signers,
                format!(
                    "reviewer@example.test {}",
                    fs::read_to_string(reviewer.with_extension("pub"))?
                ),
            )?;
            let mut report: Value =
                serde_json::from_slice(&crate::replay::successful_promotion_report())?;
            report["repository"] = serde_json::to_value(&source)?;
            let report_path = root.join("report.json");
            fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
            let signature = root.join("report.sig");
            let signed =
                artifact::sign(&source, &report_path, Kind::Baseline, &reviewer, &signature)?;
            Ok(Self {
                _directory: directory,
                root,
                source,
                report: report_path,
                signature,
                allowed_signers,
                reviewer,
                fingerprint: signed.signer_fingerprint,
            })
        }

        fn args(&self, reason: &str) -> PromoteArgs {
            PromoteArgs {
                report: self.report.clone(),
                signature: self.signature.clone(),
                allowed_signers: self.allowed_signers.clone(),
                identity: "reviewer@example.test".into(),
                store: self.root.join("baselines"),
                reason: reason.into(),
                revoked_keys: None,
                json: true,
            }
        }

        fn sign_report(&self, report: &[u8]) -> Result<()> {
            fs::write(&self.report, report)?;
            fs::remove_file(&self.signature)?;
            artifact::sign(
                &self.source,
                &self.report,
                Kind::Baseline,
                &self.reviewer,
                &self.signature,
            )?;
            Ok(())
        }
    }

    #[test]
    fn signed_promotions_preserve_exact_objects_evidence_and_approvals() -> Result<()> {
        let fixture = Fixture::new()?;
        let args = fixture.args("The reviewer approves the release baseline.");
        let bytes = fs::read(&fixture.report)?;
        let signature = fs::read(&fixture.signature)?;
        let allowed = fs::read(&fixture.allowed_signers)?;
        let first = promote(&args)?;
        let first_approval = fs::read(&first.approval)?;
        assert_eq!(first.sequence, 1);
        assert!(!first.authorizes_acceptance);
        assert!(!first.verified.authorizes_acceptance);
        assert_eq!(first.actor, args.identity);
        assert_eq!(first.reason, args.reason);
        assert_eq!(first.verified.signer_fingerprint, fixture.fingerprint);
        assert_eq!(first.object_sha256, digest(&bytes));
        assert_eq!(fs::read(&first.object)?, bytes);
        assert_eq!(
            fs::read(first.approval.parent().unwrap().join("signature"))?,
            signature
        );
        assert_eq!(
            fs::read(first.approval.parent().unwrap().join("allowed-signers"))?,
            allowed
        );
        let second = promote(&fixture.args("The reviewer confirms the release baseline."))?;
        assert_eq!(second.sequence, 2);
        assert_eq!(
            second.previous_approval_sha256.as_deref(),
            Some(first.approval_sha256.as_str())
        );
        assert_eq!(fs::read(&first.approval)?, first_approval);
        assert_eq!(fs::read(&first.object)?, bytes);
        assert_eq!(
            fs::read(fixture.source.join("source.txt"))?,
            b"Retain the source bytes.\n"
        );
        let store = Store::open(&first.store)?;
        let _lock = lock_store(store.directory())?;
        let history = validate_store(&store)?;
        assert_eq!(entries(&history.objects)?.len(), 1);
        assert_eq!(entries(&history.approvals)?.len(), 2);
        let current = history.current.unwrap();
        assert_eq!(current.approval_sha256, second.approval_sha256);
        assert_eq!(current.object_sha256, first.object_sha256);
        assert_eq!(
            fs::metadata(&first.store)?.permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(&first.object)?.permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(&first.approval)?.permissions().mode() & 0o7777,
            0o600
        );
        Ok(())
    }

    #[test]
    fn invalid_signatures_reports_metadata_and_source_paths_publish_nothing() -> Result<()> {
        let fixture = Fixture::new()?;
        let args = fixture.args("The reviewer approves the release baseline.");
        let original = fs::read(&fixture.report)?;
        let mut invalid = fixture.args("The reviewer approves the release baseline.");
        invalid.signature = fixture.root.join("invalid-signature-input.json");
        fs::write(&invalid.signature, b"Invalid detached signature.")?;
        assert!(promote(&invalid).is_err());
        assert!(!invalid.store.exists());
        let mut changed = original.clone();
        changed.push(b' ');
        fs::write(&fixture.report, changed)?;
        assert!(promote(&args).is_err());
        assert!(!args.store.exists());
        let mut failed: Value = serde_json::from_slice(&original)?;
        failed["gate"]["passed"] = Value::Bool(false);
        fixture.sign_report(&serde_json::to_vec(&failed)?)?;
        assert!(promote(&args).is_err());
        assert!(!args.store.exists());
        fixture.sign_report(&original)?;
        for reason in ["", "A reason\nwith controls."] {
            assert!(promote(&fixture.args(reason)).is_err());
        }
        let secret = format!("ghp_{}", "A".repeat(36));
        assert!(promote(&fixture.args(&secret)).is_err());
        assert!(!args.store.exists());
        let mut unsafe_store = fixture.args("The reviewer approves the release baseline.");
        unsafe_store.store = fixture.source.join("baselines");
        assert!(promote(&unsafe_store).is_err());
        assert!(!unsafe_store.store.exists());
        let alias = fixture.root.join("source-alias");
        symlink(&fixture.source, &alias)?;
        unsafe_store.store = alias.join("baselines");
        assert!(promote(&unsafe_store).is_err());
        assert!(!fixture.source.join("baselines").exists());
        let mut aliased_report: Value = serde_json::from_slice(&original)?;
        aliased_report["repository"] = serde_json::to_value(&alias)?;
        let pinned = Store::open(&fixture.source.join("baselines"))?;
        assert!(outside_sources(&pinned, &serde_json::to_vec(&aliased_report)?).is_err());
        let case_alias = fixture.root.join("SOURCE");
        if case_alias.is_dir() {
            unsafe_store.store = case_alias.join("baselines");
            assert!(promote(&unsafe_store).is_err());
            assert!(!fixture.source.join("baselines").exists());
        }
        let promoted = promote(&args)?;
        let pointer = fs::read(&promoted.current)?;
        let approval = fs::read(&promoted.approval)?;
        fixture.sign_report(&serde_json::to_vec(&failed)?)?;
        assert!(promote(&args).is_err());
        assert_eq!(fs::read(&promoted.current)?, pointer);
        assert_eq!(fs::read(&promoted.approval)?, approval);
        let mut invalid_bytes = fs::read(&fixture.report)?;
        invalid_bytes.push(b' ');
        fs::write(&fixture.report, invalid_bytes)?;
        assert!(promote(&args).is_err());
        assert_eq!(fs::read(&promoted.current)?, pointer);
        assert_eq!(fs::read(&promoted.approval)?, approval);
        let store = Store::open(&promoted.store)?;
        let _lock = lock_store(store.directory())?;
        let history = validate_store(&store)?;
        assert_eq!(history.current.unwrap().sequence, 1);
        assert_eq!(entries(&history.objects)?.len(), 1);
        assert_eq!(entries(&history.approvals)?.len(), 1);
        Ok(())
    }

    #[test]
    fn replaced_parent_cannot_redirect_new_store_into_source() -> Result<()> {
        let fixture = Fixture::new()?;
        let parent = fixture.root.join("mutable-parent");
        let retained = fixture.root.join("retained-parent");
        fs::create_dir(&parent)?;
        let mut args = fixture.args("The reviewer approves the release baseline.");
        args.store = parent.join("nested").join("baselines");
        let prepared = prepare_promotion(&args)?;
        fs::rename(&parent, &retained)?;
        symlink(&fixture.source, &parent)?;
        let promoted = publish_promotion(&args, prepared)?;
        assert!(!fixture.source.join("nested").exists());
        let actual = retained.join("nested").join("baselines");
        let store = Store::open(&actual)?;
        let _lock = lock_store(store.directory())?;
        let history = validate_store(&store)?;
        assert_eq!(
            history.current.unwrap().approval_sha256,
            promoted.approval_sha256
        );
        assert_eq!(entries(&history.objects)?.len(), 1);
        assert_eq!(entries(&history.approvals)?.len(), 1);
        assert_eq!(
            fs::read(
                actual
                    .join("objects")
                    .join(format!("{}.json", promoted.object_sha256))
            )?,
            fs::read(&fixture.report)?
        );
        assert_eq!(
            fs::read(fixture.source.join("source.txt"))?,
            b"Retain the source bytes.\n"
        );
        Ok(())
    }

    #[test]
    fn replaced_parent_preserves_existing_store_evidence_and_history() -> Result<()> {
        let fixture = Fixture::new()?;
        let parent = fixture.root.join("mutable-parent");
        let retained = fixture.root.join("retained-parent");
        fs::create_dir(&parent)?;
        let mut args = fixture.args("The reviewer approves the release baseline.");
        args.store = parent.join("baselines");
        let first = promote(&args)?;
        let approval_bytes = fs::read(&first.approval)?;
        let object_bytes = fs::read(&first.object)?;
        args.reason = "The reviewer confirms the release baseline.".into();
        let prepared = prepare_promotion(&args)?;
        fs::rename(&parent, &retained)?;
        symlink(&fixture.source, &parent)?;
        let second = publish_promotion(&args, prepared)?;
        assert!(!fixture.source.join("baselines").exists());
        assert_eq!(second.sequence, 2);
        assert_eq!(
            second.previous_approval_sha256.as_deref(),
            Some(first.approval_sha256.as_str())
        );
        let actual = retained.join("baselines");
        assert_eq!(
            fs::read(
                actual
                    .join("approvals")
                    .join(first.approval_sha256)
                    .join("approval.json")
            )?,
            approval_bytes
        );
        assert_eq!(
            fs::read(
                actual
                    .join("objects")
                    .join(format!("{}.json", first.object_sha256))
            )?,
            object_bytes
        );
        let store = Store::open(&actual)?;
        let _lock = lock_store(store.directory())?;
        let history = validate_store(&store)?;
        assert_eq!(
            history.current.unwrap().approval_sha256,
            second.approval_sha256
        );
        assert_eq!(entries(&history.objects)?.len(), 1);
        assert_eq!(entries(&history.approvals)?.len(), 2);
        Ok(())
    }

    #[test]
    fn concurrent_promotions_retain_one_complete_ordered_history() -> Result<()> {
        let fixture = Fixture::new()?;
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|index| {
                    let args = fixture.args(&format!("The reviewer approves release {index}."));
                    scope.spawn(move || promote(&args))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("The promotion thread failed."))
                .collect::<Result<Vec<_>>>()
        })?;
        let sequences: BTreeSet<_> = results.iter().map(|report| report.sequence).collect();
        assert_eq!(sequences, BTreeSet::from([1, 2, 3, 4]));
        let store = Store::open(&results[0].store)?;
        let _lock = lock_store(store.directory())?;
        let history = validate_store(&store)?;
        assert_eq!(history.current.unwrap().sequence, 4);
        assert_eq!(entries(&history.approvals)?.len(), 4);
        assert_eq!(entries(&history.objects)?.len(), 1);
        Ok(())
    }

    #[test]
    fn corrupt_stores_fail_without_pointer_repair_or_new_authority() -> Result<()> {
        let fixture = Fixture::new()?;
        let args = fixture.args("The reviewer approves the release baseline.");
        let first = promote(&args)?;
        let pointer = fs::read(&first.current)?;
        let object = fs::read(&first.object)?;
        fs::write(&first.object, b"Altered object bytes.")?;
        assert!(promote(&args).is_err());
        assert_eq!(fs::read(&first.current)?, pointer);
        fs::write(&first.object, object)?;
        let alias = fixture.root.join("object-alias");
        fs::hard_link(&first.object, &alias)?;
        assert!(promote(&args).is_err());
        assert_eq!(fs::read(&first.current)?, pointer);
        fs::remove_file(alias)?;
        let signature_path = first.approval.parent().unwrap().join("signature");
        let signature = fs::read(&signature_path)?;
        fs::write(&signature_path, b"Altered signature bytes.")?;
        assert!(promote(&args).is_err());
        assert_eq!(fs::read(&first.current)?, pointer);
        fs::write(signature_path, signature)?;
        let mut corrupt: Value = serde_json::from_slice(&pointer)?;
        corrupt["sequence"] = Value::from(0);
        let corrupt = serde_json::to_vec(&corrupt)?;
        fs::write(&first.current, &corrupt)?;
        assert!(promote(&args).is_err());
        assert_eq!(fs::read(&first.current)?, corrupt);
        fs::write(&first.current, &pointer)?;
        fs::remove_file(first.store.join("lock"))?;
        assert!(promote(&args).is_err());
        assert!(!first.store.join("lock").exists());
        assert_eq!(fs::read(&first.current)?, pointer);
        assert_eq!(
            entries(Store::open(&first.store.join("approvals"))?.directory())?.len(),
            1
        );
        Ok(())
    }

    #[test]
    fn revocation_evidence_is_exact_and_revoked_signers_cannot_promote() -> Result<()> {
        let fixture = Fixture::new()?;
        let other = fixture.root.join("other");
        key(&other)?;
        let revocations = fixture.root.join("revoked-keys");
        let original = fs::read(other.with_extension("pub"))?;
        fs::write(&revocations, &original)?;
        let mut args = fixture.args("The reviewer approves the release baseline.");
        args.revoked_keys = Some(revocations.clone());
        let first = promote(&args)?;
        assert_eq!(
            first.verified.revoked_keys_sha256.as_deref(),
            Some(digest(&original).as_str())
        );
        let stored_revocations = first.approval.parent().unwrap().join("revoked-keys");
        assert_eq!(fs::read(&stored_revocations)?, original);
        let pointer = fs::read(&first.current)?;
        fs::write(
            &revocations,
            fs::read(fixture.reviewer.with_extension("pub"))?,
        )?;
        assert!(promote(&args).is_err());
        assert_eq!(fs::read(&first.current)?, pointer);
        assert_eq!(fs::read(&stored_revocations)?, original);
        assert_eq!(
            entries(Store::open(&first.store.join("approvals"))?.directory())?.len(),
            1
        );
        Ok(())
    }
}
