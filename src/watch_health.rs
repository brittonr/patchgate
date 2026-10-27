use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DIRECTORY: &str = ".pijul/patchgate/watch";
const MAX_BYTES: u64 = 16 * 1024;
const GRACE_MS: u64 = 30_000;

type Clock = fn() -> Result<Time>;

struct Time {
    monotonic: u64,
    wall: String,
}

fn clock() -> Result<Time> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == 0,
        "The watch clock is unavailable"
    );
    ensure!(
        time.tv_sec >= 0 && (0..1_000_000_000).contains(&time.tv_nsec),
        "The watch clock is not valid"
    );
    let monotonic = u64::try_from(time.tv_sec)?
        .checked_mul(1000)
        .and_then(|value| value.checked_add(time.tv_nsec as u64 / 1_000_000))
        .ok_or_else(|| anyhow!("The watch clock exceeds its limit"))?;
    Ok(Time {
        monotonic,
        wall: chrono::Utc::now().to_rfc3339(),
    })
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Counts {
    pub accepted: usize,
    pub rejected: usize,
    pub escalated: usize,
    pub blocked: usize,
    pub waiting: usize,
    pub pending: usize,
    pub removed: usize,
    pub reverted: usize,
    pub unknown: usize,
    pub execution_errors: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Failure {
    StartupError,
    ReviewError,
    ReviewTimeout,
    ReviewRequestLimit,
    ReviewExecutionError,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    scope: String,
    instance: String,
    pid: u32,
    phase: String,
    started_at: String,
    updated_at: String,
    updated_monotonic_ms: u64,
    deadline_monotonic_ms: u64,
    last_completed_at: Option<String>,
    last_success_at: Option<String>,
    last_failure_at: Option<String>,
    consecutive_failures: u64,
    failure: Option<Failure>,
    counts: Option<Counts>,
}

#[derive(Serialize)]
pub(crate) struct Report {
    pub schema_version: u32,
    pub healthy: bool,
    pub status: &'static str,
    pub authorizes_acceptance: bool,
    pub attention_required: Option<bool>,
    snapshot: Option<Snapshot>,
}

impl Report {
    fn new(status: &'static str, snapshot: Option<Snapshot>) -> Self {
        let attention_required = snapshot
            .as_ref()
            .and_then(|state| state.counts.as_ref())
            .map(|counts| {
                counts.rejected != 0
                    || counts.escalated != 0
                    || counts.blocked != 0
                    || counts.removed != 0
                    || counts.unknown != 0
            });
        Self {
            schema_version: 1,
            healthy: status == "healthy",
            status,
            authorizes_acceptance: false,
            attention_required,
            snapshot,
        }
    }
}

pub(crate) fn show(report: &Report) {
    println!("Watch health: {}", report.status);
    println!("Health does not authorize acceptance.");
    if let Some(attention) = report.attention_required {
        println!("Attention required: {attention}");
    }
}

struct Location {
    repo: PathBuf,
    scope: String,
}

impl Location {
    fn new(repo: &Path, main: &str, inbox: &str) -> Result<Self> {
        let repo = repo.canonicalize()?;
        let mut hash = Sha256::new();
        for value in [
            repo.as_os_str().as_bytes(),
            main.as_bytes(),
            inbox.as_bytes(),
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        Ok(Self {
            repo,
            scope: format!("{:x}", hash.finalize()),
        })
    }

    fn path(&self, extension: &str) -> Result<PathBuf> {
        crate::pijul::safe_path(
            &self.repo,
            &Path::new(DIRECTORY).join(format!("{}.{}", self.scope, extension)),
        )
    }

    fn directory(&self) -> Result<(PathBuf, File)> {
        let path = crate::pijul::safe_path(&self.repo, Path::new(DIRECTORY))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        let metadata = directory.metadata()?;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o7777 == 0o700,
            "The watch directory must be private"
        );
        Ok((path, directory))
    }

    fn open(&self, extension: &str, create: bool) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(create)
            .create(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(self.path(extension)?)?;
        private_file(&file)?;
        Ok(file)
    }
}

fn private_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o7777 == 0o600,
        "A watch file must be private and regular without aliases"
    );
    ensure!(
        metadata.len() <= MAX_BYTES,
        "A watch file exceeds its size limit"
    );
    Ok(())
}

fn input(file: &File) -> Result<Vec<u8>> {
    private_file(file)?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "A watch file exceeds its size limit"
    );
    Ok(bytes)
}

pub(crate) struct Store {
    location: Location,
    lease: File,
    state: Snapshot,
    clock: Clock,
}

impl Store {
    pub(crate) fn start(repo: &Path, main: &str, inbox: &str, timeout: Duration) -> Result<Self> {
        Self::start_with_clock(repo, main, inbox, timeout, clock)
    }

    fn start_with_clock(
        repo: &Path,
        main: &str,
        inbox: &str,
        timeout: Duration,
        clock: Clock,
    ) -> Result<Self> {
        let location = Location::new(repo, main, inbox)?;
        let path = crate::pijul::safe_path(&location.repo, Path::new(DIRECTORY))?;
        DirBuilder::new().recursive(true).mode(0o700).create(path)?;
        let (_, directory) = location.directory()?;
        fs2::FileExt::lock_exclusive(&directory)?;
        let mut lease = location.open("lock", true)?;
        fs2::FileExt::try_lock_exclusive(&lease)
            .map_err(|_| anyhow!("A watch already owns this scope"))?;
        // Refuse unsafe state before the lease contents change.
        match location.open("json", false) {
            Ok(_) => {}
            Err(error) if is_missing(&error) => {}
            Err(error) => return Err(error),
        }
        let now = clock()?;
        let mut random = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let instance = format!("{:x}", Sha256::digest(random));
        let state = Snapshot {
            schema_version: 1,
            scope: location.scope.clone(),
            instance,
            pid: std::process::id(),
            phase: "starting".into(),
            started_at: now.wall.clone(),
            updated_at: now.wall,
            updated_monotonic_ms: now.monotonic,
            deadline_monotonic_ms: deadline(now.monotonic, timeout)?,
            last_completed_at: None,
            last_success_at: None,
            last_failure_at: None,
            consecutive_failures: 0,
            failure: None,
            counts: None,
        };
        location.directory()?;
        private_file(&lease)?;
        ensure!(
            same_file(&location.open("lock", false)?, &lease)?,
            "The watch lease changed"
        );
        lease.seek(SeekFrom::Start(0))?;
        lease.set_len(0)?;
        lease.write_all(state.instance.as_bytes())?;
        lease.sync_all()?;
        let store = Self {
            location,
            lease,
            state,
            clock,
        };
        store.persist()?;
        Ok(store)
    }

    pub(crate) fn reviewing(&mut self, timeout: Duration) -> Result<()> {
        self.update("reviewing", timeout)?;
        self.persist()
    }

    pub(crate) fn complete(
        &mut self,
        counts: Option<Counts>,
        failure: Option<Failure>,
        delay: Duration,
    ) -> Result<()> {
        ensure!(
            counts
                .as_ref()
                .is_none_or(|value| value.execution_errors == 0)
                || failure.is_some(),
            "Execution errors require a failed pass"
        );
        ensure!(
            failure != Some(Failure::ReviewExecutionError)
                || counts
                    .as_ref()
                    .is_none_or(|value| value.execution_errors != 0),
            "An execution failure requires execution error counts"
        );
        self.update(if failure.is_some() { "error" } else { "idle" }, delay)?;
        self.state.last_completed_at = Some(self.state.updated_at.clone());
        self.state.counts = counts;
        if let Some(failure) = failure {
            self.state.last_failure_at = Some(self.state.updated_at.clone());
            self.state.failure = Some(failure);
            self.state.consecutive_failures = self
                .state
                .consecutive_failures
                .checked_add(1)
                .ok_or_else(|| anyhow!("The watch failure count exceeds its limit"))?;
        } else {
            self.state.last_success_at = Some(self.state.updated_at.clone());
            self.state.consecutive_failures = 0;
        }
        self.persist()
    }

    pub(crate) fn stop(&mut self) -> Result<()> {
        self.update("stopped", Duration::ZERO)?;
        self.persist()
    }

    fn update(&mut self, phase: &str, timeout: Duration) -> Result<()> {
        ensure!(self.state.phase != "stopped", "The watch is stopped");
        let now = (self.clock)()?;
        ensure!(
            now.monotonic >= self.state.updated_monotonic_ms,
            "The watch clock moved backward"
        );
        self.state.deadline_monotonic_ms = deadline(now.monotonic, timeout)?;
        self.state.updated_monotonic_ms = now.monotonic;
        self.state.updated_at = now.wall;
        self.state.phase = phase.into();
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        let (path, directory) = self.location.directory()?;
        private_file(&self.lease)?;
        let lease = self.location.open("lock", false)?;
        ensure!(same_file(&lease, &self.lease)?, "The watch lease changed");
        ensure!(
            input(&lease)? == self.state.instance.as_bytes(),
            "The watch lease changed"
        );
        match self.location.open("json", false) {
            Ok(_) => {}
            Err(error) if is_missing(&error) => {}
            Err(error) => return Err(error),
        }
        let bytes = serde_json::to_vec(&self.state)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "The watch state exceeds its size limit"
        );
        let mut temporary = tempfile::Builder::new().prefix(".tmp").tempfile_in(path)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temporary.write_all(&bytes)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        // Repeat path checks immediately before replacement.
        self.location.directory()?;
        let destination = self.location.path("json")?;
        if destination.exists() {
            self.location.open("json", false)?;
        }
        temporary
            .persist(destination)
            .map_err(|error| error.error)?;
        directory.sync_all()?;
        Ok(())
    }
}

fn deadline(now: u64, duration: Duration) -> Result<u64> {
    let delay = u64::try_from(duration.as_millis())?;
    now.checked_add(delay)
        .and_then(|value| value.checked_add(GRACE_MS))
        .ok_or_else(|| anyhow!("The watch deadline exceeds its limit"))
}

fn same_file(left: &File, right: &File) -> Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn valid_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid(state: &Snapshot, scope: &str) -> bool {
    let timestamp = |value: &str| chrono::DateTime::parse_from_rfc3339(value).is_ok();
    let complete = state.last_completed_at.is_some();
    let failure = state.last_failure_at.is_some();
    state.schema_version == 1
        && state.scope == scope
        && valid_hex(&state.scope)
        && valid_hex(&state.instance)
        && state.pid != 0
        && matches!(
            state.phase.as_str(),
            "starting" | "reviewing" | "idle" | "error" | "stopped"
        )
        && timestamp(&state.started_at)
        && timestamp(&state.updated_at)
        && [
            &state.last_completed_at,
            &state.last_success_at,
            &state.last_failure_at,
        ]
        .into_iter()
        .all(|value| value.as_deref().is_none_or(timestamp))
        && state
            .deadline_monotonic_ms
            .checked_sub(state.updated_monotonic_ms)
            .is_some_and(|delay| delay >= GRACE_MS)
        && complete == (state.last_success_at.is_some() || failure)
        && failure == state.failure.is_some()
        && (state.consecutive_failures == 0 || failure)
        && (if state.consecutive_failures == 0 {
            state.last_completed_at == state.last_success_at
        } else {
            state.last_completed_at == state.last_failure_at
        })
        && (complete || state.counts.is_none())
        && (state.phase != "starting" || (!complete && state.consecutive_failures == 0))
        && (state.phase != "idle"
            || (complete && state.last_success_at.is_some() && state.consecutive_failures == 0))
        && (state.phase != "error" || (complete && state.consecutive_failures != 0))
        && state
            .counts
            .as_ref()
            .is_none_or(|counts| counts.execution_errors == 0 || state.consecutive_failures != 0)
        && (state.consecutive_failures == 0
            || state.failure != Some(Failure::ReviewExecutionError)
            || state
                .counts
                .as_ref()
                .is_none_or(|counts| counts.execution_errors != 0))
}

pub(crate) fn inspect(repo: &Path, main: &str, inbox: &str) -> Report {
    inspect_with_clock(repo, main, inbox, clock)
}

fn inspect_with_clock(repo: &Path, main: &str, inbox: &str, clock: Clock) -> Report {
    match inspect_inner(repo, main, inbox, clock) {
        Ok(report) => report,
        Err(error) => Report::new(
            if is_missing(&error) {
                "missing"
            } else {
                "unavailable"
            },
            None,
        ),
    }
}

fn inspect_inner(repo: &Path, main: &str, inbox: &str, clock: Clock) -> Result<Report> {
    let location = Location::new(repo, main, inbox)?;
    let (_, directory) = location.directory()?;
    fs2::FileExt::try_lock_shared(&directory)?;
    let bytes = input(&location.open("json", false)?)?;
    let state: Snapshot = match serde_json::from_slice(&bytes) {
        Ok(state) => state,
        Err(_) => return Ok(Report::new("invalid", None)),
    };
    if !valid(&state, &location.scope) {
        return Ok(Report::new("invalid", None));
    }
    let lease = match location.open("lock", false) {
        Ok(lease) => lease,
        Err(error) if is_missing(&error) => {
            let status = if state.phase == "stopped" {
                "stopped"
            } else {
                "not-running"
            };
            return Ok(Report::new(status, Some(state)));
        }
        Err(error) => return Err(error),
    };
    let instance = input(&lease)?;
    let owned = match fs2::FileExt::try_lock_shared(&lease) {
        Ok(()) => false,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
        Err(error) => return Err(error.into()),
    };
    if instance != state.instance.as_bytes() {
        return Ok(Report::new("not-running", Some(state)));
    }
    if !owned {
        let status = if state.phase == "stopped" {
            "stopped"
        } else {
            "not-running"
        };
        return Ok(Report::new(status, Some(state)));
    }
    let now = clock()?.monotonic;
    let status = if state.phase == "stopped" {
        "stopped"
    } else if now < state.updated_monotonic_ms || now >= state.deadline_monotonic_ms {
        "stalled"
    } else if state.consecutive_failures != 0 {
        "degraded"
    } else if state.last_success_at.is_none() {
        "starting"
    } else {
        "healthy"
    };
    Ok(Report::new(status, Some(state)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

    thread_local! { static NOW: Cell<u64> = const { Cell::new(1000) }; }

    fn test_clock() -> Result<Time> {
        Ok(Time {
            monotonic: NOW.with(Cell::get),
            wall: "2026-10-27T00:00:00Z".into(),
        })
    }

    fn repo() -> tempfile::TempDir {
        NOW.with(|now| now.set(1000));
        let repo = tempfile::tempdir().unwrap();
        fs::create_dir(repo.path().join(".pijul")).unwrap();
        repo
    }

    fn start(repo: &Path) -> Store {
        Store::start_with_clock(repo, "main", "inbox", Duration::from_secs(10), test_clock).unwrap()
    }

    fn report(repo: &Path) -> Report {
        inspect_with_clock(repo, "main", "inbox", test_clock)
    }

    #[test]
    fn success_failure_recovery_and_attention() {
        let repo = repo();
        let mut store = start(repo.path());
        assert_eq!(report(repo.path()).status, "starting");
        let counts = Counts {
            escalated: 1,
            ..Counts::default()
        };
        store
            .complete(Some(counts), None, Duration::from_secs(10))
            .unwrap();
        assert!(report(repo.path()).healthy);
        assert_eq!(report(repo.path()).attention_required, Some(true));
        store.reviewing(Duration::from_secs(10)).unwrap();
        assert_eq!(report(repo.path()).attention_required, Some(true));
        store
            .complete(None, Some(Failure::ReviewTimeout), Duration::ZERO)
            .unwrap();
        assert_eq!(report(repo.path()).status, "degraded");
        assert_eq!(report(repo.path()).attention_required, None);
        store
            .complete(Some(Counts::default()), None, Duration::ZERO)
            .unwrap();
        let state = report(repo.path()).snapshot.unwrap();
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.failure, Some(Failure::ReviewTimeout));
        assert!(state.last_failure_at.is_some());
        assert!(report(repo.path()).healthy);
    }

    #[test]
    fn deadline_boundary_and_clock_regression() {
        let repo = repo();
        let mut store = start(repo.path());
        store.complete(None, None, Duration::from_secs(10)).unwrap();
        NOW.with(|now| now.set(40_999));
        assert!(report(repo.path()).healthy);
        NOW.with(|now| now.set(41_000));
        assert_eq!(report(repo.path()).status, "stalled");
        NOW.with(|now| now.set(999));
        assert_eq!(report(repo.path()).status, "stalled");
        assert!(store.reviewing(Duration::ZERO).is_err());
    }

    #[test]
    fn stopped_and_released_lease() {
        let repo = repo();
        let mut store = start(repo.path());
        store.complete(None, None, Duration::ZERO).unwrap();
        store.stop().unwrap();
        assert_eq!(report(repo.path()).status, "stopped");
        assert!(
            Store::start_with_clock(repo.path(), "main", "inbox", Duration::ZERO, test_clock)
                .is_err()
        );
        drop(store);
        assert_eq!(report(repo.path()).status, "stopped");
    }

    #[test]
    fn duplicate_owner_does_not_change_bytes() {
        let repo = repo();
        let store = start(repo.path());
        let state = fs::read(store.location.path("json").unwrap()).unwrap();
        let lease = fs::read(store.location.path("lock").unwrap()).unwrap();
        assert!(
            Store::start_with_clock(repo.path(), "main", "inbox", Duration::ZERO, test_clock)
                .is_err()
        );
        assert_eq!(
            fs::read(store.location.path("json").unwrap()).unwrap(),
            state
        );
        assert_eq!(
            fs::read(store.location.path("lock").unwrap()).unwrap(),
            lease
        );
    }

    #[test]
    fn stale_instance_does_not_inherit_new_owner() {
        let repo = repo();
        let mut old = start(repo.path());
        old.complete(None, None, Duration::ZERO).unwrap();
        let state = fs::read(old.location.path("json").unwrap()).unwrap();
        drop(old);
        let new = start(repo.path());
        fs::write(new.location.path("json").unwrap(), state).unwrap();
        assert_eq!(report(repo.path()).status, "not-running");
    }

    #[test]
    fn malformed_foreign_and_inconsistent_state_is_invalid() {
        let repo = repo();
        let mut store = start(repo.path());
        let path = store.location.path("json").unwrap();
        fs::write(&path, b"{secret-invalid-input").unwrap();
        assert_eq!(report(repo.path()).status, "invalid");
        store.state.scope = "0".repeat(64);
        store.persist().unwrap();
        assert_eq!(report(repo.path()).status, "invalid");
        store.state.scope = store.location.scope.clone();
        store.state.phase = "idle".into();
        store.persist().unwrap();
        assert_eq!(report(repo.path()).status, "invalid");
        store.state.phase = "starting".into();
        store.state.deadline_monotonic_ms = 999;
        store.persist().unwrap();
        assert_eq!(report(repo.path()).status, "invalid");
    }

    #[test]
    fn aliases_are_refused_without_outside_changes() {
        for extension in ["json", "lock"] {
            for hard_link in [false, true] {
                let repo = repo();
                let outside = repo.path().join("outside");
                fs::write(&outside, b"outside bytes").unwrap();
                fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
                let store = start(repo.path());
                let target = store.location.path(extension).unwrap();
                drop(store);
                fs::remove_file(&target).unwrap();
                if hard_link {
                    fs::hard_link(&outside, &target).unwrap();
                } else {
                    symlink(&outside, &target).unwrap();
                }
                assert!(!report(repo.path()).healthy);
                assert!(
                    Store::start_with_clock(
                        repo.path(),
                        "main",
                        "inbox",
                        Duration::ZERO,
                        test_clock
                    )
                    .is_err()
                );
                assert_eq!(fs::read(&outside).unwrap(), b"outside bytes");
            }
        }
    }

    #[test]
    fn execution_failure_and_scope_separation() {
        let repo = repo();
        let mut store = start(repo.path());
        store
            .complete(
                Some(Counts {
                    execution_errors: 1,
                    ..Counts::default()
                }),
                Some(Failure::ReviewExecutionError),
                Duration::ZERO,
            )
            .unwrap();
        assert_eq!(report(repo.path()).status, "degraded");
        assert_eq!(
            inspect_with_clock(repo.path(), "other", "inbox", test_clock).status,
            "missing"
        );
        assert!(
            store
                .complete(
                    Some(Counts {
                        execution_errors: 1,
                        ..Counts::default()
                    }),
                    None,
                    Duration::ZERO
                )
                .is_err()
        );
    }

    #[test]
    fn oversized_and_nonregular_state_is_not_healthy() {
        let repo = repo();
        let store = start(repo.path());
        let path = store.location.path("json").unwrap();
        fs::write(&path, vec![b' '; MAX_BYTES as usize + 1]).unwrap();
        assert!(!report(repo.path()).healthy);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(!report(repo.path()).healthy);
    }

    #[test]
    fn inspection_does_not_create_state() {
        let repo = repo();
        assert_eq!(report(repo.path()).status, "missing");
        assert!(!repo.path().join(DIRECTORY).exists());
    }
}
