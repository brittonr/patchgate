use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::configuration;
use crate::pijul::{Pijul, Signer};
use crate::review::ReviewBinding;

const POINTER: &str = ".pijul/patchgate-resolution/workspace.json";
const PRIVATE: &str = ".pijul/patchgate-resolution";
const RECORDS: &str = ".pijul/patchgate/resolutions";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub kind: String,
    pub path: String,
    pub line: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub id: String,
    pub workspace: PathBuf,
    pub candidates: Vec<String>,
    pub binding: ReviewBinding,
    pub configuration: configuration::Evidence,
    pub base: Vec<String>,
    pub conflicts: Vec<Conflict>,
    pub policy_file: Option<PathBuf>,
    pub review_file: PathBuf,
    source: PathBuf,
    pub main: String,
    pub inbox: String,
    workspace_device: u64,
    workspace_inode: u64,
}

#[derive(Serialize)]
pub struct Refreshed {
    pub prepared: Prepared,
    pub previous_id: String,
    pub preserved: Vec<String>,
}

pub struct Completed {
    pub pijul: Pijul,
    pub hashes: Vec<String>,
    pub imported: HashSet<String>,
}

#[derive(Serialize)]
pub struct VerificationReport {
    pub schema_version: u8,
    pub authorizes_acceptance: bool,
    pub prepared: Prepared,
    pub validated_hashes: Vec<String>,
    pub validation: ValidationEvidence,
    pub verification: Option<std::rc::Rc<crate::verify::Verification>>,
}

#[derive(Serialize)]
pub struct ValidationEvidence {
    pub source_authority: bool,
    pub current_bindings: bool,
    pub permitted_dependencies: bool,
    pub native_expected_state: bool,
    pub credential_scan: bool,
    pub conflicts_absent: bool,
}

pub fn show_verification(report: &VerificationReport) {
    println!("Workspace verification passed.");
    println!("Prepared identity: {}", report.prepared.id);
    println!("Validated changes: {}", report.validated_hashes.len());
    if let Some(verification) = &report.verification {
        if let Some(version) = verification.observed_nix_version() {
            println!("Observed Nix version: {}", version.escape_debug());
        }
        println!("Trusted Nix checks and fresh isolation passed.");
    } else {
        println!("Trusted main defines no Nix checks.");
    }
    println!("This report does not authorize acceptance. Acceptance repeats all live guards.");
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pointer {
    schema_version: u8,
    id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    schema_version: u8,
    prepared: Prepared,
}

#[derive(Serialize)]
pub struct Blocker {
    pub code: String,
    pub detail: String,
}

#[derive(Serialize)]
pub struct PendingCheck {
    pub code: String,
    pub detail: String,
}

#[derive(Serialize)]
pub struct Readiness {
    pub schema_version: u8,
    pub authorizes_acceptance: bool,
    pub workspace: PathBuf,
    pub prepared_id: Option<String>,
    pub main: Option<String>,
    pub inbox: Option<String>,
    pub candidates: Option<Vec<String>>,
    pub recorded_conflicts: Option<Vec<Conflict>>,
    pub pending_tracked_edits: Option<bool>,
    pub stale_main: Option<bool>,
    pub stale_configuration: Option<bool>,
    pub stale_policy: Option<bool>,
    pub blockers: Vec<Blocker>,
    pub pending_verification: Vec<PendingCheck>,
}

impl Readiness {
    pub fn add_blocker(&mut self, code: &str, detail: &str) {
        if !self.blockers.iter().any(|blocker| blocker.code == code) {
            self.blockers.push(Blocker {
                code: code.to_owned(),
                detail: detail.to_owned(),
            });
        }
    }

    fn add_pending(&mut self, code: &str, detail: &str) {
        self.pending_verification.push(PendingCheck {
            code: code.to_owned(),
            detail: detail.to_owned(),
        });
    }
}

/// Inspect static readiness without acceptance authority or source execution.
pub fn inspect(
    source: &Path,
    workspace: &Path,
    baseline: &configuration::Values,
) -> Result<Readiness> {
    let mut report = Readiness {
        schema_version: 1,
        authorizes_acceptance: false,
        workspace: workspace.to_path_buf(),
        prepared_id: None,
        main: None,
        inbox: None,
        candidates: None,
        recorded_conflicts: None,
        pending_tracked_edits: None,
        stale_main: None,
        stale_configuration: None,
        stale_policy: None,
        blockers: Vec::new(),
        pending_verification: Vec::new(),
    };
    report.add_pending(
        "credential_checks",
        "Explicit acceptance must check supported credential data.",
    );
    report.add_pending(
        "runtime_isolation",
        "Explicit acceptance must verify runtime isolation before candidate execution.",
    );
    report.add_pending(
        "nix_checks",
        "Explicit acceptance must execute the required Nix checks.",
    );
    report.add_pending(
        "conditional_acceptance",
        "Explicit acceptance must verify current authority and native expected state.",
    );
    report.add_pending(
        "conflict_verification",
        "Explicit acceptance must verify conflicts after any pending tracked edits receive a native record.",
    );
    let prepared = match load(source, workspace) {
        Ok(prepared) => prepared,
        Err(_) => {
            report.add_blocker(
                "invalid_authority",
                "Source authority or workspace identity is absent, unsafe, or invalid.",
            );
            return Ok(report);
        }
    };
    report.workspace = prepared.workspace.clone();
    report.prepared_id = Some(prepared.id.clone());
    report.main = Some(prepared.main.clone());
    report.inbox = Some(prepared.inbox.clone());
    report.candidates = Some(prepared.candidates.clone());
    if [&prepared.main, &prepared.inbox].iter().any(|name| {
        name.is_empty()
            || name.starts_with('-')
            || name.trim() != name.as_str()
            || name.chars().any(char::is_control)
    }) {
        report.add_blocker(
            "unsupported_channels",
            "The trusted channel names are not supported.",
        );
        return Ok(report);
    }
    if let Some(source_copy) = inspection_copy(&prepared.source, false, &mut report) {
        inspect_source(&source_copy.pijul, &prepared, baseline, &mut report);
    }
    if let Some(workspace_copy) = inspection_copy(&prepared.workspace, true, &mut report) {
        inspect_workspace(&workspace_copy.pijul, &prepared, &mut report);
    }
    Ok(report)
}

fn inspection_copy(
    root: &Path,
    workspace: bool,
    report: &mut Readiness,
) -> Option<crate::isolation::Isolated> {
    if workspace && refuse_native_configuration(root).is_err() {
        report.add_blocker(
            "workspace_native_configuration",
            "Editable native configuration prevents safe inspection.",
        );
        return None;
    }
    if crate::pijul::safe_path(root, Path::new(".pijul"))
        .and_then(|metadata| {
            ensure!(metadata.is_dir(), "Native metadata is not a directory");
            validate_native_metadata(&metadata)
        })
        .is_err()
    {
        report.add_blocker(
            if workspace {
                "workspace_metadata"
            } else {
                "source_metadata"
            },
            "Native metadata is absent or unsafe.",
        );
        return None;
    }
    let copy = crate::isolation::copy_repository(root).and_then(|mut isolated| {
        detach_files(&isolated.pijul.repo.join(".pijul"))?;
        refuse_native_configuration(&isolated.pijul.repo)?;
        isolated.pijul = Pijul::with_timeout(
            isolated.pijul.repo.clone(),
            std::time::Duration::from_secs(30),
        );
        Ok(isolated)
    });
    match copy {
        Ok(copy) => Some(copy),
        Err(_) => {
            report.add_blocker(
                if workspace {
                    "workspace_snapshot"
                } else {
                    "source_snapshot"
                },
                "A safe private native snapshot is not available.",
            );
            None
        }
    }
}

fn inspect_source(
    source: &Pijul,
    prepared: &Prepared,
    baseline: &configuration::Values,
    report: &mut Readiness,
) {
    let channels = match source.channels() {
        Ok((_, channels)) => channels,
        Err(_) => {
            report.add_blocker(
                "source_native_read",
                "Source native state is not available.",
            );
            return;
        }
    };
    if !channels.contains(&prepared.main) || !channels.contains(&prepared.inbox) {
        report.add_blocker(
            "source_channels",
            "A trusted main or inbox channel is absent.",
        );
        return;
    }
    match source.snapshot(&prepared.main) {
        Ok(snapshot) => {
            let stale = snapshot.state != prepared.binding.main.state
                || snapshot.hashes != prepared.base.iter().cloned().collect();
            report.stale_main = Some(stale);
            if stale {
                report.add_blocker(
                    "stale_main",
                    "Trusted main differs from the prepared binding.",
                );
            }
        }
        Err(_) => report.add_blocker("main_native_read", "Trusted main state is not available."),
    }
    match source.log(&prepared.inbox) {
        Ok(entries) => {
            let candidates: Vec<_> = entries
                .into_iter()
                .filter(|entry| prepared.candidates.contains(&entry.hash))
                .map(|entry| entry.hash)
                .collect();
            if candidates != prepared.candidates {
                report.add_blocker(
                    "source_candidates",
                    "Prepared candidates are absent or differ from native inbox order.",
                );
            }
        }
        Err(_) => report.add_blocker("inbox_native_read", "Trusted inbox state is not available."),
    }
    for hash in prepared.base.iter().chain(&prepared.candidates) {
        if regular_file(&source.change_file(hash)).is_err() || source.change(hash).is_err() {
            report.add_blocker(
                "source_native_changes",
                "A prepared source change is absent or incomplete.",
            );
            break;
        }
    }
    let configuration = match configuration::load(source, &prepared.main, baseline) {
        Ok(configuration) => configuration,
        Err(_) => {
            report.add_blocker(
                "configuration_unavailable",
                "Trusted main configuration is absent, unsafe, or invalid.",
            );
            return;
        }
    };
    let stale = configuration != prepared.configuration;
    report.stale_configuration = Some(stale);
    if stale {
        report.add_blocker(
            "stale_configuration",
            "Trusted configuration differs from the prepared binding.",
        );
    }
    match source.read_file(&prepared.main, &configuration.values.policy_path) {
        Ok(policy) => {
            let stale = match (&prepared.binding.policy, &policy) {
                (None, None) => false,
                (Some(binding), Some(text)) => {
                    binding.path != configuration.values.policy_path
                        || binding.sha256 != digest(text.as_bytes())
                }
                _ => true,
            };
            report.stale_policy = Some(stale);
            if stale {
                report.add_blocker(
                    "stale_policy",
                    "Trusted policy differs from the prepared binding.",
                );
            }
        }
        Err(_) => report.add_blocker(
            "policy_unavailable",
            "Trusted main policy is not available.",
        ),
    }
}

fn inspect_workspace(private: &Pijul, prepared: &Prepared, report: &mut Readiness) {
    match private.channels() {
        Ok((current, channels))
            if current.as_deref() == Some(prepared.main.as_str())
                && channels.contains(&prepared.main) => {}
        Ok(_) => {
            report.add_blocker(
                "workspace_channels",
                "The workspace current channel differs from trusted main.",
            );
            return;
        }
        Err(_) => {
            report.add_blocker(
                "workspace_native_read",
                "Workspace native state is not available.",
            );
            return;
        }
    }
    if native_order(private, prepared).is_err() {
        report.add_blocker(
            "workspace_native_changes",
            "Prepared workspace changes are absent, incomplete, or in a different order.",
        );
    }
    if validate_prepared_files(private, prepared).is_err() {
        report.add_blocker(
            "prepared_data_changed",
            "Prepared review or policy data is absent, unsafe, or changed.",
        );
    }
    match private.conflicts() {
        Ok(conflicts) => {
            report.recorded_conflicts =
                Some(conflicts.into_iter().map(readiness_conflict).collect());
        }
        Err(_) => report.add_blocker(
            "workspace_conflicts",
            "Recorded workspace conflicts are not available.",
        ),
    }
    let workspace = Pijul::new(prepared.workspace.clone());
    match tracked_workspace_clean_private(&workspace, private, &prepared.main) {
        Ok(clean) => report.pending_tracked_edits = Some(!clean),
        Err(_) => report.add_blocker(
            "tracked_edits_unavailable",
            "Pending tracked edits cannot be determined safely.",
        ),
    }
    if report.pending_tracked_edits == Some(true) {
        report.add_pending(
            "record_tracked_edits",
            "Explicit acceptance can record pending tracked edits. Inspection does not record them.",
        );
    }
    if report.pending_tracked_edits == Some(false)
        && report
            .recorded_conflicts
            .as_ref()
            .is_some_and(|conflicts| !conflicts.is_empty())
    {
        report.add_blocker(
            "recorded_conflicts",
            "Recorded conflicts remain without pending tracked edits.",
        );
    }
}

fn readiness_conflict(conflict: crate::change::Conflict) -> Conflict {
    let kind = match conflict.kind.as_str() {
        "Order conflict" | "Deletion conflict" | "Name conflict" | "Zombie conflict"
        | "Cyclic conflict" => conflict.kind,
        _ => "Other conflict".to_owned(),
    };
    let path = if crate::secrets::scan_text("[conflict.path]", conflict.path.as_bytes()).is_empty()
        && !conflict.path.chars().any(char::is_control)
        && crate::pijul::normalize_path(Path::new(&conflict.path)).is_ok()
    {
        conflict.path
    } else {
        "[redacted-path]".to_owned()
    };
    Conflict {
        kind,
        path,
        line: conflict.line,
    }
}

/// Prepare native records without source execution or model access.
pub fn prepare(
    source: &Path,
    isolated: &Pijul,
    main: &str,
    inbox: &str,
    candidates: &[String],
    workspace: &Path,
    binding: ReviewBinding,
    configuration: configuration::Evidence,
) -> Result<Prepared> {
    prepare_plan(
        source,
        isolated,
        main,
        inbox,
        candidates,
        workspace,
        binding,
        configuration,
        None,
    )
}

fn prepare_plan(
    source: &Path,
    isolated: &Pijul,
    main: &str,
    inbox: &str,
    candidates: &[String],
    workspace: &Path,
    binding: ReviewBinding,
    configuration: configuration::Evidence,
    supplements: Option<(&Pijul, &[String])>,
) -> Result<Prepared> {
    let source = canonical_directory(source)?;
    let workspace = new_workspace_path(&source, workspace)?;
    ensure!(main != inbox, "Resolution channels must differ");
    validate_candidates(candidates)?;
    ensure!(
        binding.candidates == candidates,
        "Resolution candidate binding differs"
    );
    ensure!(
        binding.main.channel == main,
        "Resolution main binding differs"
    );
    let snapshot = isolated.snapshot(main)?;
    ensure!(
        snapshot.state == binding.main.state,
        "The recorded main state differs"
    );
    let base: Vec<_> = isolated
        .log(main)?
        .into_iter()
        .map(|entry| entry.hash)
        .collect();
    let base_set: HashSet<_> = base.iter().cloned().collect();
    ensure!(
        base_set == snapshot.hashes,
        "The main history differs from its snapshot"
    );
    ensure!(
        candidates.iter().all(|hash| !base_set.contains(hash)),
        "A resolution candidate is already in main"
    );
    let inbox_order: Vec<_> = isolated
        .log(inbox)?
        .into_iter()
        .filter(|entry| candidates.contains(&entry.hash))
        .map(|entry| entry.hash)
        .collect();
    ensure!(
        inbox_order == candidates,
        "Candidates must follow the native inbox order"
    );

    let policy = isolated.read_file(main, &configuration.values.policy_path)?;
    match (&binding.policy, &policy) {
        (None, None) => {}
        (Some(bound), Some(text)) => {
            ensure!(
                bound.path == configuration.values.policy_path,
                "The policy path binding differs"
            );
            ensure!(
                bound.sha256 == digest(text.as_bytes()),
                "The policy text binding differs"
            );
        }
        _ => bail!("The policy presence binding differs"),
    }
    let mut review = String::new();
    let mut permitted: HashSet<_> = base.iter().chain(candidates).map(String::as_str).collect();
    for hash in candidates {
        let path = crate::pijul::safe_path(
            &isolated.repo,
            isolated.change_file(hash).strip_prefix(&isolated.repo)?,
        )?;
        ensure!(
            fs::symlink_metadata(&path)?.is_file(),
            "A candidate change file is not regular"
        );
        let text = isolated.change(hash)?;
        ensure!(
            crate::change::dependencies(&text)
                .iter()
                .all(|hash| permitted.contains(hash.as_str())),
            "A candidate requires an unprepared change"
        );
        review.push_str(&text);
        if !text.ends_with('\n') {
            review.push('\n');
        }
    }
    if let Some((previous, hashes)) = supplements {
        for hash in hashes {
            validate_hash(hash)?;
            regular_file(&previous.change_file(hash))?;
            let text = previous.change(hash)?;
            ensure!(
                crate::change::dependencies(&text)
                    .iter()
                    .all(|dependency| permitted.contains(dependency.as_str())),
                "A human record requires a removed change. Restore its dependency explicitly before refresh."
            );
            permitted.insert(hash.as_str());
        }
    }

    // Reserve the workspace before the native clone can create files.
    fs::create_dir(&workspace)?;
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
    let staging = tempfile::Builder::new()
        .prefix(".patchgate-prepare-")
        .tempdir_in(&workspace)?;
    let clone = staging.path().join("main");
    isolated
        .run([
            OsStr::new("clone"),
            OsStr::new("--channel"),
            OsStr::new(main),
            isolated.repo.as_os_str(),
            clone.as_os_str(),
        ])
        .context("Cannot clone recorded main for human resolution")?;
    for entry in fs::read_dir(&clone)? {
        let entry = entry?;
        fs::rename(entry.path(), workspace.join(entry.file_name()))?;
    }
    drop(staging);
    ensure!(
        canonical_directory(&workspace)? == workspace,
        "The workspace path changed"
    );
    detach_files(&workspace.join(".pijul"))?;
    // The clone remote is not needed. No editable native configuration can enter record.
    for name in ["config", "config.toml"] {
        let path = workspace.join(".pijul").join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                regular_file(&path)?;
                fs::remove_file(path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    refuse_native_configuration(&workspace)?;
    validate_native_metadata(&workspace.join(".pijul"))?;
    let pijul = Pijul::new(workspace.clone());
    ensure!(
        pijul.snapshot(main)? == snapshot,
        "The cloned main state differs"
    );
    for hash in candidates {
        pijul
            .call([OsStr::new("apply"), isolated.change_file(hash).as_os_str()])
            .context("Cannot apply a prepared candidate")?;
        refuse_native_configuration(&workspace)?;
    }
    let mut expected: HashSet<_> = base.iter().chain(candidates).cloned().collect();
    if let Some((previous, hashes)) = supplements {
        for hash in hashes {
            if expected.insert(hash.clone()) {
                pijul
                    .call([OsStr::new("apply"), previous.change_file(hash).as_os_str()])
                    .context("Cannot preserve a recorded human change")?;
                refuse_native_configuration(&workspace)?;
            }
        }
    }
    ensure!(
        pijul.hashes(main)? == expected,
        "The workspace contains an unprepared change"
    );
    detach_files(&workspace.join(".pijul"))?;
    validate_native_metadata(&workspace.join(".pijul"))?;
    let conflicts = pijul
        .conflicts()?
        .into_iter()
        .map(|conflict| Conflict {
            kind: conflict.kind,
            path: if crate::secrets::scan_text("[conflict.path]", conflict.path.as_bytes())
                .is_empty()
            {
                conflict.path
            } else {
                "[redacted-path]".to_owned()
            },
            line: conflict.line,
        })
        .collect();
    let private = private_directory(&workspace, PRIVATE)?;
    let policy_file = policy.as_ref().map(|_| private.join("policy.txt"));
    if let (Some(path), Some(text)) = (&policy_file, policy) {
        private_file(path, text.as_bytes())?;
    }
    let review_file = private.join("review.txt");
    private_file(&review_file, review.as_bytes())?;
    let metadata = fs::symlink_metadata(&workspace)?;
    let mut prepared = Prepared {
        id: String::new(),
        workspace: workspace.clone(),
        candidates: candidates.to_vec(),
        binding,
        configuration,
        base,
        conflicts,
        policy_file,
        review_file,
        source: source.clone(),
        main: main.to_owned(),
        inbox: inbox.to_owned(),
        workspace_device: metadata.dev(),
        workspace_inode: metadata.ino(),
    };
    prepared.id = identity(&prepared)?;
    let records = private_directory(&source, RECORDS)?;
    let stored = Stored {
        schema_version: 1,
        prepared: prepared.clone(),
    };
    private_file(
        &records.join(format!("{}.json", prepared.id)),
        &serde_json::to_vec(&stored)?,
    )?;
    private_file(
        &workspace.join(POINTER),
        &serde_json::to_vec(&Pointer {
            schema_version: 1,
            id: prepared.id.clone(),
        })?,
    )?;
    Ok(prepared)
}

/// Preserve native human records on current main. Untracked files remain in the old workspace.
pub fn refresh(
    source: &Path,
    isolated: &Pijul,
    previous: &Prepared,
    candidates: &[String],
    workspace: &Path,
    binding: ReviewBinding,
    configuration: configuration::Evidence,
) -> Result<Refreshed> {
    let trusted = load(source, &previous.workspace)?;
    ensure!(
        identity(previous)? == identity(&trusted)? && previous.id == trusted.id,
        "The supplied resolution record differs from source authority"
    );
    let workspace = new_workspace_path(&trusted.source, workspace)?;
    ensure!(
        !workspace.starts_with(&trusted.workspace),
        "The new workspace must be outside the old workspace. Untracked files remain in the old workspace."
    );
    let old = Pijul::new(trusted.workspace.clone());
    validate_native_metadata(&old.repo.join(".pijul"))?;
    refuse_native_configuration(&old.repo)?;
    let (current, _) = old.channels()?;
    ensure!(
        current.as_deref() == Some(trusted.main.as_str()),
        "The workspace current channel differs"
    );
    let order = native_order(&old, &trusted)?;
    ensure!(
        old.hashes(&trusted.main)? == order.iter().cloned().collect(),
        "The workspace native membership differs"
    );
    validate_prepared_files(&old, &trusted)?;
    ensure!(
        tracked_workspace_clean(&old, &trusted.main)?,
        "Record pending tracked edits before refresh. Untracked files remain in the old workspace."
    );
    let original: HashSet<_> = trusted.base.iter().chain(&trusted.candidates).collect();
    let preserved: Vec<_> = order
        .into_iter()
        .filter(|hash| !original.contains(hash))
        .collect();
    let prepared = prepare_plan(
        source,
        isolated,
        &trusted.main,
        &trusted.inbox,
        candidates,
        &workspace,
        binding,
        configuration,
        Some((&old, &preserved)),
    )?;
    Ok(Refreshed {
        prepared,
        previous_id: trusted.id,
        preserved,
    })
}

fn tracked_workspace_clean(old: &Pijul, channel: &str) -> Result<bool> {
    let isolated = crate::isolation::copy_repository(&old.repo)?;
    tracked_workspace_clean_private(old, &isolated.pijul, channel)
}

fn tracked_workspace_clean_private(old: &Pijul, private: &Pijul, channel: &str) -> Result<bool> {
    refuse_native_configuration(&private.repo)?;
    let directory = private
        .repo
        .parent()
        .context("The private repository has no parent")?;
    let archive_path = directory.join("tracked.tar.gz");
    private.run([
        OsStr::new("archive"),
        OsStr::new("--channel"),
        OsStr::new(channel),
        OsStr::new("-o"),
        archive_path.as_os_str(),
    ])?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(File::open(archive_path)?));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let relative = crate::pijul::normalize_path(&entry.path()?)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        ensure!(
            !relative.starts_with(".pijul"),
            "Tracked files cannot replace private native metadata."
        );
        let source = crate::pijul::safe_path(&old.repo, &relative)?;
        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if entry.header().entry_type().is_dir() {
            if !metadata.is_dir() {
                return Ok(false);
            }
            continue;
        }
        ensure!(
            entry.header().entry_type().is_file(),
            "Tracked workspace data must use regular files."
        );
        if !metadata.is_file()
            || metadata.len() != entry.size()
            || metadata.permissions().mode() & 0o111 != entry.header().mode()? & 0o111
            || !same_file_bytes(&mut entry, &mut File::open(source)?)?
        {
            return Ok(false);
        }
    }
    // A fresh clone excludes staged additions and removals from the path list.
    let recorded = directory.join("recorded");
    private.run([
        OsStr::new("clone"),
        OsStr::new("--channel"),
        OsStr::new(channel),
        private.repo.as_os_str(),
        recorded.as_os_str(),
    ])?;
    // Only the private clone can contain native clone configuration.
    for name in ["config", "config.toml"] {
        let path = recorded.join(".pijul").join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                regular_file(&path)?;
                fs::remove_file(path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    refuse_native_configuration(&recorded)?;
    let recorded = Pijul::with_timeout(recorded, std::time::Duration::from_secs(30));
    Ok(private.run(["list"])? == recorded.run(["list"])?)
}

fn same_file_bytes(expected: &mut impl Read, actual: &mut File) -> Result<bool> {
    let mut left = [0; 8192];
    let mut right = [0; 8192];
    loop {
        let size = expected.read(&mut left)?;
        if size == 0 {
            return Ok(actual.read(&mut right[..1])? == 0);
        }
        match actual.read_exact(&mut right[..size]) {
            Ok(()) if left[..size] == right[..size] => {}
            Ok(()) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
}

fn validate_prepared_files(pijul: &Pijul, prepared: &Prepared) -> Result<()> {
    let review_path = crate::pijul::safe_path(&pijul.repo, Path::new(PRIVATE))?.join("review.txt");
    regular_file(&review_path)?;
    let mut review = String::new();
    for hash in &prepared.candidates {
        let text = pijul.change(hash)?;
        review.push_str(&text);
        if !text.ends_with('\n') {
            review.push('\n');
        }
    }
    ensure!(
        fs::read(&review_path)? == review.as_bytes(),
        "The prepared review data changed"
    );
    match (&prepared.binding.policy, &prepared.policy_file) {
        (None, None) => {}
        (Some(policy), Some(path)) => {
            regular_file(path)?;
            ensure!(
                policy.path == prepared.configuration.values.policy_path
                    && digest(&fs::read(path)?) == policy.sha256,
                "The prepared policy data changed"
            );
        }
        _ => bail!("The prepared policy data is incomplete"),
    }
    Ok(())
}

/// Read authority from source metadata, not from the editable workspace.
pub fn load(source: &Path, workspace: &Path) -> Result<Prepared> {
    let source = canonical_directory(source)?;
    let workspace = canonical_directory(workspace)?;
    ensure!(
        !workspace.starts_with(&source),
        "The workspace is inside the source repository"
    );
    let pointer_path = crate::pijul::safe_path(&workspace, Path::new(POINTER))?;
    let pointer: Pointer = read_json(&pointer_path)?;
    ensure!(
        pointer.schema_version == 1,
        "Unsupported resolution pointer schema"
    );
    ensure!(valid_id(&pointer.id), "Invalid resolution identity");
    let record = crate::pijul::safe_path(
        &source,
        &Path::new(RECORDS).join(format!("{}.json", pointer.id)),
    )?;
    let stored: Stored = read_json(&record)?;
    ensure!(
        stored.schema_version == 1,
        "Unsupported resolution record schema"
    );
    let prepared = stored.prepared;
    ensure!(
        prepared.id == pointer.id && identity(&prepared)? == pointer.id,
        "Resolution identity differs"
    );
    ensure!(
        prepared.source == source && prepared.workspace == workspace,
        "Resolution repository or workspace differs"
    );
    let metadata = fs::symlink_metadata(&workspace)?;
    ensure!(
        metadata.dev() == prepared.workspace_device && metadata.ino() == prepared.workspace_inode,
        "The prepared workspace was replaced"
    );
    ensure!(
        prepared.main == prepared.binding.main.channel,
        "Stored resolution main binding differs"
    );
    ensure!(
        prepared.candidates == prepared.binding.candidates,
        "Stored resolution candidate binding differs"
    );
    validate_candidates(&prepared.candidates)?;
    ensure!(
        prepared.main != prepared.inbox,
        "Stored resolution channels must differ"
    );
    let private = workspace.join(PRIVATE);
    ensure!(
        prepared.review_file == private.join("review.txt"),
        "Stored review path differs"
    );
    ensure!(
        prepared
            .policy_file
            .as_ref()
            .is_none_or(|path| *path == private.join("policy.txt")),
        "Stored policy path differs"
    );
    crate::pijul::safe_path(&workspace, Path::new(".pijul"))?;
    Ok(prepared)
}

/// Record only tracked edits. New files need an explicit native add operation.
pub fn record(prepared: &Prepared, signer: &Signer, reason: &str) -> Result<Completed> {
    let trusted = load(&prepared.source, &prepared.workspace)?;
    ensure!(
        identity(prepared)? == identity(&trusted)? && prepared.id == trusted.id,
        "The supplied resolution record differs from source authority"
    );
    record_workspace(
        &trusted,
        Pijul::new(trusted.workspace.clone()),
        signer,
        reason,
    )
}

pub(crate) fn record_private(
    prepared: &Prepared,
    private: &Pijul,
    signer: &Signer,
    reason: &str,
) -> Result<Completed> {
    let trusted = load(&prepared.source, &prepared.workspace)?;
    ensure!(
        identity(prepared)? == identity(&trusted)? && prepared.id == trusted.id,
        "The supplied resolution record differs from source authority"
    );
    record_workspace(&trusted, Pijul::new(private.repo.clone()), signer, reason)
}

fn record_workspace(
    trusted: &Prepared,
    pijul: Pijul,
    signer: &Signer,
    reason: &str,
) -> Result<Completed> {
    validate_native_metadata(&pijul.repo.join(".pijul"))?;
    refuse_native_configuration(&pijul.repo)?;
    let mut files = trusted.clone();
    files.review_file = pijul.repo.join(PRIVATE).join("review.txt");
    files.policy_file = trusted
        .policy_file
        .as_ref()
        .map(|_| pijul.repo.join(PRIVATE).join("policy.txt"));
    validate_prepared_files(&pijul, &files)?;
    let (current, _) = pijul.channels()?;
    ensure!(
        current.as_deref() == Some(trusted.main.as_str()),
        "The workspace current channel differs"
    );
    let before = native_order(&pijul, &trusted)?;
    // Native recording resolves edited conflict regions. Remaining conflicts are fatal.
    let mut environment = signer.environment()?;
    // Keep native global configuration under the signer's private HOME.
    environment.vars.remove(OsStr::new("PIJUL_CONFIG_DIR"));
    let message = if reason.trim().is_empty() {
        "Resolve the prepared human review"
    } else {
        reason
    };
    pijul
        .call_with_env(
            ["record", "-a", "-m", message, "--author", "patchgate"],
            &environment.vars,
        )
        .context("Cannot record the human resolution")?;
    drop(environment);
    ensure!(
        pijul.conflicts()?.is_empty(),
        "The human workspace still contains unresolved conflicts"
    );
    let after = native_order(&pijul, &trusted)?;
    let after_set: HashSet<_> = after.iter().collect();
    ensure!(
        before.iter().all(|hash| after_set.contains(hash)),
        "A workspace record disappeared"
    );
    let prepared_set: HashSet<_> = trusted.base.iter().chain(&trusted.candidates).collect();
    let imported = after
        .iter()
        .filter(|hash| !prepared_set.contains(hash))
        .cloned()
        .collect();
    let base: HashSet<_> = trusted.base.iter().collect();
    let hashes = after
        .into_iter()
        .filter(|hash| !base.contains(hash))
        .collect();
    Ok(Completed {
        pijul,
        hashes,
        imported,
    })
}

/// Copy native state and tracked work files without source writes or shared inodes.
pub(crate) fn copy_workspace(prepared: &Prepared) -> Result<crate::isolation::Isolated> {
    refuse_native_configuration(&prepared.workspace)?;
    validate_native_metadata(&prepared.workspace.join(".pijul"))?;
    let isolated = crate::isolation::copy_repository(&prepared.workspace)?;
    detach_files(&isolated.pijul.repo.join(".pijul"))?;
    refuse_native_configuration(&isolated.pijul.repo)?;
    let paths = workspace_paths(&isolated.pijul, prepared)?;
    for relative in paths {
        ensure!(
            !relative.as_os_str().is_empty() && !relative.starts_with(".pijul"),
            "A tracked path cannot replace native metadata"
        );
        let source = crate::pijul::safe_path(&prepared.workspace, &relative)?;
        let target = crate::pijul::safe_path(&isolated.pijul.repo, &relative)?;
        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            ensure!(
                metadata.is_file(),
                "Tracked work data must use regular files"
            );
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source, &target)?;
            let after = fs::symlink_metadata(&source)?;
            ensure!(
                after.is_file()
                    && metadata.dev() == after.dev()
                    && metadata.ino() == after.ino()
                    && metadata.len() == after.len()
                    && metadata.modified()? == after.modified()?,
                "The workspace changed during its private copy"
            );
        }
    }
    refuse_native_configuration(&isolated.pijul.repo)?;
    Ok(isolated)
}

// Native list output is ambiguous. Use it only to select empty path placeholders.
// Structured native diff paths and archive members select the actual work bytes.
fn workspace_paths(pijul: &Pijul, prepared: &Prepared) -> Result<HashSet<PathBuf>> {
    let listing = format!("\n{}", pijul.run(["list"])?);
    let mut pending = vec![PathBuf::new()];
    let mut placeholders = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(prepared.workspace.join(&directory))? {
            let entry = entry?;
            let relative = directory.join(entry.file_name());
            if relative.starts_with(".pijul") {
                continue;
            }
            let Some(path) = relative.to_str() else {
                continue;
            };
            if !listing.contains(&format!("\n{path}\n")) && !listing.contains(&format!("\n{path}/"))
            {
                continue;
            }
            let target = pijul.repo.join(&relative);
            if entry.file_type()?.is_dir() {
                fs::create_dir(&target)?;
                pending.push(relative);
            } else {
                File::create(&target)?;
                placeholders.push(relative);
            }
        }
    }
    let diff = pijul.run(["diff", "--output-format", "json"])?;
    let mut paths: HashSet<PathBuf> = if diff.trim().is_empty() {
        HashSet::new()
    } else {
        serde_json::from_str::<std::collections::BTreeMap<PathBuf, serde_json::Value>>(&diff)?
            .into_keys()
            .collect()
    };
    // Empty recorded files can match the placeholders and have no diff.
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let archive = directory.path().join("recorded.tar.gz");
    pijul.call([
        OsStr::new("archive"),
        OsStr::new("--channel"),
        OsStr::new(&prepared.main),
        OsStr::new("-o"),
        archive.as_os_str(),
    ])?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(File::open(archive)?));
    for entry in archive.entries()? {
        paths.insert(crate::pijul::normalize_path(&entry?.path()?)?);
    }
    for path in placeholders {
        fs::remove_file(pijul.repo.join(path))?;
    }
    // Empty placeholder directories do not affect a native record.
    paths.remove(Path::new(""));
    Ok(paths)
}

fn native_order(pijul: &Pijul, prepared: &Prepared) -> Result<Vec<String>> {
    let hashes: Vec<_> = pijul
        .log(&prepared.main)?
        .into_iter()
        .map(|entry| entry.hash)
        .collect();
    let present: HashSet<_> = hashes.iter().collect();
    ensure!(
        prepared
            .base
            .iter()
            .chain(&prepared.candidates)
            .all(|hash| present.contains(hash)),
        "The workspace lacks a prepared base or candidate change"
    );
    let base: HashSet<_> = prepared.base.iter().collect();
    let actual_base: Vec<_> = hashes.iter().filter(|hash| base.contains(hash)).collect();
    ensure!(
        actual_base == prepared.base.iter().collect::<Vec<_>>(),
        "The workspace base order differs"
    );
    let candidates: HashSet<_> = prepared.candidates.iter().collect();
    let actual_candidates: Vec<_> = hashes
        .iter()
        .filter(|hash| candidates.contains(hash))
        .collect();
    ensure!(
        actual_candidates == prepared.candidates.iter().collect::<Vec<_>>(),
        "The workspace candidate order differs"
    );
    for hash in &hashes {
        validate_hash(hash)?;
        regular_file(&pijul.change_file(hash))?;
        pijul
            .change(hash)
            .context("A workspace change is incomplete")?;
    }
    Ok(hashes)
}

fn validate_candidates(candidates: &[String]) -> Result<()> {
    ensure!(
        !candidates.is_empty(),
        "A resolution needs at least one candidate"
    );
    let mut seen = HashSet::new();
    for hash in candidates {
        validate_hash(hash)?;
        ensure!(seen.insert(hash), "Resolution candidates repeat a change");
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<()> {
    ensure!(
        hash.len() == 53
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte)),
        "Invalid native change hash"
    );
    Ok(())
}

fn identity(prepared: &Prepared) -> Result<String> {
    let mut value = serde_json::to_value(prepared)?;
    value
        .as_object_mut()
        .context("Resolution identity is not an object")?
        .remove("id");
    Ok(digest(&serde_json::to_vec(&value)?))
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for part in path.components() {
        if part == Component::ParentDir {
            ensure!(
                fs::symlink_metadata(&current)?.is_dir(),
                "A resolution parent path is not a directory"
            );
            current.pop();
            continue;
        }
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "A resolution path uses a symbolic link"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(current)
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let path = absolute_path(path)?;
    ensure!(
        fs::symlink_metadata(&path)?.is_dir(),
        "A resolution path is not a directory"
    );
    fs::canonicalize(path).context("Cannot resolve a resolution directory")
}

fn new_workspace_path(source: &Path, workspace: &Path) -> Result<PathBuf> {
    let workspace = absolute_path(workspace)?;
    ensure!(
        fs::symlink_metadata(&workspace)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "The resolution workspace must be new"
    );
    let name = workspace
        .file_name()
        .context("The workspace has no directory name")?;
    let parent = canonical_directory(workspace.parent().context("The workspace has no parent")?)?;
    let workspace = parent.join(name);
    ensure!(
        !workspace.starts_with(source),
        "The workspace must be outside the source repository"
    );
    Ok(workspace)
}

fn regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("A required resolution file is absent")?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1,
        "A resolution file is not a private regular file"
    );
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    regular_file(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    serde_json::from_reader(file).map_err(|_| anyhow::anyhow!("Resolution metadata is invalid"))
}

fn private_directory(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = crate::pijul::safe_path(root, Path::new(relative))?;
    fs::create_dir_all(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("A resolution file has no parent")?)?.sync_all()?;
    Ok(())
}

// Detach shared native files before private operations need owner-write access.
pub(crate) fn detach_files(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "Workspace metadata uses a symbolic link"
    );
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            detach_files(&entry?.path())?;
        }
    } else {
        ensure!(
            metadata.is_file(),
            "Workspace metadata contains a special file"
        );
        if metadata.nlink() > 1 {
            let mut copy =
                tempfile::NamedTempFile::new_in(path.parent().context("Metadata has no parent")?)?;
            std::io::copy(&mut File::open(path)?, &mut copy)?;
            copy.as_file()
                .set_permissions(fs::Permissions::from_mode(metadata.mode() | 0o200))?;
            copy.as_file().sync_all()?;
            copy.persist(path).map_err(|error| error.error)?;
        } else if metadata.mode() & 0o200 == 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(metadata.mode() | 0o200))?;
        }
    }
    Ok(())
}

fn validate_native_metadata(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "Workspace metadata uses a symbolic link"
    );
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            validate_native_metadata(&entry?.path())?;
        }
    } else {
        regular_file(path)?;
    }
    Ok(())
}

// Pijul reads personal hooks from either metadata file and shared hooks from pijul.toml.
// Reject each route, not selected TOML keys. New native options must not bypass this boundary.
fn refuse_native_configuration(workspace: &Path) -> Result<()> {
    for relative in [".pijul/config", ".pijul/config.toml", "pijul.toml"] {
        match fs::symlink_metadata(workspace.join(relative)) {
            Ok(_) => {
                bail!("Native configuration is not permitted in a resolution workspace: {relative}")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::MainBinding;
    use std::os::unix::fs::symlink;

    fn prepared(source: &Path, workspace: &Path) -> Result<Prepared> {
        fs::create_dir_all(workspace.join(".pijul"))?;
        let metadata = fs::metadata(workspace)?;
        let candidates = vec!["A".repeat(53)];
        Ok(Prepared {
            id: String::new(),
            source: source.to_path_buf(),
            workspace: workspace.to_path_buf(),
            binding: ReviewBinding {
                candidates: candidates.clone(),
                policy: None,
                main: MainBinding {
                    channel: "main".into(),
                    state: None,
                },
            },
            configuration: configuration::Evidence {
                source: "environment".into(),
                path: None,
                sha256: None,
                values: configuration::Values::default(),
            },
            candidates,
            base: Vec::new(),
            conflicts: Vec::new(),
            policy_file: None,
            review_file: workspace.join(PRIVATE).join("review.txt"),
            main: "main".into(),
            inbox: "inbox".into(),
            workspace_device: metadata.dev(),
            workspace_inode: metadata.ino(),
        })
    }

    fn store(prepared: &mut Prepared) -> Result<()> {
        prepared.id = identity(prepared)?;
        let records = private_directory(&prepared.source, RECORDS)?;
        private_directory(&prepared.workspace, PRIVATE)?;
        private_file(
            &records.join(format!("{}.json", prepared.id)),
            &serde_json::to_vec(&Stored {
                schema_version: 1,
                prepared: prepared.clone(),
            })?,
        )?;
        private_file(
            &prepared.workspace.join(POINTER),
            &serde_json::to_vec(&Pointer {
                schema_version: 1,
                id: prepared.id.clone(),
            })?,
        )
    }

    #[test]
    fn workspace_paths_refuse_source_links_and_existing_directories() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source");
        fs::create_dir(&source)?;
        assert!(new_workspace_path(&source, &source.join("workspace")).is_err());
        assert!(new_workspace_path(&source, &source).is_err());
        symlink(&root, root.join("alias"))?;
        assert!(new_workspace_path(&source, &root.join("alias/workspace")).is_err());
        assert!(new_workspace_path(&source, &root.join("alias/../workspace")).is_err());
        assert!(new_workspace_path(&source, &root.join("missing/../workspace")).is_err());
        fs::write(root.join("file"), "A regular file.\n")?;
        assert!(new_workspace_path(&source, &root.join("file/../workspace")).is_err());
        assert!(new_workspace_path(&source, &source.join("../source/workspace")).is_err());
        assert_eq!(
            new_workspace_path(&source, &source.join("../workspace"))?,
            root.join("workspace")
        );
        assert_eq!(
            new_workspace_path(&source, &root.join("workspace"))?,
            root.join("workspace")
        );
        Ok(())
    }

    #[test]
    fn editable_pointer_cannot_change_trusted_bindings() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source");
        fs::create_dir(&source)?;
        let mut original = prepared(&source, &root.join("workspace"))?;
        store(&mut original)?;
        let trusted = load(&source, &original.workspace)?;
        assert_eq!(trusted.binding.main.channel, "main");
        fs::write(
            original.workspace.join(POINTER),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1, "id": original.id,
                "binding": { "main": { "channel": "inbox", "state": null } }
            }))?,
        )?;
        assert!(load(&source, &original.workspace).is_err());
        Ok(())
    }

    #[test]
    fn copied_or_incomplete_workspace_fails() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source");
        fs::create_dir(&source)?;
        let mut original = prepared(&source, &root.join("workspace"))?;
        store(&mut original)?;
        let other = root.join("other");
        private_directory(&other, PRIVATE)?;
        fs::copy(original.workspace.join(POINTER), other.join(POINTER))?;
        assert!(load(&source, &other).is_err());
        fs::remove_file(original.workspace.join(POINTER))?;
        assert!(load(&source, &original.workspace).is_err());
        Ok(())
    }

    #[test]
    fn candidates_refuse_duplicates_and_path_hashes() {
        assert!(validate_candidates(&[]).is_err());
        assert!(validate_candidates(&["A".repeat(53), "A".repeat(53)]).is_err());
        assert!(validate_candidates(&["../changes".into()]).is_err());
        assert!(validate_candidates(&["A".repeat(53)]).is_ok());
    }

    fn native_record(pijul: &Pijul, signer: &Signer, message: &str) -> Result<String> {
        let environment = signer.environment()?;
        pijul.call_with_env(
            ["record", "-a", "-m", message, "--author", "patchgate"],
            &environment.vars,
        )?;
        let (channel, _) = pijul.channels()?;
        pijul
            .log(&channel.context("The test has no current channel")?)?
            .pop()
            .map(|entry| entry.hash)
            .context("The test record is absent")
    }

    fn native_fixture(conflict: bool) -> Result<(tempfile::TempDir, Prepared, Signer)> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source");
        fs::create_dir(&source)?;
        let pijul = Pijul::new(source.clone());
        pijul.run(["init", "--channel", "main"])?;
        let signer = Signer::new(source.join(".pijul/patchgate"));
        fs::write(source.join("value.txt"), "base\n")?;
        fs::write(source.join("POLICY.md"), "Use the recorded policy.\n")?;
        pijul.run(["add", "value.txt", "POLICY.md"])?;
        native_record(&pijul, &signer, "Define the base")?;
        pijul.run(["fork", "--channel", "main", "inbox"])?;
        pijul.run(["channel", "switch", "inbox"])?;
        fs::write(source.join("value.txt"), "candidate\n")?;
        let candidate = native_record(&pijul, &signer, "Change the value")?;
        if conflict {
            pijul.run(["channel", "switch", "main"])?;
            fs::write(source.join("value.txt"), "main\n")?;
            native_record(&pijul, &signer, "Change main independently")?;
            pijul.run(["channel", "switch", "inbox"])?;
        }
        fs::write(source.join("value.txt"), "dirty source\n")?;
        let isolated = crate::isolation::copy_repository(&source)?;
        let configuration =
            configuration::load(&isolated.pijul, "main", &configuration::Values::default())?;
        let policy = isolated.pijul.read_file("main", "POLICY.md")?;
        let binding = ReviewBinding::new(
            std::slice::from_ref(&candidate),
            "POLICY.md",
            policy.as_deref(),
            "main",
            &isolated.pijul.snapshot("main")?,
        );
        let prepared = prepare(
            &source,
            &isolated.pijul,
            "main",
            "inbox",
            &[candidate],
            &root.join("workspace"),
            binding,
            configuration,
        )?;
        Ok((directory, prepared, signer))
    }

    #[test]
    fn private_record_preserves_tracked_edits_and_native_add_remove_state() -> Result<()> {
        let (_directory, prepared, _signer) = native_fixture(false)?;
        let workspace = Pijul::new(prepared.workspace.clone());
        fs::write(workspace.repo.join("value.txt"), "pending human edit\n")?;
        fs::write(
            workspace.repo.join("added.txt"),
            "explicit native addition\n",
        )?;
        workspace.run(["add", "added.txt"])?;
        workspace.run(["remove", "POLICY.md"])?;
        fs::write(workspace.repo.join("untracked.txt"), "excluded work file\n")?;
        let pointer = fs::read(workspace.repo.join(POINTER))?;
        let authority = fs::read(
            prepared
                .source
                .join(RECORDS)
                .join(format!("{}.json", prepared.id)),
        )?;
        let private = copy_workspace(&prepared)?;
        let signer = Signer::new(private.pijul.repo.join(".pijul/patchgate"));
        let completed = record_private(&prepared, &private.pijul, &signer, "Verify private work")?;
        assert_eq!(
            completed.pijul.read_file("main", "value.txt")?.as_deref(),
            Some("pending human edit\n")
        );
        assert_eq!(
            completed.pijul.read_file("main", "added.txt")?.as_deref(),
            Some("explicit native addition\n")
        );
        assert_eq!(completed.pijul.read_file("main", "POLICY.md")?, None);
        assert_eq!(completed.pijul.read_file("main", "untracked.txt")?, None);
        assert_eq!(fs::read(workspace.repo.join(POINTER))?, pointer);
        assert_eq!(
            fs::read(
                prepared
                    .source
                    .join(RECORDS)
                    .join(format!("{}.json", prepared.id))
            )?,
            authority
        );
        assert_eq!(
            workspace.log("main")?.len(),
            prepared.base.len() + prepared.candidates.len()
        );
        assert_eq!(
            fs::read(workspace.repo.join("value.txt"))?,
            b"pending human edit\n"
        );
        assert_eq!(
            fs::read(workspace.repo.join("untracked.txt"))?,
            b"excluded work file\n"
        );
        Ok(())
    }

    #[test]
    fn private_record_preserves_newline_paths_without_untracked_alias_bytes() -> Result<()> {
        fn snapshot(root: &Path) -> Result<std::collections::BTreeMap<PathBuf, (Vec<u8>, u32)>> {
            let mut files = std::collections::BTreeMap::new();
            let mut pending = vec![root.to_path_buf()];
            while let Some(directory) = pending.pop() {
                for entry in fs::read_dir(directory)? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        pending.push(entry.path());
                    } else {
                        files.insert(
                            entry.path().strip_prefix(root)?.to_path_buf(),
                            (fs::read(entry.path())?, entry.metadata()?.mode()),
                        );
                    }
                }
            }
            Ok(files)
        }
        let (_directory, prepared, signer) = native_fixture(false)?;
        let workspace = Pijul::new(prepared.workspace.clone());
        fs::write(workspace.repo.join("tracked\nname"), "recorded work\n")?;
        fs::write(workspace.repo.join("removed\nname"), "removed work\n")?;
        fs::write(workspace.repo.join("empty\nname"), "")?;
        workspace.run(["add", "tracked\nname", "removed\nname", "empty\nname"])?;
        native_record(&workspace, &signer, "Record unusual native paths")?;
        fs::write(
            workspace.repo.join("tracked\nname"),
            "pending tracked work\n",
        )?;
        fs::write(workspace.repo.join("added\nname"), "new tracked work\n")?;
        workspace.run(["add", "added\nname"])?;
        workspace.run(["remove", "removed\nname"])?;
        for alias in ["tracked", "name", "added", "removed"] {
            fs::write(workspace.repo.join(alias), "private untracked alias\n")?;
        }
        let source_before = snapshot(&prepared.source)?;
        let workspace_before = snapshot(&prepared.workspace)?;
        let private = copy_workspace(&prepared)?;
        for alias in ["tracked", "name", "added", "removed"] {
            assert!(!private.pijul.repo.join(alias).exists());
        }
        let private_signer = Signer::new(private.pijul.repo.join(".pijul/patchgate"));
        let completed = record_private(
            &prepared,
            &private.pijul,
            &private_signer,
            "Verify exact native paths",
        )?;
        for (path, expected) in [
            ("tracked\nname", Some("pending tracked work\n")),
            ("added\nname", Some("new tracked work\n")),
            ("removed\nname", None),
            ("empty\nname", Some("")),
            ("tracked", None),
            ("name", None),
            ("added", None),
            ("removed", None),
        ] {
            assert_eq!(
                completed.pijul.read_file("main", path)?.as_deref(),
                expected
            );
        }
        assert_eq!(snapshot(&prepared.source)?, source_before);
        assert_eq!(snapshot(&prepared.workspace)?, workspace_before);
        let accepted = record(&prepared, &signer, "Accept exact native paths")?;
        for path in [
            "tracked\nname",
            "added\nname",
            "removed\nname",
            "empty\nname",
        ] {
            assert_eq!(
                completed.pijul.read_file_bytes("main", path)?,
                accepted.pijul.read_file_bytes("main", path)?,
            );
        }
        Ok(())
    }

    #[test]
    fn native_records_preserve_multiple_supplements_and_dirty_source() -> Result<()> {
        let (_directory, prepared, signer) = native_fixture(false)?;
        assert_eq!(
            fs::read(prepared.workspace.join("value.txt"))?,
            b"candidate\n"
        );
        assert_eq!(
            fs::read(prepared.policy_file.as_ref().unwrap())?,
            b"Use the recorded policy.\n"
        );
        let pijul = Pijul::new(prepared.workspace.clone());
        fs::write(prepared.workspace.join("value.txt"), "first human edit\n")?;
        let first = native_record(&pijul, &signer, "Record the first human edit")?;
        fs::write(prepared.workspace.join("value.txt"), "second human edit\n")?;
        fs::write(
            prepared.workspace.join("untracked.txt"),
            "Do not add this file.\n",
        )?;
        let completed = record(&prepared, &signer, "Record the second human edit")?;
        assert_eq!(completed.hashes.len(), 3);
        assert_eq!(completed.hashes[0], prepared.candidates[0]);
        assert_eq!(completed.hashes[1], first);
        assert_eq!(completed.imported.len(), 2);
        assert!(completed.imported.contains(&first));
        assert_eq!(completed.pijul.read_file("main", "untracked.txt")?, None);
        assert_eq!(
            fs::read(prepared.source.join("value.txt"))?,
            b"dirty source\n"
        );
        let repeated = record(&prepared, &signer, "Retain the existing human records")?;
        assert_eq!(repeated.hashes, completed.hashes);
        assert_eq!(repeated.imported, completed.imported);
        Ok(())
    }

    fn refresh_from_source(previous: &Prepared, name: &str) -> Result<Refreshed> {
        let isolated = crate::isolation::copy_repository(&previous.source)?;
        let configuration = configuration::load(
            &isolated.pijul,
            &previous.main,
            &configuration::Values::default(),
        )?;
        let policy = isolated
            .pijul
            .read_file(&previous.main, &configuration.values.policy_path)?;
        let binding = ReviewBinding::new(
            &previous.candidates,
            &configuration.values.policy_path,
            policy.as_deref(),
            &previous.main,
            &isolated.pijul.snapshot(&previous.main)?,
        );
        refresh(
            &previous.source,
            &isolated.pijul,
            previous,
            &previous.candidates,
            &previous.workspace.parent().unwrap().join(name),
            binding,
            configuration,
        )
    }

    fn advance_main(previous: &Prepared, signer: &Signer) -> Result<(Pijul, String)> {
        let source = Pijul::new(previous.source.clone());
        fs::write(source.repo.join("value.txt"), "candidate\n")?;
        source.run(["channel", "switch", "main"])?;
        fs::write(source.repo.join("main.txt"), "Current main content.\n")?;
        fs::write(source.repo.join("POLICY.md"), "Use the current policy.\n")?;
        source.run(["add", "main.txt"])?;
        let hash = native_record(&source, signer, "Advance main")?;
        Ok((source, hash))
    }

    #[test]
    fn refresh_refuses_a_new_workspace_inside_the_old_workspace() -> Result<()> {
        let (_directory, previous, _signer) = native_fixture(false)?;
        let pointer = fs::read(previous.workspace.join(POINTER))?;
        assert!(refresh_from_source(&previous, "workspace/nested").is_err());
        assert!(!previous.workspace.join("nested").exists());
        assert_eq!(fs::read(previous.workspace.join(POINTER))?, pointer);
        Ok(())
    }

    #[test]
    fn refresh_preserves_native_human_records_and_current_main() -> Result<()> {
        let (_directory, previous, signer) = native_fixture(false)?;
        let old = Pijul::new(previous.workspace.clone());
        fs::write(old.repo.join("value.txt"), "First human edit.\n")?;
        let first = native_record(&old, &signer, "Record the first edit")?;
        fs::write(old.repo.join("value.txt"), "Second human edit.\n")?;
        fs::write(old.repo.join("human.txt"), "A recorded human file.\n")?;
        old.run(["add", "human.txt"])?;
        let second = native_record(&old, &signer, "Record the second edit")?;
        fs::write(old.repo.join("untracked.txt"), "Retain this old file.\n")?;
        let pointer = fs::read(old.repo.join(POINTER))?;
        let old_state = old.snapshot("main")?;
        let (source, main_hash) = advance_main(&previous, &signer)?;
        fs::write(source.repo.join("value.txt"), "Dirty source content.\n")?;
        let refreshed = refresh_from_source(&previous, "fresh")?;
        assert_eq!(refreshed.previous_id, previous.id);
        assert_eq!(refreshed.preserved, vec![first.clone(), second.clone()]);
        assert_ne!(refreshed.prepared.id, previous.id);
        assert!(refreshed.prepared.base.contains(&main_hash));
        assert_eq!(
            fs::read(refreshed.prepared.workspace.join("value.txt"))?,
            b"Second human edit.\n"
        );
        assert_eq!(
            fs::read(refreshed.prepared.workspace.join("main.txt"))?,
            b"Current main content.\n"
        );
        assert_eq!(
            fs::read(refreshed.prepared.workspace.join("human.txt"))?,
            b"A recorded human file.\n"
        );
        assert_eq!(
            fs::read(refreshed.prepared.policy_file.as_ref().unwrap())?,
            b"Use the current policy.\n"
        );
        assert!(!refreshed.prepared.workspace.join("untracked.txt").exists());
        assert_eq!(fs::read(old.repo.join(POINTER))?, pointer);
        assert_eq!(old.snapshot("main")?, old_state);
        assert_eq!(
            fs::read(old.repo.join("untracked.txt"))?,
            b"Retain this old file.\n"
        );
        assert_eq!(
            fs::read(source.repo.join("value.txt"))?,
            b"Dirty source content.\n"
        );
        let trusted = load(&previous.source, &refreshed.prepared.workspace)?;
        assert_eq!(trusted.id, refreshed.prepared.id);
        let completed = record(&refreshed.prepared, &signer, "Accept the preserved records")?;
        assert_eq!(
            completed.hashes,
            vec![
                previous.candidates[0].clone(),
                first.clone(),
                second.clone()
            ]
        );
        assert_eq!(completed.imported, HashSet::from([first, second]));
        Ok(())
    }

    #[test]
    fn refresh_preserves_old_metadata_after_a_tracked_mtime_change() -> Result<()> {
        fn metadata_bytes(
            directory: &Path,
        ) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
            let mut files = std::collections::BTreeMap::new();
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    files.extend(metadata_bytes(&entry.path())?);
                } else {
                    files.insert(entry.path(), fs::read(entry.path())?);
                }
            }
            Ok(files)
        }
        let (_directory, previous, _signer) = native_fixture(false)?;
        let metadata = previous.workspace.join(".pijul");
        File::open(previous.workspace.join("value.txt"))?.set_times(
            fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(60)),
        )?;
        let before = metadata_bytes(&metadata)?;
        let refreshed = refresh_from_source(&previous, "fresh")?;
        assert_eq!(metadata_bytes(&metadata)?, before);
        assert_eq!(
            fs::read(refreshed.prepared.workspace.join("value.txt"))?,
            b"candidate\n"
        );
        Ok(())
    }

    #[test]
    fn refresh_refuses_tracked_edits_without_a_new_record() -> Result<()> {
        let (_directory, previous, _signer) = native_fixture(false)?;
        let old = Pijul::new(previous.workspace.clone());
        let before = old.snapshot("main")?;
        fs::write(old.repo.join("value.txt"), "A pending human edit.\n")?;
        fs::write(old.repo.join("untracked.txt"), "An untracked file.\n")?;
        assert!(refresh_from_source(&previous, "fresh").is_err());
        assert!(!old.repo.parent().unwrap().join("fresh").exists());
        assert_eq!(old.snapshot("main")?, before);
        assert_eq!(
            fs::read(old.repo.join("value.txt"))?,
            b"A pending human edit.\n"
        );
        assert!(old.repo.join("untracked.txt").exists());
        Ok(())
    }

    #[test]
    fn refresh_refuses_new_tracked_files_without_a_record() -> Result<()> {
        let (_directory, previous, _signer) = native_fixture(false)?;
        let old = Pijul::new(previous.workspace.clone());
        fs::write(old.repo.join("pending.txt"), "A pending human file.\n")?;
        old.run(["add", "pending.txt"])?;
        assert!(refresh_from_source(&previous, "fresh").is_err());
        assert!(!old.repo.parent().unwrap().join("fresh").exists());
        assert_eq!(
            fs::read(old.repo.join("pending.txt"))?,
            b"A pending human file.\n"
        );
        Ok(())
    }

    #[test]
    fn refresh_refuses_hooks_before_native_workspace_commands() -> Result<()> {
        let (_directory, previous, _signer) = native_fixture(false)?;
        let marker = previous.workspace.join("hook-marker");
        let hook = previous.workspace.join("hook");
        fs::write(&hook, b"#!/bin/sh\ntouch hook-marker\n")?;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
        for relative in [".pijul/config", ".pijul/config.toml", "pijul.toml"] {
            let path = previous.workspace.join(relative);
            let bytes = b"[hooks]\npreHooks = [\"./hook\"]\n";
            fs::write(&path, bytes)?;
            assert!(refresh_from_source(&previous, "fresh").is_err());
            assert!(!marker.exists());
            assert_eq!(fs::read(&path)?, bytes);
            fs::remove_file(path)?;
        }
        assert!(!previous.workspace.parent().unwrap().join("fresh").exists());
        Ok(())
    }

    #[test]
    fn refresh_refuses_removed_supplemental_dependencies() -> Result<()> {
        let (_directory, original, signer) = native_fixture(false)?;
        let (source, removed) = advance_main(&original, &signer)?;
        let previous = refresh_from_source(&original, "second")?.prepared;
        let old = Pijul::new(previous.workspace.clone());
        fs::write(old.repo.join("main.txt"), "A human change to old main.\n")?;
        let human = native_record(&old, &signer, "Change the old main file")?;
        assert!(crate::change::dependencies(&old.change(&human)?).contains(&removed));
        source.run(["unrecord", &removed])?;
        let old_state = old.snapshot("main")?;
        assert!(refresh_from_source(&previous, "fresh").is_err());
        assert_eq!(old.snapshot("main")?, old_state);
        assert!(!previous.workspace.parent().unwrap().join("fresh").exists());
        assert!(!source.hashes("main")?.contains(&removed));
        Ok(())
    }

    #[test]
    fn refresh_retains_unresolved_conflicts_for_human_review() -> Result<()> {
        let (_directory, previous, _signer) = native_fixture(true)?;
        let old = Pijul::new(previous.workspace.clone());
        let before = old.snapshot("main")?;
        let refreshed = refresh_from_source(&previous, "fresh")?;
        assert!(!refreshed.prepared.conflicts.is_empty());
        assert!(refreshed.preserved.is_empty());
        assert_eq!(old.snapshot("main")?, before);
        assert_eq!(
            Pijul::new(refreshed.prepared.workspace.clone()).hashes("main")?,
            previous
                .base
                .iter()
                .chain(&previous.candidates)
                .cloned()
                .collect()
        );
        Ok(())
    }

    #[test]
    fn refresh_refuses_changed_prepared_data_and_missing_native_records() -> Result<()> {
        for kind in ["review", "policy", "candidate", "authority", "channel"] {
            let (_directory, previous, _signer) = native_fixture(false)?;
            let old = Pijul::new(previous.workspace.clone());
            match kind {
                "review" => fs::write(&previous.review_file, "Changed review data.\n")?,
                "policy" => fs::remove_file(previous.policy_file.as_ref().unwrap())?,
                "candidate" => fs::remove_file(old.change_file(&previous.candidates[0]))?,
                "authority" => fs::remove_file(
                    previous
                        .source
                        .join(RECORDS)
                        .join(format!("{}.json", previous.id)),
                )?,
                "channel" => {
                    old.run(["fork", "--channel", "main", "other"])?;
                    old.run(["channel", "switch", "other"])?;
                }
                _ => unreachable!(),
            }
            assert!(refresh_from_source(&previous, "fresh").is_err());
            assert!(!old.repo.parent().unwrap().join("fresh").exists());
        }
        Ok(())
    }

    #[test]
    fn refresh_does_not_restore_removed_old_base_changes() -> Result<()> {
        let (_directory, original, signer) = native_fixture(false)?;
        let (source, removed) = advance_main(&original, &signer)?;
        let previous = refresh_from_source(&original, "second")?.prepared;
        source.run(["unrecord", &removed])?;
        let refreshed = refresh_from_source(&previous, "fresh")?;
        assert!(!refreshed.prepared.base.contains(&removed));
        assert!(!refreshed.prepared.workspace.join("main.txt").exists());
        assert!(previous.workspace.join("main.txt").exists());
        assert_eq!(
            Pijul::new(refreshed.prepared.workspace).hashes("main")?,
            original
                .base
                .iter()
                .chain(&original.candidates)
                .cloned()
                .collect()
        );
        Ok(())
    }

    #[test]
    fn refresh_retains_supplements_that_current_main_already_contains() -> Result<()> {
        let (_directory, previous, signer) = native_fixture(false)?;
        let old = Pijul::new(previous.workspace.clone());
        fs::write(old.repo.join("POLICY.md"), "Use the human policy.\n")?;
        let human = native_record(&old, &signer, "Update the policy")?;
        assert!(
            !crate::change::dependencies(&old.change(&human)?).contains(&previous.candidates[0])
        );
        let source = Pijul::new(previous.source.clone());
        fs::write(source.repo.join("value.txt"), "candidate\n")?;
        source.run(["channel", "switch", "main"])?;
        source.call([OsStr::new("apply"), old.change_file(&human).as_os_str()])?;
        let refreshed = refresh_from_source(&previous, "fresh")?;
        assert_eq!(refreshed.preserved, vec![human.clone()]);
        assert!(refreshed.prepared.base.contains(&human));
        let completed = record(&refreshed.prepared, &signer, "Accept the current plan")?;
        assert_eq!(completed.hashes, previous.candidates);
        assert!(completed.imported.is_empty());
        Ok(())
    }

    #[test]
    fn native_configuration_cannot_run_a_hook_with_the_signer() -> Result<()> {
        let (_directory, prepared, signer) = native_fixture(false)?;
        let pijul = Pijul::new(prepared.workspace.clone());
        fs::write(
            prepared.workspace.join("value.txt"),
            "existing human record\n",
        )?;
        let existing = native_record(&pijul, &signer, "Retain the human record")?;
        fs::write(prepared.workspace.join("value.txt"), "pending human edit\n")?;
        let marker = prepared.workspace.join("hook-marker");
        let hook = prepared.workspace.join("hook");
        fs::write(
            &hook,
            b"#!/bin/sh\nprintf '%s\\n' \"$SSH_AUTH_SOCK\" > hook-marker\n",
        )?;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
        let configuration = b"[hooks]\npreHooks = [\"./hook\"]\nrecord = [\"./hook\"]\n";
        for relative in [".pijul/config", ".pijul/config.toml", "pijul.toml"] {
            let path = prepared.workspace.join(relative);
            fs::write(&path, configuration)?;
            let error = record(&prepared, &signer, "Refuse executable configuration")
                .err()
                .context("Native configuration did not stop the record")?;
            assert!(error.to_string().contains(relative));
            assert!(!marker.exists());
            assert_eq!(fs::read(&path)?, configuration);
            assert_eq!(
                fs::read(prepared.workspace.join("value.txt"))?,
                b"pending human edit\n"
            );
            fs::remove_file(path)?;
        }
        let completed = record(&prepared, &signer, "Record the retained edit")?;
        assert_eq!(completed.hashes.len(), 3);
        assert_eq!(completed.hashes[0], prepared.candidates[0]);
        assert_eq!(completed.hashes[1], existing);
        assert!(completed.imported.contains(&existing));
        assert_eq!(
            completed.pijul.read_file("main", "value.txt")?,
            Some("pending human edit\n".into())
        );
        assert!(!marker.exists());
        assert_eq!(
            fs::read(prepared.source.join("value.txt"))?,
            b"dirty source\n"
        );
        Ok(())
    }

    #[test]
    fn missing_native_candidate_fails_before_record() -> Result<()> {
        let (_directory, prepared, signer) = native_fixture(false)?;
        let pijul = Pijul::new(prepared.workspace.clone());
        pijul.run(["unrecord", &prepared.candidates[0]])?;
        assert!(record(&prepared, &signer, "Refuse an incomplete workspace").is_err());
        Ok(())
    }

    #[test]
    fn different_current_channel_fails_before_record() -> Result<()> {
        let (_directory, prepared, signer) = native_fixture(false)?;
        let pijul = Pijul::new(prepared.workspace.clone());
        pijul.run(["fork", "--channel", "main", "other"])?;
        pijul.run(["channel", "switch", "other"])?;
        assert!(record(&prepared, &signer, "Refuse a different channel").is_err());
        Ok(())
    }

    #[test]
    fn unresolved_native_conflicts_cannot_complete() -> Result<()> {
        let (_directory, prepared, signer) = native_fixture(true)?;
        assert!(!prepared.conflicts.is_empty());
        assert!(record(&prepared, &signer, "Refuse unresolved conflicts").is_err());
        Ok(())
    }

    #[test]
    fn missing_native_base_file_fails_before_record() -> Result<()> {
        let (_directory, prepared, signer) = native_fixture(false)?;
        let pijul = Pijul::new(prepared.workspace.clone());
        fs::remove_file(pijul.change_file(&prepared.base[0]))?;
        assert!(record(&prepared, &signer, "Refuse an incomplete base").is_err());
        Ok(())
    }

    #[test]
    fn altered_prepared_binding_and_linked_pointer_fail() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source");
        fs::create_dir(&source)?;
        let mut original = prepared(&source, &root.join("workspace"))?;
        store(&mut original)?;
        let original_id = original.id.clone();
        original.binding.main.channel = "inbox".into();
        assert_ne!(identity(&original)?, original_id);
        let authoritative = load(&source, &original.workspace)?;
        assert_eq!(authoritative.binding.main.channel, "main");
        fs::hard_link(original.workspace.join(POINTER), root.join("pointer-alias"))?;
        assert!(load(&source, &original.workspace).is_err());
        Ok(())
    }

    fn readiness(prepared: &Prepared) -> Result<Readiness> {
        inspect(
            &prepared.source,
            &prepared.workspace,
            &configuration::Values::default(),
        )
    }

    fn has_blocker(report: &Readiness, code: &str) -> bool {
        report.blockers.iter().any(|blocker| blocker.code == code)
    }

    fn tree_bytes(root: &Path) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
        let mut files = std::collections::BTreeMap::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                files.extend(tree_bytes(&entry.path())?);
            } else {
                files.insert(entry.path(), fs::read(entry.path())?);
            }
        }
        Ok(files)
    }

    #[test]
    fn readiness_refuses_editable_authority_without_trusted_fields() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source");
        fs::create_dir(&source)?;
        let mut prepared = prepared(&source, &root.join("workspace"))?;
        store(&mut prepared)?;
        fs::write(
            prepared.workspace.join(POINTER),
            br#"{"schema_version":1,"id":"untrusted","main":"editable-channel"}"#,
        )?;
        let source_before = tree_bytes(&source)?;
        let workspace_before = tree_bytes(&prepared.workspace)?;
        let report = readiness(&prepared)?;
        assert!(has_blocker(&report, "invalid_authority"));
        assert!(!report.authorizes_acceptance);
        assert!(report.prepared_id.is_none());
        assert!(report.main.is_none());
        assert!(report.inbox.is_none());
        assert!(report.candidates.is_none());
        assert!(report.pending_tracked_edits.is_none());
        assert_eq!(tree_bytes(&source)?, source_before);
        assert_eq!(tree_bytes(&prepared.workspace)?, workspace_before);
        assert!(!serde_json::to_string(&report)?.contains("editable-channel"));
        Ok(())
    }

    #[test]
    fn readiness_refuses_unsupported_trusted_channel_names() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let source = root.join("source");
        fs::create_dir(&source)?;
        let mut prepared = prepared(&source, &root.join("workspace"))?;
        prepared.main = "--unsupported".into();
        prepared.binding.main.channel = prepared.main.clone();
        store(&mut prepared)?;
        let report = readiness(&prepared)?;
        assert!(has_blocker(&report, "unsupported_channels"));
        assert!(report.pending_tracked_edits.is_none());
        Ok(())
    }

    #[test]
    fn readiness_preserves_all_bytes_and_retains_pending_checks() -> Result<()> {
        let (_directory, prepared, _signer) = native_fixture(false)?;
        File::open(prepared.workspace.join("value.txt"))?.set_times(
            fs::FileTimes::new().set_modified(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
            ),
        )?;
        fs::write(
            prepared.workspace.join("untracked.txt"),
            "Untracked data.\n",
        )?;
        let source_before = tree_bytes(&prepared.source)?;
        let workspace_before = tree_bytes(&prepared.workspace)?;
        let report = readiness(&prepared)?;
        assert!(report.blockers.is_empty());
        assert!(!report.authorizes_acceptance);
        assert_eq!(report.prepared_id.as_deref(), Some(prepared.id.as_str()));
        assert_eq!(report.main.as_deref(), Some("main"));
        assert_eq!(report.inbox.as_deref(), Some("inbox"));
        assert_eq!(report.candidates.as_ref(), Some(&prepared.candidates));
        assert_eq!(report.pending_tracked_edits, Some(false));
        assert_eq!(report.stale_main, Some(false));
        assert_eq!(report.stale_configuration, Some(false));
        assert_eq!(report.stale_policy, Some(false));
        assert!(report.recorded_conflicts.as_ref().unwrap().is_empty());
        for code in [
            "credential_checks",
            "runtime_isolation",
            "nix_checks",
            "conditional_acceptance",
            "conflict_verification",
        ] {
            assert!(
                report
                    .pending_verification
                    .iter()
                    .any(|check| check.code == code)
            );
        }
        assert_eq!(tree_bytes(&prepared.source)?, source_before);
        assert_eq!(tree_bytes(&prepared.workspace)?, workspace_before);
        Ok(())
    }

    #[test]
    fn readiness_reports_pending_edits_without_preventing_explicit_record() -> Result<()> {
        let (_directory, prepared, signer) = native_fixture(false)?;
        fs::write(
            prepared.workspace.join("value.txt"),
            "A pending human edit.\n",
        )?;
        let before = tree_bytes(&prepared.workspace)?;
        let report = readiness(&prepared)?;
        assert_eq!(report.pending_tracked_edits, Some(true));
        assert!(report.blockers.is_empty());
        assert!(
            report
                .pending_verification
                .iter()
                .any(|check| check.code == "record_tracked_edits")
        );
        assert_eq!(tree_bytes(&prepared.workspace)?, before);
        let completed = record(&prepared, &signer, "Accept the pending human edit")?;
        assert_eq!(completed.imported.len(), 1);
        assert_eq!(
            completed.pijul.read_file(&prepared.main, "value.txt")?,
            Some("A pending human edit.\n".into()),
        );
        Ok(())
    }

    #[test]
    fn readiness_reports_staged_additions_and_tracked_removals() -> Result<()> {
        let (_directory, prepared, _signer) = native_fixture(false)?;
        let workspace = Pijul::new(prepared.workspace.clone());
        fs::write(workspace.repo.join("added.txt"), "A staged file.\n")?;
        workspace.run(["add", "added.txt"])?;
        let before = tree_bytes(&workspace.repo)?;
        let report = readiness(&prepared)?;
        assert_eq!(report.pending_tracked_edits, Some(true));
        assert!(report.blockers.is_empty());
        assert_eq!(tree_bytes(&workspace.repo)?, before);
        fs::remove_file(workspace.repo.join("value.txt"))?;
        let report = readiness(&prepared)?;
        assert_eq!(report.pending_tracked_edits, Some(true));
        assert!(report.blockers.is_empty());
        Ok(())
    }

    #[test]
    fn readiness_reports_recorded_conflicts_until_explicit_record() -> Result<()> {
        let (_directory, prepared, signer) = native_fixture(true)?;
        let report = readiness(&prepared)?;
        assert!(has_blocker(&report, "recorded_conflicts"));
        fs::write(
            prepared.workspace.join("value.txt"),
            "A human resolution.\n",
        )?;
        let before = tree_bytes(&prepared.workspace)?;
        let report = readiness(&prepared)?;
        assert_eq!(report.pending_tracked_edits, Some(true));
        assert!(!report.recorded_conflicts.as_ref().unwrap().is_empty());
        assert!(!has_blocker(&report, "recorded_conflicts"));
        assert!(
            report
                .pending_verification
                .iter()
                .any(|check| check.code == "conflict_verification")
        );
        assert_eq!(tree_bytes(&prepared.workspace)?, before);
        record(&prepared, &signer, "Accept the human resolution")?;
        Ok(())
    }

    #[test]
    fn readiness_reports_main_configuration_and_policy_drift() -> Result<()> {
        let (_directory, prepared, signer) = native_fixture(false)?;
        let (source, _) = advance_main(&prepared, &signer)?;
        fs::write(
            source.repo.join(configuration::PATH),
            br#"{"schema_version":1,"settings":{"max_change_chars":5000}}"#,
        )?;
        source.run(["add", configuration::PATH])?;
        native_record(&source, &signer, "Change trusted configuration")?;
        fs::write(source.repo.join("value.txt"), "Dirty source data.\n")?;
        let before = tree_bytes(&source.repo)?;
        let report = readiness(&prepared)?;
        assert_eq!(report.stale_main, Some(true));
        assert_eq!(report.stale_configuration, Some(true));
        assert_eq!(report.stale_policy, Some(true));
        for code in ["stale_main", "stale_configuration", "stale_policy"] {
            assert!(has_blocker(&report, code));
        }
        assert_eq!(tree_bytes(&source.repo)?, before);
        Ok(())
    }

    #[test]
    fn readiness_refuses_all_editable_native_configuration_routes() -> Result<()> {
        let (_directory, prepared, _signer) = native_fixture(false)?;
        let marker = prepared.workspace.join("hook-marker");
        let hook = prepared.workspace.join("hook");
        fs::write(&hook, b"#!/bin/sh\nprintf '%s\\n' unsafe > hook-marker\n")?;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
        for relative in [".pijul/config", ".pijul/config.toml", "pijul.toml"] {
            let path = prepared.workspace.join(relative);
            fs::write(&path, b"[hooks]\npreHooks = [\"./hook\"]\n")?;
            let before = tree_bytes(&prepared.workspace)?;
            let report = readiness(&prepared)?;
            assert!(has_blocker(&report, "workspace_native_configuration"));
            assert!(report.pending_tracked_edits.is_none());
            assert!(report.recorded_conflicts.is_none());
            assert!(!marker.exists());
            assert_eq!(tree_bytes(&prepared.workspace)?, before);
            fs::remove_file(path)?;
        }
        Ok(())
    }

    #[test]
    fn readiness_reports_changed_prepared_data_and_missing_native_changes() -> Result<()> {
        let (_directory, prepared, _signer) = native_fixture(false)?;
        fs::write(&prepared.review_file, "Changed review data.\n")?;
        let report = readiness(&prepared)?;
        assert!(has_blocker(&report, "prepared_data_changed"));
        let workspace = Pijul::new(prepared.workspace.clone());
        fs::remove_file(workspace.change_file(&prepared.candidates[0]))?;
        let before = tree_bytes(&prepared.workspace)?;
        let report = readiness(&prepared)?;
        assert!(has_blocker(&report, "workspace_native_changes"));
        assert_eq!(tree_bytes(&prepared.workspace)?, before);
        Ok(())
    }

    #[test]
    fn readiness_reports_unsafe_native_metadata_and_wrong_channel() -> Result<()> {
        let (_directory, prepared, _signer) = native_fixture(false)?;
        let workspace = Pijul::new(prepared.workspace.clone());
        let alias = prepared.workspace.join(".pijul/unsafe-alias");
        symlink(prepared.source.join("value.txt"), &alias)?;
        let report = readiness(&prepared)?;
        assert!(has_blocker(&report, "workspace_metadata"));
        assert!(report.pending_tracked_edits.is_none());
        fs::remove_file(alias)?;
        workspace.run(["fork", "--channel", "main", "other"])?;
        workspace.run(["channel", "switch", "other"])?;
        let before = tree_bytes(&prepared.workspace)?;
        let report = readiness(&prepared)?;
        assert!(has_blocker(&report, "workspace_channels"));
        assert!(report.pending_tracked_edits.is_none());
        assert_eq!(tree_bytes(&prepared.workspace)?, before);
        Ok(())
    }

    #[test]
    fn readiness_conflicts_hide_unknown_diagnostics_and_unsafe_paths() {
        let secret = format!("ghp_{}", "A".repeat(36));
        let conflict = readiness_conflict(crate::change::Conflict {
            kind: format!("Native diagnostic with {secret}"),
            path: format!("path/{secret}"),
            line: 7,
        });
        assert_eq!(conflict.kind, "Other conflict");
        assert_eq!(conflict.path, "[redacted-path]");
        assert_eq!(conflict.line, 7);
        for path in ["/private/native-path", "../outside", "control\npath"] {
            let conflict = readiness_conflict(crate::change::Conflict {
                kind: "Order conflict".into(),
                path: path.into(),
                line: 1,
            });
            assert_eq!(conflict.kind, "Order conflict");
            assert_eq!(conflict.path, "[redacted-path]");
        }
    }
}
