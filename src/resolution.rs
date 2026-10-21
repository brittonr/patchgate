use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
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

pub struct Completed {
    pub pijul: Pijul,
    pub hashes: Vec<String>,
    pub imported: HashSet<String>,
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
    let permitted: HashSet<_> = base.iter().chain(candidates).map(String::as_str).collect();
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
    let pijul = Pijul::new(workspace.clone());
    ensure!(
        pijul.snapshot(main)? == snapshot,
        "The cloned main state differs"
    );
    for hash in candidates {
        pijul
            .call([OsStr::new("apply"), isolated.change_file(hash).as_os_str()])
            .context("Cannot apply a prepared candidate")?;
    }
    let expected: HashSet<_> = base.iter().chain(candidates).cloned().collect();
    ensure!(
        pijul.hashes(main)? == expected,
        "The workspace contains an unprepared change"
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
    let pijul = Pijul::new(trusted.workspace.clone());
    validate_native_metadata(&pijul.repo.join(".pijul"))?;
    refuse_native_configuration(&pijul.repo)?;
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
    ensure!(
        !path
            .components()
            .any(|part| matches!(part, Component::ParentDir)),
        "A resolution path cannot contain parent components"
    );
    let mut current = PathBuf::new();
    for part in path.components() {
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
    Ok(path)
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

// Native clones can share immutable files. The human copy must not share source inodes.
fn detach_files(path: &Path) -> Result<()> {
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
            copy.as_file().set_permissions(metadata.permissions())?;
            copy.as_file().sync_all()?;
            copy.persist(path).map_err(|error| error.error)?;
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
        assert!(new_workspace_path(&source, &root.join("../workspace")).is_err());
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
}
