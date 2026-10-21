use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tempfile::TempDir;

use crate::pijul::Pijul;

pub struct Isolated {
    directory: TempDir,
    pub pijul: Pijul,
}

/// Copy native metadata without source writes, gate keys, or native configuration.
pub fn copy_repository(source: &Path) -> Result<Isolated> {
    let metadata = crate::pijul::safe_path(source, Path::new(".pijul"))?;
    let directory = tempfile::Builder::new()
        .prefix("patchgate-isolated-")
        .tempdir()?;
    let root = directory.path().join("repo");
    fs::create_dir(&root)?;
    copy_metadata(&metadata, &root.join(".pijul"), false, true)?;
    Ok(Isolated {
        directory,
        pijul: Pijul::new(root),
    })
}

fn copy_metadata(source: &Path, target: &Path, immutable: bool, root: bool) -> Result<()> {
    let before = fs::symlink_metadata(source)?;
    if before.file_type().is_symlink() {
        bail!("Repository metadata uses a symbolic link");
    }
    if before.is_dir() {
        fs::create_dir(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let name = entry.file_name();
            if root
                && [b"patchgate".as_slice(), b"config", b"config.toml"]
                    .iter()
                    .any(|excluded| name.as_encoded_bytes().eq_ignore_ascii_case(excluded))
            {
                continue;
            }
            copy_metadata(
                &entry.path(),
                &target.join(&name),
                immutable || (root && name == "changes"),
                false,
            )?;
        }
    } else if before.is_file() {
        if immutable {
            match fs::hard_link(source, target) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                    fs::copy(source, target)?;
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            fs::copy(source, target)?;
        }
        let after = fs::symlink_metadata(source)?;
        if before.len() != after.len() || before.modified()? != after.modified()? {
            bail!("The repository changed during metadata copy. Retry the command.");
        }
    } else {
        bail!("Repository metadata contains a special file");
    }
    Ok(())
}

impl Isolated {
    /// Restore only recorded, validated source inside the private repository.
    pub fn materialize(&self) -> Result<()> {
        let (current, _) = self.pijul.channels()?;
        let current = current.context("The repository has no current channel")?;
        let source: PathBuf = self.directory.path().join("source");
        self.pijul.export_working_copy(&current, &source)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            fs::rename(entry.path(), self.pijul.repo.join(entry.file_name()))?;
        }
        Ok(())
    }
}
