use std::ffi::{CString, OsStr};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Result, anyhow, bail, ensure};

const MAX_CONTROL_BYTES: u64 = 16 * 1024 * 1024;
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

fn open_at(parent: &File, name: &CString, flags: libc::c_int) -> io::Result<File> {
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
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

fn name(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| anyhow!("A pilot artifact path is not valid."))
}

struct AnchoredPath {
    path: PathBuf,
    directories: Vec<File>,
    name: CString,
}

impl AnchoredPath {
    fn open(path: &Path) -> Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|_| anyhow!("Cannot read the pilot artifact directory."))?
                .join(path)
        };
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|_| anyhow!("Cannot open the pilot artifact root directory."))?;
        let mut directories = vec![root];
        let mut resolved = PathBuf::from("/");
        let mut components = absolute.components().peekable();
        while let Some(component) = components.next() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    ensure!(
                        directories.len() > 1,
                        "A pilot artifact path has an invalid parent."
                    );
                    directories.pop();
                    resolved.pop();
                }
                Component::Normal(component) => {
                    let name = name(component)?;
                    resolved.push(component);
                    if components.peek().is_none() {
                        return Ok(Self {
                            path: resolved,
                            directories,
                            name,
                        });
                    }
                    let directory = open_at(
                        directories.last().unwrap(),
                        &name,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                    )
                    .map_err(|_| anyhow!("The pilot artifact parent must exist without links."))?;
                    directories.push(directory);
                }
                Component::Prefix(_) => bail!("A pilot artifact path is not valid."),
            }
        }
        bail!("A pilot artifact path must name a file.")
    }

    fn parent(&self) -> &File {
        self.directories.last().unwrap()
    }

    fn outside(&self, protected: &[PathBuf]) -> Result<()> {
        for source in protected {
            ensure!(
                !crate::bundle::directory_contains(source, &self.path)
                    .map_err(|_| anyhow!("Cannot inspect a protected pilot source path."))?,
                "The pilot output must remain outside each protected source path."
            );
            let expected = match fs::metadata(source) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => bail!("Cannot inspect a protected pilot source path."),
            };
            // Compare retained ancestors, not names below a mutable parent.
            for directory in &self.directories {
                let actual = directory
                    .metadata()
                    .map_err(|_| anyhow!("Cannot inspect the pilot output parent."))?;
                ensure!(
                    !same_file(&expected, &actual),
                    "The pilot output must remain outside each protected source path."
                );
            }
        }
        Ok(())
    }

    fn revalidate(&self, protected: &[PathBuf]) -> Result<()> {
        self.outside(protected)?;
        let mut retained = self.directories.iter();
        let mut parent = retained.next().unwrap();
        for component in self.path.parent().unwrap().components() {
            let Component::Normal(component) = component else {
                continue;
            };
            let child = retained
                .next()
                .ok_or_else(|| anyhow!("The pilot output parent path is not valid."))?;
            let expected = child
                .metadata()
                .map_err(|_| anyhow!("Cannot inspect the retained pilot output parent."))?;
            let name = name(component)?;
            let mut named = std::mem::MaybeUninit::<libc::stat>::uninit();
            ensure!(
                unsafe {
                    libc::fstatat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        named.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } == 0,
                "The pilot output parent changed before publication."
            );
            let named = unsafe { named.assume_init() };
            ensure!(
                named.st_dev as u64 == expected.dev()
                    && named.st_ino as u64 == expected.ino()
                    && named.st_mode as u32 & libc::S_IFMT as u32 == libc::S_IFDIR as u32,
                "The pilot output parent changed before publication."
            );
            parent = child;
        }
        Ok(())
    }

    fn require_new(&self) -> Result<()> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.parent().as_raw_fd(),
                self.name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            bail!("The pilot output destination already exists.");
        }
        ensure!(
            io::Error::last_os_error().kind() == io::ErrorKind::NotFound,
            "Cannot inspect the pilot output destination."
        );
        Ok(())
    }

    fn output(path: &Path, protected: &[PathBuf]) -> Result<Self> {
        let output = Self::open(path)?;
        output.outside(protected)?;
        output.require_new()?;
        Ok(output)
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn same_capture(left: &Metadata, right: &Metadata) -> bool {
    same_file(left, right)
        && left.is_file()
        && right.is_file()
        && left.nlink() == 1
        && right.nlink() == 1
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

struct Control {
    path: AnchoredPath,
    file: File,
    before: Metadata,
}

impl Control {
    fn open(path: &Path) -> Result<Self> {
        let path = AnchoredPath::open(path)?;
        let file = open_at(path.parent(), &path.name, libc::O_RDONLY)
            .map_err(|_| anyhow!("Cannot open a pilot control artifact without links."))?;
        let before = file
            .metadata()
            .map_err(|_| anyhow!("Cannot inspect a pilot control artifact."))?;
        ensure!(
            before.is_file() && before.nlink() == 1,
            "A pilot control artifact must be a regular file without aliases."
        );
        ensure!(
            before.len() <= MAX_CONTROL_BYTES,
            "A pilot control artifact exceeds the 16 MiB limit."
        );
        Ok(Self { path, file, before })
    }

    fn capture(mut self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.before.len() as usize);
        Read::by_ref(&mut self.file)
            .take(MAX_CONTROL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow!("Cannot read a pilot control artifact."))?;
        ensure!(
            bytes.len() as u64 <= MAX_CONTROL_BYTES,
            "A pilot control artifact exceeds the 16 MiB limit."
        );
        let after = self
            .file
            .metadata()
            .map_err(|_| anyhow!("Cannot inspect a pilot control artifact after capture."))?;
        let named = open_at(self.path.parent(), &self.path.name, libc::O_RDONLY)
            .and_then(|file| file.metadata())
            .map_err(|_| anyhow!("A pilot control artifact changed during capture."))?;
        ensure!(
            bytes.len() as u64 == self.before.len()
                && same_capture(&self.before, &after)
                && same_capture(&self.before, &named),
            "A pilot control artifact changed during capture."
        );
        Ok(bytes)
    }
}

pub(super) fn read_control(path: &Path) -> Result<Vec<u8>> {
    Control::open(path)?.capture()
}

struct StagedFile<'a> {
    output: &'a AnchoredPath,
    protected: &'a [PathBuf],
    name: CString,
    active: bool,
}

impl<'a> StagedFile<'a> {
    fn new(output: &'a AnchoredPath, protected: &'a [PathBuf], bytes: &[u8]) -> Result<Self> {
        for _ in 0..128 {
            let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let name = CString::new(format!(
                ".patchgate-pilot-{}-{sequence}.tmp",
                std::process::id()
            ))
            .map_err(|_| anyhow!("Cannot name the private pilot output."))?;
            output.revalidate(protected)?;
            let mut file = match open_at(
                output.parent(),
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            ) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => bail!("Cannot create the private pilot output."),
            };
            let staged = Self {
                output,
                protected,
                name,
                active: true,
            };
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| anyhow!("Cannot set private pilot output permissions."))?;
            file.write_all(bytes)
                .map_err(|_| anyhow!("Cannot write the complete pilot output."))?;
            file.sync_all()
                .map_err(|_| anyhow!("Cannot sync the complete pilot output."))?;
            return Ok(staged);
        }
        bail!("Cannot create a new private pilot output stage.")
    }

    fn publish(mut self) -> Result<()> {
        self.output.revalidate(self.protected)?;
        let parent = self.output.parent();
        let result = unsafe {
            libc::linkat(
                parent.as_raw_fd(),
                self.name.as_ptr(),
                parent.as_raw_fd(),
                self.output.name.as_ptr(),
                0,
            )
        };
        if result != 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
                bail!("The pilot output destination already exists.");
            }
            bail!("Cannot publish the new pilot output.");
        }
        ensure!(
            unsafe { libc::unlinkat(parent.as_raw_fd(), self.name.as_ptr(), 0) } == 0,
            "Cannot remove the private pilot output stage."
        );
        self.active = false;
        parent
            .sync_all()
            .map_err(|_| anyhow!("Cannot sync the pilot output parent."))?;
        Ok(())
    }
}

impl Drop for StagedFile<'_> {
    fn drop(&mut self) {
        if self.active {
            unsafe { libc::unlinkat(self.output.parent().as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

pub(super) fn write_new(path: &Path, protected: &[PathBuf], bytes: &[u8]) -> Result<()> {
    let output = AnchoredPath::output(path, protected)?;
    StagedFile::new(&output, protected, bytes)?.publish()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::sync::Barrier;

    use super::*;

    fn fixture() -> Result<(tempfile::TempDir, PathBuf)> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        Ok((directory, root))
    }

    fn entries(path: &Path) -> Result<Vec<PathBuf>> {
        let mut entries = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        entries.sort();
        Ok(entries)
    }

    #[test]
    fn controls_preserve_exact_bytes_and_accept_the_size_limit() -> Result<()> {
        let (_directory, root) = fixture()?;
        let path = root.join("control.json");
        let bytes = b" \n{\"schema_version\":1}\r\n";
        fs::write(&path, bytes)?;
        assert_eq!(read_control(&path)?, bytes);
        let file = OpenOptions::new().write(true).open(&path)?;
        file.set_len(MAX_CONTROL_BYTES)?;
        let captured = read_control(&path)?;
        assert_eq!(captured.len() as u64, MAX_CONTROL_BYTES);
        assert_eq!(&captured[..bytes.len()], bytes);
        assert!(captured[bytes.len()..].iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn oversized_and_special_controls_fail_with_static_errors() -> Result<()> {
        let (_directory, root) = fixture()?;
        let oversized = root.join("private-input-name.json");
        File::create(&oversized)?.set_len(MAX_CONTROL_BYTES + 1)?;
        let error = read_control(&oversized).unwrap_err();
        assert_eq!(
            error.to_string(),
            "A pilot control artifact exceeds the 16 MiB limit."
        );
        assert!(read_control(&root).is_err());
        let fifo = root.join("control-fifo");
        let fifo_name = name(fifo.as_os_str())?;
        ensure!(
            unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) } == 0,
            "Create the test FIFO."
        );
        assert!(read_control(&fifo).is_err());
        let socket = root.join("control-socket");
        let _listener = UnixListener::bind(&socket)?;
        assert!(read_control(&socket).is_err());
        Ok(())
    }

    #[test]
    fn linked_controls_and_linked_parent_directories_fail() -> Result<()> {
        let (_directory, root) = fixture()?;
        let parent = root.join("controls");
        fs::create_dir(&parent)?;
        let path = parent.join("control.json");
        let marker = b"{\"source\":\"private\"}\n";
        fs::write(&path, marker)?;
        let linked = root.join("linked-control");
        symlink(&path, &linked)?;
        assert!(read_control(&linked).is_err());
        let alias = root.join("control-alias");
        fs::hard_link(&path, &alias)?;
        assert!(read_control(&alias).is_err());
        assert!(read_control(&path).is_err());
        fs::remove_file(&alias)?;
        let linked_parent = root.join("linked-parent");
        symlink(&parent, &linked_parent)?;
        assert!(read_control(&linked_parent.join("control.json")).is_err());
        assert_eq!(fs::read(&path)?, marker);
        Ok(())
    }

    #[test]
    fn changed_and_replaced_controls_fail_after_open() -> Result<()> {
        let (_directory, root) = fixture()?;
        let path = root.join("control.json");
        fs::write(&path, b"original")?;
        let control = Control::open(&path)?;
        fs::write(&path, b"modified")?;
        assert!(control.capture().is_err());
        let control = Control::open(&path)?;
        let replacement = root.join("replacement.json");
        fs::write(&replacement, b"modified")?;
        fs::rename(&replacement, &path)?;
        assert!(control.capture().is_err());
        Ok(())
    }

    #[test]
    fn existing_outputs_and_input_aliases_keep_their_bytes() -> Result<()> {
        let (_directory, root) = fixture()?;
        let input = root.join("input.json");
        let marker = b"Retain the input bytes.\n";
        fs::write(&input, marker)?;
        let linked = root.join("linked-output.json");
        symlink(&input, &linked)?;
        let alias = root.join("alias-output.json");
        fs::hard_link(&input, &alias)?;
        for output in [&input, &linked, &alias, &root] {
            assert!(write_new(output, &[], b"{\"new\":true}\n").is_err());
        }
        assert_eq!(fs::read(&input)?, marker);
        assert_eq!(fs::read(&alias)?, marker);
        assert!(fs::symlink_metadata(&linked)?.file_type().is_symlink());
        assert_eq!(entries(&root)?.len(), 3);
        Ok(())
    }

    #[test]
    fn complete_outputs_have_private_mode_and_no_stage() -> Result<()> {
        let (_directory, root) = fixture()?;
        let output = root.join("pilot.json");
        let bytes = b"{\"schema_version\":1,\"status\":\"blocked\"}\n";
        write_new(&output, &[], bytes)?;
        let metadata = fs::metadata(&output)?;
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(fs::read(&output)?, bytes);
        assert_eq!(entries(&root)?, vec![output]);
        Ok(())
    }

    #[test]
    fn source_paths_and_directory_aliases_refuse_outputs() -> Result<()> {
        let (_directory, root) = fixture()?;
        let source = root.join("source");
        let nested = source.join("nested");
        fs::create_dir_all(&nested)?;
        let marker = source.join("source.txt");
        fs::write(&marker, b"Retain the source bytes.\n")?;
        let alias = root.join("source-alias");
        symlink(&source, &alias)?;
        for (output, protected) in [
            (source.join("pilot.json"), source.clone()),
            (nested.join("pilot.json"), source.clone()),
            (source.join("pilot.json"), alias.clone()),
            (alias.join("pilot.json"), source.clone()),
            (alias.join("nested/pilot.json"), source.clone()),
        ] {
            assert!(write_new(&output, &[protected], b"{}\n").is_err());
        }
        assert!(!source.join("pilot.json").exists());
        assert!(!nested.join("pilot.json").exists());
        assert_eq!(fs::read(&marker)?, b"Retain the source bytes.\n");
        let absent_input = root.join("absent-input.json");
        assert!(write_new(&absent_input, &[absent_input.clone()], b"{}\n").is_err());
        assert!(!absent_input.exists());
        Ok(())
    }

    #[test]
    fn absent_output_parents_fail_without_directory_creation() -> Result<()> {
        let (_directory, root) = fixture()?;
        let parent = root.join("absent");
        let error = write_new(&parent.join("pilot.json"), &[], b"{}\n").unwrap_err();
        assert_eq!(
            error.to_string(),
            "The pilot artifact parent must exist without links."
        );
        assert!(!parent.exists());
        assert!(entries(&root)?.is_empty());
        Ok(())
    }

    #[test]
    fn concurrent_publication_retains_one_complete_private_output() -> Result<()> {
        let (_directory, root) = fixture()?;
        let output = root.join("pilot.json");
        let barrier = Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|index| {
                    let output = &output;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let bytes = format!("{{\"writer\":{index}}}\n").into_bytes();
                        barrier.wait();
                        (write_new(output, &[], &bytes), bytes)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("The publication thread failed."))
                .collect::<Vec<_>>()
        });
        let winners: Vec<_> = results
            .iter()
            .filter(|(result, _)| result.is_ok())
            .collect();
        assert_eq!(winners.len(), 1);
        assert_eq!(fs::read(&output)?, winners[0].1);
        assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(&output)?.nlink(), 1);
        assert_eq!(entries(&root)?, vec![output]);
        Ok(())
    }

    #[test]
    fn publication_failure_removes_its_stage_and_keeps_the_destination() -> Result<()> {
        let (_directory, root) = fixture()?;
        let destination = root.join("pilot.json");
        let output = AnchoredPath::output(&destination, &[])?;
        let staged = StagedFile::new(&output, &[], b"{\"new\":true}\n")?;
        let marker = b"Retain the other output.\n";
        fs::write(&destination, marker)?;
        assert!(staged.publish().is_err());
        assert_eq!(fs::read(&destination)?, marker);
        assert_eq!(entries(&root)?, vec![destination]);
        Ok(())
    }

    #[test]
    fn changed_parent_identity_refuses_publication_and_removes_the_stage() -> Result<()> {
        let (_directory, root) = fixture()?;
        let parent = root.join("parent");
        let retained = root.join("retained");
        fs::create_dir(&parent)?;
        let destination = parent.join("pilot.json");
        let output = AnchoredPath::output(&destination, &[])?;
        let staged = StagedFile::new(&output, &[], b"{\"new\":true}\n")?;
        fs::rename(&parent, &retained)?;
        fs::create_dir(&parent)?;
        let marker = b"Retain the replacement output.\n";
        fs::write(&destination, marker)?;
        assert!(staged.publish().is_err());
        assert_eq!(fs::read(&destination)?, marker);
        assert_eq!(entries(&parent)?, vec![destination]);
        assert!(entries(&retained)?.is_empty());
        Ok(())
    }

    #[test]
    fn parent_replacement_cannot_redirect_stage_or_publication_into_source() -> Result<()> {
        let (_directory, root) = fixture()?;
        let source = root.join("source");
        fs::create_dir(&source)?;
        let marker = source.join("source.txt");
        fs::write(&marker, b"Retain the source bytes.\n")?;
        for staged_before_replacement in [false, true] {
            let index = usize::from(staged_before_replacement);
            let parent = root.join(format!("parent-{index}"));
            let retained = root.join(format!("retained-{index}"));
            fs::create_dir(&parent)?;
            let protected = [source.clone()];
            let output = AnchoredPath::output(&parent.join("pilot.json"), &protected)?;
            let bytes = b"{\"status\":\"blocked\"}\n";
            let staged = if staged_before_replacement {
                Some(StagedFile::new(&output, &protected, bytes)?)
            } else {
                None
            };
            fs::rename(&parent, &retained)?;
            symlink(&source, &parent)?;
            match staged {
                Some(staged) => assert!(staged.publish().is_err()),
                None => assert!(StagedFile::new(&output, &protected, bytes).is_err()),
            }
            assert!(entries(&retained)?.is_empty());
            assert!(!source.join("pilot.json").exists());
            assert_eq!(entries(&source)?, vec![marker.clone()]);
            assert_eq!(fs::read(&marker)?, b"Retain the source bytes.\n");
        }
        Ok(())
    }
}
