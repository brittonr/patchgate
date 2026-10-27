use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use flate2::Compression;
use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::case_metadata;

const MANIFEST: &str = "manifest.json";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Export {
    pub schema_version: u32,
    pub output: PathBuf,
    pub cases: Vec<String>,
    pub native_changes: usize,
    pub sha256: String,
}

pub struct Loaded {
    pub directory: tempfile::TempDir,
    pub manifest: Value,
    pub repository: PathBuf,
    pub origin_repository: PathBuf,
    pub sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema_version: u32,
    manifest: Value,
    files: BTreeMap<String, Contents>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Contents {
    size: u64,
    sha256: String,
}

struct Hashed<R> {
    reader: R,
    digest: Sha256,
}

impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(bytes)?;
        self.digest.update(&bytes[..count]);
        Ok(count)
    }
}

fn hash_reader(reader: impl Read) -> Result<Contents> {
    let mut reader = Hashed {
        reader,
        digest: Sha256::new(),
    };
    let size = io::copy(&mut reader, &mut io::sink())?;
    Ok(Contents {
        size,
        sha256: format!("{:x}", reader.digest.finalize()),
    })
}

fn open_regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("Read the bundle input {}.", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "A bundle input must be a regular file without aliases."
    );
    Ok(file)
}

fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::ParentDir => {
                ensure!(
                    resolved.is_dir() && resolved.pop(),
                    "A bundle parent path is not a directory."
                );
                continue;
            }
            _ => resolved.push(component),
        }
        match fs::symlink_metadata(&resolved) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "A bundle path must not contain links."
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(resolved)
}

pub fn directory_contains(directory: &Path, path: &Path) -> Result<bool> {
    if path.starts_with(directory) {
        return Ok(true);
    }
    let expected = match fs::metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut ancestor = Some(path);
    while let Some(path) = ancestor {
        match fs::metadata(path) {
            Ok(metadata)
                if metadata.dev() == expected.dev() && metadata.ino() == expected.ino() =>
            {
                return Ok(true);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ancestor = path.parent();
    }
    Ok(false)
}

fn no_links(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        ensure!(
            !matches!(component, Component::ParentDir | Component::CurDir),
            "A bundle path must not contain relative components."
        );
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "A bundle path must not contain links."
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(crate) fn validate_policy(source: &Path, path: &Path) -> Result<()> {
    let path = absolute(path)?;
    let resolved = fs::canonicalize(&path).context("Read the bundle policy path.")?;
    ensure!(
        !directory_contains(&source.join(".pijul"), &resolved)?,
        "A bundle policy must not use source metadata."
    );
    open_regular(&resolved)?;
    Ok(())
}

fn output_path(source: &Path, output: &Path) -> Result<PathBuf> {
    let output = absolute(output)?;
    ensure!(
        output.file_name().is_some() && !directory_contains(source, &output)?,
        "The bundle output must name a new file outside the source repository."
    );
    match fs::symlink_metadata(&output) {
        Ok(_) => bail!("The bundle destination already exists."),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(output)
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .with_context(|| format!("The bundle {field} value must be text."))
}

fn native_path(hash: &str) -> Result<String> {
    ensure!(
        hash.len() == 53
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte)),
        "A bundle native hash is not valid."
    );
    Ok(format!(
        "repository/.pijul/changes/{}/{}.change",
        &hash[..2],
        &hash[2..]
    ))
}

fn safe_member(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.contains('\\')
            && !path.chars().any(char::is_control)
            && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
            && Path::new(path)
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "The bundle contains an unsafe member path."
    );
    Ok(())
}

fn members(manifest: &Value) -> Result<(PathBuf, Vec<String>, BTreeSet<String>)> {
    ensure!(
        manifest["schema_version"] == 1,
        "The bundle replay schema_version must be 1."
    );
    let origin = PathBuf::from(text(manifest, "repository")?);
    ensure!(origin.is_absolute(), "The bundle origin must be absolute.");
    let cases = manifest["cases"]
        .as_array()
        .context("The bundle cases must be an array.")?;
    ensure!(!cases.is_empty(), "The bundle has no selected cases.");
    let mut ids = Vec::new();
    let mut unique = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for case in cases {
        let id = text(case, "id")?;
        ensure!(
            !id.is_empty() && unique.insert(id),
            "Bundle case IDs must be nonempty and unique."
        );
        ids.push(id.to_owned());
        let snapshot = &case["snapshot"];
        ensure!(
            snapshot.is_object()
                && snapshot["repository"] == manifest["repository"]
                && snapshot["base"] == case["base"]
                && snapshot["candidate"] == case["candidate"]
                && snapshot["main"] == manifest["main"]
                && snapshot["inbox"] == manifest["inbox"]
                && snapshot["configuration"]["values"] == case["configuration"],
            "A bundle snapshot differs from its captured bindings."
        );
        let labels = case["labels"]
            .as_array()
            .context("A bundle case needs its human label history.")?;
        ensure!(
            labels.last().is_some_and(|label| {
                matches!(
                    label["expected"].as_str(),
                    Some("accept" | "reject" | "escalate")
                ) && label["expected"] == case["expected"]
            }),
            "A bundle case needs an explicit human label."
        );
        let notes: Vec<case_metadata::NoteRecord> = case.get("notes")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose().context("The bundle notes are not valid.")?.unwrap_or_default();
        let seen: Vec<case_metadata::SeenRecord> = case.get("seen")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose().context("The bundle seen records are not valid.")?.unwrap_or_default();
        case_metadata::validate_histories(&notes, &seen)?;
        let candidate = text(case, "candidate")?;
        paths.insert(native_path(candidate)?);
        let mut base_hashes = BTreeSet::new();
        for hash in case["base"]
            .as_array()
            .context("The bundle base must be an array.")?
        {
            let hash = hash.as_str().context("A bundle base hash must be text.")?;
            ensure!(
                hash != candidate && base_hashes.insert(hash),
                "A bundle base hash is repeated or names its candidate."
            );
            paths.insert(native_path(hash)?);
        }
    }
    let variants = manifest["variants"]
        .as_array()
        .context("The bundle variants must be an array.")?;
    ensure!(!variants.is_empty(), "The bundle variants array is empty.");
    for (index, variant) in variants.iter().enumerate() {
        if !variant["policy"].is_null() {
            let policy = text(variant, "policy")?;
            ensure!(
                policy == format!("policies/{index}.txt"),
                "The bundle policy path is not valid."
            );
            paths.insert(policy.to_owned());
        }
    }
    Ok((origin, ids, paths))
}

fn append(
    builder: &mut tar::Builder<impl Write>,
    path: &str,
    size: u64,
    reader: impl Read,
) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(size);
    header.set_cksum();
    builder.append_data(&mut header, path, reader)?;
    Ok(())
}

pub fn write(source: &Path, mut manifest: Value, output: &Path) -> Result<Export> {
    let source = fs::canonicalize(source).context("Read the bundle source path.")?;
    ensure!(
        manifest["repository"].as_str() == source.to_str(),
        "The bundle manifest belongs to a different source."
    );
    let output = output_path(&source, output)?;
    let parent = output
        .parent()
        .context("The bundle output parent is absent.")?;
    let staging = tempfile::tempdir()?;
    let mut policies = BTreeMap::new();
    for (index, variant) in manifest["variants"]
        .as_array_mut()
        .context("The bundle variants must be an array.")?
        .iter_mut()
        .enumerate()
    {
        if !variant["policy"].is_null() {
            let policy = PathBuf::from(text(variant, "policy")?);
            validate_policy(&source, &policy)?;
            let relative = format!("policies/{index}.txt");
            policies.insert(relative.clone(), policy);
            variant["policy"] = Value::String(relative);
        }
    }
    let (_, cases, expected) = members(&manifest)?;
    let mut files = BTreeMap::new();
    for relative in &expected {
        let input = if let Some(policy) = policies.get(relative) {
            policy.clone()
        } else {
            source.join(
                relative
                    .strip_prefix("repository/")
                    .context("The native path is absent.")?,
            )
        };
        no_links(&input)?;
        let mut input = open_regular(&input)?;
        let staged = staging.path().join(relative);
        fs::create_dir_all(staged.parent().context("The staged parent is absent.")?)?;
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(staged)?;
        let mut reader = Hashed {
            reader: &mut input,
            digest: Sha256::new(),
        };
        let size = io::copy(&mut reader, &mut destination)?;
        files.insert(
            relative.clone(),
            Contents {
                size,
                sha256: format!("{:x}", reader.digest.finalize()),
            },
        );
    }
    let inventory = Inventory {
        schema_version: 1,
        manifest,
        files,
    };
    let bytes = serde_json::to_vec(&inventory)?;
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "The bundle manifest is too large."
    );
    fs::create_dir_all(parent)?;
    output_path(&source, &output)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    {
        let encoder = GzEncoder::new(temporary.as_file_mut(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        append(&mut builder, MANIFEST, bytes.len() as u64, bytes.as_slice())?;
        for (path, contents) in &inventory.files {
            append(
                &mut builder,
                path,
                contents.size,
                File::open(staging.path().join(path))?,
            )?;
        }
        builder.into_inner()?.finish()?;
    }
    temporary.as_file().sync_all()?;
    temporary.as_file_mut().seek(SeekFrom::Start(0))?;
    let sha256 = hash_reader(temporary.as_file_mut())?.sha256;
    output_path(&source, &output)?;
    temporary
        .persist_noclobber(&output)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(Export {
        schema_version: 1,
        output,
        cases,
        native_changes: expected
            .iter()
            .filter(|path| path.starts_with("repository/"))
            .count(),
        sha256,
    })
}

pub fn load(path: &Path) -> Result<Loaded> {
    let reader = Hashed {
        reader: open_regular(path)?,
        digest: Sha256::new(),
    };
    let decoder = GzDecoder::new(BufReader::new(reader));
    let mut archive = tar::Archive::new(decoder);
    archive.set_ignore_zeros(true);
    let directory = tempfile::tempdir()?;
    let mut inventory: Option<Inventory> = None;
    let mut expected = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry.context("Read a bundle archive member.")?;
        ensure!(
            entry.header().entry_type() == tar::EntryType::Regular,
            "The bundle contains a link, directory, or special member."
        );
        let path = std::str::from_utf8(entry.path_bytes().as_ref())?.to_owned();
        safe_member(&path)?;
        ensure!(
            seen.insert(path.clone()),
            "The bundle contains a duplicate member."
        );
        if inventory.is_none() {
            ensure!(
                path == MANIFEST,
                "The first bundle member must be its manifest."
            );
            ensure!(
                entry.size() <= MAX_MANIFEST_BYTES,
                "The bundle manifest is too large."
            );
            let parsed: Inventory =
                serde_json::from_reader(&mut entry).context("Read the bundle manifest.")?;
            ensure!(
                parsed.schema_version == 1,
                "The bundle schema_version must be 1."
            );
            let (_, _, paths) = members(&parsed.manifest)?;
            ensure!(
                parsed.files.keys().cloned().collect::<BTreeSet<_>>() == paths,
                "The bundle inventory has extra or absent files."
            );
            for (path, contents) in &parsed.files {
                safe_member(path)?;
                ensure!(
                    contents.sha256.len() == 64
                        && contents
                            .sha256
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                    "A bundle checksum is not valid."
                );
            }
            expected = paths;
            inventory = Some(parsed);
            continue;
        }
        ensure!(
            expected.contains(&path),
            "The bundle contains an unknown member."
        );
        let contents = &inventory
            .as_ref()
            .context("The bundle manifest is absent.")?
            .files[&path];
        ensure!(
            entry.size() == contents.size,
            "A bundle file size differs from its inventory."
        );
        let output = directory.path().join(&path);
        fs::create_dir_all(
            output
                .parent()
                .context("The bundle member parent is absent.")?,
        )?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output)?;
        let mut reader = Hashed {
            reader: &mut entry,
            digest: Sha256::new(),
        };
        let size = io::copy(&mut reader, &mut file)?;
        ensure!(
            size == contents.size && format!("{:x}", reader.digest.finalize()) == contents.sha256,
            "A bundle file checksum differs from its inventory."
        );
        if path.starts_with("policies/") {
            fs::read_to_string(output).context("A bundle policy must contain UTF-8 text.")?;
        }
    }
    let mut decoder = archive.into_inner();
    io::copy(&mut decoder, &mut io::sink()).context("Read the bundle gzip checksum.")?;
    let mut reader = decoder.into_inner();
    ensure!(
        reader.fill_buf()?.is_empty(),
        "The bundle contains trailing archive data."
    );
    let sha256 = format!("{:x}", reader.into_inner().digest.finalize());
    let inventory = inventory.context("The bundle manifest is absent.")?;
    ensure!(
        seen.len() == expected.len() + 1 && expected.iter().all(|path| seen.contains(path)),
        "The bundle has absent files."
    );
    let (origin_repository, _, _) = members(&inventory.manifest)?;
    let repository = directory.path().join("repository");
    Ok(Loaded {
        directory,
        manifest: inventory.manifest,
        repository,
        origin_repository,
        sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, PathBuf, Value) {
        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        let source = root.join("source");
        let candidate = "A".repeat(53);
        let path = source.join(
            native_path(&candidate)
                .unwrap()
                .strip_prefix("repository/")
                .unwrap(),
        );
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"native bytes").unwrap();
        let configuration = json!({
            "policy_path": "POLICY.md", "protected": [], "max_change_chars": 8000,
            "timeout_seconds": 1.0, "check_timeout_seconds": 2.0
        });
        let snapshot = json!({
            "repository": source, "main": "main", "inbox": "inbox", "base": [],
            "candidate": candidate, "configuration": {"values": configuration}
        });
        let manifest = json!({
            "schema_version": 1, "repository": source, "main": "main", "inbox": "inbox",
            "configuration": configuration,
            "cases": [{"id": "case", "base": [], "candidate": candidate,
                "configuration": configuration, "snapshot": snapshot, "expected": "accept",
                "labels": [{"expected": "accept", "user": "reviewer",
                    "reason": "The reviewer approves the change.", "time": "2026-01-01T00:00:00Z"}]}],
            "variants": [{"id": "model", "model_url": "http://localhost:8080",
                "model": "model", "api": "openai", "revision": "checkpoint", "policy": null}]
        });
        (directory, source, manifest)
    }

    fn inventory(manifest: Value) -> Inventory {
        let (_, _, paths) = members(&manifest).unwrap();
        Inventory {
            schema_version: 1,
            manifest,
            files: paths
                .into_iter()
                .map(|path| (path, hash_reader(b"native bytes".as_slice()).unwrap()))
                .collect(),
        }
    }

    fn archive(path: &Path, inventory: &Inventory, entries: &[(&str, tar::EntryType, &[u8])]) {
        let file = File::create(path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let bytes = serde_json::to_vec(inventory).unwrap();
        append(&mut builder, MANIFEST, bytes.len() as u64, bytes.as_slice()).unwrap();
        for (path, entry_type, bytes) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(*entry_type);
            header.set_mode(0o600);
            header.set_size(bytes.len() as u64);
            header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn load_refuses_corruption_extras_omissions_and_duplicate_members() {
        let (directory, _source, manifest) = fixture();
        let root = fs::canonicalize(directory.path()).unwrap();
        let inventory = inventory(manifest);
        let native = inventory.files.keys().next().unwrap().as_str();
        let path = root.join("bundle.tar.gz");
        let regular = tar::EntryType::Regular;
        let valid = (native, regular, b"native bytes".as_slice());
        archive(&path, &inventory, &[valid]);
        let loaded = load(&path).unwrap();
        assert_eq!(
            loaded.origin_repository,
            PathBuf::from(inventory.manifest["repository"].as_str().unwrap())
        );
        assert_eq!(loaded.manifest, inventory.manifest);
        for entries in [
            vec![],
            vec![(native, regular, b"changed data".as_slice())],
            vec![(native, regular, b"short".as_slice())],
            vec![valid, valid],
            vec![valid, ("extra", regular, b"extra".as_slice())],
            vec![(MANIFEST, regular, b"duplicate".as_slice()), valid],
        ] {
            archive(&path, &inventory, &entries);
            assert!(load(&path).is_err());
        }
        archive(&path, &inventory, &[valid]);
        let mut bytes = fs::read(&path).unwrap();
        let crc = bytes.len() - 8;
        bytes[crc] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(load(&path).is_err());
        archive(&path, &inventory, &[valid]);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"extra archive bytes")
            .unwrap();
        assert!(load(&path).is_err());
        archive(&path, &inventory, &[valid]);
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn load_refuses_unsafe_paths_links_special_files_and_tar_extensions() {
        let (directory, _source, manifest) = fixture();
        let root = fs::canonicalize(directory.path()).unwrap();
        let inventory = inventory(manifest);
        let path = root.join("bundle.tar.gz");
        for unsafe_path in [
            "../escape",
            "/absolute",
            "repository/../escape",
            "repository//extra",
            "./manifest.json",
            "repository\\extra",
        ] {
            archive(
                &path,
                &inventory,
                &[(unsafe_path, tar::EntryType::Regular, b"")],
            );
            assert!(load(&path).is_err());
        }
        let native = inventory.files.keys().next().unwrap().as_str();
        for kind in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Directory,
            tar::EntryType::Fifo,
            tar::EntryType::Char,
            tar::EntryType::GNULongName,
            tar::EntryType::XHeader,
        ] {
            archive(&path, &inventory, &[(native, kind, b"")]);
            assert!(load(&path).is_err());
        }
        assert!(!root.join("escape").exists());
    }

    #[test]
    fn load_refuses_inventory_changes_and_origin_mismatches() {
        let (directory, _source, manifest) = fixture();
        let root = fs::canonicalize(directory.path()).unwrap();
        let mut inventory = inventory(manifest);
        let path = root.join("bundle.tar.gz");
        inventory.files.insert(
            "private-key".into(),
            hash_reader(b"secret".as_slice()).unwrap(),
        );
        archive(&path, &inventory, &[]);
        assert!(load(&path).is_err());
        inventory.files.remove("private-key");
        inventory.manifest["cases"][0]["snapshot"]["repository"] = json!("/different/origin");
        archive(&path, &inventory, &[]);
        assert!(load(&path).is_err());
    }

    #[test]
    fn write_publishes_private_files_without_source_changes() {
        let (directory, source, manifest) = fixture();
        let root = fs::canonicalize(directory.path()).unwrap();
        let native = source.join(
            native_path(&"A".repeat(53))
                .unwrap()
                .strip_prefix("repository/")
                .unwrap(),
        );
        let before = fs::read(&native).unwrap();
        let output = root.join("bundle.tar.gz");
        let report = write(&source, manifest.clone(), &output).unwrap();
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&native).unwrap(), before);
        assert_eq!(report.native_changes, 1);
        assert!(write(&source, manifest.clone(), &output).is_err());
        assert!(write(&source, manifest, &source.join("bundle.tar.gz")).is_err());
        let loaded = load(&output).unwrap();
        assert_eq!(loaded.sha256, report.sha256);
        assert_eq!(
            fs::metadata(
                loaded
                    .repository
                    .join(".pijul/changes/AA")
                    .join(format!("{}.change", "A".repeat(51)))
            )
            .unwrap()
            .permissions()
            .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn case_aliases_cannot_publish_into_source_or_export_private_metadata() {
        let (directory, source, manifest) = fixture();
        let alias = source.with_file_name("SOURCE");
        if alias.is_dir() {
            assert!(write(&source, manifest, &alias.join("bundle.tar.gz")).is_err());
            assert!(!source.join("bundle.tar.gz").exists());
        }
        let key = source.join(".pijul/patchgate/key");
        fs::create_dir_all(key.parent().unwrap()).unwrap();
        fs::write(&key, b"private signer data").unwrap();
        let alias = source.join(".PIJUL/patchgate/key");
        if alias.is_file() {
            assert!(validate_policy(&source, &alias).is_err());
        }
        let alias = directory.path().join("policy");
        fs::hard_link(&key, &alias).unwrap();
        assert!(validate_policy(&source, &alias).is_err());
        assert_eq!(fs::read(key).unwrap(), b"private signer data");
    }
}
