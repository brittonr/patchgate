//! Deterministic checks for selected credential formats. This is not complete secret detection.
//!
//! Rule IDs and formats:
//! - `private-key`: PEM headers for PKCS#8, RSA, EC, DSA, and OpenSSH private keys.
//! - `aws-access-key`: AKIA and ASIA access-key IDs with 16 uppercase letters or digits.
//! - `github-token`: ghp, gho, ghu, ghs, and ghr tokens with 36 characters, and github_pat tokens with 82 characters.
//! - `slack-token`: xoxb, xoxa, xoxp, xoxr, and xoxs tokens with 24 to 200 letters, digits, or hyphens.
//! - `credential-assignment`: password, secret, token, and key assignments with substantial literals.
//!
//! Assignment values need at least 16 bytes and eight distinct bytes. Values need letters and digits or punctuation.
//! Quoted values with at least 24 bytes can contain letters only. Names can use an application prefix and a separator.
//! Example markers, environment references, and unquoted identifiers without digits do not qualify.
//!
//! Checks operate on bytes, including binary files. Line numbers start at one and count LF bytes.
//! Findings contain locations only. A secret-bearing path becomes `[redacted-path]`.
//!
//! Tree checks inspect link targets but never follow symbolic links, including internal links.
//! Regular targets inside the tree receive their own checks. Unsupported special files cause errors.

use std::ffi::{CStr, CString, OsString};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

use crate::pijul::ReviewChange;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub path: String,
    pub line: usize,
}

struct Rule {
    id: &'static str,
    pattern: Regex,
    boundary: bool,
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    [
        (
            "private-key",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            false,
        ),
        ("aws-access-key", r"(?:AKIA|ASIA)[A-Z0-9]{16}", true),
        (
            "github-token",
            r"(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})",
            true,
        ),
        ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{24,200}", true),
    ]
    .into_iter()
    .map(|(id, pattern, boundary)| Rule {
        id,
        pattern: Regex::new(pattern).expect("valid secret rule"),
        boundary,
    })
    .collect()
});

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m-u)(?:^|[^A-Za-z0-9_.-])["']?(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)["']?[ \t]*(?:=|:)[ \t]*(?:"(?P<double>[^"\r\n]{16,})"|'(?P<single>[^'\r\n]{16,})'|(?P<bare>[A-Za-z0-9_./+~=:@!%?&$*\-]{16,}))"#,
    )
    .expect("valid credential assignment rule")
});

fn adjacent_identifier(bytes: &[u8], boundary: usize, before: bool) -> bool {
    for length in 1..=4 {
        let slice = if before {
            boundary
                .checked_sub(length)
                .and_then(|start| bytes.get(start..boundary))
        } else {
            boundary
                .checked_add(length)
                .and_then(|end| bytes.get(boundary..end))
        };
        let Some(slice) = slice else { break };
        if let Ok(text) = std::str::from_utf8(slice) {
            let mut characters = text.chars();
            if let Some(character) = characters.next() {
                if characters.next().is_none() {
                    return character.is_alphanumeric() || character == '_';
                }
            }
        }
    }
    false
}

fn credential_name(name: &[u8]) -> bool {
    let names: &[&[u8]] = &[
        b"password",
        b"passwd",
        b"pwd",
        b"secret",
        b"token",
        b"apikey",
        b"api_key",
        b"api-key",
        b"accesskey",
        b"access_key",
        b"access-key",
        b"secretkey",
        b"secret_key",
        b"secret-key",
        b"clientsecret",
        b"client_secret",
        b"client-secret",
        b"privatekey",
        b"private_key",
        b"private-key",
    ];
    names.iter().any(|suffix| {
        let Some(start) = name.len().checked_sub(suffix.len()) else {
            return false;
        };
        name[start..].eq_ignore_ascii_case(suffix)
            && (start == 0 || matches!(name[start - 1], b'_' | b'-' | b'.'))
    })
}

fn substantial_literal(value: &[u8]) -> bool {
    let shell_reference = value.first() == Some(&b'$')
        && value
            .get(1)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && value[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    if shell_reference {
        return false;
    }
    // These literal forms describe examples or references, not embedded credentials.
    if [
        b"synthetic-".as_slice(),
        b"synthetic_",
        b"example-",
        b"example_",
        b"your-",
        b"your_",
        b"replace-",
        b"replace_",
        b"placeholder",
        b"changeme",
        b"process.env.",
        b"env.",
        b"config.",
        b"secrets.",
        b"std::env",
        b"${",
        b"$(",
        b"{{",
        b"<",
    ]
    .iter()
    .any(|prefix| {
        value
            .get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
    }) {
        return false;
    }
    let mut seen = [false; 256];
    let mut distinct = 0;
    let mut letters = false;
    let mut digits = false;
    let mut symbols = false;
    for &byte in value {
        if !seen[usize::from(byte)] {
            distinct += 1;
            seen[usize::from(byte)] = true;
        }
        letters |= byte.is_ascii_alphabetic();
        digits |= byte.is_ascii_digit();
        symbols |= byte.is_ascii_punctuation();
    }
    value.len() >= 16 && distinct >= 8 && letters && (digits || symbols || value.len() >= 24)
}

fn matches(bytes: &[u8]) -> Vec<(&'static str, usize, usize)> {
    let mut found = Vec::new();
    for rule in RULES.iter() {
        for hit in rule.pattern.find_iter(bytes) {
            if rule.boundary
                && (adjacent_identifier(bytes, hit.start(), true)
                    || adjacent_identifier(bytes, hit.end(), false))
            {
                continue;
            }
            // This is the published AWS documentation ID, not an account credential.
            if rule.id == "aws-access-key" && hit.as_bytes() == b"AKIAIOSFODNN7EXAMPLE" {
                continue;
            }
            found.push((rule.id, hit.start(), hit.end()));
        }
    }
    for captures in ASSIGNMENT.captures_iter(bytes) {
        let name = captures.name("name").expect("assignment name");
        let value = captures
            .name("double")
            .or_else(|| captures.name("single"))
            .or_else(|| captures.name("bare"))
            .expect("assignment value");
        if captures.name("bare").is_some() {
            let value_bytes = value.as_bytes();
            let identifier = value_bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                && !value_bytes.iter().any(u8::is_ascii_digit);
            let expression = bytes
                .get(value.end())
                .is_some_and(|byte| matches!(byte, b'(' | b'['));
            if identifier || expression {
                continue;
            }
        }
        if credential_name(name.as_bytes()) && substantial_literal(value.as_bytes()) {
            found.push(("credential-assignment", value.start(), value.end()));
        }
    }
    found.sort_unstable_by_key(|&(rule, offset, _)| (offset, rule));
    found
}

fn safe_location(path: &str, bytes: &[u8], hits: &[(&str, usize, usize)]) -> String {
    let path_bytes = path.as_bytes();
    let contains_format = RULES.iter().any(|rule| rule.pattern.is_match(path_bytes))
        || !matches(path_bytes).is_empty();
    let contains_value = hits.iter().any(|&(_, start, end)| {
        path_bytes
            .windows(end - start)
            .any(|window| window == &bytes[start..end])
    });
    if contains_format || contains_value {
        "[redacted-path]".to_owned()
    } else {
        path.to_owned()
    }
}

fn context_location<'a>(path: &str, texts: impl IntoIterator<Item = &'a [u8]>) -> String {
    for text in texts {
        let hits = matches(text);
        if !hits.is_empty() && safe_location(path, text, &hits) == "[redacted-path]" {
            return "[redacted-path]".to_owned();
        }
    }
    path.to_owned()
}

fn normalize(findings: &mut Vec<Finding>) {
    // Assignment values contain at least 16 bytes. Shorter locations cannot disclose them.
    if findings
        .iter()
        .any(|finding| finding.rule_id == "credential-assignment")
    {
        for finding in findings
            .iter_mut()
            .filter(|finding| finding.path.len() >= 16)
        {
            finding.path.clear();
            finding.path.push_str("[redacted-path]");
        }
    }
    findings
        .sort_unstable_by(|a, b| (&a.path, a.line, &a.rule_id).cmp(&(&b.path, b.line, &b.rule_id)));
    findings.dedup();
}

/// Check bytes without UTF-8 conversion. The path is a location, not an extra input.
/// Each rule produces at most one finding per line and location.
pub fn scan_text(path: &str, bytes: &[u8]) -> Vec<Finding> {
    let hits = matches(bytes);
    if hits.is_empty() {
        return Vec::new();
    }
    let path = safe_location(path, bytes, &hits);
    let mut findings = Vec::with_capacity(hits.len());
    let mut offset = 0;
    let mut line = 1;
    for (rule_id, start, _) in hits {
        line += bytes[offset..start]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count();
        offset = start;
        findings.push(Finding {
            rule_id: rule_id.to_owned(),
            path: path.clone(),
            line,
        });
    }
    normalize(&mut findings);
    findings
}

/// Check every exported review field before a model receives the review.
pub fn scan_change(change: &ReviewChange) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, text) in [
        ("[change.hash]", change.hash.as_str()),
        ("[change.message]", change.message.as_str()),
        ("[change.timestamp]", change.timestamp.as_str()),
    ] {
        findings.extend(scan_text(path, text.as_bytes()));
    }
    for author in &change.authors {
        findings.extend(scan_text("[change.author]", author.as_bytes()));
    }
    for dependency in &change.dependencies {
        findings.extend(scan_text("[change.dependency]", dependency.as_bytes()));
    }
    for path in &change.paths {
        findings.extend(scan_text("[change.path]", path.as_bytes()));
    }
    for file in &change.context.files {
        findings.extend(scan_text("[change.path]", file.path.as_bytes()));
        let mut before = Vec::new();
        let mut after = Vec::new();
        for vertex in &file.vertices {
            match &vertex.kind {
                crate::pijul::NativeVertexKind::Keep => {
                    before.extend_from_slice(vertex.text.as_bytes());
                    after.extend_from_slice(vertex.text.as_bytes());
                }
                crate::pijul::NativeVertexKind::Del => {
                    before.extend_from_slice(vertex.text.as_bytes())
                }
                crate::pijul::NativeVertexKind::Add => {
                    after.extend_from_slice(vertex.text.as_bytes())
                }
            }
        }
        let location = context_location(
            &file.path,
            file.vertices
                .iter()
                .map(|vertex| vertex.text.as_bytes())
                .chain([before.as_slice(), after.as_slice()]),
        );
        for vertex in &file.vertices {
            findings.extend(scan_text(&location, vertex.text.as_bytes()));
            findings.extend(scan_text("[context.change]", vertex.change.as_bytes()));
        }
        // Check both file states because changed vertices are alternatives, not adjacent text.
        findings.extend(scan_text(&location, &before));
        findings.extend(scan_text(&location, &after));
    }
    for metadata in &change.metadata_context {
        findings.extend(scan_text("[change.path]", metadata.path.as_bytes()));
        let location = context_location(
            &metadata.path,
            [&metadata.before, &metadata.after]
                .into_iter()
                .flatten()
                .map(|text| text.as_bytes()),
        );
        for text in [&metadata.before, &metadata.after].into_iter().flatten() {
            findings.extend(scan_text(&location, text.as_bytes()));
        }
    }
    normalize(&mut findings);
    findings
}

/// Check all regular files, names, and link targets. Do not follow symbolic links.
/// Descriptor-relative operations prevent directory replacement from escaping the root.
/// Preserve Unicode names. Escape invalid UTF-8 bytes in report locations.
pub fn scan_tree(root: &Path) -> Result<Vec<Finding>> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .context("Cannot open source root")?;
    let mut findings = Vec::new();
    scan_directory(directory, Path::new(""), &mut findings)?;
    normalize(&mut findings);
    Ok(findings)
}

struct Directory(*mut libc::DIR);

impl Drop for Directory {
    fn drop(&mut self) {
        // The directory stream owns its descriptor after fdopendir succeeds.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn entry_names(directory: File) -> Result<(Directory, Vec<OsString>)> {
    let descriptor = directory.into_raw_fd();
    // fdopendir transfers ownership only on success.
    let pointer = unsafe { libc::fdopendir(descriptor) };
    if pointer.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(descriptor);
        }
        return Err(error).context("Cannot read source directory");
    }
    let stream = Directory(pointer);
    let mut names = Vec::new();
    loop {
        // readdir uses errno to distinguish the end of the stream from an error.
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        unsafe {
            *libc::__error() = 0;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) != 0 {
                return Err(error).context("Cannot read source directory entry");
            }
            break;
        }
        // The name remains valid until the next readdir call on this stream.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    names.sort_unstable();
    Ok((stream, names))
}

fn display_path(path: &Path) -> String {
    let bytes = path.as_os_str().as_encoded_bytes();
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_owned();
    }
    let mut text = String::new();
    for &byte in bytes {
        if byte.is_ascii_graphic() && byte != b'\\' {
            text.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(text, "\\x{byte:02x}").expect("string write");
        }
    }
    text
}

fn scan_directory(directory: File, relative: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let (stream, names) = entry_names(directory)?;
    let parent = unsafe { libc::dirfd(stream.0) };
    for name in names {
        let path: PathBuf = relative.join(&name);
        let raw_path = path.as_os_str().as_encoded_bytes();
        let path_findings = scan_text("[tree.path]", raw_path);
        let location = if path_findings.is_empty() {
            display_path(&path)
        } else {
            "[redacted-path]".to_owned()
        };
        findings.extend(path_findings);
        let name = CString::new(name.as_encoded_bytes()).context("Invalid source entry name")?;
        // A single entry name cannot traverse a parent. O_NOFOLLOW rejects link replacement.
        let descriptor = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ELOOP) {
                return Err(error).context("Cannot open source entry");
            }
            let target = read_link(parent, &name)?;
            findings.extend(scan_text(&location, &target));
            continue;
        }
        // This File owns the descriptor from openat.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().context("Cannot inspect source entry")?;
        if metadata.is_dir() {
            scan_directory(file, &path, findings)?;
        } else if metadata.is_file() {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .context("Cannot read source file")?;
            findings.extend(scan_text(&location, &bytes));
        } else {
            bail!("Source tree contains a special file");
        }
    }
    Ok(())
}

fn read_link(parent: libc::c_int, name: &CStr) -> Result<Vec<u8>> {
    let mut bytes = vec![0; 256];
    loop {
        let length = unsafe {
            libc::readlinkat(
                parent,
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(std::io::Error::last_os_error()).context("Cannot read source link");
        }
        let length = usize::try_from(length).context("Invalid source link length")?;
        if length < bytes.len() {
            bytes.truncate(length);
            return Ok(bytes);
        }
        bytes.resize(
            bytes
                .len()
                .checked_mul(2)
                .context("Source link is too long")?,
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pijul::{
        MetadataContext, NativeContext, NativeContextFile, NativeVertex, NativeVertexKind,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::symlink;

    const AWS: &str = concat!("AKIA", "23456789ABCDEFGH");
    const GITHUB: &str = concat!("ghp_", "0123456789abcdefghijklmnopqrstuvwxyz");

    #[test]
    fn binary_input_and_private_key_lines() {
        let header = concat!("-----BEGIN ", "RSA PRIVATE KEY-----");
        let bytes = format!("\0\u{fffd}\n{AWS}\n{header}\nbase64\n-----END RSA PRIVATE KEY-----");
        let mut bytes = bytes.into_bytes();
        bytes.insert(1, 0xff);
        let found = scan_text("資料/鍵.bin", &bytes);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].line, 2);
        assert_eq!(found[1].line, 3);
        assert_eq!(found[0].path, "資料/鍵.bin");
        assert_eq!(found[1].rule_id, "private-key");
        let binary = [b"\xff".as_slice(), AWS.as_bytes(), b"\x80"].concat();
        assert_eq!(scan_text("binary", &binary).len(), 1);
        let assignment = [b"\xffPASSWORD=".as_slice(), b"aB3dE5fG7hJ9kL2n", b"\x80"].concat();
        assert_eq!(scan_text("binary", &assignment).len(), 1);
    }

    #[test]
    fn exact_token_boundaries_and_formats() {
        for token in [
            AWS.to_owned(),
            GITHUB.to_owned(),
            format!("github_pat_{}", "aB4_".repeat(20) + "cD"),
        ] {
            assert_eq!(scan_text("file", format!("({token})").as_bytes()).len(), 1);
            for text in [
                format!("a{token}"),
                format!("{token}z"),
                format!("_{token}"),
                format!("é{token}"),
            ] {
                assert!(scan_text("file", text.as_bytes()).is_empty());
            }
        }
        let slack = concat!(
            "xoxb-",
            "123456789012-987654321012-abcdefghijklmnopqrstuvwx"
        );
        assert_eq!(scan_text("file", slack.as_bytes()).len(), 1);
        assert!(scan_text("file", format!("{slack}_").as_bytes()).is_empty());
        assert!(scan_text("file", format!("a{slack}").as_bytes()).is_empty());
    }

    #[test]
    fn examples_references_and_identifiers_are_not_credentials() {
        for text in [
            "DEMO_SECRET=synthetic-test-value",
            "api_key = \"your_api_key_goes_here\"",
            "secret = process.env.PRODUCTION_SECRET",
            "password = \"${LONG_PASSWORD_REFERENCE}\"",
            "token_count = 12345678901234567890",
            "secret_name = abcdefghijklmnop1234",
            "password = aaaaaaaaaaaaaaaaaaaaaaaa",
            "AKIAIOSFODNN7EXAMPLE",
            "-----BEGIN PUBLIC KEY-----",
            "secret = configured_secret_value",
            "api_key = create_service_api_key()",
            "PASSWORD=$PRODUCTION_PASSWORD",
            "PASSWORD=$PRODUCTION_PASSWORD_2",
        ] {
            assert!(scan_text("fixture", text.as_bytes()).is_empty(), "{text}");
        }
        let literal = "aB3dE5fG7hJ9kL2n";
        for text in [
            format!("{}={literal}", "SERVICE_SECRET"),
            serde_json::json!({"api_key": literal}).to_string(),
            format!("{} = '{literal}'", "password"),
            format!("{} = '{}'", "password", "correcthorsebatterystaple"),
        ] {
            assert_eq!(
                scan_text("fixture", text.as_bytes())[0].rule_id,
                "credential-assignment"
            );
        }
        let literal = "$PRODUCTION_PASSWORD-aB3dE5fG7hJ9kL2n";
        assert!(!scan_text("fixture", format!("PASSWORD={literal}").as_bytes()).is_empty());
    }

    #[test]
    fn reports_do_not_disclose_values_or_secret_paths() {
        let found = scan_text(
            &format!("src/{GITHUB}.txt"),
            format!("{AWS}\n{GITHUB}").as_bytes(),
        );
        assert!(
            found
                .iter()
                .all(|finding| finding.path == "[redacted-path]")
        );
        for output in [serde_json::to_string(&found).unwrap(), format!("{found:?}")] {
            assert!(!output.contains(AWS));
            assert!(!output.contains(GITHUB));
        }
        let literal = "aB3dE5fG7hJ9kL2n";
        let found = scan_text(
            &format!("src/{literal}.txt"),
            format!("PASSWORD={literal}").as_bytes(),
        );
        assert_eq!(found[0].path, "[redacted-path]");
        assert!(!serde_json::to_string(&found).unwrap().contains(literal));
        let found = scan_text(&format!("prefix{GITHUB}suffix"), AWS.as_bytes());
        assert_eq!(found[0].path, "[redacted-path]");
    }

    #[test]
    fn review_covers_context_metadata_messages_authors_and_paths() {
        let vertex = |kind, text: &str| NativeVertex {
            change: String::new(),
            start: 0,
            end: text.len() as u64,
            kind,
            text: text.to_owned(),
        };
        let change = ReviewChange {
            hash: String::new(),
            message: AWS.to_owned(),
            authors: vec![GITHUB.to_owned()],
            timestamp: String::new(),
            dependencies: Vec::new(),
            paths: BTreeSet::from([GITHUB.to_owned()]),
            context: NativeContext {
                full: true,
                files: vec![
                    NativeContextFile {
                        path: "native".to_owned(),
                        vertices: vec![
                            vertex(NativeVertexKind::Add, &format!("{AWS}\n")),
                            vertex(NativeVertexKind::Del, &format!("{GITHUB}\n")),
                            vertex(
                                NativeVertexKind::Keep,
                                concat!("-----BEGIN ", "PRIVATE KEY-----\n"),
                            ),
                        ],
                    },
                    NativeContextFile {
                        path: "split".to_owned(),
                        vertices: vec![
                            vertex(NativeVertexKind::Keep, &GITHUB[..12]),
                            vertex(NativeVertexKind::Add, &GITHUB[12..]),
                        ],
                    },
                ],
            },
            metadata_context: vec![MetadataContext {
                path: "metadata".to_owned(),
                before: Some(AWS.to_owned()),
                after: Some(GITHUB.to_owned()),
            }],
        };
        let found = scan_change(&change);
        for path in [
            "[change.message]",
            "[change.author]",
            "[change.path]",
            "native",
            "split",
            "metadata",
        ] {
            assert!(found.iter().any(|finding| finding.path == path), "{path}");
        }
        for rule in ["aws-access-key", "github-token", "private-key"] {
            assert!(
                found
                    .iter()
                    .any(|finding| finding.path == "native" && finding.rule_id == rule)
            );
        }
        let output = serde_json::to_string(&found).unwrap();
        assert!(!output.contains(AWS));
        assert!(!output.contains(GITHUB));
    }

    #[test]
    fn native_states_detect_replacements_and_redact_values_from_other_vertices() {
        let literal = "aB3dE5fG7hJ9kL2n";
        let vertex = |kind, text: String| NativeVertex {
            change: String::new(),
            start: 0,
            end: text.len() as u64,
            kind,
            text,
        };
        let change = ReviewChange {
            hash: String::new(),
            message: String::new(),
            authors: Vec::new(),
            timestamp: String::new(),
            dependencies: Vec::new(),
            paths: BTreeSet::new(),
            context: NativeContext {
                full: true,
                files: vec![
                    NativeContextFile {
                        path: format!("src/{literal}.txt"),
                        vertices: vec![
                            vertex(NativeVertexKind::Add, AWS.to_owned()),
                            vertex(NativeVertexKind::Keep, format!("PASSWORD={literal}")),
                        ],
                    },
                    NativeContextFile {
                        path: "replacement".to_owned(),
                        vertices: vec![
                            vertex(NativeVertexKind::Keep, GITHUB[..4].to_owned()),
                            vertex(NativeVertexKind::Del, "placeholder".to_owned()),
                            vertex(NativeVertexKind::Add, GITHUB[4..].to_owned()),
                        ],
                    },
                    NativeContextFile {
                        path: "before".to_owned(),
                        vertices: vec![
                            vertex(NativeVertexKind::Keep, GITHUB[..4].to_owned()),
                            vertex(NativeVertexKind::Add, "placeholder".to_owned()),
                            vertex(NativeVertexKind::Del, GITHUB[4..].to_owned()),
                        ],
                    },
                    NativeContextFile {
                        path: format!("other/{literal}.txt"),
                        vertices: vec![vertex(NativeVertexKind::Keep, AWS.to_owned())],
                    },
                ],
            },
            metadata_context: vec![MetadataContext {
                path: format!("metadata/{literal}"),
                before: Some(AWS.to_owned()),
                after: Some(format!("PASSWORD={literal}")),
            }],
        };
        let found = scan_change(&change);
        assert!(
            found
                .iter()
                .any(|finding| finding.rule_id == "aws-access-key")
        );
        assert!(
            found
                .iter()
                .any(|finding| finding.rule_id == "credential-assignment")
        );
        for path in ["replacement", "before"] {
            assert!(
                found
                    .iter()
                    .any(|finding| finding.path == path && finding.rule_id == "github-token")
            );
        }
        for output in [serde_json::to_string(&found).unwrap(), format!("{found:?}")] {
            assert!(!output.contains(literal));
            assert!(!output.contains(AWS));
            assert!(!output.contains(GITHUB));
        }
    }

    #[test]
    fn tree_checks_binary_names_links_and_unicode_without_external_reads() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root");
        fs::create_dir(&root)?;
        fs::write(directory.path().join("external"), GITHUB)?;
        fs::write(
            root.join("資料.bin"),
            [b"\xff\0".as_slice(), AWS.as_bytes()].concat(),
        )?;
        fs::write(root.join(GITHUB), b"safe")?;
        symlink("../external", root.join("outside"))?;
        symlink("..", root.join("outside-directory"))?;
        symlink(".", root.join("cycle"))?;
        symlink("missing", root.join("dangling"))?;
        symlink(AWS, root.join("credential-target"))?;
        let found = scan_tree(&root)?;
        assert!(found.iter().any(|finding| finding.path == "資料.bin"));
        assert!(
            found
                .iter()
                .any(|finding| finding.path == "credential-target")
        );
        assert!(found.iter().any(|finding| finding.path == "[tree.path]"));
        assert!(!found.iter().any(|finding| finding.path == "outside"));
        assert!(
            !found
                .iter()
                .any(|finding| finding.path.starts_with("outside-directory/"))
        );
        assert!(!serde_json::to_string(&found)?.contains(GITHUB));
        #[cfg(target_os = "linux")]
        {
            fs::write(root.join(OsString::from_vec(b"bad-\xff.bin".to_vec())), AWS)?;
            let secret_name = [b"\xff".as_slice(), GITHUB.as_bytes()].concat();
            fs::write(root.join(OsString::from_vec(secret_name)), AWS)?;
            let found = scan_tree(&root)?;
            assert!(found.iter().any(|finding| finding.path == "bad-\\xff.bin"));
            assert!(!serde_json::to_string(&found)?.contains(GITHUB));
        }
        let linked_root = directory.path().join("linked-root");
        symlink(&root, &linked_root)?;
        assert!(scan_tree(&linked_root).is_err());
        Ok(())
    }
}
