use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

static DEPENDENCY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\[\d+\]\s+([A-Z2-7]{53})(?:\s|$)").expect("valid dependency pattern")
});
static CHANGE_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\[(?:\d+|\*)\]\+?\s*([A-Z2-7]{53})(?:\s|$)")
        .expect("valid change reference pattern")
});
static SECTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^# (?:Hunks|Changes)$").expect("valid section pattern"));
static HUNK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d+\. (.+)$").expect("valid hunk pattern"));
static QUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""((?:[^"\\]|\\.)*)""#).expect("valid quoted path pattern"));
static CONFLICT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*-\s+(?P<kind>.*?conflict)\b(?:\s+(?:in|on))?\s+"(?P<path>(?:[^"\\]|\\.)*)"(?:\s+starting on line (?P<line>\d+))?"#,
    )
    .expect("valid conflict pattern")
});
static ANSI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").expect("valid ANSI pattern"));

pub const CONTEXT_LINES: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmerged(pub String);

impl fmt::Display for Unmerged {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Unmerged {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub kind: String,
    pub path: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Side {
    pub hashes: Vec<String>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub line: usize,
    pub sides: Vec<Side>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    Text(String),
    Region(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictFile {
    pub pieces: Vec<Piece>,
    pub regions: Vec<Region>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub removed: Vec<String>,
    pub added: Vec<String>,
}

pub type Hunks = BTreeMap<String, Vec<Hunk>>;
pub type Choices = Vec<(String, String)>;

// Python splitlines accepts more separators than Rust lines.
fn splitlines(text: &str) -> impl Iterator<Item = &str> {
    let mut chars = text.char_indices().peekable();
    let mut start = 0;
    std::iter::from_fn(move || {
        while let Some((index, character)) = chars.next() {
            if matches!(
                character,
                '\n' | '\r'
                    | '\u{b}'
                    | '\u{c}'
                    | '\u{1c}'
                    | '\u{1d}'
                    | '\u{1e}'
                    | '\u{85}'
                    | '\u{2028}'
                    | '\u{2029}'
            ) {
                let line = &text[start..index];
                start = index + character.len_utf8();
                if character == '\r' && chars.peek().is_some_and(|(_, next)| *next == '\n') {
                    chars.next();
                    start += 1;
                }
                return Some(line);
            }
        }
        if start < text.len() {
            let line = &text[start..];
            start = text.len();
            Some(line)
        } else {
            None
        }
    })
}

/// A numbered policy rule that carries a stable identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub text: String,
}

pub const MAX_POLICY_RULES: usize = 16;

/// Read the identified rules of a policy text.
///
/// A rule line is a numbered or bulleted item with a `[R1]` style identifier.
/// A policy without identifiers keeps the single-verdict behavior.
pub fn policy_rules(text: &str) -> Result<Vec<PolicyRule>, String> {
    let mut rules = Vec::new();
    for line in splitlines(text) {
        let line = line.trim();
        let line = line
            .strip_prefix("- ")
            .or_else(|| line.strip_prefix("* "))
            .unwrap_or(line);
        let line = match line.find('.') {
            Some(index)
                if !line[..index].is_empty()
                    && line[..index].chars().all(|character| character.is_ascii_digit()) =>
            {
                line[index + 1..].trim_start()
            }
            _ => line,
        };
        let Some(rest) = line.strip_prefix('[') else {
            continue;
        };
        let Some(close) = rest.find(']') else {
            return Err(format!("A policy rule has no closing bracket: {line:?}"));
        };
        let id = &rest[..close];
        let text = rest[close + 1..].trim();
        if !id.strip_prefix('R').is_some_and(|digits| {
            (1..=3).contains(&digits.len()) && digits.chars().all(|c| c.is_ascii_digit())
        }) {
            return Err(format!("A policy rule identifier is invalid: [{id}]"));
        }
        if text.is_empty() {
            return Err(format!("Policy rule [{id}] has no text"));
        }
        if text.chars().count() > 240 {
            return Err(format!("Policy rule [{id}] is too long"));
        }
        if rules.iter().any(|rule: &PolicyRule| rule.id == id) {
            return Err(format!("Policy rule [{id}] appears two times"));
        }
        rules.push(PolicyRule {
            id: id.to_owned(),
            text: text.to_owned(),
        });
    }
    if rules.len() > MAX_POLICY_RULES {
        return Err(format!(
            "The policy has {} rules. The limit is {MAX_POLICY_RULES}.",
            rules.len()
        ));
    }
    Ok(rules)
}

pub fn short(hash: &str) -> &str {
    &hash[..hash
        .char_indices()
        .nth(12)
        .map_or(hash.len(), |(index, _)| index)]
}

pub fn dependencies(text: &str) -> Vec<String> {
    parse_change_hashes(text, &DEPENDENCY)
}

/// Read the message of a native change text. An absent message gives an empty string.
pub fn message(text: &str) -> String {
    let mut header = String::new();
    for line in splitlines(text) {
        if line.starts_with('[') || line.trim().is_empty() {
            break;
        }
        header.push_str(line);
        header.push('\n');
    }
    toml::from_str::<toml::Value>(&header)
        .ok()
        .and_then(|value| value.get("message").and_then(toml::Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

pub fn related_changes(text: &str) -> Vec<String> {
    parse_change_hashes(text, &CHANGE_REFERENCE)
}

fn parse_change_hashes(text: &str, pattern: &Regex) -> Vec<String> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    let mut inside = false;
    for line in splitlines(text) {
        if line.starts_with("# ") {
            inside = line.trim_end() == "# Dependencies";
        } else if inside {
            if let Some(capture) = pattern.captures(line) {
                let hash = capture.get(1).expect("dependency capture").as_str();
                if seen.insert(hash) {
                    found.push(hash.to_owned());
                }
            }
        }
    }
    found
}

fn hunk_body(text: &str) -> Option<&str> {
    SECTION
        .find_iter(text)
        .last()
        .map(|section| &text[section.end()..])
}

pub fn hunk_headers(text: &str) -> Vec<&str> {
    let Some(body) = hunk_body(text) else {
        return Vec::new();
    };
    splitlines(body)
        .filter_map(|line| HUNK.captures(line))
        .map(|capture| capture.get(1).expect("hunk capture").as_str())
        .collect()
}

pub fn is_root_change(text: &str) -> bool {
    let headers = hunk_headers(text);
    !headers.is_empty() && headers.iter().all(|header| header.trim() == "Root add")
}

fn unquote_path(path: &str) -> String {
    serde_json::from_str(&format!("\"{path}\"")).unwrap_or_else(|_| path.to_owned())
}

pub fn touched_paths(log_paths: &[String], text: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = log_paths
        .iter()
        .filter(|path| path.as_str() != "/")
        .cloned()
        .collect();
    for header in hunk_headers(text) {
        for capture in QUOTED.captures_iter(header) {
            let path = unquote_path(capture.get(1).expect("quoted path capture").as_str());
            names.insert(path);
        }
    }
    names.remove("");
    names
}

pub fn rename_targets(text: &str) -> Vec<String> {
    hunk_headers(text)
        .into_iter()
        .filter(|header| header.starts_with("Moved:"))
        .filter_map(|header| QUOTED.captures_iter(header).nth(1))
        .map(|capture| unquote_path(capture.get(1).expect("rename target capture").as_str()))
        .collect()
}

pub fn conflict_report(stderr: &str) -> Vec<Conflict> {
    let clean = ANSI.replace_all(stderr, "");
    let mut found = Vec::new();
    let mut inside = false;
    for line in splitlines(&clean) {
        if line.trim() == "There were conflicts:" {
            inside = true;
        } else if inside && line.trim_start().starts_with("- ") {
            if let Some(capture) = CONFLICT.captures(line) {
                found.push(Conflict {
                    kind: capture["kind"].to_owned(),
                    path: capture["path"].to_owned(),
                    line: capture
                        .name("line")
                        .and_then(|line| line.as_str().parse().ok())
                        .unwrap_or(0),
                });
            } else {
                found.push(Conflict {
                    kind: line.trim()[2..].to_owned(),
                    path: String::new(),
                    line: 0,
                });
            }
        }
    }
    found
}

fn credit_hashes(entry: &Value) -> Result<Vec<String>, Unmerged> {
    let Some(value) = entry.get("sides") else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| Unmerged("pijul credit shows invalid conflict sides.".to_owned()))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Unmerged("pijul credit shows an invalid conflict hash.".to_owned()))
        })
        .collect()
}

fn credit_number(entry: &Value, name: &str) -> Result<usize, Unmerged> {
    entry
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| Unmerged(format!("pijul credit shows an invalid {name}.")))
}

fn entry_label(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(value) => value.to_string(),
    }
}

pub fn split_conflicts(entries: &[Value]) -> Result<ConflictFile, Unmerged> {
    let mut pieces = Vec::new();
    let mut regions = Vec::new();
    let mut current: Option<Region> = None;
    let mut line: usize = 1;
    for entry in entries {
        match entry.get("type").and_then(Value::as_str) {
            Some("line") => {
                line = credit_number(entry, "startLine")?
                    .checked_add(credit_number(entry, "lineCount")?)
                    .ok_or_else(|| {
                        Unmerged("pijul credit shows an invalid line range.".to_owned())
                    })?;
                let content = entry
                    .get("content")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        Unmerged("pijul credit shows invalid line content.".to_owned())
                    })?;
                if let Some(region) = current.as_mut() {
                    let side = region.sides.last_mut().ok_or_else(|| {
                        Unmerged("The file has a conflict without a side.".to_owned())
                    })?;
                    side.text.push_str(content);
                } else {
                    pieces.push(Piece::Text(content.to_owned()));
                }
            }
            Some("conflict") => {
                match (
                    entry.get("marker").and_then(Value::as_str),
                    current.as_mut(),
                ) {
                    (Some("start"), None) => {
                        current = Some(Region {
                            line,
                            sides: vec![Side {
                                hashes: credit_hashes(entry)?,
                                text: String::new(),
                            }],
                        });
                    }
                    (Some("separator"), Some(region)) => {
                        region.sides.push(Side {
                            hashes: credit_hashes(entry)?,
                            text: String::new(),
                        });
                    }
                    (Some("end"), Some(_)) => {
                        if let Some(region) = current.take() {
                            pieces.push(Piece::Region(regions.len()));
                            regions.push(region);
                        }
                    }
                    _ => {
                        return Err(Unmerged(format!(
                            "The file has a conflict structure that patchgate does not know ({}).",
                            entry_label(entry.get("marker")),
                        )));
                    }
                }
                line = line.checked_add(1).ok_or_else(|| {
                    Unmerged("pijul credit shows an invalid line range.".to_owned())
                })?;
            }
            _ => {
                return Err(Unmerged(format!(
                    "pijul credit shows an entry that patchgate does not know: {}",
                    entry_label(entry.get("type")),
                )));
            }
        }
    }
    if current.is_some() {
        return Err(Unmerged(
            "The file has a conflict without an end.".to_owned(),
        ));
    }
    Ok(ConflictFile { pieces, regions })
}

fn piece_lines(pieces: &[Piece]) -> Vec<String> {
    let mut text = String::new();
    for piece in pieces {
        match piece {
            Piece::Text(content) => text.push_str(content),
            Piece::Region(_) => text.push_str("(another conflict)\n"),
        }
    }
    splitlines(&text).map(str::to_owned).collect()
}

pub fn context(pieces: &[Piece], index: usize) -> (Vec<String>, Vec<String>) {
    let Some(position) = pieces
        .iter()
        .position(|piece| matches!(piece, Piece::Region(region) if *region == index))
    else {
        return (Vec::new(), Vec::new());
    };
    let mut before = piece_lines(&pieces[..position]);
    if before.len() > CONTEXT_LINES {
        before.drain(..before.len() - CONTEXT_LINES);
    }
    let mut after = piece_lines(&pieces[position + 1..]);
    after.truncate(CONTEXT_LINES);
    (before, after)
}

pub fn file_hunks(text: &str, path: &str) -> Vec<Hunk> {
    let Some(body) = hunk_body(text) else {
        return Vec::new();
    };
    let mut hunks: Vec<Hunk> = Vec::new();
    let mut inside = false;
    for line in splitlines(body) {
        if let Some(capture) = HUNK.captures(line) {
            inside = QUOTED
                .captures_iter(&capture[1])
                .any(|name| unquote_path(&name[1]) == path);
            if inside {
                hunks.push(Hunk {
                    removed: Vec::new(),
                    added: Vec::new(),
                });
            }
        } else if inside {
            let target = if line.starts_with("+ ") || line == "+" {
                hunks.last_mut().map(|hunk| &mut hunk.added)
            } else if line.starts_with("- ") || line == "-" {
                hunks.last_mut().map(|hunk| &mut hunk.removed)
            } else {
                None
            };
            if let Some(target) = target {
                target.push(line.get(2..).unwrap_or("").to_owned());
            }
        }
    }
    hunks
}

fn replaced_lines<'a>(side: &Side, hunks: &'a Hunks) -> Vec<&'a [String]> {
    let lines: Vec<&str> = splitlines(&side.text).collect();
    side.hashes
        .iter()
        .filter_map(|hash| hunks.get(hash))
        .flatten()
        .filter(|hunk| {
            hunk.added
                .iter()
                .map(String::as_str)
                .eq(lines.iter().copied())
        })
        .map(|hunk| hunk.removed.as_slice())
        .collect()
}

pub fn merge_choices(kind: &str, sides: &[Side], hunks: &Hunks) -> Result<Choices, Unmerged> {
    if kind == "Order conflict" && sides.len() >= 2 {
        let mut seen = HashSet::new();
        for side in sides {
            let replaced: HashSet<&str> = replaced_lines(side, hunks)
                .into_iter()
                .flatten()
                .map(String::as_str)
                .filter(|line| !line.trim().is_empty())
                .collect();
            if !seen.is_disjoint(&replaced) {
                return Err(Unmerged(
                    "The sides replace the same lines with different text, so a human must choose one.".to_owned(),
                ));
            }
            seen.extend(replaced);
        }
        let mut choices = Vec::with_capacity(sides.len() + 2);
        if sides.len() == 2 {
            choices.push((
                "both, side 1 first".to_owned(),
                format!("{}{}", sides[0].text, sides[1].text),
            ));
            choices.push((
                "both, side 2 first".to_owned(),
                format!("{}{}", sides[1].text, sides[0].text),
            ));
        } else {
            choices.push((
                "all sides, in order".to_owned(),
                sides.iter().map(|side| side.text.as_str()).collect(),
            ));
        }
        choices.extend(
            sides
                .iter()
                .enumerate()
                .map(|(index, side)| (format!("only side {}", index + 1), side.text.clone())),
        );
        return Ok(choices);
    }
    if kind != "Deletion conflict" || sides.len() != 1 {
        return Err(Unmerged(format!(
            "patchgate cannot build a merge for this {} with {} sides.",
            kind.to_lowercase(),
            sides.len(),
        )));
    }
    let mut choices = vec![("the deletion wins".to_owned(), String::new())];
    let side = &sides[0];
    let written = replaced_lines(side, hunks);
    if written.len() != 1 {
        return Ok(choices);
    }
    let edited = written[0];
    if edited.is_empty() {
        choices.push(("keep the inserted lines".to_owned(), side.text.clone()));
        return Ok(choices);
    }
    let mut block = None;
    for (hash, change_hunks) in hunks {
        if side.hashes.contains(hash) {
            continue;
        }
        for hunk in change_hunks {
            for (start, run) in hunk.removed.windows(edited.len()).enumerate() {
                if run == edited {
                    if block.is_some() {
                        return Ok(choices);
                    }
                    block = Some((hunk.removed.as_slice(), start));
                }
            }
        }
    }
    if let Some((removed, start)) = block {
        let mut restored = String::new();
        for line in removed[..start]
            .iter()
            .map(String::as_str)
            .chain(splitlines(&side.text))
            .chain(removed[start + edited.len()..].iter().map(String::as_str))
        {
            restored.push_str(line);
            restored.push('\n');
        }
        choices.push((
            "restore the deleted lines with the edit".to_owned(),
            restored,
        ));
    }
    Ok(choices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn side(hash: &str, text: &str) -> Side {
        Side {
            hashes: vec![hash.to_owned()],
            text: text.to_owned(),
        }
    }

    fn hunk(removed: &[&str], added: &[&str]) -> Hunk {
        Hunk {
            removed: removed.iter().map(|line| (*line).to_owned()).collect(),
            added: added.iter().map(|line| (*line).to_owned()).collect(),
        }
    }

    #[test]
    fn parser_uses_last_section_and_retains_empty_hunk_lines() {
        let text = "# Hunks\n1. Root add\n# Changes\n1. Edit in \"a\\\"b\":1\n- old\n-\n+ new\n+ \n2. Edit in \"other\":1\n+ ignored\n";
        assert!(!is_root_change(text));
        assert_eq!(
            file_hunks(text, "a\"b"),
            vec![hunk(&["old", ""], &["new", ""])]
        );
        let paths = touched_paths(&["/old/".to_owned()], text);
        assert_eq!(
            paths,
            BTreeSet::from(["/old/".to_owned(), "a\"b".to_owned(), "other".to_owned()])
        );
    }

    #[test]
    fn path_parser_preserves_unsafe_paths_and_literal_names() {
        let text = "# Hunks\n1. Moved: \"draft.rs\" \"guard.rs\" 3.18\n2. Edit in \"-safe 'quote\\\" café.txt\":1\n+ safe\n";
        assert_eq!(rename_targets(text), vec!["guard.rs"]);
        let paths = touched_paths(
            &["/".into(), "../external".into(), "/absolute".into()],
            text,
        );
        assert!(paths.contains("../external"));
        assert!(paths.contains("/absolute"));
        assert!(paths.contains("-safe 'quote\" café.txt"));
        assert!(!paths.contains("/"));
    }

    #[test]
    fn dependencies_match_native_prerequisites_not_context() {
        let a = "A".repeat(53);
        let b = "B".repeat(53);
        let c = "C".repeat(53);
        let text = format!(
            "[1] {b}\n# Dependencies  \n[2] {a}\n[3]+{b}\n[*] {b}\n[4] {c}\n[5] {a}\n# Hunks\n[6] {b}\n"
        );
        assert_eq!(dependencies(&text), vec![a.clone(), c.clone()]);
        assert_eq!(related_changes(&text), vec![a, b, c]);
    }

    #[test]
    fn credit_and_context_preserve_blank_lines_and_partial_pieces() {
        let file = split_conflicts(&[
            json!({"type":"line", "startLine":1, "lineCount":2, "content":"before\r\n\r\n"}),
            json!({"type":"conflict", "marker":"start", "sides":["a"]}),
            json!({"type":"line", "startLine":4, "lineCount":2, "content":"\nleft\n"}),
            json!({"type":"conflict", "marker":"separator", "sides":["b"]}),
            json!({"type":"line", "startLine":7, "lineCount":1, "content":"right"}),
            json!({"type":"conflict", "marker":"end"}),
            json!({"type":"line", "startLine":9, "lineCount":1, "content":"af"}),
            json!({"type":"line", "startLine":10, "lineCount":1, "content":"ter\u{2028}\n"}),
        ])
        .unwrap();
        assert_eq!(file.regions[0].line, 3);
        assert_eq!(file.regions[0].sides[0].text, "\nleft\n");
        assert_eq!(file.regions[0].sides[1].text, "right");
        assert_eq!(
            context(&file.pieces, 0),
            (
                vec!["before".to_owned(), "".to_owned()],
                vec!["after".to_owned(), "".to_owned()]
            )
        );
        assert_eq!(
            splitlines("a\r\nb\rc\u{b}d\u{c}e\u{1c}f\u{1d}g\u{1e}h\u{85}i\u{2028}j\u{2029}")
                .collect::<Vec<_>>(),
            vec!["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
        );
    }

    #[test]
    fn malformed_credit_requires_a_human() {
        for entries in [
            vec![json!({"type":"conflict", "marker":"end"})],
            vec![json!({"type":"conflict", "marker":"separator"})],
            vec![json!({"type":"conflict", "marker":"start"})],
            vec![
                json!({"type":"conflict", "marker":"start"}),
                json!({"type":"conflict", "marker":"start"}),
            ],
            vec![json!({"type":"conflict", "marker":"start", "sides":[42]})],
            vec![json!({"type":"line", "startLine":1, "lineCount":1, "content":null})],
            vec![json!({"type":"line", "startLine":u64::MAX, "lineCount":1, "content":"x"})],
            vec![json!(null)],
        ] {
            assert!(split_conflicts(&entries).is_err(), "{entries:?}");
        }
    }

    #[test]
    fn conflict_report_retains_quoted_paths_and_unknown_reports() {
        let report = conflict_report(
            "- ignored\n\u{1b}[31mThere were conflicts:\u{1b}[0m\n - Order conflict in \"a\\\"b\" starting on line 9\n - Name conflict on \"other\"\n - unknown shape\n",
        );
        assert_eq!(
            report,
            vec![
                Conflict {
                    kind: "Order conflict".to_owned(),
                    path: "a\\\"b".to_owned(),
                    line: 9
                },
                Conflict {
                    kind: "Name conflict".to_owned(),
                    path: "other".to_owned(),
                    line: 0
                },
                Conflict {
                    kind: "unknown shape".to_owned(),
                    path: String::new(),
                    line: 0
                },
            ]
        );
    }

    #[test]
    fn same_line_replacements_cannot_be_model_choices() {
        let hunks = BTreeMap::from([
            (
                "a".to_owned(),
                vec![hunk(&["value = old", ""], &["value = left"])],
            ),
            (
                "b".to_owned(),
                vec![hunk(&["value = old"], &["value = right"])],
            ),
        ]);
        assert!(
            merge_choices(
                "Order conflict",
                &[side("a", "value = left\n"), side("b", "value = right\n")],
                &hunks
            )
            .is_err()
        );
        assert!(merge_choices("Deletion conflict", &[], &hunks).is_err());
        assert!(merge_choices("Name conflict", &[side("a", "x")], &hunks).is_err());
    }

    #[test]
    fn deletion_restores_only_one_exact_source_block() {
        let sides = [side("edit", "    return 2\n")];
        let mut hunks = BTreeMap::from([
            (
                "edit".to_owned(),
                vec![hunk(&["    return 1"], &["    return 2"])],
            ),
            (
                "delete".to_owned(),
                vec![hunk(&["def f():", "    return 1", ""], &[])],
            ),
        ]);
        assert_eq!(
            merge_choices("Deletion conflict", &sides, &hunks).unwrap(),
            vec![
                ("the deletion wins".to_owned(), String::new()),
                (
                    "restore the deleted lines with the edit".to_owned(),
                    "def f():\n    return 2\n\n".to_owned()
                ),
            ]
        );
        hunks
            .get_mut("delete")
            .unwrap()
            .push(hunk(&["    return 1"], &[]));
        assert_eq!(
            merge_choices("Deletion conflict", &sides, &hunks).unwrap(),
            vec![("the deletion wins".to_owned(), String::new()),]
        );
        hunks.remove("delete");
        assert_eq!(
            merge_choices("Deletion conflict", &sides, &hunks).unwrap(),
            vec![("the deletion wins".to_owned(), String::new()),]
        );
        hunks.insert("edit".to_owned(), vec![hunk(&[], &["    return 2"])]);
        assert_eq!(
            merge_choices("Deletion conflict", &sides, &hunks).unwrap(),
            vec![
                ("the deletion wins".to_owned(), String::new()),
                (
                    "keep the inserted lines".to_owned(),
                    "    return 2\n".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn policy_rules_need_one_unique_identifier_and_text() {
        let text = "# Policy\n\n- [R1] Reject a secret.\n\n## Reject\n1. [R2] Reject build output.\n2. No identifier here.\n";
        assert_eq!(
            policy_rules(text).unwrap(),
            vec![
                PolicyRule {
                    id: "R1".into(),
                    text: "Reject a secret.".into()
                },
                PolicyRule {
                    id: "R2".into(),
                    text: "Reject build output.".into()
                }
            ]
        );
        assert_eq!(policy_rules("# Policy\nAccept safe changes.\n").unwrap(), vec![]);
        assert!(policy_rules("- [X1] Wrong prefix.\n").is_err());
        assert!(policy_rules("- [R1]\n").is_err());
        assert!(policy_rules("- [R1] One.\n- [R1] Two.\n").is_err());
        assert!(policy_rules("- [R1234] Too many digits.\n").is_err());
        assert!(policy_rules("- [R1 No closing bracket.\n").is_err());
    }
}
